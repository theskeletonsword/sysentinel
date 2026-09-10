// SPDX-License-Identifier: MIT OR GPL-2.0-or-later
//!
//! # sysentinel-cam — capture a single JPEG frame from ANY webcam
//!
//! Pure userspace V4L2 (no libv4l, no ffmpeg): open the first usable video
//! capture device in `/dev/video*` (USB or integrated camera), set a format,
//! mmap one buffer, stream one frame and encode it to a JPEG file.
//!
//! # CLI
//!
//! ```text
//! sysentinel-cam --out <path.jpg>                 # auto-detect camera
//! sysentinel-cam --out <path.jpg> --dev /dev/videoN
//! sysentinel-cam --out <path.jpg> --width 640 --height 480 --timeout 8
//! sysentinel-cam --list                           # print usable cameras
//! ```
//!
//! # Exit codes (the callers depend on these)
//!
//! | code | meaning                                                    |
//! |------|------------------------------------------------------------|
//! | `0`  | photo written                                             |
//! | `1`  | no usable camera present (no `/dev/video*`, or none is a capture device) |
//! | `2`  | a camera exists but capture/conversion failed             |
//! | `3`  | usage error                                               |
//! | `130`| killed by signal (SIGINT/SIGTERM) — abort cleanly        |
//!
//! The initramfs hook and the daemon use the exit code to decide whether to
//! send a photo or just a text notice.

use std::ffi::CString;
use std::os::fd::RawFd;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

// ── V4L2 ABI constants (verified against /usr/include/linux/videodev2.h
//    on the host kernel; the ioctl request numbers encode the struct sizes) ──
//
// The request-number ABI differs between libc flavours: glibc's ioctl(2)
// takes the request as `unsigned long`, musl's as `int`. The values are
// 32-bit V4L2 _IOC encodings either way, so we carry them as c_ulong and cast
// to the target's request type at the call site.

const REQ_QUERYCAP: IoctlReq = 0x8068_5600u64 as IoctlReq;
const REQ_S_FMT:    IoctlReq = 0xc0d0_5605u64 as IoctlReq;
const REQ_REQBUFS:  IoctlReq = 0xc014_5608u64 as IoctlReq;
const REQ_QUERYBUF: IoctlReq = 0xc058_5609u64 as IoctlReq;
const REQ_QBUF:     IoctlReq = 0xc058_560fu64 as IoctlReq;
const REQ_DQBUF:    IoctlReq = 0xc058_5611u64 as IoctlReq;
const REQ_STREAMON: IoctlReq = 0x4004_5612u64 as IoctlReq;
const REQ_STREAMOFF: IoctlReq = 0x4004_5613u64 as IoctlReq;

/// The `request` parameter type of ioctl(2) on this libc flavour.
#[cfg(target_env = "musl")]
type IoctlReq = libc::c_int;
#[cfg(not(target_env = "musl"))]
type IoctlReq = libc::c_ulong;

const V4L2_CAP_VIDEO_CAPTURE: u32 = 0x0000_0001;
const V4L2_BUF_TYPE_VIDEO_CAPTURE: u32 = 1;
const V4L2_MEMORY_MMAP: u32 = 1;

const PIX_FMT_YUYV: u32 = 0x5659_5559; // "YUYV"
const PIX_FMT_MJPEG: u32 = 0x4750_4A4D; // "MJPG"
const PIX_FMT_GREY: u32 = 0x5945_5247; // "GREY"

// ── V4L2 structs (repr(C), layout matches the ABI on 64-bit Linux) ───────────

/// struct v4l2_capability (104 bytes).
#[repr(C)]
struct V4l2Capability {
    driver: [u8; 16],
    card: [u8; 32],
    bus_info: [u8; 32],
    version: u32,
    capabilities: u32,
    device_caps: u32,
    reserved: [u32; 3],
}

/// struct v4l2_pix_format (48 bytes).
#[repr(C)]
#[derive(Clone, Copy)]
struct V4l2PixFormat {
    width: u32,
    height: u32,
    pixelformat: u32,
    field: u32,
    bytesperline: u32,
    sizeimage: u32,
    colorspace: u32,
    priv_: u32,
    flags: u32,
    ycbcr_enc: u32,
    quantization: u32,
    xfer_func: u32,
}

/// struct v4l2_format (208 bytes). The union `fmt` sits at offset 8: `type`
/// is u32 and the union is 8-aligned, so the kernel pads 4 bytes after it.
/// The union itself is `raw_data[200]` actually.
#[repr(C)]
struct V4l2Format {
    typ: u32,
    _pad: [u8; 4],
    fmt: [u8; 200],
}

/// struct v4l2_requestbuffers (20 bytes).
#[repr(C)]
struct V4l2Requestbuffers {
    count: u32,
    typ: u32,
    memory: u32,
    reserved: [u32; 2],
}

/// struct v4l2_buffer (88 bytes on x86_64).
#[repr(C)]
struct V4l2Buffer {
    index: u32,
    typ: u32,
    bytesused: u32,
    flags: u32,
    field: u32,
    tv_sec: i64,
    tv_usec: i64,
    timecode_type: u32,
    timecode_flags: u32,
    timecode_frames: u8,
    timecode_seconds: u8,
    timecode_minutes: u8,
    timecode_hours: u8,
    timecode_userbits: [u8; 4],
    sequence: u32,
    memory: u32,
    m: u64,
    length: u32,
    reserved2: u32,
    reserved: u32,
}

const _: () = {
    assert!(std::mem::size_of::<V4l2Capability>() == 104);
    assert!(std::mem::size_of::<V4l2PixFormat>() == 48);
    assert!(std::mem::size_of::<V4l2Format>() == 208);
    assert!(std::mem::offset_of!(V4l2Format, fmt) == 8);
    assert!(std::mem::size_of::<V4l2Requestbuffers>() == 20);
    assert!(std::mem::size_of::<V4l2Buffer>() == 88);
};

impl V4l2Buffer {
    fn mmap_offset(&self) -> u64 {
        // Union member `m`: for V4L2_MEMORY_MMAP the low 32 bits are `offset`.
        self.m & 0xFFFF_FFFF
    }
}

// ── CLI ───────────────────────────────────────────────────────────────────────

struct Args {
    dev:   Option<PathBuf>,
    out:   Option<PathBuf>,
    list:  bool,
    width: u32,
    height: u32,
    timeout: u64,
}

enum ParseErr {
    Usage(String),
    Exit(i32),
}

fn usage() -> &'static str {
    "usage: sysentinel-cam --out <path.jpg> [--dev /dev/videoN] \
     [--width W] [--height H] [--timeout SECS] | sysentinel-cam --list"
}

fn parse_args() -> Result<Args, ParseErr> {
    let mut args = Args {
        dev: None, out: None, list: false,
        width: 640, height: 480, timeout: 8,
    };
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--out" => {
                let v = it.next().ok_or_else(|| ParseErr::Usage(usage().into()))?;
                args.out = Some(PathBuf::from(v));
            }
            "--dev" => {
                let v = it.next().ok_or_else(|| ParseErr::Usage(usage().into()))?;
                args.dev = Some(PathBuf::from(v));
            }
            "--list" => args.list = true,
            "--width" => {
                args.width = it.next()
                    .and_then(|s| s.parse().ok())
                    .ok_or_else(|| ParseErr::Usage("bad --width".into()))?;
            }
            "--height" => {
                args.height = it.next()
                    .and_then(|s| s.parse().ok())
                    .ok_or_else(|| ParseErr::Usage("bad --height".into()))?;
            }
            "--timeout" => {
                args.timeout = it.next()
                    .and_then(|s| s.parse().ok())
                    .ok_or_else(|| ParseErr::Usage("bad --timeout".into()))?;
            }
            "-h" | "--help" => return Err(ParseErr::Exit(0)),
            other => {
                if other.starts_with('-') {
                    return Err(ParseErr::Usage(format!("unknown option: {other}")));
                }
                return Err(ParseErr::Usage(usage().into()));
            }
        }
    }
    if args.list {
        if args.out.is_some() || args.dev.is_some() {
            return Err(ParseErr::Usage("--list takes no other options".into()));
        }
    } else if args.out.is_none() {
        return Err(ParseErr::Usage(usage().into()));
    }
    Ok(args)
}

// ── Camera enumeration / probing ──────────────────────────────────────────────

/// All `/dev/video*` candidates, sorted for determinism (video0 first).
fn video_devices() -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = match std::fs::read_dir("/dev") {
        Ok(rd) => rd
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with("video"))
            })
            .collect(),
        Err(_) => vec![],
    };
    v.sort();
    v
}

/// Open a video device. Returns Ok(fd) — without extended ioctls.
fn open_device(path: &Path) -> Result<RawFd, String> {
    let c = CString::new(path.to_string_lossy().as_bytes())
        .map_err(|e| format!("bad path {path:?}: {e}"))?;
    // O_NONBLOCK: DQBUF is polled anyway; open must never block on a busy cam.
    let fd = unsafe {
        libc::open(c.as_ptr(), libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC)
    };
    if fd < 0 {
        return Err(format!("open {path:?}: {}", io_err()));
    }
    Ok(fd)
}

fn io_err() -> String {
    std::io::Error::last_os_error().to_string()
}

/// Is this device a usable video CAPTURE source?
fn has_capture_cap(fd: RawFd) -> bool {
    let mut cap: V4l2Capability = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::ioctl(fd, REQ_QUERYCAP, &mut cap) };
    if rc < 0 {
        return false;
    }
    // `device_caps` overrides `capabilities` when it is non-zero (multiplexed
    // nodes like the metadata / tracking device of an integrated camera).
    let caps = if cap.device_caps != 0 { cap.device_caps } else { cap.capabilities };
    caps & V4L2_CAP_VIDEO_CAPTURE != 0
}

fn dev_name(fd: RawFd) -> String {
    let mut cap: V4l2Capability = unsafe { std::mem::zeroed() };
    if unsafe { libc::ioctl(fd, REQ_QUERYCAP, &mut cap) } == 0 {
        let card = cstr(&cap.card);
        if !card.is_empty() {
            return card;
        }
    }
    "unknown".to_string()
}

fn cstr(b: &[u8]) -> String {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    String::from_utf8_lossy(&b[..end]).into_owned()
}

/// First device that accepts a capture query.
fn pick_device(preferred: Option<&Path>) -> Result<PathBuf, i32> {
    if let Some(p) = preferred {
        let fd = open_device(p).map_err(|e| { eprintln!("sysentinel-cam: {e}"); 2 })?;
        if has_capture_cap(fd) {
            unsafe { libc::close(fd) };
            return Ok(p.to_path_buf());
        }
        unsafe { libc::close(fd) };
        return Err(2);
    }
    for dev in video_devices() {
        match open_device(&dev) {
            Ok(fd) => {
                let ok = has_capture_cap(fd);
                unsafe { libc::close(fd) };
                if ok {
                    return Ok(dev);
                }
            }
            Err(e) => { eprintln!("sysentinel-cam: {e}"); }
        }
    }
    Err(1)
}

// ── Single frame capture ──────────────────────────────────────────────────────

struct Frame {
    bytes: Vec<u8>,
    width: u32,
    height: u32,
    pixelformat: u32,
}

fn ioctl_ptr<T>(fd: RawFd, req: IoctlReq, data: &mut T) -> std::io::Result<()> {
    let rc = unsafe { libc::ioctl(fd, req, data as *mut _ as *mut libc::c_void) };
    if rc < 0 {
        Err(std::io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Configure the device with a given format, at the requested resolution.
/// Returns (actual width, actual height).
fn set_format(fd: RawFd, pixelformat: u32, w: u32, h: u32)
    -> std::io::Result<(u32, u32)> {
    let pix = V4l2PixFormat {
        width: w, height: h, pixelformat, field: 0,
        bytesperline: 0, sizeimage: 0, colorspace: 0, priv_: 0,
        flags: 0, ycbcr_enc: 0, quantization: 0, xfer_func: 0,
    };
    let pix_bytes = unsafe {
        std::slice::from_raw_parts(&pix as *const _ as *const u8,
                                   std::mem::size_of::<V4l2PixFormat>())
    };
    let mut fmt = V4l2Format { typ: V4L2_BUF_TYPE_VIDEO_CAPTURE, _pad: [0; 4], fmt: [0u8; 200] };
    fmt.fmt[..48].copy_from_slice(pix_bytes);
    ioctl_ptr(fd, REQ_S_FMT, &mut fmt)?;

    // Read back what the driver actually negotiated.
    // SAFETY: fmt.fmt[..48] is the v4l2_pix_format when type == VIDEO_CAPTURE.
    let got: &V4l2PixFormat = unsafe { &*(fmt.fmt.as_ptr() as *const V4l2PixFormat) };
    if got.pixelformat != pixelformat {
        return Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            format!("pixel format {pixelformat:#x} not honoured (got {:#x})", got.pixelformat),
        ));
    }
    let (gw, gh) = (got.width.max(1), got.height.max(1));
    // A 0x0 answer means "pick the default" — clamp to something sane.
    Ok((gw, gh))
}

/// Stream one frame from the configured device.
fn grab_frame(fd: RawFd, timeout_secs: u64) -> std::io::Result<Frame> {
    // 1 buffer, mmap.
    let mut reqb = V4l2Requestbuffers {
        count: 1, typ: V4L2_BUF_TYPE_VIDEO_CAPTURE, memory: V4L2_MEMORY_MMAP, reserved: [0; 2],
    };
    ioctl_ptr(fd, REQ_REQBUFS, &mut reqb)?;
    if reqb.count == 0 {
        return Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "no buffers available"));
    }

    // Query buffer 0 → mmap it.
    let mut qbuf = V4l2Buffer {
        index: 0, typ: V4L2_BUF_TYPE_VIDEO_CAPTURE, memory: V4L2_MEMORY_MMAP,
        bytesused: 0, flags: 0, field: 0,
        tv_sec: 0, tv_usec: 0,
        timecode_type: 0, timecode_flags: 0,
        timecode_frames: 0, timecode_seconds: 0, timecode_minutes: 0, timecode_hours: 0,
        timecode_userbits: [0; 4],
        sequence: 0, m: 0, length: 0, reserved2: 0, reserved: 0,
    };
    ioctl_ptr(fd, REQ_QUERYBUF, &mut qbuf)?;
    let length = qbuf.length.max(1) as usize;
    let offset = qbuf.mmap_offset();
    let map = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            length,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd,
            offset as libc::off_t,
        )
    };
    if map == libc::MAP_FAILED {
        return Err(std::io::Error::last_os_error());
    }
    let map_slice: &[u8] = unsafe { std::slice::from_raw_parts(map as *const u8, length) };

    let unmap = |map, length: usize| unsafe {
        libc::munmap(map, length);
    };

    // Queue + stream on.
    let mut q = V4l2Buffer { index: 0, typ: V4L2_BUF_TYPE_VIDEO_CAPTURE, memory: V4L2_MEMORY_MMAP, ..unsafe { std::mem::zeroed() } };
    if let Err(e) = ioctl_ptr(fd, REQ_QBUF, &mut q) {
        unmap(map, length);
        return Err(e);
    }
    let mut on: libc::c_int = V4L2_BUF_TYPE_VIDEO_CAPTURE as libc::c_int;
    if ioctl_ptr(fd, REQ_STREAMON, &mut on).is_err() {
        unmap(map, length);
        return Err(std::io::Error::other("streamon failed"));
    }

    // Wait for data with a hard deadline (select + POLLIN).
    let deadline = std::time::Instant::now() + Duration::from_secs(timeout_secs);
    let result: std::io::Result<Frame> = loop {
        let mut pfd = libc::pollfd {
            fd,
            events: libc::POLLIN,
            revents: 0,
        };
        let left_ms = deadline.saturating_duration_since(std::time::Instant::now());
        if left_ms.is_zero() {
            break Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "frame timeout"));
        }
        let ms = left_ms.as_millis().min(1000) as i32;
        let pr = unsafe { libc::poll(&mut pfd, 1, ms) };
        if pr < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            break Err(e);
        }
        if pr == 0 {
            continue;
        }
        if pfd.revents & libc::POLLIN == 0 {
            if pfd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL) != 0 {
                break Err(std::io::Error::other("device error"));
            }
            continue;
        }

        // Dequeue the frame.
        let mut dq = V4l2Buffer { index: 0, typ: V4L2_BUF_TYPE_VIDEO_CAPTURE, memory: V4L2_MEMORY_MMAP, ..unsafe { std::mem::zeroed() } };
        if let Err(e) = ioctl_ptr(fd, REQ_DQBUF, &mut dq) {
            break Err(e);
        }
        let used = (dq.bytesused as usize).min(length);
        if used == 0 {
            break Err(std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "empty frame"));
        }
        let bytes = map_slice[..used].to_vec();
        // intact pixels count for YUYV/GREY:
        //   YUYV: 2 bytes/pixel
        //   GREY: 1 byte/pixel
        // The negotiated width/height are re-read via S_FMT earlier and
        // passed separately; here we just need the raw + format tag.
        let frame = Frame {
            bytes,
            width: 0, height: 0, pixelformat: 0,
        };
        break Ok(frame);
    };

    let _ = ioctl_ptr::<libc::c_int>(fd, REQ_STREAMOFF, &mut on);
    unmap(map, length);
    result
}

// ── Colour conversion + JPEG ──────────────────────────────────────────────────

fn yuyv_to_rgb(bytes: &[u8], w: u32, h: u32) -> Vec<u8> {
    let n = (w as usize) * (h as usize);
    let mut rgb = vec![0u8; n * 3];
    let mut i = 0usize;
    let mut j = 0usize;
    let src = bytes.len().min(n * 2);
    while i + 1 < src && j + 3 <= rgb.len() {
        let y0 = bytes[i] as i32;
        let u = bytes[i + 1] as i32;
        let y1 = if i + 2 < src { bytes[i + 2] as i32 } else { y0 };
        let v = if i + 3 < src { bytes[i + 3] as i32 } else { u };
        i += 4;

        rgb[j..j + 3].copy_from_slice(&yuv_px(y0, u, v));
        if j + 6 <= rgb.len() {
            rgb[j + 3..j + 6].copy_from_slice(&yuv_px(y1, u, v));
        }
        j += 6;
    }
    rgb
}

fn yuv_px(y: i32, u: i32, v: i32) -> [u8; 3] {
    let c = y - 16;
    let d = u - 128;
    let e = v - 128;
    let r = (298 * c + 409 * e + 128) >> 8;
    let g = (298 * c - 100 * d - 208 * e + 128) >> 8;
    let b = (298 * c + 516 * d + 128) >> 8;
    [clamp255(r), clamp255(g), clamp255(b)]
}

fn clamp255(v: i32) -> u8 {
    v.clamp(0, 255) as u8
}

/// Encode a raw frame to a JPEG byte buffer.
fn frame_to_jpeg(frame: &Frame, w: u32, h: u32) -> Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(frame.bytes.len() / 2 + 1024);
    match frame.pixelformat {
        PIX_FMT_MJPEG => {
            // The frame is already a JPEG; ship it verbatim.
            if frame.bytes.len() > 2 && frame.bytes[0] == 0xFF && frame.bytes[1] == 0xD8 {
                out.extend_from_slice(&frame.bytes);
            } else {
                return Err("MJPG frame is not JPEG".into());
            }
        }
        PIX_FMT_GREY => {
            let mut enc = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut out, 88);
            enc.encode(&frame.bytes, w, h, image::ExtendedColorType::L8)
                .map_err(|e| format!("jpeg encode: {e}"))?;
        }
        PIX_FMT_YUYV => {
            let rgb = yuyv_to_rgb(&frame.bytes, w, h);
            let mut enc = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut out, 88);
            enc.encode(&rgb, w, h, image::ExtendedColorType::Rgb8)
                .map_err(|e| format!("jpeg encode: {e}"))?;
        }
        other => return Err(format!("unsupported pixel format {other:#x}")),
    }
    Ok(out)
}

// ── Signal handling: die cleanly so callers get a predictable code ────────────

static INTERRUPTED: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_sig: libc::c_int) {
    INTERRUPTED.store(true, Ordering::SeqCst);
}

fn install_signal_handlers() {
    // SAFETY: standard signal handlers; only set an atomic flag.
    unsafe {
        libc::signal(libc::SIGINT, on_signal as *const () as libc::sighandler_t);
        libc::signal(libc::SIGTERM, on_signal as *const () as libc::sighandler_t);
    }
}

// ── Main ──────────────────────────────────────────────────────────────────────

fn main() {
    install_signal_handlers();

    let args = match parse_args() {
        Ok(a) => a,
        Err(ParseErr::Usage(msg)) => {
            eprintln!("sysentinel-cam: {msg}");
            eprintln!("{}", usage());
            std::process::exit(3);
        }
        Err(ParseErr::Exit(0)) => {
            println!("{}", usage());
            return;
        }
        Err(ParseErr::Exit(code)) => std::process::exit(code),
    };

    if args.list {
        let mut found = false;
        for dev in video_devices() {
            match open_device(&dev) {
                Ok(fd) => {
                    if has_capture_cap(fd) {
                        println!("{} {}", dev.display(), dev_name(fd));
                        found = true;
                    }
                    unsafe { libc::close(fd) };
                }
                Err(e) => eprintln!("sysentinel-cam: {e}"),
            }
        }
        if !found {
            std::process::exit(1);
        }
        return;
    }

    let dev = match pick_device(args.dev.as_deref()) {
        Ok(d) => d,
        Err(code) => {
            eprintln!("sysentinel-cam: no usable webcam found (exit {code})");
            std::process::exit(code);
        }
    };

    let fd = match open_device(&dev) {
        Ok(fd) => fd,
        Err(e) => {
            eprintln!("sysentinel-cam: {e}");
            std::process::exit(2);
        }
    };

    // Try formats in order; the camera may not support the first choice.
    let mut captured: Option<(Frame, u32, u32, String)> = None;
    for (fmt, label) in [
        (PIX_FMT_YUYV, "YUYV"),
        (PIX_FMT_MJPEG, "MJPG"),
        (PIX_FMT_GREY, "GREY"),
    ] {
        match set_format(fd, fmt, args.width, args.height) {
            Err(e) => {
                eprintln!("sysentinel-cam: {dev:?}: {label} not available: {e}");
            }
            Ok((w, h)) => {
                match grab_frame(fd, args.timeout) {
                    Ok(mut frame) => {
                        frame.pixelformat = fmt;
                        frame.width = w;
                        frame.height = h;
                        captured = Some((frame, w, h, label.to_string()));
                        break;
                    }
                    Err(e) => {
                        eprintln!("sysentinel-cam: {dev:?}: {label} capture failed: {e}");
                    }
                }
            }
        }
        if INTERRUPTED.load(Ordering::SeqCst) {
            eprintln!("sysentinel-cam: interrupted");
            std::process::exit(130);
        }
    }

    let Some((frame, w, h, label)) = captured else {
        unsafe { libc::close(fd) };
        eprintln!("sysentinel-cam: {dev:?}: all formats failed");
        std::process::exit(2);
    };

    let jpeg = match frame_to_jpeg(&frame, w, h) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("sysentinel-cam: {dev:?}: {label}: {e}");
            std::process::exit(2);
        }
    };
    if jpeg.is_empty() {
        unsafe { libc::close(fd) };
        eprintln!("sysentinel-cam: {dev:?}: empty jpeg");
        std::process::exit(2);
    }

    // Write atomically: tmp + rename, so a mid-write kill never leaves a
    // half-photo that the daemon might try to send.
    let out = args.out.unwrap();
    let tmp = out.with_extension(format!(
        "tmp{}.jpg",
        std::process::id()
    ));
    let res = std::fs::write(&tmp, &jpeg).and_then(|()| std::fs::rename(&tmp, &out));
    unsafe { libc::close(fd) };
    if let Err(e) = res {
        let _ = std::fs::remove_file(&tmp);
        eprintln!("sysentinel-cam: write {}: {e}", out.display());
        std::process::exit(2);
    }
    eprintln!("sysentinel-cam: {dev:?} [{label}] {}x{} → {}", w, h, out.display());
}