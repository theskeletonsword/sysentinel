// SPDX-License-Identifier: Apache-2.0
//!
//! Webcam evidence (`sysentinel-cam`) integration.
//!
//! The heavy lifting (V4L2 ioctls, YUYV/GREY→JPEG, format fallback) lives in
//! the standalone `ramdisk/` crate. This module just runs it and copies the
//! produced JPEG into the evidence dir. The photo is attached to the alert;
//! with no webcam the daemon falls back to text only.
//!
//! Exit-code contract (from ramdisk/src/main.rs):
//!   0 = photo written, 1 = no usable camera, 2 = capture failed, 130 = killed.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::config::CameraConfig;

/// Outcome of a webcam snapshot.
pub enum CamResult {
    /// A JPEG was written to `path`.
    Photo { path: PathBuf },
    /// Device present but no camera usable / no frame in time.
    NoWebcam,
    /// The tool ran but produced no photo (capture error, missing binary).
    CaptureFailed,
}

/// Take one photo directly into `dest_dir`. Safe to call from any watcher
/// thread: names a unique file per shot (timestamp + pid).
pub fn capture(cfg: &CameraConfig, dest_dir: &Path) -> CamResult {
    std::fs::create_dir_all(dest_dir).ok();
    let name = format!(
        "cam_{}.jpg",
        chrono::Utc::now().format("%Y%m%d_%H%M%S%.3f")
    );
    let out = dest_dir.join(&name);
    let cam = cfg.tool_path.trim();

    // Honour the configured capture resolution: `sysentinel-cam` takes the
    // request as a hint and falls back to the camera's nearest supported mode.
    let (w, h, t) = (
        cfg.width.to_string(),
        cfg.height.to_string(),
        cfg.timeout.to_string(),
    );
    let args = [
        "--out", out.to_str().unwrap_or_default(),
        "--width", &w,
        "--height", &h,
        "--timeout", &t,
    ];

    match run_tool_with_output(cam, &args, cfg.timeout.saturating_add(5)) {
        Ok(Some((0, _))) if out.is_file() => {
            log::info!("camera: {name} captured ({})", out.display());
            CamResult::Photo { path: out }
        }
        Ok(Some((1, _))) => {
            log::info!("camera: no usable webcam (sysentinel-cam exit 1)");
            CamResult::NoWebcam
        }
        Ok(Some((_, _))) => {
            log::warn!("camera: sysentinel-cam failed on {:?}", out);
            CamResult::CaptureFailed
        }
        Ok(None) => {
            log::warn!("camera: sysentinel-cam timed out");
            CamResult::CaptureFailed
        }
        Err(e) => {
            log::warn!("camera: cannot run {}: {e:#}", cfg.tool_path);
            CamResult::CaptureFailed
        }
    }
}

/// Run a tool capturing stdout, with a hard kill timeout. `Ok(Some((exit,
/// stdout)))` = its exit code and captured output; `Ok(None)` = timed out and
/// killed; `Err` = wouldn't run.
fn run_tool_with_output(prog: &str, args: &[&str], timeout_secs: u64)
    -> Result<Option<(i32, String)>> {
    use std::os::unix::process::CommandExt;
    use std::process::{Command, Stdio};

    let mut c = Command::new(prog);
    c.args(args);
    // Own process group so the kill is a clean SIGTERM→SIGKILL of the tree.
    c.process_group(0);
    c.stdin(Stdio::null());
    c.stdout(Stdio::piped());
    c.stderr(Stdio::null());
    let mut child = c.spawn().context("spawning camera tool")?;

    let deadline = Instant::now() + Duration::from_secs(timeout_secs);

    // Drain stdout concurrently so a chatty tool can't deadlock.
    let stdout = child.stdout.take();
    let reader = stdout.map(|mut r| std::thread::spawn(move || {
        use std::io::Read;
        let mut buf = String::new();
        let mut cap = [0u8; 4096];
        loop {
            match r.read(&mut cap) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    buf.push_str(&String::from_utf8_lossy(&cap[..n]));
                    if buf.len() > 64 * 1024 {
                        break;
                    }
                }
            }
        }
        buf
    }));

    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break Some(s),
            Ok(None) => {}
            Err(e) => return Err(e).context("waiting on camera tool"),
        }
        if Instant::now() >= deadline {
            break None;
        }
        std::thread::sleep(Duration::from_millis(100));
    };

    if status.is_none() {
        // Kill the whole process group.
        unsafe {
            let pgid = -(child.id() as i32);
            libc::kill(pgid, libc::SIGTERM);
        }
        std::thread::sleep(Duration::from_millis(150));
        unsafe {
            let pgid = -(child.id() as i32);
            libc::kill(pgid, libc::SIGKILL);
        }
        let _ = child.wait();
    }

    let out = reader.map(|h| h.join().unwrap_or_default()).unwrap_or_default();
    let code = status.and_then(|s| s.code());

    log::debug!("camera: {prog} {args:?} → exit={code:?} stdout:{out:?}");
    if let Some(c) = code {
        Ok(Some((c, out)))
    } else {
        Ok(None)
    }
}