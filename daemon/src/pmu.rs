// SPDX-License-Identifier: Apache-2.0
//!
//! Performance Monitoring Unit (PMU) reader via the Linux `perf_event_open`
//! syscall interface.
//!
//! # What this reads
//!
//! Hardware counters (via `PERF_TYPE_HARDWARE`):
//! - CPU cycles
//! - Retired instructions → IPC = instructions / cycles
//! - Last-level cache misses (LLC misses)
//! - Branch mispredictions
//!
//! Software counters (via `PERF_TYPE_SOFTWARE` — always available, no
//! privilege required):
//! - Context switches
//! - Page faults (minor + major separately)
//! - CPU migrations
//!
//! # Privilege requirements
//!
//! Hardware counters require that `/proc/sys/kernel/perf_event_paranoid`
//! is ≤ 0 for system-wide measurements, OR that the daemon has
//! `CAP_PERFMON` (kernel ≥ 5.8) or `CAP_SYS_ADMIN` (older kernels).
//!
//! Software counters for the calling process (pid=0) never require
//! elevated privilege.
//!
//! The public API degrades gracefully: if a counter cannot be opened
//! (e.g. EACCES), the field is `None` in the snapshot rather than
//! returning an error.
//!
//! Add `AmbientCapabilities=CAP_PERFMON` to the systemd unit to enable
//! hardware counters without running as root.
//!
//! # No external dependencies
//!
//! This module calls `perf_event_open` directly via `libc::syscall`.
//! No `perf-event` crate or libpfm dependency is needed.

use std::fs;
use std::os::fd::AsRawFd;
use std::os::unix::io::{FromRawFd, OwnedFd};
use std::time::Duration;

// ── perf_event_open syscall numbers ──────────────────────────────────────────

#[cfg(target_arch = "x86_64")]
const SYS_PERF_EVENT_OPEN: libc::c_long = 298;

#[cfg(target_arch = "aarch64")]
const SYS_PERF_EVENT_OPEN: libc::c_long = 241;

#[cfg(target_arch = "x86")]
const SYS_PERF_EVENT_OPEN: libc::c_long = 336;

// Fallback: compile on other architectures but return None for all counters.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "x86")))]
const SYS_PERF_EVENT_OPEN: libc::c_long = -1;

// ── perf_event_attr ───────────────────────────────────────────────────────────

/// `struct perf_event_attr` from `linux/perf_event.h`, trimmed to the fields
/// we use. We zero-initialise the struct and set `size` correctly so the kernel
/// can handle both older and newer attr sizes.
///
/// The full struct in modern kernels is 136 bytes; we declare 128 bytes here
/// (the size as of kernel 3.12, which covers all fields we need). The kernel
/// accepts any valid size ≥ sizeof(struct perf_event_attr_v0) and zeroes any
/// fields we don't set.
#[repr(C)]
struct PerfEventAttr {
    /// Event type. One of `PERF_TYPE_*`.
    type_:       u32,
    /// Size of this structure, in bytes. Must be set to
    /// `sizeof(struct perf_event_attr)` from the kernel's perspective;
    /// we use 128 for broad compatibility.
    size:        u32,
    /// Hardware/software/cache event selector. One of `PERF_COUNT_*`.
    config:      u64,
    /// For sampling: period or frequency. Zero for pure counting.
    sample_period: u64,
    /// Which data to include in sampling records. Zero = count only.
    sample_type: u64,
    /// Format for `read()` result. We use 0x6 = TIME_ENABLED | TIME_RUNNING.
    read_format: u64,
    /// Packed bitfield. Key bits:
    ///   bit 0 = disabled    (set to 1 to start disabled, then ENABLE via ioctl)
    ///   bit 5 = exclude_kernel (don't count in kernel mode)
    ///   bit 6 = exclude_hv
    ///   bit 7 = exclude_idle
    flags:       u64,
    /// Sampling: wakeup every N events or bytes.
    wakeup:      u32,
    /// Breakpoint type (BP events only).
    bp_type:     u32,
    /// Extended config (cache events use this). Two 32-bit sub-fields packed.
    config1:     u64,
    /// Extended config 2.
    config2:     u64,
    /// Branch sample type (branch stack events).
    branch_sample_type: u64,
    /// Register mask for user-space register capture.
    sample_regs_user:   u64,
    /// Stack size for user-space stack capture.
    sample_stack_user:  u32,
    /// Clock ID (CLOCK_MONOTONIC etc.) for timestamps.
    clockid:     i32,
    /// Register mask for intr-time register capture.
    sample_regs_intr:   u64,
    /// Aux area watermark.
    aux_watermark:      u32,
    /// Max stack depth for stack traces.
    sample_max_stack:   u16,
    _reserved2:  u16,
    /// Aux sample size.
    aux_sample_size:    u32,
    _reserved3:  u32,
}

impl PerfEventAttr {
    fn zeroed() -> Self {
        // SAFETY: all-zero is a valid (and meaningful) initial value for
        // perf_event_attr — the kernel documents this.
        unsafe { std::mem::zeroed() }
    }
}

// PERF_TYPE_* constants
const PERF_TYPE_HARDWARE: u32 = 0;
const PERF_TYPE_SOFTWARE: u32 = 1;

// PERF_COUNT_HW_* constants
const PERF_COUNT_HW_CPU_CYCLES:     u64 = 0;
const PERF_COUNT_HW_INSTRUCTIONS:   u64 = 1;
const PERF_COUNT_HW_CACHE_MISSES:   u64 = 3; // last-level cache misses
const PERF_COUNT_HW_BRANCH_MISSES:  u64 = 5;

// PERF_COUNT_SW_* constants
const PERF_COUNT_SW_CONTEXT_SWITCHES: u64 = 3;
const PERF_COUNT_SW_PAGE_FAULTS_MIN:  u64 = 5;
const PERF_COUNT_SW_PAGE_FAULTS_MAJ:  u64 = 6;
const PERF_COUNT_SW_CPU_MIGRATIONS:   u64 = 4;

// read_format: include time_enabled and time_running so we can scale when
// the counter was multiplexed.
const PERF_FORMAT_TOTAL_TIME_ENABLED: u64 = 0x2;
const PERF_FORMAT_TOTAL_TIME_RUNNING: u64 = 0x4;

// Flags bits
const PERF_ATTR_DISABLED:      u64 = 1 << 0;
const PERF_ATTR_INHERIT:       u64 = 1 << 1;
const PERF_ATTR_EXCLUDE_IDLE:  u64 = 1 << 7;

// ioctl numbers for perf_event_open file descriptors
const PERF_EVENT_IOC_ENABLE:  libc::c_ulong = 0x2400;
const PERF_EVENT_IOC_DISABLE: libc::c_ulong = 0x2401;
const PERF_EVENT_IOC_RESET:   libc::c_ulong = 0x2403;

// Flags for perf_event_open
const PERF_FLAG_FD_CLOEXEC: libc::c_ulong = 1 << 3;

// ── Scaled read result ────────────────────────────────────────────────────────

/// Data returned by `read(fd, …)` when `read_format` includes TIME_ENABLED
/// and TIME_RUNNING.
#[repr(C)]
struct PerfReadValue {
    value:        u64,
    time_enabled: u64,
    time_running: u64,
}

impl PerfReadValue {
    /// Scaled count, accounting for multiplexing.
    /// If `time_running == 0`, returns 0 (counter never ran).
    fn scaled(&self) -> u64 {
        if self.time_running == 0 {
            return 0;
        }
        if self.time_running == self.time_enabled {
            return self.value;
        }
        // Scale: value * (enabled / running) — use u128 intermediate to avoid overflow.
        let v   = self.value as u128;
        let en  = self.time_enabled as u128;
        let run = self.time_running as u128;
        ((v * en) / run) as u64
    }
}

// ── PmuSnapshot ───────────────────────────────────────────────────────────────

/// A snapshot of PMU counters at a point in time.
///
/// Fields are `None` when the corresponding counter could not be opened
/// (permission denied, unsupported by hardware, or PMU not compiled in).
#[derive(Debug, Clone, Default)]
pub struct PmuSnapshot {
    // Hardware counters
    /// CPU cycles elapsed.
    pub cycles:         Option<u64>,
    /// Retired instructions.
    pub instructions:   Option<u64>,
    /// Instructions per cycle (IPC = instructions / cycles). ≥ 1.0 is good.
    pub ipc:            Option<f64>,
    /// Last-level cache (LLC) misses.
    pub llc_misses:     Option<u64>,
    /// Branch mispredictions.
    pub branch_misses:  Option<u64>,

    // Software counters (process-level; no privilege required)
    /// Context switches (voluntary + involuntary).
    pub context_switches: Option<u64>,
    /// Minor page faults (no I/O needed).
    pub page_faults_min:  Option<u64>,
    /// Major page faults (disk I/O needed).
    pub page_faults_maj:  Option<u64>,
    /// CPU migrations (process moved to a different CPU).
    pub cpu_migrations:   Option<u64>,

    /// Duration over which the counters were sampled.
    pub sample_duration:  Duration,

    /// Whether hardware counters required (and had) elevated privilege.
    pub hw_available: bool,

    /// Human-readable note about access level (e.g. paranoid setting).
    pub access_note: Option<String>,
}

impl PmuSnapshot {
    /// Format as a compact summary suitable for inclusion in the LLM context.
    pub fn to_context_string(&self) -> String {
        let mut out = String::from("PMU counters:\n");

        let sample_ms = self.sample_duration.as_millis();
        out.push_str(&format!("  Sample duration: {sample_ms} ms\n"));

        if self.hw_available {
            if let Some(c) = self.cycles {
                out.push_str(&format!("  CPU cycles:          {:>14}\n", fmt_large(c)));
            }
            if let Some(i) = self.instructions {
                out.push_str(&format!("  Instructions:        {:>14}\n", fmt_large(i)));
            }
            if let Some(ipc) = self.ipc {
                let quality = if ipc >= 2.0 { "good" } else if ipc >= 1.0 { "ok" } else { "low — possible stall" };
                out.push_str(&format!("  IPC:                 {ipc:.2}  ({quality})\n"));
            }
            if let Some(m) = self.llc_misses {
                out.push_str(&format!("  LLC cache misses:    {:>14}\n", fmt_large(m)));
            }
            if let Some(b) = self.branch_misses {
                out.push_str(&format!("  Branch mispredicts:  {:>14}\n", fmt_large(b)));
            }
        } else {
            out.push_str("  Hardware counters: unavailable");
            if let Some(ref note) = self.access_note {
                out.push_str(&format!(" ({note})"));
            }
            out.push('\n');
        }

        // Software counters
        if let Some(cs) = self.context_switches {
            out.push_str(&format!("  Context switches:    {:>14}\n", fmt_large(cs)));
        }
        if let Some(mf) = self.page_faults_maj {
            out.push_str(&format!("  Major page faults:   {:>14}", fmt_large(mf)));
            if mf > 100 {
                out.push_str("  ← high, check for swap pressure");
            }
            out.push('\n');
        }
        if let Some(mi) = self.page_faults_min {
            out.push_str(&format!("  Minor page faults:   {:>14}\n", fmt_large(mi)));
        }
        if let Some(mg) = self.cpu_migrations {
            out.push_str(&format!("  CPU migrations:      {:>14}\n", fmt_large(mg)));
        }

        out
    }
}

/// Format a large integer with thousands separators (underscore-style).
fn fmt_large(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::new();
    for (i, ch) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 { result.push('_'); }
        result.push(ch);
    }
    result.chars().rev().collect()
}

// ── Counter opening helpers ───────────────────────────────────────────────────

/// Build a `perf_event_attr` for a hardware or software counter.
///
/// `pid = 0` means the calling process.
/// `pid = -1` means system-wide (requires permission).
/// `cpu = -1` means all CPUs (only valid when `pid != -1`).
/// `cpu = N`  means CPU N specifically.
fn make_attr(type_: u32, config: u64, system_wide: bool) -> PerfEventAttr {
    let mut attr = PerfEventAttr::zeroed();
    attr.type_       = type_;
    attr.size        = 128; // perf_event_attr as of kernel 3.12
    attr.config      = config;
    attr.read_format = PERF_FORMAT_TOTAL_TIME_ENABLED | PERF_FORMAT_TOTAL_TIME_RUNNING;
    // Start disabled so we can reset before enabling.
    attr.flags       = PERF_ATTR_DISABLED;
    if !system_wide {
        attr.flags |= PERF_ATTR_INHERIT; // inherit to child processes/threads
    } else {
        attr.flags |= PERF_ATTR_EXCLUDE_IDLE; // don't count idle cycles on system-wide
    }
    attr
}

/// Open a single perf counter. Returns `None` on permission error or if
/// hardware does not support the event.
fn open_counter(
    type_:       u32,
    config:      u64,
    pid:         libc::pid_t,
    cpu:         libc::c_int,
) -> Option<OwnedFd> {
    if SYS_PERF_EVENT_OPEN < 0 {
        return None; // unsupported architecture
    }

    let attr = make_attr(type_, config, pid == -1);

    // SAFETY: `attr` is a valid, initialised perf_event_attr with correct
    // `size` field; pid/cpu are valid values; -1 means "no group"; flags are
    // valid. The returned fd is owned and will be closed on drop.
    let fd = unsafe {
        libc::syscall(
            SYS_PERF_EVENT_OPEN,
            &attr as *const PerfEventAttr,
            pid,
            cpu,
            -1i32,               // group_fd: no group
            PERF_FLAG_FD_CLOEXEC,
        )
    };

    if fd < 0 {
        let err = std::io::Error::last_os_error();
        match err.raw_os_error() {
            // EACCES / EPERM: paranoid setting too high. Not a bug.
            Some(libc::EACCES) | Some(libc::EPERM) => {}
            // ENOENT / EOPNOTSUPP: event not supported on this CPU.
            Some(libc::ENOENT) | Some(libc::EOPNOTSUPP) => {}
            // EBUSY: the PMU is exclusively used by another process.
            Some(libc::EBUSY) => {}
            _ => {
                log::debug!("perf_event_open(type={type_}, config={config:#x}, pid={pid}, cpu={cpu}) failed: {err}");
            }
        }
        return None;
    }

    // SAFETY: fd is positive and we are now the owner of this file descriptor.
    Some(unsafe { OwnedFd::from_raw_fd(fd as libc::c_int) })
}

/// Reset, enable, sleep for `duration`, disable, then read a counter.
/// Returns `None` if the fd is invalid.
fn sample_counter(fd: &OwnedFd, duration: Duration) -> Option<u64> {
    let raw = fd.as_raw_fd();

    // SAFETY: valid open perf fd; ioctl codes are correct.
    unsafe {
        if libc::ioctl(raw, PERF_EVENT_IOC_RESET,   0) < 0 { return None; }
        if libc::ioctl(raw, PERF_EVENT_IOC_ENABLE,  0) < 0 { return None; }
    }

    std::thread::sleep(duration);

    unsafe {
        if libc::ioctl(raw, PERF_EVENT_IOC_DISABLE, 0) < 0 { return None; }
    }

    let mut val = PerfReadValue { value: 0, time_enabled: 0, time_running: 0 };
    // SAFETY: `val` is correctly sized for the read_format we requested.
    let nread = unsafe {
        libc::read(
            raw,
            &mut val as *mut PerfReadValue as *mut libc::c_void,
            std::mem::size_of::<PerfReadValue>(),
        )
    };

    if nread < std::mem::size_of::<PerfReadValue>() as isize {
        return None;
    }

    Some(val.scaled())
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Read the kernel's `perf_event_paranoid` setting.
///
/// Returns `None` if the file cannot be read (e.g. SELinux-restricted sysctl).
pub fn read_paranoid() -> Option<i32> {
    fs::read_to_string("/proc/sys/kernel/perf_event_paranoid")
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// Take a PMU snapshot.
///
/// `sample_duration` is how long to count before reading each counter.
/// 250 ms is a good balance between responsiveness and statistical accuracy;
/// use 1000 ms for more precise IPC estimates.
///
/// Hardware counters are attempted system-wide first (pid=-1, cpu=0).
/// If that fails (permission), we fall back to process-level (pid=0, cpu=-1)
/// to get at least software counters.
///
/// Never panics — all failures degrade to `None` fields.
pub fn snapshot(sample_duration: Duration) -> PmuSnapshot {
    let paranoid = read_paranoid();
    let can_syswide = paranoid.map(|p| p <= 0).unwrap_or(false);

    let mut snap = PmuSnapshot {
        sample_duration,
        hw_available: false,
        access_note: paranoid.map(|p| {
            format!(
                "perf_event_paranoid={p}; hw counters need ≤0 or CAP_PERFMON"
            )
        }),
        ..Default::default()
    };

    // ── Hardware counters (system-wide if permitted, else per-process) ─────────
    let (hw_pid, hw_cpu): (libc::pid_t, libc::c_int) =
        if can_syswide { (-1, 0) } else { (0, -1) };

    let fd_cycles  = open_counter(PERF_TYPE_HARDWARE, PERF_COUNT_HW_CPU_CYCLES,     hw_pid, hw_cpu);
    let fd_instr   = open_counter(PERF_TYPE_HARDWARE, PERF_COUNT_HW_INSTRUCTIONS,   hw_pid, hw_cpu);
    let fd_llc     = open_counter(PERF_TYPE_HARDWARE, PERF_COUNT_HW_CACHE_MISSES,   hw_pid, hw_cpu);
    let fd_branch  = open_counter(PERF_TYPE_HARDWARE, PERF_COUNT_HW_BRANCH_MISSES,  hw_pid, hw_cpu);

    // ── Software counters (always process-level — no privilege needed) ─────────
    let fd_cs  = open_counter(PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CONTEXT_SWITCHES, 0, -1);
    let fd_pfm = open_counter(PERF_TYPE_SOFTWARE, PERF_COUNT_SW_PAGE_FAULTS_MAJ,  0, -1);
    let fd_pfn = open_counter(PERF_TYPE_SOFTWARE, PERF_COUNT_SW_PAGE_FAULTS_MIN,  0, -1);
    let fd_mig = open_counter(PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_MIGRATIONS,   0, -1);

    snap.hw_available = fd_cycles.is_some() || fd_instr.is_some();
    if snap.hw_available {
        snap.access_note = None;
    }

    // Sample all open counters concurrently by sleeping once.
    // Reset + enable phase (before sleep)
    for fd in [&fd_cycles, &fd_instr, &fd_llc, &fd_branch,
               &fd_cs, &fd_pfm, &fd_pfn, &fd_mig].into_iter().flatten()
    {
        let raw = fd.as_raw_fd();
        unsafe {
            libc::ioctl(raw, PERF_EVENT_IOC_RESET,  0);
            libc::ioctl(raw, PERF_EVENT_IOC_ENABLE, 0);
        }
    }

    std::thread::sleep(sample_duration);

    // Disable + read phase (after sleep)
    fn read_fd(fd: Option<&OwnedFd>) -> Option<u64> {
        let fd = fd?;
        let raw = fd.as_raw_fd();
        unsafe { libc::ioctl(raw, PERF_EVENT_IOC_DISABLE, 0); }

        let mut val = PerfReadValue { value: 0, time_enabled: 0, time_running: 0 };
        let nread = unsafe {
            libc::read(
                raw,
                &mut val as *mut _ as *mut libc::c_void,
                std::mem::size_of::<PerfReadValue>(),
            )
        };
        if nread < std::mem::size_of::<PerfReadValue>() as isize {
            return None;
        }
        Some(val.scaled())
    }

    snap.cycles        = read_fd(fd_cycles.as_ref());
    snap.instructions  = read_fd(fd_instr.as_ref());
    snap.llc_misses    = read_fd(fd_llc.as_ref());
    snap.branch_misses = read_fd(fd_branch.as_ref());

    snap.context_switches = read_fd(fd_cs.as_ref());
    snap.page_faults_maj  = read_fd(fd_pfm.as_ref());
    snap.page_faults_min  = read_fd(fd_pfn.as_ref());
    snap.cpu_migrations   = read_fd(fd_mig.as_ref());

    // Derived: IPC
    if let (Some(c), Some(i)) = (snap.cycles, snap.instructions) {
        if c > 0 {
            snap.ipc = Some(i as f64 / c as f64);
        }
    }

    snap
}

/// Quick (250 ms) PMU snapshot — suitable for the LLM context and status command.
pub fn quick_snapshot() -> PmuSnapshot {
    snapshot(Duration::from_millis(250))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_does_not_panic() {
        // Even with no permissions, should return a valid (possibly empty) snapshot.
        let snap = snapshot(Duration::from_millis(50));
        // Software counters should always work.
        // (context_switches may be Some on Linux even without privs.)
        println!("{}", snap.to_context_string());
    }

    #[test]
    fn fmt_large_works() {
        assert_eq!(fmt_large(0),          "0");
        assert_eq!(fmt_large(1_000),      "1_000");
        assert_eq!(fmt_large(1_000_000),  "1_000_000");
        assert_eq!(fmt_large(1_234_567),  "1_234_567");
    }
}
