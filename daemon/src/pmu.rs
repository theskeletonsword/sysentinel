// SPDX-License-Identifier: Apache-2.0
//!
//! Performance Monitoring Unit (PMU) reader via the Linux `perf_event_open`
//! syscall interface, with a dispatcher for heterogeneous (hybrid) CPUs.
//!
//! # Provenance
//!
//! This repository is Apache-2.0 and the Linux kernel is GPL-2.0, so the two
//! things this file needs are sourced separately and deliberately:
//!
//! - **The syscall ABI** — constants and the `perf_event_attr` layout — comes
//!   from `include/uapi/linux/perf_event.h`, which is licensed
//!   `GPL-2.0 WITH Linux-syscall-note`. That exception states that using kernel
//!   services through normal system calls is not a derived work; calling
//!   `perf_event_open` from an Apache-2.0 program is exactly that. There is no
//!   way to "clean room" a syscall number, and no need to: an interface
//!   contract is not the implementation behind it.
//! - **Everything about hybrid CPUs** comes from [`crate::coretype`], which is
//!   derived clean-room from processor vendors' own architecture manuals
//!   (Intel SDM `CPUID.1AH`, Arm ARM `MIDR_EL1`) and confirmed against the
//!   silicon. No kernel source informs it.
//!
//! The privilege rules below are observable behaviour, stated in our own words
//! and — more to the point — never relied upon: the code probes instead.
//!
//! # Hybrid dispatch — two independent strategies
//!
//! A hybrid CPU puts two microarchitectures in one package, with *different*
//! counter hardware. One aggregate IPC across both is a weighted average of two
//! unrelated populations: a busy E-core cluster and an idle P-core cluster
//! average out to a number describing neither. So the counters have to be
//! attributed per core type, and there are two ways to do it:
//!
//! **A — per-CPU grouping (preferred).** System-wide counting opens one fd per
//! CPU anyway. [`crate::coretype`] says which cluster each CPU belongs to, so
//! the fds are simply bucketed by cluster and summed. This needs *no* hybrid
//! support from the kernel at all: it uses the plain event encoding that every
//! kernel since 2009 understands, and works on any vendor whose manual we can
//! read. It also stays correct on a kernel too old to split the PMUs, which is
//! precisely where asking the kernel would fail.
//!
//! **B — PMU-typed events (fallback).** When only per-process counting is
//! permitted, events are opened with `cpu = -1` and there is no per-CPU fd to
//! bucket. Attribution then has to come from the kernel, by naming the owning
//! PMU in the event: `config = (pmu_type << PERF_PMU_TYPE_SHIFT) | event`. The
//! kernel counts such an event only while the task runs on a CPU that PMU owns.
//! Older kernels reject the encoding, in which case the split is reported as
//! unavailable rather than faked.
//!
//! Both were confirmed on an i9-14900HX (`cpu_core` type 4 on CPUs 0-15,
//! `cpu_atom` type 10 on CPUs 16-31), where CPUID.1AH independently reports
//! `CORE_TYPE` `40H` on 0-15 and `20H` on 16-31 — two sources agreeing, which
//! is evidence neither gives alone. A `cpu_core` event opened on an E-core CPU
//! fails `ENOENT`, so strategy B only ever opens a domain on the CPUs it owns.
//!
//! # Privilege — the paranoid ladder
//!
//! `/proc/sys/kernel/perf_event_paranoid` gates measurement through two
//! independent checks — one for system-wide (CPU-scoped) events, one for
//! counting kernel-mode execution:
//!
//! | paranoid | system-wide events | kernel-mode counting |
//! |----------|--------------------|----------------------|
//! | `-1`     | yes                | yes                  |
//! | `0`      | yes                | yes                  |
//! | `1`      | **no**             | yes                  |
//! | `2`      | **no**             | **no** — `exclude_kernel` required |
//!
//! **Upstream's default is 2**, so the restricted rung is the normal case on a
//! stock kernel, not an edge case — and note that it is also the rung where
//! hybrid strategy A becomes unavailable. (Fedora ships `-1`.) There is no `3`
//! row upstream; Debian and Ubuntu carry a downstream patch that treats higher
//! values as "refuse `perf_event_open` outright". `CAP_PERFMON` (kernel ≥ 5.8)
//! or `CAP_SYS_ADMIN` bypasses every row.
//!
//! [`snapshot`] does not predict from the sysctl — it walks a ladder and keeps
//! the highest rung that actually opens. Probing is what makes `CAP_PERFMON`
//! work at `paranoid = 2`, where the sysctl alone would say no, and what makes
//! the downstream `3` behaviour need no special case:
//!
//! 1. [`PmuAccess::SystemWide`] — `pid = -1`, one fd per CPU, kernel counted.
//! 2. [`PmuAccess::PerProcessKernel`] — `pid = 0`, kernel counted.
//! 3. [`PmuAccess::PerProcessUser`] — `pid = 0`, `exclude_kernel = 1`.
//! 4. [`PmuAccess::Denied`] — no hardware counters. Software counters are still
//!    attempted; under the downstream `3` patch they fail too.
//!
//! Each rung means something different by "IPC", so [`PmuSnapshot::access`]
//! travels with the numbers. Every rung degrades to `None` fields — never an
//! error, never a panic.
//!
//! Grant hardware counters without running as root by adding
//! `AmbientCapabilities=CAP_PERFMON` to the systemd unit.
//!
//! # No external dependencies
//!
//! `perf_event_open` is called directly via `libc::syscall`. No `perf-event`
//! crate and no libpfm.

use crate::coretype::{self, CoreClass};
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

/// `struct perf_event_attr` — the syscall ABI, trimmed to the fields we use.
///
/// The kernel accepts any size from a known ABI revision and zero-fills the
/// fields beyond it, so a shorter struct is fine — but `attr.size` must match
/// this struct exactly, because the kernel copies that many bytes *out of it*.
/// This declaration ends at `__reserved_3` (120 bytes); the later `sig_data`
/// and `config3` fields are ones we never set.
#[repr(C)]
struct PerfEventAttr {
    /// Event type. One of `PERF_TYPE_*`.
    type_:       u32,
    /// Size of this structure, in bytes, from the kernel's perspective.
    size:        u32,
    /// Event selector. Under hybrid strategy B the owning PMU's type goes in
    /// bits 63:32 — see [`PERF_PMU_TYPE_SHIFT`].
    config:      u64,
    /// For sampling: period or frequency. Zero for pure counting.
    sample_period: u64,
    /// Which data to include in sampling records. Zero = count only.
    sample_type: u64,
    /// Format for `read()`. We use 0x6 = TIME_ENABLED | TIME_RUNNING.
    read_format: u64,
    /// Packed bitfield. Key bits:
    ///   bit 0 = disabled       (start disabled, then ENABLE via ioctl)
    ///   bit 1 = inherit        (count children; invalid on CPU-scoped events)
    ///   bit 5 = exclude_kernel (don't count kernel-mode execution)
    ///   bit 6 = exclude_hv
    ///   bit 7 = exclude_idle (never set — see `make_attr`)
    flags:       u64,
    /// Sampling: wakeup every N events or bytes.
    wakeup:      u32,
    /// Breakpoint type (BP events only).
    bp_type:     u32,
    /// Extended config (cache events use this).
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
        // perf_event_attr — the ABI documents this.
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
const PERF_COUNT_SW_CPU_MIGRATIONS:   u64 = 4;
const PERF_COUNT_SW_PAGE_FAULTS_MIN:  u64 = 5;
const PERF_COUNT_SW_PAGE_FAULTS_MAJ:  u64 = 6;

/// Hybrid strategy B selector: `config = (pmu_type << 32) | event`.
/// A PMU type of 0 selects the one and only core PMU (the plain encoding).
const PERF_PMU_TYPE_SHIFT: u32 = 32;

// Ask for both timing words, so a multiplexed counter can be corrected. The
// buffer `read()` returns then has three words; see `PerfReadValue`.
//
// These are bits 0 and 1, and getting them wrong is silent and vicious. Bit 2
// selects the event identifier instead, so asking for 0x2|0x4 shifts the layout
// and leaves the third word holding an id — a small, ever-incrementing integer.
// Dividing by that as though it were a duration produced counts hundreds of
// times larger than the silicon can issue.
const PERF_FORMAT_TOTAL_TIME_ENABLED: u64 = 1 << 0;
const PERF_FORMAT_TOTAL_TIME_RUNNING: u64 = 1 << 1;

// Flags bits
const PERF_ATTR_DISABLED:       u64 = 1 << 0;
const PERF_ATTR_INHERIT:        u64 = 1 << 1;
const PERF_ATTR_EXCLUDE_KERNEL: u64 = 1 << 5;

// ioctl numbers for perf_event_open file descriptors
const PERF_EVENT_IOC_ENABLE:  libc::c_ulong = 0x2400;
const PERF_EVENT_IOC_DISABLE: libc::c_ulong = 0x2401;
const PERF_EVENT_IOC_RESET:   libc::c_ulong = 0x2403;

// Flags for perf_event_open
const PERF_FLAG_FD_CLOEXEC: libc::c_ulong = 1 << 3;

/// Capability bit numbers, as they appear in `/proc/self/status` `CapEff`.
const CAP_SYS_ADMIN: u32 = 21;
const CAP_PERFMON:   u32 = 38;

/// The hardware events we sample, in a fixed order. Indices into
/// [`DomainFds::fds`], so the order is load-bearing.
const HW_EVENTS: [u64; 4] = [
    PERF_COUNT_HW_CPU_CYCLES,
    PERF_COUNT_HW_INSTRUCTIONS,
    PERF_COUNT_HW_CACHE_MISSES,
    PERF_COUNT_HW_BRANCH_MISSES,
];
const EV_CYCLES: usize = 0;
const EV_INSTR:  usize = 1;
const EV_LLC:    usize = 2;
const EV_BRANCH: usize = 3;

// ── Scaled read result ────────────────────────────────────────────────────────

/// Coverage below which an *absolute* count is not worth reporting.
///
/// PMU counters are multiplexed when more events are wanted than the hardware
/// has counters, and the kernel reports both durations so the count can be
/// scaled back up. That correction is sound for a counter that ran
/// for most of the window; applied to one that barely ran it turns a thin
/// sample into a confident-looking number.
///
/// Ratios survive what totals cannot: IPC is instructions ÷ cycles, and when
/// both were multiplexed alike the scale factor cancels. So below this
/// threshold the absolute counts are withheld and the IPC is kept, rather than
/// discarding a usable measurement or publishing an unsound one. An eighth
/// still admits the ordinary 2-3× correction from counter contention.
const MIN_RUNNING_RATIO: f64 = 0.125;

/// One counter reading: the (possibly multiplexing-corrected) value, and how
/// much of the sampling window it was really running for.
#[derive(Debug, Clone, Copy)]
struct Reading {
    value:    u64,
    /// `running_ns / enabled_ns`, in `0.0..=1.0`. 1.0 means no correction.
    coverage: f64,
}

/// The three-word buffer `read(fd, …)` hands back for the `read_format` we ask
/// for. Both times are nanoseconds, and the names say so — `enabled_ns` is how
/// long the event was armed, `running_ns` how much of that it was actually on
/// the hardware. They differ only when the PMU was multiplexed.
#[repr(C)]
struct PerfReadValue {
    raw:        u64,
    enabled_ns: u64,
    running_ns: u64,
}

impl PerfReadValue {
    /// Scaled count, accounting for multiplexing.
    ///
    /// `None` when `running_ns == 0`: open, but never ran. On a hybrid CPU
    /// that is the ordinary state of a cluster nothing was scheduled on, and it
    /// must not be reported as a measured zero — "the E-cores retired no
    /// instructions" and "the E-cores were never sampled" are different claims,
    /// and only one of them is evidence.
    ///
    /// The returned [`Reading`] also carries `coverage` — the fraction of the
    /// window the counter really ran for. The kernel reports both durations so
    /// a multiplexed counter can be scaled up, but that
    /// correction is only trustworthy while the sample is representative, and
    /// the caller needs to know which it has. See [`MIN_RUNNING_RATIO`].
    fn scaled(&self) -> Option<Reading> {
        if self.running_ns == 0 || self.enabled_ns == 0 {
            return None;
        }
        let coverage =
            (self.running_ns as f64 / self.enabled_ns as f64).clamp(0.0, 1.0);
        if self.running_ns >= self.enabled_ns {
            return Some(Reading { value: self.raw, coverage: 1.0 });
        }
        // Scale by enabled/running — u128 intermediate so a long window on a
        // wide counter cannot overflow.
        let v   = self.raw as u128;
        let en  = self.enabled_ns as u128;
        let run = self.running_ns as u128;
        Some(Reading { value: ((v * en) / run) as u64, coverage })
    }
}

// ── The dispatcher ────────────────────────────────────────────────────────────

/// How this snapshot attributes counters to core types.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum HybridStrategy {
    /// Not a hybrid part (or nothing to split): one domain, plain encoding.
    #[default]
    Uniform,
    /// Strategy A — per-CPU fds bucketed by the silicon's own core-type map.
    /// Needs no kernel hybrid support.
    PerCpuGrouping,
    /// Strategy B — events tagged with the owning PMU's type, for per-process
    /// counting where there is no per-CPU fd to bucket.
    PmuTyped,
    /// Hybrid hardware, but neither strategy is available at this privilege
    /// rung and kernel. Counters are reported combined.
    Unavailable,
}

impl HybridStrategy {
    pub fn describe(&self) -> &'static str {
        match self {
            HybridStrategy::Uniform        => "uniform cores",
            HybridStrategy::PerCpuGrouping => "per-CPU fds grouped by silicon core type",
            HybridStrategy::PmuTyped       => "PMU-typed events",
            HybridStrategy::Unavailable    => "hybrid, but not separable here",
        }
    }
}

/// One counting domain: a set of CPUs whose counters are summed together.
#[derive(Debug, Clone)]
pub struct PmuDomain {
    /// Human label — from the silicon where known, else the sysfs PMU name.
    pub label: String,
    /// The silicon's verdict for these CPUs, when a vendor interface answered.
    pub class: Option<CoreClass>,
    /// sysfs PMU device name, when one owns exactly these CPUs.
    pub pmu_name: Option<String>,
    /// `pmu_type << PERF_PMU_TYPE_SHIFT`, for strategy B. `None` means the
    /// plain encoding.
    pub config_base: Option<u64>,
    /// CPUs in this domain, ascending.
    pub cpus: Vec<u32>,
}

impl PmuDomain {
    /// Human account of how this domain was identified: the vendor's name for
    /// the core type, the owning PMU, or both when the two sources agree.
    fn provenance(&self) -> Option<String> {
        match (self.class, &self.pmu_name) {
            (Some(c), Some(p)) => Some(format!("{} · {p}", c.label())),
            (Some(c), None)    => Some(c.label()),
            (None,    Some(p)) => Some(p.clone()),
            (None,    None)    => None,
        }
    }
}

/// A core PMU as sysfs describes it: name, type, and the CPUs it owns.
#[derive(Debug, Clone)]
struct SysfsPmu {
    name:  String,
    type_: u32,
    cpus:  Vec<u32>,
}

/// Enumerate core PMUs. A core PMU is exactly a device publishing a `cpus`
/// file; uncore, cstate, RAPL and power PMUs publish `cpumask` instead, so this
/// never mistakes one for a core type.
fn sysfs_core_pmus() -> Vec<SysfsPmu> {
    let mut out = Vec::new();
    let Ok(rd) = fs::read_dir("/sys/bus/event_source/devices") else {
        return out;
    };
    for entry in rd.flatten() {
        let path = entry.path();
        let Ok(cpus_raw) = fs::read_to_string(path.join("cpus")) else {
            continue;
        };
        let cpus = coretype::parse_cpu_list(&cpus_raw);
        if cpus.is_empty() {
            continue;
        }
        let Some(type_) = fs::read_to_string(path.join("type"))
            .ok()
            .and_then(|s| s.trim().parse::<u32>().ok())
        else {
            continue;
        };
        out.push(SysfsPmu {
            name: entry.file_name().to_string_lossy().into_owned(),
            type_,
            cpus,
        });
    }
    out.sort_by(|a, b| b.name.cmp(&a.name)); // `cpu_core` before `cpu_atom`
    out
}

/// The plan for one snapshot: which domains to open, and how.
#[derive(Debug, Clone)]
pub struct PmuPlan {
    pub domains:  Vec<PmuDomain>,
    pub strategy: HybridStrategy,
    /// Whether silicon and sysfs agree on the CPU partition. `None` when only
    /// one of the two had anything to say.
    pub sources_agree: Option<bool>,
    /// One-line summary for the report.
    pub topology: String,
}

/// Build the counting plan for `access`.
///
/// Dispatch order reflects which strategy is *sound* here, not which is
/// convenient: strategy A first because it needs nothing from the kernel, then
/// B, then a combined view rather than a fabricated split.
pub fn plan_for(access: PmuAccess) -> PmuPlan {
    let silicon = coretype::topology();
    let pmus    = sysfs_core_pmus();
    let all_cpus = coretype::online_cpus();

    // Do the two independent sources describe the same partition?
    let sources_agree = if silicon.is_heterogeneous() && pmus.len() >= 2 {
        let mut a: Vec<Vec<u32>> = silicon.clusters.iter().map(|c| c.cpus.clone()).collect();
        let mut b: Vec<Vec<u32>> = pmus.iter().map(|p| p.cpus.clone()).collect();
        a.sort();
        b.sort();
        Some(a == b)
    } else {
        None
    };

    // The combined, always-valid fallback.
    let uniform = |strategy: HybridStrategy, note: String| PmuPlan {
        domains: vec![PmuDomain {
            label:       "all cores".to_string(),
            class:       None,
            pmu_name:    pmus.first().map(|p| p.name.clone()),
            config_base: None,
            cpus:        all_cpus.clone(),
        }],
        strategy,
        sources_agree,
        topology: note,
    };

    if !silicon.is_heterogeneous() && pmus.len() < 2 {
        return uniform(
            HybridStrategy::Uniform,
            format!("uniform ({} CPUs)", all_cpus.len()),
        );
    }

    // ── Strategy A: bucket per-CPU fds by the silicon's core-type map ─────────
    // Only meaningful with CPU-scoped events, which is what system-wide gives.
    if access == PmuAccess::SystemWide && silicon.is_heterogeneous() {
        let domains: Vec<PmuDomain> = silicon
            .clusters
            .iter()
            .map(|c| {
                // Attach the owning PMU's identity when one covers exactly this
                // cluster — useful in the report, not needed for counting.
                let pmu = pmus.iter().find(|p| p.cpus == c.cpus);
                PmuDomain {
                    label:       c.class.short_label(),
                    class:       Some(c.class),
                    pmu_name:    pmu.map(|p| p.name.clone()),
                    config_base: None, // plain encoding: no kernel support needed
                    cpus:        c.cpus.clone(),
                }
            })
            .collect();
        let full: Vec<String> = silicon
            .clusters
            .iter()
            .map(|c| format!("{} ×{}", c.class.label(), c.cpus.len()))
            .collect();
        return PmuPlan {
            topology: format!("hybrid — {} (via {})", full.join(" + "), silicon.source),
            domains,
            strategy: HybridStrategy::PerCpuGrouping,
            sources_agree,
        };
    }

    // ── Strategy B: PMU-typed events, for per-process counting ───────────────
    if pmus.len() >= 2 && access != PmuAccess::Denied {
        let base = (pmus[0].type_ as u64) << PERF_PMU_TYPE_SHIFT;
        let works = open_counter(
            PERF_TYPE_HARDWARE,
            base | PERF_COUNT_HW_CPU_CYCLES,
            match access {
                PmuAccess::SystemWide => {
                    Target::Cpu(pmus[0].cpus.first().copied().unwrap_or(0) as libc::c_int)
                }
                _ => Target::Process,
            },
            access.exclude_kernel(),
        )
        .is_some();

        if works {
            let domains: Vec<PmuDomain> = pmus
                .iter()
                .map(|p| {
                    // Prefer the silicon's name for these CPUs over the kernel's.
                    let class = p.cpus.first().and_then(|c| silicon.class_of(*c));
                    PmuDomain {
                        label: class
                            .map(|c| c.short_label())
                            .unwrap_or_else(|| p.name.clone()),
                        class,
                        pmu_name:    Some(p.name.clone()),
                        config_base: Some((p.type_ as u64) << PERF_PMU_TYPE_SHIFT),
                        cpus:        p.cpus.clone(),
                    }
                })
                .collect();
            let via = if silicon.is_heterogeneous() {
                format!("{} (via {} + PMU types)", silicon.describe(), silicon.source)
            } else {
                let names: Vec<&str> = pmus.iter().map(|p| p.name.as_str()).collect();
                format!("{} (via PMU types)", names.join(" + "))
            };
            return PmuPlan {
                topology: format!("hybrid — {via}"),
                domains,
                strategy: HybridStrategy::PmuTyped,
                sources_agree,
            };
        }
    }

    // ── Hybrid hardware we cannot separate here ──────────────────────────────
    uniform(
        HybridStrategy::Unavailable,
        format!(
            "hybrid — {} (not separable at this access level; reported combined)",
            if silicon.is_heterogeneous() {
                silicon.describe()
            } else {
                pmus.iter().map(|p| p.name.clone()).collect::<Vec<_>>().join(" + ")
            }
        ),
    )
}

// ── Access ladder ─────────────────────────────────────────────────────────────

/// The highest rung of the paranoid ladder that actually opened.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum PmuAccess {
    /// `pid = -1`, one fd per CPU. The whole machine, kernel included.
    /// The only rung where hybrid strategy A is possible.
    SystemWide,
    /// `pid = 0`. This daemon and its children, kernel time included.
    PerProcessKernel,
    /// `pid = 0` with `exclude_kernel` — user-mode only. Where a stock
    /// `paranoid = 2` kernel leaves an uncapable process.
    PerProcessUser,
    /// No hardware counters at all.
    #[default]
    Denied,
}

impl PmuAccess {
    /// What numbers from this rung actually cover. Carried alongside every
    /// snapshot because "IPC" means something different on each one.
    pub fn describe(&self) -> &'static str {
        match self {
            PmuAccess::SystemWide       => "system-wide (all CPUs, kernel included)",
            PmuAccess::PerProcessKernel => "this process only (kernel included)",
            PmuAccess::PerProcessUser   => "this process only (user-mode; exclude_kernel)",
            PmuAccess::Denied           => "denied",
        }
    }

    fn exclude_kernel(&self) -> bool {
        matches!(self, PmuAccess::PerProcessUser)
    }
}

/// Where to attach a counter.
#[derive(Clone, Copy)]
enum Target {
    /// `pid = -1` on one specific CPU — gated by the system-wide check.
    Cpu(libc::c_int),
    /// `pid = 0`, `cpu = -1` — this process wherever it is scheduled.
    Process,
}

/// Read the kernel's `perf_event_paranoid` setting.
///
/// `None` if the file cannot be read (e.g. a restricted sysctl). Only ever used
/// to *explain* an outcome, never to decide one.
pub fn read_paranoid() -> Option<i32> {
    fs::read_to_string("/proc/sys/kernel/perf_event_paranoid")
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// Whether this process holds a capability that bypasses the paranoid ladder.
/// `None` when `CapEff` cannot be read.
pub fn has_perfmon_capability() -> Option<bool> {
    let status = fs::read_to_string("/proc/self/status").ok()?;
    let line = status.lines().find_map(|l| l.strip_prefix("CapEff:"))?;
    let bits = u64::from_str_radix(line.trim(), 16).ok()?;
    Some(bits & (1u64 << CAP_PERFMON) != 0 || bits & (1u64 << CAP_SYS_ADMIN) != 0)
}

/// Walk the ladder and return the highest rung that opens.
///
/// Probing rather than deriving from `perf_event_paranoid` is what makes
/// `CAP_PERFMON` work at `paranoid = 2`, where the sysctl alone would say no.
/// The probe uses the plain event encoding, so the answer is about privilege
/// alone and never about hybrid support.
pub fn probe_access() -> PmuAccess {
    let cpu = coretype::online_cpus().first().copied().unwrap_or(0) as libc::c_int;
    let ev = PERF_COUNT_HW_CPU_CYCLES;
    if open_counter(PERF_TYPE_HARDWARE, ev, Target::Cpu(cpu), false).is_some() {
        return PmuAccess::SystemWide;
    }
    if open_counter(PERF_TYPE_HARDWARE, ev, Target::Process, false).is_some() {
        return PmuAccess::PerProcessKernel;
    }
    if open_counter(PERF_TYPE_HARDWARE, ev, Target::Process, true).is_some() {
        return PmuAccess::PerProcessUser;
    }
    PmuAccess::Denied
}

// ── Counter opening helpers ───────────────────────────────────────────────────

/// Build a `perf_event_attr` for a hardware or software counter.
fn make_attr(type_: u32, config: u64, target: Target, exclude_kernel: bool) -> PerfEventAttr {
    let mut attr = PerfEventAttr::zeroed();
    attr.type_       = type_;
    // Must be the size of *this* struct: the kernel reads exactly this many
    // bytes from it. Hard-coding a larger ABI version (128, which adds
    // `sig_data`) would make it read past the end of our 120-byte object.
    attr.size        = std::mem::size_of::<PerfEventAttr>() as u32;
    attr.config      = config;
    attr.read_format = PERF_FORMAT_TOTAL_TIME_ENABLED | PERF_FORMAT_TOTAL_TIME_RUNNING;
    // Start disabled so we can reset before enabling.
    attr.flags       = PERF_ATTR_DISABLED;
    // `inherit` is rejected on CPU-scoped events, and such an event already
    // sees every task on that CPU, so it is only set for per-process counting.
    //
    // `exclude_idle` is deliberately NOT set. For "how busy is this machine"
    // the idle time is part of the answer: cycles barely tick in a C-state, so
    // a quiet CPU reports few cycles on its own, and that is the honest signal.
    // Leaving the counter running for the whole window also keeps
    // `running_ns == enabled_ns`, so no multiplexing correction is applied
    // where none is warranted.
    if let Target::Process = target {
        attr.flags |= PERF_ATTR_INHERIT;
    }
    if exclude_kernel {
        attr.flags |= PERF_ATTR_EXCLUDE_KERNEL;
    }
    attr
}

/// Open a single perf counter. `None` on permission error, or if the event is
/// unsupported here.
fn open_counter(
    type_:          u32,
    config:         u64,
    target:         Target,
    exclude_kernel: bool,
) -> Option<OwnedFd> {
    if SYS_PERF_EVENT_OPEN < 0 {
        return None; // unsupported architecture
    }

    let attr = make_attr(type_, config, target, exclude_kernel);
    let (pid, cpu): (libc::pid_t, libc::c_int) = match target {
        Target::Cpu(c)  => (-1, c),
        Target::Process => (0, -1),
    };

    // SAFETY: `attr` is a valid, initialised perf_event_attr with a correct
    // `size`; pid/cpu are valid; -1 means "no group"; flags are valid. The
    // returned fd is owned and closed on drop.
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
            // Paranoid setting too high — expected; the caller steps down a rung.
            Some(libc::EACCES) | Some(libc::EPERM) => {}
            // Event unsupported here. Under strategy B, ENOENT is also what a
            // PMU-typed event on the wrong CPU returns, which is how domain/CPU
            // pairing enforces itself.
            Some(libc::ENOENT) | Some(libc::EOPNOTSUPP) | Some(libc::EINVAL) => {}
            // The PMU is held exclusively by another process.
            Some(libc::EBUSY) => {}
            _ => {
                log::debug!(
                    "perf_event_open(type={type_}, config={config:#x}, pid={pid}, cpu={cpu}) failed: {err}"
                );
            }
        }
        return None;
    }

    // SAFETY: fd is positive and we now own this file descriptor.
    Some(unsafe { OwnedFd::from_raw_fd(fd as libc::c_int) })
}

/// Reset + enable. Failures are ignored: a counter that will not arm reads back
/// as never-run and is reported as `None`.
fn arm(fd: &OwnedFd) {
    let raw = fd.as_raw_fd();
    // SAFETY: valid open perf fd; ioctl codes are correct.
    unsafe {
        libc::ioctl(raw, PERF_EVENT_IOC_RESET,  0);
        libc::ioctl(raw, PERF_EVENT_IOC_ENABLE, 0);
    }
}

/// Disable and read one counter. `None` when the read fails or it never ran.
fn disarm_and_read(fd: &OwnedFd) -> Option<Reading> {
    let raw = fd.as_raw_fd();
    // SAFETY: valid open perf fd; ioctl code is correct.
    unsafe {
        libc::ioctl(raw, PERF_EVENT_IOC_DISABLE, 0);
    }

    let mut val = PerfReadValue { raw: 0, enabled_ns: 0, running_ns: 0 };
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
    val.scaled()
}

/// Upper bound on hardware-counter fds held open by one snapshot.
///
/// System-wide counting needs one fd per CPU per event, so a 256-core server
/// would want 1024 and run into `RLIMIT_NOFILE`. The budget comes from the
/// actual soft limit; when it binds, CPUs are sampled with a stride and the
/// result is labelled with its coverage rather than passed off as a total.
fn fd_budget() -> usize {
    let mut lim = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: `lim` is a valid, writable rlimit for the duration of the call.
    let ok = unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) } == 0;
    let soft = if ok { lim.rlim_cur as usize } else { 1024 };
    // Never take more than a quarter of the process's descriptors.
    (soft / 4).clamp(16, 1024)
}

/// Which CPUs of a domain to instrument, given a cap. Returns an evenly-spaced
/// subset when the cap binds, so the sample spreads across the domain instead
/// of crowding onto its lowest CPUs.
fn cpus_within_budget(cpus: &[u32], max_cpus: usize) -> Vec<u32> {
    if max_cpus == 0 {
        return Vec::new();
    }
    if cpus.len() <= max_cpus {
        return cpus.to_vec();
    }
    let stride = cpus.len().div_ceil(max_cpus);
    cpus.iter().step_by(stride).copied().take(max_cpus).collect()
}

// ── Snapshot types ────────────────────────────────────────────────────────────

/// Hardware counters for one core type.
#[derive(Debug, Clone, Default)]
pub struct DomainCounters {
    /// Human label (`P-cores`, `E-cores`, `all cores`).
    pub label: String,
    /// Where this domain's identity came from — the vendor's own name for the
    /// core type and/or the sysfs PMU that owns the CPUs. Shown in the report
    /// so a reader can tell a silicon-derived split from a kernel-derived one.
    pub provenance: Option<String>,
    /// CPU cycles elapsed on this core type.
    pub cycles:        Option<u64>,
    /// Retired instructions on this core type.
    pub instructions:  Option<u64>,
    /// Instructions per cycle for this core type alone.
    pub ipc:           Option<f64>,
    /// Last-level cache misses.
    pub llc_misses:    Option<u64>,
    /// Branch mispredictions.
    pub branch_misses: Option<u64>,
    /// Fraction of the sampling window the counters really ran for, in
    /// `0.0..=1.0`. Below 1.0 the PMU was multiplexed; below
    /// [`MIN_RUNNING_RATIO`] the absolute counts above are withheld and only
    /// [`DomainCounters::ipc`] — which survives multiplexing — is reported.
    pub coverage: Option<f64>,
    /// CPUs actually instrumented, and how many the domain owns. Equal unless
    /// the fd budget forced a stride.
    pub cpus_sampled:  usize,
    pub cpus_total:    usize,
}

impl DomainCounters {
    /// True when the counters opened but never ran — nothing was scheduled on
    /// this core type during the sample. Distinct from a measured zero.
    pub fn never_ran(&self) -> bool {
        self.cycles.is_none() && self.instructions.is_none()
    }

    /// True when only part of the domain's CPUs could be instrumented, so the
    /// totals are a sample rather than a sum.
    pub fn partial(&self) -> bool {
        self.cpus_sampled < self.cpus_total
    }

    /// True when the PMU was multiplexed hard enough that absolute counts were
    /// withheld. The IPC is still meaningful.
    pub fn multiplexed(&self) -> bool {
        self.coverage.is_some_and(|c| c < MIN_RUNNING_RATIO)
    }

    /// One report line for this core type.
    fn render_line(&self) -> String {
        let coverage = if self.partial() {
            format!(" [{} of {} CPUs]", self.cpus_sampled, self.cpus_total)
        } else {
            String::new()
        };
        let via = self
            .provenance
            .as_deref()
            .map(|p| format!("  [{p}]"))
            .unwrap_or_default();
        if self.multiplexed() {
            let pct = self.coverage.unwrap_or(0.0) * 100.0;
            let ipc = self
                .ipc
                .map(|v| format!("IPC {v:.2} ({})", ipc_quality(v)))
                .unwrap_or_else(|| "IPC n/a".to_string());
            return format!(
                "{:<9} {ipc}; PMU multiplexed (counters ran {pct:.2}% of the \
                 window) — absolute counts withheld{coverage}{via}",
                self.label
            );
        }
        if self.never_ran() {
            return format!(
                "{:<9} idle — nothing scheduled during the sample{coverage}{via}",
                self.label
            );
        }
        let ipc = self
            .ipc
            .map(|v| format!("IPC {v:.2} ({})", ipc_quality(v)))
            .unwrap_or_else(|| "IPC n/a".to_string());
        format!(
            "{:<9} {ipc}, {} cycles, {} instr{coverage}{via}",
            self.label,
            self.cycles.map_or_else(|| "n/a".into(), fmt_large),
            self.instructions.map_or_else(|| "n/a".into(), fmt_large),
        )
    }
}

/// A snapshot of PMU counters at a point in time.
///
/// Fields are `None` when the counter could not be opened (permission,
/// unsupported hardware, no PMU) or when it opened but never ran.
#[derive(Debug, Clone, Default)]
pub struct PmuSnapshot {
    // Hardware counters, summed across every core type.
    /// CPU cycles elapsed.
    pub cycles:         Option<u64>,
    /// Retired instructions.
    pub instructions:   Option<u64>,
    /// Instructions per cycle (IPC = instructions / cycles). ≥ 1.0 is good.
    /// On a hybrid CPU this is the machine-wide weighted average; the
    /// per-core-type figures in [`PmuSnapshot::per_domain`] are the ones worth
    /// acting on.
    pub ipc:            Option<f64>,
    /// Last-level cache (LLC) misses.
    pub llc_misses:     Option<u64>,
    /// Branch mispredictions.
    pub branch_misses:  Option<u64>,

    /// Per-core-type breakdown: one entry on a uniform CPU, one per core type
    /// when the dispatcher could separate them.
    pub per_domain: Vec<DomainCounters>,

    // Software counters (process-level; no privilege needed on stock kernels)
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

    /// Whether hardware counters were readable at all.
    pub hw_available: bool,

    /// Which rung of the paranoid ladder produced these numbers.
    pub access: PmuAccess,

    /// How core types were attributed.
    pub strategy: HybridStrategy,

    /// Whether the silicon and the kernel's PMU grouping agreed, when both
    /// had something to say.
    pub sources_agree: Option<bool>,

    /// Topology description for the report.
    pub topology: String,

    /// Human-readable note about access level, when one is warranted.
    pub access_note: Option<String>,
}

impl PmuSnapshot {
    /// Format as a compact summary for the LLM context and `/status`.
    pub fn to_context_string(&self) -> String {
        let mut out = String::from("PMU counters:\n");

        let sample_ms = self.sample_duration.as_millis();
        out.push_str(&format!("  Sample duration: {sample_ms} ms\n"));
        if !self.topology.is_empty() {
            out.push_str(&format!("  CPU topology:    {}\n", self.topology));
        }
        out.push_str(&format!("  Scope:           {}\n", self.access.describe()));
        if self.strategy != HybridStrategy::Uniform {
            out.push_str(&format!("  Core split:      {}\n", self.strategy.describe()));
        }
        // Only worth a line when the two sources actually disagree.
        if self.sources_agree == Some(false) {
            out.push_str(
                "  ⚠ silicon core types and kernel PMU grouping disagree — \
                 counters follow the PMU grouping\n",
            );
        }

        if self.hw_available {
            if let Some(c) = self.cycles {
                out.push_str(&format!("  CPU cycles:          {:>14}\n", fmt_large(c)));
            }
            if let Some(i) = self.instructions {
                out.push_str(&format!("  Instructions:        {:>14}\n", fmt_large(i)));
            }
            if let Some(ipc) = self.ipc {
                out.push_str(&format!("  IPC:                 {ipc:.2}  ({})\n", ipc_quality(ipc)));
            }
            if let Some(m) = self.llc_misses {
                out.push_str(&format!("  LLC cache misses:    {:>14}\n", fmt_large(m)));
            }
            if let Some(b) = self.branch_misses {
                out.push_str(&format!("  Branch mispredicts:  {:>14}\n", fmt_large(b)));
            }

            // The breakdown only says something when there is more than one
            // core type to compare.
            if self.per_domain.len() > 1 {
                out.push_str("  Per core type:\n");
                for d in &self.per_domain {
                    out.push_str(&format!("    {}\n", d.render_line()));
                }
            }
        } else {
            out.push_str("  Hardware counters: unavailable");
            if let Some(ref note) = self.access_note {
                out.push_str(&format!(" ({note})"));
            }
            out.push('\n');
        }

        // A withheld total is a different statement from an absent counter.
        if self.hw_available && self.cycles.is_none() {
            if let Some(ref note) = self.access_note {
                out.push_str(&format!("  Note:            {note}\n"));
            }
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

/// Plain-language reading of an IPC number.
fn ipc_quality(ipc: f64) -> &'static str {
    if ipc >= 2.0 {
        "good"
    } else if ipc >= 1.0 {
        "ok"
    } else {
        "low — possible stall"
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

// ── Sampling ──────────────────────────────────────────────────────────────────

/// Sum a set of readings, treating "never ran" as absent rather than zero.
/// `None` only when nothing in the set produced a reading.
///
/// The summed coverage is the *worst* of the parts: one starved CPU makes the
/// whole domain's total no better than that CPU's.
fn sum_readings(readings: &[Option<Reading>]) -> Option<Reading> {
    let mut total: u64 = 0;
    let mut coverage = f64::INFINITY;
    let mut any = false;
    for r in readings.iter().flatten() {
        total = total.saturating_add(r.value);
        coverage = coverage.min(r.coverage);
        any = true;
    }
    any.then_some(Reading { value: total, coverage })
}

/// Open fds for one domain. `fds[event]` holds one fd per instrumented CPU
/// under strategy A, or exactly one under strategy B / per-process counting.
struct DomainFds {
    domain:       PmuDomain,
    fds:          [Vec<OwnedFd>; HW_EVENTS.len()],
    cpus_sampled: usize,
}

impl DomainFds {
    fn open(domain: &PmuDomain, access: PmuAccess, max_cpus: usize) -> Self {
        // Strategy B tags the event with its PMU; strategy A leaves it plain
        // and gets its attribution from *which CPU* the fd is bound to.
        let base = domain.config_base.unwrap_or(0);
        let exclude_kernel = access.exclude_kernel();

        let mut fds: [Vec<OwnedFd>; HW_EVENTS.len()] = Default::default();
        let mut cpus_sampled = 0;

        match access {
            PmuAccess::SystemWide => {
                let cpus = cpus_within_budget(&domain.cpus, max_cpus);
                cpus_sampled = cpus.len();
                for &cpu in &cpus {
                    for (slot, ev) in HW_EVENTS.iter().enumerate() {
                        if let Some(fd) = open_counter(
                            PERF_TYPE_HARDWARE,
                            base | ev,
                            Target::Cpu(cpu as libc::c_int),
                            exclude_kernel,
                        ) {
                            fds[slot].push(fd);
                        }
                    }
                }
            }
            PmuAccess::PerProcessKernel | PmuAccess::PerProcessUser => {
                // A per-process event follows the task; under strategy B the
                // kernel counts it only while that task runs on a CPU the
                // named PMU owns. Nothing is restricted, so coverage is the
                // whole domain.
                cpus_sampled = domain.cpus.len();
                for (slot, ev) in HW_EVENTS.iter().enumerate() {
                    if let Some(fd) = open_counter(
                        PERF_TYPE_HARDWARE,
                        base | ev,
                        Target::Process,
                        exclude_kernel,
                    ) {
                        fds[slot].push(fd);
                    }
                }
            }
            PmuAccess::Denied => {}
        }

        DomainFds { domain: domain.clone(), fds, cpus_sampled }
    }

    fn arm_all(&self) {
        for slot in &self.fds {
            for fd in slot {
                arm(fd);
            }
        }
    }

    /// Read every fd and fold this domain into its counters.
    ///
    /// Also returns the raw (cycles, instructions) readings. They are withheld
    /// from the public totals when coverage is poor, but the machine-wide IPC
    /// still needs them: a ratio is sound where the absolutes are not.
    fn collect(self) -> (DomainCounters, Option<Reading>, Option<Reading>) {
        let read_slot = |slot: usize| -> Option<Reading> {
            let readings: Vec<Option<Reading>> =
                self.fds[slot].iter().map(disarm_and_read).collect();
            sum_readings(&readings)
        };
        let cycles       = read_slot(EV_CYCLES);
        let instructions = read_slot(EV_INSTR);
        let llc          = read_slot(EV_LLC);
        let branch       = read_slot(EV_BRANCH);

        // IPC first: a ratio of two counters multiplexed alike survives the
        // scaling that makes their absolute values untrustworthy.
        let ipc = match (cycles, instructions) {
            (Some(c), Some(i)) if c.value > 0 => Some(i.value as f64 / c.value as f64),
            _ => None,
        };

        // Worst coverage across the domain's counters decides whether the
        // absolute totals get published at all.
        let coverage = [cycles, instructions, llc, branch]
            .iter()
            .flatten()
            .map(|r| r.coverage)
            .fold(f64::INFINITY, f64::min);
        let coverage = coverage.is_finite().then_some(coverage);
        let trustworthy = coverage.is_none_or(|c| c >= MIN_RUNNING_RATIO);
        let total = |r: Option<Reading>| trustworthy.then(|| r.map(|r| r.value)).flatten();

        let counters = DomainCounters {
            label:      self.domain.label.clone(),
            provenance: self.domain.provenance(),
            cycles:        total(cycles),
            instructions:  total(instructions),
            ipc,
            llc_misses:    total(llc),
            branch_misses: total(branch),
            coverage,
            cpus_sampled:  self.cpus_sampled,
            cpus_total:    self.domain.cpus.len(),
        };
        (counters, cycles, instructions)
    }
}

/// Explain the access outcome in a sentence, or `None` when the snapshot is
/// machine-wide and needs no caveat.
fn access_note(access: PmuAccess, paranoid: Option<i32>) -> Option<String> {
    match access {
        PmuAccess::SystemWide => None,
        PmuAccess::Denied => {
            let cap = has_perfmon_capability().unwrap_or(false);
            Some(match paranoid {
                // No such row upstream: this is the Debian/Ubuntu patch.
                Some(p) if p >= 3 => format!(
                    "perf_event_paranoid={p} — perf_event_open refused outright \
                     (Debian/Ubuntu patch); needs ≤2 or CAP_PERFMON"
                ),
                Some(p) if cap => format!(
                    "perf_event_paranoid={p} and CAP_PERFMON is held, yet nothing \
                     opened — the PMU may be in use, virtualised away, or absent"
                ),
                Some(p) => format!(
                    "perf_event_paranoid={p} — no hw counters; needs CAP_PERFMON"
                ),
                None => "perf_event_paranoid unreadable and no counter opened".to_string(),
            })
        }
        // Not an error, but narrower than a reader assumes — and on a hybrid
        // part it is also what costs us the per-CPU core-type split.
        narrower => Some(match paranoid {
            Some(p) => format!(
                "perf_event_paranoid={p} — scope limited to {}; set it to 0 or \
                 grant CAP_PERFMON for machine-wide counters",
                narrower.describe()
            ),
            None => format!("scope limited to {}", narrower.describe()),
        }),
    }
}

/// Take a PMU snapshot.
///
/// `sample_duration` is how long to count before reading each counter. 250 ms
/// balances responsiveness against statistical accuracy; use 1000 ms for more
/// precise IPC estimates.
///
/// Dispatches on the privilege rung that actually opens, then on the hybrid
/// strategy that rung permits — see the module docs. Never panics: all failures
/// degrade to `None` fields.
pub fn snapshot(sample_duration: Duration) -> PmuSnapshot {
    let paranoid = read_paranoid();
    let access   = probe_access();
    let plan     = plan_for(access);

    let mut snap = PmuSnapshot {
        sample_duration,
        access,
        strategy:      plan.strategy,
        sources_agree: plan.sources_agree,
        topology:      plan.topology.clone(),
        access_note:   access_note(access, paranoid),
        ..Default::default()
    };

    // Each instrumented CPU costs one fd per event; split the budget evenly.
    let max_cpus_per_domain = if access == PmuAccess::SystemWide {
        (fd_budget() / HW_EVENTS.len() / plan.domains.len().max(1)).max(1)
    } else {
        usize::MAX
    };

    let opened: Vec<DomainFds> = plan
        .domains
        .iter()
        .map(|d| DomainFds::open(d, access, max_cpus_per_domain))
        .collect();

    // ── Software counters (process-level; no privilege on stock kernels) ──────
    let fd_cs  = open_counter(PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CONTEXT_SWITCHES, Target::Process, false);
    let fd_pfm = open_counter(PERF_TYPE_SOFTWARE, PERF_COUNT_SW_PAGE_FAULTS_MAJ,  Target::Process, false);
    let fd_pfn = open_counter(PERF_TYPE_SOFTWARE, PERF_COUNT_SW_PAGE_FAULTS_MIN,  Target::Process, false);
    let fd_mig = open_counter(PERF_TYPE_SOFTWARE, PERF_COUNT_SW_CPU_MIGRATIONS,   Target::Process, false);

    // ── One shared window for every counter ───────────────────────────────────
    for d in &opened {
        d.arm_all();
    }
    for fd in [&fd_cs, &fd_pfm, &fd_pfn, &fd_mig].into_iter().flatten() {
        arm(fd);
    }

    std::thread::sleep(sample_duration);

    // Raw sums are kept alongside the published (possibly withheld) totals so
    // the machine-wide IPC survives a multiplexed PMU.
    let mut raw_cycles: Option<u64> = None;
    let mut raw_instrs: Option<u64> = None;
    for (counters, cycles, instrs) in opened.into_iter().map(DomainFds::collect) {
        if let Some(c) = cycles {
            raw_cycles = Some(raw_cycles.unwrap_or(0).saturating_add(c.value));
        }
        if let Some(i) = instrs {
            raw_instrs = Some(raw_instrs.unwrap_or(0).saturating_add(i.value));
        }
        snap.per_domain.push(counters);
    }

    snap.context_switches = fd_cs.as_ref().and_then(disarm_and_read).map(|r| r.value);
    snap.page_faults_maj  = fd_pfm.as_ref().and_then(disarm_and_read).map(|r| r.value);
    snap.page_faults_min  = fd_pfn.as_ref().and_then(disarm_and_read).map(|r| r.value);
    snap.cpu_migrations   = fd_mig.as_ref().and_then(disarm_and_read).map(|r| r.value);

    // ── Machine-wide aggregate across core types ──────────────────────────────
    // Domain totals are already scaled (or withheld); summing them needs no
    // further coverage bookkeeping.
    let pick = |f: fn(&DomainCounters) -> Option<u64>| -> Option<u64> {
        let parts: Vec<Option<u64>> = snap.per_domain.iter().map(f).collect();
        let mut total = 0u64;
        let mut any = false;
        for v in parts.into_iter().flatten() {
            total = total.saturating_add(v);
            any = true;
        }
        any.then_some(total)
    };
    snap.cycles        = pick(|d| d.cycles);
    snap.instructions  = pick(|d| d.instructions);
    snap.llc_misses    = pick(|d| d.llc_misses);
    snap.branch_misses = pick(|d| d.branch_misses);

    // IPC from the raw sums: instructions ÷ cycles is scale-invariant, so it
    // holds even where the absolute counts were withheld as untrustworthy.
    if let (Some(c), Some(i)) = (raw_cycles, raw_instrs) {
        if c > 0 {
            snap.ipc = Some(i as f64 / c as f64);
        }
    }

    // Counters were readable if anything came back — an IPC with withheld
    // totals is still a measurement, and the one this daemon acts on.
    snap.hw_available = snap.ipc.is_some()
        || snap.cycles.is_some()
        || snap.instructions.is_some()
        || snap.per_domain.iter().any(|d| d.ipc.is_some());

    // Say so when the machine-wide totals were withheld, so the absent lines
    // are not read as absent counters.
    if snap.hw_available && snap.cycles.is_none() {
        let worst = snap
            .per_domain
            .iter()
            .filter_map(|d| d.coverage)
            .fold(f64::INFINITY, f64::min);
        if worst.is_finite() {
            snap.access_note = Some(format!(
                "PMU multiplexed — counters ran {:.2}% of the window, so absolute \
                 counts are withheld; IPC is a ratio and still holds",
                worst * 100.0
            ));
        }
    }

    snap
}

/// Quick (250 ms) PMU snapshot — suitable for the LLM context and `/status`.
pub fn quick_snapshot() -> PmuSnapshot {
    snapshot(Duration::from_millis(250))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn snapshot_does_not_panic() {
        // Even with no permissions, this must return a valid snapshot.
        let snap = snapshot(Duration::from_millis(50));
        println!("{}", snap.to_context_string());
    }

    #[test]
    fn fmt_large_works() {
        assert_eq!(fmt_large(0),          "0");
        assert_eq!(fmt_large(1_000),      "1_000");
        assert_eq!(fmt_large(1_000_000),  "1_000_000");
        assert_eq!(fmt_large(1_234_567),  "1_234_567");
    }

    #[test]
    fn plan_domains_partition_their_cpus() {
        for access in [
            PmuAccess::SystemWide,
            PmuAccess::PerProcessKernel,
            PmuAccess::PerProcessUser,
            PmuAccess::Denied,
        ] {
            let plan = plan_for(access);
            assert!(!plan.domains.is_empty(), "{access:?} produced no domain");
            let mut seen = std::collections::HashSet::new();
            for d in &plan.domains {
                assert!(!d.cpus.is_empty(), "{} has no CPUs", d.label);
                for cpu in &d.cpus {
                    assert!(seen.insert(*cpu), "CPU {cpu} in two domains ({access:?})");
                }
            }
            println!("{access:?} → {} [{}]", plan.topology, plan.strategy.describe());
        }
    }

    #[test]
    fn strategy_a_needs_no_pmu_type() {
        // The whole point of per-CPU grouping: attribution comes from which CPU
        // the fd is bound to, so the event stays plainly encoded and no kernel
        // hybrid support is required.
        let plan = plan_for(PmuAccess::SystemWide);
        if plan.strategy != HybridStrategy::PerCpuGrouping {
            println!("not using strategy A here ({:?}) — skipping", plan.strategy);
            return;
        }
        for d in &plan.domains {
            assert_eq!(d.config_base, None, "{} should use the plain encoding", d.label);
            assert!(d.class.is_some(), "{} must come from the silicon", d.label);
        }
        assert!(plan.domains.len() > 1, "strategy A only applies to hybrid parts");
    }

    #[test]
    fn strategy_b_tags_every_domain_with_its_pmu() {
        let plan = plan_for(PmuAccess::PerProcessKernel);
        if plan.strategy != HybridStrategy::PmuTyped {
            println!("not using strategy B here ({:?}) — skipping", plan.strategy);
            return;
        }
        for d in &plan.domains {
            let base = d.config_base.expect("strategy B must name the PMU");
            assert_ne!(base, 0, "{} has a zero PMU type", d.label);
            // The type lives in the upper 32 bits and nothing else may.
            assert_eq!(base & 0xffff_ffff, 0, "PMU type must be pre-shifted");
        }
    }

    #[test]
    fn the_two_sources_agree_on_this_machine() {
        let plan = plan_for(PmuAccess::SystemWide);
        match plan.sources_agree {
            // The cross-validation this design exists for: the silicon's own
            // core-type map and the kernel's PMU grouping describe the same
            // partition, derived completely independently.
            Some(true)  => println!("silicon and PMU grouping agree: {}", plan.topology),
            Some(false) => panic!("silicon and PMU grouping disagree: {}", plan.topology),
            None        => println!("only one source had anything to say — nothing to cross-check"),
        }
    }

    #[test]
    fn hybrid_snapshot_splits_by_core_type() {
        if !coretype::topology().is_heterogeneous() {
            println!("not a hybrid CPU — split not exercised here");
            return;
        }
        let snap = snapshot(Duration::from_millis(80));
        if !snap.hw_available {
            println!("no hw counters ({:?}) — skipping", snap.access);
            return;
        }
        if snap.strategy == HybridStrategy::Unavailable {
            println!("hybrid not separable at {:?} — reported combined", snap.access);
            return;
        }
        assert!(snap.per_domain.len() > 1, "a separable hybrid must report >1 domain");
        // The aggregate is exactly the sum of its parts.
        if let Some(total) = snap.cycles {
            let parts: u64 = snap.per_domain.iter().filter_map(|d| d.cycles).sum();
            assert_eq!(total, parts);
        }
        println!("{}", snap.to_context_string());
    }

    #[test]
    fn never_ran_is_not_a_measured_zero() {
        // A counter that never ran reads back absent, not as 0 — the whole
        // point on a hybrid part, where an unused cluster is the normal case.
        assert!(PerfReadValue { raw: 0, enabled_ns: 1000, running_ns: 0 }
            .scaled()
            .is_none());
        // One that ran and genuinely counted zero stays a real reading of 0.
        let ran_zero = PerfReadValue { raw: 0, enabled_ns: 1000, running_ns: 1000 }
            .scaled()
            .expect("a counter that ran is a reading");
        assert_eq!(ran_zero.value, 0);
        assert_eq!(ran_zero.coverage, 1.0);
    }

    #[test]
    fn read_format_bits_match_the_abi() {
        // Bits 0 and 1. Bit 2 is PERF_FORMAT_ID, and asking for it silently
        // shifts the layout so the third u64 is an event id rather than a
        // time — which reads as a wildly multiplexed counter and inflates
        // every scaled count. `PerfReadValue` assumes exactly these two.
        assert_eq!(PERF_FORMAT_TOTAL_TIME_ENABLED, 0x1);
        assert_eq!(PERF_FORMAT_TOTAL_TIME_RUNNING, 0x2);
        assert_eq!(
            PERF_FORMAT_TOTAL_TIME_ENABLED | PERF_FORMAT_TOTAL_TIME_RUNNING,
            0x3,
            "the two time fields and nothing else"
        );
        // The read buffer must match the three fields we asked for.
        assert_eq!(std::mem::size_of::<PerfReadValue>(), 3 * 8);
    }

    #[test]
    fn attr_size_matches_the_struct_we_send() {
        // The kernel copies `attr.size` bytes out of our object, so claiming a
        // larger ABI revision than we actually declare reads past its end.
        let attr = make_attr(PERF_TYPE_HARDWARE, 0, Target::Process, false);
        assert_eq!(attr.size as usize, std::mem::size_of::<PerfEventAttr>());
    }

    #[test]
    fn multiplexing_is_corrected_and_its_coverage_reported() {
        // A genuinely multiplexed counter gets its correction, and says how
        // much of the window it actually ran for.
        let muxed = PerfReadValue { raw: 100, enabled_ns: 1000, running_ns: 500 }
            .scaled()
            .unwrap();
        assert_eq!(muxed.value, 200);
        assert_eq!(muxed.coverage, 0.5);

        // A counter that ran for a sliver of the window still gets a value,
        // but its coverage marks it as not worth publishing as a total.
        let noise = PerfReadValue { raw: 1_040_183, enabled_ns: 50_346_142, running_ns: 723 }
            .scaled()
            .unwrap();
        assert!(noise.coverage < MIN_RUNNING_RATIO, "coverage {}", noise.coverage);
        assert!(noise.value > 70_000_000_000, "the raw extrapolation is absurd");
    }

    #[test]
    fn a_starved_domain_keeps_ipc_but_withholds_totals() {
        // IPC is a ratio, so it survives multiplexing; absolute counts do not.
        let d = DomainCounters {
            label: "P-cores".into(),
            ipc: Some(1.5),
            cycles: None,
            instructions: None,
            coverage: Some(0.0001),
            cpus_sampled: 16,
            cpus_total: 16,
            ..Default::default()
        };
        assert!(d.multiplexed());
        let line = d.render_line();
        assert!(line.contains("IPC 1.50"), "{line}");
        assert!(line.contains("multiplexed"), "{line}");
        assert!(line.contains("withheld"), "{line}");

        // Full coverage is not multiplexed and reports its totals.
        let full = DomainCounters { coverage: Some(1.0), ..d.clone() };
        assert!(!full.multiplexed());
        // Absent coverage (nothing read at all) must not count as multiplexed.
        let none = DomainCounters { coverage: None, ..d };
        assert!(!none.multiplexed());
    }

    #[test]
    fn idle_domain_reports_as_idle_not_zero() {
        let idle = DomainCounters {
            label: "E-cores".into(),
            provenance: Some("Intel Atom · cpu_atom".into()),
            coverage: None, // nothing read at all, as opposed to read-and-starved
            cpus_sampled: 16,
            cpus_total: 16,
            ..Default::default()
        };
        assert!(idle.never_ran());
        assert!(!idle.partial());
        let line = idle.render_line();
        assert!(line.contains("idle"), "{line}");
        assert!(!line.contains("0 cycles"), "must not read as a measured zero: {line}");
    }

    #[test]
    fn partial_coverage_is_labelled() {
        let d = DomainCounters {
            label: "P-cores".into(),
            cycles: Some(1_000),
            instructions: Some(2_000),
            ipc: Some(2.0),
            coverage: Some(1.0),
            cpus_sampled: 4,
            cpus_total: 16,
            ..Default::default()
        };
        assert!(d.partial());
        assert!(d.render_line().contains("4 of 16 CPUs"));
    }

    #[test]
    fn sum_readings_treats_absent_as_absent() {
        let r = |value, coverage| Some(Reading { value, coverage });
        assert!(sum_readings(&[None, None]).is_none());
        assert!(sum_readings(&[]).is_none());

        let s = sum_readings(&[r(2, 1.0), None, r(3, 1.0)]).unwrap();
        assert_eq!(s.value, 5);
        assert_eq!(s.coverage, 1.0);

        // Coverage is the worst of the parts: one starved CPU taints the sum.
        let s = sum_readings(&[r(10, 1.0), r(10, 0.01)]).unwrap();
        assert_eq!(s.value, 20);
        assert_eq!(s.coverage, 0.01);

        // Saturating, so one bogus counter cannot overflow the total.
        assert_eq!(sum_readings(&[r(u64::MAX, 1.0), r(5, 1.0)]).unwrap().value, u64::MAX);
    }

    #[test]
    fn cpu_budget_strides_across_the_domain() {
        let cpus: Vec<u32> = (0..16).collect();
        assert_eq!(cpus_within_budget(&cpus, 32).len(), 16, "budget not binding");
        let sampled = cpus_within_budget(&cpus, 4);
        assert_eq!(sampled.len(), 4);
        // Spread out, not crowded onto the lowest CPUs.
        assert_eq!(sampled, vec![0, 4, 8, 12]);
        assert!(cpus_within_budget(&cpus, 0).is_empty());
    }

    #[test]
    fn access_probe_agrees_with_the_paranoid_gates() {
        let access = probe_access();
        let cap    = has_perfmon_capability().unwrap_or(false);
        println!("paranoid={:?} cap_perfmon={cap} access={access:?}", read_paranoid());

        // The ladder must never claim more than the sysctl allows, unless a
        // capability explains it.
        if let (Some(p), false) = (read_paranoid(), cap) {
            if p >= 1 {
                assert_ne!(
                    access, PmuAccess::SystemWide,
                    "system-wide needs paranoid <= 0 or CAP_PERFMON"
                );
            }
            if p >= 2 {
                assert!(
                    matches!(access, PmuAccess::PerProcessUser | PmuAccess::Denied),
                    "paranoid >= 2 forbids counting kernel mode, got {access:?}"
                );
            }
        }
    }

    #[test]
    fn access_note_explains_every_rung() {
        // A machine-wide snapshot needs no caveat; every other rung gets one.
        assert!(access_note(PmuAccess::SystemWide, Some(-1)).is_none());
        for rung in [
            PmuAccess::PerProcessKernel,
            PmuAccess::PerProcessUser,
            PmuAccess::Denied,
        ] {
            let note = access_note(rung, Some(2)).expect("rung must be explained");
            assert!(note.contains("perf_event_paranoid=2"), "{note}");
        }
        // The downstream-only value is named as such rather than silently
        // treated as an upstream row.
        assert!(access_note(PmuAccess::Denied, Some(3)).unwrap().contains("Debian/Ubuntu"));
        // An unreadable sysctl still produces a usable note.
        assert!(access_note(PmuAccess::Denied, None).is_some());
    }
}




/// A load-response check, kept separate because it deliberately burns CPU.
///
/// This is the test that would have caught the `read_format` bug: it bounds the
/// counts by what the silicon can physically issue, which the mis-decoded event
/// id violated by three orders of magnitude.
///
/// Deliberately *not* compared against an idle baseline — the harness runs tests
/// in parallel, so "idle" is whatever the rest of the suite happens to be doing.
/// The assertions below are absolute and hold however busy the machine is.
#[cfg(test)]
mod load_check {
    use super::*;

    /// No production core retires more than a handful of instructions per
    /// cycle; past this the arithmetic is inventing work.
    const MAX_PLAUSIBLE_IPC: f64 = 12.0;

    #[test]
    fn counters_stay_within_what_the_silicon_can_issue() {
        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let mut hs = Vec::new();
        for _ in 0..8 {
            let s = stop.clone();
            hs.push(std::thread::spawn(move || {
                let mut x: u64 = 0;
                while !s.load(std::sync::atomic::Ordering::Relaxed) {
                    x = x.wrapping_mul(6364136223846793005).wrapping_add(1);
                }
                x
            }));
        }
        std::thread::sleep(Duration::from_millis(50));
        let window = Duration::from_millis(200);
        let busy = snapshot(window);
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        for h in hs {
            let _ = h.join();
        }

        println!("busy: cycles={:?} ipc={:?}", busy.cycles, busy.ipc);
        for d in &busy.per_domain {
            println!("  {}", d.render_line());
        }

        if !busy.hw_available {
            println!("no hw counters ({:?}) — nothing to bound", busy.access);
            return;
        }

        // Upper bound: every online CPU issuing flat out at an absurdly
        // generous 8 GHz for the whole window. Real hardware cannot reach it,
        // so exceeding it proves the scaling is wrong rather than the box fast.
        if let Some(cycles) = busy.cycles {
            let ceiling = coretype::online_cpus().len() as u64
                * 8_000_000_000
                * window.as_millis() as u64
                / 1000;
            assert!(cycles <= ceiling, "impossible cycle count: {cycles} > {ceiling}");
            assert!(cycles > 0, "eight spinning threads must produce cycles");
        }

        // Every IPC reported must be one a real pipeline could produce.
        for ipc in busy.ipc.into_iter().chain(busy.per_domain.iter().filter_map(|d| d.ipc)) {
            assert!(ipc > 0.0 && ipc < MAX_PLAUSIBLE_IPC, "implausible IPC: {ipc}");
        }
    }
}
