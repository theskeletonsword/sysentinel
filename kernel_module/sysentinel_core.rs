// SPDX-License-Identifier: MIT OR GPL-2.0-or-later
//!
//! sysentinel_metrics — system metrics, hypervisor + ME/PSP status, and
//! privileged control commands, exposed as `/proc/sysentinel_metrics`.
//!
//! # Interface
//!
//! A single procfs file. Every `read()` returns a one-line snapshot:
//!
//! ```text
//! uptime_s=12345 modules=64 mem_free_kb=204800 mem_total_kb=8388608
//! hypervisor=bare-metal ring3=intel-me cr0=0x0000000080050033
//! me_fw=18.1.2204.0 me_live=ok(v18.1.2204.0,rt=2ms)
//! smm=off ro=ok(rt=0us)
//! ```
//!
//! The ring −3 channel is chosen by the [`ring3`] dispatcher (mirroring the
//! daemon HAL): **Intel** → ME/HECI/MKHI tokens above; **AMD/Hygon** → a
//! `psp=up(...)` handshake token instead; **neither** → no ME/PSP tokens at
//! all (old/VIA/ARM-class silicon). Fields are space-separated `key=value`
//! segments ending with a newline. The exact set depends on the
//! hardware/virtualisation platform at runtime:
//!
//! | Field           | Source                            | Always present? |
//! |---|---|---|
//! | `uptime_s`      | `ktime_get_boottime_seconds()`    | yes             |
//! | `modules`       | module list length                | yes (0 on error)|
//! | `mem_free_kb`   | `si_meminfo().freeram`            | yes             |
//! | `mem_total_kb`  | `si_meminfo().totalram`           | yes             |
//! | `hypervisor`    | CPUID leaf 0x40000000 / EL1 reg   | yes             |
//! | `ring3`         | dispatcher: intel-me / amd-psp / none | yes           |
//! | `cr0`           | current `%cr0` value              | x86_64 only     |
//! | `kvm_features`  | `KVM_HC_FEATURES` hypercall       | only under KVM  |
//! | `me_fw`         | MKHI GET_FW_VERSION via MEI bus   | Intel only      |
//! | `me_live`       | live MKHI re-query (rate-limited) | Intel only      |
//! | `me_drift`      | live ≠ probe firmware version     | Intel, if drifted|
//! | `psp`           | AMD PSP HSTI handshake            | AMD only        |
//! | `smm`           | ring −2 SMM firmware posture — ACPI-only, **provably never raises an SMI** (`off` default; `acpi` / `err(c=…)` after the read-only scan on `smm on`) | yes |
//! | `smm_iface`     | read-only: the firmware's declared SMM bridge (FADT `smi_command` port + documented command values) | armed |
//! | `smm_wsmt`      | read-only: WSMT SMM-mitigation posture (fixed-buffers, comm-nested-ptr, system-res) | armed |
//! | `crosstalk`     | ring −1 hypercall vs ring −2 SMM latency | SMM on + VM |
//! | `ro`            | passive rodata canary watch (`ok`/`dirty`) | yes          |
//!
//! The procfs shim that owns the file is `src/proc_entry.c`; the logic
//! lives here. rust-for-linux 7.1 has no `/proc` abstraction, so this
//! module publishes the entry from C and delegates to the Rust exports
//! `rs_render_snapshot()` and `rs_exec_command()`.
//!
//! # Control commands (write path)
//!
//! Writing a short command performs a privileged action. Require real
//! confirmation *in the client* before sending these — they are immediate
//! (the Reactor / command layer enforces a confirm step):
//!
//! | Command       | Effect                                          |
//! |---|---|
//! | `reboot`      | `kernel_restart(NULL)`                      |
//! | `poweroff`    | `orderly_poweroff(true)`                    |
//! | `triplefault` / `triplefault restart` | hard reset via bogus IDT + `int3` (CPU RESET) |
//! | `triplefault shutdown` | `kernel_power_off()` forced power-down |
//! | `kernelpanic` | `panic()` — deliberate kernel panic (halt, or reboot per `panic=N`) |
//! | `cr0_wp on`   | set `%cr0.WP` (write-protect)                |
//! | `cr0_wp off`  | clear `%cr0.WP`                              |
//! | `smm on`      | arm the ring −2 SMM channel: runs the **read-only** ACPI posture scan (FADT + WSMT) — no SMI, no port I/O |
//! | `smm off`     | disable the SMM channel                       |
//! | `status`      | no-op (round-trip check)                     |
//!
//! Every `triplefault*` command fires **exactly once per boot**: a per-boot
//! latch (`TRIPLEFAULT_FIRED`) refuses any duplicate with `-EBUSY`, and the
//! reset path can never loop (bogus IDT → `#BP` → `#NP` → `#DF` → triple
//! fault; if the firmware/VM refuses to reset, `cli; hlt` parks the CPU).
//! The daemon additionally enforces ARM → `confirm` before every send.
//!
//! Writes are gate-kept by the procfs shim: `capable(CAP_SYS_ADMIN)` or
//! membership of the GID in the `write_gid` modparam (0 = root only).
//!
//! # What this module deliberately does NOT do
//!
//! - No ioctl surface, no mmap, no /dev node (the interface is now `/proc`).
//! - The hypercall path only reads KVM features; no state-modifying
//!   hypercalls.
//! - MEI access is gated behind the `mei_available` cfg flag (see Makefile).
//!
//! # Build requirements
//!
//! Standard `rust-for-linux` build (`CONFIG_RUST=y`). For MEI support:
//! `make MEI=y KDIR=/path/to/kernel`. See `README.md`.

#![no_std]

// Pull in both submodules. They are conditionally compiled inside.
mod hypercall;
mod psp;
mod ring3;
mod smm;

#[cfg(mei_available)]
mod mei_driver;

use core::fmt::Write;
use core::sync::atomic::{AtomicBool, Ordering};
use kernel::prelude::*;

// Control actions call straight into exported kernel symbols (not in the
// generated bindings); declared here and resolved by the module linker.
extern "C" {
    fn kernel_restart(cmd: *const core::ffi::c_char);
    fn orderly_poweroff(force: bool);
    fn kernel_power_off();
}

// The procfs shim (src/proc_entry.c) exposes init/exit to the Rust module.
extern "C" {
    fn sysentinel_proc_init() -> core::ffi::c_long;
    fn sysentinel_proc_exit();
}

// One-shot CPU hard reset + forced panic helpers (src/triplefault.c).
extern "C" {
    fn sysentinel_triplefault_reset() -> core::ffi::c_long;
    fn sysentinel_kernel_panic() -> core::ffi::c_long;
}

/// Per-boot guard for the `triplefault*` commands. The whole point of the
/// feature is "fires once, never in a loop": the first triplefault of a boot
/// runs immediately; every later attempt returns `-EBUSY`. The machine then
/// resets/powers off (module is gone), so the next *boot* starts fresh and
/// the command is available again — exactly "each time it is asked with
/// confirmation, never in a loop".
static TRIPLEFAULT_FIRED: AtomicBool = AtomicBool::new(false);

// The hypercall watcher (src/hypercall_watcher.c): kprobes the exported KVM
// symbol `kvm_emulate_hypercall` so every guest -> hypervisor hypercall on a
// KVM host is captured and drained via /proc/sysentinel_hypercalls. It also
// owns the privileged `killsession <pid>` helper used to close an intruder's
// login (SIGTERM then SIGKILL on the session leader).
extern "C" {
    fn sysentinel_hypercall_watcher_init() -> core::ffi::c_long;
    fn sysentinel_hypercall_watcher_exit();
    fn sysentinel_session_kill(pid: core::ffi::c_long) -> core::ffi::c_long;
}

// The ring0 rootkit defender (src/rootkit_defender.c): snapshots MSR_LSTAR
// (the syscall entry point) and the IDT at module load, then `rootkit scan`
// detects and `rootkit clean` neutralises hooks to those crime sites (the
// classic ring0 interceptor targets), restores CR0.WP, and can SIGKILL rogue
// processes/sessions via kill_pid. This is ring0-only — it is the part that
// can actually kill a malicious ring0 rootkit. `lstar` on the snapshot line
// reports hook status on every read.
extern "C" {
    fn sysentinel_defense_init() -> core::ffi::c_long;
    fn sysentinel_defense_exit();
    fn sysentinel_defense_scan() -> core::ffi::c_long;
    fn sysentinel_defense_clean() -> core::ffi::c_long;
    fn sysentinel_kill_process(pid: core::ffi::c_long) -> core::ffi::c_long;
    fn sysentinel_defense_lstar_status() -> core::ffi::c_long;
}

module! {
    type: SysentinelMetrics,
    name: "sysentinel_metrics",
    authors: ["sysentinel contributors"],
    description: "System metrics, ME/PSP status, and privileged controls via /proc/sysentinel_metrics",
    license: "Dual MIT/GPL",
}

// ── Metrics snapshot ──────────────────────────────────────────────────────────

/// A snapshot of all metrics we are willing to expose in a single read.
struct Snapshot {
    /// System uptime in seconds (from ktime_get_boottime).
    uptime_secs: u64,
    /// Number of currently loaded kernel modules.
    loaded_modules: u32,
    /// Free physical memory in KiB.
    free_mem_kb: u64,
    /// Total physical memory in KiB.
    total_mem_kb: u64,
    /// Human-readable hypervisor description.
    hypervisor: &'static str,
    /// KVM feature bitmask from KVM_HC_FEATURES, or None if not under KVM
    /// or the hypercall returned an error.
    kvm_features: Option<u64>,
    /// Intel ME firmware version, or None if ME is not present / not queried.
    me_fw: Option<hypercall_types::MeFwVersionStr>,
    /// AMD PSP presence (see `psp` module).
    psp: psp::PspStatus,
    /// Current CR register values (x86_64 only; None on other arches).
    /// Whether the reader may see the control registers that are addresses.
    /// Not hardware state: it is who is asking, decided by the procfs shim.
    privileged: bool,
    cr0: Option<u64>,
    cr2: Option<u64>,
    cr3: Option<u64>,
    cr4: Option<u64>,
    cr8: Option<u64>,
}

/// Stack-allocated string buffer for an ME firmware version.
mod hypercall_types {
    /// A small fixed-size buffer holding "major.minor.build.hotfix\0".
    /// Avoids heap allocation inside the read path.
    pub struct MeFwVersionStr {
        pub buf: [u8; 32],
        pub len: usize,
    }

    impl MeFwVersionStr {
        pub fn as_bytes(&self) -> &[u8] {
            &self.buf[..self.len]
        }
    }
}

impl Snapshot {
    /// Gather a fresh snapshot.
    ///
    /// All data sources here are either pure kernel counters (uptime, memory)
    /// accessible to any kernel context, or already-computed cached values
    /// (hypervisor kind, ME version set during module init). No blocking I/O
    /// or memory allocation is performed on the read path.
    fn gather(privileged: bool) -> Self {
        // ── Uptime ───────────────────────────────────────────────────────────
        // kernel::time::Ktime::ktime_get_boottime() returns nanoseconds since
        // boot. API shape varies by kernel version; check your tree's
        // rust/kernel/time.rs for the exact method name.
        //
        // Adjust if your kernel version uses a different wrapper name:
        let uptime_ns = kernel::time::Instant::<kernel::time::BootTime>::now()
            .elapsed()
            .as_nanos();
        let uptime_secs = (uptime_ns.unsigned_abs()) / 1_000_000_000;

        // ── Memory ───────────────────────────────────────────────────────────
        // si_meminfo() is provided by the kernel's C helpers (not yet wrapped
        // in a safe Rust abstraction), so we call the raw binding directly.
        let mut info: kernel::bindings::sysinfo = kernel::bindings::sysinfo {
            ..Default::default()
        };
        // SAFETY: `info` points to a valid, writable struct; `si_meminfo`
        // never fails and requires no locks.
        unsafe { kernel::bindings::si_meminfo(&mut info) };
        let page_kb = kernel::bindings::PAGE_SIZE as u64 / 1024;
        let free_mem_kb = info.freeram as u64 * page_kb;
        let total_mem_kb = info.totalram as u64 * page_kb;

        // ── Loaded modules ───────────────────────────────────────────────────
        // The module list is not currently exposed in a safe Rust API;
        // replace 0 with iteration over `modules` list if your kernel
        // has the necessary binding.
        let loaded_modules: u32 = 0; // ← wire to module list length

        // ── Hypervisor ───────────────────────────────────────────────────────
        let hypervisor = hypercall::hypervisor_description();

        // ── KVM features (non-blocking; uses cached detection) ────────────────
        let kvm_features = match hypercall::kvm_query_features() {
            Ok(bits) => Some(bits),
            Err(_)   => None,
        };

        // ── Intel ME firmware version (cached from MEI probe callback) ────────
        #[cfg(mei_available)]
        let me_fw = mei_driver::get_me_fw_version().map(|v| {
            use core::fmt::Write;
            let mut s = hypercall_types::MeFwVersionStr { buf: [0u8; 32], len: 0 };
            let mut w = BufWriter { buf: &mut s.buf, pos: 0 };
            let _ = write!(w, "{}.{}.{}.{}", v.major, v.minor, v.build, v.hotfix);
            s.len = w.pos;
            s
        });

        #[cfg(not(mei_available))]
        let me_fw: Option<hypercall_types::MeFwVersionStr> = None;

        // ── AMD PSP presence ───────────────────────────────────────────────────
        let psp = psp::detect();

        Self {
            uptime_secs,
            loaded_modules,
            free_mem_kb,
            total_mem_kb,
            hypervisor,
            kvm_features,
            me_fw,
            psp,
            privileged,
            cr0: current_cr(0),
            cr2: current_cr(2),
            cr3: current_cr(3),
            cr4: current_cr(4),
            cr8: current_cr(8),
        }
    }

    /// Serialise the snapshot as a space-separated key=value line.
    ///
    /// Output format (example):
    /// ```text
    /// uptime_s=12345 modules=64 mem_free_kb=204800 mem_total_kb=8388608 hypervisor=KVM/Intel_VT-x kvm_features=0x000001ff ring3=intel-me me_fw=18.1.2204.0
    /// ```
    fn render(&self) -> KVec<u8> {
        let mut buf: KVec<u8> = KVec::new();
        let mut w = KVecWriter(&mut buf);

        // Spaces are used as field separators; the line ends with '\n'.
        let _ = write!(
            w,
            "uptime_s={} modules={} mem_free_kb={} mem_total_kb={} hypervisor={} ring3={}",
            self.uptime_secs,
            self.loaded_modules,
            self.free_mem_kb,
            self.total_mem_kb,
            // Spaces in the hypervisor string would break the format; replace with '_'.
            HypervisorEscaped(self.hypervisor),
            ring3::partner().short(),
        );

        if let Some(features) = self.kvm_features {
            let _ = write!(w, " kvm_features={:#010x}", features);
        }

        // Ring0 rootkit status: is the syscall entry (MSR_LSTAR) still the
        // one we baselined at module load?
        // SAFETY: reads an MSR; only touches our own module state.
        let lstar = unsafe { sysentinel_defense_lstar_status() };
        let lstar_str = match lstar {
            0 => "ok",
            1 => "hooked",
            _ => "n/a",
        };
        let _ = write!(w, " lstar={}", lstar_str);

        if let Some(ref v) = self.me_fw {
            let _ = write!(w, " me_fw=");
            let text = core::str::from_utf8(v.as_bytes()).unwrap_or("?");
            let _ = write!(w, "{}", text);
        }

        // Live ME channel: re-run the MKHI handshake over the bound MEI client
        // (rate-limited by mei_driver) so the daemon sees the module → ring -3
        // alliance working right now, and flags drift from the probe-time value.
        // Engaged only when the ring −3 dispatcher picked Intel ME.
        #[cfg(mei_available)]
        if ring3::partner().is_intel_me() {
            let now_ns = mei_driver::boottime_ns();
            let live = mei_driver::live_status(now_ns);
            if !live.bound {
                let _ = write!(w, " me_live=no-client");
            } else if let Some(v) = live.version {
                let _ = write!(
                    w,
                    " me_live=ok(v{}.{}.{}.{},rt={}ms)",
                    v.major,
                    v.minor,
                    v.build,
                    v.hotfix,
                    live.rt_us / 1000
                );
                if let Some(cached) = mei_driver::get_me_fw_version() {
                    if cached.major != v.major
                        || cached.minor != v.minor
                        || cached.build != v.build
                        || cached.hotfix != v.hotfix
                    {
                        let _ = write!(w, " me_drift=1");
                    }
                }
            } else {
                let _ = write!(w, " me_live=err");
            }
        }

        // Control registers, with the two that are addresses held back from
        // unprivileged readers.
        //
        // The procfs file is 0644 so any local process can read the snapshot,
        // and most of it is harmless — uptime, module count, firmware
        // versions. CR2 and CR3 are not. CR2 is the last page-fault linear
        // address and CR3 is the physical base of the page tables, which is
        // exactly the pair a local exploit wants in order to defeat kernel
        // address randomisation. Publishing them to every process on the
        // machine hands that away for free, and the kernel itself restricts
        // far less useful things (kptr_restrict, dmesg_restrict) for the same
        // reason. CR0/CR4/CR8 are feature and flag bits, already inferable
        // from /proc/cpuinfo, and stay visible so `/status` keeps working for
        // an unprivileged daemon.
        for reg in [0u8, 2, 3, 4, 8] {
            let sensitive = matches!(reg, 2 | 3);
            match cr_value(&self, reg) {
                Some(_) if sensitive && !self.privileged => {
                    let _ = write!(w, " cr{}=restricted", reg);
                }
                Some(v) => {
                    let _ = write!(w, " cr{}={:#018x}", reg, v);
                }
                None => {}
            }
        }

        // AMD PSP: engaged only when the ring −3 dispatcher picked the PSP; on
        // Intel the token is absent entirely (that silicon talks to the ME, not
        // the PSP), and on neither-vendor old silicon no token is emitted.
        if ring3::partner().is_amd_psp() {
            if let psp::PspStatus::Up { hsti, rt_us } = self.psp {
                let mut flags = [0u8; 64];
                let flen = self.psp.hsti_flags_buf(&mut flags);
                let _ = write!(
                    w,
                    " psp=up(hsti={:#010x},flags={},rt={}ms)",
                    hsti,
                    core::str::from_utf8(&flags[..flen]).unwrap_or("?"),
                    rt_us / 1000
                );
            } else {
                let _ = write!(w, " psp={}", self.psp.as_str());
            }
        }

        // Ring −2 (SMM) firmware posture + passive rodata watch. Reading NEVER
        // raises an SMI: the module has no path to the APM ports at all — the
        // posture is read from the ACPI tables the firmware publishes (FADT
        // smi_command + WSMT), so `smm on`/`smm_wsmt` are pure table reads and
        // the rodata canary is a checksum over our own memory.
        let now_ns = kernel::time::Instant::<kernel::time::BootTime>::now()
            .elapsed()
            .as_nanos()
            .unsigned_abs();
        smm::ro_check(now_ns);
        smm::write_tokens(&mut w);
        smm::write_ro_token(&mut w);

        let _ = write!(w, "\n");
        buf
    }
}

// ── Helper writers ────────────────────────────────────────────────────────────

/// Adapts `KVec<u8>` to `core::fmt::Write`.
struct KVecWriter<'a>(&'a mut KVec<u8>);

impl core::fmt::Write for KVecWriter<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        self.0
            .extend_from_slice(s.as_bytes(), GFP_KERNEL)
            .map_err(|_| core::fmt::Error)
    }
}

/// Stack-allocated buf writer (for no-alloc formatting of ME version).
#[cfg(mei_available)]
struct BufWriter<'a> {
    buf: &'a mut [u8; 32],
    pos: usize,
}

#[cfg(mei_available)]
impl core::fmt::Write for BufWriter<'_> {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        let remaining = self.buf.len().saturating_sub(self.pos);
        let to_copy = s.len().min(remaining);
        self.buf[self.pos..self.pos + to_copy].copy_from_slice(&s.as_bytes()[..to_copy]);
        self.pos += to_copy;
        Ok(())
    }
}

/// Display adapter that replaces ASCII spaces with underscores.
struct HypervisorEscaped<'a>(&'a str);

impl core::fmt::Display for HypervisorEscaped<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for ch in self.0.chars() {
            if ch == ' ' { f.write_char('_')?; } else { f.write_char(ch)?; }
        }
        Ok(())
    }
}

// ── CR register helpers (x86_64 only) ─────────────────────────────────────────

/// Read the value of a control register. Only 0, 2, 3, 4, 8 are supported;
/// any other number returns `None`.
///
/// CR2 (page-fault linear address) is read-only — writes to it are rejected
/// in `rs_exec_command`.
#[cfg(target_arch = "x86_64")]
fn current_cr(reg: u8) -> Option<u64> {
    let mut val: u64 = 0;
    // SAFETY: reading a control register in kernel mode is always legal.
    unsafe {
        match reg {
            2 => core::arch::asm!("mov {}, cr2", out(reg) val, options(nomem, nostack, preserves_flags)),
            3 => core::arch::asm!("mov {}, cr3", out(reg) val, options(nomem, nostack, preserves_flags)),
            4 => core::arch::asm!("mov {}, cr4", out(reg) val, options(nomem, nostack, preserves_flags)),
            8 => core::arch::asm!("mov {}, cr8", out(reg) val, options(nomem, nostack, preserves_flags)),
            _ => core::arch::asm!("mov {}, cr0", out(reg) val, options(nomem, nostack, preserves_flags)),
        }
    }
    Some(val)
}

/// Non-x86-64 stub.
#[cfg(not(target_arch = "x86_64"))]
fn current_cr(_reg: u8) -> Option<u64> {
    None
}

/// Fetch the cached CR value from a snapshot (avoids duplicating the field
/// juggling in the render path).
fn cr_value(snap: &Snapshot, reg: u8) -> Option<u64> {
    match reg {
        0 => snap.cr0,
        2 => snap.cr2,
        3 => snap.cr3,
        4 => snap.cr4,
        8 => snap.cr8,
        _ => None,
    }
}

/// Write an arbitrary value to a control register (0, 3, 4, 8). CR2 is
/// rejected: it is a read-only status register.
///
/// # Safety-bound guard
///
/// Writing CR3 to `0` is guaranteed to crash the CPU (kernel runs with a
/// null page table); reject it up front. Everything else is the caller's
/// responsibility — the daemon enforces human confirmation before sending.
#[cfg(target_arch = "x86_64")]
fn set_cr(reg: u8, value: u64) -> Result<()> {
    // SAFETY: writing a control register from kernel mode. The caller has
    // confirmed; some values can be fatal (e.g. nonsense CR3/CR4).
    unsafe {
        match reg {
            2 => return Err(EPERM),
            3 => {
                if value == 0 {
                    return Err(EINVAL);
                }
                core::arch::asm!("mov cr3, {}", in(reg) value, options(nomem, nostack, preserves_flags));
            }
            4 => core::arch::asm!("mov cr4, {}", in(reg) value, options(nomem, nostack, preserves_flags)),
            8 => core::arch::asm!("mov cr8, {}", in(reg) value, options(nomem, nostack, preserves_flags)),
            _ => core::arch::asm!("mov cr0, {}", in(reg) value, options(nomem, nostack, preserves_flags)),
        }
    }
    Ok(())
}

/// Non-x86-64 stub.
#[cfg(not(target_arch = "x86_64"))]
fn set_cr(_reg: u8, _value: u64) -> Result<()> {
    Err(EINVAL)
}

/// Toggle the CR0.WP bit (bit 16, write protection of kernel pages).
///
/// Dangerous when left off — require confirmation first (the daemon does)
/// and re-enable WP afterwards.
fn set_cr0_wp(enabled: bool) -> Result<()> {
    let cur = current_cr(0).ok_or(EINVAL)?;
    let next = if enabled { cur | (1 << 16) } else { cur & !(1 << 16) };
    set_cr(0, next)
}

// ── Rust exports called from the procfs shim (src/proc_entry.c) ──────────────

/// Convert a kernel [`Error`] constant into a negative errno suitable for the
/// C procfs shim (the kernel convention: negative on failure).
fn neg_errno(e: Error) -> core::ffi::c_long {
    e.to_errno() as core::ffi::c_long
}

/// Render a fresh snapshot into `buf` (best effort up to `cap` bytes).
/// Returns the byte count on success, a negative errno on error.
///
/// `privileged` is non-zero when the reader cleared the same gate that guards
/// writes (CAP_SYS_ADMIN, or membership of `write_gid`). It decides whether the
/// address-bearing control registers are rendered or held back.
///
/// # Safety
///
/// `buf` must point to a writable region of at least `cap` bytes.
#[no_mangle]
pub unsafe extern "C" fn rs_render_snapshot(
    buf: *mut u8,
    cap: usize,
    privileged: core::ffi::c_int,
) -> core::ffi::c_long {
    if cap == 0 {
        return neg_errno(EINVAL);
    }
    // SAFETY: caller supplies a valid, writable buffer (documented above).
    let snap = Snapshot::gather(privileged != 0);
    let line = snap.render();
    let n = line.len().min(cap);
    unsafe { core::ptr::copy_nonoverlapping(line.as_ptr(), buf, n) };
    n as core::ffi::c_long
}

/// Execute a control command string (`reboot`, `poweroff`, `cr0_wp on|off`,
/// `status`). Returns 0 on success, a negative errno on error.
///
/// # Safety
///
/// `cmd` must be a valid NUL-terminated string (bounded by the C shim to
/// 63 bytes).
#[no_mangle]
pub unsafe extern "C" fn rs_exec_command(
    cmd: *const core::ffi::c_char,
) -> core::ffi::c_long {
    if cmd.is_null() {
        return neg_errno(EINVAL);
    }
    // SAFETY: the shim guarantees a NUL-terminated C string of bounded size.
    let cs = unsafe { core::ffi::CStr::from_ptr(cmd) };
    let s = match cs.to_str() {
        Ok(s) => s.trim(),
        Err(_) => return neg_errno(EINVAL),
    };

    match s {
        "status" => {
            pr_info!("sysentinel_metrics: status ping from procfs write\n");
            0
        }
        "reboot" => {
            pr_warn!("sysentinel_metrics: CONTROL: kernel restart issued from procfs\n");
            // SAFETY: kernel_restart takes a char*; NULL selects default.
            unsafe { kernel_restart(core::ptr::null()) };
            0
        }
        "poweroff" => {
            pr_warn!("sysentinel_metrics: CONTROL: poweroff issued from procfs\n");
            // SAFETY: orderly_poweroff takes a bool and never returns error.
            unsafe { orderly_poweroff(true) };
            0
        }
        "triplefault" | "triplefault restart" => triplefault_once(|| {
            pr_emerg!(
                "sysentinel_metrics: CONTROL: TRIPLE FAULT RESET (hard reboot) — one shot, no loop\n"
            );
            // SAFETY: bogus IDT + int3 → CPU reset; never returns on real
            // hardware (falls through to cli;hlt if the firmware refuses).
            unsafe { sysentinel_triplefault_reset() }
        }),
        "triplefault shutdown" => triplefault_once(|| {
            pr_emerg!(
                "sysentinel_metrics: CONTROL: EMERGENCY POWER OFF via kernel_power_off — one shot, no loop\n"
            );
            // SAFETY: low-level power-down (ACPI S5 on x86); never returns
            // on hardware that honours it.
            unsafe { kernel_power_off() };
            0
        }),
        "kernelpanic" => {
            pr_emerg!(
                "sysentinel_metrics: CONTROL: FORCED KERNEL PANIC (confirmed)\n"
            );
            // SAFETY: calls the kernel's real panic(); __noreturn, so the
            // machine halts (or reboot per `panic=N`). Terminal one-shot by
            // definition — nothing here loops or retries.
            unsafe { sysentinel_kernel_panic() }
        }
        "cr0_wp on" => match set_cr0_wp(true) {
            Ok(()) => {
                pr_info!("sysentinel_metrics: CONTROL: CR0.WP set\n");
                0
            }
            Err(e) => e.to_errno() as core::ffi::c_long,
        },
        "cr0_wp off" => match set_cr0_wp(false) {
            Ok(()) => {
                pr_warn!("sysentinel_metrics: CONTROL: CR0.WP cleared! (write protection disabled)\n");
                0
            }
            Err(e) => e.to_errno() as core::ffi::c_long,
        },
        "rootkit scan" => {
            pr_info!("sysentinel_metrics: CONTROL: rootkit scan requested\n");
            // SAFETY: read-only scan; result lands in /proc/sysentinel_defense.
            unsafe { sysentinel_defense_scan() }
        }
        "rootkit clean" => {
            pr_warn!("sysentinel_metrics: CONTROL: rootkit clean; restoring LSTAR/IDT from baseline\n");
            // SAFETY: restores baseline MSR_LSTAR + deviating IDT gates and
            // re-sets CR0.WP. The daemon enforces human confirmation before
            // this reaches us.
            unsafe { sysentinel_defense_clean() }
        }
        // Ring −2 SMM channel — ACPI-only, provably never raises an SMI. Arming
        // performs the read-only firmware-posture scan (FADT + WSMT, pure
        // table reads); there is no path to the APM ports at all.
        "smm on" => {
            smm::smm_enable();
            pr_info!("sysentinel_metrics: CONTROL: ring −2 SMM channel armed (ACPI posture scan, no SMI possible)\n");
            0
        }
        "smm off" => {
            smm::smm_disable();
            pr_info!("sysentinel_metrics: CONTROL: ring −2 SMM channel disabled\n");
            0
        }
        "smm status" => {
            let state = if smm::smm_is_enabled() { "enabled" } else { "disabled" };
            pr_info!("sysentinel_metrics: CONTROL: ring −2 SMM channel {state}\n");
            0
        }
        _ => parse_pid_command(s, |pid| {
            // SAFETY: C helper SIGKILLs the pid via find_vpid/kill_pid.
            unsafe { sysentinel_kill_process(pid) }
        })
        .or_else(|| {
            parse_pid_command(s, |pid| {
                // SAFETY: C helper SIGTERM+SIGKILLs the session leader pid.
                unsafe { sysentinel_session_kill(pid) }
            })
        })
        .unwrap_or_else(|| parse_cr_write(s)),
    }
}

/// Fire a `triplefault*` action guarded by the per-boot latch.
///
/// Exactly one triplefault may fire per boot: the latch is set *before* the
/// action runs, so a duplicate write (stuck daemon, retry loop, second human
/// command racing the reset) is refused with `-EBUSY` and never re-fired.
/// Nothing here sleeps, retries or re-arms — a reboot/poweroff loop is
/// impossible by construction.
fn triplefault_once(action: impl FnOnce() -> core::ffi::c_long) -> core::ffi::c_long {
    if TRIPLEFAULT_FIRED.swap(true, Ordering::SeqCst) {
        pr_warn!(
            "sysentinel_metrics: CONTROL: triplefault already fired this boot; refusing duplicate (-EBUSY)\n"
        );
        return neg_errno(EBUSY);
    }
    action()
}

/// Parse `killpid <pid>` / `killsession <pid>` style commands. Returns Some
/// when the first token matched and the pid parsed; the callback runs the
/// action. A pid that fails to parse yields an errno back to the writer.
fn parse_pid_command(s: &str, action: impl FnOnce(core::ffi::c_long) -> core::ffi::c_long)
    -> Option<core::ffi::c_long>
{
    let mut it = s.split_whitespace();
    let tok = it.next()?;
    if !(tok == "killpid" || tok == "killsession") {
        return None;
    }
    let pid_str = it.next()?;
    let Ok(pid): Result<i64, _> = pid_str.parse() else {
        return Some(neg_errno(EINVAL));
    };
    pr_warn!("sysentinel_metrics: CONTROL: {tok} {pid}\n");
    Some(action(pid))
}

/// Parse a `crX=0x...` command (X in 0, 3, 4, 8; CR2 is read-only) and apply
/// it. Returns 0 on success, a negative errno otherwise.
fn parse_cr_write(s: &str) -> core::ffi::c_long {
    let mut it = s.splitn(2, '=');
    let reg_str = it.next().unwrap_or("");
    let val_str = it.next();
    let (Some(val_str), Some(reg)) = (val_str, reg_str.strip_prefix("cr")) else {
        return neg_errno(EINVAL);
    };
    let Ok(reg): Result<u8, _> = reg.parse() else {
        return neg_errno(EINVAL);
    };
    if !matches!(reg, 0 | 2 | 3 | 4 | 8) {
        return neg_errno(EINVAL);
    }
    let Some(hex) = val_str.strip_prefix("0x").or_else(|| val_str.strip_prefix("0X")) else {
        return neg_errno(EINVAL);
    };
    let Ok(value) = u64::from_str_radix(hex, 16) else {
        return neg_errno(EINVAL);
    };
    if reg == 2 {
        // CR2 is the page-fault linear address: status only, never writable.
        pr_warn!("sysentinel_metrics: refused write to read-only CR2\n");
        return neg_errno(EPERM);
    }
    match set_cr(reg, value) {
        Ok(()) => {
            pr_warn!("sysentinel_metrics: CONTROL: cr{reg} <- {value:#018x}\n");
            0
        }
        Err(e) => e.to_errno() as core::ffi::c_long,
    }
}

// ── Module entry / exit ───────────────────────────────────────────────────────

struct SysentinelMetrics {
    _mei_registered: bool,
}

impl kernel::Module for SysentinelMetrics {
    fn init(_module: &'static ThisModule) -> Result<Self> {
        pr_info!("sysentinel_metrics: loading\n");
        pr_info!(
            "sysentinel_metrics: hypervisor detected: {}\n",
            hypercall::hypervisor_description()
        );

        // Seed the passive rodata canary (ring −2 instrument #3; no SMI).
        smm::ro_init();

        // Register /proc/sysentinel_metrics (see src/proc_entry.c).
        // SAFETY: C shim just allocates a proc entry; no pointers shared.
        let rc = unsafe { sysentinel_proc_init() };
        if rc != 0 {
            pr_err!("sysentinel_metrics: failed to create /proc/sysentinel_metrics (errno {})\n", -rc);
            return Err(Error::from_errno(rc as i32));
        }

        // Arm the ring0 defender: snapshot MSR_LSTAR + IDT as the trusted
        // baseline. Non-fatal if the platform lacks the required MSRs.
        // SAFETY: C code captures two CPU registers; nothing else touched.
        let defense_rc = unsafe { sysentinel_defense_init() };
        if defense_rc != 0 {
            pr_warn!("sysentinel_metrics: rootkit defender unavailable (errno {})\n", -defense_rc);
        }

        // Attach the guest-hypercall kprobe + create /proc/sysentinel_hypercalls.
        // Non-fatal: on a bare-metal host without the kvm module the probe
        // cannot attach and the watcher reports "unavailable".
        // SAFETY: C code registers/deregisters a kprobe on an exported symbol.
        let hcw_rc = unsafe { sysentinel_hypercall_watcher_init() };
        if hcw_rc != 0 {
            pr_warn!("sysentinel_metrics: hypercall watcher init failed (errno {})\n", -hcw_rc);
        }

        // Engage the ring −3 partner chosen by the dispatcher (mirrors the
        // daemon HAL): on Intel, register the MEI client driver (ME/HECI/MKHI);
        // on AMD the PSP path needs no driver registration, so nothing else is
        // done here. Failure is non-fatal — we continue without ME status.
        let partner = ring3::partner();
        pr_info!("sysentinel_metrics: ring −3 partner: {}\n", partner.label());

        #[cfg(mei_available)]
        let mei_registered = {
            mei_driver::ensure_initialized();
            if partner.is_intel_me() {
                match mei_driver::register() {
                    Ok(()) => true,
                    Err(e) if e == ENODEV => false,
                    Err(e) => {
                        pr_warn!("sysentinel_metrics: MEI registration failed ({e:?}); continuing without ME\n");
                        false
                    }
                }
            } else {
                pr_info!(
                    "sysentinel_metrics: silicon has no Intel ME ({}); MEI client not registered\n",
                    partner.label()
                );
                false
            }
        };
        #[cfg(not(mei_available))]
        let mei_registered = false;

        // Keep the #[no_mangle] exports reachable (rustc drops symbols it
        // believes are otherwise unused).
        let (a, b) = (rs_render_snapshot as usize, rs_exec_command as usize);
        let _ = (a, b);

        pr_info!("sysentinel_metrics: /proc/sysentinel_metrics ready\n");

        Ok(Self { _mei_registered: mei_registered })
    }
}

impl Drop for SysentinelMetrics {
    fn drop(&mut self) {
        #[cfg(mei_available)]
        if self._mei_registered {
            mei_driver::unregister();
        }
        // SAFETY: proc_remove is safe to call here; no other users remain.
        unsafe { sysentinel_proc_exit() };
        // SAFETY: unregisters the hypercall kprobe (if attached) and removes
        // its proc node; then drops the defender's IDT/LSTAR baselines.
        unsafe { sysentinel_hypercall_watcher_exit() };
        unsafe { sysentinel_defense_exit() };
        pr_info!("sysentinel_metrics: unloading\n");
    }
}
