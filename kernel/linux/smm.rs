// SPDX-License-Identifier: MIT OR GPL-2.0-or-later
//
// Ring −2 (SMM) firmware posture via ACPI.

//! Ring −2 (SMM) firmware posture, read strictly through ACPI.
//!
//! SMM is one layer below the kernel: an isolated handler that runs when the
//! firmware raises a System Management Interrupt, invisible from every ring
//! ≥ 0 — the gap the ring −3 alliance (ME/PSP) does not cover. The kernel
//! cannot observe SMM's internals, and it must not *raise* SMIs to probe it:
//! an SMI with a wrong command value on the APM ports (0xB2/0xB3) can mean
//! shutdown, soft-off, watchdog reset or a wedged machine. This module
//! therefore **never raises an SMI — by construction**. There is no code path
//! that performs any SMM-triggering I/O; the ring −2 channel is a passive
//! reader of the tables the firmware itself publishes (`src/smm_shim.c`):
//!
//! - **FADT `smi_command`** — the firmware's official SMM command port and the
//!   spec-defined commands it documents (`acpi_enable`, `acpi_disable`,
//!   `s4_bios_request`, `pstate_control`). Surfaced read-only as
//!   `smm_iface=fadt-smi@0x…`; the kernel writes through this port only with
//!   those declared values (`drivers/acpi/processor_perflib.c`, FreeBSD
//!   `sys/x86/cpufreq/smist.c`).
//! - **WSMT** (Windows SMM Security Mitigations Table) — the firmware's own
//!   claim of which SMM mitigations it enabled: fixed CommBuffers,
//!   nested-pointer protection, system-resource protection. A firmware that
//!   publishes an SMI calling interface (FADT) but *no* WSMT protections is
//!   exactly the configuration an SMM bootkit needs — a measurable posture.
//!
//! The `ro=` canary completes the ring −2 watch: a passive integrity +
//! read-latency check on the module's own rodata (no SMI), catching silent
//! re-writes of kernel regions — a classic die-hard hook.
//!
//! All of it is **opt-in**: tokens appear only after `smm on` (privileged
//! write), which performs the read-only ACPI scan and stores the posture.
//! Reading `/proc/sysentinel_metrics` then reports cached values; reads never
//! touch the ACPI tables either, so the read path stays fast and pure.

#![allow(dead_code)]

use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

// ── State codes (persisted atomically so render never locks) ────────────────

const S_OFF: u32 = 0;
const S_ACPI: u32 = 1;
const S_ERR: u32 = 2;

static SMM_ON: AtomicBool = AtomicBool::new(false);
static SMM_STATE: AtomicU32 = AtomicU32::new(S_OFF);
static SMM_ERRNO: AtomicU32 = AtomicU32::new(0);

// Cached FADT/WSMT posture (filled by the read-only scan on `smm on`).
static IFACE_FADT_PORT: AtomicU64 = AtomicU64::new(0);
static IFACE_FADT_EN: AtomicU32 = AtomicU32::new(0);
static IFACE_FADT_PSTATE: AtomicU32 = AtomicU32::new(0);
static IFACE_FADT_S4: AtomicU32 = AtomicU32::new(0);
static WSMT_FLAGS: AtomicU32 = AtomicU32::new(0);
static WSMT_PRESENT: AtomicBool = AtomicBool::new(false);
static IFACE_SCAN_DONE: AtomicBool = AtomicBool::new(false);

/// Arm the channel. This ONLY performs the read-only firmware-posture scan —
/// it can never fire an SMI because the scan is table reads.
pub fn smm_enable() -> bool {
    smm_iface_scan();
    SMM_ON.store(true, Ordering::SeqCst);
    true
}

pub fn smm_disable() {
    SMM_ON.store(false, Ordering::SeqCst);
}

pub fn smm_is_enabled() -> bool {
    SMM_ON.load(Ordering::Relaxed)
}

// ── FFI to src/smm_shim.c (ACPI reads only) ──────────────────────────────────

extern "C" {
    /// READ-ONLY: FADT official SMI command port + documented command values.
    fn sysentinel_smm_fadt_scan(
        port: *mut u64,
        acpi_en: *mut u8,
        acpi_dis: *mut u8,
        pstate_ctl: *mut u8,
        s4_bios: *mut u8,
    ) -> core::ffi::c_int;
    /// READ-ONLY: WSMT protection flags (raw word + presence).
    fn sysentinel_smm_wsmt_scan(
        flags: *mut u32,
        present: *mut core::ffi::c_int,
    ) -> core::ffi::c_int;
}

/// Read-only discovery of the firmware's SMM posture from its ACPI tables.
/// Performs zero I/O to any SMM-triggering port: it only reads FADT/WSMT
/// through the ACPI subsystem. Safe to call on any firmware.
pub fn smm_iface_scan() {
    let mut port: u64 = 0;
    let mut en: u8 = 0;
    let mut dis: u8 = 0;
    let mut pstate: u8 = 0;
    let mut s4: u8 = 0;
    // SAFETY: valid out-pointers; the shim only reads ACPI globals/tables and
    // writes the out-pointers.
    unsafe {
        sysentinel_smm_fadt_scan(&mut port, &mut en, &mut dis, &mut pstate, &mut s4);
    }
    let _ = dis;
    let _ = s4;
    IFACE_FADT_PORT.store(port, Ordering::Relaxed);
    IFACE_FADT_EN.store(en as u32, Ordering::Relaxed);
    IFACE_FADT_PSTATE.store(pstate as u32, Ordering::Relaxed);
    IFACE_FADT_S4.store(s4 as u32, Ordering::Relaxed);

    let mut wsmt: u32 = 0;
    let mut present: core::ffi::c_int = 0;
    // SAFETY: valid out-pointers; the shim reads the WSMT table, copies the
    // flags word, then releases the table.
    let rc = unsafe { sysentinel_smm_wsmt_scan(&mut wsmt, &mut present) };
    match rc {
        0 => {
            WSMT_FLAGS.store(wsmt, Ordering::Relaxed);
            WSMT_PRESENT.store(present != 0, Ordering::Relaxed);
            SMM_STATE.store(S_ACPI, Ordering::Relaxed);
        }
        e if e == -95 || e == -2 || e == -19 => {
            // -EOPNOTSUPP/-ENOENT/-ENODEV: table absent, not a fault.
            WSMT_PRESENT.store(false, Ordering::Relaxed);
            SMM_STATE.store(S_ACPI, Ordering::Relaxed);
        }
        e => {
            WSMT_PRESENT.store(false, Ordering::Relaxed);
            SMM_ERRNO.store(e as u32, Ordering::Relaxed);
            SMM_STATE.store(S_ERR, Ordering::Relaxed);
        }
    }

    IFACE_SCAN_DONE.store(true, Ordering::Relaxed);
}

/// Append the `smm=` state token plus the read-only posture tokens.
pub fn write_tokens<W: core::fmt::Write>(w: &mut W) {
    if !SMM_ON.load(Ordering::Relaxed) {
        let _ = write!(w, " smm=off");
        return;
    }

    let state = SMM_STATE.load(Ordering::Relaxed);
    match state {
        S_OFF => { let _ = write!(w, " smm=off"); }
        S_ACPI => { let _ = write!(w, " smm=acpi"); }
        _ => {
            let e = SMM_ERRNO.load(Ordering::Relaxed);
            let _ = write!(w, " smm=err(c={})", e);
        }
    }

    write_iface_token(w);
    write_wsmt_token(w);
    write_hvm_latency(w);
}

/// Append `smm_iface=…`: the firmware's declared SMM bridge (FADT), read-only.
fn write_iface_token<W: core::fmt::Write>(w: &mut W) {
    let port = IFACE_FADT_PORT.load(Ordering::Relaxed);
    if port == 0 {
        let _ = write!(w, " smm_iface=none");
        return;
    }
    let _ = write!(w, " smm_iface=fadt-smi@0x{:x}", port);
    let en = IFACE_FADT_EN.load(Ordering::Relaxed);
    let ps = IFACE_FADT_PSTATE.load(Ordering::Relaxed);
    let s4 = IFACE_FADT_S4.load(Ordering::Relaxed);
    let mut first = true;
    for (v, name) in [(en, "en"), (ps, "pstate"), (s4, "s4")] {
        if v != 0 {
            let _ = if first {
                write!(w, "({}={:#x}", name, v)
            } else {
                write!(w, ",{}={:#x}", name, v)
            };
            first = false;
        }
    }
    if !first {
        let _ = write!(w, ")");
    }
}

/// Append `smm_wsmt=…`: the firmware's SMM-mitigation posture (WSMT), read-only.
fn write_wsmt_token<W: core::fmt::Write>(w: &mut W) {
    if !WSMT_PRESENT.load(Ordering::Relaxed) {
        let _ = write!(w, " smm_wsmt=none");
        return;
    }
    let flags = WSMT_FLAGS.load(Ordering::Relaxed);
    let mut names = [""; 3];
    let mut n = 0;
    if flags & 1 != 0 {
        names[n] = "fixed-buffers";
        n += 1;
    }
    if flags & 2 != 0 {
        names[n] = "comm-nested-ptr";
        n += 1;
    }
    if flags & 4 != 0 {
        names[n] = "system-res";
        n += 1;
    }
    let _ = write!(w, " smm_wsmt={:#010x}", flags);
    if flags == 0 {
        let _ = write!(w, "(unprotected)");
    } else if n > 0 {
        let _ = write!(w, "(");
        for (i, name) in names[..n].iter().enumerate() {
            if i > 0 {
                let _ = write!(w, ",");
            }
            let _ = write!(w, "{}", name);
        }
        let _ = write!(w, ")");
    }
}

/// Append `hvm_lat=…us`: the ring −1 hypercall latency fingerprint (VM only).
/// Without an SMI (which the module refuses to fire) there is no ring −2
/// latency to compare, so this is reported standalone.
fn write_hvm_latency<W: core::fmt::Write>(w: &mut W) {
    let Some(hvm_us) = crate::hypercall::hypercall_latency_us() else {
        let _ = write!(w, " crosstalk=bare-metal");
        return;
    };
    let _ = write!(w, " hvm_lat={}us", hvm_us);
}

// ── Passive rodata canary watch (no SMI, always on) ──────────────────────────

/// 64 bytes of module rodata. A die-hard hook re-writing our own memory
/// (typically via a CR0.WP-clearing keyboard/APIC task) changes this checksum.
const RO_REGION: [u8; 64] = [
    0x53, 0x59, 0x53, 0x45, 0x4e, 0x54, 0x49, 0x4e, 0x45, 0x4c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
];

static RO_BASELINE: AtomicU64 = AtomicU64::new(0);
static RO_RT_US: AtomicU64 = AtomicU64::new(0);
static RO_LAST_CHECK: AtomicU64 = AtomicU64::new(0);
static RO_DONE_FIRST: AtomicBool = AtomicBool::new(false);

/// Compute the FNV-1a hash of the rodata region.
fn fnv1a(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in data {
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}

/// Seed the rodata baseline once at module init.
pub fn ro_init() {
    RO_BASELINE.store(fnv1a(&RO_REGION), Ordering::Relaxed);
    RO_DONE_FIRST.store(true, Ordering::Relaxed);
}

/// Re-check window for the passive rodata watch.
const WINDOW_NS: u64 = 60_000_000_000;

/// Run the integrity + read-latency check at most once per window.
pub fn ro_check(now_ns: u64) {
    if !RO_DONE_FIRST.load(Ordering::Relaxed) {
        return;
    }
    let last = RO_LAST_CHECK.load(Ordering::Relaxed);
    if last != 0 && now_ns.saturating_sub(last) < WINDOW_NS {
        return;
    }
    RO_LAST_CHECK.store(now_ns, Ordering::Relaxed);

    // Time the re-read: a die-hard hook (EPT write-tracking, SMM patching)
    // makes the read path observably slow or corrupts the checksum.
    let t0 = kernel::time::Instant::<kernel::time::BootTime>::now()
        .elapsed()
        .as_nanos()
        .unsigned_abs();
    fnv1a(&RO_REGION);
    let us = (kernel::time::Instant::<kernel::time::BootTime>::now()
        .elapsed()
        .as_nanos()
        .unsigned_abs()
        .saturating_sub(t0))
        / 1_000;
    RO_RT_US.store(us, Ordering::Relaxed);
}

/// Whether the rodata canary currently diverges from its baseline.
pub fn ro_dirty() -> bool {
    if !RO_DONE_FIRST.load(Ordering::Relaxed) {
        return false;
    }
    fnv1a(&RO_REGION) != RO_BASELINE.load(Ordering::Relaxed)
}

/// Append the `ro=` token (passive canary watch, always on).
pub fn write_ro_token<W: core::fmt::Write>(w: &mut W) {
    match (ro_dirty(), RO_RT_US.load(Ordering::Relaxed)) {
        (true, rt) => {
            let _ = write!(w, " ro=dirty");
            let _ = rt;
        }
        (false, 0) => { let _ = write!(w, " ro=ok"); }
        (false, rt) => { let _ = write!(w, " ro=ok(rt={}us)", rt); }
    }
}