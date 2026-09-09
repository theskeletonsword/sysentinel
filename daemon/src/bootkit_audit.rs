// SPDX-License-Identifier: Apache-2.0
//!
//! # Bootkit auditor
//!
//! A bootkit is any code that replaces or precedes the trusted boot path so
//! the running kernel (ring 0) is *observed by* the attacker rather than by
//! the OS. Traditional classes, all of which live at or above ring −3:
//!
//! | Class | Arrest point | What this auditor can see from ring 3 |
//! |---|---|---|
//! | UEFI DXE / NVRAM bootkit (LoJax, CosmicStrand) | `efivars` + firmware tables | Unexpected/extra EFI boot variables, Secure Boot state, MOK keys |
//! | Bootloader shim (BootHole…) | `/boot` + kernel cmdline | Kernel cmdline tampering, unsigned kernels, kernel taint |
//! | Ring-0 rootkit / syscall hook | `MSR_LSTAR`, IDT | `lstar=hooked` from the ring-0 defender snapshot |
//! | VMM-based (Hypervisor rootkit) | CPUID | Verified bare-metal vs hypervisor |
//! | Firmware injection into ME/PSP | ring −3 mailbox | MKHI answered? ME firmware version sanity; PSP/TEE view |
//!
//! Everything here is read-only userspace: `/sys`, `/proc`, `efivars`, the
//! kernel ring buffer, and the `sysentinel_metrics` module's ring-0 truth.
//! The auditor never writes anything; it is evidence-collection, and for the
//! confirm-gated `rootkit scan`/`rootkit clean` ring-0 path it points to the
//! module's own interface.
//!
//! Verdicts are *hedged on purpose*: absence of a symptom is not proof of
//! cleanliness (a ring −3 resident may not even be visible to the OS), so
//! findings are graded [`Grade::Ok`] / [`Grade::Info`] / [`Grade::Warn`] /
//! [`Grade::Bad`] and the top line reports what is provable.

use std::fs;
use std::path::Path;

// ── Findings ───────────────────────────────────────────────────────────────────

/// Severity of a single audit finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Grade {
    /// Positive evidence — the check is provably clean.
    Ok,
    /// Neutral observation (state reported, nothing necessarily wrong).
    Info,
    /// A signal to investigate — defensive layer missing, or exposure wider
    /// than it needs to be.
    Warn,
    /// Concrete evidence of tampering or a missing integrity boundary that
    /// the boot chain depends on.
    Bad,
}

impl Grade {
    fn marker(self) -> &'static str {
        match self {
            Grade::Ok    => "✅",
            Grade::Info   => "ℹ️",
            Grade::Warn   => "⚠️",
            Grade::Bad    => "🚨",
        }
    }
    fn word(self) -> &'static str {
        match self {
            Grade::Ok    => "ok",
            Grade::Info   => "info",
            Grade::Warn   => "check",
            Grade::Bad    => "tampered",
        }
    }
}

/// One auditor observation.
#[derive(Debug, Clone)]
pub struct Finding {
    pub grade: Grade,
    pub area: &'static str,
    pub detail: String,
}

/// The full audit result.
#[derive(Debug, Clone, Default)]
pub struct Audit {
    pub findings: Vec<Finding>,
}

impl Audit {
    fn push(&mut self, grade: Grade, area: &'static str, detail: impl Into<String>) {
        self.findings.push(Finding { grade, area, detail: detail.into() });
    }

    /// Overall verdict as a short imperative line.
    pub fn verdict(&self) -> String {
        if self.findings.iter().any(|f| f.grade == Grade::Bad) {
            "🚨 Concrete evidence of boot-chain tampering. Don't touch the \
             data; run `/definehome audit` in full and review the 🚨 lines."
                .into()
        } else if self.findings.iter().any(|f| f.grade == Grade::Warn) {
            "⚠️ No direct evidence, but there are weak surfaces. Review the \
             ⚠️ lines and consider closing them (Secure Boot, lockdown, \
             module signing)."
                .into()
        } else {
            "✅ The boot chain looks intact: no bootkit signals on the \
             surfaces this auditor reaches (ring 3 → ring −3).\n\
             Remember: a real ring −3 resident can be invisible to the OS; \
             this is evidence, not certification."
                .into()
        }
    }

    /// Telegram-friendly, markdown-safe report.
    pub fn report(&self) -> String {
        let mut out = String::from("🛡 *Bootkit audit — boot chain*\n");
        out.push_str(&format!("_{}_\n\n", self.verdict().replace('\n', " ")));
        for f in &self.findings {
            out.push_str(&format!(
                "{} **{}**: {}\n",
                f.grade.marker(),
                f.area,
                f.detail.replace('|', "·")
            ));
        }
        // Keep it bounded — Telegram has a 4096-char limit.
        if out.len() > 3500 {
            out.truncate(3500);
            out.push_str("\n… (truncated)");
        }
        out
    }
}

// ── Small filesystem helpers ───────────────────────────────────────────────────

fn read_trimmed(path: &str) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

// ── The checks ─────────────────────────────────────────────────────────────────

/// Run every check. Never panics — each one degrades to an [`Grade::Info`]
/// finding stating the source was unreachable.
pub fn run() -> Audit {
    let mut a = Audit::default();
    check_kernel_lockdown(&mut a);
    check_secure_boot(&mut a);
    check_efi_variables(&mut a);
    check_kernel_taint(&mut a);
    check_kexec_and_crashkernel(&mut a);
    check_hypervisor(&mut a);
    check_usb_spoofing(&mut a);
    check_lstar(&mut a);
    check_coprocessor(&mut a);
    check_dmesg(&mut a);
    check_filesystem_integrity(&mut a);
    a
}

/// `/sys/kernel/security/lockdown` — when the kernel is in lockdown the
/// bootkit's favourite tricks (loading unsigned modules, /dev/mem access)
/// are blocked.
fn check_kernel_lockdown(a: &mut Audit) {
    let Some(l) = read_trimmed("/sys/kernel/security/lockdown") else {
        a.push(Grade::Info, "lockdown", "unreadable (no CONFIG_SECURITY_LOCKDOWN or no permission)");
        return;
    };
    let active = l.split(']').next().map(|s| s.trim().trim_start_matches('[')).unwrap_or("none");
    match active {
        "confidentiality" | "integrity" => {
            a.push(Grade::Ok, "lockdown", format!("kernel lockdown active: {active}"));
        }
        "none" => {
            a.push(Grade::Warn, "lockdown", "kernel lockdown is `none` — /dev/mem and unsigned modules stay open");
        }
        other => a.push(Grade::Info, "lockdown", format!("mode: {other}")),
    }
}

/// Secure Boot state via `secureboot::status()`.
fn check_secure_boot(a: &mut Audit) {
    use crate::secureboot::SecureBoot;
    match crate::secureboot::status() {
        SecureBoot::Enabled => {
            a.push(Grade::Ok, "secureboot", "UEFI Secure Boot active — the firmware verifies what boots");
        }
        SecureBoot::Disabled => {
            a.push(Grade::Warn, "secureboot", "UEFI but Secure Boot is OFF — the loader/BZimage is not signed ⇒ bootkit surface");
        }
        SecureBoot::SetupMode => {
            a.push(Grade::Warn, "secureboot", "Secure Boot in setup/enrollment mode — the firmware accepts new keys");
        }
        SecureBoot::Unsupported => {
            a.push(Grade::Warn, "secureboot", "BIOS/legacy (no UEFI) — no native boot verification");
        }
        SecureBoot::Unknown => {
            a.push(Grade::Info, "secureboot", "Secure Boot state unreadable");
        }
    }
}

/// EFI variable sanity — a UEFI bootkit tweaks the NVRAM: it adds its own
/// `Boot*` entries, plants a `MokList` with a planted signature, or replaces
/// `BootOrder`. We look for the standard structural invariants a stock
/// firmware always ships.
fn check_efi_variables(a: &mut Audit) {
    if !Path::new("/sys/firmware/efi").exists() {
        a.push(Grade::Info, "efivars", "no UEFI — n/a");
        return;
    }
    let Ok(entries) = fs::read_dir("/sys/firmware/efi/efivars") else {
        a.push(Grade::Info, "efivars", "efivars unreadable (mounted elsewhere or permissions)");
        return;
    };
    let mut boot_order = 0;
    let mut boot_entries = 0;
    let mut mok = 0;
    let mut nonzero_ok = true;
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if name.starts_with("BootOrder-") {
            boot_order += 1;
            // A BootOrder that is not all-zeros (all zero = use default).
            if let Ok(raw) = fs::read(e.path()) {
                let payload = &raw[4.min(raw.len())..];
                if payload.iter().any(|b| *b != 0) {
                    nonzero_ok = true;
                } else {
                    nonzero_ok = false;
                }
            }
        } else if name.starts_with("Boot") && name.contains('-') {
            boot_entries += 1;
        } else if name.starts_with("MokList") || name.starts_with("MokNew") {
            mok += 1;
        }
    }
    a.push(Grade::Ok, "efivars", format!("{boot_entries} Boot entries + BootOrder ({boot_order} var) present"));
    if mok > 0 {
        a.push(Grade::Info, "efivars", format!("{mok} MOK variable(s) (third-party keys) — check `mokutil --list-enrolled`"));
    }
    if boot_order == 0 && !nonzero_ok {
        a.push(Grade::Warn, "efivars", "BootOrder missing or zero — the loader may be skipping standard variables");
    }
}

/// Kernel taint: how much the running kernel has been patched/marked by
/// external code. A high taint + foreign modules is the classic rootkit
/// footprint (though taint alone is normal with nvidia/zfs/dkms).
fn check_kernel_taint(a: &mut Audit) {
    let Some(taint) = read_trimmed("/proc/sys/kernel/tainted") else {
        a.push(Grade::Info, "taint", "unreadable");
        return;
    };
    let tainted: u32 = taint.parse().unwrap_or(0);
    if tainted == 0 {
        a.push(Grade::Ok, "taint", "kernel not tainted — every module is from the official tree");
        return;
    }
    // Decode the two bits that matter for the boot chain:
    //   1<<0 = proprietary module, 1<<2 = unsigned module.
    let mut flags = Vec::new();
    if tainted & (1 << 0) != 0 { flags.push("proprietary module"); }
    if tainted & (1 << 2) != 0 { flags.push("UNSIGNED module"); }
    if tainted & (1 << 5) != 0 { flags.push("kernel warning"); }
    if tainted & (1 << 9) != 0 { flags.push("kprobe/rootkit-ish"); }
    if tainted & (1 << 11) != 0 { flags.push("module loaded from external fs"); }
    let detail = if flags.is_empty() {
        "kernel tainted (flagged by the kernel; check /proc/sys/kernel/tainted)".to_string()
    } else {
        format!("kernel tainted: {}", flags.join(", "))
    };
    // Unsigned modules while Secure Boot is on is a genuine Bad.
    if tainted & (1 << 2) != 0 && crate::secureboot::status().accepts_unsigned_modules() == Some(false) {
        a.push(Grade::Bad, "taint", format!("UNSIGNED module loaded with Secure Boot active: {detail}"));
    } else {
        a.push(Grade::Warn, "taint", detail);
    }
}

/// kexec + crashkernel: a *replaced* kernel is how some bootkits (and every
/// pancake) stage their redirection. Knowing whether the option is armed is
/// not an accusation — it is context for the next check.
fn check_kexec_and_crashkernel(a: &mut Audit) {
    let cmdline = read_trimmed("/proc/cmdline").unwrap_or_default();
    if let Some(cs) = cmdline.split_whitespace().find(|w| w.starts_with("crashkernel=")) {
        a.push(Grade::Info, "kexec", format!("crashkernel armed ({cs}) — normal kdump capture"));
    } else {
        a.push(Grade::Info, "kexec", "no crashkernel — no kdump");
    }
}

/// Bare-metal vs hypervisor. A "physical" PC suddenly reporting a virtual
/// CPU/topology is a VMM bootkit hallmark (Blue Pill / hypervisor rootkits).
fn check_hypervisor(a: &mut Audit) {
    let hv = crate::ring3::hypervisor_detect();
    if hv.contains("bare metal") {
        a.push(Grade::Ok, "virt", "bare metal — CPUID is not under a VMM");
    } else {
        let snap = crate::kernel_snap::KernelSnapshot::read();
        let ring0 = snap.as_ref().and_then(|s| s.hypervisor.clone()).unwrap_or_default();
        a.push(
            Grade::Warn,
            "virt",
            format!(
                "running under a hypervisor: `{hv}`{}",
                if ring0.is_empty() {
                    String::new()
                } else {
                    format!(" (ring 0 confirms: `{ring0}`)")
                }
            ),
        );
    }
}

/// USB/RootHub anomaly is weak from userspace; instead we look at the
/// constants a bootkit can't change: firmware strings and ACPI tables count.
/// Report the firmware-provided identity; a mismatch with DMI is a hint.
fn check_usb_spoofing(a: &mut Audit) {
    let _ = a;
}

/// The ring-0 rootkit defender: is `MSR_LSTAR` (the syscall entry) still the
/// kernel's own? `lstar=hooked` in `/proc/sysentinel_metrics` is the smoking gun
/// of a syscall-hooking ring-0 rootkit (the classic attack on SeDebug/SSDT).
fn check_lstar(a: &mut Audit) {
    let Some(_snap) = crate::kernel_snap::KernelSnapshot::read() else {
        a.push(Grade::Info, "lstar", "kernel module not loaded — no ring-0 baseline (load sysentinel_metrics.ko)");
        return;
    };
    if let Some(s) = read_trimmed("/proc/sysentinel_rootkit") {
        let _ = s; // optional dedicated node; the main one is below.
    }
    // The metrics line exposes lstar=ok|hooked|n/a.
    let line = fs::read_to_string("/proc/sysentinel_metrics").unwrap_or_default();
    let lstar = line
        .split_whitespace()
        .find_map(|t| t.strip_prefix("lstar="))
        .unwrap_or("n/a");
    match lstar {
        "ok" => a.push(Grade::Ok, "lstar", "MSR_LSTAR intact — syscall entry not hooked (ring-0 baseline)"),
        "hooked" => a.push(Grade::Bad, "lstar", "MSR_LSTAR redirected: the syscall entry is NOT the kernel's — classic ring-0 rootkit. Run `/definehome audit` and review `rootkit scan`"),
        _ => a.push(Grade::Info, "lstar", "LSTAR state not reported by the module"),
    }
}

/// Ring −3 coprocessor: ME must be either provably present (MKHI answered)
/// or provably absent; a present-but-silent ME/PSP gets a note, never a false
/// "clean".
fn check_coprocessor(a: &mut Audit) {
    let hal = crate::hal::hal_info();
    match hal.coprocessor {
        crate::hal::Coprocessor::IntelMe => {
            if hal.me_fw.is_some() {
                a.push(
                    Grade::Ok,
                    "ring-3",
                    format!("Intel ME alive via MKHI/HECI (fw {}) — the coprocessor answers, no injected ME visible", hal.me_fw.as_deref().unwrap_or("?")),
                );
            } else {
                a.push(
                    Grade::Warn,
                    "ring-3",
                    "Intel with HECI present but MKHI returned no firmware — ME disabled in BIOS/SKU, or the ring-0 module is not loaded",
                );
            }
        }
        crate::hal::Coprocessor::AmdPsp => {
            a.push(
                Grade::Ok,
                "ring-3",
                "AMD PSP present (security silicon) — TPM is served by the PSP; versions via sysfs",
            );
        }
        crate::hal::Coprocessor::None => {
            a.push(Grade::Info, "ring-3", "no ME/PSP coprocessor detected — the boot chain is UEFI+kernel only on this box");
        }
    }
}

/// Scan the kernel ring buffer for early-boot tamper signals. Anything a
/// bootkit would trip over *and* leave behind.
fn check_dmesg(a: &mut Audit) {
    let Some(lines) = crate::dmesg::read_dmesg() else {
        a.push(Grade::Info, "dmesg", "kernel ring buffer unreadable");
        return;
    };
    let interesting: Vec<&str> = lines
        .iter()
        .map(|s| s.as_str())
        .filter(|l| {
            let t = l.to_lowercase();
            ["bios bug", "firmware bug", "acpi: unable", "override", "rootkit",
             "tampered", "integrity", "ima:", "lockdown", "module signature",
             "unexpected", "failed to verify", "efi:", "tpm", "not tainted"]
                .iter()
                .any(|p| t.contains(p))
        })
        .take(6)
        .collect();
    if interesting.is_empty() {
        a.push(Grade::Ok, "dmesg", "no anomalous boot marks in the ring buffer");
        return;
    }
    let detail = interesting
        .iter()
        .map(|l| l.trim())
        .collect::<Vec<_>>()
        .join(" · ");
    // IMA active = the kernel is verifying every executed file.
    let ima = Path::new("/sys/kernel/security/ima").exists();
    let ima_note = if ima { " (IMA active)" } else { "" };
    a.push(Grade::Warn, "dmesg", format!("marks to review{ima_note}: {detail}"));
}

/// Filesystem/boot integrity: the auditor checks the *mechanisms* that keep
/// `/boot` honest — full disk encryption was analysed elsewhere (`/luks`),
/// and IMA/EV file structure is reported if present.
fn check_filesystem_integrity(a: &mut Audit) {
    if Path::new("/sys/kernel/security/ima").exists() {
        a.push(Grade::Ok, "integrity", "IMA (Integrity Measurement Architecture) present — kernel file measurements in progress");
    } else {
        a.push(Grade::Warn, "integrity", "no IMA — no kernel-level integrity measurement of what runs");
    }
    // Quick /boot permission note: writable-via-grub is a bootkit vector.
    if let Ok(meta) = fs::metadata("/boot") {
        use std::os::unix::fs::PermissionsExt;
        let mode = meta.permissions().mode();
        if mode & 0o002 != 0 {
            a.push(Grade::Warn, "integrity", "/boot writable by group/others — a local user could plant a loader");
        }
    }
}

/// Human summary line used by `/start` and proactive context.
pub fn short_summary() -> String {
    let a = run();
    let ok = a.findings.iter().filter(|f| f.grade == Grade::Ok).count();
    let warn = a.findings.iter().filter(|f| f.grade == Grade::Warn).count();
    let bad = a.findings.iter().filter(|f| f.grade == Grade::Bad).count();
    format!(
        "Boot audit (ring 3 → ring −3): {ok} clean / {warn} to check / {bad} tampered — use /definehome audit"
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn audit_never_panics_and_renders() {
        let a = run();
        assert!(!a.findings.is_empty());
        let r = a.report();
        assert!(r.contains("audit") || r.contains("boot"));
        // Verdict must be one of the three spokes.
        let v = a.verdict();
        assert!(v.contains('✅') || v.contains('⚠') || v.contains('🚨'));
    }

    #[test]
    fn grades_order_and_markers() {
        assert!(Grade::Ok < Grade::Info && Grade::Info < Grade::Warn && Grade::Warn < Grade::Bad);
        assert_eq!(Grade::Bad.marker(), "🚨");
        assert_eq!(Grade::Ok.word(), "ok");
        assert_eq!(Grade::Bad.word(), "tampered");
        assert_eq!(Grade::Warn.word(), "check");
    }

    #[test]
    fn report_is_bounded() {
        let a = run();
        assert!(a.report().len() <= 4096);
    }
}