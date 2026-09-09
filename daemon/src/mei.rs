// SPDX-License-Identifier: MIT OR GPL-2.0-or-later
//!
//! User-space Intel ME / AMD PSP firmware status reader.
//!
//! # Intel ME (HECI/MEI)
//!
//! ME firmware queries are performed **in ring-0** by the `sysentinel_metrics`
//! kernel module (see `kernel_module/`), which binds the MKHI MEI client on the
//! kernel's own MEI bus and exposes the result on `/proc/sysentinel_metrics`.
//! This module just reads that one-shot procfs file and parses `me_fw=` from it.
//!
//! No raw (`ioctl`/`read`/`write` on `/dev/mei0`) protocol is used here, and
//! the daemon therefore does **not** need root or membership in a `mei` group —
//! it needs only read access to the module's procfs file (mode `0644`).
//!
//! If the kernel module is not loaded (or ME is not available), the query
//! degrades silently to "no Intel ME" — never an error.
//!
//! # AMD PSP
//!
//! The AMD Platform Security Processor does not expose a stable ioctl ABI to
//! user-space for direct firmware-version queries. The PSP mailbox registers
//! (`MP0_SMN_C2P_MSG_*`) are accessible from the x86 side only via SMN
//! (System Management Network) aperture reads, which require ring-0 or a
//! specialised kernel driver. This module reads best-effort version
//! information from the kernel's TPM sysfs interface (**only when the host CPU
//! is AMD/Hygon**) and from CCP device presence in `/sys`.
//!
//! On non-AMD hosts (e.g. Intel with PTT) the same TPM sysfs data is reported
//! under a vendor-accurate label instead of being misattributed to the PSP.
//!
//! # Dependencies
//!
//! Pure `std` file reads; no raw syscalls and no `libc`.

use anyhow::Result;
use std::fs;

// ── Public types ─────────────────────────────────────────────────────────────

/// Intel ME firmware version reported by the MKHI MEI client.
#[derive(Debug, Clone)]
pub struct MeFirmwareVersion {
    pub major:  u16,
    pub minor:  u16,
    pub build:  u16,
    pub hotfix: u16,
}

impl std::fmt::Display for MeFirmwareVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}.{}.{}", self.major, self.minor, self.build, self.hotfix)
    }
}

/// Aggregated firmware/coprocessor status for this host.
#[derive(Debug, Clone, Default)]
pub struct FirmwareStatus {
    /// Intel ME version, or `None` if not present or not accessible.
    pub intel_me: Option<MeFirmwareVersion>,
    /// AMD PSP description string, or `None` if not present.
    pub amd_psp:  Option<String>,
    /// Additional notes (active LSMs, TPM caps, etc.).
    pub notes:    Vec<String>,
}

impl std::fmt::Display for FirmwareStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(ref me) = self.intel_me {
            writeln!(f, "Intel ME firmware: {me}")?;
        }
        if let Some(ref psp) = self.amd_psp {
            writeln!(f, "AMD PSP: {psp}")?;
        }
        for note in &self.notes {
            writeln!(f, "  {note}")?;
        }
        if self.intel_me.is_none() && self.amd_psp.is_none() && self.notes.is_empty() {
            write!(f, "(no Intel ME or AMD PSP detected on this system)")?;
        }
        Ok(())
    }
}

// ── Intel ME query (via kernel module) ────────────────────────────────────────

/// Parse an `M.H.B.F` ME firmware version string (major.minor.build.hotfix).
fn parse_me_fw(s: &str) -> Option<MeFirmwareVersion> {
    let mut it = s.split('.');
    let major: u16 = it.next()?.trim().parse().ok()?;
    let minor: u16 = it.next()?.trim().parse().ok()?;
    let build: u16 = it.next()?.trim().parse().ok()?;
    let hotfix: u16 = it.next().and_then(|h| h.trim().parse().ok()).unwrap_or(0);
    Some(MeFirmwareVersion { major, minor, build, hotfix })
}

/// Query the Intel ME firmware version from the `sysentinel_metrics` kernel
/// module (`/proc/sysentinel_metrics`).
///
/// Returns:
/// - `Ok(Some(version))` on success (module loaded, ME available).
/// - `Ok(None)` if the module is not loaded, the file is unreadable, or the
///   firmware data is absent — treated silently as "no Intel ME", never an error.
pub fn query_intel_me() -> Result<Option<MeFirmwareVersion>> {
    let data = match fs::read_to_string("/proc/sysentinel_metrics") {
        Ok(d) => d,
        Err(e) => {
            log::debug!("mei: /proc/sysentinel_metrics unreadable ({e}); \
                         ME query needs the loaded kernel module");
            return Ok(None);
        }
    };

    for token in data.split_whitespace() {
        if let Some(v) = token.strip_prefix("me_fw=") {
            if let Some(ver) = parse_me_fw(v) {
                return Ok(Some(ver));
            }
        }
    }

    Ok(None)
}

// ── CPU vendor helpers ────────────────────────────────────────────────────────

/// Read the first `vendor_id` line from `/proc/cpuinfo`.
fn cpu_vendor_id() -> Option<String> {
    let cpuinfo = fs::read_to_string("/proc/cpuinfo").ok()?;
    for line in cpuinfo.lines() {
        let mut it = line.splitn(2, ':');
        if it.next().map(str::trim) == Some("vendor_id") {
            return it.next().map(|v| v.trim().to_string());
        }
    }
    None
}

/// True only for AMD (or Hygon, which implements AMD-compatible PSP silicon).
fn cpu_is_amd() -> bool {
    matches!(
        cpu_vendor_id().as_deref(),
        Some("AuthenticAMD" | "HygonGenuine")
    )
}

/// True for Intel CPUs.
fn cpu_is_intel() -> bool {
    cpu_vendor_id().as_deref() == Some("GenuineIntel")
}

// ── AMD PSP query (sysfs) ─────────────────────────────────────────────────────

/// Read the AMD PSP / TPM firmware information from sysfs.
///
/// On AMD platforms the PSP manages the TPM 2.0 stack. The kernel exposes
/// basic version information via `/sys/class/tpm/tpm0/`. This function
/// aggregates what's readable without elevated privileges.
///
/// Returns `Ok(None)` on non-AMD hosts — the TPM there is not the PSP.
pub fn query_amd_psp() -> Result<Option<String>> {
    if !cpu_is_amd() {
        log::debug!("mei: host CPU is not AMD — no AMD PSP query");
        return Ok(None);
    }

    let mut parts = tpm_summary();

    // AMD CCP/PSP device presence in sysfs.
    let ccp_present = [
        "/dev/ccp",
        "/sys/bus/platform/drivers/ccp",
        "/sys/module/ccp",
    ]
    .iter()
    .any(|p| std::path::Path::new(p).exists());

    if ccp_present && parts.is_empty() {
        parts.push(
            "AMD CCP/PSP present (direct firmware-version query requires \
             ring-0 access; see kernel_module/ for the ring-0 path)"
                .to_string(),
        );
    }

    // AMD-specific: check for PSP version via /sys/class/firmware-attributes
    // (available on some Ryzen laptop platforms).
    let fw_attrs = "/sys/class/firmware-attributes";
    if std::path::Path::new(fw_attrs).exists() {
        if let Ok(entries) = fs::read_dir(fw_attrs) {
            for entry in entries.flatten() {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if name.contains("psp") || name.contains("PSP") {
                    parts.push(format!("PSP firmware attribute: {name}"));
                }
            }
        }
    }

    if parts.is_empty() {
        Ok(None)
    } else {
        Ok(Some(parts.join("\n  ")))
    }
}

/// Best-effort TPM 2.0 summary from `/sys/class/tpm/tpm0/`.
fn tpm_summary() -> Vec<String> {
    let mut parts: Vec<String> = Vec::new();

    // /sys/class/tpm/tpm0/caps — older kernel format.
    let caps_path = "/sys/class/tpm/tpm0/caps";
    if let Ok(caps) = fs::read_to_string(caps_path) {
        for line in caps.lines() {
            let l = line.trim();
            if l.starts_with("Manufacturer:")
                || l.starts_with("Firmware version:")
                || l.starts_with("TCG version:")
            {
                parts.push(l.to_string());
            }
        }
    }

    // /sys/class/tpm/tpm0/tpm_version_major
    if let Ok(v) = fs::read_to_string("/sys/class/tpm/tpm0/tpm_version_major") {
        parts.push(format!("TPM version major: {}", v.trim()));
    }

    // /sys/class/tpm/tpm0/description
    if let Ok(desc) = fs::read_to_string("/sys/class/tpm/tpm0/description") {
        let d = desc.trim();
        if !d.is_empty() {
            parts.push(format!("TPM description: {d}"));
        }
    }

    parts
}

// ── Aggregated query ──────────────────────────────────────────────────────────

/// Query both Intel ME and AMD PSP, aggregate results.
///
/// This is the main entry point used by `hwdiag.rs` and `bot.rs`.
/// Never panics — errors are logged and treated as absence.
pub fn query_firmware_status() -> FirmwareStatus {
    let intel_me = match query_intel_me() {
        Ok(v)  => v,
        Err(e) => {
            log::warn!("Intel ME query failed: {e:#}");
            None
        }
    };

    let amd_psp = match query_amd_psp() {
        Ok(v)  => v,
        Err(e) => {
            log::warn!("AMD PSP query failed: {e:#}");
            None
        }
    };

    let mut notes: Vec<String> = Vec::new();

    // On non-AMD hosts the TPM is not driven by an AMD PSP (on Intel platforms
    // it is usually the in-CPU "Intel PTT"). Report the same sysfs data under
    // a vendor-accurate label instead of misattributing it to the PSP.
    if !cpu_is_amd() {
        let tpm = tpm_summary();
        if !tpm.is_empty() {
            let label = if cpu_is_intel() { "Intel PTT TPM" } else { "System TPM" };
            notes.push(format!("{label}:\n  {}", tpm.join("\n  ")));
        }
    }

    // Add active LSM list if available.
    if let Ok(lsm) = fs::read_to_string("/sys/kernel/security/lsm") {
        let lsm = lsm.trim();
        if !lsm.is_empty() {
            notes.push(format!("Active LSMs: {lsm}"));
        }
    }

    // Kernel lockdown status.
    if let Ok(ld) = fs::read_to_string("/sys/kernel/security/lockdown") {
        let ld = ld.trim();
        if !ld.is_empty() {
            notes.push(format!("Kernel lockdown: {ld}"));
        }
    }

    FirmwareStatus { intel_me, amd_psp, notes }
}
