// SPDX-License-Identifier: Apache-2.0
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
//! user-space for direct firmware-version queries. The kernel module now
//! performs a real ring-0 handshake with it (`PSP_CMD_HSTI_QUERY` via the ccp
//! driver's exported platform-access API) and reports the fused HSTI word on
//! `psp=up(...)` — that token is parsed below when present. On hosts without
//! the module (or without ccp platform-access), this module falls back to
//! best-effort TPM sysfs data (**only when the host CPU is AMD/Hygon**).
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
#[derive(Debug, Clone, PartialEq, Eq)]
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

/// Live ME channel status from the kernel module's `me_live=` token.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MeLiveStatus {
    /// The MKHI round-trip succeeded on the most recent live re-query.
    pub ok: bool,
    /// Firmware version returned by the live query (present only when `ok`).
    pub version: Option<MeFirmwareVersion>,
    /// Round-trip time in milliseconds.
    pub rt_ms: Option<u64>,
}

/// Aggregated firmware/coprocessor status for this host.
#[derive(Debug, Clone, Default)]
pub struct FirmwareStatus {
    /// Intel ME version, or `None` if not present or not accessible.
    pub intel_me: Option<MeFirmwareVersion>,
    /// Live ME channel status (kernel module `me_live=`), if the module
    /// reported it. `None` when the kernel module is not loaded / no ME.
    pub me_live: Option<MeLiveStatus>,
    /// `me_drift=1` — the live MKHI version differs from the probe-time one.
    pub me_drift: bool,
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
        if let Some(ref live) = self.me_live {
            match (&live.version, live.rt_ms) {
                (Some(v), Some(ms)) => {
                    writeln!(f, "Intel ME live channel: ok (v{v}, rt={ms}ms)")?;
                }
                (Some(v), None) => {
                    writeln!(f, "Intel ME live channel: ok (v{v})")?;
                }
                (None, _) => {
                    writeln!(f, "Intel ME live channel: {}", if live.ok { "ok" } else { "down" })?;
                }
            }
        }
        if self.me_drift {
            writeln!(f, "⚠ Intel ME live version differs from probe-time value (me_drift)")?;
        }
        if let Some(ref psp) = self.amd_psp {
            writeln!(f, "AMD PSP: {psp}")?;
        }
        for note in &self.notes {
            writeln!(f, "  {note}")?;
        }
        if self.intel_me.is_none()
            && self.me_live.is_none()
            && self.amd_psp.is_none()
            && self.notes.is_empty()
        {
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

/// Read the kernel module's one-line snapshot, if the module is loaded.
fn metrics_text() -> Option<String> {
    match fs::read_to_string("/proc/sysentinel_metrics") {
        Ok(d) => Some(d),
        Err(e) => {
            log::debug!("mei: /proc/sysentinel_metrics unreadable ({e}); \
                         query needs the loaded kernel module");
            None
        }
    }
}

/// Query the Intel ME firmware version from the `sysentinel_metrics` kernel
/// module (`/proc/sysentinel_metrics`).
///
/// Returns:
/// - `Ok(Some(version))` on success (module loaded, ME available).
/// - `Ok(None)` if the module is not loaded, the file is unreadable, or the
///   firmware data is absent — treated silently as "no Intel ME", never an error.
pub fn query_intel_me() -> Result<Option<MeFirmwareVersion>> {
    let Some(data) = metrics_text() else {
        return Ok(None);
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

/// Parse a kernel-module `me_live=` token.
///
/// Accepted shapes:
/// - `ok(v18.1.2204.0,rt=2ms)`
/// - `ok(v18.1.2204.0)`
/// - `ok`
/// - `err`
/// - `no-client`
fn parse_me_live(s: &str) -> Option<MeLiveStatus> {
    if matches!(s, "err" | "no-client") {
        return Some(MeLiveStatus::default());
    }
    let rest = s.strip_prefix("ok")?.trim_start_matches('(');
    if rest.is_empty() || rest == ")" {
        // Bare `me_live=ok` — round-trip fine, no version details.
        return Some(MeLiveStatus {
            ok: true,
            version: None,
            rt_ms: None,
        });
    }
    let body = rest.strip_suffix(')')?;
    let mut fields = body.split(',');
    let version = fields
        .next()
        .and_then(|v| v.strip_prefix('v'))
        .and_then(parse_me_fw);
    let rt_ms = fields
        .next()
        .and_then(|r| r.strip_prefix("rt="))
        .and_then(|n| n.strip_suffix("ms"))
        .and_then(|n| n.parse().ok());
    Some(MeLiveStatus {
        ok: true,
        version,
        rt_ms,
    })
}

/// Parse a kernel-module `psp=up(...)` token into its detail string.
fn parse_psp_up(s: &str) -> Option<String> {
    s.strip_prefix("up(")?.strip_suffix(')').map(String::from)
}

/// Query the live ME channel status (`me_live=`) from the kernel module.
pub fn query_me_live() -> Result<Option<MeLiveStatus>> {
    let Some(data) = metrics_text() else {
        return Ok(None);
    };
    for token in data.split_whitespace() {
        if let Some(v) = token.strip_prefix("me_live=") {
            return Ok(parse_me_live(v));
        }
        if token == "me_drift=1" {
            return Ok(Some(MeLiveStatus {
                ok: true,
                version: None,
                rt_ms: None,
            }));
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

    let me_live = match query_me_live() {
        Ok(v)  => v,
        Err(e) => {
            log::warn!("Intel ME live query failed: {e:#}");
            None
        }
    };

    // me_drift=1 requires the kernel module's own classification; the live
    // token above is also present in that case.
    let me_drift = metrics_text()
        .map(|d| d.split_whitespace().any(|t| t == "me_drift=1"))
        .unwrap_or(false);

    let amd_psp = match query_amd_psp() {
        Ok(v)  => v,
        Err(e) => {
            log::warn!("AMD PSP query failed: {e:#}");
            None
        }
    };

    let mut notes: Vec<String> = Vec::new();

    // Kernel-module ring −3 channel: the dispatcher's decision and, on AMD,
    // the fused PSP HSTI handshake evidence (`psp=up(...)`). Ring −2 tokens
    // (`smm=`, `smm_iface=`, `smm_wsmt=`, `ro=`) come from the same line.
    if let Some(data) = metrics_text() {
        for token in data.split_whitespace() {
            if let Some(d) = token.strip_prefix("ring3=") {
                notes.push(format!("Ring −3 dispatch (kernel module): {d}"));
            } else if let Some(d) = token.strip_prefix("smm_iface=") {
                notes.push(format!(
                    "Firmware-declared SMM bridge (ACPI FADT SMI port): {d}"
                ));
            } else if let Some(d) = token.strip_prefix("smm_wsmt=") {
                if d == "none" {
                    notes.push(
                        "No WSMT table — firmware claims no SMM mitigations".into(),
                    );
                } else {
                    notes.push(format!("WSMT SMM-mitigation posture: {d}"));
                }
            } else if let Some(d) = token.strip_prefix("smm=") {
                notes.push(format!("Ring −2 SMM channel: {d}"));
                if d == "acpi" {
                    notes.push(
                        "ACPI-only (FADT + WSMT read) — provably zero SMIs fired".into(),
                    );
                }
            } else if let Some(d) = token.strip_prefix("hvm_lat=") {
                notes.push(format!("Ring −1 hypercall latency: {d}"));
            } else if let Some(d) = token.strip_prefix("crosstalk=") {
                if d != "bare-metal" && d != "no-smm" {
                    notes.push(format!("Cross-side latency delta: {d}"));
                }
            } else if token == "ro=dirty" {
                notes.push("Module rodata changed — possible silent write-hook".into());
            } else if let Some(detail) = token.strip_prefix("psp=up(") {
                let detail = detail.strip_suffix(')').unwrap_or(detail);
                notes.push(format!("PSP HSTI handshake (kernel module): {detail}"));
            }
        }
    }

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

    FirmwareStatus { intel_me, me_live, me_drift, amd_psp, notes }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_me_live_full() {
        let st = parse_me_live("ok(v18.1.2204.0,rt=2ms)").unwrap();
        assert!(st.ok);
        assert_eq!(st.rt_ms, Some(2));
        let v = st.version.unwrap();
        assert_eq!((v.major, v.minor, v.build, v.hotfix), (18, 1, 2204, 0));
    }

    #[test]
    fn parse_me_live_bare_and_down() {
        assert_eq!(parse_me_live("ok").unwrap(), MeLiveStatus { ok: true, version: None, rt_ms: None });
        assert_eq!(parse_me_live("err").unwrap(), MeLiveStatus::default());
        assert_eq!(parse_me_live("no-client").unwrap(), MeLiveStatus::default());
        assert!(parse_me_live("bogus").is_none());
    }

    #[test]
    fn parse_psp_up_token() {
        assert_eq!(
            parse_psp_up("up(hsti=0x00002100,flags=tsme,rt=1ms)").unwrap(),
            "hsti=0x00002100,flags=tsme,rt=1ms"
        );
        assert!(parse_psp_up("present").is_none());
    }

    #[test]
    fn me_drift_classifier() {
        let text = "uptime_s=1 me_fw=18.1.2204.0 me_live=ok(v18.1.2204.0,rt=2ms) me_drift=1 ring3=intel-me\n";
        assert!(text.split_whitespace().any(|t| t == "me_drift=1"));
        assert!(text.split_whitespace().any(|t| t == "ring3=intel-me"));
    }

    #[test]
    fn ring3_token_surface() {
        // Intel: ME tokens, no psp token. AMD: psp token, no me_live token.
        let intel = "ring3=intel-me me_fw=18.1.2204.0 me_live=ok(v18.1.2204.0,rt=2ms)\n";
        let amd = "ring3=amd-psp psp=up(hsti=0x00002100,flags=tsme,rt=1ms)\n";
        let old = "ring3=none cr0=0x0000000080050033\n";

        let dispatch = |text: &str| {
            text.split_whitespace()
                .find_map(|t| t.strip_prefix("ring3="))
                .map(str::to_string)
        };
        assert_eq!(dispatch(intel).as_deref(), Some("intel-me"));
        assert_eq!(dispatch(amd).as_deref(), Some("amd-psp"));
        assert_eq!(dispatch(old).as_deref(), Some("none"));
        assert!(!amd.contains("me_live"));
        assert!(!intel.contains("psp="));
        assert!(!old.contains("me_") && !old.contains("psp="));
    }

    #[test]
    fn ring2_smm_tokens_surface() {
        // SMM channel off by default; opt-in states surface as smm=… and the
        // passive rodata watch always emits ro=.
        let off = "ring3=amd-psp smm=off ro=ok(rt=0us)\n";
        assert!(off.contains("smm=off"));
        assert!(off.contains("ro=ok"));

        let acpi = "ring3=intel-me smm=acpi smm_iface=fadt-smi@0xb2(en=0xf0,pstate=0x80) smm_wsmt=0x00000001(fixed-buffers) hvm_lat=3us ro=ok(rt=1us)\n";
        for t in acpi.split_whitespace() {
            assert!(t != "ro=dirty");
        }
        assert!(acpi.contains("smm=acpi"));
        assert!(acpi.contains("smm_iface=fadt-smi@0xb2"));
        assert!(acpi.contains("smm_wsmt=0x00000001(fixed-buffers)"));
        assert!(acpi.contains("hvm_lat=3us"));
        assert!(acpi.contains("ro=ok"));

        let noiface = "ring3=intel-me smm=acpi smm_iface=none smm_wsmt=none crosstalk=bare-metal ro=ok(rt=1us)\n";
        assert!(noiface.contains("smm_iface=none"));
        assert!(noiface.contains("smm_wsmt=none"));
        assert!(noiface.contains("crosstalk=bare-metal"));

        let dirty = "ring3=amd-psp smm=acpi smm_iface=fadt-smi@0xb2 smm_wsmt=0x00000000(unprotected) ro=dirty\n";
        assert!(dirty.contains("ro=dirty"));
        assert!(dirty.contains("smm_wsmt=0x00000000(unprotected)"));
    }
}
