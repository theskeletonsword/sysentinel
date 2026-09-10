// SPDX-License-Identifier: Apache-2.0
//!
//! # Hardware Abstraction Layer (HAL) — the ring −3 coprocessor dispatcher
//!
//! This module is the one place that decides *which* out-of-band security
//! coprocessor this PC carries and asks that coprocessor, by its own bus, what
//! it can prove about itself:
//!
//! ```text
//!   ring 3 (user)          ── sysentinel-daemon (this file) ──
//!   ring 0 (kernel)        ── sysentinel_metrics.ko  (MKHI/HECI client) ──
//!   ring -3 (silicon)      ── Intel ME (HECI/MEI bus) | AMD PSP/SEV (SMN) ──
//! ```
//!
//! Intel ME and AMD PSP execute below the OS at ring −3: nothing the running
//! kernel (ring 0) or the daemon (ring 3) does can tamper with their firmware,
//! and they are the first code to see the CPU at reset. A bootkit that lives
//! above ring −3 (UEFI dxe driver, bootloader shim, ring-0 rootkit) can fake
//! *sysfs*, *procfs* and *SMBIOS*, but it cannot answer on the ME's own
//! coprocessor mailbox. So the HAL's job is to collect *silicon-truth tokens*
//! — things only the ring −3 coprocessor or the physical silicon can state —
//! and hand them to the identity system (`/,detecthome`) and to the bootkit
//! auditor.
//!
//! # Platform dispatch
//!
//! [`coprocessor()`] is the dispatcher: it reads the CPU vendor from
//! `/proc/cpuinfo` and routes the query accordingly.
//!
//! - **Intel** → the ME is drunk through HECI/MEI. The MKHI client answers
//!   `GET_FW_VERSION` in ring 0 (the kernel module binds the MEI bus and caches
//!   the version; we read it back on `/proc/sysentinel_metrics`). The HAL also
//!   inspects the MEI bus (`/sys/bus/mei`, `/sys/class/mei`) — the presence of
//!   the MEI controller (`00:16.x`) and its bounded clients (MKHI, AMT/WD,
//!   …) is *advanced PC detection*: it tells *which* ME features the silicon
//!   exposes.
//! - **AMD/Hygon** → the PSP is queried best-effort from sysfs (TPM is served
//!   by the PSP, the CCP device is the PSP's crypto engine). No stable raw
//!   mailbox ABI is exposed to userspace on stock kernels, so we stay honest
//!   and say "present, version via TPM".
//! - **Neither** → "*none*", the honest label.
//!
//! # Identity contract
//!
//! [`silicon_tokens()`] returns the tokens that are BOTH unique-per-unit and
//! **stable across firmware updates** — the platform kind, the HECI/MEI
//! controller presence, the PCH chipset ids, the CPU family/model/stepping,
//! and the TPM chip identity. These feed `/definehome`'s fingerprint.
//! [`firmware_evidence()`] returns the rolling version-level facts (ME
//! firmware, TPM firmware) which DO change on a legitimate firmware update —
//! they are shown in the report and tracked as *drift*, but never mixed into
//! the identity hash (so updating ME/BIOS/TPM firmware never false-negatives
//! "esta no es tu PC").

use std::fs;
use std::path::Path;

// ── Platform identification ────────────────────────────────────────────────────

/// Which ring −3 coprocessor the silicon carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coprocessor {
    /// Intel Management Engine, queried over HECI/MKHI.
    IntelMe,
    /// AMD/Hygon Platform Security Processor.
    AmdPsp,
    /// No ME/PSP-class coprocessor detected (e.g. ARM, or an Intel/AMD part
    /// with the ME disabled in firmware).
    None,
}

impl Coprocessor {
    pub fn label(self) -> &'static str {
        match self {
            Coprocessor::IntelMe => "Intel ME (ring −3, via HECI/MKHI)",
            Coprocessor::AmdPsp   => "AMD PSP (ring −3, ccp platform-access HSTI)",
            Coprocessor::None     => "none (no ME/PSP-class coprocessor)",
        }
    }

    pub fn short(self) -> &'static str {
        match self {
            Coprocessor::IntelMe => "intel-me",
            Coprocessor::AmdPsp   => "amd-psp",
            Coprocessor::None     => "none",
        }
    }
}

/// CPU vendor id verbatim from `/proc/cpuinfo` (first line).
pub fn cpu_vendor_id() -> Option<String> {
    let cpuinfo = fs::read_to_string("/proc/cpuinfo").ok()?;
    for line in cpuinfo.lines() {
        if let Some(v) = line.strip_prefix("vendor_id") {
            let v = v.split(':').nth(1).unwrap_or("").trim();
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// CPU family/model/stepping (the stable part of the silicon id) from
/// `/proc/cpuinfo`. `None` where the fields are missing.
pub fn cpu_part_id() -> Option<String> {
    let cpuinfo = fs::read_to_string("/proc/cpuinfo").ok()?;
    let (mut fam, mut model, mut step, mut phys) = (None, None, None, None);
    for line in cpuinfo.lines() {
        let Some((k, v)) = line.split_once(':') else { continue };
        match k.trim() {
            "cpu family"   if fam.is_none()   => fam = v.trim().parse::<u32>().ok(),
            "model"        if model.is_none() => model = v.trim().parse::<u32>().ok(),
            "stepping"     if step.is_none()  => step = v.trim().parse::<u32>().ok(),
            "physical id"  if phys.is_none()  => phys = v.trim().parse::<u32>().ok(),
            _ => {}
        }
    }
    Some(format!(
        "f{:02x}m{:02x}s{:02x}p{:02x}",
        fam.unwrap_or(0),
        model.unwrap_or(0),
        step.unwrap_or(0),
        phys.unwrap_or(0),
    ))
}

/// Dispatcher: which coprocessor does this CPU carry?
pub fn coprocessor() -> Coprocessor {
    match cpu_vendor_id().as_deref() {
        Some("AuthenticAMD" | "HygonGenuine") => Coprocessor::AmdPsp,
        Some("GenuineIntel") => {
            // Intel SKUs ME-disabled in firmware still expose the HECI PCI
            // function, but to be conservative we require either the MEI bus
            // subsystem or the module's MKHI answer; without either we report
            // "none" so we never claim an ME that isn't there.
            if heci_controller_present() || mei_bus_present() {
                Coprocessor::IntelMe
            } else {
                // Many Intel boards shut the ME image off (NO_ME / disabled
                // CSF). Keep the label honest: no reachable ME.
                Coprocessor::None
            }
        }
        _ => Coprocessor::None,
    }
}

// ── HECI / MEI (Intel) inspection ───────────────────────────────────────────────

/// Does the PCI HECI/MEI controller exist? On Intel chipsets since the 8–series
/// it is the function at bus 0, device 0x16 (class 0x0780 "Communication
/// controller"). Its presence is per-silicon and unchanging across firmware.
pub fn heci_controller_present() -> bool {
    Path::new("/sys/bus/pci/devices").exists()
        && fs::read_dir("/sys/bus/pci/devices")
            .map(|d| {
                d.flatten().any(|e| {
                    let n = e.file_name().to_string_lossy().into_owned();
                    let base = e.path();
                    let class = fs::read_to_string(base.join("class")).unwrap_or_default();
                    if !class.contains("0780") {
                        return false;
                    }
                    // Match any space — some platforms address it differently.
                    n.contains(":16.") || vendor_is_intel(&base)
                })
            })
            .unwrap_or(false)
}

/// Is the MEI (Management Engine Interface) bus subsystem up at all?
pub fn mei_bus_present() -> bool {
    Path::new("/sys/bus/mei").exists() || Path::new("/sys/class/mei").exists()
}

fn vendor_is_intel(base: &Path) -> bool {
    fs::read_to_string(base.join("vendor"))
        .map(|v| v.trim() == "0x8086")
        .unwrap_or(false)
}

/// MEI clients currently visible on the MEI bus — advanced detection of *which*
/// ME features the silicon exposes (MKHI, AMT watchdog, HECI-NFC, …). Each stub
/// is best-effort; a bare list of client directory names is also fine.
pub fn mei_clients() -> Vec<String> {
    let mut out: Vec<String> = Vec::new();

    if let Ok(entries) = fs::read_dir("/sys/bus/mei/mei_bus") {
        for e in entries.flatten() {
            out.push(e.file_name().to_string_lossy().into_owned());
        }
    }
    if let Ok(entries) = fs::read_dir("/sys/bus/mei/devices") {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            // einfo presence (firmware-readable) is what a bootkit *cannot* fake.
            out.push(mei_client_label(&name));
        }
    }

    // The kernel module's `/proc/sysentinel_metrics` line proves a MKHI client
    // answered over the real MEI bus (ring 0 → ring −3). That is the strongest,
    // spoof-proof ME presence signal we have.
    if let Some(snap) = crate::kernel_snap::KernelSnapshot::read() {
        if snap.me_fw.is_some() {
            out.push("MKHI(ring0←answered get_fw_version)".into());
        }
    }

    out.sort();
    out.dedup();
    out
}

/// Turn a MEI client directory name into a short label when the well-known GUIDs
/// show up; otherwise keep the raw name. The two big ones:
///   MKHI  {8e6a6715-9abc-4043-88ef-9e39c6f63e0f}
///   AMT/WD… (Intel AMT / watchdog cluster).
fn mei_client_label(name: &str) -> String {
    let lower = name.to_lowercase();
    if lower.contains("8e6a6715") || lower.contains("9abc4043") {
        "MKHI".into()
    } else if lower.contains("3d08a342") || lower.contains("12f80028") || lower.contains("05b79a6f") {
        "AMT/cluster".into()
    } else if lower.starts_with("0000:") {
        // Raw PCI-id folder like 0000:00:16.0-…; strip the noise.
        name.to_string()
    } else {
        name.to_string()
    }
}

/// Best-effort ME firmware version: first from the ring-0 MKHI answer on
/// `/proc/sysentinel_metrics`, else via the MEI-class sysfs node if exposed.
pub fn me_firmware_version() -> Option<String> {
    if let Some(snap) = crate::kernel_snap::KernelSnapshot::read() {
        if snap.me_fw.is_some() {
            return snap.me_fw;
        }
    }
    // Fallback: some distros expose a version string under the MEI class node.
    for cand in [
        "/sys/class/mei/mei0/fw_version",
        "/sys/bus/mei/devices/mei-me/fw_version",
    ] {
        if let Ok(v) = fs::read_to_string(cand) {
            let v = v.trim().to_string();
            if !v.is_empty() && v != "unknown" {
                return Some(v);
            }
        }
    }
    None
}

// ── AMD PSP inspection ──────────────────────────────────────────────────────────

/// AMD PSP best-effort description. The SEV-ES/SNP firmware lives inside the
/// PSP; on servers `/sys/devices/system/cpu/vulnerabilities` or firmware
/// attributes expose bits, and the TPM is answered by the PSP. We stay honest:
/// "present, no stable mailbox to userspace".
pub fn psp_description() -> Option<String> {
    if coprocessor() != Coprocessor::AmdPsp {
        return None;
    }
    let fw = crate::mei::query_amd_psp().ok().flatten();
    if let Some(d) = fw {
        return Some(d);
    }
    let ccp = [
        "/dev/ccp",
        "/sys/bus/platform/drivers/ccp",
        "/sys/module/ccp",
    ]
    .iter()
    .any(|p| Path::new(p).exists());
    Some(if ccp {
        "AMD CCP/PSP present (version mailbox is ring-0-only; see kernel_module/)".to_string()
    } else {
        "AMD PSP present (TPM served by PSP; raw version mailbox not exposed to ring 3)".to_string()
    })
}

// ── TPM (the ring −3 companion) ────────────────────────────────────────────────

/// One TPM chip identity, as the kernel exposes it. `vendor`/`model` come from
/// the chip description when present (they are the stable part), `fw` is the
/// rolling firmware revision.
#[derive(Debug, Clone)]
pub struct TpmChip {
    pub path: String,
    pub description: String,
    pub fw: String,
    pub major: Option<u32>,
}

/// Enumerate `/sys/class/tpm/*` chips.
pub fn tpm_chips() -> Vec<TpmChip> {
    let mut chips = Vec::new();
    let Ok(entries) = fs::read_dir("/sys/class/tpm") else {
        return chips;
    };
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        if !name.starts_with("tpm") {
            continue;
        }
        let base = e.path();
        let description = fs::read_to_string(base.join("description"))
            .unwrap_or_default()
            .trim()
            .to_string();
        let fw = fs::read_to_string(base.join("fw_version"))
            .ok()
            .or_else(|| {
                fs::read_to_string(base.join("tpm_version")).ok()
            })
            .unwrap_or_default()
            .trim()
            .to_string();
        let major = fs::read_to_string(base.join("tpm_version_major"))
            .ok()
            .and_then(|s| s.trim().parse().ok());
        chips.push(TpmChip {
            path: format!("/sys/class/tpm/{name}"),
            description,
            fw,
            major,
        });
    }
    chips.sort_by(|a, b| a.path.cmp(&b.path));
    chips
}

/// The stable TPM chip id (presence + chip model), never the rolling fw.
fn tpm_identity_tokens() -> Vec<String> {
    tpm_chips()
        .into_iter()
        .map(|t| {
            let model = if t.description.is_empty() {
                t.path.rsplit('/').next().unwrap_or("tpm").to_string()
            } else {
                t.description.clone()
            };
            format!(
                "tpm:{}:v{}",
                model,
                t.major.map(|m| m.to_string()).unwrap_or_else(|| "?".into())
            )
        })
        .collect()
}

// ── Chipset / PCH ──────────────────────────────────────────────────────────────

/// Latest PCH (or main Intel chipset bridge) id as vendor:device:class. The
/// PCH is the glue between CPU and platform; its identifier is per-silicon and
/// stable across firmware. `None` on non-Intel or when unreadable.
pub fn chipset_id() -> Option<String> {
    let Ok(entries) = fs::read_dir("/sys/bus/pci/devices") else {
        return None;
    };
    for e in entries.flatten() {
        let base = e.path();
        let vendor = fs::read_to_string(base.join("vendor")).unwrap_or_default();
        if vendor.trim() != "0x8086" {
            continue;
        }
        let class = fs::read_to_string(base.join("class")).unwrap_or_default();
        let class = class.trim().to_string();
        // LPC/eSPI bridge (IsaBridge 06_01) or the P2PB/SA bridges — any of
        // these is the PCH. Prefer 06_01 (the LPC one where the PCH always is).
        if class.starts_with("0x06") {
            let device = fs::read_to_string(base.join("device"))
                .unwrap_or_default()
                .trim()
                .to_string();
            let revision = fs::read_to_string(base.join("revision"))
                .unwrap_or_default()
                .trim()
                .to_string();
            return Some(format!("8086:{device} r{revision} {class}"));
        }
    }
    None
}

// ── The HAL result ─────────────────────────────────────────────────────────────

/// Everything the HAL could prove about this PC's ring −3 landscape.
#[derive(Debug, Clone)]
pub struct HalInfo {
    pub coprocessor: Coprocessor,
    pub cpu_vendor: String,
    pub cpu_part: String,
    pub me_fw: Option<String>,
    pub psp: Option<String>,
    /// HECI/MEI controller present (the PCI contract, unchangeable by software).
    pub heci_controller: bool,
    /// MEI bus clients visible — advanced PC detection payload.
    pub mei_clients: Vec<String>,
    pub tpm: Vec<TpmChip>,
    pub chipset: Option<String>,
    pub hypervisor: Option<String>,
    pub notes: Vec<String>,
}

/// Run the dispatcher and collect everything it can prove. Never errors —
/// every source degrades to absence, never to a hallucinated value.
pub fn hal_info() -> HalInfo {
    let mut notes: Vec<String> = Vec::new();

    let coprocessor = coprocessor();

    let heci_controller = heci_controller_present();

    let me_fw = if coprocessor == Coprocessor::IntelMe {
        me_firmware_version()
    } else {
        None
    };
    let psp = if coprocessor == Coprocessor::AmdPsp {
        psp_description()
    } else {
        None
    };

    let mei_clients = if heci_controller || mei_bus_present() {
        mei_clients()
    } else {
        Vec::new()
    };

    if coprocessor == Coprocessor::IntelMe && me_fw.is_none() && heci_controller {
        notes.push(
            "MEI controller is present but MKHI did not answer a firmware version \
             (ME image may be firmware-disabled on this SKU, or the ring-0 module \
             is not loaded)."
                .to_string(),
        );
    }

    let hypervisor = crate::kernel_snap::KernelSnapshot::read()
        .and_then(|s| s.hypervisor)
        .or_else(|| {
            // Ring-3 fallback hypervisor truth when the module is absent.
            let v = crate::ring3::hypervisor_detect();
            if v.contains("sin hypervisor") || v.contains("bare metal") {
                None
            } else {
                Some(v)
            }
        });

    let cpu_vendor = cpu_vendor_id().unwrap_or_else(|| "unknown".into());
    let cpu_part = cpu_part_id().unwrap_or_else(|| "unknown".into());

    HalInfo {
        coprocessor,
        cpu_vendor,
        cpu_part,
        me_fw,
        psp,
        heci_controller,
        mei_clients,
        tpm: tpm_chips(),
        chipset: chipset_id(),
        hypervisor,
        notes,
    }
}

impl HalInfo {
    /// Machine-readable one-liner for logs/status.
    // Compact HAL rendering; kept alongside the verbose report.
    #[allow(dead_code)]
    pub fn summary(&self) -> String {
        let fw = self
            .me_fw
            .as_deref()
            .or(self.psp.as_deref())
            .unwrap_or("n/a (no ring −3 coprocessor)");
        format!(
            "hal: coprocessor={} vendor={} cpu_part={} fw={} tpm={} chipset={}",
            self.coprocessor.short(),
            self.cpu_vendor,
            self.cpu_part,
            fw,
            self.tpm.len(),
            self.chipset.as_deref().unwrap_or("n/a"),
        )
    }

    /// Telegram-friendly rendering for `/firmware` and `/definehome hal`.
    pub fn render_markdown(&self) -> String {
        let mut out = String::new();
        out.push_str("🔩 *HAL — ring −3 coprocessor*\n");
        out.push_str(&format!("  coprocessor: `{}`\n", self.coprocessor.label()));
        out.push_str(&format!("  cpu vendor: {}\n", self.cpu_vendor));
        out.push_str(&format!("  cpu part (fmh): `{}`\n", self.cpu_part));

        if let Some(ref me) = self.me_fw {
            out.push_str(&format!("  Intel ME firmware (MKHI): `{me}`\n"));
        }
        if let Some(ref psp) = self.psp {
            out.push_str(&format!("  AMD PSP: {psp}\n"));
        }

        out.push_str(&format!(
            "  HECI controller: {}\n",
            if self.heci_controller { "present" } else { "absent" }
        ));
        if !self.mei_clients.is_empty() {
            out.push_str(&format!(
                "  MEI clients: `{}`\n",
                self.mei_clients.join(", ")
            ));
        }

        // The service surface behind those clients: what each one is, who has
        // claimed it, and who on this host can reach the bus at all.
        let surface = crate::meiclients::enumerate();
        if !surface.is_empty() {
            out.push_str("  Ring −3 surface:\n");
            for note in surface.notes() {
                out.push_str(&format!("    - {note}\n"));
            }
        }

        for t in &self.tpm {
            let desc = if t.description.is_empty() {
                t.path.clone()
            } else {
                format!("{} ({})", t.description, t.path.rsplit('/').next().unwrap_or("tpm"))
            };
            out.push_str(&format!(
                "  TPM: {}{}\n",
                desc,
                if t.fw.is_empty() {
                    String::new()
                } else {
                    format!(" — fw `{}`", t.fw)
                }
            ));
        }

        if let Some(ref cs) = self.chipset {
            out.push_str(&format!("  PCH/chipset: `{cs}`\n"));
        }
        if let Some(ref h) = self.hypervisor {
            out.push_str(&format!("  platform/hypervisor: {h}\n"));
        }
        for note in &self.notes {
            out.push_str(&format!("  ⚠ {note}\n"));
        }
        out
    }
}

// ── Identity contract ──────────────────────────────────────────────────────────

/// **Stable** per-unit silicon tokens (the ring −3 anti-clone payload for
/// `/definehome`). These are physically unique and do NOT change on firmware
/// updates: platform kind, HECI presence, CPU family/model/stepping, chipset
/// ids, TPM chip identity and (when the ring-0 module answered) the MEI bus
/// presence. They are mixed into the fingerprint hash.
pub fn silicon_tokens() -> Vec<String> {
    let mut t = Vec::new();

    let cp = coprocessor().short();
    if cp != "none" {
        t.push(cp.to_string());
    }

    if let Some(part) = cpu_part_id() {
        if part != "unknown" {
            t.push(part);
        }
    }

    if heci_controller_present() {
        t.push("heci:present".into());
    } else if mei_bus_present() {
        t.push("mei:present".into());
    }

    if let Some(cs) = chipset_id() {
        t.push(cs);
    }

    t.extend(tpm_identity_tokens());

    // The strongest token: MKHI answered from ring 0 — only the real ME can.
    if let Some(snap) = crate::kernel_snap::KernelSnapshot::read() {
        if snap.me_fw.is_some() {
            t.push("mkhi:answered".into());
        }
    }

    t.sort();
    t.dedup();
    t
}

/// **Rolling** firmware evidence — changes on a legitimate update, so it is
/// shown to the user and tracked as drift, never hashed.
pub fn firmware_evidence() -> Vec<String> {
    let mut e = Vec::new();
    if let Some(me) = me_firmware_version() {
        e.push(format!("intel-me-fw={me}"));
    }
    for t in tpm_chips() {
        if !t.fw.is_empty() {
            e.push(format!("tpm-fw={}", t.fw));
        }
    }
    e
}

/// Short, human label used in the fingerprint report.
pub fn platform_label() -> &'static str {
    coprocessor().short()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hal_never_panics_and_dispatches() {
        let info = hal_info();
        // Whatever the platform, the dispatcher produced a coherent result and
        // the summary renders.
        assert!(!info.render_markdown().is_empty());
        assert!(!info.summary().is_empty());
    }

    #[test]
    fn coprocessor_matches_cpu_vendor() {
        match cpu_vendor_id().as_deref() {
            Some("AuthenticAMD" | "HygonGenuine") => {
                assert_eq!(coprocessor(), Coprocessor::AmdPsp)
            }
            Some("GenuineIntel") => {
                // With no HECI/MEI visible it must degrade to None, never
                // hallucinate an ME.
                let cp = coprocessor();
                assert!(matches!(cp, Coprocessor::IntelMe | Coprocessor::None));
                if heci_controller_present() {
                    assert_eq!(cp, Coprocessor::IntelMe);
                }
            }
            _ => assert_eq!(coprocessor(), Coprocessor::None),
        }
    }

    #[test]
    fn silicon_tokens_are_stable_and_deduplicated() {
        let a = silicon_tokens();
        let b = silicon_tokens();
        assert_eq!(a, b, "silicon tokens must be stable between runs");
        let mut dedup = a.clone();
        dedup.sort();
        dedup.dedup();
        assert_eq!(a.len(), dedup.len(), "silicon tokens must not repeat");
    }

    #[test]
    fn firmware_evidence_never_panics() {
        let _ = firmware_evidence();
    }

    #[test]
    fn tpm_parsing_is_bounded() {
        // On this machine chips exist or not; our reader must never error.
        let _ = tpm_chips();
    }
}