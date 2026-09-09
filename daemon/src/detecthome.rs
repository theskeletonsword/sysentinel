// SPDX-License-Identifier: Apache-2.0
//!
//! This-machine fingerprint for `/definehome` / `/detecthome`.
//!
//! The bot must know whether it is physically running on YOUR PC. Two
//! machines may share vendor/model/firmware strings (identical laptops roll
//! off the same assembly line), so the fingerprint NEVER relies on model
//! names alone. The identity we hash includes the per-unit unique numbers
//! printed at the factory:
//!
//!   - motherboard serial            (DMIRS — unique per board)
//!   - system product UUID           (SMBIOS SystemInformation UUID)
//!   - machine/chassis serials
//!   - per-DIMM memory serials       (each RAM stick has a unique serial)
//!   - the primary NIC MAC address
//!
//! All of those differ between two otherwise-identical PCs, so a cloned or
//! same-model machine produces a DIFFERENT hash — no false positives. The
//! CPU/GPU/RAM totals are included for the human-readable report only.
//!
//! # Ring −3 reinforcement (silicon truth)
//!
//! Since the `hal` module landed, the fingerprint is reinforced with tokens
//! the operating system cannot forge and firmware updates do NOT change:
//!
//!   - which ring −3 coprocessor the silicon carries (Intel ME via HECI/MKHI
//!     vs AMD PSP) — from `/hal`
//!   - CPU family/model/stepping + package id
//!   - the PCH/chipset vendor:device:revision (the glue of the platform)
//!   - HECI controller presence (the PCI contract for the ME, per-unit)
//!   - TPM chip identity (model + version major), read straight from sysfs
//!   - the fact that MKHI answered `GET_FW_VERSION` over the real MEI bus
//!     (ring 0 → ring −3): only the physical ME can reply, a bootkit cannot
//!
//! Those are produced by [`crate::hal::silicon_tokens()`] and mixed into the
//! same SHA-256 as the serials always were. The *rolling* firmware versions
//! (ME fw, TPM fw) are *not* hashed — they legitimately change on an update —
//! but they are captured in the profile as [`HomeProfile::silicon_note`] and
//! reported as **drift** by `/definehome status`, so a reflashed ME/BIOS/TPM
//! is visible without ever false-negativing "esta es tu PC".
//!
//! The hash is SHA-256 (implemented inline; no extra dependency, and it
//! beats the std `DefaultHasher` by being stable across builds).

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Everything this machine can say about itself (best-effort per field).
#[derive(Debug, Clone, Default)]
pub struct MachineIdentity {
    // ── DMI / SMBIOS (model-level + unique serials) ─────────────────────────
    pub sys_vendor: String,
    pub product_name: String,
    pub product_serial: String,
    pub product_uuid: String,
    pub board_vendor: String,
    pub board_name: String,
    pub board_serial: String,
    pub chassis_serial: String,
    pub bios_version: String,
    // ── Compute / GPU / RAM ────────────────────────────────────────────────
    pub cpu_model: String,
    pub cpu_cores: u32,
    pub gpus: Vec<String>,
    pub mem_total_mb: u64,
    /// Unique SMBIOS DIMM serials (the anti-clone payload).
    pub dimm_serials: Vec<String>,
    // ── Network (unique per NIC) ─────────────────────────────────────────────
    pub primary_mac: String,
    // ── Ring −3 silicon (from the `hal` module) ──────────────────────────────
    /// Long-lived, firmware-update-stable tokens (coprocessor kind, CPU part,
    /// chipset ids, HECI presence, TPM chip id, MKHI proof). Mixed into the
    /// identity hash — see the module docs.
    pub silicon_ids: Vec<String>,
    /// *Rolling* firmware versions (ME fw, TPM fw, chipset) — shown in the
    /// report and as drift, deliberately NOT hashed.
    pub firmware_evidence: Vec<String>,
}

/// Persisted "this is MY PC" profile written by `/definehome`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HomeProfile {
    pub fingerprint: String,
    pub captured_at: String,
    pub hostname: String,
    pub summary: String,
    /// Ring −3 landscape at capture time: silicon tokens + rolling firmware
    /// evidence. Used by `/definehome status` to show drift on updates.
    #[serde(default)]
    pub silicon_note: String,
    /// TPM key ("es tu PC", see `crate::tpmkey`): the AEAD-sealed holder +
    /// TPM metadata that only the physical TPM at define-time can open, bound
    /// to the fingerprint's AAD. `None` ⇒ fingerprint-only binding (no TPM).
    #[serde(default)]
    pub tpm_key: Option<crate::tpmkey::TpmKeyMeta>,
}

/// Seconds-epoch timestamp, in the profile's existing `{:?}` style.
pub fn now_iso() -> String {
    format!("{:?}", std::time::SystemTime::now())
}

/// Read a DMI value, tolerating a missing node and "unknown" markers.
fn dmi(name: &str) -> String {
    std::fs::read_to_string(format!("/sys/devices/virtual/dmi/id/{name}"))
        .map(|s| s.trim().to_string())
        .unwrap_or_default()
}

fn trimmed_or_none(s: &str) -> bool {
    !s.is_empty() && !s.eq_ignore_ascii_case("unknown") && s.to_lowercase() != "not specified"
}

/// Collect the machine identity from sysfs /proc. Never returns an error —
/// every category degrades to empty/"n/a" if unreadable.
pub fn collect_identity() -> MachineIdentity {
    let mut id = MachineIdentity {
        sys_vendor: dmi("sys_vendor"),
        product_name: dmi("product_name"),
        product_serial: dmi("product_serial"),
        product_uuid: dmi("product_uuid"),
        board_vendor: dmi("board_vendor"),
        board_name: dmi("board_name"),
        board_serial: dmi("board_serial"),
        chassis_serial: dmi("chassis_serial"),
        bios_version: dmi("bios_version"),
        ..Default::default()
    };

    // CPU model + package/core counts.
    if let Ok(raw) = std::fs::read_to_string("/proc/cpuinfo") {
        let mut seen_model = false;
        for line in raw.lines() {
            if let Some(v) = line.strip_prefix("model name") {
                if !seen_model {
                    id.cpu_model = v.split(':').nth(1).unwrap_or("").trim().to_string();
                    seen_model = true;
                }
            }
        }
        id.cpu_cores = raw.lines().filter(|l| l.starts_with("processor")).count() as u32;
    }

    // GPUs via /sys/class/drm/card* vendor:device pairs.
    if let Ok(entries) = std::fs::read_dir("/sys/class/drm") {
        for e in entries.flatten() {
            let name = e.file_name().to_string_lossy().into_owned();
            if !name.starts_with("card") || name.contains("card") && !name[4..].bytes().all(|b| b.is_ascii_digit()) {
                continue;
            }
            let dev = e.path().join("device");
            let vendor = std::fs::read_to_string(dev.join("vendor")).unwrap_or_default();
            let device = std::fs::read_to_string(dev.join("device")).unwrap_or_default();
            let v = vendor.trim().trim_start_matches("0x");
            let d = device.trim().trim_start_matches("0x");
            if !v.is_empty() && !d.is_empty() {
                let g = format!("{v}:{d}");
                if !id.gpus.contains(&g) {
                    id.gpus.push(g);
                }
            }
        }
    }
    id.gpus.sort();

    // RAM totals.
    if let Ok(raw) = std::fs::read_to_string("/proc/meminfo") {
        if let Some(line) = raw.lines().find(|l| l.starts_with("MemTotal:")) {
            if let Some(kb) = line.split_whitespace().nth(1) {
                id.mem_total_mb = kb.parse::<u64>().unwrap_or(0) / 1024;
            }
        }
    }

    // DIMM serials — the strong anti-clone token.
    if let Ok(entries) = std::fs::read_dir("/sys/firmware/dmi/entries/type-17") {
        for e in entries.flatten() {
            let serial = std::fs::read_to_string(e.path().join("serial")).unwrap_or_default();
            let s = serial.trim().to_string();
            if trimmed_or_none(&s) && s.to_lowercase() != "no dimm" {
                id.dimm_serials.push(s);
            }
        }
        id.dimm_serials.sort();
        id.dimm_serials.dedup();
    }
    if id.dimm_serials.is_empty() {
        id.dimm_serials.push("(no dimm serials readable)".into());
    }

    // Primary MAC: NIC on the default route, else the first hardware NIC.
    id.primary_mac = default_route_iface()
        .and_then(|iface| read_mac(&iface))
        .or_else(|| {
            std::fs::read_dir("/sys/class/net")
                .ok()
                .and_then(|es| es.flatten().map(|e| e.file_name().to_string_lossy().into_owned()).find(|i| i != "lo"))
                .and_then(|iface| read_mac(&iface))
        })
        .unwrap_or_default();

    // Ring −3 silicon reinforcement — see the module docs. The tokens are
    // stable and come from the HAL dispatcher; the rolling firmware evidence
    // rides along for the drift report only.
    id.silicon_ids = crate::hal::silicon_tokens();
    id.firmware_evidence = crate::hal::firmware_evidence();

    id
}

fn read_mac(iface: &str) -> Option<String> {
    let mac = std::fs::read_to_string(format!("/sys/class/net/{iface}/address"))
        .unwrap_or_default();
    let mac = mac.trim().to_lowercase();
    if mac.is_empty() || mac == "00:00:00:00:00:00" {
        None
    } else {
        Some(mac)
    }
}

/// NIC used by the default IPv4 route (from /proc/net/route).
fn default_route_iface() -> Option<String> {
    let raw = std::fs::read_to_string("/proc/net/route").ok()?;
    for line in raw.lines().skip(1) {
        let mut it = line.split_whitespace();
        let iface = it.next()?;
        let dest = it.next()?;
        let _gen = it.next()?;
        let flags = it.next()?;
        // 0x0001 = RTF_UP; 0x0002 = RTF_GATEWAY; dest 00000000 = default.
        if dest == "00000000" && flags.parse::<u32>().ok().is_some_and(|f| f & 0x0002 != 0) {
            return Some(iface.to_string());
        }
    }
    None
}

impl MachineIdentity {
    /// The tokens that make a machine ONE-OF-ITS-KIND, even against a
    /// factory-identical twin: the unique serials plus the ring −3 silicon
    /// contract, all of which are per-unit and stable across firmware updates.
    fn unique_tokens(&self) -> Vec<String> {
        let mut t: Vec<String> = vec![
            self.board_serial.clone(),
            self.product_uuid.clone(),
            self.product_serial.clone(),
            self.chassis_serial.clone(),
            self.primary_mac.clone(),
        ];
        t.extend(self.dimm_serials.clone());
        // Ring −3 reinforcement: coprocessor kind, CPU part, chipset, HECI,
        // TPM chip identity, MKHI proof.
        t.extend(self.silicon_ids.clone());
        t.sort();
        t.dedup();
        t
    }

    /// SHA-256 of the canonical unique-token string. Stable across runs and
    /// builds; differs between two machines that merely share a model.
    pub fn fingerprint(&self) -> String {
        let canonical = self.unique_tokens().join("|");
        hex(&sha256(canonical.as_bytes()))
    }

    /// Human-readable report for the bot reply.
    pub fn summary_table(&self) -> String {
        let gpu = if self.gpus.is_empty() {
            "n/a".to_string()
        } else {
            format!("{} ({:?})", self.gpus.len(), self.gpus)
        };
        let dimms = self.dimm_serials.join(", ");
        // Ring −3 line: coprocessor + the strongest silicon proofs.
        let silicon = if self.silicon_ids.is_empty() {
            "n/a (no readable silicon)".to_string()
        } else {
            let cp = crate::hal::platform_label();
            let mut t = self.silicon_ids.clone();
            // Keep the report compact: drop raw chipset/part noise we already
            // summarised, keep everything else as proof.
            t.sort();
            format!("{cp} — {}", t.join(", "))
        };
        let fw = if self.firmware_evidence.is_empty() {
            "n/a".to_string()
        } else {
            self.firmware_evidence.join(", ")
        };
        format!(
            "CPU      {}\ncores    {}\nGPU      {}\nRAM      {} MB\n\
             board    {} {}\nserial   {}\nproduct  {} {}\nuuid     {}\n\
             MAC      {}\nDIMMs    {}\nsilicon (ring −3) {}\nfw       {}",
            or_na(&self.cpu_model),
            self.cpu_cores,
            gpu,
            self.mem_total_mb,
            or_na(&self.board_vendor),
            or_na(&self.board_name),
            or_na(&self.board_serial),
            or_na(&self.sys_vendor),
            or_na(&self.product_name),
            or_na(&self.product_uuid),
            or_na(&self.primary_mac),
            dimms,
            silicon,
            fw,
        )
    }

    /// Rolling firmware evidence keyed as `name=value`.
    pub fn firmware_map(&self) -> Vec<(String, String)> {
        self.firmware_evidence
            .iter()
            .filter_map(|e| e.split_once('=').map(|(k, v)| (k.to_string(), v.to_string())))
            .collect()
    }
}

/// Diff the saved profile's silicon/firmware snapshot against the live one.
/// Returns `(silicon_stable, changed_firmware)` — silicon differences mean the
/// *hardware* changed (handled by the fingerprint), firmware differences mean
/// devices were reflashed on this same machine (drift, not identity change).
pub fn silicon_drift(
    saved: &HomeProfile,
    current: &MachineIdentity,
) -> (bool, Vec<String>) {
    let mut saved_silicon: Vec<String> = Vec::new();
    let mut saved_fw: Vec<(String, String)> = Vec::new();
    for line in saved.silicon_note.lines() {
        if let Some(rest) = line.strip_prefix("silicon|") {
            saved_silicon = rest.split('·').map(str::to_string).collect();
        } else if let Some(rest) = line.strip_prefix("fw|") {
            for pair in rest.split('·') {
                if let Some((k, v)) = pair.split_once('=') {
                    saved_fw.push((k.to_string(), v.to_string()));
                }
            }
        }
    }

    let silicon_stable = current.silicon_ids.iter().all(|t| saved_silicon.contains(t))
        && saved_silicon.iter().all(|t| current.silicon_ids.contains(t));

    let live = current.firmware_map();
    let mut changed: Vec<String> = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for (k, v) in &live {
        seen.insert(k.clone());
        let was = saved_fw.iter().find(|(sk, _)| sk == k).map(|(_, sv)| sv.as_str());
        if was.is_some() && was != Some(v.as_str()) {
            changed.push(format!(
                "{k}: {} → {}",
                was.unwrap_or("?"),
                v
            ));
        }
    }
    // Keys in the profile that are gone now (e.g. TPM removed).
    for (k, v) in &saved_fw {
        if !seen.contains(k) {
            changed.push(format!("{k}: {} → (ausente)", *v));
        }
    }
    (silicon_stable, changed)
}

fn or_na(s: &str) -> &str {
    if s.is_empty() { "n/a" } else { s }
}

// ── Profile persistence ───────────────────────────────────────────────────────

/// `/var/lib/sysentinel/home.json` (same directory as the settings file).
pub fn profile_path(settings_file: &str) -> PathBuf {
    Path::new(settings_file)
        .parent()
        .map(|p| p.join("home.json"))
        .unwrap_or_else(|| PathBuf::from("/var/lib/sysentinel/home.json"))
}

pub fn load_profile(path: &Path) -> Option<HomeProfile> {
    let raw = std::fs::read_to_string(path).ok()?;
    serde_json::from_str(&raw).ok()
}

pub fn save_profile(path: &Path, id: &MachineIdentity) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("creating {}", parent.display()))?;
    }
    let mut profile = HomeProfile {
        fingerprint: id.fingerprint(),
        captured_at: now_iso(),
        hostname: std::fs::read_to_string("/proc/sys/kernel/hostname")
            .unwrap_or_default()
            .trim()
            .to_string(),
        summary: id.summary_table(),
        // The ring −3 silicon snapshot: stable tokens first, rolling firmware
        // evidence second. This is what `/definehome status` diff-drifts.
        silicon_note: format!(
            "silicon|{}\nfw|{}",
            id.silicon_ids.join("·"),
            id.firmware_evidence
                .iter()
                .map(|e| e.to_string())
                .collect::<Vec<_>>()
                .join("·")
        ),
        tpm_key: None,
    };

    // The TPM key: bind a /dev/urandom key inside the physical TPM and seal a
    // random holder under it, AES-256-GCM if this CPU has AES-NI/VAES else
    // ChaCha20-Poly1305 (random nonce, never reused). This *accompanies* the
    // fingerprint; if the TPM is unreachable we keep fingerprint-only binding
    // and say so explicitly in the report.
    let base = path.parent();
    match base.and_then(|b| crate::tpmkey::bind(&profile.fingerprint, b).ok()) {
        Some(key) => {
            log::info!(
                "save_profile: TPM key bound (alg {}, handle 0x{:08x})",
                key.meta.alg.label(),
                key.meta.handle
            );
            profile.summary.push_str(&format!(
                "\n\n🔑 *TPM key*: bound — {} · handle `0x{:08x}`",
                key.meta.alg.label(),
                key.meta.handle
            ));
            profile.tpm_key = Some(key.meta);
        }
        None => {
            log::warn!("save_profile: no TPM key possible — fingerprint-only binding");
            profile.summary.push_str(
                "\n\n🔑 *TPM key*: none (no reachable TPM) — fingerprint-only binding.",
            );
        }
    }

    std::fs::write(path, serde_json::to_string_pretty(&profile)?)
        .with_context(|| format!("writing {}", path.display()))
}

pub fn clear_profile(path: &Path) {
    // Best-effort TPM release (evict the persistent object + drop the seal
    // directory) before forgetting the profile itself.
    if let Some(base) = path.parent() {
        crate::tpmkey::unbind(base);
    }
    let _ = std::fs::remove_file(path);
}

/// Human-readable TPM-key verdict for `/definehome status` and the fp-match
/// report, or `None` when the profile was bound fingerprint-only.
pub fn tpm_key_line(profile: &HomeProfile, live_fp: &str, base: &Path) -> Option<String> {
    let meta = profile.tpm_key.clone()?;
    let verdict = crate::tpmkey::verify(&meta, live_fp, base);
    Some(format!(
        "\n{}\n_({} · handle 0x{:08x} · bound {})_",
        verdict.short(),
        meta.alg.label(),
        meta.handle,
        meta.bound_at,
    ))
}

// ── Bare-bones SHA-256 (no external crate needed) ────────────────────────────

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];
    let bitlen = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bitlen.to_be_bytes());

    let mut w = [0u32; 64];
    for chunk in msg.chunks_exact(64) {
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                chunk[i * 4], chunk[i * 4 + 1], chunk[i * 4 + 2], chunk[i * 4 + 3],
            ]);
        }
        for i in 16..64 {
            let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
            let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16].wrapping_add(s0).wrapping_add(w[i - 7]).wrapping_add(s1);
        }

        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ (!e & g);
            let t1 = hh
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(K[i])
                .wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g; g = f; f = e; e = d.wrapping_add(t1);
            d = c; c = b; b = a; a = t1.wrapping_add(t2);
        }

        h[0] = h[0].wrapping_add(a);
        h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c);
        h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e);
        h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g);
        h[7] = h[7].wrapping_add(hh);
    }

    let mut out = [0u8; 32];
    for (i, word) in h.iter().enumerate() {
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
    }
    out
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_is_stable_and_unique_tokens_differ() {
        let mut a = collect_identity();
        let fa = a.fingerprint();
        assert_eq!(a.fingerprint(), fa, "same machine → same hash");

        // A "twin" that shares every model string but has DIFFERENT unique
        // numbers must hash differently.
        let mut b = a.clone();
        b.board_serial = if a.board_serial.is_empty() { "X1".to_string() } else { a.board_serial.clone() };
        b.board_serial.push('Z');
        b.product_uuid.push('7');
        b.primary_mac = b.primary_mac.trim_end_matches('0').to_string() + "1";
        assert_ne!(a.fingerprint(), b.fingerprint());

        // But a genuinely identical unique set hashes identically.
        let c = a.clone();
        assert_eq!(a.fingerprint(), c.fingerprint());
    }
}