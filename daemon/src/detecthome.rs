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
    // Part of the persisted fingerprint; compared as raw JSON, not field-wise.
    #[allow(dead_code)]
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

/// Read the saved home profile, distinguishing "never defined" from "cannot
/// read it".
///
/// The two must not collapse into one answer. `Ok(None)` sends `/definehome`
/// down the path that *writes* a new profile — so a truncated or corrupted
/// file used to mean the machine silently re-bound itself as home, and the
/// tripwire that says "this login came from other hardware" quietly reset to
/// whatever hardware happened to be running. A binding that disappears when a
/// file goes bad is not a binding.
pub fn load_profile(path: &Path) -> Result<Option<HomeProfile>> {
    let raw = match std::fs::read_to_string(path) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(anyhow::anyhow!(e))
                .with_context(|| format!("reading {}", path.display()))
        }
    };
    let profile = serde_json::from_str(&raw)
        .with_context(|| format!("{} is not a readable home profile", path.display()))?;
    Ok(Some(profile))
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

    // Staged and renamed, 0600 from creation: a half-written profile is what
    // the paragraph on `load_profile` is about, and this file records the
    // machine's identity.
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let json = serde_json::to_string_pretty(&profile)?;
    let tmp = path.with_extension("json.new");
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .with_context(|| format!("writing {}", tmp.display()))?;
    f.write_all(json.as_bytes())
        .with_context(|| format!("writing {}", tmp.display()))?;
    f.sync_all().with_context(|| format!("flushing {}", tmp.display()))?;
    drop(f);
    std::fs::rename(&tmp, path)
        .with_context(|| format!("renaming {} into place", tmp.display()))
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

// ── Hashing ──────────────────────────────────────────────────────────────────

/// SHA-256, from the library everything else here already uses.
///
/// This was forty lines of hand-written SHA-256 with a comment saying "no
/// external crate needed" — and it was correct, which is lucky rather than
/// reassuring. `aws-lc-rs` was already a dependency two modules away, and a
/// hash function written by hand in an application is the kind of thing that
/// is right until the day some input reaches an edge nobody tested.
///
/// The swap is invisible: the tests below pin the published vectors, including
/// the 55/56/64-byte padding boundaries where a hand-rolled implementation
/// usually goes wrong, so every fingerprint already saved in a `home.json`
/// keeps matching.
fn sha256(data: &[u8]) -> [u8; 32] {
    let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, data);
    let mut out = [0u8; 32];
    out.copy_from_slice(digest.as_ref());
    out
}

/// Lower-case hex, for the fingerprint string.
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
    fn the_fingerprint_hash_matches_the_published_vectors() {
        // This file carries a hand-written SHA-256, which is the one kind of
        // code this project has no business containing. Before replacing it
        // with the library's, pin what it currently produces against the
        // published test vectors — if it is correct, the swap is invisible and
        // every saved home.json keeps matching; if it is not, every fingerprint
        // changes and that has to be said out loud rather than discovered.
        assert_eq!(
            hex(&sha256(b"")),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        );
        assert_eq!(
            hex(&sha256(b"abc")),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        );
        assert_eq!(
            hex(&sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
        );
        // Past one block, and past the 55-byte padding boundary in both
        // directions — where a hand-rolled implementation usually goes wrong.
        assert_eq!(
            hex(&sha256(&[b'a'; 55])),
            "9f4390f8d30c2dd92ec9f095b65e2b9ae9b0a925a5258e241c9f1e910f734318",
        );
        assert_eq!(
            hex(&sha256(&[b'a'; 56])),
            "b35439a4ac6f0948b6d6f9e3c6af0f5f590ce20f1bde7090ef7970686ec6738a",
        );
        assert_eq!(
            hex(&sha256(&[b'a'; 64])),
            "ffe054fe7ae0cb6dc65c3af9b61d5209f439851db43d0ba5997337df154668eb",
        );
    }

    #[test]
    fn a_damaged_home_profile_is_not_read_as_never_defined() {
        // `Ok(None)` is what sends /definehome down the branch that WRITES a
        // profile. A corrupt file taking that branch means the machine
        // silently re-binds to whatever hardware is running, and the "this
        // login came from other hardware" tripwire resets itself.
        let dir = std::env::temp_dir().join(format!("sysentinel-home-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("home.json");

        assert!(load_profile(&path).unwrap().is_none(), "absent means absent");

        std::fs::write(&path, b"{ half a profile").unwrap();
        let err = load_profile(&path).expect_err("a corrupt profile must be an error");
        assert!(format!("{err:#}").contains("readable home profile"), "{err:#}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn fingerprint_is_stable_and_unique_tokens_differ() {
        let a = collect_identity();
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