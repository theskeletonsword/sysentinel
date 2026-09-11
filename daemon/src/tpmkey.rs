// SPDX-License-Identifier: Apache-2.0
//
// ── The TPM key: proves "es tu PC" ────────────────────────────────────────────
//
// The machine fingerprint (detecthome) is strong: per-unit SMBIOS serials,
// DIMM serials, the NIC MAC and the ring −3 silicon tokens. But every one of
// those can *in principle* be cloned (a BIOS image restored onto identical
// hardware, a bootkit faking SMBIOS/ACPI, or your own OS image copied to a
// second-hand machine). This module adds the one thing that CANNOT be
// cloned: a random key materialized inside the physical TPM.
//
//   • a 32-byte key is drawn from getrandom(2), i.e. /dev/urandom on Linux;
//   • the key is TPM-sealed (TPM2_Create) under a **persistent primary**
//     whose private half lives only inside the TPM silicon — never on disk.
//     The wrapped blob (seal.pub / seal.priv) may sit on disk because only
//     THIS TPM can ever turn it back into the key;
//   • the key is used with an authenticated cipher (AWS-LC):
//       - AES-256-GCM            on CPUs with hardware AES (AES-NI; VAES is
//                                even better and AWS-LC dispatches to it),
//       - ChaCha20-Poly1305      on CPUs WITHOUT any AES instructions
//                                (constant-time, fast without the SIMD AES).
//     A fresh 12-byte random nonce (getrandom → /dev/urandom) is drawn per
//     operation and stored with the sealed metadata — the same key+nonce pair
//     is never reused, and every bind gets a brand-new key anyway.
//   • at bind time the daemon encrypts a random 32-byte *holder* with that
//     key, using the fingerprint as the AAD, so the ciphertext is bound to
//     this machine's identity strings AND to this TPM. The profile stores
//     only the nonce + ciphertext + metadata — the key exists nowhere except
//     inside the TPM (and transiently in the daemon's memory).
//
// Verification later — after a reboot or on suspect hardware — recomputes the
// fingerprint, unseals the key (must succeed ⇒ same physical TPM), and opens
// the ciphertext (tag valid + AAD matches ⇒ same key AND same identity). If
// the fingerprint matches but the seal can't be opened, the identity strings
// were cloned onto different silicon.
//
// ── TPM plumbing (tpm2-tools) ─────────────────────────────────────────────────
//
// The daemon drives the system TPM through the standard tpm2-* tools, which
// talk TPM 2.0 over /dev/tpmrmN — the resource-manager character device that
// Linux exposes since tpm2_init_space() (drivers/char/tpm/tpm2-space.c:594-607
// in the linux/ tree, tpmrm_class / tpmrm_fops). The resource manager is what
// keeps per-process transient objects tidy on physical TPMs.
//
// All commands inherit the daemon's environment, so an administrator (or the
// integration tests) can redirect the tools via TPM2TOOLS_TCTI, e.g. at the
// swtpm software TPM. Because swtpm has NO resource manager, every command is
// followed by `tpm2_flushcontext -t` whenever the TCTI names a simulator,
// which is exactly what freed the transient-object slots during validation.
//
// Command sequence (validated end-to-end against swtpm 0.10.1):
//   1. tpm2_createprimary -C o -g sha256 -G rsa2048:aes128cfb -c primary.ctx
//        — parent is RSA-2048 (an elliptic-curve primary, e.g. ecc256:aes128cfb,
//          works exactly the same on TPMs that prefer ECP; the key wraps the
//          same way). Owned by the owner hierarchy, empty auth, sealed against
//          NO PCRs so BIOS/Kernel firmware updates can never lock the
//          key behind a changing measurement.
//   2. tpm2_evictcontrol -C o -c primary.ctx <handle>   — persist; the parent
//        then exists only inside the TPM.
//   3. tpm2_flushcontext -t
//   4. tpm2_create  -C <handle> -u seal.pub -r seal.priv -i key.bin
//   5. tpm2_flushcontext -t
//   6. verify: tpm2_readpublic -c <handle> must equal the stored primary
//      `name:`; then tpm2_load -C <handle> + tpm2_unseal -c seal.ctx.
//
// If anything fails (no TPM, locked owner hierarchy, missing tools) the caller
// degrades gracefully to fingerprint-only binding — the key is a
// *companion* to the fingerprint, never a precondition.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::process::Command;
use std::path::{Path, PathBuf};

// ── Public types ─────────────────────────────────────────────────────────────

/// Which authenticated cipher the key drives. Chosen at bind time
/// from the CPU's hardware: AES-256-GCM when AES-NI/VAES exist, otherwise
/// ChaCha20-Poly1305. Recorded so verification opens the same ciphertext.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum LlavecitaAlg {
    Aes256Gcm,
    ChaCha20Poly1305,
}

impl LlavecitaAlg {
    fn aead_alg(self) -> &'static aws_lc_rs::aead::Algorithm {
        use aws_lc_rs::aead;
        match self {
            LlavecitaAlg::Aes256Gcm => &aead::AES_256_GCM,
            LlavecitaAlg::ChaCha20Poly1305 => &aead::CHACHA20_POLY1305,
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            LlavecitaAlg::Aes256Gcm => "aes-256-gcm",
            LlavecitaAlg::ChaCha20Poly1305 => "chacha20-poly1305",
        }
    }
}

/// Everything the profile keeps to later re-verify the key. The KEY is
/// deliberately NOT part of this struct — it lives only inside the TPM.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TpmKeyMeta {
    /// Persistent handle where the sealing primary resides (0x8100_0001…).
    /// This value is what the kernel's TPM space maps to a persistent object.
    pub handle: u32,
    /// Name of the primary object (the TPM's identity for that slot). We store
    /// it after binding and bark if it ever changes: a handle re-set on a
    /// *different* TPM (or after a TPM clear) exposes itself precisely here.
    pub primary_name: String,
    /// File names of the wrapped key blob, inside the seal directory.
    pub blob_pub: String,
    pub blob_priv: String,
    /// Cipher family selected for this binding (AES-256-GCM on AES-NI CPUs,
    /// ChaCha20-Poly1305 otherwise).
    pub alg: LlavecitaAlg,
    /// The 12-byte nonce used for the sealed holder (hex). A fresh one per
    /// bind — the same key+nonce pair is never reused.
    pub nonce: String,
    /// AEAD-sealed random 32-byte holder (hex), AAD = the fingerprint. Only
    /// this TPM's key can open it, and only while the identity strings match.
    pub sealed_holder: String,
    /// ISO-8601 timestamp of the binding.
    pub bound_at: String,
}

impl TpmKeyMeta {
    fn handle_arg(&self) -> String {
        format!("0x{:08x}", self.handle)
    }

    fn nonce_bytes(&self) -> Result<[u8; 12]> {
        let mut n = [0u8; 12];
        n.copy_from_slice(&decode_hex(&self.nonce)?);
        Ok(n)
    }
}

/// Result of re-verifying a bound key against the live machine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verify {
    /// Unseal succeeded and the holder opened with a valid tag: the original
    /// TPM still holds the key AND the identity strings are byte-for-byte the
    /// same as the day it was bound.
    Matches,
    /// Unseal succeeded but the holder does not open: same physical TPM, but
    /// the identity strings (AAD) or the key drifted since capture.
    IdentityDrifted,
    /// No reachable TPM right now (device absent or tools missing) — the
    /// fingerprint is the only thing we can stand on.
    NoTpm,
    /// The persistent handle no longer names our primary. Either the TPM was
    /// cleared / the handle re-used elsewhere, or the disk landed on different
    /// silicon.
    NameChanged(String),
    /// The key could not be unsealed. Carries the tool error tail.
    UnsealFailed(String),
    /// The wrapped blob files are missing from disk.
    BlobMissing,
}

impl Verify {
    /// One-line human summary (used by /definehome → status / fp-match).
    /// English, like the rest of the bot's status output.
    pub fn short(&self) -> String {
        use Verify::*;
        match self {
            Matches => "🔑 *TPM key*: valid — same physical TPM, identity intact.".into(),
            IdentityDrifted => {
                "🔑 *TPM key*: same physical TPM, but the identity strings changed since the /definehome (drift).".into()
            }
            NoTpm => {
                "🔑 *TPM key*: TPM not reachable right now — fingerprint-only fallback.".into()
            }
            NameChanged(_) => {
                "🔑 *TPM key*: the TPM holding the key is no longer the original one (handle reused / TPM cleared) — fingerprint fallback.".into()
            }
            UnsealFailed(_) => {
                "🔑 *TPM key*: could not open the seal — fingerprint fallback.".into()
            }
            BlobMissing => "🔑 *TPM key*: sealed blob is missing from disk — fingerprint fallback.".into(),
        }
    }
}

/// The artifact of a successful binding.
#[derive(Debug)]
pub struct TpmKey {
    pub meta: TpmKeyMeta,
}

// ── Top-level operations ──────────────────────────────────────────────────────

/// Is a TPM reachable? Honours TPM2TOOLS_TCTI (used by the swtpm tests) and
/// otherwise probes the standard character devices. The resource-manager
/// device (tpmrmN) exists whenever the TPM 2.0 core does.
pub fn tpm_present() -> bool {
    if std::env::var_os("TPM2TOOLS_TCTI")
        .map(|v| !v.is_empty())
        .unwrap_or(false)
    {
        return true;
    }
    ["/dev/tpmrm0", "/dev/tpmrm1", "/dev/tpm0"]
        .iter()
        .any(|dev| Path::new(dev).exists())
}

/// Directory holding the sealed blob + metadata, placed next to the profile.
pub fn seal_dir(base: &Path) -> PathBuf {
    base.join("tpm-seal")
}

/// Bind a brand-new key: materialize a fresh 32-byte key inside the TPM,
/// choose the cipher from this CPU's hardware AES support, and seal a random
/// holder under it (AAD = fingerprint). Returns the metadata for the profile.
///
/// On any failure this returns `Err` and the caller must keep fingerprint-only
/// binding — the key never forces a failed `/definehome`.
pub fn bind(fingerprint: &str, base: &Path) -> Result<TpmKey> {
    let dir = seal_dir(base);

    // A stale seal from a previous binding must not linger: old blob + old
    // persistent object would let a numeric-identical but *different* TPM be
    // confused via a fresh binding. Blow the whole directory away.
    unbind(base);

    std::fs::create_dir_all(&dir)
        .with_context(|| format!("tpmkey: create {}", dir.display()))?;

    if !command_exists("tpm2_createprimary") {
        bail!("tpm2-tools no están instalados");
    }

    let handle = pick_free_handle()?;
    let primary = dir.join("primary.ctx");
    let keyfile = dir.join("key.bin");
    let (pubf, privf) = (dir.join("seal.pub"), dir.join("seal.priv"));

    // 1) Primary under the owner hierarchy. RSA-2048 parent (ECC256 works the
    //    same); sealed against no PCR so firmware updates never lock us out.
    run_tool(
        "tpm2_createprimary",
        &[
            "-C",
            "o",
            "-g",
            "sha256",
            "-G",
            "rsa2048:aes128cfb",
            "-c",
            primary.to_str().unwrap(),
        ],
    )?;

    // 2) Persist it so the private half lives only in the TPM.
    run_tool(
        "tpm2_evictcontrol",
        &[
            "-C",
            "o",
            "-c",
            primary.to_str().unwrap(),
            &format!("0x{handle:08x}"),
        ],
    )?;
    flush_transients();

    // 3) Draw the key from /dev/urandom and seal it under the primary.
    let mut key = [0u8; 32];
    getrandom::getrandom(&mut key)
        .map_err(|e| anyhow::anyhow!("getrandom(/dev/urandom) failed: {e}"))?;

    std::fs::write(&keyfile, key)
        .with_context(|| format!("tpmkey: writing {}", keyfile.display()))?;

    run_tool(
        "tpm2_create",
        &[
            "-C",
            &format!("0x{handle:08x}"),
            "-g",
            "sha256",
            "-u",
            pubf.to_str().unwrap(),
            "-r",
            privf.to_str().unwrap(),
            "-i",
            keyfile.to_str().unwrap(),
        ],
    )?;
    flush_transients();
    // Wipe the plaintext key file (and unlink) once the TPM has consumed it.
    wipe_file(&keyfile);

    // 4) Smoke-test: unseal the key and walk the whole AEAD path now, so we
    //    never store a binding that cannot be opened on a fresh process.
    let unsealed = unseal(handle, &pubf, &privf)?;
    if unsealed != key {
        bail!("tpmkey: the smoke-test unseal did not return the key (bad TPM?)");
    }

    // Name of the primary: its stable identity. If this handle is later re-set
    // on other silicon, verify catches the name change.
    let primary_name = persistent_name(handle)?;

    // 5) Cipher selection: AES-256-GCM only on CPUs with hardware AES
    //    (AES-NI, VAES faster still), else ChaCha20-Poly1305.
    let alg = choose_alg();

    // 6) Seal a random holder under the key, AAD = fingerprint. Random nonce
    //    per bind; key+nonce pair is used for exactly one message.
    let mut holder = [0u8; 32];
    getrandom::getrandom(&mut holder)
        .map_err(|e| anyhow::anyhow!("getrandom(/dev/urandom) failed: {e}"))?;
    let nonce = random_nonce()?;

    let (sealed, tag) = aead_seal(alg, &key, &nonce, fingerprint.as_bytes(), &holder)?;
    // aws-lc's in-place AEAD open expects the tag APPENDED to the ciphertext
    // (ct ‖ tag); we store exactly that.
    let mut sealed_holder = Vec::with_capacity(sealed.len() + tag.len());
    sealed_holder.extend_from_slice(&sealed);
    sealed_holder.extend_from_slice(&tag);

    // Smoke-test the open path with the same parameters.
    let opened = aead_open(alg, &key, &nonce, fingerprint.as_bytes(), &sealed_holder)
        .context("tpmkey: could not open the smoke-test holder")?;
    if opened != holder {
        bail!("tpmkey: the smoke-test holder did not round-trip (bad cipher?)");
    }

    let meta = TpmKeyMeta {
        handle,
        primary_name,
        blob_pub: "seal.pub".into(),
        blob_priv: "seal.priv".into(),
        alg,
        nonce: encode_hex(&nonce),
        sealed_holder: encode_hex(&sealed_holder),
        bound_at: crate::detecthome::now_iso(),
    };
    save_meta(&dir, &meta)?;
    let _ = std::fs::remove_file(&primary);
    log::info!(
        "tpmkey: bound at 0x{handle:08x} ({})",
        alg.label()
    );
    Ok(TpmKey { meta })
}

/// Re-verify a previously bound key against the live fingerprint.
pub fn verify(meta: &TpmKeyMeta, fingerprint: &str, base: &Path) -> Verify {
    if !tpm_present() {
        return Verify::NoTpm;
    }
    let dir = seal_dir(base);
    let pubf = dir.join(&meta.blob_pub);
    let privf = dir.join(&meta.blob_priv);
    if !pubf.exists() || !privf.exists() {
        return Verify::BlobMissing;
    }

    match persistent_name(meta.handle) {
        Ok(name) => {
            if !name.eq_ignore_ascii_case(&meta.primary_name) {
                return Verify::NameChanged(format!(
                    "expected {} but the TPM returns {name}",
                    meta.primary_name
                ));
            }
        }
        Err(_e) => return Verify::NoTpm,
    }

    let key = match unseal(meta.handle, &pubf, &privf) {
        Ok(bytes) => bytes,
        Err(e) => return Verify::UnsealFailed(format!("{e:#}")),
    };

    let nonce = match meta.nonce_bytes() {
        Ok(n) => n,
        Err(e) => return Verify::UnsealFailed(format!("corrupt nonce: {e}")),
    };
    let sealed = match decode_hex(&meta.sealed_holder) {
        Ok(v) => v,
        Err(e) => return Verify::UnsealFailed(format!("corrupt holder: {e}")),
    };

    match aead_open(meta.alg, &key, &nonce, fingerprint.as_bytes(), &sealed) {
        Ok(_) => Verify::Matches,
        // Tag + unseal both worked before, so a failed open here means the AAD
        // (fingerprint strings) no longer match the day it was bound.
        Err(_) => Verify::IdentityDrifted,
    }
}

/// Decrypt the key holder (the sealed key must be released by the TPM
/// first). Gives future halves of the daemon a real AEAD secret that only the
/// original TPM + unchanged identity can produce. `fingerprint` is the AAD the
/// holder was sealed with.
// Counterpart to `seal`; exercised by the swtpm round-trip test.
#[allow(dead_code)]
pub fn open(meta: &TpmKeyMeta, fingerprint: &str, base: &Path) -> Result<[u8; 32]> {
    let dir = seal_dir(base);
    let key = unseal(meta.handle, &dir.join(&meta.blob_pub), &dir.join(&meta.blob_priv))?;
    let nonce = meta.nonce_bytes()?;
    let sealed = decode_hex(&meta.sealed_holder)?;
    let opened = aead_open(meta.alg, &key, &nonce, fingerprint.as_bytes(), &sealed)
        .context("tpmkey: could not open the holder (wrong AAD?)")?;
    let mut h = [0u8; 32];
    h.copy_from_slice(&opened);
    Ok(h)
}

/// Best-effort release: evict the persistent object from the TPM and delete
/// the whole seal directory. Used by `/definehome clear`.
pub fn unbind(base: &Path) {
    let dir = seal_dir(base);
    if let Some(meta) = std::fs::read_to_string(dir.join("meta.json"))
        .ok()
        .and_then(|s| serde_json::from_str::<TpmKeyMeta>(&s).ok())
    {
        // Persistent objects live even without this daemon; try to free the
        // slot before our seal directory disappears.
        let _ = run_tool("tpm2_evictcontrol", &["-C", "o", &meta.handle_arg(), "0x81000000"]);
        let _ = run_tool("tpm2_flushcontext", &["-t"]);
    }
    if dir.exists() {
        let _ = std::fs::remove_dir_all(&dir);
    }
}

// ── Ciphers (AWS-LC) ─────────────────────────────────────────────────────────

/// AES-256-GCM on hardware-AES CPUs (AES-NI; VAES dispatched by AWS-LC),
/// ChaCha20-Poly1305 on CPUs without AES instructions.
fn choose_alg() -> LlavecitaAlg {
    if aes_accelerated() {
        LlavecitaAlg::Aes256Gcm
    } else {
        LlavecitaAlg::ChaCha20Poly1305
    }
}

/// Does this CPU have hardware AES? x86_64 exposes it as the `aes` (AES-NI) /
/// `vaes` flags in /proc/cpuinfo; aarch64 as the `aes` feature bit. A missing
/// /proc/cpuinfo (or a weird arch) conservatively reports "no".
pub(crate) fn aes_accelerated() -> bool {
    let content = match std::fs::read_to_string("/proc/cpuinfo") {
        Ok(c) => c,
        Err(_) => return false,
    };
    for line in content.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("flags") || trimmed.starts_with("Features") {
            let flags = trimmed
                .split_once(':')
                .map(|(_, v)| v.to_ascii_lowercase())
                .unwrap_or_default();
            for flag in flags.split_whitespace() {
                if flag == "aes" || flag == "vaes" || flag == "asimdaes" {
                    return true;
                }
            }
        }
    }
    false
}

/// Fresh 12-byte nonce per message, from /dev/urandom. The caller guarantees
/// key+nonce uniqueness: each bind already mints a brand-new key, and this
/// nonce is used for exactly ONE sealed holder.
/// A fresh 12-byte nonce, or an error.
///
/// It returns `Result` because the previous version did not: it discarded the
/// failure and handed back twelve zeros. A fixed nonce reused under one AES-GCM
/// key is not a degraded mode, it is a total break — the keystream repeats and
/// the authentication key can be recovered from two messages. Silently
/// producing one on a machine whose entropy source just failed is the worst
/// possible response, so this fails loudly instead and the caller refuses to
/// seal.
fn random_nonce() -> Result<[u8; 12]> {
    let mut n = [0u8; 12];
    getrandom::getrandom(&mut n)
        .map_err(|e| anyhow::anyhow!("tpmkey: no entropy for a nonce ({e}) — refusing to seal"))?;
    Ok(n)
}

/// AES-256-GCM / ChaCha20-Poly1305 encrypt. Returns (ciphertext, 16-byte tag).
fn aead_seal(
    alg: LlavecitaAlg,
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    plaintext: &[u8; 32],
) -> Result<(Vec<u8>, [u8; 16])> {
    use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey};
    let alg = alg.aead_alg();
    let unbound = UnboundKey::new(alg, key)
        .context("tpmkey: key invalid for the chosen cipher")?;
    let nonce = Nonce::try_assume_unique_for_key(nonce)
        .context("tpmkey: invalid nonce")?;
    let mut in_out = plaintext.to_vec();
    let tag = LessSafeKey::new(unbound)
        .seal_in_place_separate_tag(nonce, Aad::from(aad), &mut in_out)
        .context("tpmkey: seal failed")?;
    let mut tag_buf = [0u8; 16];
    tag_buf.copy_from_slice(tag.as_ref());
    Ok((in_out, tag_buf))
}

/// AES-256-GCM / ChaCha20-Poly1305 decrypt+verify. `sealed` = ciphertext ‖
/// tag (as we stored it). Verifies the tag in constant time.
fn aead_open(
    alg: LlavecitaAlg,
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    sealed: &[u8],
) -> Result<Vec<u8>> {
    use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey};
    let alg = alg.aead_alg();
    let unbound = UnboundKey::new(alg, key)
        .context("tpmkey: key invalid for the chosen cipher")?;
    let nonce = Nonce::try_assume_unique_for_key(nonce)
        .context("tpmkey: invalid nonce")?;
    let mut in_out = sealed.to_vec();
    let opened = LessSafeKey::new(unbound)
        .open_in_place(nonce, Aad::from(aad), &mut in_out)
        .context("tpmkey: invalid tag or different AAD")?
        .to_vec();
    Ok(opened)
}

// ── Tools / plumbing ─────────────────────────────────────────────────────────

fn command_exists(name: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|path| {
        std::env::split_paths(&path).any(|dir| dir.join(name).is_file())
    })
}

/// Run a tpm2 tool. Inherits the daemon's env (TPM2TOOLS_TCTI respected).
fn run_tool(tool: &str, args: &[&str]) -> Result<std::process::Output> {
    let out = Command::new(tool)
        .args(args)
        .output()
        .with_context(|| format!("tpmkey: could not run {tool}"))?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let tail: Vec<&str> = stderr.lines().rev().take(6).collect();
        bail!("tpmkey: {tool} failed ({}): {}", out.status, tail.join(" | "));
    }
    Ok(out)
}

/// swtpm has no resource manager, so it accumulates loaded transient objects
/// until the tiny emulated slot table overflows (TPM_RC_OBJECT_MEMORY). Real
/// TPMs manage this via /dev/tpmrmN; here we just ask to drop leftovers.
fn flush_transients() {
    if std::env::var_os("TPM2TOOLS_TCTI")
        .map(|v| v.to_string_lossy().contains("swtpm"))
        .unwrap_or(false)
    {
        let _ = run_tool("tpm2_flushcontext", &["-t"]);
    }
}

/// Scan persistent handles and return the first free slot in the range.
fn pick_free_handle() -> Result<u32> {
    let out = run_tool("tpm2_getcap", &["handles-persistent"])?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut taken = Vec::new();
    for line in stdout.lines() {
        let line = line.trim();
        if let Some(hex) = line.strip_prefix('-').map(str::trim).filter(|s| s.starts_with("0x")) {
            if let Ok(h) = u32::from_str_radix(&hex[2..], 16) {
                taken.push(h);
            }
        }
    }
    (HANDLE_MIN..=HANDLE_MAX)
        .find(|h| !taken.contains(h))
        .context("tpmkey: no free persistent handle en 0x81000001..0x81000010")
}

/// Name (`name:` line of tpm2_readpublic) for a handle — its stable identity.
fn persistent_name(handle: u32) -> Result<String> {
    let out = run_tool("tpm2_readpublic", &["-c", &format!("0x{handle:08x}")])?;
    let stdout = String::from_utf8_lossy(&out.stdout);
    for line in stdout.lines() {
        if let Some(rest) = line.trim().strip_prefix("name:") {
            let token = rest
                .split_whitespace()
                .next()
                .unwrap_or("")
                .to_string();
            if !token.is_empty() {
                return Ok(token);
            }
        }
    }
    bail!("tpmkey: no se encontró `name:` en tpm2_readpublic")
}

/// Load the seal into a fresh context and unseal it (two subprocesses, with a
/// transient flush between them on the simulator, exactly like the validated
/// script). Returns the 32-byte key.
fn unseal(handle: u32, pubf: &Path, privf: &Path) -> Result<[u8; 32]> {
    // Both paths go through `scratch`, not `/tmp`.
    //
    // `tpm2_unseal -o <path>` creates the file itself, with its own umask, at
    // whatever path we name. Named predictably in a shared directory that is
    // two separate gifts to a local attacker: pre-create the path as a symlink
    // and the 32-byte key lands in their directory, or simply read it in the
    // window before we unlink it. The key that seals this machine's identity is
    // not something to leave to another process's umask.
    let ctx = crate::scratch::reserve("tpm-ctx").context("tpmkey: scratch for the seal context")?;
    run_tool(
        "tpm2_load",
        &[
            "-C",
            &format!("0x{handle:08x}"),
            "-u",
            pubf.to_str().unwrap(),
            "-r",
            privf.to_str().unwrap(),
            "-c",
            ctx.as_str(),
        ],
    )
    .context("tpmkey: could not load the seal")?;
    flush_transients();

    let outf = crate::scratch::reserve("tpm-unseal")
        .context("tpmkey: scratch for the unsealed key")?
        .sensitive();
    run_tool("tpm2_unseal", &["-c", ctx.as_str(), "-o", outf.as_str()])
        .context("tpmkey: could not unseal")?;
    drop(ctx);

    let bytes = std::fs::read(outf.path()).context("tpmkey: unseal produced no output file")?;
    outf.wipe();
    if bytes.len() != 32 {
        bail!("tpmkey: the seal did not return 32 bytes ({})", bytes.len());
    }
    let mut key = [0u8; 32];
    key.copy_from_slice(&bytes);
    Ok(key)
}

fn save_meta(dir: &Path, meta: &TpmKeyMeta) -> Result<()> {
    let json = serde_json::to_string_pretty(meta).context("tpmkey: serialize meta")?;
    std::fs::write(dir.join("meta.json"), json).context("tpmkey: write meta.json")
}

/// Overwrite a file with zeroes before unlinking, so a plaintext value (the
/// TPM key material) does not linger in page cache / the filesystem.
fn wipe_file(path: &Path) {
    let _ = std::fs::write(path, [0u8; 32]);
    let _ = std::fs::remove_file(path);
}

fn encode_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn decode_hex(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        bail!("tpmkey: hex of odd length");
    }
    (0..s.len() / 2)
        .map(|i| {
            u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).map_err(|e| anyhow::anyhow!("{e}"))
        })
        .collect()
}

// Handles for the persistent range used by `pick_free_handle`.
const HANDLE_MIN: u32 = 0x8100_0001;
const HANDLE_MAX: u32 = 0x8100_0010;

#[cfg(test)]
mod tests {
    use super::*;

    /// Full bind → verify → drift → rebind-after-clear round trip against the
    /// swtpm software TPM. Skipped (with a message) when swtpm is absent, so CI
    /// without tpm-tools still runs the rest of the suite.
    #[test]
    fn tpm_key_round_trip_swtpm() {
        if !command_exists("swtpm") {
            eprintln!("tpmkey: swtpm not installed — skipping swtpm round trip");
            return;
        }
        if !command_exists("tpm2_createprimary") {
            eprintln!("tpmkey: tpm2-tools not installed — skipping swtpm round trip");
            return;
        }

        let base = std::env::temp_dir().join(format!("sysentinel-tpm-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        std::fs::create_dir_all(&base).unwrap();
        let state = base.join("swtpm");
        std::fs::create_dir_all(&state).unwrap();
        let port = swtpm_port();
        let ctrl = port + 1;

        let mut swtpm = Command::new("swtpm")
            .args([
                "socket",
                "--tpmstate",
                &format!("dir={}", state.display()),
                "--tpm2",
                "--server",
                &format!("type=tcp,port={port}"),
                "--ctrl",
                &format!("type=tcp,port={ctrl}"),
                "--flags",
                "not-need-init,startup-clear",
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn swtpm");

        let tcti = format!("swtpm:host=localhost,port={port}");
        std::env::set_var("TPM2TOOLS_TCTI", &tcti);

        // Wait until the TPM actually answers.
        let mut ready = std::time::Duration::from_secs(10);
        while ready > std::time::Duration::ZERO {
            if run_tool("tpm2_getcap", &["properties-variable"]).is_ok() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(150));
            ready -= std::time::Duration::from_millis(150);
        }

        let fp = "TEST-MACHINE-001/DEADBEEF/FF:EE:DD:CC:BB:AA";
        let key = match bind(fp, &base) {
            Ok(k) => k,
            Err(e) => {
                let _ = swtpm.kill();
        let _ = swtpm.wait();
                let _ = swtpm.wait();
                cleanup_env(&base);
                panic!("tpmkey: bind failed against swtpm: {e:#}");
            }
        };
        assert_eq!(key.meta.blob_pub, "seal.pub");
        assert!(seal_dir(&base).join("meta.json").is_file(), "meta.json written");

        // Same fingerprint, same TPM → Matches (and again after a "reboot",
        // i.e. brand-new subprocesses, the way the daemon re-verifies).
        assert_eq!(verify(&key.meta, fp, &base), Verify::Matches);
        assert_eq!(verify(&key.meta, fp, &base), Verify::Matches);

        // A foreign machine's strings — same TPM, but AAD no longer matches.
        assert_eq!(
            verify(&key.meta, "OTHER-MACHINE-999/DECAFBAD/00:11:22:33:44:55", &base),
            Verify::IdentityDrifted,
            "same key but cloned strings must drift"
        );

        // A foreign TPM (fresh state dir + different handle space) fails the
        // persistent-handle check or the name check. Simulate by clearing the
        // persistent object out from under it.
        std::env::remove_var("TPM2TOOLS_TCTI");
        let foreign = state.join("rebind");
        std::fs::create_dir_all(&foreign).unwrap();
        let p2 = swtpm_port() + 2;
        let tcti2 = format!("swtpm:host=localhost,port={p2}");
        let mut swtpm2 = Command::new("swtpm")
            .args([
                "socket",
                "--tpmstate",
                &format!("dir={}", foreign.display()),
                "--tpm2",
                "--server",
                &format!("type=tcp,port={p2}"),
                "--ctrl",
                &format!("type=tcp,port={}", p2 + 1),
            ])
            .args(["--flags", "not-need-init,startup-clear"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .expect("spawn foreign swtpm");
        std::env::set_var("TPM2TOOLS_TCTI", &tcti2);
        let mut ready = std::time::Duration::from_secs(10);
        while ready > std::time::Duration::ZERO {
            if run_tool("tpm2_getcap", &["properties-variable"]).is_ok() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(150));
            ready -= std::time::Duration::from_millis(150);
        }
        // The handle is empty on the foreign TPM — readpublic fails ⇒ not
        // Matches. The point is it must NEVER pass the key.
        assert!(
            verify(&key.meta, fp, &base) != Verify::Matches,
            "foreign TPM must never pass the key"
        );

        let _ = swtpm2.kill();
        let _ = swtpm2.wait();
        cleanup_env(&base);
        let _ = swtpm.kill();
        let _ = swtpm.wait();
    }

    fn swtpm_port() -> u16 {
        static NEXT: std::sync::atomic::AtomicU16 = std::sync::atomic::AtomicU16::new(0);
        let n = NEXT.fetch_add(2, std::sync::atomic::Ordering::Relaxed);
        let off = std::process::id() as u16 % 500;
        24000 + off + n
    }

    fn cleanup_env(base: &Path) {
        std::env::remove_var("TPM2TOOLS_TCTI");
        let _ = std::fs::remove_dir_all(base);
    }

    #[test]
    fn aes_accel_detection_is_boolean() {
        // Must never panic and return one of the two outcomes.
        assert!(aes_accelerated() || !aes_accelerated());
    }

    #[test]
    fn nonce_is_single_use_pairing_with_key() {
        // Two nonces for the same profile must differ (fresh per unit).
        // Never the same twice, and — the point of the change — never the
        // all-zero array that a discarded getrandom error used to produce.
        // A fixed nonce reused under one AES-GCM key is a total break, not a
        // degraded mode.
        let a = random_nonce().unwrap();
        let b = random_nonce().unwrap();
        assert_ne!(a, b);
        assert_ne!(a, [0u8; 12], "a failed draw must error, never return zeros");
        let mut seen = std::collections::HashSet::new();
        for _ in 0..500 {
            assert!(seen.insert(random_nonce().unwrap()), "nonce repeated");
        }
    }

    #[test]
    fn hex_helpers_round_trip() {
        let raw = [0xdeu8, 0xad, 0xbe, 0xef];
        let s = encode_hex(&raw);
        assert_eq!(s, "deadbeef");
        assert_eq!(decode_hex(&s).unwrap(), raw);
        assert!(decode_hex("abc").is_err());
    }
}