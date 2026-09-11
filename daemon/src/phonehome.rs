// SPDX-License-Identifier: Apache-2.0
//!
//! `/definehome` for the phone — "this is MY handset", not "a handset like mine".
//!
//! The machine already has this. [`crate::detecthome`] binds a PC by things
//! that are per-unit and stable: board and chassis serials, the ring −3 silicon
//! contract. The phone needs the same idea and cannot use the same evidence,
//! because almost nothing a phone reports about itself is per-unit.
//!
//! # Why the model tells you nothing
//!
//! Two Pixel 8s report the same `Build.MODEL`, the same manufacturer, the same
//! board, the same build fingerprint. A friend's identical handset matches on
//! every one of them. Android also stopped handing out per-device identifiers
//! years ago, on purpose: `Build.SERIAL` needs a privileged permission since
//! Android 10, IMEI is off limits to normal apps, and `ANDROID_ID` is scoped per
//! app-signing-key and resets on a factory reset.
//!
//! So model data is **supporting evidence and never the decision** — the same
//! separation `detecthome` draws between stable silicon tokens and rolling
//! firmware evidence. Recorded because it is useful to a human reading an audit
//! line; never compared to decide whether a phone is the right one.
//!
//! # What is actually per-unit
//!
//! A key generated inside that handset's TEE or secure element, which cannot be
//! read out of it. Two identical phones do not share one, and no amount of
//! copying the app's storage produces it, because the private half never leaves
//! the hardware.
//!
//! That is the difference from the pairing key in [`crate::phone`]. The pairing
//! key proves *someone knows a secret*, and a secret can be copied: an attacker
//! with the config file and the app's storage can speak as the owner. The
//! device key proves *this physical handset is present*, because using it means
//! asking hardware that only exists in one place.
//!
//! Both are kept. The pairing key authenticates the channel; the device key
//! answers "is this still the phone I paired with, or a different one holding a
//! copy of the secret?" — and only the second question survives a stolen key.
//!
//! # Claiming is still not proving
//!
//! A handset asserting "my key lives in StrongBox" is telling us about itself,
//! and whoever controls it controls what it says. The attestation chain is what
//! makes it checkable, and [`crate::confirm::ConfirmMethod::proven`] downgrades
//! an unproven claim rather than believing it. This module records what was
//! attested at pairing so a later downgrade is visible as a *change*.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use aws_lc_rs::signature::{self, UnparsedPublicKey};
use serde::{Deserialize, Serialize};

/// What the daemon remembers about the paired handset.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PhoneProfile {
    /// SubjectPublicKeyInfo DER of the device's signing key. **This is the
    /// identity.** Everything else in this struct is context.
    pub public_key_der: Vec<u8>,
    /// What the phone said backed the key, at pairing time.
    pub claimed_backing: String,
    /// Whether an attestation chain was verified for that claim.
    pub attestation_verified: bool,
    /// Context for a human reading an audit line. Never compared.
    pub model: String,
    pub manufacturer: String,
    /// When this handset became the paired one.
    pub paired_at_unix: i64,
}

impl PhoneProfile {
    /// Short, stable label for the key — the first bytes of its SHA-256, which
    /// is enough to eyeball "same phone" in a log without printing a key.
    pub fn key_id(&self) -> String {
        let digest = aws_lc_rs::digest::digest(&aws_lc_rs::digest::SHA256, &self.public_key_der);
        digest.as_ref()[..8].iter().map(|b| format!("{b:02x}")).collect()
    }

    /// A line for the owner. Leads with the key, because the key is the answer;
    /// the model is there to be recognisable, not to be trusted.
    pub fn describe(&self) -> String {
        let proof = if self.attestation_verified {
            format!("{} (atestado)", self.claimed_backing)
        } else {
            format!("{} — SIN atestación verificada", self.claimed_backing)
        };
        format!(
            "clave {} · {proof} · {} {} (el modelo es contexto, no identidad)",
            self.key_id(),
            self.manufacturer,
            self.model,
        )
    }
}

/// The answer to "is this the phone I paired with?".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhoneVerdict {
    /// Same key: the same physical handset.
    SameDevice,
    /// A different key. Possibly a factory reset or a reinstall — and possibly
    /// somebody else's handset holding a copy of the pairing key, which is the
    /// case this exists to catch.
    DifferentDevice,
    /// Nothing paired yet.
    NotPaired,
}

impl PhoneVerdict {
    pub fn describe(&self) -> &'static str {
        match self {
            PhoneVerdict::SameDevice =>
                "es el mismo teléfono con el que emparejaste",
            PhoneVerdict::DifferentDevice =>
                "NO es el teléfono con el que emparejaste. La clave del dispositivo es \
                 distinta, y esa clave no se puede copiar: o restauraste de fábrica / \
                 reinstalaste, o alguien más tiene tu clave de emparejamiento",
            PhoneVerdict::NotPaired =>
                "todavía no hay ningún teléfono emparejado",
        }
    }
}

/// Where the profile lives, beside the other daemon state.
pub fn profile_path(queue_path: &str) -> PathBuf {
    Path::new(queue_path)
        .parent()
        .unwrap_or(Path::new("/var/lib/sysentinel"))
        .join("phone-home.json")
}

/// Read the paired handset, distinguishing "nobody is paired" from "I cannot
/// tell".
///
/// # Why this is not an `Option`
///
/// It was, and the difference is the whole security property. `Ok(None)` means
/// no handset has ever been bound, and the next one to connect becomes the
/// owner's — that is how pairing works. A file that exists but will not parse
/// is a completely different statement, and folding it into `None` meant a
/// truncated write, a full disk or a deliberately corrupted byte silently
/// turned the machine back into "anyone holding the pairing key is the owner",
/// re-binding to whatever handset connected next. A check that disappears when
/// something goes wrong is not a check.
///
/// So a damaged profile is an error, and callers fail closed on it.
pub fn load(path: &Path) -> Result<Option<PhoneProfile>> {
    let raw = match std::fs::read_to_string(path) {
        Ok(r) => r,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(anyhow::anyhow!(e)).with_context(|| {
                format!(
                    "phonehome: {} exists but cannot be read — refusing to treat that \
                     as 'no phone is paired'",
                    path.display()
                )
            })
        }
    };
    let profile: PhoneProfile = serde_json::from_str(&raw).with_context(|| {
        format!(
            "phonehome: {} is not a readable profile — refusing to treat that as \
             'no phone is paired'",
            path.display()
        )
    })?;
    Ok(Some(profile))
}

/// Record this handset as the paired one — the phone's `/definehome`.
///
/// Written to a private temporary file and renamed into place, because a
/// half-written profile is not a cosmetic problem: [`load`] refuses to read one
/// and the daemon then refuses connections until a human looks. `rename` within
/// a directory is atomic, so a reader sees the old profile or the new one and
/// never a fragment.
pub fn save(path: &Path, profile: &PhoneProfile) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let json = serde_json::to_string_pretty(profile)?;
    let tmp = path.with_extension("json.new");
    // Created 0600 from the start rather than chmod'ed afterwards: the window
    // between the two is exactly when another user gets to read it.
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(&tmp)
        .with_context(|| format!("writing {}", tmp.display()))?;
    f.write_all(json.as_bytes())
        .with_context(|| format!("writing {}", tmp.display()))?;
    // Durable before it is visible: a crash between the two must not leave the
    // name pointing at a file whose contents never reached the disk.
    f.sync_all().with_context(|| format!("flushing {}", tmp.display()))?;
    drop(f);
    std::fs::rename(&tmp, path)
        .with_context(|| format!("renaming {} into place", tmp.display()))?;
    Ok(())
}

/// Compare a presented key against the paired one.
///
/// Compares the key and nothing else. Model and manufacturer are deliberately
/// not consulted: they match on a friend's identical handset, so letting them
/// influence this would reintroduce exactly the false positive the device key
/// exists to remove.
pub fn identify(saved: Option<&PhoneProfile>, presented_key: &[u8]) -> PhoneVerdict {
    match saved {
        None => PhoneVerdict::NotPaired,
        Some(p) if constant_time_eq(&p.public_key_der, presented_key) => PhoneVerdict::SameDevice,
        Some(_) => PhoneVerdict::DifferentDevice,
    }
}

/// Length-independent comparison. Public keys are not secret, so this is not
/// strictly required — it is here so nobody later copies this pattern to
/// compare something that is.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Verify that whoever is on the other end holds the private half.
///
/// This is what makes the whole thing worth anything: the public key alone
/// travels, so anyone could present it. Only the handset that generated the key
/// can sign with it, because the private half never leaves its hardware.
///
/// ECDSA P-256 over SHA-256, ASN.1 signature — what the Android Keystore
/// produces for `SHA256withECDSA`.
pub fn verify_challenge(public_key_der: &[u8], challenge: &[u8], signature: &[u8]) -> bool {
    let key = UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, public_key_der);
    key.verify(challenge, signature).is_ok()
}

/// A fresh challenge for the handset to sign.
///
/// Random and per-connection: a challenge the phone could predict, or one
/// reused between connections, would let a recorded signature be replayed by
/// something that does not hold the key at all.
pub fn fresh_challenge() -> Result<[u8; 32]> {
    let mut c = [0u8; 32];
    getrandom::getrandom(&mut c)
        .map_err(|e| anyhow::anyhow!("phonehome: no entropy for a challenge: {e}"))?;
    Ok(c)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::rand::SystemRandom;
    use aws_lc_rs::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING};

    /// A stand-in for a handset's Keystore key.
    fn a_phone() -> (EcdsaKeyPair, Vec<u8>) {
        let pair = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_ASN1_SIGNING).expect("generate");
        let pubkey = pair.public_key().as_ref().to_vec();
        (pair, pubkey)
    }

    fn profile_for(pubkey: Vec<u8>, model: &str) -> PhoneProfile {
        PhoneProfile {
            public_key_der: pubkey,
            claimed_backing: "strong_box".into(),
            attestation_verified: true,
            model: model.into(),
            manufacturer: "Google".into(),
            paired_at_unix: 1_700_000_000,
        }
    }

    #[test]
    fn an_identical_model_is_still_a_different_phone() {
        // The whole reason this module exists. Two handsets that agree on every
        // string Android will tell you about them, and differ only in a key
        // that cannot be copied out of either.
        let (_, mine) = a_phone();
        let (_, my_friends) = a_phone();
        assert_ne!(mine, my_friends);

        let saved = profile_for(mine.clone(), "Pixel 8");
        let friend = profile_for(my_friends.clone(), "Pixel 8");

        // Every piece of "identity" Android offers matches.
        assert_eq!(saved.model, friend.model);
        assert_eq!(saved.manufacturer, friend.manufacturer);

        // And the verdict is still right.
        assert_eq!(identify(Some(&saved), &mine), PhoneVerdict::SameDevice);
        assert_eq!(identify(Some(&saved), &my_friends), PhoneVerdict::DifferentDevice);
    }

    #[test]
    fn nothing_paired_is_its_own_answer() {
        let (_, key) = a_phone();
        assert_eq!(identify(None, &key), PhoneVerdict::NotPaired);
        assert!(PhoneVerdict::NotPaired.describe().contains("todavía no"));
    }

    #[test]
    fn only_the_phone_that_owns_the_key_can_answer_a_challenge() {
        // Presenting a public key proves nothing — it travels. Signing does.
        let (mine, my_pub) = a_phone();
        let (friend, friend_pub) = a_phone();
        let rng = SystemRandom::new();

        let challenge = fresh_challenge().unwrap();
        let sig = mine.sign(&rng, &challenge).unwrap();
        assert!(verify_challenge(&my_pub, &challenge, sig.as_ref()));

        // The friend's handset cannot answer for mine.
        let their_sig = friend.sign(&rng, &challenge).unwrap();
        assert!(!verify_challenge(&my_pub, &challenge, their_sig.as_ref()));
        assert!(verify_challenge(&friend_pub, &challenge, their_sig.as_ref()));

        // A signature over a different challenge must not be reusable.
        let other = fresh_challenge().unwrap();
        assert!(!verify_challenge(&my_pub, &other, sig.as_ref()));

        // Nor a tampered one.
        let mut bad = sig.as_ref().to_vec();
        bad[10] ^= 1;
        assert!(!verify_challenge(&my_pub, &challenge, &bad));
    }

    #[test]
    fn challenges_are_never_reused() {
        // A predictable or repeated challenge lets a recorded signature be
        // replayed by something holding no key at all.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..500 {
            assert!(seen.insert(fresh_challenge().unwrap()), "challenge repeated");
        }
    }

    #[test]
    fn a_profile_round_trips_and_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("sysentinel-ph-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("phone-home.json");

        assert!(load(&path).unwrap().is_none());
        let (_, key) = a_phone();
        let p = profile_for(key, "Pixel 8");
        save(&path, &p).unwrap();

        assert_eq!(load(&path).unwrap().unwrap(), p);
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_damaged_profile_is_never_read_as_nobody_is_paired() {
        // The failure that matters: if a corrupt file read as `None`, the
        // daemon would drop back to "whoever holds the pairing key is the
        // owner" and re-bind to the next handset that connected. Fail closed.
        let dir = std::env::temp_dir().join(format!("sysentinel-ph-bad-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("phone-home.json");

        std::fs::write(&path, b"{ this is not json").unwrap();
        let err = load(&path).expect_err("a corrupt profile must be an error");
        assert!(format!("{err:#}").contains("no phone is paired"), "{err:#}");

        // Truncated mid-write is the realistic version of the same thing.
        let (_, key) = a_phone();
        let good = serde_json::to_string(&profile_for(key, "Pixel 8")).unwrap();
        std::fs::write(&path, &good.as_bytes()[..good.len() / 2]).unwrap();
        assert!(load(&path).is_err(), "a truncated profile must be an error");

        // And an absent file still means exactly what it says.
        std::fs::remove_file(&path).unwrap();
        assert!(load(&path).unwrap().is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn saving_leaves_no_half_written_profile_behind() {
        let dir = std::env::temp_dir().join(format!("sysentinel-ph-atomic-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("phone-home.json");
        let (_, key) = a_phone();
        let p = profile_for(key, "Pixel 8");

        save(&path, &p).unwrap();
        save(&path, &p).unwrap(); // twice: the staging name must not collide
        assert_eq!(load(&path).unwrap().unwrap(), p);
        // The staging file must not survive a successful save.
        assert!(!path.with_extension("json.new").exists());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_description_leads_with_the_key_and_flags_a_missing_attestation() {
        let (_, key) = a_phone();
        let mut p = profile_for(key, "Pixel 8");
        assert!(p.describe().starts_with("clave "));
        assert!(p.describe().contains("contexto, no identidad"));

        p.attestation_verified = false;
        assert!(p.describe().contains("SIN atestación"), "{}", p.describe());

        // The key id is stable and short enough to eyeball.
        assert_eq!(p.key_id().len(), 16);
        assert_eq!(p.key_id(), p.key_id());
    }

    #[test]
    fn the_profile_path_sits_beside_the_queue() {
        assert_eq!(
            profile_path("/var/lib/sysentinel/phone-queue.json"),
            Path::new("/var/lib/sysentinel/phone-home.json")
        );
    }
}
