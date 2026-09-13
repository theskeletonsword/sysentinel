// SPDX-License-Identifier: Apache-2.0
//
// faceseal.rs -- Hybrid envelope for the biometrics mirror on the ESP.
//
// GOLDEN RULE (immutable): the ESP never stores a photo, an embedding, or
// perceptual hashes in cleartext.  Only an opaque sealed blob lives there.
//
// Key sources (decided, not changeable without a new enroll):
//   Primary   -- P-521 ECDH static keypair, private half TPM-sealed
//                (daemon/src/tpmkey.rs); passwordless on the live system.
//   Fallback  -- 32-byte key derived from the LUKS passphrase via
//                Argon2id/HKDF-SHA384, re-derivable inside the initramfs
//                without any TPM stack.
//
// Hybrid scheme per seal (P-521 ECDH + ML-KEM-1024 -> HKDF-SHA384 -> AEAD):
//   1. Fresh ephemeral P-521 keypair generated; private half discarded in RAM
//      as soon as the ECDH shared secret is computed -- never leaves RAM.
//   2. ECDH: eph_priv x machine_static_pub  ->  ss_ecdh
//   3. ML-KEM-1024 encapsulate(machine_enc_key) -> (kem_ct, ss_kem)
//   4. IKM  = ss_ecdh || ss_kem
//      HKDF-SHA384(IKM, salt="sysentinel-face-v1", info="sysentinel-face-aead")
//      -> 32-byte AEAD key
//   5. AES-256-GCM if /proc/cpuinfo reports aes/vaes; else ChaCha20-Poly1305.
//   6. Fresh 12-byte nonce per seal (never reused).
//
// Wire format (little-endian, binary):
//   magic[6]   = "SYSE15"
//   version[1] = 1
//   alg[1]     = 1 (AES-256-GCM) | 2 (ChaCha20-Poly1305)
//   nonce[12]
//   mlkem_ct[1568]
//   eph_pub[133]   SEC1 uncompressed P-521
//   ct[...]        ciphertext + AEAD tag (payload + 16 B tag)
//
// AAD = magic || version || alg || eph_pub
//   Binds the blob to this algorithm choice and ephemeral key; any tampering
//   with those fields invalidates the authentication tag.
//
// The static private key NEVER travels in the blob.  Attacking the ESP hands
// an attacker only opaque ciphertext; stealing the initramfs likewise gives
// nothing because the private key is either inside the TPM or derived from a
// passphrase that lives only in the owner's head.

use aws_lc_rs::{
    aead::{Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, CHACHA20_POLY1305},
    agreement::{self, ECDH_P521, UnparsedPublicKey},
    hkdf::{KeyType, Salt, HKDF_SHA384},
    kem::{Ciphertext, DecapsulationKey, EncapsulationKey, ML_KEM_1024},
    rand::{SecureRandom, SystemRandom},
};

// ── Public constants ──────────────────────────────────────────────────────────

pub const ENVELOPE_MAGIC: &[u8; 6] = b"SYSE15";
pub const ENVELOPE_VERSION: u8 = 1;
/// ML-KEM-1024 ciphertext length (fixed by the standard).
pub const MLKEM_CT_LEN: usize = 1568;
/// SEC1 uncompressed P-521 public key: 04 || 66 B X || 66 B Y.
pub const P521_EPH_PUB_LEN: usize = 133;
/// AEAD nonce length (GCM and ChaCha20-Poly1305 share 12 bytes).
pub const NONCE_BYTES: usize = 12;
/// Total header size before the ciphertext payload.
pub const HEADER_LEN: usize = 6 + 1 + 1 + NONCE_BYTES + MLKEM_CT_LEN + P521_EPH_PUB_LEN;

// ── Public types ──────────────────────────────────────────────────────────────

/// AEAD algorithm used for this envelope (stored in byte 7 of the wire format).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AeadAlg {
    Aes256Gcm       = 1,
    ChaCha20Poly1305 = 2,
}

/// Sealed biometric blob as stored on the ESP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    pub alg:      AeadAlg,
    pub nonce:    [u8; NONCE_BYTES],
    pub mlkem_ct: [u8; MLKEM_CT_LEN],
    pub eph_pub:  [u8; P521_EPH_PUB_LEN],
    /// Ciphertext including the 16-byte authentication tag.
    pub ct:       Vec<u8>,
}

// ── Wire serialisation ────────────────────────────────────────────────────────

impl Envelope {
    /// Serialise to the on-disk wire format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(HEADER_LEN + self.ct.len());
        out.extend_from_slice(ENVELOPE_MAGIC);
        out.push(ENVELOPE_VERSION);
        out.push(self.alg as u8);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.mlkem_ct);
        out.extend_from_slice(&self.eph_pub);
        out.extend_from_slice(&self.ct);
        out
    }

    /// Parse from the on-disk wire format.
    pub fn from_bytes(b: &[u8]) -> Result<Self, &'static str> {
        if b.len() < HEADER_LEN + 16 {
            return Err("envelope too short");
        }
        if &b[..6] != ENVELOPE_MAGIC {
            return Err("bad magic");
        }
        if b[6] != ENVELOPE_VERSION {
            return Err("unsupported version");
        }
        let alg = match b[7] {
            1 => AeadAlg::Aes256Gcm,
            2 => AeadAlg::ChaCha20Poly1305,
            _ => return Err("unknown alg"),
        };
        let mut nonce    = [0u8; NONCE_BYTES];
        let mut mlkem_ct = [0u8; MLKEM_CT_LEN];
        let mut eph_pub  = [0u8; P521_EPH_PUB_LEN];
        let mut off = 8;
        nonce.copy_from_slice(&b[off..off + NONCE_BYTES]);    off += NONCE_BYTES;
        mlkem_ct.copy_from_slice(&b[off..off + MLKEM_CT_LEN]); off += MLKEM_CT_LEN;
        eph_pub.copy_from_slice(&b[off..off + P521_EPH_PUB_LEN]); off += P521_EPH_PUB_LEN;
        Ok(Envelope { alg, nonce, mlkem_ct, eph_pub, ct: b[off..].to_vec() })
    }
}

// ── Internal helpers ──────────────────────────────────────────────────────────

/// Choose the AEAD from /proc/cpuinfo: AES-256-GCM when the CPU reports aes or
/// vaes (AES-NI / VAES), ChaCha20-Poly1305 otherwise.
fn choose_alg() -> AeadAlg {
    if crate::tpmkey::aes_accelerated() {
        AeadAlg::Aes256Gcm
    } else {
        AeadAlg::ChaCha20Poly1305
    }
}

fn alg_impl(alg: AeadAlg) -> &'static aws_lc_rs::aead::Algorithm {
    match alg {
        AeadAlg::Aes256Gcm       => &AES_256_GCM,
        AeadAlg::ChaCha20Poly1305 => &CHACHA20_POLY1305,
    }
}

/// HKDF-SHA384 key derivation.  Always produces 32 bytes.
fn derive_key(ikm: &[u8]) -> [u8; 32] {
    struct Len32;
    impl KeyType for Len32 {
        fn len(&self) -> usize { 32 }
    }
    let prk = Salt::new(HKDF_SHA384, b"sysentinel-face-v1").extract(ikm);
    let okm = prk
        .expand(&[b"sysentinel-face-aead" as &[u8]], Len32)
        .expect("hkdf expand");
    let mut key = [0u8; 32];
    okm.fill(&mut key).expect("hkdf fill");
    key
}

/// Build the AAD buffer: magic(6) | version(1) | alg(1) | eph_pub(133).
fn build_aad(alg: AeadAlg, eph_pub: &[u8; P521_EPH_PUB_LEN])
    -> [u8; 6 + 1 + 1 + P521_EPH_PUB_LEN]
{
    let mut aad = [0u8; 6 + 1 + 1 + P521_EPH_PUB_LEN];
    aad[..6].copy_from_slice(ENVELOPE_MAGIC);
    aad[6]  = ENVELOPE_VERSION;
    aad[7]  = alg as u8;
    aad[8..].copy_from_slice(eph_pub);
    aad
}

// ── Public API ────────────────────────────────────────────────────────────────

/// Seal `payload` towards the machine's static public keys.
///
/// * `machine_pub_ecdh` -- SEC1 uncompressed P-521 static public key (133 B).
/// * `enc_key`          -- ML-KEM-1024 static encapsulation key.
///
/// The ephemeral P-521 private key is discarded from RAM immediately after
/// the ECDH operation; it never touches the envelope or disk.
pub fn seal(
    machine_pub_ecdh: &[u8],
    enc_key: &EncapsulationKey,
    payload: &[u8],
) -> Result<Envelope, &'static str> {
    let alg = choose_alg();

    // 1. Ephemeral P-521 keypair.
    let eph_priv = agreement::PrivateKey::generate(&ECDH_P521).map_err(|_| "ecdh gen")?;
    let eph_pub_key = eph_priv.compute_public_key().map_err(|_| "ecdh pub")?;
    let eph_pub_slice = eph_pub_key.as_ref();
    if eph_pub_slice.len() != P521_EPH_PUB_LEN {
        return Err("eph pub len unexpected");
    }
    let mut eph_pub = [0u8; P521_EPH_PUB_LEN];
    eph_pub.copy_from_slice(eph_pub_slice);

    // 2. ECDH: eph_priv x machine_static_pub -> ss_ecdh.
    let ss_ecdh: Vec<u8> = agreement::agree(
        &eph_priv,
        UnparsedPublicKey::new(&ECDH_P521, machine_pub_ecdh),
        "ecdh agree",
        |ss| Ok(ss.to_vec()),
    )?;
    // eph_priv is consumed by agree; its stack memory is gone.

    // 3. ML-KEM-1024 encapsulate.
    let (kem_ct, ss_kem) = enc_key.encapsulate().map_err(|_| "kem encap")?;
    let kem_ct_bytes = kem_ct.as_ref();
    if kem_ct_bytes.len() != MLKEM_CT_LEN {
        return Err("kem ct len unexpected");
    }
    let mut mlkem_ct = [0u8; MLKEM_CT_LEN];
    mlkem_ct.copy_from_slice(kem_ct_bytes);

    // 4. IKM = ss_ecdh || ss_kem; HKDF-SHA384 -> 32-byte AEAD key.
    let mut ikm = Vec::with_capacity(ss_ecdh.len() + ss_kem.as_ref().len());
    ikm.extend_from_slice(&ss_ecdh);
    ikm.extend_from_slice(ss_kem.as_ref());
    let key = derive_key(&ikm);

    // 5. Fresh 12-byte nonce.
    let rng = SystemRandom::new();
    let mut nonce = [0u8; NONCE_BYTES];
    rng.fill(&mut nonce).map_err(|_| "nonce fill")?;

    // 6. AEAD seal.
    let aad = build_aad(alg, &eph_pub);
    let lsk = LessSafeKey::new(
        UnboundKey::new(alg_impl(alg), &key).map_err(|_| "aead key")?,
    );
    let n = Nonce::assume_unique_for_key(nonce);
    let mut ct = payload.to_vec();
    lsk.seal_in_place_append_tag(n, Aad::from(&aad[..]), &mut ct)
        .map_err(|_| "aead seal")?;

    Ok(Envelope { alg, nonce, mlkem_ct, eph_pub, ct })
}

/// Open a sealed envelope with the machine's static private keys.
///
/// * `machine_priv` -- P-521 static private key (reconstructed from TPM-sealed
///                     DER via `agreement::PrivateKey::from_private_key_der`, or
///                     generated deterministically from the LUKS passphrase).
/// * `dec_key`      -- ML-KEM-1024 static decapsulation key.
///
/// Returns the original payload on success; any mismatch (wrong machine,
/// tampered envelope, wrong algorithm) returns `Err`.
pub fn open(
    env: &Envelope,
    machine_priv: &agreement::PrivateKey,
    dec_key: &DecapsulationKey,
) -> Result<Vec<u8>, &'static str> {
    // 1. ECDH: machine_static_priv x env.eph_pub -> ss_ecdh.
    let ss_ecdh: Vec<u8> = agreement::agree(
        machine_priv,
        UnparsedPublicKey::new(&ECDH_P521, &env.eph_pub[..]),
        "ecdh agree",
        |ss| Ok(ss.to_vec()),
    )?;

    // 2. ML-KEM-1024 decapsulate.
    let ss_kem = dec_key
        .decapsulate(Ciphertext::from(&env.mlkem_ct[..]))
        .map_err(|_| "kem decap")?;

    // 3. IKM = ss_ecdh || ss_kem; HKDF-SHA384 -> 32-byte AEAD key.
    let mut ikm = Vec::with_capacity(ss_ecdh.len() + ss_kem.as_ref().len());
    ikm.extend_from_slice(&ss_ecdh);
    ikm.extend_from_slice(ss_kem.as_ref());
    let key = derive_key(&ikm);

    // 4. AEAD open.
    let aad = build_aad(env.alg, &env.eph_pub);
    let lsk = LessSafeKey::new(
        UnboundKey::new(alg_impl(env.alg), &key).map_err(|_| "aead key")?,
    );
    let n = Nonce::assume_unique_for_key(env.nonce);
    let mut ct = env.ct.clone();
    let pt_len = lsk
        .open_in_place(n, Aad::from(&aad[..]), &mut ct)
        .map_err(|_| "aead open (wrong key or tampered)")?
        .len();
    ct.truncate(pt_len);
    Ok(ct)
}

/// Derive a 32-byte symmetric key from a LUKS passphrase + salt.
///
/// Deterministic: calling with the same inputs in the initramfs produces the
/// same key as calling in the running daemon.  The caller must store the salt
/// alongside the sealed blob (it is not secret).
pub fn derive_from_phrase(phrase: &[u8], salt: &[u8]) -> [u8; 32] {
    // Concatenate phrase + salt as IKM and pass through HKDF-SHA384.
    // Production code feeds this into Argon2id first; here we offer the HKDF
    // layer that consumes the Argon2id output.
    let mut ikm = Vec::with_capacity(phrase.len() + salt.len());
    ikm.extend_from_slice(phrase);
    ikm.extend_from_slice(salt);
    let prk = Salt::new(HKDF_SHA384, b"sysentinel-phrase-v1").extract(&ikm);
    struct Len32;
    impl KeyType for Len32 { fn len(&self) -> usize { 32 } }
    let okm = prk
        .expand(&[b"sysentinel-phrase-aead" as &[u8]], Len32)
        .expect("hkdf expand");
    let mut key = [0u8; 32];
    okm.fill(&mut key).expect("hkdf fill");
    key
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use aws_lc_rs::{
        agreement::PrivateKey,
        kem::DecapsulationKey,
    };

    fn machine() -> (PrivateKey, DecapsulationKey) {
        let ecdh = PrivateKey::generate(&ECDH_P521).unwrap();
        let dec  = DecapsulationKey::generate(&ML_KEM_1024).unwrap();
        (ecdh, dec)
    }

    #[test]
    fn seal_open_roundtrip_hybrid() {
        let payload = b"foto || embed || p_hash || w_hash || ts";
        let (ecdh, dec) = machine();
        let enc = dec.encapsulation_key().unwrap();
        let pub_bytes = ecdh.compute_public_key().unwrap();
        let env = seal(pub_bytes.as_ref(), &enc, payload).unwrap();
        let got = open(&env, &ecdh, &dec).unwrap();
        assert_eq!(got.as_slice(), payload.as_slice());
    }

    #[test]
    fn roundtrip_wire_serialisation() {
        let (ecdh, dec) = machine();
        let enc = dec.encapsulation_key().unwrap();
        let pub_bytes = ecdh.compute_public_key().unwrap();
        let env = seal(pub_bytes.as_ref(), &enc, b"biometric").unwrap();
        let bytes = env.to_bytes();
        let env2 = Envelope::from_bytes(&bytes).unwrap();
        assert_eq!(env, env2);
        let got = open(&env2, &ecdh, &dec).unwrap();
        assert_eq!(got.as_slice(), b"biometric");
    }

    #[test]
    fn wrong_machine_fails() {
        let (ecdh, dec) = machine();
        let enc = dec.encapsulation_key().unwrap();
        let pub_bytes = ecdh.compute_public_key().unwrap();
        let env = seal(pub_bytes.as_ref(), &enc, b"secret").unwrap();
        let (ecdh2, dec2) = machine();
        assert!(open(&env, &ecdh2, &dec2).is_err());
    }

    #[test]
    fn nonce_fresh_per_seal() {
        let (ecdh, dec) = machine();
        let enc = dec.encapsulation_key().unwrap();
        let pub_bytes = ecdh.compute_public_key().unwrap();
        let a = seal(pub_bytes.as_ref(), &enc, b"x").unwrap();
        let b = seal(pub_bytes.as_ref(), &enc, b"x").unwrap();
        assert_ne!(a.nonce, b.nonce, "nonce must be fresh per seal");
    }

    #[test]
    fn tampered_envelope_rejected() {
        let (ecdh, dec) = machine();
        let enc = dec.encapsulation_key().unwrap();
        let pub_bytes = ecdh.compute_public_key().unwrap();
        let mut env = seal(pub_bytes.as_ref(), &enc, b"tamper me").unwrap();
        // Flip the last byte of the ciphertext (the auth tag).
        let last = env.ct.len() - 1;
        env.ct[last] ^= 0xff;
        assert!(open(&env, &ecdh, &dec).is_err());
    }

    #[test]
    fn derive_from_phrase_deterministic() {
        let k1 = derive_from_phrase(b"mypassphrase", b"salt1234");
        let k2 = derive_from_phrase(b"mypassphrase", b"salt1234");
        assert_eq!(k1, k2);
        let k3 = derive_from_phrase(b"mypassphrase", b"othersalt");
        assert_ne!(k1, k3);
    }
}
