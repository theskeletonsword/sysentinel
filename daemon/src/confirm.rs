// SPDX-License-Identifier: Apache-2.0
//!
//! What actually backed a confirmation.
//!
//! Destructive operations need the owner to say yes. Until now that meant a
//! one-time `CONFIRM-XXXXXX` code typed into a chat within a time window, which
//! is fine as a floor and is weak as a ceiling:
//!
//! - it can be read over a shoulder;
//! - it can be demanded out loud by somebody standing there;
//! - and once spoken, anyone can type it.
//!
//! A phone can do better, because it can hold a key the machine cannot reach
//! and that its owner has to be *physically present* to use. A fingerprint
//! bound to a secure element with user authentication required is not
//! replayable by someone who is not there — that is the whole point of it.
//!
//! # A claim is not a proof
//!
//! The distinction this module exists to keep is between what a phone *says*
//! and what it can *demonstrate*. A handset reporting "I used StrongBox" is
//! telling the daemon something about itself, and whoever controls the handset
//! controls what it says. It is worth nothing on its own.
//!
//! What is worth something is **key attestation**: a certificate chain rooted
//! in a key the manufacturer signed at the factory, in which the secure element
//! itself states the key's security level, whether user authentication was
//! required, and whether that authentication was biometric. Until that chain is
//! verified, a confirmation is graded at the level it can *prove* — see
//! [`ConfirmMethod::proven`].
//!
//! # The ladder
//!
//! The same shape as every other degradation in this daemon: take the strongest
//! rung available, say which one it was, and never pretend it was a better one.
//!
//! | Rung | Backed by | Replayable by someone absent? |
//! |------|-----------|-------------------------------|
//! | [`ConfirmMethod::StrongBox`] | discrete secure element (Titan M, StrongBox) + biometric | no |
//! | [`ConfirmMethod::Tee`] | TrustZone / TEE key + biometric | no |
//! | [`ConfirmMethod::DeviceCredential`] | phone PIN or pattern, hardware key | no, but coercible |
//! | [`ConfirmMethod::SoftwareKey`] | key in ordinary storage | yes, if the phone is unlocked |
//! | [`ConfirmMethod::OneTimeCode`] | a code typed into a chat | **yes** |
//!
//! `OneTimeCode` stays, because a device that cannot do any of the others must
//! still be able to answer. It is the floor, not the target.

use serde::{Deserialize, Serialize};

/// How a confirmation was authenticated.
///
/// Ordered weakest to strongest, so comparisons read the way they sound:
/// `method >= ConfirmMethod::Tee`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfirmMethod {
    /// A `CONFIRM-XXXXXX` code typed into the chat. Always available.
    OneTimeCode,
    /// A key held in ordinary software storage on the phone.
    SoftwareKey,
    /// A hardware-backed key released by the phone's PIN, pattern or password.
    DeviceCredential,
    /// A hardware-backed key in the TEE (ARM TrustZone), released by biometric.
    Tee,
    /// A key in a discrete secure element — Titan M on Pixels, StrongBox
    /// elsewhere — released by biometric.
    StrongBox,
}

impl ConfirmMethod {
    /// Plain description for a log line or an audit trail.
    pub fn describe(&self) -> String {
        match self {
            ConfirmMethod::OneTimeCode => crate::lang::t(
                "confirm.one_time_code",
                "a one-time code typed into the chat",
            ),
            ConfirmMethod::SoftwareKey => crate::lang::t(
                "confirm.software_key",
                "a key in the phone's ordinary storage (no hardware backing)",
            ),
            ConfirmMethod::DeviceCredential => crate::lang::t(
                "confirm.device_credential",
                "a hardware-backed key, released by the phone's PIN",
            ),
            ConfirmMethod::Tee => crate::lang::t(
                "confirm.tee",
                "a key in the TEE (TrustZone), released by a biometric",
            ),
            ConfirmMethod::StrongBox => crate::lang::t(
                "confirm.strongbox",
                "a key in a discrete secure element (Titan M / StrongBox), released by a biometric",
            ),
        }
    }

    /// Whether someone who is not physically present could reuse this.
    ///
    /// The property that matters under coercion: a code spoken aloud travels,
    /// a finger does not.
    pub fn replayable_by_absent_party(&self) -> bool {
        matches!(self, ConfirmMethod::OneTimeCode | ConfirmMethod::SoftwareKey)
    }

    /// Whether the owner had to be present, in body, to produce it.
    ///
    /// The policy hook for the duress case in [`crate::facenn`]: when the
    /// camera has just seen the owner with strangers, a typed code is exactly
    /// the wrong proof, because it is what somebody standing there can demand
    /// out loud.
    ///
    /// Enforced in `bot.rs`: once the paired handset has proved it can sign,
    /// a typed code stops clearing the bar for anything irreversible.
    pub fn proves_presence(&self) -> bool {
        matches!(self, ConfirmMethod::Tee | ConfirmMethod::StrongBox)
    }

    /// Whether accepting this at face value requires a verified attestation
    /// chain. Everything hardware-backed does: the phone's word is not enough.
    pub fn requires_attestation(&self) -> bool {
        matches!(
            self,
            ConfirmMethod::DeviceCredential | ConfirmMethod::Tee | ConfirmMethod::StrongBox
        )
    }

    /// What the daemon may record, given what was actually verified.
    ///
    /// A phone claiming `StrongBox` with no verified attestation chain is
    /// downgraded to [`ConfirmMethod::SoftwareKey`] — not rejected, because the
    /// owner may well have confirmed, but not credited with a security level
    /// nothing demonstrated. Claims never travel upward.
    pub fn proven(claimed: ConfirmMethod, attestation_verified: bool) -> ConfirmMethod {
        if claimed.requires_attestation() && !attestation_verified {
            ConfirmMethod::SoftwareKey
        } else {
            claimed
        }
    }
}

/// The AEAD the phone used to seal its side, mirroring the choice the daemon
/// already makes on x86 in `tpmkey.rs`: hardware AES where the CPU has it,
/// ChaCha where it does not.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PhoneAead {
    /// ARMv8 crypto extensions present.
    Aes256Gcm,
    /// No hardware AES — the case ChaCha20-Poly1305 was designed for, and the
    /// usual one on 32-bit `armeabi-v7a` handsets.
    ChaCha20Poly1305,
}

impl PhoneAead {
    pub fn label(&self) -> &'static str {
        match self {
            PhoneAead::Aes256Gcm => "aes-256-gcm",
            PhoneAead::ChaCha20Poly1305 => "chacha20-poly1305",
        }
    }
}

/// One confirmation, as the daemon records it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Confirmation {
    /// What the far side said backed it.
    pub claimed: ConfirmMethod,
    /// Whether an attestation chain was verified for that claim.
    pub attestation_verified: bool,
    /// Cipher the phone sealed with, when it was a phone at all.
    pub aead: Option<PhoneAead>,
    /// Free-text device label for the audit trail.
    pub device: Option<String>,
}

impl Confirmation {
    /// A code typed into the chat — the floor, and what the bot has always done.
    pub fn one_time_code() -> Self {
        Confirmation {
            claimed: ConfirmMethod::OneTimeCode,
            attestation_verified: false,
            aead: None,
            device: None,
        }
    }

    /// The level this confirmation actually demonstrated.
    pub fn effective(&self) -> ConfirmMethod {
        ConfirmMethod::proven(self.claimed, self.attestation_verified)
    }

    /// Whether it clears `required`. The bar for an operation is set by policy;
    /// this is how a confirmation is measured against it.
    #[allow(dead_code)] // measured in the tests; the live gate asks
                        // `proves_presence` directly
    pub fn satisfies(&self, required: ConfirmMethod) -> bool {
        self.effective() >= required
    }

    /// Whether the owner had to be bodily present to produce this — judged on
    /// what was proven, never on what was claimed.
    #[allow(dead_code)]
    pub fn proves_presence_now(&self) -> bool {
        self.effective().proves_presence()
    }

    /// One line for the audit trail. Names the effective level, and says so
    /// out loud when it is lower than what was claimed — a downgrade is
    /// exactly the sort of thing that must not pass quietly.
    pub fn audit_line(&self) -> String {
        let effective = self.effective();
        let mut s = format!(
            "{} {}",
            crate::lang::t("confirm.audit_prefix", "confirmed by:"),
            effective.describe()
        );
        if effective < self.claimed {
            s.push_str(
                &crate::lang::t(
                    "confirm.downgraded",
                    " ⚠️ (the device claimed «{claimed}» and did not demonstrate it: no \
                     verified attestation chain, so it counts as the rung above)",
                )
                .replace("{claimed}", &self.claimed.describe()),
            );
        }
        if let Some(d) = &self.device {
            s.push_str(&format!(" · {d}"));
        }
        if let Some(a) = self.aead {
            s.push_str(&format!(" · {}", a.label()));
        }
        if effective.replayable_by_absent_party() {
            s.push_str(&crate::lang::t(
                "confirm.replayable",
                " · ⚠️ reusable by somebody who is not present",
            ));
        }
        s
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ladder_is_ordered_weakest_first() {
        assert!(ConfirmMethod::StrongBox > ConfirmMethod::Tee);
        assert!(ConfirmMethod::Tee > ConfirmMethod::DeviceCredential);
        assert!(ConfirmMethod::DeviceCredential > ConfirmMethod::SoftwareKey);
        assert!(ConfirmMethod::SoftwareKey > ConfirmMethod::OneTimeCode);
    }

    #[test]
    fn a_claim_without_attestation_never_travels_upward() {
        // The property this module exists for: whoever controls the phone
        // controls what it says about itself.
        for claimed in [
            ConfirmMethod::StrongBox,
            ConfirmMethod::Tee,
            ConfirmMethod::DeviceCredential,
        ] {
            assert!(claimed.requires_attestation());
            assert_eq!(
                ConfirmMethod::proven(claimed, false),
                ConfirmMethod::SoftwareKey,
                "{claimed:?} was credited without proof"
            );
            assert_eq!(ConfirmMethod::proven(claimed, true), claimed);
        }
        // A code claims nothing, so there is nothing to downgrade.
        assert!(!ConfirmMethod::OneTimeCode.requires_attestation());
        assert_eq!(
            ConfirmMethod::proven(ConfirmMethod::OneTimeCode, false),
            ConfirmMethod::OneTimeCode
        );
    }

    #[test]
    fn an_unproven_strongbox_claim_is_visibly_downgraded() {
        let c = Confirmation {
            claimed: ConfirmMethod::StrongBox,
            attestation_verified: false,
            aead: Some(PhoneAead::Aes256Gcm),
            device: Some("Pixel 8".into()),
        };
        assert_eq!(c.effective(), ConfirmMethod::SoftwareKey);
        let line = c.audit_line();
        assert!(line.contains("did not demonstrate it"), "{line}");
        assert!(line.contains("reusable by somebody"), "{line}");
        // And it must not clear a bar it did not reach.
        assert!(!c.satisfies(ConfirmMethod::Tee));
        assert!(!c.satisfies(ConfirmMethod::StrongBox));
    }

    #[test]
    fn a_proven_strongbox_confirmation_clears_every_bar() {
        let c = Confirmation {
            claimed: ConfirmMethod::StrongBox,
            attestation_verified: true,
            aead: Some(PhoneAead::Aes256Gcm),
            device: Some("Pixel 8 (Titan M2)".into()),
        };
        assert_eq!(c.effective(), ConfirmMethod::StrongBox);
        assert!(c.satisfies(ConfirmMethod::StrongBox));
        assert!(c.proves_presence_now());
        assert!(!c.effective().replayable_by_absent_party());
        let line = c.audit_line();
        assert!(!line.contains("did not demonstrate it"), "{line}");
        assert!(line.contains("Titan"), "{line}");
    }

    #[test]
    fn the_typed_code_is_honest_about_being_replayable() {
        // The floor still works — a phone that can do none of this must be
        // able to answer — but it says what it is.
        let c = Confirmation::one_time_code();
        assert_eq!(c.effective(), ConfirmMethod::OneTimeCode);
        assert!(c.satisfies(ConfirmMethod::OneTimeCode));
        assert!(!c.satisfies(ConfirmMethod::SoftwareKey));
        assert!(c.effective().replayable_by_absent_party());
        assert!(!c.proves_presence_now());
        assert!(c.audit_line().contains("reusable by somebody"));
    }

    #[test]
    fn only_biometric_hardware_rungs_prove_presence() {
        // A PIN can be demanded out loud; a finger has to be there.
        assert!(ConfirmMethod::StrongBox.proves_presence());
        assert!(ConfirmMethod::Tee.proves_presence());
        assert!(!ConfirmMethod::DeviceCredential.proves_presence());
        assert!(!ConfirmMethod::SoftwareKey.proves_presence());
        assert!(!ConfirmMethod::OneTimeCode.proves_presence());
    }

    #[test]
    fn the_wire_format_is_stable() {
        // The phone and the daemon have to agree on these strings.
        assert_eq!(
            serde_json::to_string(&ConfirmMethod::StrongBox).unwrap(),
            "\"strong_box\""
        );
        assert_eq!(
            serde_json::to_string(&PhoneAead::ChaCha20Poly1305).unwrap(),
            "\"cha_cha20_poly1305\""
        );
        let round: ConfirmMethod = serde_json::from_str("\"tee\"").unwrap();
        assert_eq!(round, ConfirmMethod::Tee);
    }
}
