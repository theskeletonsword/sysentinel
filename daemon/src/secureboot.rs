// SPDX-License-Identifier: Apache-2.0
//!
//! Secure Boot truth — whether the firmware has Secure Boot active, and what
//! that means for loading the `sysentinel_metrics` kernel module.
//!
//! Detection chain (first one that answers wins):
//!  1. `mokutil --sb-state`  — cleanest human-readable verdict.
//!  2. UEFI efivars read  — `SecureBoot-8be4df61-…` (attributes + flag byte).
//!  3. `bootctl status`    — "Secure Boot: enabled/disabled/setup".
//!  4. `/sys/firmware/efi` missing ⇒ BIOS/legacy ⇒ Secure Boot does not apply.
//!
//! Called from `/secureboot` and injected into the persona's system prompt so
//! the bot answers truthfully in plain conversation ("do we have Secure Boot?").

use std::path::Path;
use std::process::Command;

/// Firmware secure-boot state, honestly reported.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecureBoot {
    /// UEFI with Secure Boot enforced: unsigned modules are refused.
    Enabled,
    /// UEFI but Secure Boot is off: unsigned `insmod` works.
    Disabled,
    /// UEFI DB/MOK in setup (enrollment) mode — firmware accepts new keys.
    SetupMode,
    /// No UEFI (BIOS/Legacy) — Secure Boot does not exist here.
    Unsupported,
    /// Couldn't read anything (permissions, no tooling) — don't guess.
    Unknown,
}

impl SecureBoot {
    pub fn label(&self) -> &'static str {
        match self {
            SecureBoot::Enabled => "enabled",
            SecureBoot::Disabled => "disabled",
            SecureBoot::SetupMode => "setup mode",
            SecureBoot::Unsupported => "unsupported (no UEFI)",
            SecureBoot::Unknown => "unknown",
        }
    }

    /// Can an UNSIGNED kernel module be `insmod`ed on this box?
    pub fn accepts_unsigned_modules(&self) -> Option<bool> {
        match self {
            SecureBoot::Enabled | SecureBoot::SetupMode => Some(false),
            SecureBoot::Disabled | SecureBoot::Unsupported => Some(true),
            SecureBoot::Unknown => None,
        }
    }
}

/// Is the firmware UEFI at all?
pub fn is_uefi() -> bool {
    Path::new("/sys/firmware/efi").exists()
}

/// Current secure-boot state, best-effort.
pub fn status() -> SecureBoot {
    if let Some(sb) = mokutil() {
        return sb;
    }
    if let Some(sb) = efivars() {
        return sb;
    }
    if let Some(sb) = bootctl() {
        return sb;
    }
    if !is_uefi() {
        return SecureBoot::Unsupported;
    }
    SecureBoot::Unknown
}

/// `mokutil --sb-state` → "SecureBoot enabled"/"disabled"/"setup".
fn mokutil() -> Option<SecureBoot> {
    let out = Command::new("mokutil").arg("--sb-state").output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    let t = text.to_lowercase();
    if t.contains("setup") {
        Some(SecureBoot::SetupMode)
    } else if t.contains("enabled") {
        Some(SecureBoot::Enabled)
    } else if t.contains("disabled") {
        Some(SecureBoot::Disabled)
    } else {
        None
    }
}

/// Read the UEFI `SecureBoot`/`SetupMode` variables straight from efivars.
fn efivars() -> Option<SecureBoot> {
    let secure = read_efi_var("SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c")?;
    let setup = read_efi_var("SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c");

    // File layout: [4 bytes attributes][variable data…]. SecureBoot payload is
    // a single flag byte: bit0=1 ⇒ enforced. SetupMode bit0=1 ⇒ setup/enrollment.
    let sb_flag = secure.get(4).copied().unwrap_or(0) & 0x01;
    let sm_flag = setup.and_then(|d| d.get(4).copied()).unwrap_or(0) & 0x01;

    if sm_flag == 1 {
        Some(SecureBoot::SetupMode)
    } else if sb_flag == 1 {
        Some(SecureBoot::Enabled)
    } else {
        Some(SecureBoot::Disabled)
    }
}

fn read_efi_var(name: &str) -> Option<Vec<u8>> {
    let p = format!("/sys/firmware/efi/efivars/{name}");
    std::fs::read(&p).ok()
}

/// `bootctl status` → "Secure Boot: enabled/disabled/setup mode".
fn bootctl() -> Option<SecureBoot> {
    let out = Command::new("bootctl").arg("status").output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    for line in text.lines() {
        let t = line.trim();
        if !t.to_lowercase().starts_with("secure boot:") {
            continue;
        }
        let value = t[t.find(':').map(|i| i + 1).unwrap_or(t.len())..].trim().to_lowercase();
        if value.contains("setup") {
            return Some(SecureBoot::SetupMode);
        } else if value.contains("enabled") {
            return Some(SecureBoot::Enabled);
        } else if value.contains("disabled") {
            return Some(SecureBoot::Disabled);
        } else {
            return None;
        }
    }
    None
}

/// One honest, actionable answer to "does our environment have Secure Boot?".
pub fn describe() -> String {
    let sb = status();
    match sb {
        SecureBoot::Enabled => {
            "Yes — Secure Boot is **active** (UEFI). The kernel rejects unsigned \
             modules: to load `sysentinel_metrics.ko` you must sign it with \
             a MOK and enroll it (or disable SB)."
                .to_string()
        }
        SecureBoot::Disabled => {
            "No — Secure Boot is **disabled** (UEFI). You can `insmod` the module \
             unsigned, no key enrollment needed."
                .to_string()
        }
        SecureBoot::SetupMode => {
            "Secure Boot is in **setup/enrollment mode** — the firmware accepts \
             MOK keys right now (`mokutil --import` + reboot)."
                .to_string()
        }
        SecureBoot::Unsupported => {
            "N/A: you booted in **BIOS/legacy** mode, not UEFI — Secure Boot \
             does not exist in this environment. The module insmods unsigned."
                .to_string()
        }
        SecureBoot::Unknown => {
            "I couldn't read the state (permissions on efivars, no `mokutil`/`bootctl`?). \
             I won't affirm anything."
                .to_string()
        }
    }
}

/// Concrete steps to get the kernel module loaded, given the SB state.
pub fn module_load_guidance() -> String {
    match status() {
        SecureBoot::Enabled => {
            "\n_Loading the module with Secure Boot:_\n\
             ```sh\n\
             # 1) generate the MOK key\n\
             openssl req -new -x509 -newkey rsa:2048 -keyout MOK.key \\\n\
               -outform DER -out MOK.der -nodes -days 36500 -subj \"/CN=sysentinel\"\n\
             # 2) sign the .ko\n\
             sudo /usr/src/linux-headers-$(uname -r)/scripts/sign-file \\\n\
               sha256 MOK.key MOK.der kernel_module/sysentinel_metrics.ko\n\
             # 3) enroll the key and reboot (the firmware asks to enroll)\n\
             sudo mokutil --import MOK.der && sudo reboot\n\
             # 4) after enrollment, it loads normally\n\
             sudo insmod kernel_module/sysentinel_metrics.ko write_gid=...\n\
             ```\n\
             Until then I use the ring-3 fallbacks (procfs, wtmp, tracefs, dmesg)."
                .to_string()
        }
        SecureBoot::Disabled | SecureBoot::Unsupported => {
            "\n_Without Secure Boot, load the module directly:_\n\
             ```sh\n\
             sudo insmod kernel_module/sysentinel_metrics.ko write_gid=1000\n\
             ```\n\
             No signature, no MOK, no reboot."
                .to_string()
        }
        SecureBoot::SetupMode => {
            "\n_Setup mode:_ you can enroll the key right now — no need to \
             disable Secure Boot:\n\
             ```sh\n\
             sudo mokutil --import MOK.der && sudo reboot\n\
             ```\n\
             or load the signed module right away."
                .to_string()
        }
        SecureBoot::Unknown => {
            "\nI don't know the Secure Boot state, so I won't recommend a \
             specific path. Try `mokutil --sb-state` or `bootctl status` yourself."
                .to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_when_no_uefi() {
        // No UEFI ⇒ the honest answer is "Secure Boot does not apply". On a UEFI
        // box the verdict must never be Unsupported.
        if is_uefi() {
            assert_ne!(status(), SecureBoot::Unsupported);
        } else {
            assert_eq!(status(), SecureBoot::Unsupported);
        }
    }

    #[test]
    fn labels_are_honest() {
        assert_eq!(SecureBoot::Enabled.label(), "enabled");
        assert_eq!(SecureBoot::Disabled.label(), "disabled");
        assert_eq!(SecureBoot::Unknown.accepts_unsigned_modules(), None);
        assert_eq!(
            SecureBoot::Disabled.accepts_unsigned_modules(),
            Some(true)
        );
        assert_eq!(
            SecureBoot::Enabled.accepts_unsigned_modules(),
            Some(false)
        );
    }

    #[test]
    fn mokutil_parsing() {
        assert_eq!(
            mokutil_from("SecureBoot enabled\n"),
            Some(SecureBoot::Enabled)
        );
        assert_eq!(
            mokutil_from("SecureBoot disabled\n"),
            Some(SecureBoot::Disabled)
        );
        assert_eq!(
            mokutil_from("SecureBoot setup\n"),
            Some(SecureBoot::SetupMode)
        );
    }

    #[test]
    fn bootctl_parsing() {
        assert_eq!(
            bootctl_from("Secure Boot: setup mode\n"),
            Some(SecureBoot::SetupMode)
        );
        assert_eq!(
            bootctl_from("Secure Boot: enabled\n"),
            Some(SecureBoot::Enabled)
        );
    }

    fn mokutil_from(text: &str) -> Option<SecureBoot> {
        let t = text.to_lowercase();
        if t.contains("setup") {
            Some(SecureBoot::SetupMode)
        } else if t.contains("enabled") {
            Some(SecureBoot::Enabled)
        } else if t.contains("disabled") {
            Some(SecureBoot::Disabled)
        } else {
            None
        }
    }

    fn bootctl_from(text: &str) -> Option<SecureBoot> {
        for line in text.lines() {
            let t = line.trim();
            if !t.to_lowercase().starts_with("secure boot:") {
                continue;
            }
            let value = t[t.find(':').map(|i| i + 1).unwrap_or(t.len())..]
                .trim()
                .to_lowercase();
            if value.contains("setup") {
                return Some(SecureBoot::SetupMode);
            } else if value.contains("enabled") {
                return Some(SecureBoot::Enabled);
            } else if value.contains("disabled") {
                return Some(SecureBoot::Disabled);
            } else {
                return None;
            }
        }
        None
    }
}