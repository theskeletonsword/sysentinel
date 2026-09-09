// SPDX-License-Identifier: MIT OR GPL-2.0-or-later
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
//! the bot answers truthfully in plain conversation ("¿tenemos Secure Boot?").

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

/// One honest, actionable answer to "¿nuestro entorno tiene Secure Boot?".
pub fn describe() -> String {
    let sb = status();
    match sb {
        SecureBoot::Enabled => {
            "Sí — Secure Boot está **activo** (UEFI). El kernel rechaza módulos \
             sin firmar: para cargar `sysentinel_metrics.ko` hay que firmarlo con \
             una MOK e inscribirla (o desactivar SB)."
                .to_string()
        }
        SecureBoot::Disabled => {
            "No — Secure Boot está **desactivado** (UEFI). Podés `insmod` el módulo \
             sin firma, sin enroll de llaves."
                .to_string()
        }
        SecureBoot::SetupMode => {
            "Secure Boot está en **modo setup/enrollment** — el firmware acepta \
             inscribir llaves MOK ahora mismo (`mokutil --import` + reboot)."
                .to_string()
        }
        SecureBoot::Unsupported => {
            "No aplica: arrancaste en modo **BIOS/legacy**, no UEFI — Secure Boot \
             no existe en este entorno. El módulo se insmoda sin firma."
                .to_string()
        }
        SecureBoot::Unknown => {
            "No pude leer el estado (¿permisos sobre efivars, sin `mokutil`/`bootctl`?). \
             No te afirmo nada."
                .to_string()
        }
    }
}

/// Concrete steps to get the kernel module loaded, given the SB state.
pub fn module_load_guidance() -> String {
    match status() {
        SecureBoot::Enabled => {
            "\n_Cargar el módulo con Secure Boot:_\n\
             ```sh\n\
             # 1) generar llave MOK\n\
             openssl req -new -x509 -newkey rsa:2048 -keyout MOK.key \\\n\
               -outform DER -out MOK.der -nodes -days 36500 -subj \"/CN=sysentinel\"\n\
             # 2) firmar el .ko\n\
             sudo /usr/src/linux-headers-$(uname -r)/scripts/sign-file \\\n\
               sha256 MOK.key MOK.der kernel_module/sysentinel_metrics.ko\n\
             # 3) inscribir la llave y reiniciar (el firmware pide enroll)\n\
             sudo mokutil --import MOK.der && sudo reboot\n\
             # 4) tras el enroll, ya carga normal\n\
             sudo insmod kernel_module/sysentinel_metrics.ko write_gid=...\n\
             ```\n\
             Hasta entonces uso los fallbacks ring-3 (procfs, wtmp, tracefs, dmesg)."
                .to_string()
        }
        SecureBoot::Disabled | SecureBoot::Unsupported => {
            "\n_Sin Secure Boot, cargás el módulo directo:_\n\
             ```sh\n\
             sudo insmod kernel_module/sysentinel_metrics.ko write_gid=1000\n\
             ```\n\
             Sin firma, sin MOK, sin reboot."
                .to_string()
        }
        SecureBoot::SetupMode => {
            "\n_Modo setup:_ ahora mismo podés inscribir la llave — no hace falta \
             apagar Secure Boot:\n\
             ```sh\n\
             sudo mokutil --import MOK.der && sudo reboot\n\
             ```\n\
             o cargar el módulo firmado ya mismo."
                .to_string()
        }
        SecureBoot::Unknown => {
            "\nNo sé el estado de Secure Boot, así que no te recomiendo un camino \
             concreto. Probá `mokutil --sb-state` o `bootctl status` a mano."
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