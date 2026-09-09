// SPDX-License-Identifier: Apache-2.0
//!
//! Undervolt/overvolt truth — the persona must NEVER claim a V/F curve shift
//! that isn't actually there. This module checks, per CPU vendor, whether an
//! undervolt (or overvolt) is really applied and returns an honest verdict.
//!
//! # Signal sources (best-effort, all userspace)
//!
//! * **Intel** — `intel-undervolt read` (reads MSR 0x150 OC mailbox) is the
//!   ground truth; falls back to `/etc/intel-undervolt.conf` when the service
//!   is enabled; absent tooling ⇒ stock.
//! * **AMD**  — Curve Optimizer lives in SMU/BIOS and is not readable from
//!   Linux; no active undervolt is verifiable userspace ⇒ stock (honest).
//! * **Zhaoxin** — no mainstream undervolt support ⇒ stock.
//!
//! Only *positive evidence* ever flips the state to `Active`. Anything else
//! reads as `Inactive` (the machine is at stock unless proven otherwise).

use std::path::Path;
use std::process::Command;

/// What the machine is actually doing with its V/F curve.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UndervoltStatus {
    /// A non-zero offset is applied (undervolt **or** overvolt).
    Active,
    /// No active offset found — the CPU runs at stock.
    Inactive,
    /// A mechanism exists but we couldn't confirm whether it applied.
    Unknown,
}

impl UndervoltStatus {
    /// True only when positive evidence of a shift exists.
    pub fn is_active(&self) -> bool {
        matches!(self, UndervoltStatus::Active)
    }
}

/// `vendor_id` from `/proc/cpuinfo` (first CPU).
pub fn cpu_vendor_id() -> Option<String> {
    let raw = std::fs::read_to_string("/proc/cpuinfo").ok()?;
    raw.lines().find_map(|l| {
        let mut it = l.splitn(2, ':');
        if it.next().map(str::trim) == Some("vendor_id") {
            Some(it.next().map(str::trim).unwrap_or("").to_string())
        } else {
            None
        }
    })
}

/// Honest verdict for the current CPU.
pub fn status() -> UndervoltStatus {
    match cpu_vendor_id().as_deref() {
        Some("GenuineIntel") => intel_status(),
        Some("AuthenticAMD" | "HygonGenuine") => amd_status(),
        Some("CentaurHauls" | "Zhaoxin") => zhaoxin_status(),
        _ => UndervoltStatus::Unknown,
    }
}

fn intel_status() -> UndervoltStatus {
    // Ground truth: apply-time offsets read straight from the OC mailbox.
    if let Ok(out) = Command::new("intel-undervolt").arg("read").output() {
        if out.status.success() {
            let text = String::from_utf8_lossy(&out.stdout).into_owned();
            return offsets_verdict(&text);
        }
    }

    // Fallback: configured at boot via the intel-undervolt systemd service.
    let conf = Path::new("/etc/intel-undervolt.conf");
    if conf.exists() {
        let raw = std::fs::read_to_string(conf).unwrap_or_default();
        let nonzero = any_nonzero_offset(&raw) || has_percent_offset(&raw);
        if !nonzero {
            return UndervoltStatus::Inactive;
        }
        // Configured but is it actually applied? Ask systemd.
        let enabled = Command::new("systemctl")
            .args(["is-enabled", "intel-undervolt"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        return if enabled {
            UndervoltStatus::Active
        } else {
            UndervoltStatus::Unknown
        };
    }

    // No tooling configured on this machine → stock.
    UndervoltStatus::Inactive
}

fn amd_status() -> UndervoltStatus {
    // Curve Optimizer / overvolt lives in the SMU; not readable from Linux.
    // False positive alert: claiming undervolt here IS the hallucination the
    // persona must avoid. Stock unless proven otherwise.
    UndervoltStatus::Inactive
}

fn zhaoxin_status() -> UndervoltStatus {
    UndervoltStatus::Inactive
}

/// Offsets verdict from `intel-undervolt read` text (`cpu: -80 mV`, …). Any
/// non-zero signed millivolt → active (positive = overvolt, negative =
/// undervolt). No numbers or all-zero → stock.
fn offsets_verdict(text: &str) -> UndervoltStatus {
    let mut saw_number = false;
    for line in text.lines() {
        for tok in line.split_whitespace() {
            let cleaned = tok.trim_end_matches(|c| matches!(c, 'm' | 'M' | 'v' | 'V'));
            let Ok(n): Result<i64, _> = cleaned.parse() else {
                continue;
            };
            saw_number = true;
            if n != 0 {
                return UndervoltStatus::Active;
            }
        }
    }
    if saw_number {
        UndervoltStatus::Inactive
    } else {
        UndervoltStatus::Unknown
    }
}

/// `intel-undervolt.conf` values (millivolts with optional +/- sign).
fn any_nonzero_offset(conf: &str) -> bool {
    parse_signed_values(conf).any(|n| n != 0)
}

/// Some versions configure offsets as percentages (e.g. `gpu -15%`); a non-zero
/// percent also means a shift is in place.
fn has_percent_offset(conf: &str) -> bool {
    conf.lines().any(|l| {
        let Some(percent) = l.find('%') else {
            return false;
        };
        l[..percent]
            .split(|c: char| !(c.is_ascii_digit() || c == '-' || c == '+' || c == '.'))
            .filter_map(|t| t.parse::<f64>().ok())
            .last()
            .map(|n| n != 0.0)
            .unwrap_or(false)
    })
}

fn parse_signed_values(text: &str) -> impl Iterator<Item = i64> + '_ {
    text.split(|c: char| !(c.is_ascii_digit() || c == '-' || c == '+'))
        .filter_map(|s| s.parse::<i64>().ok())
}

/// One honest sentence answering "is there a real undervolt/overvolt?".
pub fn describe() -> String {
    let vendor = cpu_vendor_id().unwrap_or_else(|| "?".to_string());
    match status() {
        UndervoltStatus::Active => {
            format!("Yes — a V/F offset is **active** (`{vendor}`); undervolt or overvolt depending on the sign.")
        }
        UndervoltStatus::Inactive => match vendor.as_str() {
            "AuthenticAMD" | "HygonGenuine" => {
                "No verified undervolt/overvolt is active. On AMD, the Curve \
                 Optimizer is set in BIOS/SMU and isn't visible from Linux, \
                 so without positive evidence your CPU runs stock."
                    .to_string()
            }
            "CentaurHauls" | "Zhaoxin" => {
                "No — Zhaoxin doesn't expose V/F offsets; your CPU runs stock."
                    .to_string()
            }
            "GenuineIntel" => {
                "No — no intel-undervolt active (nor offsets in `/etc/intel-undervolt.conf` \
                 with the service applied). Intel runs stock."
                    .to_string()
            }
            _ => "No evidence of an active undervolt/overvolt; the CPU runs stock.".to_string(),
        },
        UndervoltStatus::Unknown => {
            "I couldn't verify the V/F curve state with certainty (there's a \
             `/etc/intel-undervolt.conf` config but the service isn't \
             enabled). I won't affirm anything."
                .to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn intel_undervolt_read_active() {
        let out = "cpu: -100 mV\ncache: -100 mV\nuncore: 0 mV\nanalogio: 0 mV\ngpu: -80 mV\n";
        assert_eq!(offsets_verdict(out), UndervoltStatus::Active);
    }

    #[test]
    fn intel_undervolt_read_overvolt_active() {
        let out = "cpu: +50 mV\ncache: 0 mV\n";
        assert_eq!(offsets_verdict(out), UndervoltStatus::Active);
    }

    #[test]
    fn intel_undervolt_read_stock() {
        let out = "cpu: 0 mV\ncache: 0 mV\nuncore: 0 mV\n";
        assert_eq!(offsets_verdict(out), UndervoltStatus::Inactive);
    }

    #[test]
    fn intel_undervolt_read_no_numbers() {
        assert_eq!(offsets_verdict("command not applicable\n"), UndervoltStatus::Unknown);
    }

    #[test]
    fn conf_nonzero_millivolts() {
        assert!(any_nonzero_offset("cpu -120 -120 -120 -120\n"));
        assert!(!any_nonzero_offset("cpu 0 0 0 0\ncache 0\n"));
        assert!(any_nonzero_offset("key gpu -80 0 0 0\n"));
    }

    #[test]
    fn conf_percent_offset() {
        assert!(has_percent_offset("gpu -15%\n"));
        assert!(has_percent_offset("[UNDERVOLT]\ncpu -20 %\n"));
        assert!(!has_percent_offset("gpu 0%\n"));
        assert!(!has_percent_offset("cpu -100\n"));
    }

    #[test]
    fn amd_and_zhaoxin_never_fabricate() {
        // AMD / Zhaoxin are not readable from Linux → honest stock, never Active.
        assert_eq!(amd_status(), UndervoltStatus::Inactive);
        assert_eq!(zhaoxin_status(), UndervoltStatus::Inactive);
    }
}