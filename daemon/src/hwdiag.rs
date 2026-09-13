// SPDX-License-Identifier: Apache-2.0
//!
//! Hardware diagnostics summariser.
//!
//! Aggregates:
//! - Temperature, fan, and voltage data from `sensors -j` (lm-sensors).
//! - Public PCI device list from `/sys/bus/pci/devices`.
//! - Intel ME / AMD PSP firmware version (via `mei::query_firmware_status()`).
//! - PMU counters (via `pmu::quick_snapshot()`), when enabled in config.
//!
//! All data sources here are either world-readable sysfs files or standard
//! userspace tools. No ring-0 access and no raw PCI configuration-space reads
//! beyond what the kernel already publishes in sysfs.

use crate::config::Config;
use crate::mei;
use crate::pmu;
use anyhow::{Context, Result};
use std::fs;
use std::path::Path;
use std::process::Command;

// ── lm-sensors ───────────────────────────────────────────────────────────────

/// Run `sensors -j` and return its raw JSON output.
///
/// Returns `Ok(None)` if `sensors` is not installed — hardware diagnostics
/// are optional and best-effort.
pub fn read_sensors_json() -> Result<Option<String>> {
    let output = match Command::new("sensors").arg("-j").output() {
        Ok(o)  => o,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).context("spawning `sensors -j`"),
    };

    if !output.status.success() {
        log::warn!(
            "`sensors -j` exited {:?}; temperature data will be absent",
            output.status.code()
        );
        return Ok(None);
    }

    Ok(Some(String::from_utf8_lossy(&output.stdout).into_owned()))
}

// ── PCI device list ───────────────────────────────────────────────────────────

/// A single PCI device summary sourced from sysfs (equivalent to `lspci -n`).
#[derive(Debug, Clone)]
pub struct PciDeviceSummary {
    pub address:   String,
    pub vendor_id: String,
    pub device_id: String,
    pub class:     String,
}

/// Enumerate PCI devices via `/sys/bus/pci/devices`. No raw config-space reads.
pub fn list_pci_devices() -> Result<Vec<PciDeviceSummary>> {
    let root = Path::new("/sys/bus/pci/devices");
    if !root.exists() {
        return Ok(Vec::new());
    }

    let mut devices = Vec::new();
    for entry in fs::read_dir(root).context("reading /sys/bus/pci/devices")? {
        let entry = entry?;
        let path  = entry.path();
        let address = entry.file_name().to_string_lossy().into_owned();

        let vendor_id = read_trimmed(&path.join("vendor")).unwrap_or_default();
        let device_id = read_trimmed(&path.join("device")).unwrap_or_default();
        let class     = read_trimmed(&path.join("class")).unwrap_or_default();

        devices.push(PciDeviceSummary { address, vendor_id, device_id, class });
    }

    devices.sort_by(|a, b| a.address.cmp(&b.address));
    Ok(devices)
}

fn read_trimmed(path: &Path) -> Option<String> {
    fs::read_to_string(path).ok().map(|s| s.trim().to_string())
}

// ── Public summarise function ─────────────────────────────────────────────────

/// Build a human-readable diagnostics summary.
///
/// The summary is designed to be both sent directly to the phone (wrapped in
/// a code block) and passed to the LLM backend for annotation.
pub fn summarize(config: &Config) -> Result<String> {
    let mut out = String::new();

    // ── Temperature / fan / voltage ───────────────────────────────────────────
    match read_sensors_json()? {
        Some(json) => {
            out.push_str("=== sensors -j ===\n");
            out.push_str(&json);
            out.push('\n');
        }
        None => out.push_str("(lm-sensors not installed; skipping temperature/fan data)\n"),
    }

    // ── PCI device count ──────────────────────────────────────────────────────
    let pci = list_pci_devices()?;
    out.push_str(&format!("\n=== PCI devices ({} total) ===\n", pci.len()));
    // Only list interesting device classes (GPU, NIC, storage).
    for dev in pci.iter().filter(|d| is_notable_class(&d.class)) {
        out.push_str(&format!(
            "  {} vendor={} device={} class={}\n",
            dev.address, dev.vendor_id, dev.device_id, dev.class
        ));
    }

    // ── Intel ME / AMD PSP firmware ───────────────────────────────────────────
    if config.hwdiag.include_firmware {
        let fw = mei::query_firmware_status();
        out.push_str("\n=== Firmware status ===\n");
        out.push_str(&format!("{fw}"));
    }

    // ── PMU counters ──────────────────────────────────────────────────────────
    if config.pmu.enabled {
        let snap = pmu::snapshot(std::time::Duration::from_millis(config.pmu.sample_ms));
        out.push_str("\n=== PMU counters ===\n");
        out.push_str(&snap.to_context_string());
    }

    Ok(out)
}

/// Returns true for PCI device classes likely to be interesting in a diagnostic.
fn is_notable_class(class: &str) -> bool {
    // Class codes are 6-hex-digit strings like "0x030200" (Display Controller).
    let notable_prefixes = [
        "0x0300", // Display: VGA controller
        "0x0200", // Network: Ethernet
        "0x0280", // Network: Wireless
        "0x0100", // Storage: SCSI
        "0x0101", // Storage: IDE
        "0x0106", // Storage: SATA (AHCI)
        "0x0108", // Storage: NVMe
        "0x0800", // System: IRQ / PIC
        "0x0604", // Bridge: PCIe
    ];
    notable_prefixes.iter().any(|p| class.starts_with(p))
}
