// SPDX-License-Identifier: Apache-2.0
//!
//! Hardware inventory straight from `/proc` and `/sysfs` — the userspace
//! equivalent of `lscpu`, a PCI bus list, and (when an NVIDIA GPU exists)
//! an `nvidia-smi` snapshot. No `lspci`, no privileges, no shelling out
//! except for `nvidia-smi`, which only runs when the GPU is NVIDIA.

use std::collections::BTreeMap;
use std::fs;
use std::process::Command;

// ── CPU (lscpu-style) ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct CpuInfo {
    pub vendor: String,
    pub model_name: String,
    pub cores: u32,
    pub threads: u32,
    /// Does the CPU advertise virtualisation (vmx/svm)?
    pub has_virt: bool,
    /// Notable compute flags the persona/firmware doc cares about.
    pub notable_flags: Vec<String>,
    /// Current per-core MHz from /proc/cpuinfo (first line seen), if any.
    pub mhz: Option<f64>,
    /// `cpuinfo_max_freq` in kHz from cpufreq, if exposed.
    pub max_mhz: Option<u32>,
}

/// Parse `/proc/cpuinfo`. We only rely on fields that all x86 kernels emit.
pub fn cpu_info() -> CpuInfo {
    let raw = match fs::read_to_string("/proc/cpuinfo") {
        Ok(r) => r,
        Err(_) => return CpuInfo::default(),
    };

    let mut info = CpuInfo::default();
    let mut physical_ids = BTreeMap::new();
    let mut seen_flags = false;

    let mut mhz: Option<f64> = None;
    for line in raw.lines() {
        let Some((k, v)) = line.split_once(':') else { continue };
        let k = k.trim();
        let v = v.trim();
        match k {
            "vendor_id" if info.vendor.is_empty() => info.vendor = v.to_string(),
            "model name" if info.model_name.is_empty() => info.model_name = v.to_string(),
            "cpu MHz" if mhz.is_none() => mhz = v.parse().ok(),
            "physical id" => {
                if let Ok(id) = v.parse::<u32>() {
                    *physical_ids.entry(id).or_insert(0u32) += 1;
                }
            }
            "processor" => info.threads += 1,
            "flags" if !seen_flags => {
                seen_flags = true;
                info.has_virt = v.contains("vmx") || v.contains("svm");
                for f in ["avx512f", "avx2", "fma", "sse4_2", "sse4_1"] {
                    if v.split_whitespace().any(|x| x == f) {
                        info.notable_flags.push(f.to_string());
                    }
                }
            }
            _ => {}
        }
    }
    info.mhz = mhz;
    info.cores = physical_ids.values().sum();

    if let Ok(max_khz) = fs::read_to_string(
        "/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq",
    ) {
        info.max_mhz = max_khz.trim().parse::<u32>().ok().map(|k| k / 1000);
    }

    info
}

// ── PCI bus (sysfs) ───────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct PciSlot {
    /// domain:bus:device.function, e.g. "0000:00:02.0"
    pub addr: String,
    pub vendor: String,
    pub device: String,
    pub class: String,
    pub vendor_name: String,
    /// PCI class name if the top class is recognised (VGA, 3D, Network, …).
    pub class_name: Option<String>,
}

/// Read the kernel's own PCI tree from `/sys/bus/pci/devices/*`.
pub fn pci_list() -> Vec<PciSlot> {
    let mut slots = Vec::new();
    let Ok(entries) = fs::read_dir("/sys/bus/pci/devices") else {
        return slots;
    };
    for entry in entries.flatten() {
        let addr = entry.file_name().to_string_lossy().to_string();
        let base = entry.path();
        let vendor = read_hex(&base.join("vendor"));
        let device = read_hex(&base.join("device"));
        let class = read_hex(&base.join("class"));
        let (vendor_name, class_name) = classify_pci(&vendor, &class);
        slots.push(PciSlot {
            addr,
            vendor,
            device,
            class,
            vendor_name,
            class_name,
        });
    }
    slots.sort_by(|a, b| a.addr.cmp(&b.addr));
    slots
}

/// Which PCI devices expose a display controller (class 0x03 - all subclasses).
pub fn display_adapters(slots: &[PciSlot]) -> Vec<&PciSlot> {
    slots
        .iter()
        .filter(|s| s.class.starts_with("0x03"))
        .collect()
}

// ── GPU / nvidia-smi ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default)]
pub struct GpuInfo {
    /// Model name resolved from vendor ID (e.g. "Intel", "NVIDIA").
    pub vendor: String,
    pub vendor_id: String,
    pub device_id: String,
    /// Empty when no NVIDIA GPU is present.
    pub nvidia_smi: String,
}

/// Resolve the DRM-visible GPUs and, if any is NVIDIA, grab an `nvidia-smi`
/// one-line summary (name, memory, driver, utilisation) without installing
/// anything — the tool is only invoked when it already exists.
pub fn gpu_info() -> Vec<GpuInfo> {
    let mut gpus = Vec::new();
    let Ok(cards) = fs::read_dir("/sys/class/drm") else {
        return gpus;
    };
    let mut nvidia_present = false;
    let mut seen = std::collections::HashSet::new();

    for card in cards.flatten() {
        let name = card.file_name().to_string_lossy().to_string();
        if !name.starts_with("card") || name == "card0-DP-1" {
            continue;
        }
        // Skip connector links (cardX-*) and only take the card device node.
        if name.contains('-') && !name.starts_with("card") {
            continue;
        }
        if !name.starts_with("card") || name.len() != 5 || !name.as_bytes()[4].is_ascii_digit() {
            // handles card0, card1 … (links are card0-connector)
            continue;
        }
        let device = card.path().join("device");
        let vendor = read_hex(&device.join("vendor"));
        if vendor.is_empty() {
            continue;
        }
        let vendor_id = vendor;
        let device_id = read_hex(&device.join("device"));
        if !seen.insert((vendor_id.clone(), device_id.clone())) {
            continue;
        }
        if vendor_id == "0x10de" {
            nvidia_present = true;
        }
        gpus.push(GpuInfo {
            vendor: vendor_label(&vendor_id).to_string(),
            vendor_id,
            device_id,
            nvidia_smi: String::new(),
        });
    }

    if nvidia_present {
        if let Some(smi) = nvidia_smi_summary() {
            for g in &mut gpus {
                if g.vendor_id == "0x10de" {
                    g.nvidia_smi = smi.clone();
                }
            }
        }
    }

    gpus
}

/// One-line `nvidia-smi` output: name, memory.total, driver_version, util.
fn nvidia_smi_summary() -> Option<String> {
    let out = Command::new("nvidia-smi")
        .args([
            "--query-gpu=name,memory.total,driver_version,utilization.gpu",
            "--format=csv,noheader,nounits",
        ])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    String::from_utf8(out.stdout)
        .ok()
        .map(|s| s.trim().to_string())
}

// ── helpers ──────────────────────────────────────────────────────────────────

fn read_hex(path: &std::path::Path) -> String {
    fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().trim_start_matches("0x").to_string())
        .filter(|s| !s.is_empty())
        .map(|s| format!("0x{pad}{s}", pad = "0000".to_string().chars().take(0).collect::<String>()))
        .map(|s| if s.len() - 2 < 4 { format!("0x{:0>4}", &s[2..]) } else { s })
        .unwrap_or_default()
}

fn classify_pci(vendor: &str, class: &str) -> (String, Option<String>) {
    let vendor_name = vendor_label(vendor).to_string();
    let class_name_str: Option<String> = match class.get(2..4) {
        Some("03") => Some(match class.get(4..6) {
            Some("00") => "VGA compatible controller".into(),
            Some("01") => "XGA compatible controller".into(),
            Some("02") => "3D controller".into(),
            _ => "Display controller".into(),
        }),
        Some("02") => Some("Network controller".into()),
        Some("01") => Some("Mass storage".into()),
        Some("06") => Some("Bridge".into()),
        Some("04") => Some("Multimedia audio".into()),
        Some("0c") => Some("Serial bus".into()),
        _ => {
            let top = class.get(0..2).unwrap_or("");
            match top {
                "03" => Some("Display controller".into()),
                "02" => Some("Network controller".into()),
                "01" => Some("Mass storage".into()),
                "06" => Some("Bridge".into()),
                "04" => Some("Multimedia audio".into()),
                "0c" => Some("Serial bus".into()),
                "00" => Some("Non-VGA unclassified".into()),
                _ => None,
            }
        }
    };
    (vendor_name, class_name_str)
}

fn vendor_label(vendor: &str) -> &'static str {
    match vendor.get(2..6) {
        Some("8086") => "Intel",
        Some("10de") => "NVIDIA",
        Some("1002") => "AMD",
        Some("1022") => "AMD",
        Some("8088") => "Loongson",
        Some("1d0f") => "Amazon",
        Some("14e4") => "Broadcom",
        Some("8087") => "Intel",
        Some("168c") => "Qualcomm",
        Some("10ec") => "Realtek",
        Some("1b73") => "Fresco Logic",
        Some("1b4b") => "Marvell",
        _ => "Unknown",
    }
}

/// Compact single-message hardware report for `/hardware`.
pub fn hardware_report() -> String {
    let mut out = String::new();
    let cpu = cpu_info();
    out.push_str("🖥 *CPU*\n");
    out.push_str(&format!("  vendor: {}\n", if cpu.vendor.is_empty() { "?" } else { &cpu.vendor }));
    out.push_str(&format!("  model: {}\n", if cpu.model_name.is_empty() { "?" } else { &cpu.model_name }));
    out.push_str(&format!("  okayed: {} cores / {} threads\n", cpu.cores, cpu.threads));
    if let Some(m) = cpu.mhz {
        out.push_str(&format!("  clock: {m:.0} MHz\n"));
    }
    if let Some(m) = cpu.max_mhz {
        out.push_str(&format!("  max: {m} MHz\n"));
    }
    out.push_str(&format!(
        "  virt: {} | flags: {}\n",
        if cpu.has_virt { "vmx/svm ✓" } else { "no" },
        if cpu.notable_flags.is_empty() { "none".to_string() } else { cpu.notable_flags.join(",") }
    ));

    let tsc = crate::procinfo::tsc_status();
    out.push_str(&format!(
        "  tsc/rdtscp: {} MHz measured (nominal {} MHz) — {}\n",
        (tsc.measured_khz / 1000.0) as u64,
        tsc.nominal_khz / 1000,
        if tsc.stable { "stable" } else { "⚠ drifting/unstable" }
    ));

    let gpus = gpu_info();
    out.push_str("\n🎨 *GPU*\n");
    if gpus.is_empty() {
        out.push_str("  none detected\n");
    } else {
        for g in &gpus {
            out.push_str(&format!("  {} ({}:{})\n", g.vendor, g.vendor_id, g.device_id));
            if !g.nvidia_smi.is_empty() {
                out.push_str("  nvidia-smi: ");
                for part in g.nvidia_smi.split(',') {
                    out.push_str(part.trim());
                    out.push_str(" | ");
                }
                out.pop();
                out.pop();
                out.push('\n');
            }
        }
    }

    let slots = pci_list();
    out.push_str("\n🔌 *PCI bus*\n");
    let adapters = display_adapters(&slots);
    if adapters.is_empty() {
        out.push_str("  (no display adapters found — no GPU?)\n");
    }
    for slot in slots.iter().take(24) {
        out.push_str(&format!(
            "  {} {}:{} {} {}\n",
            slot.addr,
            slot.vendor,
            slot.device,
            slot.vendor_name,
            slot.class_name.as_deref().unwrap_or("")
        ));
    }
    if slots.len() > 24 {
        out.push_str(&format!("  … {} more PCI devices\n", slots.len() - 24));
    }

    out
}

/// Human-friendly summary for `/pci` listing display adapters specifically.
pub fn display_report() -> String {
    let slots = pci_list();
    let adapters = display_adapters(&slots);
    if adapters.is_empty() {
        return "No graphics adapter on this machine 😔".to_string();
    }
    let mut out = String::from("🎨 *Adaptadores graficos (PCI class 0x03):*\n");
    for a in &adapters {
        out.push_str(&format!(
            "  {} {}:{} — {}\n",
            a.addr,
            a.vendor,
            a.device,
            a.class_name.as_deref().unwrap_or("display")
        ));
    }
    out
}

// ── lsblk / lsusb / lsmod ─────────────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct BlockDev {
    pub name: String,
    /// Size in bytes (sectors × 512).
    pub bytes: u64,
    /// "hdd", "ssd", "nvme", "zram", "loop", "md", "other"
    pub kind: &'static str,
    pub partitions: u32,
}

/// lsblk-style top-level block devices from `/sys/block/*`.
pub fn block_devices() -> Vec<BlockDev> {
    let mut devs = Vec::new();
    let Ok(entries) = fs::read_dir("/sys/block") else { return devs };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let base = entry.path();

        let bytes = fs::read_to_string(base.join("size"))
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .map(|sectors| sectors * 512)
            .unwrap_or(0);

        let kind = if name.starts_with("loop") {
            "loop"
        } else if name.starts_with("zram") {
            "zram"
        } else if name.starts_with("nvme") {
            "nvme"
        } else if name.starts_with("md") {
            "md"
        } else if fs::read_to_string(base.join("queue/rotational"))
            .ok()
            .and_then(|s| s.trim().parse::<u8>().ok())
            == Some(1)
        {
            "hdd"
        } else if name.starts_with("dm-") || name.starts_with("sr") {
            "other"
        } else {
            "ssd"
        };

        let partitions = fs::read_dir(&base)
            .map(|d| {
                d.flatten()
                    .filter(|e| {
                        let n = e.file_name().to_string_lossy().to_string();
                        n.starts_with(&name) && n.len() > name.len()
                            && n[name.len()..].bytes().all(|b| b.is_ascii_digit())
                    })
                    .count()
            })
            .unwrap_or(0);

        devs.push(BlockDev { name, bytes, kind, partitions: partitions as u32 });
    }
    devs.sort_by(|a, b| a.name.cmp(&b.name));
    devs
}

#[derive(Debug, Clone)]
pub struct UsbDev {
    pub path: String,
    pub vendor: String,
    pub product: String,
    pub vendor_name: String,
}

/// lsusb-style tree leaves from `/sys/bus/usb/devices`.
pub fn usb_devices() -> Vec<UsbDev> {
    let mut devs = Vec::new();
    let Ok(entries) = fs::read_dir("/sys/bus/usb/devices") else { return devs };
    for entry in entries.flatten() {
        let path = entry.file_name().to_string_lossy().to_string();
        let base = entry.path();
        // Interface dirs ("1-1:1.0") duplicate their parent's vendor data.
        if path.contains(':') {
            continue;
        }
        let vendor_id = read_hex(&base.join("idVendor"));
        let product_id = read_hex(&base.join("idProduct"));
        if vendor_id.is_empty() && product_id.is_empty() {
            continue;
        }
        let product = fs::read_to_string(base.join("product"))
            .unwrap_or_default()
            .trim()
            .to_string();
        devs.push(UsbDev {
            vendor: vendor_id.clone(),
            product,
            vendor_name: usb_vendor_label(&vendor_id).to_string(),
            path,
        });
    }
    devs.sort_by(|a, b| a.path.cmp(&b.path));
    devs
}

fn usb_vendor_label(vendor: &str) -> &'static str {
    match vendor.get(2..6) {
        Some("8087") => "Intel",
        Some("1058") => "Western Digital",
        Some("0781") => "SanDisk",
        Some("0951") => "Kingston",
        Some("04f2") => "Chicony",
        Some("046d") => "Logitech",
        Some("1d6b") => "Linux (root hub)",
        Some("0cf3") => "Qualcomm Atheros",
        Some("8086") => "Intel",
        Some("2ce3") => "GPD",
        Some("06cb") => "Synaptics",
        Some("24ae") => "Rapoo",
        _ => "USB",
    }
}

/// lsmod-style module table from `/proc/modules`.
pub fn modules() -> Vec<(String, u64, String)> {
    // (name, size_bytes, used_by_summary)
    let mut out = Vec::new();
    let Ok(raw) = fs::read_to_string("/proc/modules") else { return out };
    for line in raw.lines() {
        let mut it = line.split_whitespace();
        let Some(name) = it.next() else { continue };
        let size: u64 = it.next().and_then(|s| s.parse().ok()).unwrap_or(0);
        let used_by: Vec<&str> = it
            .skip(2) // skip refcount and "-" (usage list terminator)
            .take_while(|w| *w != "-")
            .collect();
        out.push((name.to_string(), size, used_by.join(", ")));
    }
    out.sort();
    out
}

fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "K", "M", "G", "T", "P"];
    let mut v = bytes as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    format!("{v:.1}{}", UNITS[u])
}

/// `/lsblk` report.
pub fn block_report() -> String {
    let devs = block_devices();
    if devs.is_empty() {
        return "No block devices 😕".to_string();
    }
    let mut out = String::from("💾 *lsblk*\n");
    for d in &devs {
        out.push_str(&format!(
            "  `{}` {} [{}] ({} part)\n",
            d.name,
            human_size(d.bytes),
            d.kind,
            d.partitions
        ));
    }
    out
}

/// `/lsusb` report.
pub fn usb_report() -> String {
    let devs = usb_devices();
    if devs.is_empty() {
        return "No USB devices 😕".to_string();
    }
    let mut out = String::from("🔌 *lsusb*\n");
    for d in devs.iter().take(30) {
        let extra = if d.product.is_empty() { String::new() } else { format!(" — {}", d.product) };
        out.push_str(&format!("  `{}` {}:{}{}\n", d.path, d.vendor, d.vendor_name, extra));
    }
    if devs.len() > 30 {
        out.push_str(&format!("  … {} more USB devices\n", devs.len() - 30));
    }
    out
}

/// `/lsmod` report.
pub fn modules_report() -> String {
    let mods = modules();
    if mods.is_empty() {
        return "No modules 🫥".to_string();
    }
    let mut out = String::from("🧩 *lsmod* (");
    out.push_str(&mods.len().to_string());
    out.push_str(")\n");
    for (name, size, used_by) in mods.iter().take(24) {
        out.push_str(&format!("  `{name}` {}K", size / 1024));
        if !used_by.is_empty() {
            out.push_str(&format!(" (used: {used_by})"));
        }
        out.push('\n');
    }
    if mods.len() > 24 {
        out.push_str(&format!("  … {} more modules\n", mods.len() - 24));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cpu_info_reads_this_machine() {
        let c = cpu_info();
        assert!(!c.model_name.is_empty());
        assert!(c.threads > 0);
    }

    #[test]
    fn pci_list_reads_this_machine() {
        let slots = pci_list();
        assert!(!slots.is_empty());
        assert!(slots.iter().all(|s| !s.addr.is_empty()));
    }

    #[test]
    fn pci_class_labelling() {
        let (v, c) = classify_pci("0x8086", "0x030000");
        assert_eq!(v, "Intel");
        assert_eq!(c.unwrap(), "VGA compatible controller");

        let (v, c) = classify_pci("0x10de", "0x030200");
        assert_eq!(v, "NVIDIA");
        assert_eq!(c.unwrap(), "3D controller");
    }

    #[test]
    fn disk_report_never_panics() {
        let r = block_report();
        assert!(r.contains("lsblk"));
    }

    #[test]
    fn usb_and_modules_reports_never_panic() {
        // Reports render whatever this machine exposes; empty is fine.
        let _ = usb_report();
        let m = modules_report();
        assert!(m.contains("lsmod"));
    }
}