// SPDX-License-Identifier: Apache-2.0
//! Hardware snapshot builder for the `/evidence list` JSON response.
//!
//! All probes are best-effort: a missing sysfs entry returns zero/empty rather
//! than an error so the evidence JSON is always complete and parseable.

use std::fs;

// ── CPU ───────────────────────────────────────────────────────────────────────

struct FullCpuInfo {
    vendor:         String,
    model_name:     String,
    physical_cores: u32,
    logical_cores:  u32,
    ghz:            f64,
    flags:          Vec<String>,
    microcode:      String,
    vm_hypervisor:  String,
}

fn read_full_cpu() -> FullCpuInfo {
    let raw = fs::read_to_string("/proc/cpuinfo").unwrap_or_default();

    let mut vendor       = String::new();
    let mut model_name   = String::new();
    let mut logical      = 0u32;
    let mut cpu_cores    = 0u32;  // "cpu cores" field = physical per socket
    let mut flags        = Vec::new();
    let mut mhz          = 0.0f64;
    let mut flags_read   = false;
    let mut cpu_cores_seen = false;
    let mut is_vm        = false;

    for line in raw.lines() {
        let Some((k, v)) = line.split_once(':') else { continue };
        let k = k.trim();
        let v = v.trim();
        match k {
            "vendor_id"  if vendor.is_empty()      => vendor     = v.to_string(),
            "model name" if model_name.is_empty()  => model_name = v.to_string(),
            "processor"                            => logical    += 1,
            "cpu cores"  if !cpu_cores_seen        => {
                cpu_cores_seen = true;
                cpu_cores = v.parse().unwrap_or(0);
            }
            "cpu MHz"    if mhz == 0.0             => mhz        = v.parse().unwrap_or(0.0),
            "flags"      if !flags_read            => {
                flags_read = true;
                for f in v.split_whitespace() {
                    flags.push(f.to_string());
                    if f == "hypervisor" { is_vm = true; }
                }
            }
            _ => {}
        }
    }

    let max_mhz: f64 = fs::read_to_string(
        "/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq",
    )
    .ok()
    .and_then(|s| s.trim().parse::<f64>().ok())
    .map(|k| k / 1000.0)   // kHz → MHz
    .unwrap_or(0.0);

    let ghz = if max_mhz > 0.0 { max_mhz / 1000.0 } else { mhz / 1000.0 };

    let microcode = fs::read_to_string(
        "/sys/devices/system/cpu/cpu0/microcode/version",
    )
    .unwrap_or_default()
    .trim()
    .to_string();

    let vm_hypervisor = if is_vm {
        detect_hypervisor().unwrap_or_else(|| "unknown".to_string())
    } else {
        String::new()
    };

    // physical_cores: "cpu cores" × sockets; if unavailable fall back to logical.
    let physical_cores = if cpu_cores > 0 { cpu_cores } else { logical };

    FullCpuInfo {
        vendor,
        model_name,
        physical_cores,
        logical_cores: logical,
        ghz,
        flags,
        microcode,
        vm_hypervisor,
    }
}

#[cfg(target_arch = "x86_64")]
fn detect_hypervisor() -> Option<String> {
    let res = unsafe { std::arch::x86_64::__cpuid(0x4000_0000) };
    let mut b = [0u8; 12];
    b[0..4].copy_from_slice(&res.ebx.to_le_bytes());
    b[4..8].copy_from_slice(&res.ecx.to_le_bytes());
    b[8..12].copy_from_slice(&res.edx.to_le_bytes());
    let v = std::str::from_utf8(&b).ok()?.trim_end_matches('\0').trim().to_string();
    if v.is_empty() { return None; }
    Some(match v.as_str() {
        "KVMKVMKVM"    => "KVM".to_string(),
        "VMwareVMware" => "VMware".to_string(),
        "VBoxVBoxVBox" => "VirtualBox".to_string(),
        "Microsoft Hv" => "Hyper-V".to_string(),
        "XenVMMXenVMM" => "Xen".to_string(),
        _              => v,
    })
}

#[cfg(not(target_arch = "x86_64"))]
fn detect_hypervisor() -> Option<String> { None }

// ── RAM ───────────────────────────────────────────────────────────────────────

fn ram_total_bytes() -> u64 {
    let raw = fs::read_to_string("/proc/meminfo").unwrap_or_default();
    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix("MemTotal:") {
            if let Some(kb) = rest.trim().split_whitespace().next() {
                return kb.parse::<u64>().unwrap_or(0) * 1024;
            }
        }
    }
    0
}

// ── Disks ─────────────────────────────────────────────────────────────────────

struct DiskInfo {
    model:   String,
    vendor:  String,
    size:    u64,
    fs_type: String,
    smart:   String,
}

fn disk_info() -> Vec<DiskInfo> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir("/sys/block") else { return out };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with("loop") || name.starts_with("zram") ||
           name.starts_with("dm-")  || name.starts_with("ram")  ||
           name.starts_with("sr")   || name.starts_with("fd")    { continue; }

        let base = entry.path();
        let size = fs::read_to_string(base.join("size"))
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .map(|s| s * 512)
            .unwrap_or(0);
        if size == 0 { continue; }

        let model  = fs::read_to_string(base.join("device/model"))
            .unwrap_or_default().trim().to_string();
        let vendor = fs::read_to_string(base.join("device/vendor"))
            .unwrap_or_default().trim().to_string();
        let fs_type = detect_fs_for(&name);
        let smart   = smart_status_for(&name);

        out.push(DiskInfo { model, vendor, size, fs_type, smart });
    }
    out
}

fn detect_fs_for(dev_name: &str) -> String {
    let raw = fs::read_to_string("/proc/mounts").unwrap_or_default();
    for line in raw.lines() {
        let mut parts = line.split_whitespace();
        let dev  = parts.next().unwrap_or("").trim_start_matches("/dev/");
        let _mnt = parts.next();
        let fs   = parts.next().unwrap_or("");
        if dev.starts_with(dev_name) && !fs.is_empty() {
            return fs.to_string();
        }
    }
    String::new()
}

fn smart_status_for(dev_name: &str) -> String {
    let dev = format!("/dev/{dev_name}");
    match std::process::Command::new("smartctl").args(["-H", &dev]).output() {
        Ok(o) => {
            let s = String::from_utf8_lossy(&o.stdout);
            if s.contains("PASSED") { "PASSED".to_string() }
            else if s.contains("FAILED!") { "FAILED".to_string() }
            else { "N/A".to_string() }
        }
        Err(_) => "N/A".to_string(),
    }
}

// ── GPU ───────────────────────────────────────────────────────────────────────

struct GpuInfo {
    vendor: String,
    model:  String,
    vram:   u64,
    arch:   String,
}

fn gpu_info() -> Vec<GpuInfo> {
    let base = crate::hwinfo::gpu_info();
    let mut out = Vec::new();
    let Ok(cards) = fs::read_dir("/sys/class/drm") else {
        return base.iter().map(|g| GpuInfo {
            vendor: g.vendor.clone(),
            model:  g.nvidia_smi.lines().next().unwrap_or("").to_string(),
            vram:   0,
            arch:   String::new(),
        }).collect();
    };

    let mut idx = 0usize;
    let mut seen = std::collections::HashSet::new();
    for card in cards.flatten() {
        let cname = card.file_name().to_string_lossy().to_string();
        // card0, card1 — skip connector links like card0-DP-1
        if !cname.starts_with("card") || cname.contains('-') { continue; }
        if cname.len() < 5 || !cname.as_bytes()[4].is_ascii_digit() { continue; }

        let device = card.path().join("device");
        let vid = fs::read_to_string(device.join("vendor"))
            .unwrap_or_default().trim().to_string();
        if vid.is_empty() { continue; }
        let did = fs::read_to_string(device.join("device"))
            .unwrap_or_default().trim().to_string();
        if !seen.insert((vid.clone(), did)) { continue; }

        // VRAM: AMD exposes mem_info_vram_total; Intel/NVIDIA don't in sysfs
        let vram = fs::read_to_string(device.join("mem_info_vram_total"))
            .ok()
            .and_then(|s| s.trim().parse::<u64>().ok())
            .unwrap_or(0);

        let vendor = match vid.as_str() {
            "0x10de" => "NVIDIA",
            "0x1002" => "AMD",
            "0x8086" => "Intel",
            _        => "unknown",
        };

        let model = base.get(idx)
            .map(|g| if !g.nvidia_smi.is_empty() {
                g.nvidia_smi.lines().next().unwrap_or("").to_string()
            } else { String::new() })
            .unwrap_or_default();

        out.push(GpuInfo { vendor: vendor.to_string(), model, vram, arch: String::new() });
        idx += 1;
    }

    if out.is_empty() {
        out = base.iter().map(|g| GpuInfo {
            vendor: g.vendor.clone(),
            model:  g.nvidia_smi.lines().next().unwrap_or("").to_string(),
            vram:   0,
            arch:   String::new(),
        }).collect();
    }
    out
}

// ── JSON helpers ──────────────────────────────────────────────────────────────

fn je(s: &str) -> String { s.replace('\\', "\\\\").replace('"', "\\\"") }

// ── Public interface ──────────────────────────────────────────────────────────

/// Build the full hardware snapshot JSON object string (no surrounding array).
///
/// Returns a `{…}` JSON object that matches the `HardwareSnapshot` model on the
/// Android side (`MultimediaScreen.kt` → `parseHw`).
pub fn hw_snapshot_json() -> String {
    let cpu  = read_full_cpu();
    let ram  = ram_total_bytes();
    let disks = disk_info();
    let gpus  = gpu_info();
    let tpm   = crate::tpmkey::tpm_present();
    let sb    = crate::secureboot::status();
    let fw    = crate::mei::query_firmware_status();
    let (hw_gp, hw_fixed) = crate::pmu::hw_counter_count();

    let flags_json: String = {
        let quoted: Vec<String> = cpu.flags.iter()
            .map(|f| format!("\"{}\"", je(f)))
            .collect();
        format!("[{}]", quoted.join(","))
    };

    let disks_json: String = {
        let items: Vec<String> = disks.iter().map(|d| format!(
            "{{\"model\":\"{}\",\"vendor\":\"{}\",\"size_bytes\":{},\
             \"filesystem\":\"{}\",\"smart_status\":\"{}\"}}",
            je(&d.model), je(&d.vendor), d.size, je(&d.fs_type), je(&d.smart),
        )).collect();
        format!("[{}]", items.join(","))
    };

    let gpus_json: String = {
        let items: Vec<String> = gpus.iter().map(|g| format!(
            "{{\"vendor\":\"{}\",\"model\":\"{}\",\"vram_bytes\":{},\"architecture\":\"{}\"}}",
            je(&g.vendor), je(&g.model), g.vram, je(&g.arch),
        )).collect();
        format!("[{}]", items.join(","))
    };

    let mei_fw = fw.intel_me.as_ref()
        .map(|v| v.to_string())
        .unwrap_or_default();
    let psp_fw = fw.amd_psp.as_deref().unwrap_or("").to_string();

    format!(
        "{{\"cpu_model\":\"{}\",\"cpu_vendor\":\"{}\",\
         \"cpu_cores_physical\":{},\"cpu_cores_logical\":{},\"cpu_threads\":{},\
         \"cpu_ghz\":{:.3},\"cpu_flags\":{},\"cpu_microcode\":\"{}\",\
         \"cr_bits\":64,\"vm_hypervisor\":\"{}\",\
         \"ram_total_bytes\":{},\"disks\":{},\"gpus\":{},\
         \"secure_boot\":\"{}\",\"tpm_present\":{},\
         \"mei_fw\":\"{}\",\"psp_fw\":\"{}\",\
         \"pmu_hw_gp\":{},\"pmu_hw_fixed\":{},\"pmu_sw\":{}}}",
        je(&cpu.model_name), je(&cpu.vendor),
        cpu.physical_cores, cpu.logical_cores, cpu.logical_cores,
        cpu.ghz, flags_json, je(&cpu.microcode),
        je(&cpu.vm_hypervisor),
        ram, disks_json, gpus_json,
        je(sb.label()), tpm,
        je(&mei_fw), je(&psp_fw),
        hw_gp, hw_fixed, crate::pmu::SW_COUNTER_COUNT,
    )
}

/// Estimate duration_ms for an OGG/Opus file from the last Ogg page's
/// granule position.
///
/// An Ogg page stores the granule position (sample count) as a 64-bit LE at
/// byte offset 6 within the page header.  We read the last 64 KiB of the
/// file, scan backward for the last "OggS" sync word, and decode its granule.
/// Opus streams always use 48 000 Hz as the granule clock.
/// Returns 0 on any parse failure.
pub fn ogg_duration_ms(path: &std::path::Path) -> u64 {
    ogg_duration_inner(path).unwrap_or(0)
}

fn ogg_duration_inner(path: &std::path::Path) -> Option<u64> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = fs::File::open(path).ok()?;
    let len = f.metadata().ok()?.len();
    if len < 64 { return None; }

    let tail = len.min(65536);
    f.seek(SeekFrom::End(-(tail as i64))).ok()?;
    let mut buf = vec![0u8; tail as usize];
    f.read_exact(&mut buf).ok()?;

    // Scan backward for last "OggS" sync word
    let pos = (0..buf.len().saturating_sub(27))
        .rev()
        .find(|&i| &buf[i..i+4] == b"OggS")?;

    if pos + 14 > buf.len() { return None; }
    let gran = u64::from_le_bytes(buf[pos+6..pos+14].try_into().ok()?);
    if gran == 0 || gran == u64::MAX { return None; }
    // Opus granule clock = 48 000 Hz regardless of the encoder input rate
    Some((gran * 1000) / 48_000)
}
