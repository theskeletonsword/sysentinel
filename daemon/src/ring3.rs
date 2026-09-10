// SPDX-License-Identifier: Apache-2.0
//!
//! Ring-3 fallbacks — facts the daemon can still gather when the
//! `sysentinel_metrics` kernel module is NOT loaded (Secure Boot without a
//! signed module, module blacklisted, `insmod` forgotten, …).
//!
//! Nothing here reads `/proc/sysentinel_metrics`; every method is plain
//! userspace (procfs / sysfs / `systemd-detect-virt` / `modinfo`) so the
//! machine still answers "what am I running on?" truthfully.
//!
//! The kernel module only *adds* ring-0 truths (CR registers, hypercall
//! counter, ME/PSP firmware via the MEI bus, killsession). Without it these
//! degrade to the best-effort sources below — the bot must say so, never fake
//! a ring-0 reading.

use std::process::Command;

/// Does the ring-0 module answer?
pub fn module_loaded() -> bool {
    crate::kernel_snap::KernelSnapshot::read().is_some()
}

/// Hypervisor truth without ring-0: `systemd-detect-virt` first, then a
/// procfs/manual sniff. Returns e.g. "KVM", "VMware", "VirtualBox", or
/// "bare metal (no hypervisor)".
pub fn hypervisor_detect() -> String {
    // systemd-detect-virt is authoritative when present.
    if let Ok(out) = Command::new("systemd-detect-virt").output() {
        if out.status.success() {
            let v = String::from_utf8_lossy(&out.stdout).trim().to_string();
            if !v.is_empty() && v != "none" {
                return v;
            }
        }
    }

    // Manual sniff (kinda 90s, but ring-3 honest).
    if let Ok(cpu) = std::fs::read_to_string("/proc/cpuinfo") {
        if cpu.lines().any(|l| l.starts_with("hypervisor")) {
            if cpu.to_lowercase().contains("qemu") {
                return "QEMU".into();
            }
            if cpu.to_lowercase().contains("kvm") {
                return "KVM".into();
            }
            return "VM (hypervisor flag set)".into();
        }
    }
    if std::path::Path::new("/proc/xen").exists() {
        return "Xen".into();
    }
    if std::path::Path::new("/sys/hypervisor/type").exists() {
        return "hypervisor (sysfs)".into();
    }
    if let Ok(mods) = std::fs::read_to_string("/proc/modules") {
        let m = mods.to_lowercase();
        if m.contains("kvm") && m.contains("intel") || m.contains("kvm_amd") {
            return "KVM (kvm modules loaded)".into();
        }
        if m.contains("vboxdrv") {
            return "VirtualBox".into();
        }
        if m.contains("vmw_vmci") || m.contains("vmware") {
            return "VMware".into();
        }
    }
    "bare metal (no hypervisor detected)".into()
}

/// The block appended to `/status` and the LLM context when the module is
/// absent, so nothing is silently missing — and nothing is faked.
pub fn module_fallback_block() -> String {
    let mut out = String::new();
    out.push_str("⚠️ kernel module (`sysentinel_metrics`) **not loaded** — ");
    out.push_str("no ring-0 reads (CR, ME/PSP, killsession). Using ring-3 fallbacks:\n");

    out.push_str(&format!("- Platform (ring-3): {}\n", hypervisor_detect()));

    let fw = crate::mei::query_firmware_status();
    if let Some(me) = &fw.intel_me {
        out.push_str(&format!("- Intel ME firmware (sysfs): {me}\n"));
    }
    if let Some(psp) = &fw.amd_psp {
        out.push_str(&format!("- AMD PSP (sysfs): {psp}\n"));
    }
    for note in &fw.notes {
        out.push_str(&format!("- {note}\n"));
    }
    if fw.intel_me.is_none() && fw.amd_psp.is_none() {
        out.push_str("- No ME/PSP versions readable from sysfs without the module.\n");
    }

    // PMU: pure perf_event_open — works WITHOUT the module. With
    // perf_event_paranoid ≤ 0 (the user's -1) it runs system-wide.
    // Ask the PMU what scope it actually got rather than predicting from the
    // sysctl: CAP_PERFMON widens it past what perf_event_paranoid implies.
    let paranoid = crate::pmu::read_paranoid();
    let access   = crate::pmu::probe_access();
    let pmu_note = match paranoid {
        Some(p) => format!("perf_event_open {} (paranoid={p})", access.describe()),
        None    => format!("perf_event_open {}", access.describe()),
    };

    out.push_str(&format!("- PMU/IPC: {pmu_note}\n"));

    out
}

/// Guidance for loading the module from the ring-3 side (Secure Boot aware).
pub fn load_hint() -> String {
    crate::secureboot::module_load_guidance()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fallback_block_never_fabricates_ring0() {
        let b = module_fallback_block();
        assert!(b.contains("not loaded"));
        assert!(b.contains("ring-3"));
    }

    #[test]
    fn hypervisor_sniff_is_deterministic() {
        // Whatever the result, it's a string and never panics.
        let v = hypervisor_detect();
        assert!(!v.is_empty());
    }
}