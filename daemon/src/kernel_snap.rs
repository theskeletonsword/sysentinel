// SPDX-License-Identifier: MIT OR GPL-2.0-or-later
//!
//! Live snapshot and control channel for the `sysentinel_metrics` module.
//!
//! The module renders a single `key=value` line on every `read()` of
//! `/proc/sysentinel_metrics` — ring-0 ground truth about uptime, memory,
//! loaded kernel modules, hypervisor presence, KVM features, Intel ME
//! firmware, AMD PSP presence, and the CR0/CR2/CR3/CR4/CR8 control
//! registers. This parser decodes that line so the daemon can answer "what
//! is this PC?" from the kernel, not from guesses.
//!
//! Reading the procfs file is side-effect free and needs no privileges
//! (mode 0644). Writing a *control command* (```reboot```, ```poweroff```,
//! `cr0_wp on|off`, `cr3=0x…`) is privileged: the module only accepts it
//! from uid 0 or from the GID passed as `write_gid` at modprobe time. The
//! bot layers a human-confirmation flow on top before it ever sends one.
//!
//! Works identically on Intel ME and AMD PSP hosts: on an AMD machine the
//! module reports `psp=present` (and no `me_fw=`); on an Intel bare-metal or
//! VM host it reports the opposite.

/// One decoded read of `/proc/sysentinel_metrics`. All fields optional —
/// the value is present only if the module reported it.
#[derive(Debug, Default, Clone)]
pub struct KernelSnapshot {
    pub uptime_secs:    Option<u64>,
    pub loaded_modules: Option<u64>,
    pub mem_free_kb:    Option<u64>,
    pub mem_total_kb:   Option<u64>,
    pub hypervisor:     Option<String>,
    pub cr0:            Option<u64>,
    pub cr2:            Option<u64>,
    pub cr3:            Option<u64>,
    pub cr4:            Option<u64>,
    pub cr8:            Option<u64>,
    pub kvm_features:   Option<String>,
    pub me_fw:          Option<String>,
    pub psp:            Option<String>,
}

impl KernelSnapshot {
    const DEV_PATH: &'static str = "/proc/sysentinel_metrics";

    /// Read and decode a fresh snapshot from the kernel module.
    ///
    /// Returns `None` when the module is not loaded or the file is
    /// unreadable — never an error (callers treat it as "kernel module off").
    pub fn read() -> Option<KernelSnapshot> {
        let data = std::fs::read_to_string(Self::DEV_PATH).ok()?;
        let mut snap = KernelSnapshot::default();

        for token in data.split_whitespace() {
            let Some((k, v)) = token.split_once('=') else { continue };
            match k {
                "uptime_s"     => snap.uptime_secs = v.parse().ok(),
                "modules"      => snap.loaded_modules = v.parse().ok(),
                "mem_free_kb"  => snap.mem_free_kb = v.parse().ok(),
                "mem_total_kb" => snap.mem_total_kb = v.parse().ok(),
                // The module escapes spaces in the hypervisor string with '_'.
                "hypervisor"   => snap.hypervisor = Some(v.replace('_', " ")),
                "cr0"          => snap.cr0 = parse_hex(v),
                "cr2"          => snap.cr2 = parse_hex(v),
                "cr3"          => snap.cr3 = parse_hex(v),
                "cr4"          => snap.cr4 = parse_hex(v),
                "cr8"          => snap.cr8 = parse_hex(v),
                "kvm_features" => snap.kvm_features = Some(v.to_string()),
                "me_fw"        => snap.me_fw = Some(v.to_string()),
                "psp"          => snap.psp = Some(v.to_string()),
                _ => {}
            }
        }

        Some(snap)
    }

    /// Read the current value of a control register (0, 2, 3, 4, 8) as
    /// reported by the module. `None` when the module is off.
    pub fn current_cr(reg: u8) -> Option<u64> {
        let snap = Self::read()?;
        match reg {
            0 => snap.cr0,
            2 => snap.cr2,
            3 => snap.cr3,
            4 => snap.cr4,
            8 => snap.cr8,
            _ => None,
        }
    }

    /// How the CR0.WP bit (write-protect, bit 16) currently sits.
    pub fn cr0_wp_enabled() -> Option<bool> {
        Self::current_cr(0).map(|v| (v >> 16) & 1 == 1)
    }

    /// Send one control command to the kernel module (e.g. `reboot`,
    /// `poweroff`, `cr0_wp on`, `cr3=0x…`). Returns an error string when the
    /// module rejects it (usually permission or bad value).
    pub fn send_command(cmd: &str) -> Result<(), String> {
        std::fs::write(Self::DEV_PATH, cmd.as_bytes())
            .map_err(|e| format!("kernel module rejected command: {e}"))
    }

    /// True when the module reports no hypervisor — the host is bare metal.
    pub fn is_bare_metal(&self) -> bool {
        self.hypervisor
            .as_deref()
            .map_or(false, |h| h.contains("bare-metal") || h.eq_ignore_ascii_case("none"))
    }

    /// Compact multi-line summary suitable for an LLM system prompt.
    /// Empty string when nothing was decoded.
    pub fn summary(&self) -> String {
        let mut s = String::new();
        let mut have = false;

        if let Some(m) = &self.me_fw {
            s.push_str(&format!("Live Intel ME firmware: {m}\n"));
            have = true;
        }
        if let Some(p) = &self.psp {
            s.push_str(&format!("AMD PSP (kernel module): {p}\n"));
            have = true;
        }
        if let Some(h) = &self.hypervisor {
            s.push_str(&format!("Live platform: {h}\n"));
            have = true;
        }
        if let Some(k) = &self.kvm_features {
            s.push_str(&format!("KVM CPU features: {k}\n"));
            have = true;
        }
        if let Some(n) = self.loaded_modules {
            s.push_str(&format!("Kernel modules loaded: {n}\n"));
            have = true;
        }
        if let Some(u) = self.uptime_secs {
            let (h, m) = ((u / 3600), (u % 3600) / 60);
            s.push_str(&format!("Kernel uptime: {h}h {m}m\n"));
            have = true;
        }

        if have { s } else { String::new() }
    }
}

/// Parse a `0x…` hex value the module renders.
fn parse_hex(v: &str) -> Option<u64> {
    let hex = v.strip_prefix("0x").or_else(|| v.strip_prefix("0X"))?;
    u64::from_str_radix(hex, 16).ok()
}