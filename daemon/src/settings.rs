// SPDX-License-Identifier: MIT OR GPL-2.0-or-later
//!
//! Per-user notification preferences, driven by the bot's `/settings`.
//!
//! Every category the daemon can *tell you about* lives here, so "avísame de
//! todo" is the default and the user trims what they do not want:
//!
//! | Category   | What it notifies about                              |
//! |---|---|
//! | `kernel`   | OOM kills, panics, oopses, segfaults from `/dev/kmsg` |
//! | `selinux`  | SELinux AVC denials from `/dev/kmsg`                |
//! | `thermal`  | CPU temperature crossing the hot threshold          |
//! | `memory`   | RAM pressure (MemAvailable under the floor)         |
//! | `load`     | Load average vs CPU count spiking                   |
//! | `htop`     | Periodic top-CPU/memory processes (htop-style)      |
//! | `pmu`      | PMU throughput stalls (low IPC)                     |
//! | `tsc`      | TSC/rdtscp drift or instability detected            |
//! | `diag`     | Periodic hardware diagnostics summary               |
//! | `control`  | Privileged actions executed (reboot/poweroff/CR)    |
//! | `login`    | Every login (GUI + SSH) announced; deny closes it  |
//! | `hypercall`| Guest -> KVM-host hypercall interception digests   |
//! | `modwatch` | Foreign kernel modules announced (keep/remove/analyse)|
//! | `exec`     | `/exec <cmd>` arbitrary commands (module loaded + confirm) |
//! | `luks`     | LUKS tripwire: asks `¿fui yo?` when initramfs saw a decrypt |
//! | `proactive`| LLM reviews sensors+dmesg on its own and decides   |
//! |             | whether to tell you, beyond fixed thresholds (off   |
//! |             | by default; costs a small LLM call per review)      |
//! |             |                                                      |
//! | Numeric:    | `login_timeout` seconds to answer a login alert     |
//! |             | `login_auto_close` closes the session on timeout    |
//!
//! The file is JSON, written by `/settings`. Missing file ⇒ everything on.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Settings {
    #[serde(default = "default_true")] pub kernel:  bool,
    #[serde(default = "default_true")] pub selinux: bool,
    #[serde(default = "default_true")] pub thermal: bool,
    #[serde(default = "default_true")] pub memory:  bool,
    #[serde(default = "default_true")] pub load:    bool,
    #[serde(default = "default_true")] pub htop:    bool,
    #[serde(default = "default_true")] pub pmu:     bool,
    #[serde(default = "default_true")] pub tsc:     bool,
    #[serde(default = "default_false")] pub diag:       bool,
    #[serde(default = "default_true")] pub control:    bool,
    /// Announce every login (GUI + SSH) and let the user accept or kill it.
    #[serde(default = "default_true")] pub login: bool,
    /// Intercept guest -> KVM-host hypercalls and report what each VM asked.
    #[serde(default = "default_true")] pub hypercall: bool,
    /// Seconds to answer a login alert before the pending decision expires.
    #[serde(default = "default_login_timeout")] pub login_timeout: u64,
    /// On timeout with no answer: close the login (true) or leave it (false).
    #[serde(default = "default_true")] pub login_auto_close: bool,
    /// Watch for foreign kernel modules being loaded, announce and let the
    /// user decide to keep/remove/analyse them.
    #[serde(default = "default_true")] pub modwatch: bool,
    /// Alert when the battery on a notebook reaches low/critical/drained levels.
    /// Only fires on laptops (a power_supply Battery is present); on a desktop
    /// tower there is nothing to report ("no aplica").
    #[serde(default = "default_true")] pub battery: bool,
    /// Allow `/exec <cmd>` — arbitrary commands, but ONLY while the kernel
    /// module is loaded (ring-3 trust anchor) and always after ARM+`confirm`.
    #[serde(default = "default_true")] pub exec: bool,
    /// Seconds a foreground `/exec` command may run before it is killed
    /// (a process-group SIGTERM→SIGKILL; `/exec stop` can do it earlier).
    #[serde(default = "default_exec_timeout")] pub exec_timeout: u64,
    /// Stop a bogus `/exec` burst: max running background jobs at once.
    #[serde(default = "default_exec_max_jobs")] pub exec_max_jobs: u64,
    /// Ask the "¿fui yo?" question every boot after the initramfs LUKS
    /// tripwire reports the disk was decrypted (evidence written pre-pivot).
    #[serde(default = "default_true")] pub lukswatch: bool,
    /// Action when a LUKS-decrypt ask is denied (or times out unanswered):
    /// `poweroff` (ACPI, "a la buena"), `triplefault` (forced power-down), or
    /// `none` (just log it). Only the module-backed actions need ring-0.
    #[serde(default = "default_luks_deny")] pub luks_deny_action: String,
    /// Seconds to answer the LUKS "¿fui yo?" ask before the deny action runs.
    #[serde(default = "default_luks_timeout")] pub luks_timeout: u64,
    #[serde(default = "default_false")] pub proactive:  bool,
    /// Active LLM provider chosen live via `/llm` (persisted here so it
    /// survives restarts). Non-empty single provider — wins over
    /// `llm_backends` and `[llm].backend`.
    #[serde(default)]
    pub llm_provider: String,
    /// Ordered LLM fallback chain set live via `/settings backends a,b,c`
    /// (persisted). Empty = use `[llm].backend` from config.
    #[serde(default)]
    pub llm_backends: Vec<String>,
    /// Context length for the llama.cpp backend, in tokens (`n_ctx`, the `-c`
    /// counterpart). `0` = don't override, use the server's own context.
    #[serde(default)]
    pub llama_ctx: u32,
    /// Rolling conversation turns kept in context.txt (the bot's conversational
    /// window). `0` = use `[memory] context_max_entries` from config.
    #[serde(default)]
    pub context_entries: usize,
    /// Context length for the in-process `local` backend, in tokens. `0` = use
    /// `[llm.local] context_size` from config.
    #[serde(default)]
    pub local_ctx: u32,
    /// Selected local model name (`/model <name>`), empty = auto/single.
    #[serde(default)]
    pub local_model: String,
    /// Model-name override for the API backends (`/model <name>`), e.g.
    /// `deepseek-v4-flash-vision-exp`. Empty = use `[llm].model`.
    #[serde(default)]
    pub llm_model: String,
    /// Ordered model lists per provider (persisted in settings.json, never in
    /// config.toml which only holds credentials). Maps provider name →
    /// ordered list of model names. A backend with a list tries each model in
    /// order; if one fails (404 / timeout / API error) it falls through to the
    /// next model of the SAME provider before the daemon moves to the next
    /// provider in the chain. Empty map = fall back to `[llm].model`.
    #[serde(default)]
    pub llm_models: std::collections::HashMap<String, Vec<String>>,
    /// Full system-prompt override set live via `/systemprompt <text>`. When
    /// set, it replaces the ENTIRE generated prompt (the `[persona]` tone /
    /// language defaults from config + the hardware anchor). `None` / empty =
    /// use the default builder. Cleared with `/systemprompt clear`.
    #[serde(default)]
    pub system_prompt_override: Option<String>,
}

fn default_true()  -> bool { true }
fn default_false() -> bool { false }
fn default_login_timeout() -> u64 { 180 }
fn default_exec_timeout() -> u64 { 120 }
fn default_exec_max_jobs() -> u64 { 4 }
fn default_luks_deny() -> String { "poweroff".to_string() }
fn default_luks_timeout() -> u64 { 120 }

impl Default for Settings {
    fn default() -> Self {
        Self {
            kernel:     true,
            selinux:    true,
            thermal:    true,
            memory:     true,
            load:       true,
            htop:       true,
            pmu:        true,
            tsc:        true,
            diag:       false,
            control:    true,
            login:      true,
            hypercall:  true,
            login_timeout: 180,
            login_auto_close: true,
            modwatch:   true,
            battery:    true,
            exec:       true,
            exec_timeout: 120,
            exec_max_jobs: 4,
            lukswatch:  true,
            luks_deny_action: "poweroff".to_string(),
            luks_timeout: 120,
            proactive:  false,
            llm_provider: String::new(),
            llm_backends: Vec::new(),
            llama_ctx: 0,
            context_entries: 0,
            local_ctx: 0,
            local_model: String::new(),
            llm_model: String::new(),
            llm_models: std::collections::HashMap::new(),
            system_prompt_override: None,
        }
    }
}

/// A named category the Settings table exposes.
pub const CATEGORIES: &[&str] = &[
    "kernel", "selinux", "thermal", "memory", "load", "htop",
    "pmu", "battery", "tsc", "diag", "control", "login", "hypercall", "modwatch",
    "exec", "luks", "proactive",
];

impl Settings {
    /// Load from a JSON file; missing/corrupt file falls back to defaults.
    pub fn load(path: &Path) -> Self {
        match std::fs::read_to_string(path) {
            Ok(raw) => serde_json::from_str(&raw).unwrap_or_else(|e| {
                log::warn!("settings: failed to parse {}: {e}; using defaults",
                           path.display());
                Settings::default()
            }),
            Err(_) => Settings::default(),
        }
    }

    /// Persist to the JSON file (best-effort; missing dir is created).
    pub fn save(&self, path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating {}", parent.display()))?;
        }
        let raw = serde_json::to_string_pretty(self)
            .context("serialising settings")?;
        std::fs::write(path, raw)
            .with_context(|| format!("writing {}", path.display()))
    }

    /// Read the current value of a category, if recognised.
    pub fn enabled(&self, cat: &str) -> Option<bool> {
        match cat {
            "kernel"    => Some(self.kernel),
            "selinux"   => Some(self.selinux),
            "thermal"   => Some(self.thermal),
            "memory"    => Some(self.memory),
            "load"      => Some(self.load),
            "htop"      => Some(self.htop),
            "pmu"       => Some(self.pmu),
            "battery"   => Some(self.battery),
            "tsc"       => Some(self.tsc),
            "diag"      => Some(self.diag),
            "control"   => Some(self.control),
            "login"     => Some(self.login),
            "hypercall" => Some(self.hypercall),
            "modwatch"  => Some(self.modwatch),
            "exec"      => Some(self.exec),
            "luks"      => Some(self.lukswatch),
            "proactive" => Some(self.proactive),
            _ => None,
        }
    }

    /// Set a category and return its new value; `None` for unknown names.
    pub fn set_enabled(&mut self, cat: &str, on: bool) -> Option<bool> {
        let slot = match cat {
            "kernel"    => &mut self.kernel,
            "selinux"   => &mut self.selinux,
            "thermal"   => &mut self.thermal,
            "memory"    => &mut self.memory,
            "load"      => &mut self.load,
            "htop"      => &mut self.htop,
            "pmu"       => &mut self.pmu,
            "battery"   => &mut self.battery,
            "tsc"       => &mut self.tsc,
            "diag"      => &mut self.diag,
            "control"   => &mut self.control,
            "login"     => &mut self.login,
            "hypercall" => &mut self.hypercall,
            "modwatch"  => &mut self.modwatch,
            "exec"      => &mut self.exec,
            "luks"      => &mut self.lukswatch,
            "proactive" => &mut self.proactive,
            _ => return None,
        };
        *slot = on;
        Some(on)
    }

    /// The effective ordered backend chain, in preference order. A single
    /// provider selected via `/llm` wins; otherwise the `/settings backends`
    /// chain; otherwise `[llm].backend` from config.
    pub fn llm_chain(&self, config_backends: &[String]) -> Vec<String> {
        if !self.llm_provider.is_empty() {
            return vec![self.llm_provider.clone()];
        }
        if !self.llm_backends.is_empty() {
            return self.llm_backends.clone();
        }
        config_backends.to_vec()
    }

    /// A compact per-category on/off table for the bot reply.
    pub fn to_table(&self) -> String {
        let mut out = String::from("Notification settings (avísame de):\n");
        for cat in CATEGORIES {
            let on = self.enabled(cat).unwrap_or(false);
            let (emoji, state) = if on { ("🔔", "on") } else { ("🔕", "off") };
            out.push_str(&format!("  {emoji} `{cat}` = {state}\n"));
        }
        out.push_str(&format!(
            "  🦙 `llama_ctx` = {} tokens (0 = llama-server default)\n",
            self.llama_ctx
        ));
        out.push_str(&format!(
            "  🧠 `context_entries` = {} turns (0 = config default)\n",
            self.context_entries
        ));
        out.push_str(&format!(
            "  💻 `local_ctx` = {} tokens (0 = config default)\n",
            self.local_ctx
        ));
        out.push_str(&format!(
            "  ⏳ `login_timeout` = {} s\n",
            self.login_timeout
        ));
        out.push_str(&format!(
            "  🔐 `login_auto_close` = {}\n",
            if self.login_auto_close { "on" } else { "off" }
        ));
        out.push_str(&format!(
            "  ⏱️ `exec_timeout` = {} s (max /exec foreground run)\n",
            self.exec_timeout
        ));
        out.push_str(&format!(
            "  🧯 `exec_max_jobs` = {} (max concurrent /exec jobs)\n",
            self.exec_max_jobs
        ));
        out.push_str(&format!(
            "  🔓 `luks_deny_action` = {} (LUKS deny/timeout action)\n",
            self.luks_deny_action
        ));
        out.push_str(&format!(
            "  ⏳ `luks_timeout` = {} s to answer the ¿fui yo? ask\n",
            self.luks_timeout
        ));
        let model = if self.llm_model.is_empty() {
            "config default".to_string()
        } else {
            self.llm_model.clone()
        };
        out.push_str(&format!("  🧬 `model` = {model}\n"));
        if !self.llm_backends.is_empty() {
            out.push_str(&format!(
                "  🔀 backends (fallback chain) = {}\n",
                self.llm_backends.join(" → ")
            ));
        }
        match self.system_prompt_override.as_deref() {
            Some(s) if !s.trim().is_empty() => {
                out.push_str(&format!(
                    "  📝 `system_prompt` = override ({} chars): `{}`\n",
                    s.len(),
                    truncate_inline(s, 60)
                ));
            }
            _ => out.push_str("  📝 `system_prompt` = default (config persona + hardware)\n"),
        }
        if !self.local_model.is_empty() {
            out.push_str(&format!(
                "  📦 `local model` = {} (provider: local)\n",
                self.local_model
            ));
        }
        out.push_str("\nFlip one with: `/settings <cat> on|off`\n");
        out.push_str("              `/settings backends a,b,c` (fallback chain)\n");
        out.push_str("Numbers: `/settings llama_ctx <tokens>`\n");
        out.push_str("         `/settings context_entries <turns>`\n");
        out.push_str("         `/settings local_ctx <tokens>`\n");
        out.push_str("         `/settings login_timeout <seconds>`\n");
        out.push_str("         `/settings exec_timeout <seconds>`\n");
        out.push_str("         `/settings luks_deny poweroff|triplefault|none`\n");
        out.push_str("Models: `/model <name>` (API name) or `/model <local-gguf>`");
        out.push_str("System prompt: `/systemprompt <text>` / `/systemprompt clear`");
        out.push_str("(default: everything on except `diag` and `proactive`)");
        out
    }
}

/// Collapse whitespace and truncate to `max` chars for inline display.
fn truncate_inline(s: &str, max: usize) -> String {
    let collapsed: String = s.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.chars().count() <= max {
        collapsed
    } else {
        let cut: String = collapsed.chars().take(max).collect();
        format!("{cut}…")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_all_on() {
        let s = Settings::default();
        assert!(s.to_table().contains("`htop` = on"));
        assert!(!s.diag);
    }

    #[test]
    fn llm_chain_resolution() {
        let cfg: Vec<String> = vec!["deepseek".into(), "llama".into()];
        let mut s = Settings::default();

        // No overrides → config chain.
        assert_eq!(s.llm_chain(&cfg), cfg);

        // /settings backends chain wins over the config.
        s.llm_backends = vec!["deepseek".into(), "local".into(), "none".into()];
        assert_eq!(
            s.llm_chain(&cfg),
            vec!["deepseek".to_string(), "local".to_string(), "none".to_string()]
        );

        // /llm single provider wins over everything.
        s.llm_provider = "gemini".to_string();
        assert_eq!(s.llm_chain(&cfg), vec!["gemini".to_string()]);
    }

    #[test]
    fn set_enabled_round_trips() {
        let mut s = Settings::default();
        assert_eq!(s.set_enabled("pmu", false), Some(false));
        assert!(!s.pmu);
        assert_eq!(s.enabled("nope"), None);
    }

    #[test]
    fn system_prompt_override_round_trips_via_file() {
        let dir = std::env::temp_dir().join(format!("sysentinel-sp-test-{}", std::process::id()));
        let path = dir.join("settings.json");
        let _ = std::fs::remove_dir_all(&dir);

        let mut s = Settings::default();
        assert!(s.system_prompt_override.is_none());
        s.system_prompt_override = Some("Eres el PC, flaite chileno.".to_string());
        s.save(&path).expect("save");

        let loaded = Settings::load(&path);
        assert_eq!(
            loaded.system_prompt_override.as_deref(),
            Some("Eres el PC, flaite chileno.")
        );
        assert!(loaded.to_table().contains("system_prompt` = override"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn save_load_round_trip_via_file() {
        let dir = std::env::temp_dir().join(format!("sysentinel-settings-test-{}", std::process::id()));
        let path = dir.join("settings.json");
        let _ = std::fs::remove_dir_all(&dir);

        let mut s = Settings::default();
        s.set_enabled("selinux", false);
        s.set_enabled("tsc", false);
        s.save(&path).expect("save");

        let loaded = Settings::load(&path);
        assert!(!loaded.selinux);
        assert!(!loaded.tsc);
        assert!(loaded.kernel, "untouched categories keep their value");

        let _ = std::fs::remove_dir_all(&dir);
    }
}