// SPDX-License-Identifier: Apache-2.0
//!
//! Configuration loading and validation.
//!
//! All secrets (bot token, LLM API keys) live only in the local TOML file
//! supplied by the user. The path defaults to `/etc/sysentinel/config.toml`
//! and can be overridden with `--config`.
//!
//! # Pairing and interactive mode
//!

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

// ── Top-level Config ──────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Clone)]
pub struct Config {
    pub general:  GeneralConfig,
    pub persona:  PersonaConfig,
    pub llm:      LlmConfig,
    #[serde(default)]
    pub memory:   MemoryConfig,
    #[serde(default)]
    pub hwdiag:   HwDiagConfig,
    #[serde(default)]
    pub pmu:      PmuConfig,
    #[serde(default)]
    pub camera:   CameraConfig,
    #[serde(default)]
    pub face:     FaceConfig,
    #[serde(default)]
    pub ipc:      IpcConfig,
    #[serde(default)]
    pub phone:    PhoneConfig,
}

// ── [general] ────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Clone)]
pub struct GeneralConfig {
    /// Minimum severity that triggers an alert: "info", "warning", "error", "critical".
    #[serde(default = "default_severity")]
    pub min_severity: String,
    /// Fallback sleep between /dev/kmsg reads when blocking mode is unavailable.
    #[serde(default = "default_poll_interval")]
    pub poll_interval_ms: u64,
    /// JSON file where the user's /settings notification preferences live.
    /// Managed by the bot; defaults to everything ON.
    #[serde(default = "default_settings_file")]
    pub settings_file: String,
    /// How often the live watcher re-checks thermal / memory / load / PMU /
    /// TSC thresholds and reports the top processes (htop).
    #[serde(default = "default_watch_interval")]
    pub watch_interval_secs: u64,
    /// How often the **proactive** reviewer runs (when the user enabled the
    /// `proactive` category in /settings): the LLM looks at sensors + recent
    /// dmesg events and decides on its own whether to tell the user anything,
    /// beyond the fixed thresholds. Only costs tokens while proactive is on.
    #[serde(default = "default_review_interval")]
    pub review_interval_secs: u64,
}

fn default_severity()      -> String { "warning".to_string() }
fn default_poll_interval() -> u64    { 500 }
fn default_settings_file() -> String { "/var/lib/sysentinel/settings.json".to_string() }
fn default_watch_interval() -> u64   { 15 }
fn default_review_interval() -> u64   { 300 }

// ── [persona] ────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Clone)]
pub struct PersonaConfig {
    /// Free-text description of the LLM's tone and persona. This is injected
    /// verbatim into the system prompt. Examples:
    ///   "formal and concise, like an incident report"
    ///   "colloquial Chilean Spanish, casual and direct, use local slang"
    pub tone: String,
    /// BCP-47 language tag. The LLM will answer in this language.
    #[serde(default = "default_language")]
    pub language: String,
    /// The persona is the PC itself, personified: it mirrors the machine's
    /// live mood (load, memory, temperature, PMU) on every conversational
    /// turn. Set `false` to disable the emotional line entirely.
    #[serde(default = "default_true")]
    pub emotions: bool,
    /// Has the CPU been undervolted? (V/F curve lowered.) **Resolved at
    /// runtime by `crate::undervolt::status()` per vendor (Intel/AMD/Zhaoxin):
    /// `true` only with positive evidence (intel-undervolt applied), `false`
    /// when stock. This flag is only consulted when the vendor state is
    /// unverifiable (`Unknown`) — an explicit opt-in, never a claim on its own.
    #[serde(default = "default_false")]
    pub undervolted: bool,
    /// Rewrite **every** push notification (SELinux denials, thermal / RAM /
    /// load / PMU / TSC watcher alerts) in the persona's own dialect instead
    /// of sending cold log lines. The user controls this: if they set the
    /// bot to talk Chilean Spanish, the alerts will too. Costs one small LLM
    /// call per alert (edge-triggered, so not chatty by volume).
    #[serde(default = "default_true")]
    pub chatty_alerts: bool,
}

fn default_language() -> String { "en".to_string() }
fn default_false()   -> bool   { false }

// ── [llm] ────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Clone)]
pub struct LlmConfig {
    /// Certificate pins for LLM endpoints, as `sha256/<base64 of the SPKI>`.
    ///
    /// Empty means ordinary HTTPS with public CA validation, which trusts every
    /// CA in the store. A pin narrows that to a key you name. Additive: the
    /// chain still has to validate first.
    ///
    /// Get one with:
    ///   openssl s_client -connect api.anthropic.com:443 </dev/null 2>/dev/null \
    ///     | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der \
    ///     | openssl dgst -sha256 -binary | openssl enc -base64
    ///
    /// A stale pin is an outage, so this is opt-in.
    #[serde(default)]
    pub tls_pins: Vec<String>,
    /// Ordered fallback chain of LLM backends: `"openai"`, `"anthropic"`,
    /// `"deepseek"`, `"gemini"`, `"llama"` (llama.cpp HTTP server), `"local"`
    /// or `"none"`. Accepts either a single string (`backend = "deepseek"`)
    /// or a list (`backend = ["deepseek", "llama", "none"]`). The list is
    /// tried in order — if one fails (API error / timeout) the next one is
    /// used. `"none"` never fails and echoes raw text, so it is the natural
    /// last resort for graceful degradation.
    ///
    /// The chain is changeable live: `/llm <name>` switches to a single
    /// provider, `/settings backends a,b,c` sets the whole list. Both persist
    /// to the settings file and win over this value.
    #[serde(default = "default_backend_chain", deserialize_with = "de_backend_chain")]
    pub backend: Vec<String>,
    /// Model name/ID passed to the API backends.
    pub model: String,
    /// Maximum output tokens per LLM call.
    #[serde(default = "default_max_tokens")]
    pub max_tokens: u32,
    /// Per-request timeout, in seconds, for the HTTP backends (OpenAI,
    /// DeepSeek, Anthropic, Gemini, llama.cpp server). After this the backend
    /// is considered failed and the fallback chain moves to the next one.
    #[serde(default = "default_timeout_secs")]
    pub timeout_secs: u64,

    pub openai:    Option<ProviderConfig>,
    pub anthropic: Option<ProviderConfig>,
    pub deepseek:  Option<ProviderConfig>,
    pub gemini:    Option<ProviderConfig>,
    pub llama:     Option<ProviderConfig>,
    pub local:     Option<LocalLlmConfig>,
}

fn default_max_tokens() -> u32 { 512 }
fn default_timeout_secs() -> u64 { 60 }
fn default_backend_chain() -> Vec<String> { vec!["none".to_string()] }

/// True if any backend other than the raw-echo `"none"` provider is in the
/// chain — i.e. a real LLM is reachable and persona/alert rewrites are worth
/// the tokens.
impl LlmConfig {
    pub fn llm_enabled(&self) -> bool {
        self.backend.iter().any(|b| b != "none")
    }

    /// Per-request deadline applied by the HTTP backends.
    pub fn timeout(&self) -> std::time::Duration {
        std::time::Duration::from_secs(self.timeout_secs)
    }
}

/// Accepts `backend = "deepseek"` (string) or `backend = ["a", "b"]` / a
/// comma-separated string; entries are trimmed and empties are dropped.
fn de_backend_chain<'de, D>(d: D) -> Result<Vec<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::Error as _;
    match Option::<toml::Value>::deserialize(d)? {
        None => Ok(Vec::new()),
        Some(toml::Value::String(s)) => {
            let list: Vec<String> = s
                .split(',')
                .map(str::trim)
                .filter(|e| !e.is_empty())
                .map(str::to_string)
                .collect();
            if list.is_empty() {
                Err(D::Error::custom(
                    "llm.backend string must name at least one provider",
                ))
            } else {
                Ok(list)
            }
        }
        Some(toml::Value::Array(arr)) => {
            if arr.is_empty() {
                return Ok(Vec::new());
            }
            arr.into_iter()
                .map(|v| match v {
                    toml::Value::String(s) => Ok(s),
                    other => Err(D::Error::custom(format!(
                        "llm.backend entries must be strings, got {other:?}"
                    ))),
                })
                .collect()
        }
        Some(other) => Err(D::Error::custom(format!(
            "llm.backend must be a string or an array of strings, got {other:?}"
        ))),
    }
}

#[derive(Debug, Deserialize, Clone)]
pub struct ProviderConfig {
    pub api_key:  String,
    pub base_url: String,
}

#[derive(Debug, Deserialize, Clone)]
#[cfg_attr(not(feature = "local-llm"), allow(dead_code))]
pub struct LocalLlmConfig {
    /// Path to a local .gguf model file — or a DIRECTORY of models (e.g.
    /// `/opt/sysentinel/models/`). A directory is scanned **recursively** for
    /// `.gguf` models; vision projectors (`*-mmproj-*.gguf`) and MTP files
    /// (`*.mtp`) are recognised and attached to their base model, so models
    /// like `deepseek-v4-flash-vision-exp` get their vision companion.
    pub model_path: String,
    /// Optional explicit vision projector (mmproj). Leave unset to auto-resolve
    /// next to the selected model.
    #[serde(default)]
    pub mmproj_path: Option<String>,
    /// Optional explicit multi-token-prediction companion. Leave unset to
    /// auto-resolve.
    #[serde(default)]
    pub mtp_path: Option<String>,
    /// Default context length, in tokens. Changeable live via
    /// `/settings local_ctx <tokens>`.
    #[serde(default = "default_ctx")]
    pub context_size: u32,
}

fn default_ctx() -> u32 { 2048 }

// ── [memory] ─────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Clone)]
pub struct MemoryConfig {
    /// Path to the long-term memory file (read-only for the bot; edit it
    /// yourself to teach the bot permanent facts).
    #[serde(default = "default_memory_file")]
    pub memory_file: String,
    /// Path to the rolling conversation context file (context window).
    /// Cleared with `/resetcontext`.
    #[serde(default = "default_context_file")]
    pub context_file: String,
    /// Max number of stored turns in context.txt before old ones are pruned.
    /// Capped low (default 15) to keep input-token / cache-token cost down,
    /// especially on paid APIs like DeepSeek.
    #[serde(default = "default_context_max_entries")]
    pub context_max_entries: usize,
}

fn default_memory_file()         -> String { "/var/lib/sysentinel/memory.txt".to_string() }
fn default_context_file()        -> String { "/var/lib/sysentinel/context.txt".to_string() }
fn default_context_max_entries() -> usize  { 15 }

impl Default for MemoryConfig {
    fn default() -> Self {
        Self {
            memory_file:         default_memory_file(),
            context_file:        default_context_file(),
            context_max_entries: default_context_max_entries(),
        }
    }
}

// ── [hwdiag] ─────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Clone, Default)]
pub struct HwDiagConfig {
    /// Enable periodic hardware diagnostics summaries.
    #[serde(default)]
    pub enabled: bool,
    /// How often to send diagnostics summaries, in minutes.
    #[serde(default = "default_hwdiag_interval")]
    pub interval_minutes: u64,
    /// Include Intel ME / AMD PSP firmware status in diagnostics.
    #[serde(default = "default_true")]
    pub include_firmware: bool,
}

fn default_hwdiag_interval() -> u64 { 60 }

// ── [pmu] ────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Clone)]
pub struct PmuConfig {
    /// Include PMU counters in the system context sent to the LLM and in
    /// `/status` replies. Requires at least software-counter access
    /// (always available); hardware counters need CAP_PERFMON or
    /// `perf_event_paranoid ≤ 0`.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// How long to sample PMU counters, in milliseconds. 250 ms is a good
    /// default. Increase for more accurate IPC estimates.
    #[serde(default = "default_pmu_sample_ms")]
    pub sample_ms: u64,
}

fn default_pmu_sample_ms() -> u64 { 250 }

impl Default for PmuConfig {
    fn default() -> Self {
        Self { enabled: true, sample_ms: 250 }
    }
}

// ── [camera] ─────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Clone)]
pub struct CameraConfig {
    /// Take webcam photos of intruders at LUKS unlock (evidence written by
    /// the initramfs hook) and at login events (successful login or ≥
    /// `login_fail_threshold` failed attempts). Photos are attached with
    /// attached to the alert; with no webcam only the text goes out.
    #[serde(default)]
    pub enabled: bool,
    /// The V4L2 capture binary (`sysentinel-cam`, built from ramdisk/).
    /// Installed by scripts/install-dracut.sh.
    #[serde(default = "default_cam_tool")]
    pub tool_path: String,
    /// Where the initramfs hook mirrors LUKS evidence (markers + photos). The
    /// capture now starts BEFORE the LUKS password prompt (pre-pivot hook is
    /// the fallback), but this dir plus the vfat ESPs are always scanned.
    /// The daemon scans this dir and dedupes by boot_id.
    #[serde(default = "default_luks_evidence")]
    pub evidence_dir: String,
    /// Consecutive failed login attempts within `fail_window_minutes` that
    /// trigger an intruder alert + photo.
    #[serde(default = "default_fail_threshold")]
    pub login_fail_threshold: u32,
    /// Keep counting failures for this many minutes before a fresh burst.
    #[serde(default = "default_fail_window")]
    pub fail_window_minutes: u64,
    /// Requested capture resolution (the camera may pick the nearest one).
    #[serde(default = "default_width")]  pub width:  u32,
    #[serde(default = "default_height")] pub height: u32,
    /// Seconds to wait for a frame before giving up on a format.
    #[serde(default = "default_cam_timeout")]
    pub timeout: u64,
}

fn default_cam_tool()         -> String { "/usr/libexec/sysentinel-cam".to_string() }
fn default_luks_evidence()    -> String { "/var/lib/sysentinel/luks-evidence".to_string() }
fn default_fail_threshold()   -> u32    { 3 }
fn default_fail_window()      -> u64    { 10 }
fn default_width()            -> u32    { 640 }
fn default_height()           -> u32    { 480 }
fn default_cam_timeout()      -> u64    { 10 }

impl Default for CameraConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            tool_path: default_cam_tool(),
            evidence_dir: default_luks_evidence(),
            login_fail_threshold: 3,
            fail_window_minutes: 10,
            width: 640,
            height: 480,
            timeout: 10,
        }
    }
}

// ── [phone] ──────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Clone, Default)]
pub struct PhoneConfig {
    /// Serve the phone app. Off by default: this makes a root daemon listen on
    /// a socket, which is a surface that did not exist before.
    #[serde(default)]
    pub enabled: bool,
    /// Address to listen on. Written out on purpose rather than defaulted to
    /// something convenient — "which interface is this reachable from" is the
    /// decision, and it should be made deliberately.
    #[serde(default)]
    pub bind: Option<String>,
    /// 64 hex characters: the key shared with the paired phone. Sealing a frame
    /// with it IS the authentication, so it is the whole secret.
    #[serde(default)]
    pub pairing_key: Option<String>,
    /// Alerts kept while the phone is away. The oldest are dropped past this,
    /// so a handset left off for a month cannot fill the disk.
    #[serde(default = "default_phone_queue")]
    pub queue_capacity: usize,
    /// Where the undelivered queue lives.
    #[serde(default = "default_phone_queue_path")]
    pub queue_path: String,
}

fn default_phone_queue() -> usize { 500 }
fn default_phone_queue_path() -> String {
    "/var/lib/sysentinel/phone-queue.json".to_string()
}

fn default_true() -> bool { true }

// ── [ipc] ────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Clone)]
pub struct IpcConfig {
    /// Serve the local control socket that the desktop GUI talks to.
    #[serde(default)]
    pub enabled: bool,
    /// Group handed the socket, making it 0660 for that group's members.
    /// Unset keeps it 0600 root-only — remember the daemon behind it is root,
    /// so this is the whole access control.
    #[serde(default)]
    pub group: Option<String>,
}

impl Default for IpcConfig {
    /// Off, and root-only when switched on. A local socket onto a root daemon
    /// is not something to enable by accident.
    fn default() -> Self {
        Self { enabled: false, group: None }
    }
}

// ── [face] ───────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize, Clone)]
pub struct FaceConfig {
    /// Compare a webcam frame at login against the registered owner-face
    /// hashes. Pure local perceptual hashing (pHash + wHash, 64 bits each) —
    /// no photos retained, no LLM tokens.
    #[serde(default)]
    pub enabled: bool,
    /// Where the owner-face hashes live (JSON, mode 0600). Populated by
    /// `/face register`; may hold several enrollments.
    #[serde(default = "default_face_path")]
    pub path: String,
    /// Hamming thresholds over the 64-bit hashes. Under `*_owner` the probe is
    /// the owner; under `*_ambiguous` it's a possible owner; above that it's an
    /// unknown face (potential intruder).
    #[serde(default = "default_p_owner")] pub p_owner: u32,
    #[serde(default = "default_w_owner")] pub w_owner: u32,
    #[serde(default = "default_p_amb")]   pub p_ambiguous: u32,
    #[serde(default = "default_w_amb")]   pub w_ambiguous: u32,

    /// The static-musl face tool. It carries both ONNX models inside it, so a
    /// single binary serves the initramfs and this glibc daemon alike.
    #[serde(default = "default_face_tool")]
    pub tool_path: String,
    /// Cosine over the 128-D embeddings at or above which the probe is the
    /// owner. See `facenn` for where the defaults come from.
    #[serde(default = "default_nn_owner")]
    pub nn_owner: f32,
    /// Cosine at or above which the probe is a *possible* owner.
    #[serde(default = "default_nn_amb")]
    pub nn_ambiguous: f32,
}

fn default_face_path() -> String { "/var/lib/sysentinel/faces.json".to_string() }
fn default_face_tool() -> String { "/usr/libexec/sysentinel-face".to_string() }
// Measured on this project's models: an identical image scores 1.000000 and
// six different faces scored up to 0.46 — hence a floor above that, not the
// 0.45 often quoted for MobileFaceNet.
fn default_nn_owner() -> f32 { 0.62 }
fn default_nn_amb()   -> f32 { 0.50 }
fn default_p_owner()  -> u32 { 14 }
fn default_w_owner()  -> u32 { 15 }
fn default_p_amb()    -> u32 { 20 }
fn default_w_amb()    -> u32 { 22 }

impl Default for FaceConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: default_face_path(),
            tool_path: default_face_tool(),
            nn_owner: default_nn_owner(),
            nn_ambiguous: default_nn_amb(),
            p_owner: 14, w_owner: 15, p_ambiguous: 20, w_ambiguous: 22,
        }
    }
}

// ── Validation + loading ──────────────────────────────────────────────────────

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading config file at {}", path.display()))?;
        let cfg: Config = toml::from_str(&raw)
            .with_context(|| format!("parsing config file at {}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> Result<()> {
        // Every provider URL must be https. A plain-HTTP endpoint would send
        // the API key, and everything this daemon tells the model, in the clear
        // — and nothing used to say so.
        for (name, url) in [
            ("openai", self.llm.openai.as_ref().map(|p| &p.base_url)),
            ("anthropic", self.llm.anthropic.as_ref().map(|p| &p.base_url)),
            ("deepseek", self.llm.deepseek.as_ref().map(|p| &p.base_url)),
            ("gemini", self.llm.gemini.as_ref().map(|p| &p.base_url)),
            // `llama` is normally a local llama.cpp on loopback, where plain
            // HTTP is the usual setup and nothing leaves the machine. It is
            // exempt on purpose rather than by omission.
        ] {
            if let Some(url) = url {
                if !url.trim().is_empty() {
                    crate::httpsec::require_https(url)
                        .with_context(|| format!("llm.{name}.base_url"))?;
                }
            }
        }

        // The phone channel needs both halves or it cannot start, and a
        // watchdog that cannot reach anyone is the state worth refusing early
        // rather than discovering when something happens.
        if self.phone.enabled {
            anyhow::ensure!(
                self.phone.bind.is_some(),
                "phone.bind is not set in config.toml — say which address the app \
                 should reach this machine on"
            );
            anyhow::ensure!(
                self.phone.pairing_key.is_some(),
                "phone.pairing_key is not set in config.toml — start the daemon once \
                 and it will print a fresh one to paste in"
            );
        }

        const KNOWN: &[&str] = &[
            "openai", "anthropic", "deepseek", "gemini", "llama", "local", "none",
        ];
        for b in &self.llm.backend {
            anyhow::ensure!(
                KNOWN.contains(&b.as_str()),
                "llm.backend must be a list of {KNOWN:?}, got '{b}'"
            );
        }
        anyhow::ensure!(
            !self.llm.backend.is_empty(),
            "llm.backend must name at least one provider"
        );

        if self.llm.llm_enabled() {
            anyhow::ensure!(
                !self.llm.model.trim().is_empty(),
                "llm.model must be set when an LLM backend is configured"
            );
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const HEADER: &str = r#"
        [general]
        [persona]
        tone = "casual"
    "#;

    fn parse(backend_lines: &str) -> Config {
        let raw = format!("{HEADER}\n[llm]\nmodel = \"m\"\n{backend_lines}\n");
        toml::from_str(&raw).expect("config parses")
    }

    #[test]
    fn backend_accepts_single_string() {
        let c = parse("backend = \"deepseek\"");
        assert_eq!(c.llm.backend, vec!["deepseek".to_string()]);
        assert!(c.llm.llm_enabled());
    }

    #[test]
    fn backend_accepts_array() {
        let c = parse("backend = [\"deepseek\", \"llama\", \"none\"]");
        assert_eq!(
            c.llm.backend,
            vec![
                "deepseek".to_string(),
                "llama".to_string(),
                "none".to_string()
            ]
        );
    }

    #[test]
    fn backend_accepts_comma_string() {
        let c = parse("backend = \"deepseek, llama , local\"");
        assert_eq!(
            c.llm.backend,
            vec!["deepseek".to_string(), "llama".to_string(), "local".to_string()]
        );
    }

    #[test]
    fn backend_defaults_to_none() {
        let raw = format!("{HEADER}\n[llm]\nmodel = \"m\"\n");
        let c: Config = toml::from_str(&raw).expect("config parses");
        assert_eq!(c.llm.backend, vec!["none".to_string()]);
        assert!(!c.llm.llm_enabled());
    }

    #[test]
    fn validate_accepts_full_chain() {
        let raw = format!("{HEADER}\n[llm]\nmodel = \"m\"\nbackend = [\"deepseek\", \"llama\"]\n");
        let c: Config = toml::from_str(&raw).expect("config parses");
        c.validate().expect("full chain validates");
    }

    #[test]
    fn validate_rejects_unknown_provider() {
        let raw = format!("{HEADER}\n[llm]\nmodel = \"m\"\nbackend = [\"deepseek\", \"wat\"]\n");
        let c: Config = toml::from_str(&raw).expect("config parses");
        assert!(c.validate().is_err());
    }

    #[test]
    fn timeout_defaults_to_60s() {
        let c = parse("backend = \"deepseek\"");
        assert_eq!(c.llm.timeout_secs, 60);
        assert_eq!(c.llm.timeout(), std::time::Duration::from_secs(60));
    }
}
