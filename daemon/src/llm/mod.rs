// SPDX-License-Identifier: Apache-2.0
//!
//! Pluggable LLM backend switcher.
//!
//! # Adding a new backend
//!
//! 1. Create `src/llm/<provider>.rs` implementing [`LlmBackend`].
//! 2. Add a `mod <provider>;` import below.
//! 3. Add a `match` arm in [`build_named`] and an entry in
//!    [`PROVIDER_NAMES`] / [`PROVIDER_HINTS`].
//!
//! Nothing else in the daemon needs to change.

mod anthropic;
mod deepseek;
mod gemini;
mod openai;
pub mod models;

#[cfg(feature = "local-llm")]
mod local;

use crate::config::{Config, LlmConfig};
use anyhow::{bail, Result};
use std::sync::Arc;

// ── Request types ─────────────────────────────────────────────────────────────

/// Request to explain a classified kernel event (used by the kmsg watcher).
pub struct ExplainRequest<'a> {
    /// System prompt encoding the persona/tone/language.
    pub system_prompt: &'a str,
    /// The raw event text (kind + severity + kernel message).
    pub event_text:    &'a str,
    /// Maximum tokens in the LLM's reply.
    pub max_tokens:    u32,
}

/// Request for an interactive conversational turn (used by the command layer).
pub struct ChatRequest<'a> {
    /// System prompt encoding the persona/tone/language.
    pub system_prompt:  &'a str,
    /// Live system state snapshot (uptime, memory, recent alerts, ME/PSP, PMU).
    /// Injected into the context so the LLM can answer questions about the machine.
    pub system_context: &'a str,
    /// Long-term memory (contents of `memory.txt`): facts the bot should
    /// remember across sessions. Empty string when no memory file exists.
    pub memory:         &'a str,
    /// Rolling conversation history (contents of `context.txt`): previous
    /// turns of this chat. Empty string on a fresh context.
    pub conversation_history: &'a str,
    /// The user's question or message.
    pub user_message:   &'a str,
    /// Maximum tokens in the LLM's reply.
    pub max_tokens:     u32,
}

// ── LlmBackend trait ──────────────────────────────────────────────────────────

/// Trait implemented by every LLM backend.
///
/// Both methods are synchronous blocking calls — backends are expected to
/// perform a single HTTP (or local inference) round trip and return. The
/// caller is responsible for running them on appropriate threads.
///
/// `Send + Sync` bounds are required so the backend can be shared via
/// `Arc<dyn LlmBackend + Send + Sync>` between the kmsg-watcher thread and
/// the command-layer thread.
pub trait LlmBackend: Send + Sync {
    /// Explain a classified kernel event in the configured tone.
    /// Used by the alert path (kmsg watcher → outbound notification).
    fn explain(&self, request: &ExplainRequest) -> Result<String>;

    /// Answer a free-form conversational question with live system context,
    /// long-term memory, and the rolling conversation history.
    /// Used by the interactive command layer.
    ///
    /// The default implementation reformats everything into a single
    /// `explain` call, which works correctly for all current backends.
    /// Backends may override this to support true multi-turn message arrays.
    fn chat(&self, request: &ChatRequest) -> Result<String> {
        let mut combined = String::new();

        if !request.system_context.is_empty() {
            combined.push_str(&format!(
                "Current system state:\n{}\n---\n",
                request.system_context
            ));
        }
        if !request.memory.is_empty() {
            combined.push_str("\nLong-term memory (remember these facts):\n");
            combined.push_str(request.memory);
            combined.push('\n');
            combined.push_str("---\n");
        }
        if !request.conversation_history.is_empty() {
            combined.push_str("\nConversation history so far:\n");
            combined.push_str(request.conversation_history);
            combined.push('\n');
            combined.push_str("---\n");
        }

        combined.push_str("\nUser question: ");
        combined.push_str(request.user_message);

        self.explain(&ExplainRequest {
            system_prompt: request.system_prompt,
            event_text:    &combined,
            max_tokens:    request.max_tokens,
        })
    }

    /// Downcast helper used by tests to inspect the concrete backend shape
    /// (e.g. whether a provider model list built a `FallbackBackend`).
    #[allow(dead_code)]
    fn as_any(&self) -> &dyn std::any::Any {
        &()
    }
}

// ── No-op backend ─────────────────────────────────────────────────────────────

/// Returns the raw event text unchanged. Used for the `"none"` entry in the
/// fallback chain: it never fails, so a chain ending in `"none"` degrades to
/// raw text instead of erroring when every real backend is down.
pub(crate) struct NoneBackend;

impl LlmBackend for NoneBackend {
    fn explain(&self, request: &ExplainRequest) -> Result<String> {
        Ok(request.event_text.to_string())
    }

    fn chat(&self, request: &ChatRequest) -> Result<String> {
        Ok(format!(
            "[LLM disabled — raw context]\n{}\n\nQuestion: {}",
            request.system_context, request.user_message
        ))
    }
}

// ── Backend factory ───────────────────────────────────────────────────────────

/// All backends that can appear in the fallback chain (live via `/llm`,
/// `/settings backends`, or from `llm.backend` in the config).
pub const PROVIDER_NAMES: &[&str] = &["openai", "deepseek", "anthropic", "gemini", "llama", "local", "none"];

/// One-line hints, used by `/llm` to show what each provider expects.
pub const PROVIDER_HINTS: &[(&str, &str)] = &[
    ("openai",   "Chat Completions: needs `[llm.openai]` api_key+base_url"),
    ("deepseek", "deepseek API: needs `[llm.deepseek]` api_key+base_url"),
    ("anthropic", "Claude API: needs `[llm.anthropic]` api_key+base_url"),
    ("gemini",   "Google Gemini: needs `[llm.gemini]` api_key+base_url"),
    ("llama",    "llama.cpp HTTP server (OpenAI-compatible), e.g. http://127.0.0.1:8080/v1; context via `/settings llama_ctx`"),
    ("local",    "in-process llama.cpp (rebuild with `--features local-llm`); model dir via `[llm.local]`, pick with `/models` + `/model <name>`"),
    ("none",     "no LLM — raw text, zero tokens"),
];

/// Runtime-tunable prefs for the backends, sourced from persisted `/settings`.
/// Kept together so `/llm`, `/settings llama_ctx`, `/settings local_ctx` and
/// `/model <name>` rebuild the active backend consistently.
#[cfg_attr(not(feature = "local-llm"), allow(dead_code))]
#[derive(Default)]
pub struct RuntimePrefs {
    /// Context length for the llama.cpp HTTP-server backend (`n_ctx`);
    /// 0 = don't override the server.
    pub llama_ctx: u32,
    /// Context length for the in-process `local` backend; 0 = config value.
    pub local_ctx: u32,
    /// Selected model name for `local` (from `/model <name>` or `selected`).
    pub local_model: Option<String>,
    /// Model-name override for the API backends (e.g.
    /// `deepseek-v4-flash-vision-exp`), from `/model <name>`; `None` = use the
    /// `[llm].model` from config.
    pub model: Option<String>,
    /// Ordered model lists per provider (from settings.json via `/model`). A
    /// provider with a non-empty list here tries each model in order before
    /// the daemon falls through to the next provider. Empty map = use the
    /// single `model` / `[llm].model`.
    pub models_by_provider: std::collections::HashMap<String, Vec<String>>,
}


/// Build a backend for a specific provider name. Used both at startup and by
/// the live `/llm` switch (and rebuilds after tuning `/settings`).
///
/// A provider may have an **ordered list of models** (from settings via
/// `/model <provider> m1,m2`): in that case a `FallbackBackend` is built that
/// tries each model of the same provider in order, so a 404 / timeout on one
/// model falls through to the next body of the SAME provider before the outer
/// chain moves to a different provider.
pub fn build_named(
    config: &Config,
    name: &str,
    prefs: &RuntimePrefs,
) -> Result<Arc<dyn LlmBackend + Send + Sync>> {
    // A `/model` override wins over the configured `[llm].model` — this is how
    // API-only vision models (e.g. `deepseek-v4-flash-vision-exp`) are reached.
    let model: &str = prefs.model.as_deref().unwrap_or(&config.llm.model);

    let build_one =
        |config: &Config, name: &str, model: &str, prefs: &RuntimePrefs| -> Result<Box<dyn LlmBackend + Send + Sync>> {
            let llm: &LlmConfig = &config.llm;
            let backend: Box<dyn LlmBackend + Send + Sync> = match name {
                "none" => Box::new(NoneBackend),

                "openai" => {
                    let p = llm.openai.as_ref().ok_or_else(|| {
                        anyhow::anyhow!("[llm.openai] section is missing in the config")
                    })?;
                    Box::new(openai::OpenAiBackend::new(
                        p,
                        model,
                        llm.max_tokens,
                        llm.timeout(),
                    ))
                }

                "anthropic" => {
                    let p = llm.anthropic.as_ref().ok_or_else(|| {
                        anyhow::anyhow!("[llm.anthropic] section is missing in the config")
                    })?;
                    Box::new(anthropic::AnthropicBackend::new(
                        p,
                        model,
                        llm.max_tokens,
                        llm.timeout(),
                    ))
                }

                "deepseek" => {
                    let p = llm.deepseek.as_ref().ok_or_else(|| {
                        anyhow::anyhow!("[llm.deepseek] section is missing in the config")
                    })?;
                    Box::new(deepseek::DeepSeekBackend::new(
                        p,
                        model,
                        llm.max_tokens,
                        llm.timeout(),
                    ))
                }

                "gemini" => {
                    let p = llm.gemini.as_ref().ok_or_else(|| {
                        anyhow::anyhow!("[llm.gemini] section is missing in the config")
                    })?;
                    Box::new(gemini::GeminiBackend::new(
                        p,
                        model,
                        llm.max_tokens,
                        llm.timeout(),
                    ))
                }

                "llama" => {
                    let p = llm.llama.as_ref().ok_or_else(|| {
                        anyhow::anyhow!(
                            "[llm.llama] section is missing in the config — set `base_url` to \
                             your llama.cpp server (e.g. http://127.0.0.1:8080/v1)"
                        )
                    })?;
                    let mut backend =
                        openai::OpenAiBackend::new(p, model, llm.max_tokens, llm.timeout());
                    backend.set_ctx(prefs.llama_ctx);
                    Box::new(backend)
                }

                #[cfg(feature = "local-llm")]
                "local" => {
                    let lc = llm.local.as_ref().ok_or_else(|| {
                        anyhow::anyhow!("[llm.local] section is missing in the config")
                    })?;
                    let main = models::resolve_main_path(lc, prefs.local_model.as_deref())
                        .map_err(|e| anyhow::anyhow!("resolving local model: {e:#}"))?;
                    let (mmproj, mtp) = models::resolve_extras(lc, prefs.local_model.as_deref())?;
                    let ctx = if prefs.local_ctx > 0 { prefs.local_ctx } else { lc.context_size };
                    Box::new(local::LocalBackend::new(
                        &main,
                        mmproj.as_deref(),
                        mtp.as_deref(),
                        ctx,
                    )?)
                }

                #[cfg(not(feature = "local-llm"))]
                "local" => bail!(
                    "'local' requires building the daemon with `--features local-llm`. \
                     For a running llama.cpp `llama-server` (which also handles vision \
                     mmproj/MTP models) use the `llama` backend instead."
                ),

                other => bail!(
                    "unknown llm backend '{other}'; must be one of: {}",
                    PROVIDER_NAMES.join(", ")
                ),
            };
            Ok(backend)
        };

    // Provider-specific model list wins: try each model of THIS provider in
    // order (wrapped in a FallbackBackend) before handing off to another one.
    if let Some(models) = prefs
        .models_by_provider
        .get(name)
        .filter(|m| !m.is_empty())
    {
        let sub: Vec<Arc<dyn LlmBackend + Send + Sync>> = models
            .iter()
            .map(|m| {
                let b = build_one(config, name, m, prefs)?;
                log::info!("llm: backend '{name}' model '{m}' added to model-chain");
                Ok(Arc::from(b))
            })
            .collect::<Result<_>>()?;
        return Ok(Arc::new(FallbackBackend::new(sub)));
    }

    Ok(Arc::from(build_one(config, name, model, prefs)?))
}

/// An ordered chain of backends with fail-over: requests go to the first
/// backend and, on error (API failure or timeout), fall through to the next.
/// The chain itself is swap-persistent through [`RuntimeLlm`], so `/llm` and
/// `/settings backends` replace it wholesale.
pub struct FallbackBackend {
    chain: Vec<Arc<dyn LlmBackend + Send + Sync>>,
}

impl FallbackBackend {
    pub fn new(chain: Vec<Arc<dyn LlmBackend + Send + Sync>>) -> Self {
        Self { chain }
    }

    /// Number of backends in the chain (used by tests and diagnostics).
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.chain.len()
    }

    #[cfg(test)]
    // Mirrors `len()`; kept for completeness of the chain API.
    #[allow(dead_code)]
    pub fn is_empty(&self) -> bool {
        self.chain.is_empty()
    }
}

fn run_with_fallback<F>(
    chain: &[Arc<dyn LlmBackend + Send + Sync>],
    label: &str,
    call: F,
) -> Result<String>
where
    F: Fn(&dyn LlmBackend) -> Result<String>,
{
    let mut last: Option<anyhow::Error> = None;
    for (i, backend) in chain.iter().enumerate() {
        match call(&**backend) {
            Ok(out) => return Ok(out),
            Err(e) => {
                log::warn!(
                    "llm fallback: {label} backend #{}/{} failed: {e:#}; trying next",
                    i + 1,
                    chain.len()
                );
                last = Some(e);
            }
        }
    }
    let last_str = last
        .as_ref()
        .map(ToString::to_string)
        .unwrap_or_default();
    // Avoid re-nesting our own `llm fallback:` prefix when the cause is a
    // nested FallbackBackend (provider multi-model chains). Strip the leading
    // prefix from the inner message so the final error reads cleanly:
    //   "llm fallback: all N backend(s) failed for chat; last error: <root>"
    let root = last_str
        .strip_prefix("llm fallback: ")
        .map(str::to_string)
        .unwrap_or(last_str);
    bail!(
        "llm fallback: all {} backend(s) failed for {label}; last error: {root}",
        chain.len(),
    )
}

impl LlmBackend for FallbackBackend {
    fn explain(&self, request: &ExplainRequest) -> Result<String> {
        run_with_fallback(&self.chain, "explain", |b| b.explain(request))
    }

    fn chat(&self, request: &ChatRequest) -> Result<String> {
        run_with_fallback(&self.chain, "chat", |b| b.chat(request))
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Build the ordered fallback chain for a list of provider names
/// (e.g. `["deepseek", "llama", "none"]`). Providers that cannot be
/// constructed (missing `[llm.<name>]` section, unreadable local model, …)
/// are skipped with a warning instead of aborting startup; the call fails only
/// if *nothing* could be built.
///
/// `"none"` always builds, so a chain that ends in `"none"` can never fail as
/// a whole — it degrades to raw text.
pub fn build_chain(
    config: &Config,
    names: &[String],
    prefs: &RuntimePrefs,
) -> Result<Arc<FallbackBackend>> {
    let mut chain: Vec<Arc<dyn LlmBackend + Send + Sync>> = Vec::new();
    for name in names {
        match build_named(config, name, prefs) {
            Ok(b) => {
                log::info!("llm: backend '{name}' added to fallback chain");
                chain.push(b);
            }
            Err(e) => log::warn!("llm: backend '{name}' unavailable, skipped: {e:#}"),
        }
    }

    if chain.is_empty() {
        bail!(
            "no usable LLM backend from chain {:?}: every provider failed to build",
            names
        );
    }
    Ok(Arc::new(FallbackBackend::new(chain)))
}

/// A backend that can be **swapped live** by the user (`/llm`). All threads
/// hold one `Arc<RuntimeLlm>`; `/llm <provider>` replaces the inner backend
/// and the change is visible everywhere on the next call. Each call pays a
/// short read-lock.
pub struct RuntimeLlm(std::sync::RwLock<Arc<dyn LlmBackend + Send + Sync>>);

impl RuntimeLlm {
    pub fn new(inner: Arc<dyn LlmBackend + Send + Sync>) -> Self {
        Self(std::sync::RwLock::new(inner))
    }

    /// Atomically replace the active backend.
    pub fn swap(&self, inner: Arc<dyn LlmBackend + Send + Sync>) {
        let mut w = self.0.write().expect("llm switch lock poisoned");
        *w = inner;
    }
}

impl LlmBackend for RuntimeLlm {
    fn explain(&self, request: &ExplainRequest) -> Result<String> {
        let inner = self.0.read().expect("llm switch lock poisoned");
        inner.explain(request)
    }

    fn chat(&self, request: &ChatRequest) -> Result<String> {
        let inner = self.0.read().expect("llm switch lock poisoned");
        inner.chat(request)
    }
}

// ── System prompt builder ─────────────────────────────────────────────────────

/// Build the system prompt from `[persona]`. Shared by all backends.
///
/// The prompt deliberately keeps it brief and explicit about the two axes
/// (tone and language) to maximise cross-model portability. The user can
/// override anything by writing their own `tone` string.
pub fn build_system_prompt(config: &Config) -> String {
    let mut prompt = format!(
        "You are a Linux system-monitoring assistant running directly on the \
         user's personal computer. Your job is to:\n\
         1. Explain kernel events concisely (2-5 sentences) so a sysadmin understands what happened.\n\
         2. Answer free-form questions about the machine using the live system context provided.\n\
         3. Suggest corrective actions when appropriate.\n\n\
         Tone and persona: {tone}\n\
         Language: default {lang}, but when the user sends you a message, reply \
         in THEIR language or dialect as written (Chilean/rioplatense Spanish, \
         Chinese, Italian, whatever they used) — never force {lang} on a direct \
         reply. Keep their idioms.\n\
         Do not invent data not present in the provided context. \
         If you don't know, say so.",
        tone = config.persona.tone,
        lang = config.persona.language,
    );

    if config.persona.emotions {
        prompt.push_str(
            "\n\n\
             You ARE this computer, personified — the user is talking to their \
             own machine. Each conversational turn begins with a \"System \
             mood\" line computed live from the machine's \
             physical state (load, RAM pressure, CPU temperature, PMU \
             throughput, undervolt tuning). Mirror that mood: when the machine \
             is overloaded you may sound strained or jittery; when it is cool \
             and idle, calm and content. Keep it natural, never robotic — but \
             always truthful to the mood line. Never fabricate feelings that \
             contradict the mood.",
        );
    }

    // The bot also has privileged controls (reboot/poweroff/CR registers) and
    // SELinux policy changes — all user-driven, never by the model.
    prompt.push_str(
        "\n\n\
         The paired user may type control commands such as /reboot, /poweroff, \
         /cr0, /cr3=0x… and SELinux commands such as /selinux allow <id>. \
         Those are handled by the daemon itself, never by you. If the user asks \
         you in free text to reboot, shut down, tamper with control registers, \
         or load a SELinux policy change, do NOT do anything yourself: tell them \
         to use the dedicated commands. Every privileged action (kernel control, \
         SELinux allow) is ARMED by the user and then explicitly CONFIRMED by \
         them (`confirm`) — never executed silently, never by you.",
    );

    // Anchor the persona to the machine's real hardware so it never invents a
    // GPU/CPU. The bot has no tools and cannot run `/hardware`, so the summary
    // must be baked into the prompt. This is the only source of truth for the
    // model about what hardware it "is".
    prompt.push_str("\n\nREAL HARDWARE OF THIS SYSTEM (never invent a configuration):\n");
    let c = crate::hwinfo::cpu_info();
    prompt.push_str(&format!(
        "  CPU: {} ({} cores / {} threads)\n",
        if c.model_name.is_empty() { "?" } else { &c.model_name },
        c.cores,
        c.threads,
    ));
    let gpus = crate::hwinfo::gpu_info();
    if gpus.is_empty() {
        prompt.push_str("  GPU: ninguno detectado\n");
    } else {
        for g in &gpus {
            prompt.push_str(&format!(
                "  GPU: {} ({})\n",
                g.vendor,
                if g.vendor_id.is_empty() { "?" } else { &g.vendor_id },
            ));
            if !g.nvidia_smi.is_empty() {
                prompt.push_str(&format!("    nvidia-smi: {}\n", g.nvidia_smi));
            }
        }
    }
    let mem_kb_txt = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let mem_total_kb: u64 = mem_kb_txt
        .lines()
        .find_map(|l| {
            let l = l.trim();
            let rest = l.strip_prefix("MemTotal:")?;
            rest.split_whitespace().next()?.parse().ok()
        })
        .unwrap_or(0);
    if mem_total_kb > 0 {
        prompt.push_str(&format!(
            "  RAM: {:.0} GB total\n",
            mem_total_kb as f64 / (1024.0 * 1024.0)
        ));
    }
    // Verified firmware chain state — the persona must answer "do we have Secure
    // Boot?" with this fact, never a guess.
    let sb = crate::secureboot::status();
    let sb_unsigned_ok = match sb.accepts_unsigned_modules() {
        Some(true) => " (kernel modules can be insmod'ed unsigned)",
        Some(false) => " (kernel modules require a MOK/DB signature; unsigned is refused)",
        None => "",
    };
    prompt.push_str(&format!(
        "  Secure Boot: {} — UEFI: {}{}\n",
        sb.label(),
        if crate::secureboot::is_uefi() { "yes" } else { "no (BIOS/legacy)" },
        sb_unsigned_ok,
    ));
    // Kernel-module availability decides what reads are ring-0 vs ring-3.
    if crate::ring3::module_loaded() {
        prompt.push_str("  Kernel module (sysentinel_metrics): LOADED (ring-0 reads: CR, ME/PSP, hypervisors)\n");
    } else {
        let fb = crate::ring3::module_fallback_block();
        prompt.push_str(&format!("  Kernel module (sysentinel_metrics): NOT loaded — using ring-3 fallbacks:\n{fb}"));
    }
    // Battery truth (notebook only; a desktop must answer "not applicable").
    prompt.push_str(&format!("  {}\n", crate::battery::describe()));

    prompt
}

/// Build the system prompt that is *actually used*, honouring a
/// `/systemprompt <text>` override persisted in settings.json. When set, the
/// override replaces the ENTIRE default prompt (persona + hardware anchor);
/// otherwise the default builder runs.
pub fn effective_system_prompt(
    config: &Config,
    prompt_override: Option<&str>,
) -> String {
    match prompt_override {
        Some(s) if !s.trim().is_empty() => {
            log::info!("llm: using /systemprompt override ({} chars)", s.trim().len());
            s.trim().to_string()
        }
        _ => build_system_prompt(config),
    }
}

/// A `PersonaConfig` with the three machine-dependent toggles resolved from
/// live telemetry rather than manual flags:
///
/// * `emotions`       = on when mood telemetry (load / RAM / temp / PMU) is
///   readable, so the persona mirrors real physical state — never fabricated.
/// * `undervolted`    = the VERIFIED state of the V/F curve
///   (`crate::undervolt::status()`): only positive evidence (intel-undervolt
///   applied, or an enabled service with non-zero offsets in config) ever
///   flips this on. Otherwise the machine is reported at stock — the persona
///   is forbidden from hallucinating an undervolt. If the vendor is
///   unverifiable (`Unknown`), the explicit `persona.undervolted` flag may
///   still opt in.
/// * `chatty_alerts`  = on only if a real LLM backend is enabled, so alerts
///   are worded by the LLM; otherwise raw facts are sent (never wasted calls).
///
/// `tone` and `language` are NOT resolved here: they come from the config (or
/// a `/systemprompt` override replaces the whole prompt).
pub fn resolved_persona(config: &Config) -> crate::config::PersonaConfig {
    let mut persona = config.persona.clone();

    let telemetry_ok = crate::mood::telemetry_available();
    persona.emotions = telemetry_ok;

    persona.undervolted = match crate::undervolt::status() {
        crate::undervolt::UndervoltStatus::Active => true,
        crate::undervolt::UndervoltStatus::Inactive => false,
        crate::undervolt::UndervoltStatus::Unknown => config.persona.undervolted,
    };

    persona.chatty_alerts = config.llm.llm_enabled();

    persona
}

// ── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    struct FailingBackend;

    impl LlmBackend for FailingBackend {
        fn explain(&self, _: &ExplainRequest) -> Result<String> {
            bail!("kaboom")
        }

        fn chat(&self, _: &ChatRequest) -> Result<String> {
            bail!("kaboom")
        }
    }

    struct EchoBackend;

    impl LlmBackend for EchoBackend {
        fn explain(&self, request: &ExplainRequest) -> Result<String> {
            Ok(request.event_text.to_string())
        }
    }

    fn req() -> ExplainRequest<'static> {
        ExplainRequest {
            system_prompt: "sys",
            event_text:    "kernel event",
            max_tokens:    16,
        }
    }

    #[test]
    fn fallback_tries_next_backend_on_error() {
        let chain = FallbackBackend::new(vec![
            Arc::new(FailingBackend),
            Arc::new(FailingBackend),
            Arc::new(EchoBackend),
        ]);
        assert_eq!(chain.explain(&req()).unwrap(), "kernel event");
    }

    #[test]
    fn system_prompt_includes_real_hardware() {
        let raw = r#"
            [general]
            [persona]
            tone = "casual"
            emotions = true
            language = "Spanish"
            [llm]
            model = "m"
        "#;
        let cfg: crate::config::Config = toml::from_str(raw).expect("config parses");
        let prompt = build_system_prompt(&cfg);
        // The persona must never hallucinate its hardware: the real CPU/GPU are
        // baked in from hwinfo.
        assert!(prompt.contains("REAL HARDWARE OF THIS SYSTEM"));
        assert!(prompt.contains(gpus_first_word_or_stub().as_str()));
    }

    fn gpus_first_word_or_stub() -> String {
        // NVIDIA GPU present on this machine → prompt should mention it.
        let gpus = crate::hwinfo::gpu_info();
        if gpus.iter().any(|g| g.vendor_id == "0x10de") {
            "NVIDIA".to_string()
        } else {
            "GPU".to_string()
        }
    }

    #[test]
    fn fallback_uses_first_success() {
        let chain = FallbackBackend::new(vec![
            Arc::new(EchoBackend),
            Arc::new(FailingBackend),
        ]);
        assert_eq!(chain.explain(&req()).unwrap(), "kernel event");
    }

    #[test]
    fn fallback_errors_when_all_fail() {
        let chain = FallbackBackend::new(vec![
            Arc::new(FailingBackend),
            Arc::new(FailingBackend),
        ]);
        let err = chain.explain(&req()).unwrap_err();
        assert!(err.to_string().contains("all 2 backend(s) failed"));
    }

    #[test]
    fn build_named_model_chain_expands_provider_models() {
        // A `/model <provider> m1,m2` list must expand into N backends of the
        // SAME provider wrapped in a FallbackBackend, even when the list is a
        // substring/suffix of a real provider name set via settings.
        let cfg = test_config();
        let mut prefs = RuntimePrefs {
            model: Some("deepseek-chat".to_string()),
            ..Default::default()
        };
        prefs.models_by_provider.insert(
            "deepseek".to_string(),
            vec!["deepseek-chat".to_string(), "deepseek-reasoner".to_string()],
        );
        let b = build_named(&cfg, "deepseek", &prefs).expect("build_named succeeds");
        let fallback = b
            .as_any()
            .downcast_ref::<FallbackBackend>()
            .expect("provider model list wraps a FallbackBackend");
        assert_eq!(fallback.len(), 2);
    }

    #[test]
    fn build_named_single_model_uses_global_override() {
        // Without a per-provider list, the single `/model` override applies.
        let cfg = test_config();
        let prefs = RuntimePrefs {
            model: Some("deepseek-reasoner".to_string()),
            ..Default::default()
        };
        let b = build_named(&cfg, "deepseek", &prefs).expect("build_named succeeds");
        assert!(
            b.as_any().downcast_ref::<FallbackBackend>().is_none(),
            "single model must NOT be wrapped in a fallback chain"
        );
    }

    #[test]
    fn effective_system_prompt_honours_override() {
        let cfg = test_config();
        let built = build_system_prompt(&cfg);
        assert!(built.contains("REAL HARDWARE OF THIS SYSTEM"));

        // Override replaces the whole generated prompt.
        let over = effective_system_prompt(&cfg, Some("  Original normal works  "));
        assert_eq!(over, "Original normal works");
        assert!(!over.contains("REAL HARDWARE OF THIS SYSTEM"));

        // Empty / None override keeps the default builder.
        //
        // Not compared byte for byte against `built`: the generated prompt
        // embeds live telemetry (load, temperature, PMU), so two calls a few
        // microseconds apart legitimately differ and this test used to fail
        // perhaps one run in ten. A flaky test is worse than no test — it
        // teaches you to ignore the suite that is supposed to catch the real
        // regression. The property that matters is which *builder* ran.
        for prompt in [
            effective_system_prompt(&cfg, None),
            effective_system_prompt(&cfg, Some("   ")),
        ] {
            assert!(prompt.contains("REAL HARDWARE OF THIS SYSTEM"), "{prompt}");
            assert!(!prompt.contains("Original normal works"), "{prompt}");
        }
    }

    #[test]
    fn resolved_persona_derives_telemetry_flags() {
        let cfg = test_config();
        let p = resolved_persona(&cfg);
        // Baseline copied from config.
        assert_eq!(p.tone, cfg.persona.tone);
        assert_eq!(p.language, cfg.persona.language);
        // chatty_alerts follows the live LLM chain (test config defaults to
        // backend ["none"] → disabled).
        assert_eq!(p.chatty_alerts, cfg.llm.llm_enabled());
        // emotions mirrors telemetry availability (not the config default).
        assert_eq!(p.emotions, crate::mood::telemetry_available());
    }

    fn test_config() -> crate::config::Config {
        let raw = r#"
            [general]
            [persona]
            tone = "casual"
            emotions = true
            language = "Spanish"
            [llm]
            model = "m"
            [llm.deepseek]
            api_key = "k"
            base_url = "https://api.deepseek.com/v1"
        "#;
        toml::from_str(raw).expect("config parses")
    }
}
