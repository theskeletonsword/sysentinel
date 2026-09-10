// SPDX-License-Identifier: Apache-2.0
//!
//! sysentinel-daemon — your PC's AI companion.
//!
//! # What this does
//!
//! Three concurrent activities run for the life of the process:
//!
//! 1. **kmsg watcher** (main thread) — tails `/dev/kmsg` for OOM kills,
//!    kernel panics, segfaults, and oopses. On each event: asks the LLM to
//!    explain it in the configured tone, then sends a Telegram alert to the
//!    paired chat.
//!
//! 2. **Telegram bot** (background thread, optional) — long-polls
//!    `getUpdates` for incoming messages. Handles the pairing flow (one-time
//!    token, 5-minute window) and then routes conversational queries to the
//!    LLM with live system context (uptime, memory, kernel alerts, Intel ME /
//!    AMD PSP firmware version, PMU counters).
//!
//! 3. **Hardware diagnostics** (background thread, optional) — periodically
//!    calls `sensors`, reads PCI sysfs, queries ME/PSP, and sends a summary
//!    to Telegram.
//!
//! # Privilege model
//!
//! The daemon runs as a dedicated `sysentinel` system user with:
//!   - `CAP_SYSLOG`   — read `/dev/kmsg`
//!   - `CAP_PERFMON`  — read hardware PMU counters (optional, graceful fallback)
//!
//! No additional groups are needed. Intel ME firmware is queried in ring-0 by
//! the `sysentinel_metrics` kernel module and read back from `/proc/sysentinel_metrics`
//! (readable via a udev rule shipped by `scripts/install.sh`); AMD PSP / TPM
//! info is read from sysfs. Compatible with both Intel ME and AMD PSP hosts.
//!
//! See `scripts/sysentinel.service` for the full systemd unit.

mod bot;
mod battery;
mod bootkit_audit;
mod camera;
mod channel;
mod classify;
mod config;
mod confirm;
mod coretype;
mod detecthome;
mod dmesg;
mod facenn;
mod fhash;
mod fsprobe;
mod hal;
mod hwdiag;
mod hwinfo;
mod hyperwatch;
mod ipc;
mod kmsg;
mod kernel_snap;
mod llm;
mod loginwatch;
mod luks;
mod mei;
mod meiclients;
mod memory;
mod mood;
mod modulewatch;
mod pmu;
mod presence;
mod procinfo;
mod selinux;
mod settings;
mod ring3;
mod secureboot;
mod telegram;
mod tpmkey;
mod undervolt;

use anyhow::{Context, Result};
use bot::{SharedBotState, TelegramBot};
use clap::Parser;
use classify::Severity;
use config::Config;
use kmsg::KmsgReader;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

// ── CLI ───────────────────────────────────────────────────────────────────────

#[derive(Parser, Debug)]
#[command(
    name    = "sysentinel-daemon",
    version,
    about   = "Kernel log watchdog + interactive AI companion via Telegram",
    long_about = None,
)]
struct Args {
    /// Path to config.toml.
    #[arg(short, long, default_value = "/etc/sysentinel/config.toml")]
    config: PathBuf,

    /// Echo every classified kmsg event to stdout (does not suppress Telegram alerts).
    #[arg(long)]
    verbose: bool,

    /// Suppress Telegram alerts (useful for testing the LLM backend locally).
    #[arg(long)]
    dry_run: bool,
}

// ── Entry point ───────────────────────────────────────────────────────────────

fn main() -> Result<()> {
    // Initialise logging. Level defaults to `info`; override with RUST_LOG.
    env_logger::Builder::from_env(
        env_logger::Env::default().default_filter_or("info"),
    )
    .init();

    let args   = Args::parse();
    let config = Config::load(&args.config)
        .with_context(|| format!("loading config from {}", args.config.display()))?;

    // Resolve minimum severity for alerting.
    let min_severity = Severity::from_str_name(&config.general.min_severity)
        .context("general.min_severity is not a recognised severity name")?;

    // Shared bot state (paired chat_id, pairing token, recent alert buffer).
    let persisted_id = bot::load_paired_chat_id(&config);
    let shared_state: Arc<Mutex<SharedBotState>> =
        Arc::new(Mutex::new(SharedBotState::new(persisted_id)));

    // ── How this daemon reaches its owner ─────────────────────────────────────
    // Registered once; every watcher then says "reach the owner" without
    // knowing or caring which transport carries it. That is what makes the
    // transport replaceable: swapping Telegram for the phone app is a change
    // here, not across seven watchers.
    {
        let telegram = channel::TelegramChannel::new(&config, Arc::clone(&shared_state));
        channel::init(channel::Channels::new(vec![Box::new(telegram)]));

        if channel::is_deaf() {
            log::warn!(
                "no channel can reach you: this daemon will watch and never be able \
                 to report. Pair a channel, or the alerts go nowhere."
            );
        } else {
            log::info!("channels ready: {}", channel::ready_names().join(", "));
        }
        // Say out loud what the live channels expose, rather than leaving it
        // implied. A bot endpoint strangers can reach is a real property of
        // this setup and the owner should be reminded of it, not surprised.
        if let Some(note) = channel::exposure_note() {
            log::warn!("channel exposure — {note}");
        }
    }

    // Notification preferences (/settings) — shared with the bot and watchers.
    let settings: Arc<Mutex<settings::Settings>> = Arc::new(Mutex::new(
        settings::Settings::load(std::path::Path::new(&config.general.settings_file)),
    ));

    // Build the LLM fallback chain once, wrapped in a swappable handle so
    // `/llm` and `/settings backends` can exchange it live. A provider chosen
    // via `/llm` (persisted to the settings file) wins over `[llm].backend`.
    let llm_chain = {
        let guard = settings.lock().expect("settings mutex");
        guard.llm_chain(&config.llm.backend)
    };
    let prefs = {
        let s = settings.lock().expect("settings mutex");
        llm::RuntimePrefs {
            llama_ctx:  s.llama_ctx,
            local_ctx:  s.local_ctx,
            local_model: if s.local_model.is_empty() { None } else { Some(s.local_model.clone()) },
            model:       if s.llm_model.is_empty() { None } else { Some(s.llm_model.clone()) },
            models_by_provider: s.llm_models.clone(),
        }
    };
    let llm_backend = Arc::new(llm::RuntimeLlm::new(
        llm::build_chain(&config, &llm_chain, &prefs)
            .with_context(|| format!("initialising LLM fallback chain {llm_chain:?}"))?,
    ));
    let system_prompt = llm::build_system_prompt(&config);

    log::info!(
        "sysentinel-daemon starting — llm_chain={} telegram={} interactive={} \
         min_severity={:?} paired_chat_id={:?} settings_file={}",
        llm_chain.join(" → "),
        config.telegram.enabled,
        config.telegram.interactive,
        min_severity,
        persisted_id,
        config.general.settings_file,
    );

    // ── Firmware status (log at startup) ─────────────────────────────────────
    let fw_status = mei::query_firmware_status();
    if let Some(ref me) = fw_status.intel_me {
        log::info!("Intel ME firmware: {me}");
    }
    if let Some(ref psp) = fw_status.amd_psp {
        log::info!("AMD PSP: {psp}");
    }

    // ── Pairing token (when interactive mode is on) ───────────────────────────
    if config.telegram.enabled && config.telegram.interactive {
        // Only announce a new token if not already paired.
        if persisted_id.is_none() {
            bot::announce_pairing_token(
                &shared_state,
                &config,
                &config.telegram.bot_token,
            );
        } else if let Some(id) = persisted_id {
            log::info!("telegram: already paired with chat_id={id}");
        }
    }

    // ── Telegram bot thread ───────────────────────────────────────────────────
    if config.telegram.enabled && config.telegram.interactive {
        let tg_bot = TelegramBot::new(
            config.clone(),
            Arc::clone(&llm_backend),
            system_prompt.clone(),
            Arc::clone(&shared_state),
            Arc::clone(&settings),
        );
        thread::Builder::new()
            .name("telegram-bot".to_string())
            .spawn(move || tg_bot.run())
            .context("spawning Telegram bot thread")?;
        log::info!("telegram: interactive bot thread started");
    }

    // ── Live watcher thread (thresholds, htop, PMU, TSC) ─────────────────────
    let watch_state = Arc::clone(&shared_state);
    let watch_settings = Arc::clone(&settings);
    let watch_config = config.clone();
    let watch_dry = args.dry_run;
    let watch_llm: Arc<dyn llm::LlmBackend + Send + Sync> = llm_backend.clone();
    thread::Builder::new()
        .name("live-watch".to_string())
        .spawn(move || {
            run_watch_loop(
                &watch_config,
                &watch_state,
                &watch_settings,
                &watch_llm,
                watch_dry,
            )
        })
        .context("spawning live watcher thread")?;
    log::info!("live-watch: threshold + process monitor started");

    // ── Hardware diagnostics thread ───────────────────────────────────────────
    if config.hwdiag.enabled {
        let cfg2    = config.clone();
        let llm2    = Arc::clone(&llm_backend);
        let dry2    = args.dry_run;
        let state2  = Arc::clone(&shared_state);
        let settings2 = Arc::clone(&settings);
        thread::Builder::new()
            .name("hwdiag".to_string())
            .spawn(move || {
                run_hwdiag_loop(&cfg2, &*llm2, dry2, &state2, &settings2)
            })
            .context("spawning hwdiag thread")?;
        log::info!("hwdiag: periodic diagnostics thread started");
    }

    // ── Login watcher thread (wtmp → Telegram announce + kill ritual) ────────
    {
        let cfg3   = config.clone();
        let state3 = Arc::clone(&shared_state);
        let st3    = Arc::clone(&settings);
        let dry3   = args.dry_run;
        let llm3: Arc<llm::RuntimeLlm> = Arc::clone(&llm_backend);
        thread::Builder::new()
            .name("login-watch".to_string())
            .spawn(move || loginwatch::run_login_loop(&cfg3, &state3, &st3, llm3.as_ref(), dry3))
            .context("spawning login watcher thread")?;
        log::info!("login-watch: wtmp watcher thread started");
    }

    // ── LUKS tripwire watcher thread (¿fui yo? from initramfs evidence) ──────
    {
        let cfg3   = config.clone();
        let state3 = Arc::clone(&shared_state);
        let st3    = Arc::clone(&settings);
        let dry3   = args.dry_run;
        let llm3: Arc<llm::RuntimeLlm> = Arc::clone(&llm_backend);
        thread::Builder::new()
            .name("luks-watch".to_string())
            .spawn(move || luks::run_luks_loop(&cfg3, &state3, &st3, llm3.as_ref(), dry3))
            .context("spawning LUKS watcher thread")?;
        log::info!("luks-watch: evidence watcher thread started");
    }

    // ── Hypercall watcher thread (guest → hypervisor requests) ────────────────
    {
        let cfg4   = config.clone();
        let state4 = Arc::clone(&shared_state);
        let st4    = Arc::clone(&settings);
        let dry4   = args.dry_run;
        let llm4: Arc<llm::RuntimeLlm> = Arc::clone(&llm_backend);
        thread::Builder::new()
            .name("hypercall-watch".to_string())
            .spawn(move || hyperwatch::run_hypercall_loop(&cfg4, &state4, &st4, llm4.as_ref(), dry4))
            .context("spawning hypercall watcher thread")?;
        log::info!("hypercall-watch: guest hypercall watcher thread started");
    }

    // ── Foreign-module watcher thread ─────────────────────────────────────────
    {
        let cfg5   = config.clone();
        let state5 = Arc::clone(&shared_state);
        let st5    = Arc::clone(&settings);
        let dry5   = args.dry_run;
        let llm5: Arc<llm::RuntimeLlm> = Arc::clone(&llm_backend);
        thread::Builder::new()
            .name("module-watch".to_string())
            .spawn(move || {
                modulewatch::run_module_loop(&cfg5, &state5, &st5, llm5.as_ref(), dry5)
            })
            .context("spawning module watcher thread")?;
        log::info!("module-watch: foreign module watcher thread started");
    }

    // ── Battery watcher thread (notebooks only; desktop = "no aplica") ────────
    {
        let cfg6   = config.clone();
        let state6 = Arc::clone(&shared_state);
        let st6    = Arc::clone(&settings);
        let dry6   = args.dry_run;
        let llm6: Arc<llm::RuntimeLlm> = Arc::clone(&llm_backend);
        thread::Builder::new()
            .name("battery-watch".to_string())
            .spawn(move || battery::run_battery_loop(&cfg6, &state6, &st6, llm6.as_ref(), dry6))
            .context("spawning battery watcher thread")?;
        log::info!("battery-watch: battery watcher thread started");
    }

    // ── Local control socket for the desktop GUI (answers only, never pushes)
    if config.ipc.enabled {
        let cfg_ipc = config.clone();
        let st_ipc = Arc::clone(&settings);
        let llm_ipc: Arc<llm::RuntimeLlm> = Arc::clone(&llm_backend);
        thread::Builder::new()
            .name("ipc".to_string())
            .spawn(move || ipc::run_ipc_loop(&cfg_ipc, &st_ipc, llm_ipc.as_ref()))
            .context("spawning ipc thread")?;
        log::info!("ipc: local control socket thread started");
    }

    // ── Device watcher: keyboards and storage appearing on any bus ────────────
    {
        let cfg7 = config.clone();
        let state7 = Arc::clone(&shared_state);
        let st7 = Arc::clone(&settings);
        let dry7 = args.dry_run;
        let llm7: Arc<llm::RuntimeLlm> = Arc::clone(&llm_backend);
        thread::Builder::new()
            .name("device-watch".to_string())
            .spawn(move || presence::run_device_loop(&cfg7, &state7, &st7, llm7.as_ref(), dry7))
            .context("spawning device watcher thread")?;
        log::info!("device-watch: device watcher thread started");
    }

    // ── Main loop: watch /dev/kmsg ────────────────────────────────────────────
    let kmsg_llm: Arc<dyn llm::LlmBackend + Send + Sync> = llm_backend.clone();
    run_kmsg_loop(
        &config,
        min_severity,
        &kmsg_llm,
        &shared_state,
        &settings,
        args.verbose,
        args.dry_run,
    )
}

// ── kmsg watcher ──────────────────────────────────────────────────────────────

fn run_kmsg_loop(
    config:        &Config,
    min_severity:  Severity,
    llm:           &Arc<dyn llm::LlmBackend + Send + Sync>,
    state:         &Arc<Mutex<SharedBotState>>,
    settings:      &Arc<Mutex<settings::Settings>>,
    verbose:       bool,
    dry_run:       bool,
) -> Result<()> {
    let mut reader = KmsgReader::open_follow()
        .context("opening /dev/kmsg in follow mode (daemon needs CAP_SYSLOG)")?;

    log::info!("kmsg: watching /dev/kmsg for kernel events");

    loop {
        let record = match reader.next_record() {
            Ok(Some(r)) => r,
            Ok(None) => {
                thread::sleep(Duration::from_millis(config.general.poll_interval_ms));
                continue;
            }
            Err(e) => {
                log::error!("kmsg read error: {e:#}; retrying in 2s");
                thread::sleep(Duration::from_secs(2));
                continue;
            }
        };

        let Some(event) = classify::classify(&record) else { continue; };

        if verbose {
            log::info!(
                "[{:?}/{:?}] {}",
                event.kind, event.severity, event.raw_message
            );
        }

        let target_id = {
            let guard = state.lock().expect("bot state mutex");
            guard.paired_chat_id
                .or(config.telegram.chat_id)
                .filter(|&id| id != 0)
        };

        // ── SELinux denials: record, notify, and ASK the user ────────────────
        if event.kind == classify::EventKind::Selinux {
            let Some(denial) = state.lock().expect("bot state mutex").push_selinux(&event.raw_message)
            else {
                // Already ignored by the user or a duplicate — stay quiet.
                continue;
            };
            let id = denial.id;
            log::info!(
                "kmsg: SELinux denial #{id} recorded — {comm} denied {{{perms}}} on {tclass}",
                comm = denial.comm.as_deref().unwrap_or("?"),
                perms = denial.permissions,
                tclass = denial.tclass,
            );

            {
                let summary = format!(
                    "[SELinux] #{id} {} denied {{{}}} on {}",
                    denial.comm.as_deref().unwrap_or("?"),
                    denial.permissions,
                    denial.tclass,
                );
                state.lock().expect("bot state mutex").push_alert(summary);
            }

            let enabled = settings.lock().expect("settings mutex").selinux;
            if !enabled {
                continue;
            }

            // Phrase the denial in the persona's dialect (chileno o el que sea)
            // — cold log lines only if chatty_alerts is off. Persona + prompt
            // are resolved fresh so a `/systemprompt` override applies live.
            let persona = llm::resolved_persona(config);
            let persona_on = persona.chatty_alerts && config.llm.llm_enabled();
            let prompt = {
                let g = settings.lock().expect("settings mutex");
                llm::effective_system_prompt(config, g.system_prompt_override.as_deref())
            };
            let denied_human = speak_in_persona(
                llm,
                &prompt,
                config.llm.max_tokens,
                persona_on,
                &persona.language,
                &persona.tone,
                &format!(
                    "SELinux denied process {comm} the permissions {{{perms}}} on a \
                     {tclass} object (from {sctx} to {tctx}). You ARE the machine — \
                     tell the user about it in your own words.",
                    comm = denial.comm.as_deref().unwrap_or("???"),
                    perms = denial.permissions,
                    tclass = denial.tclass,
                    sctx = denial.scontext,
                    tctx = denial.tcontext,
                ),
            );

            let alert_text = format!(
                "⛔ *SELinux* — me bloquearon un acceso\n\n{denied_human}\n\n\
                 ¿De qué se trata, lo permito o lo dejo?\n\
                 *Explicar:* `/selinux explain {id}`\n\
                 *Permitir* (vas a confirmar): `/selinux allow {id}`\n\
                 *Denegar / ignorar:* `/selinux deny {id}`"
            );

            if dry_run {
                log::info!("DRY RUN — would send SELinux alert #{id}");
                continue;
            }
            if let Some(chat_id) = target_id {
                if let Err(e) = bot::send_message(
                    &config.telegram.bot_token,
                    chat_id,
                    &alert_text,
                    Some("Markdown"),
                ) {
                    log::error!("Telegram SELinux alert failed: {e:#}");
                }
            } else if config.telegram.enabled {
                log::warn!("SELinux denial not sent (not yet paired): {}", denial.raw);
            }
            continue;
        }

        if event.severity < min_severity {
            continue;
        }

        // Push to the shared alert buffer (for bot context) regardless of
        // notification preference.
        {
            let summary = format!("[{:?}] {}", event.kind, event.raw_message);
            let mut guard = state.lock().expect("bot state mutex");
            guard.push_alert(summary.clone());
            // Raw copy for the proactive reviewer's own judgement.
            guard.push_kmsg(summary);
        }

        // Respect /settings: the `kernel` category controls dmesg alerts.
        // Checked BEFORE the LLM call so disabled notifications cost zero
        // tokens (the summary above is still recorded for /alerts).
        let notify = settings.lock().expect("settings mutex").kernel;
        if dry_run || !notify {
            if dry_run {
                log::info!("DRY RUN — would explain+send: [{:?}] {}", event.kind, event.raw_message);
            }
            continue;
        }

        let event_text = format!(
            "Event kind: {:?}\nSeverity: {:?}\nKernel message: {}",
            event.kind, event.severity, event.raw_message
        );

        // Resolve prompt fresh so a `/systemprompt` override applies to kernel
        // alerts too, not just the interactive bot.
        let prompt = {
            let g = settings.lock().expect("settings mutex");
            llm::effective_system_prompt(config, g.system_prompt_override.as_deref())
        };

        // Ask the LLM to explain the event.
        let explanation = llm
            .explain(&llm::ExplainRequest {
                system_prompt: &prompt,
                event_text:    &event_text,
                max_tokens:    config.llm.max_tokens,
            })
            .unwrap_or_else(|e| {
                log::warn!("LLM explain failed, using raw message: {e:#}");
                event.raw_message.clone()
            });

        // Build alert text — the LLM's own words, nothing canned. It already
        // saw kind + severity in `event_text` and the persona tone in
        // `system_prompt`, so it decides how to phrase the alert.
        let alert_text = explanation.trim().to_string();

        // Send alert to paired chat_id (from persisted state or config).
        if let Some(chat_id) = target_id {
            if let Err(e) = bot::send_message(
                &config.telegram.bot_token,
                chat_id,
                &alert_text,
                Some("Markdown"),
            ) {
                log::error!("Telegram alert failed: {e:#}");
            }
        } else if config.telegram.enabled {
            // Not paired yet — just log it.
            log::warn!("kernel alert (not sent — not yet paired): {event_text}");
        }
    }
}

/// Have the machine *tell* the user about a situation, in its own words.
/// `facts` is raw sensor data / what happened — NOT a pre-written alert. The
/// LLM decides what to say, how, and in what dialect (the persona values).
/// Falls back to the raw facts text on any error; with backend "none" it
/// never costs a call (and just forwards the facts).
#[allow(clippy::too_many_arguments)]
fn speak_in_persona(
    llm:           &Arc<dyn llm::LlmBackend + Send + Sync>,
    system_prompt: &str,
    max_tokens:    u32,
    persona_on:    bool,
    language:      &str,
    tone:          &str,
    facts:         &str,
) -> String {
    if !persona_on {
        return facts.to_string();
    }
    // Internal instruction is English so it works for any persona language —
    // the user's dialect comes from the persona values passed below.
    let text = format!(
        "These are live facts / things that just happened on this machine. \
         You ARE the machine. As itself, decide whether the user needs to \
         hear about it, and if so tell them in YOUR voice — spontaneously, \
         with your own words, your own chosen details, NOT a formatted log \
         line.\n\
         IMPORTANT — always remember the user's configured language and \
         persona:\n\
         language: {language}\npersona/tone: {tone}\n\
         So write in {language}, with the persona personality above, never in \
         plain English unless {language} is English.\n\n\
         Be brief (max 4 lines), no titles, no preamble, no formal language. \
         Do not invent numbers; use only what's here:\n\n{facts}"
    );
    llm.explain(&llm::ExplainRequest {
        system_prompt,
        event_text: &text,
        max_tokens,
    })
    .unwrap_or_else(|e| {
        log::warn!("persona voice dropped ({e:#}); forwarding raw facts");
        facts.to_string()
    })
}

// ── Hardware diagnostics loop ─────────────────────────────────────────────────

fn run_hwdiag_loop(
    config:        &Config,
    llm:           &dyn llm::LlmBackend,
    dry_run:       bool,
    state:         &Arc<Mutex<SharedBotState>>,
    settings:      &Arc<Mutex<settings::Settings>>,
) {
    let interval = Duration::from_secs(config.hwdiag.interval_minutes * 60);
    let notifier = telegram::TelegramNotifier::new(&config.telegram);

    loop {
        thread::sleep(interval);

        // Only when the user enabled `diag` in /settings.
        if !settings.lock().expect("settings mutex").diag {
            log::debug!("hwdiag: suppressed (settings.diag off)");
            continue;
        }

        // Resolve the system prompt fresh so a `/systemprompt` override sticks.
        let prompt = {
            let g = settings.lock().expect("settings mutex");
            llm::effective_system_prompt(config, g.system_prompt_override.as_deref())
        };

        match hwdiag::summarize(config) {
            Ok(summary) => {
                let text = format!("🔧 *sysentinel* hardware diagnostics\n```\n{summary}\n```");
                if dry_run {
                    log::info!("DRY RUN hwdiag: {text}");
                    continue;
                }
                // Optionally ask LLM to comment on the diagnostics.
                let annotated = if config.llm.llm_enabled() {
                    llm.explain(&llm::ExplainRequest {
                        system_prompt: &prompt,
                        event_text:    &summary,
                        max_tokens:    config.llm.max_tokens,
                    })
                    .map(|explanation| {
                        format!("🔧 *sysentinel* hardware diagnostics\n\n{explanation}\n\n```\n{summary}\n```")
                    })
                    .unwrap_or(text)
                } else {
                    text
                };

                let target = {
                    let guard = state.lock().expect("bot state mutex");
                    guard.paired_chat_id
                        .filter(|&id| id != 0)
                        .or(config.telegram.chat_id.filter(|&id| id != 0))
                };
                if let Some(chat_id) = target {
                    if let Err(e) = bot::send_message(
                        &config.telegram.bot_token,
                        chat_id,
                        &annotated,
                        Some("Markdown"),
                    ) {
                        log::error!("hwdiag Telegram send failed: {e:#}");
                    }
                } else if let Err(e) = notifier.send(&annotated) {
                    log::warn!("hwdiag fallback notifier also failed: {e:#}");
                }
            }
            Err(e) => log::error!("hwdiag summarize() failed: {e:#}"),
        }
    }
}

// ── Live watcher ───────────────────────────────────────────────────────────────

/// Thresholds the live watcher acts on. Crossing into the danger band sends
/// one alert; recovering back under the safe floor re-arms it (edge
/// triggering, so sustained conditions don't spam Telegram).
const THERMAL_HOT_MC:  u32 = 85_000; // ≥85 °C → hot
const THERMAL_RESET_MC: u32 = 75_000; // <75 °C → clear
const MEM_LOW_MB:       u64 = 512;    // ≤512 MB free → pressure
const MEM_RESET_MB:     u64 = 1024;   // ≥1 GB free → clear
const LOAD_RATIO_HOT:   f64 = 4.0;    // load1 / ncpu ≥ 4 → overloaded
const LOAD_RATIO_RESET: f64 = 2.0;    // load1 / ncpu < 2 → clear
const PMU_STALL_IPC:    f64 = 0.5;    // IPC below this (sustained) → stall

fn run_watch_loop(
    config:       &Config,
    state:        &Arc<Mutex<SharedBotState>>,
    settings:     &Arc<Mutex<settings::Settings>>,
    llm:          &Arc<dyn llm::LlmBackend + Send + Sync>,
    dry_run:      bool,
) {
    let interval = Duration::from_secs(config.general.watch_interval_secs.max(5));
    let review_interval =
        Duration::from_secs(config.general.review_interval_secs.max(60));

    let mut hot      = false;
    let mut low_mem  = false;
    let mut overload = false;
    let mut pmu_stalls = 0u32;
    let mut tsc_bad  = false;
    let mut last_review = std::time::Instant::now();

    loop {
        thread::sleep(interval);

        let target = {
            let guard = state.lock().expect("bot state mutex");
            guard.paired_chat_id
                .or(config.telegram.chat_id)
                .filter(|&id| id != 0)
        };

        // Resolve persona + system prompt fresh each pass so a `/systemprompt`
        // override (and the auto-derived chatty_alerts flag) applies without a
        // daemon restart. `persona.chatty_alerts` is now derived from the live
        // LLM chain, so `persona_on` follows it.
        let persona = llm::resolved_persona(config);
        let persona_on = persona.chatty_alerts && config.llm.llm_enabled();
        let prompt_override = {
            let g = settings.lock().expect("settings mutex");
            g.system_prompt_override.clone()
        };
        let sys_prompt = llm::effective_system_prompt(config, prompt_override.as_deref());

        // Low-level delivery (dry-run aware). `deliver` sends text as-is;
        // `notify` lets the LLM compose the message from raw facts first.
        let deliver = |text: String| {
            if dry_run {
                log::info!("DRY RUN — live watch: {text}");
                return;
            }
            if let Some(chat_id) = target {
                if let Err(e) = bot::send_message(
                    &config.telegram.bot_token,
                    chat_id,
                    &text,
                    Some("Markdown"),
                ) {
                    log::error!("live watch Telegram send failed: {e:#}");
                }
            } else {
                log::debug!("live watch: not paired yet; suppressing: {text}");
            }
        };
        let notify = |facts: String| {
            if !persona_on {
                deliver(facts);
                return;
            }
            let text = speak_in_persona(
                llm,
                &sys_prompt,
                config.llm.max_tokens,
                persona_on,
                &persona.language,
                &persona.tone,
                &facts,
            );
            deliver(text);
        };

        // ── Thermal ─────────────────────────────────────────────────────────
        let temp_mc = read_peak_thermal_mc();
        if let Some(t) = temp_mc {
            let was_hot = hot;
            if t >= THERMAL_HOT_MC {
                hot = true;
            } else if t < THERMAL_RESET_MC {
                hot = false;
            }
            if !was_hot && hot
                && settings.lock().expect("settings mutex").thermal
            {
                notify(format!(
                    "live sensor facts — CPU temperature now {}°C (hot band \
                     is ≥{hot}°C, clears below {reset}°C); peak across all \
                     /sys/class/thermal zones.",
                    t / 1000,
                    hot = THERMAL_HOT_MC / 1000,
                    reset = THERMAL_RESET_MC / 1000,
                ));
            }
        }

        // ── Memory ──────────────────────────────────────────────────────────
        let (avail_mb, total_mb) = read_meminfo();
        if let Some(a) = avail_mb {
            let was_low = low_mem;
            if a <= MEM_LOW_MB {
                low_mem = true;
            } else if a >= MEM_RESET_MB {
                low_mem = false;
            }
            if !was_low && low_mem
                && settings.lock().expect("settings mutex").memory
            {
                notify(format!(
                    "live sensor facts — MemAvailable now {a} MB of {total} MB \
                     total (low band ≤{low} MB, clears ≥{reset} MB).",
                    total = total_mb.unwrap_or(0),
                    low = MEM_LOW_MB,
                    reset = MEM_RESET_MB,
                ));
            }
        }

        // ── Load average ────────────────────────────────────────────────────
        let (load1, ncpu) = read_load();
        if let (Some(l), Some(n)) = (load1, ncpu) {
            let ratio = l / n.max(1) as f64;
            let was_over = overload;
            if ratio >= LOAD_RATIO_HOT {
                overload = true;
            } else if ratio < LOAD_RATIO_RESET {
                overload = false;
            }
            let load_on = settings.lock().expect("settings mutex").load;
            if !was_over && overload && load_on {
                notify(format!(
                    "live sensor facts — load average 1 min = {l:.2} across \
                     {n} cores (ratio {ratio:.1}; hot band ≥{LOAD_RATIO_HOT}, \
                     clears <{LOAD_RATIO_RESET})."
                ));
            }
            // The top-CPU consumers ride along on overload edges (htop).
            if !was_over && overload
                && settings.lock().expect("settings mutex").htop
            {
                let rows = procinfo::top_processes(5, 2000);
                if !rows.is_empty() {
                    let mut facts =
                        String::from("live sensor facts — top CPU consumers right now \
                                      (pid, cpu%, rss MB, name):\n");
                    for r in &rows {
                        facts.push_str(&format!(
                            "{:>6}  {:5.1}%  {:6.1} MB  {}\n",
                            r.pid, r.cpu_pct, r.rss_mb, r.comm
                        ));
                    }
                    notify(facts);
                }
            }
        }

        // ── PMU (IPC) — sustained stall, not a single dip ───────────────────
        if settings.lock().expect("settings mutex").pmu {
            let ipc = crate::pmu::quick_snapshot().ipc;
            if let Some(ipc) = ipc {
                if ipc < PMU_STALL_IPC {
                    pmu_stalls = pmu_stalls.saturating_add(1);
                    if pmu_stalls == 2 {
                        notify(format!(
                            "live sensor facts — PMU IPC sustained at {ipc:.2} \
                             for 2 consecutive samples (stall band <{PMU_STALL_IPC}); \
                             the pipeline is choking (cache misses / branch \
                             mispredicts)."
                        ));
                    }
                } else {
                    pmu_stalls = 0;
                }
            }
        }

        // ── TSC / rdtscp stability ──────────────────────────────────────────
        if settings.lock().expect("settings mutex").tsc {
            let tsc = procinfo::tsc_status();
            let was_bad = tsc_bad;
            tsc_bad = !tsc.stable;
            if !was_bad && tsc_bad {
                notify(format!(
                    "live sensor facts — rdtscp measured {:.0} MHz vs nominal \
                     {} MHz (drift); TSC flagged unstable.",
                    tsc.measured_khz / 1000.0,
                    tsc.nominal_khz / 1000
                ));
            }
        }

        // ── Proactive review — the LLM decides whether to tell you anything ─
        if settings.lock().expect("settings mutex").proactive
            && config.llm.llm_enabled()
            && last_review.elapsed() >= review_interval
        {
            last_review = std::time::Instant::now();

            // Snapshot of every sensor this loop knows about.
            let mut snapshot = String::from("Current live sensors:\n");
            match read_peak_thermal_mc() {
                Some(t) => snapshot.push_str(&format!(
                    "  cpu temperature: {}°C\n",
                    t / 1000
                )),
                None => snapshot.push_str("  cpu temperature: n/a\n"),
            }
            let (a, tot) = read_meminfo();
            snapshot.push_str(&format!(
                "  memory available: {} MB / {} MB\n",
                a.map_or_else(|| "n/a".to_string(), |v| v.to_string()),
                tot.map_or_else(|| "n/a".to_string(), |v| v.to_string()),
            ));
            let (l, n) = read_load();
            snapshot.push_str(&format!(
                "  load avg (1 min): {} across {} cores\n",
                l.map_or_else(|| "n/a".to_string(), |v| format!("{v:.2}")),
                n.map_or_else(|| "n/a".to_string(), |v| v.to_string()),
            ));
            if let Some(ipc) = crate::pmu::quick_snapshot().ipc {
                snapshot.push_str(&format!("  pmu IPC: {ipc:.2}\n"));
            }
            let tsc = procinfo::tsc_status();
            snapshot.push_str(&format!(
                "  tsc: {:.0} MHz (nominal {} MHz), stable={}\n",
                tsc.measured_khz / 1000.0,
                tsc.nominal_khz / 1000,
                tsc.stable,
            ));

            let events = state
                .lock()
                .expect("bot state mutex")
                .drain_kmsg();
            let kmsg = if events.is_empty() {
                "  no notable kernel events this window".to_string()
            } else {
                format!("Recent kernel events:\n{}", events.join("\n"))
            };

            let prompt = format!(
                "{snapshot}\n{kmsg}\n\n\
                 You ARE this machine. Review the above. If anything is worth \
                 telling the user — an anomaly, a change, a risk, or even just \
                 something interesting — tell them spontaneously in your persona \
                 voice.\n\
                 IMPORTANT — language: {language}; persona/tone: {tone}. Write your \
                 message in that language/dialect, brief (max 4 lines).\n\
                 If NOTHING is worth telling, reply with exactly the single word:\n\
                 SILENT",
                language = persona.language,
                tone     = persona.tone,
            );

            match llm.explain(&llm::ExplainRequest {
                system_prompt: &sys_prompt,
                event_text: &prompt,
                max_tokens: config.llm.max_tokens,
            }) {
                Ok(reply) => {
                    let reply = reply.trim().to_string();
                    if reply == "SILENT" || reply.starts_with("SILENT\n") {
                        log::debug!("proactive review: machine chose SILENT");
                    } else {
                        deliver(reply);
                    }
                }
                Err(e) => log::warn!("proactive review failed: {e:#} (staying silent)"),
            }
        }
    }
}

/// Peak temperature in millidegrees (reading the same thermal zones mood does).
fn read_peak_thermal_mc() -> Option<u32> {
    let zones: Vec<_> = std::fs::read_dir("/sys/class/thermal")
        .ok()?
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with("thermal_zone"))
        .collect();
    if zones.is_empty() {
        return None;
    }
    let mut peak: Option<u32> = None;
    for zone in zones {
        if let Ok(raw) = std::fs::read_to_string(zone.path().join("temp")) {
            if let Ok(mc) = raw.trim().parse::<u32>() {
                if mc > 0 && mc < 200_000 {
                    peak = Some(peak.map_or(mc, |p| p.max(mc)));
                }
            }
        }
    }
    peak
}

/// (MemAvailable MB, MemTotal MB).
fn read_meminfo() -> (Option<u64>, Option<u64>) {
    let mut avail = None;
    let mut total = None;
    if let Ok(raw) = std::fs::read_to_string("/proc/meminfo") {
        for line in raw.lines() {
            if let Some(v) = line.strip_prefix("MemAvailable:") {
                avail = v.split_whitespace().next().and_then(|s| s.parse::<u64>().ok()).map(|kb| kb / 1024);
            }
            if let Some(v) = line.strip_prefix("MemTotal:") {
                total = v.split_whitespace().next().and_then(|s| s.parse::<u64>().ok()).map(|kb| kb / 1024);
            }
        }
    }
    (avail, total)
}

/// (load1, ncpu) from /proc/loadavg + /proc/cpuinfo.
fn read_load() -> (Option<f64>, Option<usize>) {
    let load = std::fs::read_to_string("/proc/loadavg")
        .ok()
        .and_then(|raw| raw.split_whitespace().next().and_then(|s| s.parse().ok()));
    let ncpu = std::fs::read_to_string("/proc/cpuinfo")
        .ok()
        .map(|raw| raw.lines().filter(|l| l.starts_with("processor")).count())
        .filter(|&n| n > 0);
    (load, ncpu)
}
