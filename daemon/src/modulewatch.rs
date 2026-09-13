// SPDX-License-Identifier: Apache-2.0
//!
//! Module watcher — someone `insmod` an unknown kernel module? The bot asks,
//! and (on request) disassembles the suspect with `objdump` for analysis.
//!
//! # Detection (pure userspace, Secure Boot safe)
//!
//! Polls `/proc/modules` every few seconds against a baseline. Any module that
//! was NOT present at the previous pass is a load event. The interesting case —
//! the one that arms the two-step ritual — is a module that cannot be
//! attributed to the running kernel's official module tree (`modinfo -F
//! filename <name>` fails): a *foreign* module, i.e. someone's hand-copied .ko.
//! Normal auto-loaded drivers (usb gadget plugged in, etc.) resolve inside the
//! tree and are only logged.
//!
//! # Conversation (the persona speaks, not canned strings)
//!
//! The watcher hands the event to the LLM persona with a directive (via
//! [`crate::main::speak_in_persona`]-style voice) asking in the user's own
//! language whether to remove it. Verdict words are then mapped to the armed
//! state machine in the bot:
//!
//! * `sácalo` / `remove it` → `rmmod <name>`
//! * `dejalo`/`no lo saques` → keep it loaded
//! * `no estoy seguro`   → the persona *explains* it will run `objdump` against
//!   the module and — on an API backend — warns conversationally that it
//!   consumes the user's tokens/billing and asks; on local backends it just
//!   proceeds. `dale` green-lights it.
//!
//! # objdump source
//!
//! The .ko binary is resolved via `modinfo -F filename`, else a shallow search
//! of the usual drop zones (`/tmp`, `/var/tmp`, `/dev/shm`, `/root`, `/home`).
//! If the attacker deleted it, we say so and skip.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::bot::SharedBotState;
use crate::config::Config;
use crate::llm;
use crate::settings::Settings;

/// One line of `/proc/modules`.
#[derive(Debug, Clone)]
pub struct ModuleInfo {
    pub name: String,
    pub size_kb: String,
    pub refcount: String,
    pub used_by: String,
    pub state: String,
}

/// A module that just appeared for the first time.
#[derive(Debug, Clone)]
pub struct ModuleEvent {
    pub info: ModuleInfo,
    /// True when the module is not in the running kernel's official tree.
    pub foreign: bool,
    /// Known source file (from modinfo) or None.
    pub ko_hint: Option<PathBuf>,
}

// ── /proc/modules parsing ─────────────────────────────────────────────────────

fn parse_modules_record(line: &str) -> Option<ModuleInfo> {
    // `name  size  refcount  used_by  state  address [taint]`
    let mut it = line.split_whitespace();
    let name = it.next()?.to_string();
    let size_kb = it.next().unwrap_or("-").to_string();
    let refcount = it.next().unwrap_or("-").to_string();
    let used_by = it.next().unwrap_or("-").to_string();
    let state = it.next().unwrap_or("-").to_string();
    Some(ModuleInfo { name, size_kb, refcount, used_by, state })
}

pub fn read_modules() -> Vec<ModuleInfo> {
    let raw = std::fs::read_to_string("/proc/modules").unwrap_or_default();
    raw.lines().filter_map(parse_modules_record).collect()
}

/// Resolve a module name to its file in the running kernel's official tree.
/// Returns the canonical .ko path when the module is "known".
pub fn modinfo_filename(name: &str) -> Option<PathBuf> {
    let out = Command::new("modinfo")
        .args(["-F", "filename", name])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let p = String::from_utf8_lossy(&out.stdout);
    let first = p.lines().next()?.trim();
    if first.is_empty() {
        return None;
    }
    let path = PathBuf::from(first);
    path.exists().then_some(path)
}

/// The .ko for a module currently loaded. Prefers the official tree; falls
/// back to the usual drop zones for hand-copied modules.
pub fn find_ko(name: &str) -> Option<PathBuf> {
    if let Some(p) = modinfo_filename(name) {
        return Some(p);
    }
    for dir in ["/tmp", "/var/tmp", "/dev/shm", "/root", "/home", "."] {
        if let Some(p) = find_in_dir(Path::new(dir), name, 4) {
            return Some(p);
        }
    }
    None
}

fn find_in_dir(dir: &Path, name: &str, depth: usize) -> Option<PathBuf> {
    if depth == 0 {
        return None;
    }
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return None,
    };
    for e in entries.flatten() {
        let p = e.path();
        let fname = e.file_name().to_string_lossy().into_owned();
        let is_ko = fname == format!("{name}.ko")
            || fname.starts_with(&format!("{name}.ko."));
        if is_ko {
            return Some(p);
        }
        if p.is_dir() {
            if let Some(hit) = find_in_dir(&p, name, depth - 1) {
                return Some(hit);
            }
        }
    }
    None
}

/// Decompress a (possibly .xz/.gz/.zst) module into private scratch space so
/// `objdump` can read it.
///
/// `None` for an uncompressed module: there is nothing to stage, and the
/// caller reads it where it lies.
fn materialize_ko(path: &Path) -> Option<crate::scratch::ScratchFile> {
    let raw = path.to_string_lossy();
    let (decompressor, args): (&str, &[&str]) = if raw.ends_with(".xz") {
        ("xz", &["-d", "-c"])
    } else if raw.ends_with(".gz") {
        ("gzip", &["-d", "-c"])
    } else if raw.ends_with(".zst") {
        ("zstd", &["-d", "-c"])
    } else {
        return None;
    };

    let out = Command::new(decompressor).args(args).arg(path).output().ok()?;
    if !out.status.success() {
        return None;
    }
    // Not `/tmp`: the name used to be `sysentinel_ko_<pid>_<name>`, which any
    // local user could pre-create as a symlink — and `fs::write` follows one,
    // so analysing a module could be turned into overwriting an arbitrary file
    // the daemon can reach. `scratch` writes with O_EXCL into a 0700 directory.
    match crate::scratch::write("ko", &out.stdout) {
        Ok(f) => Some(f),
        Err(e) => {
            log::warn!("modwatch: cannot stage {} for objdump: {e:#}", path.display());
            None
        }
    }
}

/// `objdump -d` the module (Intel syntax). Returns disassembly, truncated.
pub fn objdump_text(path: &Path) -> Option<String> {
    if Command::new("objdump").arg("--version").output().is_err() {
        return None;
    }
    // A compressed module is staged; an uncompressed one is read where it is.
    // The guard unlinks (and for nothing here, wipes) when this returns.
    match materialize_ko(path) {
        Some(staged) => objdump_raw(staged.path()),
        None => objdump_raw(path),
    }
}

fn objdump_raw(path: &Path) -> Option<String> {
    let out = Command::new("objdump")
        .args(["-d", "-M", "intel"])
        .arg(path)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    Some(truncate_disasm(&text))
}

fn truncate_disasm(text: &str) -> String {
    // Keep it compact for the LLM: first ~70 lines after the header, plus a
    // count of insns and a tail marker.
    let mut lines = text.lines();
    let header: Vec<&str> = lines.by_ref().take(8).collect();
    let body: Vec<&str> = lines.take(70).collect();
    let mut out = header.join("\n");
    out.push('\n');
    out.push_str(&body.join("\n"));
    out.push_str(&format!("\n… ({:?} lines trimmed; total {} bytes)\n", 70, text.len()));
    out
}

// ── Facts for the persona ─────────────────────────────────────────────────────

/// Compact fact block handed to the persona so it can speak in its own voice.
pub fn module_facts(ev: &ModuleEvent) -> String {
    let i = &ev.info;
    let ko = ev
        .ko_hint
        .as_ref()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|| "unknown/not found".to_string());
    format!(
        "A NEW KERNEL MODULE WAS JUST LOADED into the running kernel.\n\
         module: {}\nsize: {} kB\nrefcount: {}\nused_by: {}\nstate: {}\n\
         in official kernel module tree: {}\nko file: {}\n\
         The user must decide: remove it (unload), keep it, or is not sure. \
         Ask them, in YOUR voice, in the user's language — briefly, no log \
         formatting. Mention the module name and that it isn't in the official \
         tree if that's true.",
        i.name, i.size_kb, i.refcount, if i.used_by == "-" { "none" } else { &i.used_by },
        i.state,
        if ev.foreign { "NO (foreign — hand-placed)" } else { "yes" },
        ko
    )
}

// ── Watch loop ────────────────────────────────────────────────────────────────

/// Polls `/proc/modules`; foreign loads arm the armed state machine, with the
/// persona phrasing the question. Needs the LLM so it can speak in voice.
pub fn run_module_loop(
    config: &Config,
    state: &Arc<Mutex<SharedBotState>>,
    settings: &Arc<Mutex<Settings>>,
    llm: &dyn llm::LlmBackend,
    dry_run: bool,
) {
    let mut baseline: std::collections::HashSet<String> =
        read_modules().into_iter().map(|m| m.name.clone()).collect();

    log::info!("module-watch: watching /proc/modules for foreign loads");

    loop {
        std::thread::sleep(Duration::from_secs(3));

        let enabled = settings.lock().expect("settings mutex").modwatch;
        let now: Vec<_> = read_modules();
        let names: std::collections::HashSet<_> =
            now.iter().map(|m| m.name.clone()).collect();

        if !enabled {
            baseline = names;
            continue;
        }

        for m in &now {
            if baseline.contains(&m.name) {
                continue;
            }
            let ko_hint = modinfo_filename(&m.name);
            let foreign = ko_hint.is_none();
            let ev = ModuleEvent {
                info: m.clone(),
                foreign,
                ko_hint,
            };
            if !foreign {
                log::info!("module-watch: known module loaded: {}", m.name);
                continue;
            }
            log::warn!(
                "module-watch: FOREIGN module loaded: {} ({} kB, used_by {})",
                m.name, m.size_kb, m.used_by
            );
            announce_foreign(config, state, settings, llm, &ev, dry_run);
        }
        baseline = names;
    }
}

fn announce_foreign(
    config: &Config,
    state: &Arc<Mutex<SharedBotState>>,
    settings: &Arc<Mutex<Settings>>,
    llm: &dyn llm::LlmBackend,
    ev: &ModuleEvent,
    dry_run: bool,
) {
    let chat_id = {
        let g = state.lock().expect("bot state mutex");
        g.paired_chat_id
    };
    let Some(chat_id) = chat_id else {
        log::info!("module-watch: foreign module, not paired → logged only");
        return;
    };

    // Persona's voice, not a template.
    let facts = module_facts(ev);
    let text = speak_module_persona(config, settings, llm, &facts);

    // Arm the decision so verdict words resolve.
    {
        let mut g = state.lock().expect("bot state mutex");
        g.pending_module = Some(crate::bot::PendingModule::new(
            ev.info.clone(),
            ev.ko_hint.clone(),
            chat_id,
        ));
    }

    if dry_run {
        log::info!("DRY RUN — module-watch announce: {text}");
        return;
    }
    if crate::channel::notify(&text) == 0 {
        log::error!("module-watch: nobody could be reached with this announce");
    }
}

/// Speak through the persona with a module directive. Falls back to the
/// raw facts if the LLM is disabled.
fn speak_module_persona(
    config: &Config,
    settings: &Arc<Mutex<Settings>>,
    llm: &dyn llm::LlmBackend,
    facts: &str,
) -> String {
    if !config.llm.llm_enabled() {
        return facts.to_string();
    }
    let persona = llm::resolved_persona(config);
    let override_txt = {
        let g = settings.lock().expect("settings mutex");
        g.system_prompt_override.clone()
    };
    let sys_prompt = llm::effective_system_prompt(config, override_txt.as_deref());
    let directive = format!(
        "These are live facts / things that just happened on this machine. You ARE \
         the machine. Something just loaded a foreign kernel module — the user \
         needs to hear about it in YOUR voice, spontaneously, as a question to them,\n\
         NEVER a formatted log line.\n\
         language: {}\ntone: {}\n\
         Write in {}, with the persona above. Be brief (max 4 lines), no titles, \
         no preamble. Use only what's here:\n\n{}",
        persona.language,
        persona.tone,
        persona.language,
        facts
    );
    llm.explain(&llm::ExplainRequest {
        system_prompt: &sys_prompt,
        event_text: &directive,
        max_tokens: config.llm.max_tokens,
    })
    .unwrap_or_else(|e| {
        log::warn!("module persona voice dropped ({e:#}); forwarding raw facts");
        facts.to_string()
    })
}