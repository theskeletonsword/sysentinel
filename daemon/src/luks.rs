// SPDX-License-Identifier: Apache-2.0
//!
//! LUKS tripwire follow-up ("¿fui yo?").
//!
//! When the initramfs hook (`ramdisk/91sysentinel/`) captures a LUKS boot —
//! primarily the pre-prompt hook that starts **before** the password prompt,
//! with a post-decrypt `sysentinel-luks.sh` fallback — it screenshots the
//! environment, mirrors evidence into the boot ESP(s) and into
//! `/var/lib/sysentinel/luks-evidence/`, and writes a marker file:
//!
//! ```text
//! luks_<kernel boot_id>.txt
//!   ok=<0|1>  boot_id=<id>  ts=<unix>  photo=<jpg name>  cam=<card|none>  hostname=<name>
//! ```
//!
//! This daemon only runs *after* a full (owner-confirmed) boot, so the marker
//! it finds is a *stale one left over from a previous abnormal boot*. It
//! dedupes by `boot_id`, asks the owner "¿fui yo?" (photo attached if a
//! webcam was present), and on `no` / timeout applies the configured deny
//! action (`poweroff`, `triplefault`, `none`) via `/proc/sysentinel_metrics`.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use crate::bot::{PendingLuks, SharedBotState};
use crate::config::Config;
use crate::llm;
use crate::settings::Settings;

/// Longest an unanswered "¿fui yo?" stays armed before the deny action runs.
fn luks_timeout(settings: &Arc<Mutex<Settings>>) -> u64 {
    settings.lock().expect("settings mutex").luks_timeout.max(10)
}

/// Walk the evidence locations: the daemon's own dir plus every exposed vfat
/// ESP (`/proc/mounts`), where the hook mirrors `<esp>/sysentinel/luks/`.
fn evidence_dirs(config: &Config) -> Vec<PathBuf> {
    let mut dirs = vec![PathBuf::from(&config.camera.evidence_dir)];

    if let Ok(mounts) = std::fs::read_to_string("/proc/mounts") {
        for line in mounts.lines() {
            // field[0]=dev field[1]=mountpoint field[2]=fs; skip non-vfat.
            let mut f = line.splitn(4, ' ');
            let (_dev, mnt, fs, _rest) = (f.next(), f.next(), f.next(), f.next());
            if let (Some(mnt), Some(fs)) = (mnt, fs) {
                if fs == "vfat" && !mnt.is_empty() {
                    dirs.push(Path::new(mnt).join("sysentinel/luks"));
                }
            }
        }
    }
    dirs
}

/// All marker files (newest first) across all evidence dirs.
fn collect_markers(config: &Config) -> Vec<(PathBuf, PathBuf)> {
    let mut out = Vec::new();
    for dir in evidence_dirs(config) {
        let Ok(entries) = std::fs::read_dir(&dir) else { continue };
        for e in entries.flatten() {
            let p = e.path();
            if p.is_file()
                && p.file_name()
                    .map(|n| {
                        let s = n.to_string_lossy();
                        s.starts_with("luks_") && s.ends_with(".txt")
                    })
                    .unwrap_or(false)
            {
                out.push((dir.clone(), p));
            }
        }
    }
    out.sort_by_key(|e| std::cmp::Reverse(e.1.mtime_s()));
    out
}

trait Mtime {
    fn mtime_s(&self) -> u64;
}
impl Mtime for PathBuf {
    fn mtime_s(&self) -> u64 {
        std::fs::metadata(self)
            .and_then(|m| m.modified())
            .ok()
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}

/// Decoded marker. Malformed lines are ignored; every value is optional.
#[derive(Default)]
struct Marker {
    boot_id: Option<String>,
    ts:      Option<u64>,
    photo:   Option<String>,
    cam:     Option<String>,
    host:    Option<String>,
    ok:      bool,
}

impl Marker {
    fn parse(body: &str) -> Marker {
        let mut m = Marker::default();
        for line in body.lines() {
            let line = line.trim();
            let Some(eq) = line.find('=') else { continue };
            let (k, v) = (line[..eq].trim(), line[eq + 1..].trim());
            if v.is_empty() {
                continue;
            }
            match k {
                "boot_id" => m.boot_id = Some(v.to_string()),
                "ts"      => m.ts = v.parse().ok(),
                "photo"   => m.photo = (!v.is_empty() && v != "none").then(|| v.to_string()),
                "cam"     => m.cam = Some(v.to_string()),
                "hostname"|"host" => m.host = Some(v.to_string()),
                "ok"      => m.ok = v == "1" || v == "true",
                _ => {}
            }
        }
        m
    }
}

/// The seen-file: one line per handled boot_id.
fn seen_file(config: &Config) -> PathBuf {
    Path::new(&config.general.settings_file)
        .parent()
        .map(|p| p.join("luks-seen.txt"))
        .unwrap_or_else(|| PathBuf::from("/var/lib/sysentinel/luks-seen.txt"))
}

fn already_seen(config: &Config, boot_id: &str) -> bool {
    std::fs::read_to_string(seen_file(config))
        .map(|s| s.lines().any(|l| l.split(' ').next() == Some(boot_id)))
        .unwrap_or(false)
}

fn mark_seen(config: &Config, boot_id: &str, verdict: &str) {
    let path = seen_file(config);
    let _ = std::fs::create_dir_all(path.parent().unwrap_or(Path::new("/")));
    if let Ok(mut f) = std::fs::OpenOptions::new().create(true).append(true).open(&path) {
        let ts = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0);
        let _ = writeln!(f, "{boot_id} {verdict} {ts}");
    }
}

/// Apply `luks_deny_action` by writing to `/proc/sysentinel_metrics`.
/// `none` → nothing. Returns whether the action ran.
pub fn apply_deny_action(action: &str) -> bool {
    let cmd = match action {
        "poweroff"     => "poweroff",
        "triplefault"  => "triplefault",
        _              => return false,
    };
    match std::fs::OpenOptions::new().write(true).open("/proc/sysentinel_metrics") {
        Ok(mut f) => {
            match f.write_all(format!("{cmd}\n").as_bytes()) {
                Ok(()) => {
                    log::error!("luks: deny action '{cmd}' issued to kernel");
                    true
                }
                Err(e) => {
                    log::error!("luks: deny action '{cmd}' failed: {e}");
                    false
                }
            }
        }
        Err(e) => {
            log::error!("luks: cannot open /proc/sysentinel_metrics for '{cmd}': {e}");
            false
        }
    }
}

/// Owner said the decrypt was theirs → record the verdict and disarm.
pub fn approve_and_clear(state: &Arc<Mutex<SharedBotState>>, chat_id: i64) -> Option<PendingLuks> {
    let mut guard = state.lock().expect("bot state mutex");
    let p = guard.pending_luks.take()?;
    if p.chat_id != chat_id {
        // Belongs to another chat; put it back.
        guard.pending_luks = Some(p);
        return None;
    }
    let mut p = p;
    p.answered = true;
    Some(p)
}

/// Owner denied the decrypt → apply the configured deny action and disarm.
pub fn deny_and_clear(
    state: &Arc<Mutex<SharedBotState>>,
    settings: &Arc<Mutex<Settings>>,
    chat_id: i64,
) -> Option<PendingLuks> {
    let pending = {
        let mut guard = state.lock().expect("bot state mutex");
        let p = guard.pending_luks.take()?;
        if p.chat_id != chat_id {
            guard.pending_luks = Some(p);
            return None;
        }
        Some(p)
    }?;

    let action = settings.lock().expect("settings mutex").luks_deny_action.clone();
    let did_run = apply_deny_action(&action);
    log::warn!(
        "luks: boot {} denied by user; deny_action={action} ran={did_run}",
        pending.boot_id
    );
    Some(pending)
}

/// Expire any pending ask whose deadline passed → deny, log, mark seen.
fn sweep_expired(
    config: &Config,
    state: &Arc<Mutex<SharedBotState>>,
    settings: &Arc<Mutex<Settings>>,
    dry_run: bool,
) {
    let (chat_id, expired) = {
        let guard = state.lock().expect("bot state mutex");
        guard
            .pending_luks
            .as_ref()
            .map(|p| (p.chat_id, p.is_expired()))
            .unwrap_or((0, false))
    };
    if !expired {
        return;
    }
    if dry_run {
        let boot = {
            let mut guard = state.lock().expect("bot state mutex");
            guard.pending_luks.take().map(|p| p.boot_id)
        };
        if let Some(boot) = boot {
            mark_seen(config, &boot, "expired-dry");
            log::info!("DRY RUN — luks: ask for boot {boot} expired; would deny");
        }
        return;
    }
    if let Some(p) = deny_and_clear(state, settings, chat_id) {
        mark_seen(config, &p.boot_id, "expired");
        log::warn!("luks: unanswered '¿fui yo?' for boot {} expired → deny fired", p.boot_id);
    }
}

/// The LUKS watcher thread. In `dry_run` nothing is sent and, crucially, no
/// deny action touches the machine — evidence is just marked "seen".
pub fn run_luks_loop(
    config: &Config,
    state: &Arc<Mutex<SharedBotState>>,
    settings: &Arc<Mutex<Settings>>,
    llm: &dyn llm::LlmBackend,
    dry_run: bool,
) {
    let mut ticks = 0u64;
    loop {
        std::thread::sleep(Duration::from_secs(1));
        ticks += 1;
        sweep_expired(config, state, settings, dry_run);
        // Scan for new markers every 5 s, and only after an early settle
        // delay (evidence dirs may still be flushing mounts at boot time).
        if ticks < 30 || !ticks.is_multiple_of(5) {
            continue;
        }
        scan_for_markers(config, state, settings, llm, dry_run);
    }
}

fn scan_for_markers(
    config: &Config,
    state: &Arc<Mutex<SharedBotState>>,
    settings: &Arc<Mutex<Settings>>,
    llm: &dyn llm::LlmBackend,
    dry_run: bool,
) {
    let current_boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .ok()
        .map(|s| s.trim().to_string());
    let paired = {
        let guard = state.lock().expect("bot state mutex");
        guard.paired_chat_id
    };
    let Some(chat_id) = paired else {
        run_pending_without_pair(config, state, settings, current_boot.as_deref(), dry_run);
        return;
    };

    // Never stack asks.
    {
        let guard = state.lock().expect("bot state mutex");
        if guard.pending_luks.is_some() {
            return;
        }
    }

    for (dir, path) in collect_markers(config) {
        let Ok(body) = std::fs::read_to_string(&path) else { continue };
        let marker = Marker::parse(&body);
        let Some(boot_id) = marker.boot_id else { continue };
        if already_seen(config, &boot_id) {
            continue;
        }
        // Owner's own boot: this marker is from *this* decrypted session, i.e.
        // the owner DID type the password. Forgive and never ask.
        if current_boot.as_deref() == Some(boot_id.as_str()) {
            mark_seen(config, &boot_id, "self");
            log::info!("luks: current boot {boot_id} decrypted by owner — forgiven");
            continue;
        }

        // New evidence → ask. Prefer the marker's matching photo in the same
        // dir; fall back to any cam_*.jpg there.
        let photo = marker
            .photo
            .as_ref()
            .map(|n| dir.join(n))
            .filter(|p| p.is_file())
            .or_else(|| {
                std::fs::read_dir(&dir)
                    .ok()
                    .and_then(|rd| {
                        rd.flatten()
                            .map(|e| e.path())
                            .filter(|p| {
                                p.file_name()
                                    .map(|n| n.to_string_lossy().starts_with("cam_"))
                                    .unwrap_or(false)
                            })
                            .max_by(|a, b| a.mtime_s().cmp(&b.mtime_s()))
                    })
            });

        let host = marker.host.clone().unwrap_or_else(|| "?".to_string());
        let ts = marker
            .ts
            .map(format_timestamp)
            .unwrap_or_else(|| "?.?".to_string());
        let cam = marker.cam.clone().unwrap_or_else(|| "none".to_string());
        let boot = if boot_id.len() > 12 { &boot_id[..12] } else { &boot_id };

        // Passive-ish ask → persona voice; the deny options stay appended.
        let facts = format!(
            "A LUKS boot was decrypted (ts {ts}, host `{host}`). boot_id `{boot}`, \
             camera used: `{cam}`. A photo may be attached."
        );
        let lead = speak_luks_persona(config, settings, llm, &facts);
        let caption = format!(
            "{lead}\n\nIf it **wasn't** you (or this doesn't ring a bell), reply `no` — \
             I'll apply the deny action and the evidence stays archived for you."
        );

        if dry_run {
            mark_seen(config, &boot_id, "asked-dry");
            log::info!("DRY RUN — luks: would ask owner about boot {boot_id}\n{caption}");
            return;
        }

        {
            let mut guard = state.lock().expect("bot state mutex");
            guard.pending_luks = Some(PendingLuks::new(
                boot_id.clone(),
                photo.clone(),
                chat_id,
                luks_timeout(settings),
            ));
        }

        let _ = if let Some(ph) = &photo {
            crate::bot::send_photo(&config.telegram.bot_token, chat_id, &caption, ph)
        } else {
            crate::bot::send_message(&config.telegram.bot_token, chat_id, &caption, Some("Markdown"))
        };
        log::warn!(
            "luks: asked owner about decrypt boot {boot_id} (photo={})",
            photo.is_some()
        );
        return;
    }
}

/// Speak a LUKS-tripwire ask through the persona — the "is it me?" question
/// in the machine's own voice. Falls back to raw facts when the LLM is off or
/// errors (the ask must always go out).
fn speak_luks_persona(
    config: &Config,
    settings: &Arc<Mutex<Settings>>,
    llm: &dyn llm::LlmBackend,
    facts: &str,
) -> String {
    if !config.llm.llm_enabled() {
        return format!("🚨 Is it me?\n\n{facts}");
    }
    let persona = llm::resolved_persona(config);
    let override_txt = {
        let g = settings.lock().expect("settings mutex");
        g.system_prompt_override.clone()
    };
    let sys_prompt = llm::effective_system_prompt(config, override_txt.as_deref());
    let directive = format!(
        "These are live facts / things that just happened on this machine. You ARE \
         the machine. The disk was decrypted at a boot that may or may not have been \
         the owner. Ask them, in YOUR voice, calmly and briefly, whether it was them —\n\
         NEVER a formatted log line, NEVER inventing anything beyond what's here.\n\
         IMPORTANT: this is a PASSIVE question, not a panic — the user is safe and the\n\
         evidence is archived. Your message is an ask, so end with a plain question.\n\
         language: {}\ntone: {}\n\
         Write in {}, with the persona above. Be brief (max 3 lines), no titles,\n\
         no preamble:\n\n{}",
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
        log::warn!("luks persona voice dropped ({e:#}); forwarding raw ask");
        format!("🚨 Is it me?\n\n{facts}")
    })
}

/// Unpaired chat. Never auto-deny the *current* boot (the owner is clearly
/// at the keyboard — they typed the password). Stale boot_ids from an
/// unattended/foreign decrypt get the deny action applied immediately, since
/// nobody is reachable to confirm; respect `luks_deny_action` (none = safe).
fn run_pending_without_pair(
    config: &Config,
    _state: &Arc<Mutex<SharedBotState>>,
    settings: &Arc<Mutex<Settings>>,
    current_boot: Option<&str>,
    dry_run: bool,
) {
    for (_dir, path) in collect_markers(config) {
        let Ok(body) = std::fs::read_to_string(&path) else { continue };
        let marker = Marker::parse(&body);
        let Some(boot_id) = marker.boot_id else { continue };
        if already_seen(config, &boot_id) {
            continue;
        }
        // Owner's own normal boot → forgive, never auto-deny.
        if current_boot == Some(boot_id.as_str()) {
            mark_seen(config, &boot_id, "self");
            log::info!("luks: current boot {boot_id} decrypted by owner — forgiven");
            continue;
        }
        mark_seen(config, &boot_id, "unpaired-denied");
        if dry_run {
            log::info!("DRY RUN — luks: stale boot {boot_id}, no pair; would deny");
            continue;
        }
        let action = settings.lock().expect("settings mutex").luks_deny_action.clone();
        let ran = apply_deny_action(&action);
        log::warn!(
            "luks: stale decrypt boot {boot_id} with no paired chat → deny '{}' (ran={ran})",
            action
        );
    }
}

fn format_timestamp(ts: u64) -> String {
    let c = chrono::DateTime::<chrono::Utc>::from_timestamp(ts as i64, 0);
    match c {
        Some(dt) => dt.format("%Y-%m-%d %H:%M:%S").to_string(),
        None => "1970-01-01 00:00:00".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn marker_parses_hook_output() {
        let body = "ok=1\nboot_id=12345678-1234-1234-1234-123456789abc\nts=1725000000\n\
                    photo=cam_12345678-1234.jpg\ncam=Integrated Camera\nhostname=myhost\n";
        let m = Marker::parse(body);
        assert_eq!(m.boot_id.as_deref(), Some("12345678-1234-1234-1234-123456789abc"));
        assert_eq!(m.ts, Some(1725000000));
        assert_eq!(m.photo.as_deref(), Some("cam_12345678-1234.jpg"));
        assert_eq!(m.cam.as_deref(), Some("Integrated Camera"));
        assert_eq!(m.host.as_deref(), Some("myhost"));
        assert!(m.ok);
    }

    #[test]
    fn marker_ignores_missing_photo_as_none() {
        let m = Marker::parse("boot_id=B\nphoto=none\n");
        assert_eq!(m.photo, None);
    }

    #[test]
    fn evidence_scan_and_dedupe() {
        let dir = std::env::temp_dir().join(format!("sysentinel-luks-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let evidence = dir.join("evidence");
        std::fs::create_dir_all(&evidence).unwrap();
        std::fs::write(
            evidence.join("luks_abc-123.txt"),
            "ok=1\nboot_id=abc-123\nts=1725000000\nphoto=cam_abc-123.jpg\n\
             cam=Integrated Camera\nhostname=h\n",
        )
        .unwrap();

        let raw = format!(
            "[general]\nsettings_file = \"{}/settings.json\"\n\
             [persona]\ntone = \"casual\"\n\
             [telegram]\nbot_token = \"t\"\n\
             [llm]\nmodel = \"m\"\n\
             [camera]\nevidence_dir = \"{}\"\n",
            dir.display(),
            evidence.display()
        );
        let cfg: crate::config::Config = toml::from_str(&raw).expect("config parses");
        assert_eq!(cfg.camera.evidence_dir, evidence.to_str().unwrap());

        // The scanner heeds the configured dir (plus any vfat ESP mount).
        let markers = collect_markers(&cfg);
        assert_eq!(markers.len(), 1);
        assert!(markers[0].1.ends_with("luks_abc-123.txt"));

        // Dedupe: a marker is seen once and never re-triggers.
        assert!(!already_seen(&cfg, "abc-123"));
        mark_seen(&cfg, "abc-123", "self");
        assert!(already_seen(&cfg, "abc-123"));

        let _ = std::fs::remove_dir_all(&dir);
    }
}