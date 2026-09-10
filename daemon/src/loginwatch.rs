// SPDX-License-Identifier: Apache-2.0
//!
//! Login watcher — announces every login (GUI and SSH) so an unauthorised
//! session can be killed before it does damage.
//!
//! # Data source
//!
//! Incrementally tails `/var/log/wtmp` (successful logins), starting at EOF so
//! history is never replayed. `/logins` shows the current snapshot instead.
//!
//! # Two-step ritual (like the privileged controls)
//!
//! 1. A login lands → the bot announces it and arms a [`bot::PendingLogin`].
//! 2. The user replies `si fui yo` (keep it) or `no` (kill the session).
//!    Without an answer within `login_timeout` seconds the session closes if
//!    `login_auto_close` is on — by default the bot prefers to be safe and
//!    kicks it.
//!
//! # Closing a session (ring-3 fallback; Secure Boot safe)
//!
//! `close_session` is pure userspace: SIGTERM→SIGKILL the recorded login PID,
//! then `loginctl terminate-session` for the matching session. The kernel
//! module additionally accepts `killsession <pid>` if the daemon holds
//! `write_gid`/CAP_SYS_ADMIN — attempted when the proc node is writable.

use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::bot::{self, PendingLogin, SharedBotState};
use crate::camera::{self, CamResult};
use crate::config::Config;
use crate::llm;
use crate::settings::Settings;

// ── Glibc utmpx constants ─────────────────────────────────────────────────────

const USER_PROCESS: libc::c_short = 7;

// NOTE: glibc's `struct utmpx` is 384 bytes; we stream records of exactly
// `size_of::<libc::utmpx>()` bytes (validated at runtime, not hard-coded).
const MAX_UTMPX: usize = 384;

/// What kind of login landed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoginChannel {
    /// Wayland/X session (ut_line starts with ':').
    Gui,
    /// Remote shell (non-local ut_host).
    Ssh,
    /// Console on a tty.
    Tty,
}

impl LoginChannel {
    pub fn label(&self) -> &'static str {
        match self {
            LoginChannel::Gui => "GUI",
            LoginChannel::Ssh => "SSH",
            LoginChannel::Tty => "consola",
        }
    }
    pub fn emoji(&self) -> &'static str {
        match self {
            LoginChannel::Gui => "🖥️",
            LoginChannel::Ssh => "🌐",
            LoginChannel::Tty => "⌨️",
        }
    }
}

/// One login record parsed from wtmp.
#[derive(Debug, Clone)]
pub struct LoginEvent {
    pub user: String,
    pub channel: LoginChannel,
    pub host: String,
    pub line: String,
    pub pid: i32,
    pub when_label: String,
}

// ── Incremental wtmp tailer ───────────────────────────────────────────────────

struct RecordTailer {
    path: String,
    file: std::fs::File,
    last_ino: u64,
}

impl RecordTailer {
    fn open(path: &str) -> Option<Self> {
        let file = std::fs::File::open(path).ok()?;
        let ino = file.metadata().ok().map(|m| m.ino()).unwrap_or(0);
        let mut t = RecordTailer { path: path.to_string(), file, last_ino: ino };
        // Start at EOF: only NEW records alert (history is /logins' job).
        let _ = t.file.seek(SeekFrom::End(0));
        Some(t)
    }

    /// Handle log rotation (file replaced → reopen and stream from the start).
    fn ensure_fresh(&mut self) {
        let Ok(meta) = std::fs::metadata(&self.path) else { return };
        if meta.ino() != self.last_ino {
            if let Ok(f) = std::fs::File::open(&self.path) {
                log::info!("loginwatch: {} rotated; re-opened", self.path);
                self.file = f;
                self.last_ino = meta.ino();
                let _ = self.file.seek(SeekFrom::Start(0));
            }
        }
    }

    /// Read any NEW successful-login records since the last call.
    fn poll(&mut self) -> Vec<LoginEvent> {
        let mut raw = Vec::new();
        self.poll_raw(&mut raw);
        raw.into_iter()
            .filter(|rec| rec.ut_type == USER_PROCESS && !user_name(rec).is_empty())
            .map(|rec| parse_record(&rec))
            .collect()
    }

    /// Read any NEW raw utmpx records (any type) since the last call — used
    /// for `/var/log/btmp` (failed login attempts).
    fn poll_raw(&mut self, out: &mut Vec<libc::utmpx>) {
        self.ensure_fresh();
        let len = std::mem::size_of::<libc::utmpx>();
        loop {
            let mut rec: libc::utmpx = unsafe { std::mem::zeroed() };
            let filled = read_exact_rec(&mut self.file, &mut rec, len);
            if filled < len {
                break; // EOF / torn record — re-poll later
            }
            out.push(rec);
        }
    }
}

fn read_exact_rec(f: &mut std::fs::File, rec: &mut libc::utmpx, len: usize) -> usize {
    debug_assert!(len <= MAX_UTMPX);
    let mut buf = [0u8; MAX_UTMPX];
    let mut filled = 0;
    loop {
        match f.read(&mut buf[filled..len]) {
            Ok(0) => break,
            Ok(k) => filled += k,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => break,
        }
        if filled >= len {
            break;
        }
    }
    if filled == len {
        unsafe {
            std::ptr::copy_nonoverlapping(buf.as_ptr(), rec as *mut _ as *mut u8, len);
        }
    }
    filled
}

fn cstr(arr: &[libc::c_char]) -> String {
    let bytes: Vec<u8> = arr
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as u8)
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

fn user_name(rec: &libc::utmpx) -> String {
    cstr(&rec.ut_user)
}

fn parse_record(rec: &libc::utmpx) -> LoginEvent {
    let line = cstr(&rec.ut_line);
    let host = cstr(&rec.ut_host);
    LoginEvent {
        user: user_name(rec),
        channel: classify_channel(&line, &host),
        host,
        line,
        pid: rec.ut_pid,
        when_label: time_label(rec.ut_tv.tv_sec as i64),
    }
}

/// GUI if ut_line starts with ':' (a display), SSH if there is a remote host,
/// else a console login.
fn classify_channel(line: &str, host: &str) -> LoginChannel {
    if line.starts_with(':') {
        LoginChannel::Gui
    } else if !host.is_empty()
        && host != "localhost"
        && !host.starts_with("127.")
        && !host.starts_with("::1")
    {
        LoginChannel::Ssh
    } else {
        LoginChannel::Tty
    }
}

fn time_label(secs: i64) -> String {
    let sys = std::time::UNIX_EPOCH + Duration::from_secs(secs.max(0) as u64);
    chrono::DateTime::<chrono::Utc>::from(sys)
        .format("%Y-%m-%d %H:%M UTC")
        .to_string()
}

// ── Public loop ───────────────────────────────────────────────────────────────

/// Tracks failed login attempts within a rolling window; returns `true` once
/// each time the window *crosses* the threshold (a new brute-force burst).
struct FailureTracker {
    window: std::collections::VecDeque<(std::time::Instant, libc::utmpx)>,
    above: bool,
}

impl FailureTracker {
    fn new() -> Self {
        Self { window: std::collections::VecDeque::new(), above: false }
    }
    /// Add one failed attempt. Returns `true` when `count ≥ threshold` and
    /// this is the record that crossed the line (alerts once per burst).
    fn push(&mut self, rec: libc::utmpx, threshold: usize, window: Duration) -> bool {
        let now = std::time::Instant::now();
        while self
            .window
            .front()
            .map(|(t, _)| now.duration_since(*t) > window)
            .unwrap_or(false)
        {
            self.window.pop_front();
        }
        self.window.push_back((now, rec));
        let crossed = !self.above && self.window.len() >= threshold;
        self.above = self.window.len() >= threshold;
        crossed
    }
}

/// Send a Markdown alert with a webcam photo attached when a camera is
/// configured; plain text otherwise.
fn send_with_photo(
    config: &Config,
    chat_id: i64,
    text: &str,
    dry_run: bool,
) {
    let shot_dir = {
        let mut d = std::path::PathBuf::from(&config.camera.evidence_dir);
        d.push("login");
        d
    };
    if config.camera.enabled && !dry_run {
        match camera::capture(&config.camera, &shot_dir) {
            CamResult::Photo { path } => {
                // Local face check (only when enrolled): the neural pipeline
                // when `sysentinel-face` is installed, perceptual hashes
                // otherwise. No tokens either way, and no images retained.
                let face_line = if config.face.enabled {
                    crate::facenn::verdict_line(&config.face, &path)
                } else {
                    None
                };
                let fatal = match &face_line {
                    Some(l) if l.contains("NO registrado") => l,
                    _ => "",
                };
                let caption = if fatal.is_empty() {
                    text.to_string()
                } else {
                    format!("{text}\n\n{fatal}")
                };
                if let Err(e) =
                    bot::send_photo(&config.telegram.bot_token, chat_id, &caption, &path)
                {
                    log::warn!("loginwatch photo alert failed: {e:#}; text only");
                    let _ = bot::send_message(
                        &config.telegram.bot_token, chat_id, &caption, Some("Markdown"),
                    );
                }
                return;
            }
            CamResult::NoWebcam => {
                // No camera → text-only alert is the agreed behaviour.
            }
            CamResult::CaptureFailed => {
                log::warn!("loginwatch: photo capture failed; sending text only");
            }
        }
    }
    let _ = bot::send_message(&config.telegram.bot_token, chat_id, text, Some("Markdown"));
}

/// Speak a login-watcher fact through the persona — passive notices are told
/// in the machine's own voice, never a canned template. Falls back to raw
/// facts when the LLM is off or errors (backend "none" costs no calls).
fn speak_login_persona(
    config: &Config,
    settings: &Arc<Mutex<Settings>>,
    llm: &dyn llm::LlmBackend,
    subject: &str,
    facts: &str,
) -> String {
    if !config.llm.llm_enabled() {
        return format!("{subject}: {facts}");
    }
    let persona = llm::resolved_persona(config);
    let override_txt = {
        let g = settings.lock().expect("settings mutex");
        g.system_prompt_override.clone()
    };
    let sys_prompt = llm::effective_system_prompt(config, override_txt.as_deref());
    let directive = format!(
        "These are live facts / things that just happened on this machine. You ARE \
         the machine. {subject} — this is a PASSIVE observation, NOT a catastrophe:\n\
         do not panic, do not ask for confirmation or propose drastic actions; just\n\
         tell the user about it in YOUR voice, spontaneously, in your own words, NEVER\n\
         a formatted log line, NEVER inventing anything beyond what's here.\n\
         language: {}\ntone: {}\n\
         Write in {}, with the persona above. Be brief (max 4 lines), no titles,\n\
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
        log::warn!("login persona voice dropped ({e:#}); forwarding raw facts");
        format!("{subject}: {facts}")
    })
}

/// Watches wtmp for new logins, arms a [`PendingLogin`] per login, and sweeps
/// expired pending decisions (auto-close or keep, per settings). Also tails
/// btmp and raises an intruder alert once a burst crosses the configured
/// `login_fail_threshold`.
pub fn run_login_loop(
    config: &Config,
    state: &Arc<Mutex<SharedBotState>>,
    settings: &Arc<Mutex<Settings>>,
    llm: &dyn llm::LlmBackend,
    dry_run: bool,
) {
    let mut tailer = match RecordTailer::open("/var/log/wtmp") {
        Some(t) => t,
        None => {
            log::error!("loginwatch: cannot open /var/log/wtmp — login alerts disabled");
            RecordTailer{ path: "/var/log/wtmp".into(), file: std::fs::File::open("/dev/null").expect("open /dev/null"), last_ino: 0 }
        }
    };
    // Failed-login tailer. Non-fatal: brute-force alerts need btmp to exist.
    let mut fail_tailer = RecordTailer::open("/var/log/btmp");
    let mut fails = FailureTracker::new();

    log::info!("loginwatch: streaming /var/log/wtmp for new logins (GUI + SSH)");

    loop {
        std::thread::sleep(Duration::from_secs(2));

        let timeout = settings.lock().expect("settings mutex").login_timeout;
        let auto_close = settings.lock().expect("settings mutex").login_auto_close;
        let login_on = settings.lock().expect("settings mutex").login;

        if login_on {
            for ev in tailer.poll() {
                announce_login(config, state, settings, llm, &ev, dry_run);
            }

            // Brute-force detection from btmp (failed attempts).
            if let Some(t) = &mut fail_tailer {
                let threshold = config.camera.login_fail_threshold.max(1) as usize;
                let window = Duration::from_secs(config.camera.fail_window_minutes.saturating_mul(60));
                let mut raw = Vec::new();
                t.poll_raw(&mut raw);
                for rec in raw {
                    if user_name(&rec).is_empty() {
                        continue;
                    }
                    if fails.push(rec, threshold, window) {
                        announce_fail_burst(config, state, settings, llm, dry_run, threshold, fails.window.back());
                    }
                }
            }
        } else {
            // Drain records while disabled so we don't replay history later.
            let _ = tailer.poll();
        }

        sweep_expired(config, state, settings, timeout, auto_close, llm, dry_run);
    }
}

fn announce_login(
    config: &Config,
    state: &Arc<Mutex<SharedBotState>>,
    settings: &Arc<Mutex<Settings>>,
    llm: &dyn llm::LlmBackend,
    ev: &LoginEvent,
    dry_run: bool,
) {
    let timeout = settings.lock().expect("settings mutex").login_timeout;
    let chat_id = {
        let g = state.lock().expect("bot state mutex");
        g.paired_chat_id.or(config.telegram.chat_id).filter(|&id| id != 0)
    };
    let Some(chat_id) = chat_id else {
        log::info!("loginwatch: login by {} ({}), not paired → logged only", ev.user, ev.channel.label());
        return;
    };

    // Arm the decision. A burst replaces the pending one; each new login
    // demands its own verdict.
    {
        let mut g = state.lock().expect("bot state mutex");
        g.pending_login = Some(PendingLogin::new(ev.clone(), chat_id, timeout));
    }
    log::warn!(
        "loginwatch: LOGIN — {} [{}] pid={} host={} — awaiting verdict",
        ev.user, ev.channel.label(), ev.pid,
        if ev.host.is_empty() { "-" } else { &ev.host }
    );

    // Passive notice → persona voice. The verdict options stay appended so
    // the yes/no flow keeps working.
    let host_txt = if ev.host.is_empty() { "none".to_string() } else { ev.host.clone() };
    let facts = format!(
        "user={} channel={} ({} {}) tty={} pid={} host={}",
        ev.user, ev.channel.label(), ev.channel.emoji(), ev.channel.label(), ev.line, ev.pid, host_txt
    );
    let lead = speak_login_persona(
        config, settings, llm,
        "a new login just landed on this machine",
        &facts,
    );
    let text = format!(
        "{lead}\n\n¿Fuiste tú? Responde *`si fui yo`* para dejarla, *`no`* para cerrar.\n\
         ⏳ Sin respuesta en {timeout}s se cierra por defecto."
    );
    if dry_run {
        log::info!("DRY RUN — loginwatch: {text}");
        return;
    }
    send_with_photo(config, chat_id, &text, dry_run);
}

/// A brute-force burst crossed `login_fail_threshold` failed attempts within
/// the window. `last` is the most recent failed record (edit-most recent).
fn announce_fail_burst(
    config: &Config,
    state: &Arc<Mutex<SharedBotState>>,
    settings: &Arc<Mutex<Settings>>,
    llm: &dyn llm::LlmBackend,
    dry_run: bool,
    threshold: usize,
    last: Option<&(std::time::Instant, libc::utmpx)>,
) {
    let chat_id = {
        let g = state.lock().expect("bot state mutex");
        g.paired_chat_id.or(config.telegram.chat_id).filter(|&id| id != 0)
    };
    let Some(chat_id) = chat_id else {
        log::info!(
            "loginwatch: failed-login burst (≥{threshold}), not paired → logged only"
        );
        return;
    };
    let Some((_, rec)) = last else { return };

    let user = user_name(rec);
    let line = cstr(&rec.ut_line);
    let host = cstr(&rec.ut_host);
    let who = if user.is_empty() { "?" } else { &user };
    let when = time_label(rec.ut_tv.tv_sec as i64);
    let facts = format!(
        "{} failed login attempts crossed the threshold in the window. Last attempt: \
         user={} tty={} host={} around {}.{}",
        threshold, who, line,
        if host.is_empty() { "none" } else { host.as_str() },
        when, if user.is_empty() { " (unknown user)" } else { "" },
    );
    let lead = speak_login_persona(
        config, settings, llm,
        "someone keeps failing to log in — a brute-force burst",
        &facts,
    );
    let text = format!(
        "{lead}\n\nWebcam photo attached if available. Check who's at the keyboard."
    );
    log::warn!(
        "loginwatch: FAIL BURST — {n} failed attempts in window (user={user} line={line} host={host})",
        n = threshold,
    );
    if dry_run {
        log::info!("DRY RUN — loginwatch fail burst: {text}");
        return;
    }
    send_with_photo(config, chat_id, &text, dry_run);
}

/// Called by the bot when the user confirms `si fui yo`. Returns true when a
/// login for this chat was pending and has been approved (session kept).
pub fn approve_pending(state: &Arc<Mutex<SharedBotState>>, chat_id: i64) -> bool {
    let mut g = state.lock().expect("bot state mutex");
    match g.pending_login.take() {
        Some(p) if p.chat_id == chat_id => {
            log::info!("loginwatch: login by {} approved by user", p.event.user);
            true
        }
        Some(p) => {
            g.pending_login = Some(p);
            false
        }
        None => false,
    }
}

/// Called by the bot when the user says `no` — closes the session.
pub fn deny_pending(state: &Arc<Mutex<SharedBotState>>, chat_id: i64) -> Option<PendingLogin> {
    let mut g = state.lock().expect("bot state mutex");
    match g.pending_login.take() {
        Some(p) if p.chat_id == chat_id => Some(p),
        Some(p) => {
            g.pending_login = Some(p);
            None
        }
        None => None,
    }
}

/// Set the pending login for `/login kill <pid>` (manual takeover).
pub fn arm_manual_kill(state: &Arc<Mutex<SharedBotState>>, chat_id: i64, ev: &LoginEvent, timeout: u64) {
    let mut g = state.lock().expect("bot state mutex");
    g.pending_login = Some(PendingLogin::new(ev.clone(), chat_id, timeout));
}

fn sweep_expired(
    config: &Config,
    state: &Arc<Mutex<SharedBotState>>,
    settings: &Arc<Mutex<Settings>>,
    _timeout: u64,
    auto_close: bool,
    llm: &dyn llm::LlmBackend,
    dry_run: bool,
) {
    let pending = {
        let mut g = state.lock().expect("bot state mutex");
        let out = g.pending_login.as_ref().filter(|p| p.is_expired()).cloned();
        if out.is_some() {
            g.pending_login = None;
        }
        out
    };
    let Some(p) = pending else { return };

    let chat_id = {
        let g = state.lock().expect("bot state mutex");
        g.paired_chat_id.or(config.telegram.chat_id).filter(|&id| id != 0)
    };
    let _ = &chat_id;

    if auto_close {
        let closed = close_session(&p);
        log::warn!(
            "loginwatch: timeout auto-close for {} pid={} closed={}",
            p.event.user, p.event.pid, closed
        );
        let facts = format!(
            "Unconfirmed session: user={} channel={} pid={} was not approved within \
             the timeout. I tried to close it — closed={}.",
            p.event.user,
            p.event.channel.label(),
            p.event.pid,
            closed,
        );
        let lead = speak_login_persona(
            config, settings,
            llm, "an unconfirmed login session timed out",
            &facts,
        );
        let txt = format!(
            "{lead}\n{}",
            if closed {
                "🗑️ Session closed.".to_string()
            } else {
                format!("⚠️ Could not close it — `/login kill {}` to retry.", p.event.pid)
            }
        );
        if dry_run {
            log::info!("DRY RUN — loginwatch timeout: {txt}");
            return;
        }
        if let Some(chat_id) = chat_id {
            if let Err(e) = bot::send_message(&config.telegram.bot_token, chat_id, &txt, Some("Markdown")) {
                log::error!("loginwatch timeout alert failed: {e:#}");
            }
        }
    } else {
        let facts = format!(
            "Unconfirmed session: user={} channel={} pid={} timed out — I left it open \
             because login_auto_close is disabled.",
            p.event.user, p.event.channel.label(), p.event.pid,
        );
        let lead = speak_login_persona(
            config, settings,
            llm, "an unconfirmed login session was left open",
            &facts,
        );
        let txt = format!(
            "{lead}\nClose it yourself with `/login kill {}` if it was an intruder.",
            p.event.pid,
        );
        log::warn!("loginwatch: timeout, auto_close off — left session by {} open", p.event.user);
        if dry_run {
            log::info!("DRY RUN — loginwatch timeout (keep): {txt}");
            return;
        }
        if let Some(chat_id) = chat_id {
            let _ = bot::send_message(&config.telegram.bot_token, chat_id, &txt, Some("Markdown"));
        }
    }
}

// ── Session termination (ring-3; Secure Boot safe) ───────────────────────────

/// Kill the session recorded in a pending login. Returns true if any method
/// reported success.
pub fn close_session(p: &PendingLogin) -> bool {
    let mut ok = false;
    log::warn!("loginwatch: closing session pid={} user={}", p.event.pid, p.event.user);

    // 1) Direct signal kill of the recorded login pid.
    if p.event.pid > 1 {
        unsafe {
            if libc::kill(p.event.pid, libc::SIGTERM) == 0 {
                ok = true;
            }
        }
        std::thread::sleep(Duration::from_millis(350));
        unsafe {
            if libc::kill(p.event.pid, 0) == 0 {
                libc::kill(p.event.pid, libc::SIGKILL);
                ok = true;
            }
        }
    }

    // 2) systemd: terminate the matching login session.
    if let Some(session) = find_session_by_pid(p.event.pid) {
        if let Ok(o) = std::process::Command::new("loginctl")
            .args(["terminate-session", &session]).output()
        {
            if o.status.success() {
                ok = true;
            }
        }
    }

    // 3) Kernel module (privileged; only reachable via the module's own
    //    write gate — usually root, so best-effort).
    if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open("/proc/sysentinel_metrics") {
        use std::io::Write;
        if f.write_all(format!("killsession {}\n", p.event.pid).as_bytes()).is_ok() {
            ok = true;
            log::info!("loginwatch: kernel module accepted killsession {}", p.event.pid);
        }
    }

    ok
}

/// Best-effort `loginctl list-sessions` → session id for the given pid.
fn find_session_by_pid(pid: i32) -> Option<String> {
    let out = std::process::Command::new("loginctl")
        .args(["list-sessions", "--no-legend", "--no-pager"])
        .output().ok()?;
    if !out.status.success() {
        return None;
    }
    let raw = String::from_utf8_lossy(&out.stdout);
    for line in raw.lines() {
        let mut it = line.split_whitespace();
        let id = it.next()?;
        let _uid = it.next()?;
        let _user = it.next()?;
        let _seat = it.next()?;
        let _tty = it.next()?;
        let pid_s = it.next()?;
        if pid_s.parse::<i32>().ok() == Some(pid) {
            return Some(id.to_string());
        }
    }
    None
}

/// Snapshot for `/logins`: USER_PROCESS records from the tail of wtmp.
pub fn current_logins(max: usize) -> Vec<LoginEvent> {
    let mut tailer = match RecordTailer::open("/var/log/wtmp") {
        Some(t) => t,
        None => return vec![],
    };
    // Only the last ~half of the file is consulted (logins stay live).
    let _ = tailer.file.seek(SeekFrom::Start(0));
    let all = tailer.poll();
    let mut recent = all;
    recent.sort_by(|a, b| b.when_label.cmp(&a.when_label));
    recent.truncate(max);
    recent
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rec() -> libc::utmpx {
        let mut r: libc::utmpx = unsafe { std::mem::zeroed() };
        r.ut_type = 0;
        r.ut_pid = 1;
        r
    }

    #[test]
    fn failure_tracker_crosses_threshold_once() {
        let mut t = FailureTracker::new();
        let w = Duration::from_secs(600);
        assert!(!t.push(rec(), 3, w));
        assert!(!t.push(rec(), 3, w));
        // Crossing the line → alert fires exactly once.
        assert!(t.push(rec(), 3, w));
        assert!(!t.push(rec(), 3, w));
    }

    #[test]
    fn failure_tracker_rearms_after_window() {
        let mut t = FailureTracker::new();
        let w = Duration::from_secs(600);
        assert!(!t.push(rec(), 2, w));
        assert!(t.push(rec(), 2, w));
        // Simulate the whole window aging out: a fresh burst alerts again.
        t.window.clear();
        t.above = false;
        assert!(!t.push(rec(), 2, w));
        assert!(t.push(rec(), 2, w));
    }
}