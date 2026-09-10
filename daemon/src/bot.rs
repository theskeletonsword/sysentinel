// SPDX-License-Identifier: Apache-2.0
//!
//! Interactive Telegram bot — pairing, whitelist, and conversational AI.
//!
//! # Architecture
//!
//! This module runs a long-polling `getUpdates` loop in a dedicated thread.
//! It shares [`SharedBotState`] with the main kmsg-watcher thread via
//! `Arc<Mutex<SharedBotState>>`.
//!
//! ## Pairing flow
//!
//! 1. On daemon start a random, one-time **pairing token** is generated and
//!    printed to the daemon's log (visible via `journalctl -u sysentinel`).
//!    Format: `SYN-XXXXX` (5 uppercase alphanumeric characters, ~32-bit entropy).
//! 2. The user opens Telegram, sends that token to the bot.
//! 3. The bot validates: correct token AND within the 5-minute window.
//! 4. On success: the sender's `chat_id` is saved to the state file
//!    (`/var/lib/sysentinel/state.json`), the token is invalidated immediately,
//!    and a confirmation message is sent.
//! 5. From this point on, only messages from the paired `chat_id` are processed.
//!    Any other sender receives a "not paired" reply.
//!
//! ## Interactive chat
//!
//! Once paired, any free-form message to the bot is forwarded to the configured
//! LLM backend together with:
//! - The configured persona system prompt.
//! - A live snapshot of the system (uptime, memory, recent kernel alerts,
//!   Intel ME / AMD PSP firmware version).
//!
//! Special commands (always start with `/`):
//! - `/status`   — short system snapshot.
//! - `/alerts`   — last N kernel alerts caught by the kmsg watcher.
//! - `/firmware` — Intel ME / AMD PSP firmware status.
//! - `/help`     — command list.
//! - `/unpair`   — remove this chat_id from the whitelist (re-pairing required).
//!
//! ## Security properties
//!
//! - One paired `chat_id` per daemon instance (no multi-user support).
//! - Pairing token has 5-minute hard expiry; expired tokens are rejected.
//! - Token is invalidated immediately on first successful use.
//! - State file is written with mode 0600 (owner-read-only).
//! - No inbound commands are accepted before pairing is complete.

use crate::config::Config;
use crate::kernel_snap;
use crate::llm::{self, ChatRequest, LlmBackend, PROVIDER_NAMES};
use crate::mei;
use crate::memory::MemoryStore;
use crate::selinux::{self, AvcDenial};
use crate::settings::Settings;
use crate::loginwatch;
use anyhow::{Context, Result};
use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
};
use password_hash::{rand_core::OsRng, SaltString};
use serde::{Deserialize, Serialize};
use std::collections::{HashSet, VecDeque};
use std::io::{Read, Write as IoWrite};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

// ── Pairing state ─────────────────────────────────────────────────────────────

/// A one-time pairing token with a hard 5-minute expiry, **bound to a single
/// Telegram user id**.
///
/// The token is meaningless on its own: it only succeeds when presented by the
/// user whose `from.id` equals [`PairingToken::target_user_id`]. This is the
/// core binding that stops a third party who merely copies the printed token
/// from pairing their own chat and hijacking the daemon.
///
/// # Token hardening (Argon2id)
///
/// The plaintext token is generated from `/dev/urandom` and shown **once** in
/// the daemon log. What the daemon keeps in memory is the Argon2id hash of the
/// token with a random salt (`SaltString::generate(&mut OsRng)` — OsRng reads
/// `/dev/urandom` on Linux). The bot verifies a presented token by re-hashing
/// it with the stored salt and comparing against the hash. A token that leaks
/// from a memory/state dump therefore cannot be brute-forced or replayed.
///
/// # Binding enforcement — two independent layers
///
/// 1. The bot rejects any sender whose `from.id` differs from
///    `target_user_id` (in `handle_pairing`).
/// 2. As a belt-and-braces measure, the configured `telegram_id` whitelist in
///    `[telegram]` is applied globally in `handle_message`, so a foreign user
///    never even reaches pairing logic.
pub struct PairingToken {
    /// Plaintext token, held in memory ONLY so it can be logged/announced
    /// once at startup. Never persisted anywhere.
    pub token:          String,
    /// Argon2id PHC hash of the token (`$argon2id$v=19$m=19456,t=2,p=1$…$…`).
    /// The only representation the daemon keeps for verification.
    pub token_hash:     String,
    /// The Telegram user id (`from.id`) this token is bound to.
    pub target_user_id: i64,
    pub expires_at:     Instant,
    /// We asked this user for an explicit identity confirmation ("YES")
    /// after they presented the correct token. Only `true` unlocks the
    /// final pairing step.
    pub awaiting_confirm: bool,
    /// Consecutive invalid token attempts. Burn the token after
    /// [`PairingToken::MAX_FAILED_ATTEMPTS`] to stop brute-forcing.
    pub failed_attempts:  u32,
}

impl PairingToken {
    const TTL: Duration = Duration::from_secs(5 * 60); // exactly 5 minutes
    /// Burn the token after this many invalid attempts.
    const MAX_FAILED_ATTEMPTS: u32 = 5;

    /// Generate a fresh token bound to `target_user_id`.
    /// Randomness comes from `/dev/urandom`: directly for the token characters,
    /// and via `OsRng` for the Argon2id salt. 8 bytes → 8 unambiguous chars
    /// from a 32-symbol alphabet (~40 bits of entropy), one-time use.
    pub fn generate(target_user_id: i64) -> Self {
        let mut bytes = [0u8; 8];
        let mut f = std::fs::File::open("/dev/urandom")
            .expect("opening /dev/urandom for token generation");
        f.read_exact(&mut bytes).expect("reading /dev/urandom");
        // Unambiguous charset: no 0/O, 1/I/L, no lowercase.
        const CHARSET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";
        let token: String = bytes.iter()
            .map(|b| CHARSET[(*b as usize) % CHARSET.len()] as char)
            .collect();
        let token = format!("SYN-{token}");

        // Argon2id hash with a fresh random salt (~16 bytes from OsRng).
        let salt = SaltString::generate(&mut OsRng);
        let hash = Argon2::default()
            .hash_password(token.as_bytes(), &salt)
            .expect("Argon2id hashing cannot fail with valid parameters")
            .to_string();

        Self {
            token,
            token_hash: hash,
            target_user_id,
            expires_at: Instant::now() + Self::TTL,
            awaiting_confirm: false,
            failed_attempts: 0,
        }
    }

    /// Constant-ish Argon2id verification of a presented token against the
    /// stored hash. A correct token returns `true`, anything else `false`.
    /// This is what "no lien pueden romper el token" means in practice: the
    /// stored blob is a salted PHC hash, not the shared secret.
    // Covered by the pairing unit tests; the live path verifies via `check_token`.
    #[allow(dead_code)]
    pub fn verify(&self, presented: &str) -> bool {
        // Normalise what the user typed: trim whitespace and case-fold to
        // uppercase (the token charset is case-insensitive by convention:
        // A-Z, 2-9). This absorbs copy/paste noise without weakening anything,
        // because the token alphabet has no ambiguous chars.
        let presented = presented.trim().to_uppercase();

        let Ok(parsed) = PasswordHash::new(&self.token_hash) else {
            log::error!("stored pairing-token hash is not a valid PHC string");
            return false;
        };

        // SAFETY-NOTE: `PasswordVerifier`'s `verify_password` times out to a
        // constant length whether the hash parses or the password mismatches,
        // defeating timing-based token guessing.
        match Argon2::default().verify_password(presented.as_bytes(), &parsed) {
            Ok(()) => true,
            Err(_) => false,
        }
    }

    /// Record one invalid token attempt. Returns `true` if the token must be
    /// burned (attempt limit reached) so the daemon logs it loudly.
    pub fn record_failure(&mut self) -> bool {
        self.failed_attempts += 1;
        self.failed_attempts >= Self::MAX_FAILED_ATTEMPTS
    }

    pub fn remaining_attempts(&self) -> u32 {
        Self::MAX_FAILED_ATTEMPTS.saturating_sub(self.failed_attempts)
    }

    /// Immediately make the token unusable (used on burn / over-limit).
    pub fn burn(&mut self) {
        self.expires_at = Instant::now() - Duration::from_secs(1);
    }

    pub fn is_valid(&self) -> bool {
        Instant::now() < self.expires_at
    }

    /// True when `sender_id` is the exact user this token was minted for.
    pub fn matches_user(&self, sender_id: i64) -> bool {
        self.target_user_id == sender_id
    }

    pub fn seconds_remaining(&self) -> u64 {
        self.expires_at
            .checked_duration_since(Instant::now())
            .unwrap_or(Duration::ZERO)
            .as_secs()
    }
}

// ── Shared bot state ──────────────────────────────────────────────────────────

/// Snapshot of the pending pairing token, copied out of the mutex so it can
/// be verified without holding the lock during Argon2 evaluation.
#[derive(Clone)]
struct PendingPairing {
    hash:              String,
    is_valid:          bool,
    bound_to_sender:   bool,
    awaiting_confirm:  bool,
    // Snapshot of the token budget, kept for logging/diagnostics.
    #[allow(dead_code)]
    remaining_attempts: u32,
    seconds_remaining: u64,
}

impl PendingPairing {
    /// Argon2id verification against the stored hash.
    fn verify(&self, presented: &str) -> bool {
        let Ok(parsed) = PasswordHash::new(&self.hash) else {
            return false;
        };
        Argon2::default().verify_password(presented.as_bytes(), &parsed).is_ok()
    }
}

/// State shared between the kmsg-watcher thread and the Telegram bot thread.
pub struct SharedBotState {
    /// Paired Telegram chat ID, or `None` before pairing.
    pub paired_chat_id: Option<i64>,
    /// Current pending pairing token (if any).
    pub pairing_token:  Option<PairingToken>,
    /// Circular buffer of the last N kernel alert summaries for context.
    pub recent_alerts:  VecDeque<String>,
    /// Raw classified kmsg events (short summaries) since the last *proactive*
    /// review drained them. Feeds the LLM's own decision to tell (or stay
    /// silent). Never grows unbounded.
    pub recent_kmsg:    VecDeque<String>,
    /// A privileged action awaiting explicit confirmation (armed state).
    pub(crate) pending_control: Option<PendingControl>,
    /// Per-daemon-run latch for the `triplefault*` controls: one shot per
    /// session, so a reboot/power-off can never loop. Cleared by a real
    /// daemon restart (i.e. after the machine reboots), or explicitly via
    /// `/triplefault allow` when the host somehow came back.
    pub(crate) triplefault_fired: bool,
    /// Recent unresolved SELinux AVC denials, with stable ids.
    pub recent_selinux: VecDeque<AvcDenial>,
    /// Fingerprints of denials the user chose to ignore (`/selinux deny`).
    pub selinux_ignored: HashSet<String>,
    /// Monotonic id source for `recent_selinux`.
    next_selinux_id: u32,
    /// An `allow` of a SELinux denial awaiting `confirm` (armed state).
    pub(crate) pending_selinux: Option<PendingSelinuxAllow>,
    /// A login that has been *armed* (announced) but not yet confirmed.
    /// Set by the login watcher; resolved by `si fui yo` / `no` or timeout.
    pub(crate) pending_login: Option<PendingLogin>,
    /// A LUKS "¿fui yo?" ask from the initramfs tripwire (evidence seen
    /// post-boot, photo attached if a webcam was present pre-login).
    /// Resolved by `si fui yo` / `no`, or by `luks_timeout` via the deny
    /// action (poweroff / triplefault / none).
    pub(crate) pending_luks: Option<PendingLuks>,
    /// A foreign module waiting for the owner's verdict.
    pub(crate) pending_module: Option<PendingModule>,
    /// Photos still expected for `/face register` (0 = not arming). While > 0,
    /// incoming photo messages are consumed and hashed locally (never stored
    /// as images — only pHash/wHash 64-bit values, per zero-token policy).
    pub(crate) face_pending: u32,
}

/// A privileged control command that has been *armed* but not yet confirmed.
///
/// The kernel module is dangerous by design (reboot, poweroff, CR register
/// writes). These commands therefore travel through a two-step ritual:
/// first the user arms one (`/reboot`), then confirms it (`confirm`) within
/// `CONFIRMATION_WINDOW`, from the same paired chat. Nothing reaches the
/// kernel module until both steps complete.
pub(crate) struct PendingControl {
    kind: ControlKind,
    /// Chat that armed the action — only the same chat may confirm it.
    chat_id: i64,
    /// When this armed action expires (never confirmed ⇒ no execution).
    expires: std::time::Instant,
    /// Language-free execution code: the user replies this exact code to
    /// confirm, so no hardcoded yes-word in any language ever gates execution.
    nonce: String,
}

impl PendingControl {
    const CONFIRMATION_WINDOW: std::time::Duration =
        std::time::Duration::from_secs(60);

    fn new(kind: ControlKind, chat_id: i64) -> Self {
        Self {
            kind,
            chat_id,
            expires: std::time::Instant::now() + Self::CONFIRMATION_WINDOW,
            nonce: fresh_confirm_nonce(),
        }
    }

    fn is_expired(&self) -> bool {
        self.expires < std::time::Instant::now()
    }
}

/// Mint a one-time `CONFIRM-XXXXXX` code from `/dev/urandom`. Unambiguous
/// charset (no 0/O, 1/I/L), case-insensitive by convention. 6 chars ≈ 30 bits
/// of entropy — not a secret against the *same* paired chat (which could do
/// ~1M guesses in the 60 s window), but the real gate is that only the paired
/// chat can reach this prompt at all, so the code is a human intent beacon.
fn fresh_confirm_nonce() -> String {
    let mut bytes = [0u8; 6];
    if std::fs::File::open("/dev/urandom")
        .and_then(|mut f| {
            use std::io::Read;
            f.read_exact(&mut bytes)
        })
        .is_err()
    {
        // Non-secret fallback: partition-id drift, so the code is still
        // one-time-only per process lifetime. Windows/dev boxes without
        // /dev/urandom should never reach here on Linux, but never panic.
        let seed = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0x5A5A_5A5A_5A5A_5A5A);
        let mut x = seed;
        for b in bytes.iter_mut() {
            x = x.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            *b = (x >> 33) as u8;
        }
    }
    const CHARSET: &[u8] = b"ABCDEFGHJKMNPQRSTUVWXYZ23456789";
    let code: String = bytes
        .iter()
        .map(|b| CHARSET[(*b as usize) % CHARSET.len()] as char)
        .collect();
    format!("CONFIRM-{code}")
}

/// An SELinux `allow` that has been *armed* (`/selinux allow <id>`) but not
/// yet confirmed. Same two-step ritual as `PendingControl`: policy changes to
/// a mandatorily-enforcing LSM are privileged and confirmed explicitly.
pub(crate) struct PendingSelinuxAllow {
    denial: AvcDenial,
    /// Chat that armed the allow — only the same chat may confirm it.
    chat_id: i64,
    /// When this armed action expires.
    expires: std::time::Instant,
}

impl PendingSelinuxAllow {
    const CONFIRMATION_WINDOW: std::time::Duration =
        std::time::Duration::from_secs(60);

    fn new(denial: AvcDenial, chat_id: i64) -> Self {
        Self {
            denial,
            chat_id,
            expires: std::time::Instant::now() + Self::CONFIRMATION_WINDOW,
        }
    }

    fn is_expired(&self) -> bool {
        self.expires < std::time::Instant::now()
    }
}

/// A login that has been *armed* (announced) but not yet confirmed by the
/// user.  The watcher sets it; the bot's `si fui yo` / `no` answers resolve
/// it, as does a timeout.
#[derive(Clone)]
pub(crate) struct PendingLogin {
    pub event: crate::loginwatch::LoginEvent,
    /// Only the paired chat that saw the announcement may confirm/deny it.
    pub chat_id: i64,
    /// When this decision expires.
    pub expires: std::time::Instant,
}

impl PendingLogin {
    pub fn new(event: crate::loginwatch::LoginEvent, chat_id: i64, timeout_secs: u64) -> Self {
        Self {
            event,
            chat_id,
            expires: std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs),
        }
    }
    pub fn is_expired(&self) -> bool {
        self.expires < std::time::Instant::now()
    }
}

/// A LUKS "¿fui yo?" ask armed by the initramfs tripwire evidence.
#[derive(Clone)]
pub(crate) struct PendingLuks {
    /// Kernel boot_id of the decrypted boot (the dedupe key).
    pub boot_id: String,
    /// Photo taken by the initramfs hook, if a webcam was present.
    // Kept as the record of which frame was sent; the photo goes out at ask time.
    #[allow(dead_code)]
    pub photo: Option<std::path::PathBuf>,
    /// Only the paired chat that saw the ask may answer it.
    pub chat_id: i64,
    /// When this decision expires (→ `luks_deny_action`).
    pub expires: std::time::Instant,
    /// Whether the user confirmed it before expiry.
    pub answered: bool,
}

impl PendingLuks {
    pub fn new(boot_id: String, photo: Option<std::path::PathBuf>, chat_id: i64, timeout_secs: u64) -> Self {
        Self {
            boot_id,
            photo,
            chat_id,
            expires: std::time::Instant::now() + std::time::Duration::from_secs(timeout_secs),
            answered: false,
        }
    }
    pub fn is_expired(&self) -> bool {
        self.expires < std::time::Instant::now()
    }
}

/// The two conversational steps of a foreign-module verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ModulePhase {
    /// Waiting for the owner's verdict (remove / keep / investigate).
    AwaitVerdict,
    /// The persona warned about billing (API) and waits for the go-ahead.
    AwaitAnalysisGo,
}

/// A foreign kernel module that has been *armed* (announced by the watcher)
/// but whose verdict is still pending.
#[derive(Clone, Debug)]
pub(crate) struct PendingModule {
    pub name: String,
    pub size_kb: String,
    pub used_by: String,
    /// Source on disk for a future `objdump` (may be None if the .ko is gone).
    pub ko: Option<std::path::PathBuf>,
    pub chat_id: i64,
    pub phase: ModulePhase,
    pub expires: std::time::Instant,
}

impl PendingModule {
    pub fn new(
        info: crate::modulewatch::ModuleInfo,
        ko: Option<std::path::PathBuf>,
        chat_id: i64,
    ) -> Self {
        Self {
            name: info.name,
            size_kb: info.size_kb,
            used_by: info.used_by,
            ko,
            chat_id,
            phase: ModulePhase::AwaitVerdict,
            expires: std::time::Instant::now() + std::time::Duration::from_secs(300),
        }
    }

    fn is_expired(&self) -> bool {
        self.expires < std::time::Instant::now()
    }
}

/// What a confirmed control command asks the kernel module to do.
#[derive(Clone, Debug, PartialEq)]
enum ControlKind {
    /// `reboot` — kernel_restart(NULL).
    Reboot,
    /// `poweroff` — orderly_poweroff(true).
    PowerOff,
    /// `triplefault` / `triplefault restart` — hard CPU reset (bogus IDT).
    TripleFaultRestart,
    /// `triplefault shutdown` — forced `kernel_power_off()`.
    TripleFaultShutdown,
    /// `kernelpanic` — deliberate `panic()` (halt, or reboot per panic=N).
    KernelPanic,
    /// `cr0_wp on|off` — toggle the CR0 write-protect bit.
    Cr0Wp(bool),
    /// `crX=0x…` — write a raw value to control register X (0, 3, 4, 8).
    SetCr(u8, u64),
}

impl ControlKind {
    /// Human-readable label used in confirmation prompts and logs.
    fn label(&self) -> String {
        match self {
            ControlKind::Reboot     => "reboot (kernel_restart)".into(),
            ControlKind::PowerOff   => "poweroff (orderly_poweroff)".into(),
            ControlKind::TripleFaultRestart => "triplefault restart (hard CPU reset)".into(),
            ControlKind::TripleFaultShutdown => "triplefault shutdown (forced power-off)".into(),
            ControlKind::KernelPanic => "kernelpanic (deliberate panic())".into(),
            ControlKind::Cr0Wp(on)  => format!("set CR0.WP to {on}"),
            ControlKind::SetCr(reg, value) => {
                format!("write cr{reg} = {value:#016x}")
            }
        }
    }

    /// The exact payload sent to `/proc/sysentinel_metrics`.
    fn kernel_command(&self) -> String {
        match self {
            ControlKind::Reboot         => "reboot".into(),
            ControlKind::PowerOff       => "poweroff".into(),
            ControlKind::TripleFaultRestart => "triplefault restart".into(),
            ControlKind::TripleFaultShutdown => "triplefault shutdown".into(),
            ControlKind::KernelPanic => "kernelpanic".into(),
            ControlKind::Cr0Wp(on)      => format!("cr0_wp {}", if *on { "on" } else { "off" }),
            ControlKind::SetCr(reg, v)  => format!("cr{reg}={v:#x}"),
        }
    }

    fn is_fatal_to_host(&self) -> bool {
        matches!(
            self,
            ControlKind::Reboot
                | ControlKind::PowerOff
                | ControlKind::TripleFaultRestart
                | ControlKind::TripleFaultShutdown
                | ControlKind::KernelPanic
        )
    }
}

impl SharedBotState {
    const MAX_ALERTS: usize = 10;
    const MAX_SELINUX: usize = 20;
    const MAX_KMSG: usize = 64;

    pub fn new(paired_chat_id: Option<i64>) -> Self {
        Self {
            paired_chat_id,
            pairing_token: None,
            recent_alerts: VecDeque::with_capacity(Self::MAX_ALERTS),
            recent_kmsg: VecDeque::with_capacity(Self::MAX_KMSG),
            pending_control: None,
            triplefault_fired: false,
            recent_selinux: VecDeque::with_capacity(Self::MAX_SELINUX),
            selinux_ignored: HashSet::new(),
            next_selinux_id: 1,
            pending_selinux: None,
            pending_login: None,
            pending_luks: None,
            pending_module: None,
            face_pending: 0,
        }
    }

    /// Record a new kernel alert (called from the kmsg-watcher thread).
    pub fn push_alert(&mut self, summary: String) {
        if self.recent_alerts.len() >= Self::MAX_ALERTS {
            self.recent_alerts.pop_front();
        }
        self.recent_alerts.push_back(summary);
    }

    /// Record a raw classified kmsg event for the proactive reviewer to look
    /// at later. Always pushed (cheap); `drain_kmsg` empties it.
    pub fn push_kmsg(&mut self, summary: String) {
        if self.recent_kmsg.len() >= Self::MAX_KMSG {
            self.recent_kmsg.pop_front();
        }
        self.recent_kmsg.push_back(summary);
    }

    /// Take all events the proactive reviewer hasn't seen yet.
    pub fn drain_kmsg(&mut self) -> Vec<String> {
        self.recent_kmsg.drain(..).collect()
    }

    /// Register a fresh SELinux denial. Returns `None` when the denial was
    /// previously ignored by the user or is already pending — in both cases
    /// the watcher should not re-alert.
    pub fn push_selinux(&mut self, raw: &str) -> Option<AvcDenial> {
        let denial = selinux::parse_avc(self.next_selinux_id, raw);
        let fp = selinux::fingerprint(&denial);
        if self.selinux_ignored.contains(&fp) {
            return None;
        }
        if self.recent_selinux.iter().any(|d| selinux::fingerprint(d) == fp) {
            return None;
        }
        self.next_selinux_id += 1;

        if self.recent_selinux.len() >= Self::MAX_SELINUX {
            self.recent_selinux.pop_front();
        }
        self.recent_selinux.push_back(denial.clone());
        Some(denial)
    }

    /// Look up a denial by its id.
    pub fn get_selinux(&self, id: u32) -> Option<AvcDenial> {
        self.recent_selinux.iter().find(|d| d.id == id).cloned()
    }

    /// User denied a policy: remove the denial from the pending list and
    /// record its fingerprint so it never re-alerts. Returns the removed
    /// denial, if any.
    pub fn deny_selinux(&mut self, id: u32) -> Option<AvcDenial> {
        let pos = self.recent_selinux.iter().position(|d| d.id == id);
        if let Some(p) = pos {
            let denial = self.recent_selinux.remove(p).unwrap();
            self.selinux_ignored.insert(selinux::fingerprint(&denial));
            if self
                .pending_selinux
                .as_ref()
                .is_some_and(|p| p.denial.id == id)
            {
                self.pending_selinux = None;
            }
            return Some(denial);
        }
        None
    }

    /// Pop the armed SELinux allow if it belongs to this chat and is not
    /// expired — the confirmed-action gate.
    pub fn take_pending_selinux(&mut self, chat_id: i64) -> Option<PendingSelinuxAllow> {
        let taken = self
            .pending_selinux
            .take()
            .filter(|p| p.chat_id == chat_id && !p.is_expired());
        if taken.is_none() {
            self.pending_selinux = None;
        }
        taken
    }
}

// ── Persisted state ───────────────────────────────────────────────────────────

/// Persisted state written to `/var/lib/sysentinel/state.json`.
#[derive(Debug, Serialize, Deserialize, Default)]
struct PersistedState {
    paired_chat_id: Option<i64>,
}

impl PersistedState {
    fn path(config: &Config) -> PathBuf {
        PathBuf::from(&config.telegram.state_file)
    }

    fn load(config: &Config) -> Option<Self> {
        let path = Self::path(config);
        let raw  = std::fs::read_to_string(&path).ok()?;
        serde_json::from_str(&raw)
            .map_err(|e| log::warn!("failed to parse state file {}: {e:#}", path.display()))
            .ok()
    }

    fn save(&self, config: &Config) -> Result<()> {
        let path = Self::path(config);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating state directory {}", parent.display()))?;
        }
        let json = serde_json::to_string_pretty(self)?;
        // mode 0600: only the owner can read the chat_id.
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
            .with_context(|| format!("writing state file {}", path.display()))?;
        file.write_all(json.as_bytes())?;
        Ok(())
    }
}

// ── Telegram API types ────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct TgResponse<T> {
    ok:     bool,
    result: Option<T>,
}

#[derive(Deserialize, Clone)]
struct TgUpdate {
    update_id: i64,
    message:   Option<TgMessage>,
}

#[derive(Deserialize, Clone)]
struct TgMessage {
    chat: TgChat,
    from: Option<TgUser>,
    text: Option<String>,
    // Part of the Telegram wire format; deserialised but not consulted.
    #[allow(dead_code)]
    date: i64,
    /// Photos sent by the user (`/face register`). Sorted largest→smallest.
    #[serde(default)]
    photo: Vec<TgPhotoSize>,
}

#[derive(Deserialize, Clone)]
struct TgPhotoSize {
    file_id: String,
    width:   u32,
    height:  u32,
}

#[derive(Deserialize, Clone)]
struct TgChat {
    id: i64,
}

#[derive(Deserialize, Clone)]
struct TgUser {
    id:         i64,
    first_name: String,
    username:   Option<String>,
}

#[derive(Serialize)]
struct SendMessageBody<'a> {
    chat_id:                  i64,
    text:                     &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    parse_mode:               Option<&'a str>,
    disable_web_page_preview: bool,
}

// ── Telegram bot runner ───────────────────────────────────────────────────────

/// Runs the interactive Telegram bot loop.
pub struct TelegramBot {
    bot_token:     String,
    llm:           Arc<llm::RuntimeLlm>,
    /// Startup default; each turn resolves its own via `effective_system_prompt`.
    #[allow(dead_code)]
    system_prompt: String,
    max_tokens:    u32,
    state:         Arc<Mutex<SharedBotState>>,
    settings:      Arc<Mutex<Settings>>,
    config:        Config,
    memory:        MemoryStore,
}

impl TelegramBot {
    pub fn new(
        config:        Config,
        llm:           Arc<llm::RuntimeLlm>,
        system_prompt: String,
        state:         Arc<Mutex<SharedBotState>>,
        settings:      Arc<Mutex<Settings>>,
    ) -> Self {
        let max_tokens = config.llm.max_tokens;
        let bot_token  = config.telegram.bot_token.clone();
        // `/settings context_entries` (persisted) overrides the config value.
        let context_entries = {
            let s = settings.lock().expect("settings mutex");
            if s.context_entries == 0 {
                config.memory.context_max_entries
            } else {
                s.context_entries
            }
        };
        let memory = MemoryStore::new(
            &config.memory.memory_file,
            &config.memory.context_file,
            context_entries,
        );
        Self { bot_token, llm, system_prompt, max_tokens, state, settings, config, memory }
    }

    /// The `n_ctx` (llama.cpp context length) currently in effect; 0 = don't
    /// override the server.
    fn effective_llama_ctx(&self) -> u32 {
        self.settings.lock().expect("settings mutex").llama_ctx
    }

    /// The runtime prefs used to (re)build a backend: context knobs + the
    /// selected model names, all sourced from the persisted `/settings`.
    fn llm_prefs(&self) -> llm::RuntimePrefs {
        let guard = self.settings.lock().expect("settings mutex");
        llm::RuntimePrefs {
            llama_ctx: guard.llama_ctx,
            local_ctx: guard.local_ctx,
            local_model: if guard.local_model.is_empty() {
                None
            } else {
                Some(guard.local_model.clone())
            },
            model: if guard.llm_model.is_empty() {
                None
            } else {
                Some(guard.llm_model.clone())
            },
            models_by_provider: guard.llm_models.clone(),
        }
    }

    /// The main loop. Blocks forever; run in a dedicated `std::thread::spawn`.
    pub fn run(self) {
        log::info!("telegram bot: starting getUpdates long-poll loop");
        let mut offset: i64 = 0;

        loop {
            match self.poll_updates(offset) {
                Ok(updates) => {
                    for update in updates {
                        offset = offset.max(update.update_id + 1);
                        if let Some(msg) = update.message {
                            self.handle_message(&msg);
                        }
                    }
                }
                Err(e) => {
                    log::error!("telegram getUpdates failed: {e:#}; retrying in 10s");
                    std::thread::sleep(Duration::from_secs(10));
                }
            }
        }
    }

    fn api_url(&self, method: &str) -> String {
        format!("https://api.telegram.org/bot{}/{method}", self.bot_token)
    }

    /// Long-poll for new updates. Times out after 30 seconds (Telegram
    /// standard); returns an empty vec on timeout or no new messages.
    fn poll_updates(&self, offset: i64) -> Result<Vec<TgUpdate>> {
        #[derive(Serialize)]
        struct Params { offset: i64, timeout: u64, limit: u8 }

        let resp: TgResponse<Vec<TgUpdate>> = ureq::post(&self.api_url("getUpdates"))
            .timeout(Duration::from_secs(35)) // slightly more than telegram timeout
            .send_json(&Params { offset, timeout: 30, limit: 10 })
            .context("Telegram getUpdates request")?
            .into_json()
            .context("parsing Telegram getUpdates response")?;

        if !resp.ok {
            anyhow::bail!("Telegram API returned ok=false for getUpdates");
        }
        Ok(resp.result.unwrap_or_default())
    }

    /// Dispatch a received message.
    ///
    /// # Security: user-level whitelist
    ///
    /// When `config.telegram.telegram_id` is set, **any** message whose
    /// `from.id` does not match is rejected here, before pairing logic runs.
    /// This means a third party who obtains the pairing token still cannot
    /// hack the bot: the token is only accepted from the authorised user.
    fn handle_message(&self, msg: &TgMessage) {
        let chat_id  = msg.chat.id;
        let text     = msg.text.as_deref().unwrap_or("").trim();
        let username = msg.from.as_ref()
            .map(|u| u.username.as_deref().unwrap_or(&u.first_name))
            .unwrap_or("unknown");

        log::debug!("telegram: message from chat_id={chat_id} user={username}: {:?}", text);

        // ── Enforce the per-user whitelist BEFORE anything else ──────────────
        if let Some(allowed) = self.config.telegram.telegram_id {
            let sender_id = msg.from.as_ref().map(|u| u.id);
            if sender_id != Some(allowed) {
                log::warn!(
                    "telegram: DENIED — user '{username}' (id={:?}, chat={chat_id}) is not \
                     the authorised user (id={allowed}); ignoring message",
                    sender_id,
                );
                // Do NOT reveal that a token exists, that the bot is paired,
                // or any other detail. Minimal, uninformative reply.
                let _ = self.send(chat_id, "⛔ Access denied.");
                return;
            }
        }

        let paired_id = self.state.lock().expect("bot state mutex").paired_chat_id;

        match paired_id {
            None => {
                // Not paired yet — only accept a valid pairing token.
                let sender_id = msg.from.as_ref().map(|u| u.id);
                self.handle_pairing(chat_id, text, username, sender_id);
            }
            Some(pid) if pid == chat_id => {
                // Message from the paired user. A photo while a `/face register`
                // is arming is consumed here (face enrollment); otherwise the
                // message is treated as text (which is empty for a photo).
                if !msg.photo.is_empty() {
                    let wants = {
                        let g = self.state.lock().expect("bot state mutex");
                        g.face_pending > 0
                    };
                    if wants {
                        self.enroll_face_photo(chat_id, msg);
                        return;
                    }
                }
                self.handle_paired_message(chat_id, text, username);
            }
            Some(_) => {
                // Message from a stranger on a *different* chat, but from the
                // authorised user — brief, uninformative rejection.
                let _ = self.send(chat_id, "⛔ This bot is already paired to another device.");
            }
        }
    }

    /// Handle a message when no pairing has occurred yet.
    ///
    /// # Challenge–response, token→user binding
    ///
    /// The bot *asks* the user to present the token rather than passively
    /// waiting. Pairing requires passing BOTH steps:
    ///
    /// 1. **Token proof** — the sender presents the token from the daemon log.
    ///    Accepted only when all of:
    ///      - the sender's `from.id` equals the token's `target_user_id`, AND
    ///      - the token Argon2id-verifies against the stored hash, AND
    ///      - it is still within its 5-minute window.
    /// 2. **Explicit identity confirmation** — the bot then asks: *"type YES
    ///    to confirm"*. Only an explicit affirmative reply from the same user
    ///    opens the door (the answer may come in any language — the LLM judge
    ///    reads it). This is the "el bot debe saber que eres TÚ" guarantee:
    ///    even possession of the token alone never pairs on its own.
    ///
    /// A stranger who copies the token cannot pair (wrong `from.id`); the
    /// stored hash cannot be reversed or brute-forced; and repeated invalid
    /// attempts burn the token entirely.
    fn handle_pairing(
        &self,
        chat_id: i64,
        text: &str,
        username: &str,
        sender_id: Option<i64>,
    ) {
        let Some(sender_id) = sender_id else {
            // We could not resolve who sent this (Telegram always sends
            // `from` on private chats, so this is defensive only).
            log::warn!("telegram: pairing message with no sender id; ignoring");
            return;
        };

        // Snapshot the pending token under the lock, then verify off-lock.
        let pending = {
            let guard = self.state.lock().expect("bot state mutex");
            guard.pairing_token.as_ref().map(|t| PendingPairing {
                hash:               t.token_hash.clone(),
                is_valid:           t.is_valid(),
                bound_to_sender:    t.matches_user(sender_id),
                awaiting_confirm:   t.awaiting_confirm,
                remaining_attempts: t.remaining_attempts(),
                seconds_remaining:  t.seconds_remaining(),
            })
        };

        // ── No token active at all ───────────────────────────────────────────
        let Some(token) = pending else {
            let _ = self.send(
                chat_id,
                "⚠️ No pairing token is currently active. \
                 Restart the daemon or check the log \
                 (`journalctl -u sysentinel`) for a token.",
            );
            return;
        };

        // ── Token expired OR bound to a different user ───────────────────────
        if !token.is_valid || !token.bound_to_sender {
            log::warn!(
                "telegram: pairing denied for user '{}' (id={sender_id}, chat={chat_id}): {}",
                username,
                if !token.bound_to_sender {
                    "token bound to a different Telegram account"
                } else {
                    "token expired"
                },
            );
            let _ = self.send(
                chat_id,
                "⛔ Access denied. This pairing token cannot be used from this account.",
            );
            return;
        }

        // ── Step 2: explicit identity confirmation ───────────────────────────
        if token.awaiting_confirm {
            if Self::is_confirmation_phrase(text) {
                self.complete_pairing(chat_id, username, sender_id);
            } else {
                // Language-agnostic: the conversational judge reads a clear
                // yes/no in ANY language ("ja", "nein", "sì"…) — an explicit
                // English "DENY" is always a hard "no".
                match self.llm_yes_no(
                    "A security bot is asking the owner for final confirmation \
                     to bind their Telegram chat to this machine. Should this \
                     chat be paired?",
                    text,
                ) {
                    Some(true) => {
                        log::info!(
                            "telegram: pairing confirmed conversationally (id={sender_id}, chat={chat_id})"
                        );
                        self.complete_pairing(chat_id, username, sender_id);
                    }
                    Some(false) => {
                        {
                            let mut guard = self.state.lock().expect("bot state mutex");
                            if let Some(t) = guard.pairing_token.as_mut() {
                                t.burn();
                            }
                        }
                        log::warn!(
                            "telegram: pairing DENIED by user '{}' (id={sender_id}, chat={chat_id}); token burned",
                            username
                        );
                        let _ = self.send_markdown(
                            chat_id,
                            "⛔ Pairing denied and the token was discarded. \
                             If you did not expect this, check the machine now.",
                        );
                    }
                    None => {
                        let reminder = "\
✅ *Token accepted.*\n\
But before this chat can talk to the kernel, I need final confirmation.\n\
\n\
⚠️ *WARNING:* pairing grants this chat the ability to ask anything about the \
machine (kernel events, memory, firmware, PMU counters).\n\
\n\
If this is really you, reply: **YES**\n\
If you did NOT expect this, reply: **DENY** (or ignore — the token dies in \
a few minutes).";

                        // If they explicitly deny, kill the token immediately.
                        if Self::is_denial_phrase(text) {
                            {
                                let mut guard = self.state.lock().expect("bot state mutex");
                                if let Some(t) = guard.pairing_token.as_mut() {
                                    t.burn();
                                }
                            }
                            log::warn!(
                                "telegram: pairing DENIED by user '{}' (id={sender_id}, chat={chat_id}); token burned",
                                username
                            );
                        }
                        let _ = self.send_markdown(chat_id, reminder);
                    }
                }
            }
            return;
        }

        // ── Step 1: ask for the token if nothing was presented ───────────────
        if text.is_empty() {
            let minutes = token.seconds_remaining.div_ceil(60);
            let prompt = format!(
                "🔑 *Pairing required.*\n\
                 Send me the pairing token from the daemon log.\n\
                 (It looks like `SYN-XXXXXXXX` and is valid for {minutes} minute(s).)",
            );
            let _ = self.send(chat_id, &prompt);
            return;
        }

        // ── Step 1: verify the presented token ───────────────────────────────
        if token.verify(text.trim()) {
            {
                let mut guard = self.state.lock().expect("bot state mutex");
                if let Some(t) = guard.pairing_token.as_mut() {
                    t.awaiting_confirm = true;
                }
            }
            log::info!(
                "telegram: token accepted from user '{}' (id={sender_id}, chat={chat_id}); \
                 requesting identity confirmation",
                username
            );
            let msg = "\
✅ *Token accepted.*\n\
\n\
I have kernel access to the machine, so I must be 100% sure it is really you.\n\
If this is really you, reply: **YES**\n\
If you did NOT expect this, reply: **DENY**";
            let _ = self.send_markdown(chat_id, msg);
            return;
        }

        // ── Invalid token: record failure; burn after too many attempts ─────
        let (burned, remaining) = {
            let mut guard = self.state.lock().expect("bot state mutex");
            let mut burned = false;
            let mut remaining = 0u32;
            if let Some(t) = guard.pairing_token.as_mut() {
                if t.record_failure() {
                    t.burn();
                    burned = true;
                }
                remaining = t.remaining_attempts();
            }
            (burned, remaining)
        };

        if burned {
            log::error!(
                "telegram: pairing token BURNED after too many invalid attempts \
                 (user '{}', id={sender_id}, chat={chat_id})",
                username
            );
            let _ = self.send(
                chat_id,
                "🚫 Too many invalid attempts. The token has been revoked. \
                 Restart the daemon to generate a new one.",
            );
        } else {
            log::warn!(
                "telegram: invalid pairing token from user '{}' (id={sender_id}, chat={chat_id}): {:?} — {} attempt(s) left",
                username, text, remaining
            );
            let _ = self.send(
                chat_id,
                &format!(
                    "❌ Invalid pairing token. {remaining} attempt(s) left before the token is revoked."
                ),
            );
        }
    }

    /// Complete the pairing for an identity-confirmed user.
    fn complete_pairing(&self, chat_id: i64, username: &str, sender_id: i64) {
        {
            let mut guard = self.state.lock().expect("bot state mutex");
            guard.paired_chat_id = Some(chat_id);
            guard.pairing_token  = None; // consumed: one-time use only
        }

        // Persist.
        let state = PersistedState { paired_chat_id: Some(chat_id) };
        if let Err(e) = state.save(&self.config) {
            log::error!("failed to save pairing state: {e:#}");
        }

        log::info!(
            "telegram: PAIRED successfully with user '{}' (id={sender_id}, chat_id={}) \
             after token + explicit confirmation",
            username, chat_id
        );

        let reply = "✅ *Paired and confirmed.*\n\
                     Your system is now connected to this chat.\n\
                     You can ask me anything about your machine.\n\n\
                     Try: `/start` for the menu, or just ask a question.";
        let _ = self.send_markdown(chat_id, reply);
    }

    /// The exact phrases that count as an identity confirmation.
    fn is_confirmation_phrase(text: &str) -> bool {
        matches!(
            text.trim().to_lowercase().as_str(),
            "yes" | "si" | "sí" | "confirm" | "confirmar"
        )
    }

    /// The exact phrases that explicitly abort an in-progress pairing.
    fn is_denial_phrase(text: &str) -> bool {
        matches!(
            text.trim().to_lowercase().as_str(),
            "no" | "deny" | "denegar" | "cancel" | "cancelar"
        )
    }

    /// Handle a message from the already-paired user.
    fn handle_paired_message(&self, chat_id: i64, text: &str, username: &str) {
        if text.is_empty() {
            return;
        }

        // Privileged control commands (reboot/poweroff/CR writes) are handled
        // here deterministically: first the slash commands, the language-free
        // `CONFIRM-XXXXXX` code, and the explicit control cancel/confirm (the
        // execution gate never touches the LLM), plus the LLM-judged verdicts
        // for pending login/LUKS asks. Anything they don't catch flows to
        // cmd_chat, where the LLM recognizes control orders in any language
        // via the `[ARM:…]` protocol.
        if self.handle_control_message(chat_id, text) {
            return;
        }

        // Foreign-module verdict (any language, judged by the LLM).
        if self.handle_module_message(chat_id, text) {
            return;
        }

        // SELinux workflow (list / explain / allow / deny).
        if text.trim().starts_with("/selinux") {
            self.cmd_selinux(chat_id, text);
            return;
        }

        match text {
            "/start"          => self.cmd_start(chat_id),
            "/help"           => self.cmd_help(chat_id),
            "/status"         => self.cmd_status(chat_id),
            "/alerts"         => self.cmd_alerts(chat_id),
            "/firmware"       => self.cmd_firmware(chat_id),
            "/memory"         => self.cmd_dump_context(chat_id),
            "/showmemory"     => self.cmd_dump_memory(chat_id),
            "/hardware"       => self.cmd_hardware(chat_id),
            "/pci"            => self.cmd_pci(chat_id),
            "/lsblk"          => self.cmd_lsblk(chat_id),
            "/lsusb"          => self.cmd_lsusb(chat_id),
            "/lsmod"          => self.cmd_lsmod(chat_id),
            "/settings"       => self.cmd_settings(chat_id, ""),
            "/systemprompt"   => self.cmd_system_prompt(chat_id, ""),
            "/llm"            => self.cmd_llm(chat_id, ""),
            "/model"          => self.cmd_model(chat_id, ""),
            "/models"         => self.cmd_models(chat_id, ""),
            "/resetcontext"   => self.cmd_reset_context(chat_id),
            "/unpair"         => self.cmd_unpair(chat_id, username),
            "/definehome"     => self.cmd_definehome(chat_id, ""),
            "/detecthome"     => self.cmd_definehome(chat_id, ""),
            "/bootkit"        => self.cmd_bootkit(chat_id),
            "/logins"         => self.cmd_logins(chat_id),
            "/mods"           => self.cmd_mods(chat_id),
            "/dmesg"          => self.cmd_dmesg(chat_id),
            "/undervolt"      => self.cmd_undervolt(chat_id),
            "/secureboot"     => self.cmd_secureboot(chat_id),
            "/battery"        => self.cmd_battery(chat_id),
            "/face"           => self.cmd_face(chat_id, text),
            _ if text.trim().starts_with("/llm ") => {
                let rest = &text.trim()["/llm ".len()..];
                self.cmd_llm(chat_id, rest);
            }
            _ if text.trim().starts_with("/model ") => {
                let rest = &text.trim()["/model ".len()..];
                self.cmd_model(chat_id, rest);
            }
            _ if text.trim().starts_with("/models ") => {
                let rest = &text.trim()["/models ".len()..];
                self.cmd_models(chat_id, rest);
            }
            _ if text.trim().starts_with("/settings ") => {
                let rest = &text.trim()["/settings ".len()..];
                self.cmd_settings(chat_id, rest);
            }
            _ if text.trim().starts_with("/systemprompt ") => {
                let rest = &text.trim()["/systemprompt ".len()..];
                self.cmd_system_prompt(chat_id, rest);
            }
            _ if text.trim().starts_with("/remember ") => {
                let rest = &text.trim()["/remember ".len()..];
                self.cmd_remember(chat_id, rest);
            }
            _ if text.trim().starts_with("/definehome ") => {
                let rest = &text.trim()["/definehome ".len()..];
                self.cmd_definehome(chat_id, rest);
            }
            _ if text.trim().starts_with("/detecthome ") => {
                let rest = &text.trim()["/detecthome ".len()..];
                self.cmd_definehome(chat_id, rest);
            }
            _ if text.trim().starts_with("/login ") => {
                let rest = &text.trim()["/login ".len()..];
                self.cmd_login(chat_id, rest);
            }
            _                 => self.cmd_chat(chat_id, text, username),
        }
    }

    /// Foreign-module verdict routing. While a module is armed, the LLM judges
    /// the user's answer in any language (REMOVE / KEEP / ANALYSE, then
    /// GO / NO); anything unclear flows on to normal chat untouched.
    fn handle_module_message(&self, chat_id: i64, text: &str) -> bool {
        let pending = {
            let g = self.state.lock().expect("bot state mutex");
            g.pending_module
                .as_ref()
                .filter(|p| p.chat_id == chat_id && !p.is_expired())
                .cloned()
        };
        let Some(pm) = pending else { return false };

        match pm.phase {
            ModulePhase::AwaitVerdict => match self.llm_module_verdict(&pm, text) {
                Some(l) if l == "REMOVE" => {
                    self.state.lock().expect("bot state mutex").pending_module = None;
                    self.remove_module(chat_id, &pm);
                    true
                }
                Some(l) if l == "KEEP" => {
                    self.state.lock().expect("bot state mutex").pending_module = None;
                    self.module_kept(chat_id, &pm);
                    true
                }
                Some(l) if l == "ANALYSE" => {
                    // User wants it investigated. The persona explains it will
                    // disassemble + analyse; on an API backend it warns about
                    // token cost and asks before spending money. Local: go.
                    self.arm_module_analysis(chat_id, &mut pm.clone());
                    true
                }
                _ => false,
            },
            ModulePhase::AwaitAnalysisGo => match self.llm_module_verdict(&pm, text) {
                Some(l) if l == "GO" => {
                    self.state.lock().expect("bot state mutex").pending_module = None;
                    self.analyse_module(chat_id, &pm);
                    true
                }
                Some(l) if l == "NO" => {
                    self.state.lock().expect("bot state mutex").pending_module = None;
                    let _ = self.send_markdown(
                        chat_id,
                        &format!(
                            "Done — I won't analyse anything about `{}`. If you want to look \
                             at it later: `/mods` or tell me you're \"not sure\".",
                            pm.name
                        ),
                    );
                    true
                }
                _ => false,
            },
        }
    }

    /// Conversational module verdict judge (any language). Asks the LLM to
    /// label the reply as one of the phase's choices; `None` when the reply is
    /// not a verdict at all (so normal chat can continue).
    fn llm_module_verdict(&self, pm: &PendingModule, text: &str) -> Option<String> {
        if text.chars().count() > 200 {
            return None;
        }
        let (allowed, ask) = match pm.phase {
            ModulePhase::AwaitVerdict => (
                "REMOVE, KEEP, ANALYSE",
                "You classify a single user reply. A foreign kernel module \
                 just loaded on this machine and a security bot asked the \
                 owner what to do about it. Decide what the reply means and \
                 answer with exactly one word: REMOVE (unload it now), KEEP \
                 (leave it loaded), or ANALYSE (investigate it first). Answer \
                 UNSURE when the reply is not a clear choice (questions, \
                 jokes, irrelevant text).",
            ),
            ModulePhase::AwaitAnalysisGo => (
                "GO, NO",
                "You classify a single user reply. A security bot asked the \
                 owner whether to run a full disassembly + analysis of a \
                 kernel module, which costs tokens on API backends. Decide \
                 what the reply means and answer with exactly one word: GO \
                 (proceed) or NO (skip). Answer UNSURE when the reply is not \
                 a clear choice.",
            ),
        };
        let label = self.llm_roundtrip_short(
            &format!(
                "{ask} The module is named '{name}'. Always one of: {allowed}.",
                name = pm.name,
            ),
            &format!("User's reply: \"{}\"", text.trim()),
        )?;
        if matches!(label.as_str(), "REMOVE" | "KEEP" | "ANALYSE" | "GO" | "NO") {
            Some(label)
        } else {
            None
        }
    }

    /// "investigate it" → ask, through the persona, to run objdump + analysis.
    /// API backends get the billing warning (conversationally); local skips it.
    fn arm_module_analysis(&self, chat_id: i64, pm: &mut PendingModule) {
        pm.phase = ModulePhase::AwaitAnalysisGo;
        {
            let mut g = self.state.lock().expect("bot state mutex");
            g.pending_module = Some(pm.clone());
        }

        if self.provider_is_api() {
            self.voice_in_persona(
                chat_id,
                &format!(
                    "The user isn't sure whether the kernel module `{}` (foreign, not \
                     in the official tree) can be trusted, and asked me to analyse it.\n\
                     My analysis will run `objdump` against its .ko and ask the LLM to \
                     review the disassembly IN THE API BACKEND — that costs the user's \
                     tokens / billing (they pay per request). Explain this to them in \
                     YOUR voice, in their language, and ask whether to proceed. \
                     Answer: say yes or no. Options are: user replies \"dale\" to run, \
                     or \"dejalo\"/\"no\" to skip. Keep it short and natural.",
                    pm.name
                ),
            );
        } else {
            // Local backend: no money spent, proceed straight away.
            self.analyse_module(chat_id, pm);
        }
    }

    /// objdump the module and have the persona review the disassembly.
    fn analyse_module(&self, chat_id: i64, pm: &PendingModule) {
        log::info!("module: analysing {} (objdump + persona)", pm.name);

        let ko = match pm.ko.clone() {
            Some(p) => p,
            None => match crate::modulewatch::find_ko(&pm.name) {
                Some(p) => p,
                None => {
                    let _ = self.send_markdown(
                        chat_id,
                        &format!(
                            "I can't find the `.ko` for `{}` on disk (already deleted?). \
                             Without the binary there's nothing to disassemble.",
                            pm.name
                        ),
                    );
                    return;
                }
            },
        };

        let disasm = match crate::modulewatch::objdump_text(&ko) {
            Some(d) => d,
            None => {
                let _ = self.send(
                    chat_id,
                    "❌ Couldn't run `objdump` (`binutils` installed?), or the \
                     file isn't an ELF I can read.",
                );
                return;
            }
        };

        let persona = llm::resolved_persona(&self.config);
        let system_prompt = self.resolved_system_prompt();
        let system_context = build_system_context(&self.state, &persona);
        let user_message = format!(
            "A foreign kernel module just got loaded: `{}` ({} kB, used_by: {}). It is \
             NOT in the official module tree. I ran `objdump -d -M intel` on its binary:\n\n\
             ```\n{}\n```\n\n\
             As a malware analyst in YOUR voice: what does this module do? Is the \
             disassembly suspicious (direct sys_call_table/KVM hooks, kallsyms lookups, \
             hidden LKM in .init, suspicious writes)? Say what you'd keep an eye on. Be \
             brief — the essentials only, in the user's language.",
            pm.name, pm.size_kb, if pm.used_by == "-" { "none" } else { &pm.used_by },
            truncate_for_telegram(&disasm)
        );

        let request = ChatRequest {
            system_prompt: &system_prompt,
            system_context: &system_context,
            memory: "",
            conversation_history: "",
            user_message: &user_message,
            max_tokens: self.max_tokens,
        };
        match self.llm.chat(&request) {
            Ok(reply) => {
                let header = format!("🧠 *Analysis of `{}`*\n\n", pm.name);
                let _ = self.send_markdown(chat_id, &truncate_for_telegram(&(header + &reply)));
            }
            Err(e) => {
                log::error!("module analysis LLM failed: {e:#}");
                let _ = self.send(
                    chat_id,
                    "❌ The backend did not respond. Check the daemon logs.",
                );
            }
        }
    }

    /// Was the verdict to actually unload the module?
    fn remove_module(&self, chat_id: i64, pm: &PendingModule) {
        let name = &pm.name;
        if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-') {
            let _ = self.send(chat_id, "❌ Invalid module name; I won't touch anything.");
            return;
        }
        log::warn!("module: user ordered rmmod of `{name}`");
        let out = std::process::Command::new("rmmod")
            .arg(name)
            .output();
        match out {
            Ok(o) if o.status.success() => {
                let _ = self.send_markdown(
                    chat_id,
                    &format!(
                        "🪓 Unloaded `{name}` from the kernel. If it was an unwelcome guest, \
                         it's gone now. Confirm with `/mods`."
                    ),
                );
            }
            Ok(o) => {
                let err = String::from_utf8_lossy(&o.stderr);
                let _ = self.send(
                    chat_id,
                    &format!("⚠️ Could not unload `{name}`: {} (permissions? in use?)", err.trim()),
                );
            }
            Err(e) => {
                let _ = self.send(chat_id, &format!("❌ `rmmod` failed: {e:#}"));
            }
        }
    }

    fn module_kept(&self, chat_id: i64, pm: &PendingModule) {
        log::info!("module: user OK keeping `{}` loaded", pm.name);
        let _ = self.send_markdown(
            chat_id,
            &format!("OK, keeping `{}` loaded. Noted. 👀", pm.name),
        );
    }

    /// Is the currently active provider an API one (token billing)?
    fn provider_is_api(&self) -> bool {
        let chain = self.current_llm_chain();
        let active = chain.first().map(|s| s.as_str()).unwrap_or("");
        !matches!(active, "local" | "llama" | "none" | "")
    }

    /// Speak one message through the persona (like the watchers do).
    fn voice_in_persona(&self, chat_id: i64, facts: &str) {
        let persona = llm::resolved_persona(&self.config);
        let system_prompt = self.resolved_system_prompt();
        let directive = format!(
            "These are live facts / things that just happened. You ARE the machine; \
             speak to the user in YOUR voice, in their language — naturally, briefly \
             (max 4 lines), no log formatting, no titles.\n\
             language: {}\ntone: {}\n\n{facts}",
            persona.language, persona.tone
        );
        let text = self
            .llm
            .explain(&llm::ExplainRequest {
                system_prompt: &system_prompt,
                event_text: &directive,
                max_tokens: self.max_tokens,
            })
            .unwrap_or_else(|e| {
                log::warn!("persona voice dropped ({e:#}); forwarding raw facts");
                facts.to_string()
            });
        let _ = self.send_markdown(chat_id, &truncate_for_telegram(&text));
    }

    /// Try to interpret `text` as a control command, a control confirmation,
    /// or a control query. Returns `true` when the message was consumed.
    fn handle_control_message(&self, chat_id: i64, text: &str) -> bool {
        let lower = text.trim().to_lowercase();

        let (has_armed, has_selinux_armed, has_login_pending, has_luks_pending) = {
            let guard = self.state.lock().expect("bot state mutex");
            (
                guard.pending_control.is_some(),
                guard.pending_selinux.is_some(),
                guard
                    .pending_login
                    .as_ref()
                    .map(|p| p.chat_id == chat_id)
                    .unwrap_or(false),
                guard
                    .pending_luks
                    .as_ref()
                    .map(|p| p.chat_id == chat_id && !p.is_expired())
                    .unwrap_or(false),
            )
        };

        // ── The one-time code from the ARM prompt is a language-free confirm.
        //    A concrete `CONFIRM-XXXXXX` can never be chatter, so it wins over
        //    every word-based rule below (only an armed control carries one).
        let nonce_confirm = {
            let guard = self.state.lock().expect("bot state mutex");
            let armed_here = |p: &PendingControl| p.chat_id == chat_id && !p.is_expired();
            match guard.pending_control.as_ref() {
                Some(p) if armed_here(p) => {
                    let plain = lower.replace('-', "").replace([' ', '\t'], "");
                    !plain.is_empty()
                        && (plain == p.nonce.to_lowercase().replace('-', "")
                            || lower.eq_ignore_ascii_case(&p.nonce))
                }
                _ => false,
            }
        };
        if nonce_confirm {
            let control = {
                let mut guard = self.state.lock().expect("bot state mutex");
                let armed = guard
                    .pending_control
                    .take()
                    .filter(|p| p.chat_id == chat_id && !p.is_expired());
                if armed.is_none() {
                    guard.pending_control = None;
                }
                armed
            };
            if let Some(p) = control {
                self.execute_control(chat_id, p);
                return true;
            }
            let _ = self.send(
                chat_id,
                "⚠️ No armed control to confirm (expired or cancelled).",
            );
            return true;
        }

        // ── Conversational verdicts for pending "is it me?" asks. A clear
        //    yes/no in ANY language is judged by the LLM; anything else drops
        //    through to the word rules and normal chat below. Login keeps the
        //    same priority over LUKS it always had. ──────────────────────────
        if has_login_pending {
            let question = {
                let guard = self.state.lock().expect("bot state mutex");
                guard.pending_login.as_ref().map(|p| {
                    format!(
                        "Is this login session yours? user='{}', channel='{}', pid={}",
                        p.event.user,
                        p.event.channel.label(),
                        p.event.pid
                    )
                })
            };
            if let Some(question) = question {
                if let Some(yes) = self.llm_yes_no(&question, text) {
                    if yes {
                        if loginwatch::approve_pending(&self.state, chat_id) {
                            log::info!("telegram: login approved by user (chat={chat_id})");
                            let _ = self.send(
                                chat_id,
                                "✅ Understood — I'll leave the session alone and keep watching.",
                            );
                            return true;
                        }
                    } else if let Some(p) = loginwatch::deny_pending(&self.state, chat_id) {
                        let closed = loginwatch::close_session(&p);
                        log::warn!(
                            "telegram: login by {} denied by user (chat={chat_id}, closed={closed})",
                            p.event.user
                        );
                        let _ = self.send(
                            chat_id,
                            &format!(
                                "{} the session of `{}` (pid={}).",
                                if closed { "🚫 Closed" } else { "⚠️ Could not close" },
                                p.event.user,
                                p.event.pid
                            ),
                        );
                        return true;
                    }
                }
            }
        }
        if has_luks_pending {
            let question = {
                let guard = self.state.lock().expect("bot state mutex");
                guard.pending_luks.as_ref().map(|p| {
                    format!("Was this LUKS decryption yours? boot_id='{}'", p.boot_id)
                })
            };
            if let Some(question) = question {
                if let Some(yes) = self.llm_yes_no(&question, text) {
                    if yes {
                        if let Some(p) = crate::luks::approve_and_clear(&self.state, chat_id) {
                            log::info!(
                                "telegram: LUKS boot {} confirmed by owner (chat={chat_id})",
                                p.boot_id
                            );
                            let _ = self.send(
                                chat_id,
                                "✅ It was me — all good. The evidence stays archived \
                                 (no action taken).",
                            );
                            return true;
                        }
                    } else if let Some(p) =
                        crate::luks::deny_and_clear(&self.state, &self.settings, chat_id)
                    {
                        log::warn!(
                            "telegram: LUKS boot {} denied by user (chat={chat_id})",
                            p.boot_id
                        );
                        let _ = self.send(
                            chat_id,
                            "🚫 Understood — it wasn't you. Applying the deny action; \
                             the evidence stays on record.",
                        );
                        return true;
                    }
                }
            }
        }

        // ── Cancel / deny: drop an armed control or SELinux allow. Login and
        //    LUKS verdicts are handled conversationally above, not by words. ─
        if matches!(lower.as_str(), "cancel" | "cancelar" | "no") {
            if !has_armed && !has_selinux_armed {
                return false; // maybe a "no" in normal conversation
            }
            let had = {
                let mut guard = self.state.lock().expect("bot state mutex");
                let a = guard.pending_control.take().is_some();
                let b = guard.pending_selinux.take().is_some();
                a || b
            };
            if had {
                log::info!("telegram: armed control/allow cancelled (chat={chat_id})");
                let _ = self.send(chat_id, "🚫 Cancelled. Nothing was executed or permitted.");
            }
            return true;
        }

        // ── Confirm words: execute an armed control/allow. Backwards-compat
        //    convenience — the language-free path is the nonce above. ────────
        if matches!(
            lower.as_str(),
            "confirm" | "confirmar" | "si fui yo" | "si" | "sí"
        ) || lower.ends_with(" confirm")
        {
            if !has_armed && !has_selinux_armed && !lower.ends_with(" confirm") {
                // A bare "confirm"/"si"/"sí" with nothing armed is normal
                // conversation — let the LLM answer it.
                return false;
            }
            // First try a kernel control.
            let control = {
                let mut guard = self.state.lock().expect("bot state mutex");
                let armed = guard
                    .pending_control
                    .take()
                    .filter(|p| p.chat_id == chat_id && !p.is_expired());
                if armed.is_none() {
                    guard.pending_control = None;
                }
                armed
            };
            if let Some(p) = control {
                self.execute_control(chat_id, p);
                return true;
            }
            // Else a pending SELinux allow.
            let selinux_pending = {
                let mut guard = self.state.lock().expect("bot state mutex");
                guard.take_pending_selinux(chat_id)
            };
            match selinux_pending {
                Some(p) => self.execute_selinux_allow(chat_id, p),
                None => {
                    let _ = self.send(
                        chat_id,
                        "⚠️ No armed control or SELinux allow to confirm \
                         (expired or cancelled).",
                    );
                }
            }
            return true;
        }

        // ── /cr0 /cr2 /cr3 /cr4 /cr8 — read a control register (no confirm) ─
        if let Some(reg) = lower.strip_prefix("/cr") {
            if reg.chars().all(|c| c.is_ascii_digit()) {
                if let Some(reg) = parse_control_register(reg) {
                    self.report_control_register(chat_id, reg);
                    return true;
                }
            }
        }
        if let Some(arg) = lower.strip_prefix("/cr0 wp ") {
            let on = match arg {
                "on" => true,
                "off" => false,
                _ => {
                    let _ = self.send(chat_id, "Usage: `/cr0 wp on` or `/cr0 wp off`.");
                    return true;
                }
            };
            self.arm_control(chat_id, ControlKind::Cr0Wp(on));
            return true;
        }

        // ── /crX=0x… — arm a raw control-register write ─────────────────────
        if lower.starts_with("/cr") {
            if let Some(eq) = lower.find('=') {
                let reg_str = &lower[3..eq];
                if let Some(reg) = parse_control_register(reg_str) {
                    let hex = lower[eq + 1..]
                        .strip_prefix("0x")
                        .or_else(|| lower[eq + 1..].strip_prefix("0X"))
                        .unwrap_or(&lower[eq + 1..]);
                    match u64::from_str_radix(hex, 16) {
                        Ok(value) => {
                            if reg == 2 {
                                let _ = self.send(
                                    chat_id,
                                    "❌ CR2 is read-only (page-fault linear address). \
                                     It cannot be written.",
                                );
                                return true;
                            }
                            self.arm_control(chat_id, ControlKind::SetCr(reg, value));
                        }
                        Err(_) => {
                            let _ = self.send(chat_id, "❌ Invalid hexadecimal value.");
                        }
                    }
                    return true;
                }
            }
        }

        // ── /reboot and /poweroff — arm the fatal controls ─────────────────
        if lower.starts_with("/reboot") {
            self.arm_control(chat_id, ControlKind::Reboot);
            return true;
        }
        if lower.starts_with("/poweroff") {
            self.arm_control(chat_id, ControlKind::PowerOff);
            return true;
        }

        // ── /kernelpanic and conversational panic orders — deliberate panic()
        //    (terminal one-shot: halt, or the kernel's own reboot via panic=N). ─
        if let Some(kind) = parse_kernelpanic_order(&lower) {
            self.try_arm_kernelpanic(chat_id, kind);
            return true;
        }

        // ── /triplefault [restart|shutdown] / /triplefault allow, and the
        //    conversational equivalents — one shot, never in a loop. ────────
        if lower.starts_with("/triplefault allow") {
            self.rearm_triplefault(chat_id);
            return true;
        }
        if let Some(kind) = parse_triplefault_order(&lower) {
            self.try_arm_triplefault(chat_id, kind);
            return true;
        }

        false
    }

    /// A tiny forcing-function round trip: ask the LLM to stick to one label.
    /// Returns the first uppercase word of the reply, or `None` on backend
    /// errors or empty answers. Never panics.
    fn llm_roundtrip_short(&self, instruction: &str, content: &str) -> Option<String> {
        if content.chars().count() > 200 {
            return None;
        }
        let request = ChatRequest {
            system_prompt: instruction,
            system_context: "",
            memory: "",
            conversation_history: "",
            user_message: content,
            max_tokens: 8,
        };
        match self.llm.chat(&request) {
            Ok(r) => {
                let first = r
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .trim_matches(|c: char| !c.is_alphabetic())
                    .to_string();
                if first.is_empty() {
                    None
                } else {
                    Some(first.to_uppercase())
                }
            }
            Err(e) => {
                log::debug!("verdict judge unavailable ({e:#}); falling through to chat");
                None
            }
        }
    }

    /// Conversational yes/no judge over a pending "is it me?" question. The
    /// LLM classifies the owner's answer in *any* language; returns `Some` only
    /// on a clear YES or NO, and `None` whenever the reply is not a verdict
    /// (questions, jokes, irrelevant text) so normal chat can continue.
    fn llm_yes_no(&self, question: &str, reply: &str) -> Option<bool> {
        if reply.chars().count() > 200 {
            return None;
        }
        let label = self.llm_roundtrip_short(
            "You classify a single user reply. A security bot asked the owner \
             a yes/no question about a machine event. Was the user's reply a \
             clear YES (confirm/approve) or a clear NO (deny/reject)? Reply \
             with exactly one word: YES, NO, or UNSURE (UNSURE when it is not \
             a clear answer: questions, jokes, or anything irrelevant).",
            &format!("Question: {question}\nUser's reply: \"{reply}\""),
        )?;
        match label.as_str() {
            "YES" => Some(true),
            "NO" => Some(false),
            _ => None,
        }
    }

    /// Arm a privileged action: set it as pending and ask for confirmation.
    fn arm_control(&self, chat_id: i64, kind: ControlKind) {
        let nonce = {
            let mut guard = self.state.lock().expect("bot state mutex");
            guard.pending_control = Some(PendingControl::new(kind.clone(), chat_id));
            guard
                .pending_control
                .as_ref()
                .map(|p| p.nonce.clone())
                .expect("just-armed control")
        };
        log::warn!(
            "telegram: control ARMED by paired chat {chat_id}: {:?} (confirm with {nonce})",
            kind
        );

        let secs = PendingControl::CONFIRMATION_WINDOW.as_secs();
        let label = kind.label();
        let _ = self.send(
            chat_id,
            &format!(
                "⚠️ *Control armed:* `{label}`\n\
                 This is a privileged, {}. To execute, reply exactly:\n\n\
                 `{nonce}`\n\n\
                 It expires in {secs} s — just ignore this message to cancel \
                 (or reply `cancel`).",
                if kind.is_fatal_to_host() {
                    "potentially FATAL action for this machine"
                } else {
                    "ring-0 machine-language operation"
                },
            ),
        );
    }

    /// Arm a `triplefault*` control with its anti-loop guards: it must be
    /// possible to fire the command every time the user asks (with explicit
    /// `confirm`), but the machine must NEVER reboot/power-off in a loop.
    /// Two independent layers guarantee that:
    ///   • per-boot latch in the kernel module (`-EBUSY` on duplicates);
    ///   • per-daemon-run latch here, armed once and only re-armed by a human
    ///     (`/triplefault allow`) or by a fresh daemon start after reboot.
    /// Nothing here retries.
    fn try_arm_triplefault(&self, chat_id: i64, kind: ControlKind) {
        // The feature only applies when our ring-0 module is actually up.
        if !crate::ring3::module_loaded() {
            let hint = crate::ring3::load_hint();
            let _ = self.send(
                chat_id,
                &format!(
                    "❌ Kernel module not loaded: `/proc/sysentinel_metrics` is \
                     missing, so there's no way to force a triplefault from ring-0.\n{hint}"
                ),
            );
            return;
        }
        {
            let guard = self.state.lock().expect("bot state mutex");
            if guard.triplefault_fired {
                let _ = self.send(
                    chat_id,
                    "⚠️ A triplefault already fired in this daemon session. \
                     I never retry it on my own. If the machine is still up (VM? firmware \
                     that refused?), use `/triplefault allow` and re-arm it — or restart the \
                     daemon for a clean session.",
                );
                return;
            }
        }
        self.arm_control(chat_id, kind);
    }

    /// Arm a `kernelpanic` control. No latching needed: `panic()` is terminal
    /// by definition (the machine halts, or the kernel reboots once per its
    /// own `panic=N` policy — nothing here loops or retries). Only needs the
    /// module to be up, because the daemon has no `CAP_SYS_ADMIN` to write
    /// `/proc/sysrq-trigger` (and SysRq needs `CONFIG_MAGIC_SYSRQ` + `sysrq=1`).
    fn try_arm_kernelpanic(&self, chat_id: i64, kind: ControlKind) {
        if !crate::ring3::module_loaded() {
            let hint = crate::ring3::load_hint();
            let _ = self.send(
                chat_id,
                &format!(
                    "❌ Kernel module not loaded: without ring-0 there's no way to \
                     trigger `panic()` from here (the daemon has no `CAP_SYS_ADMIN`, so \
                     `/proc/sysrq-trigger` wouldn't work either).\n{hint}",
                ),
            );
            return;
        }
        self.arm_control(chat_id, kind);
    }

    /// Route a conversational control order (recognized by the LLM in any
    /// language) onto the correct arm path. Only *arms* — the deterministic
    /// `confirm` gate and the module/offline checks below are unchanged.
    fn arm_conversational_control(&self, chat_id: i64, kind: ControlKind) {
        match kind {
            ControlKind::KernelPanic => self.try_arm_kernelpanic(chat_id, kind),
            ControlKind::TripleFaultRestart | ControlKind::TripleFaultShutdown => {
                self.try_arm_triplefault(chat_id, kind)
            }
            ControlKind::Reboot | ControlKind::PowerOff => self.arm_control(chat_id, kind),
            // CR writes stay slash-only (`/cr0=0x…`): parsing a hex value out of
            // free-form text is a footgun the LLM must never drive.
            ControlKind::Cr0Wp(_) | ControlKind::SetCr(_, _) => {}
        }
    }

    /// `/triplefault allow` — human-gated re-arm after a fired triplefault.
    /// This only clears the daemon latch; the actual command still needs a
    /// fresh ARM + `confirm`, so nothing can ever fire automatically.
    fn rearm_triplefault(&self, chat_id: i64) {
        let was_set = {
            let mut guard = self.state.lock().expect("bot state mutex");
            let w = guard.triplefault_fired;
            guard.triplefault_fired = false;
            w
        };
        if was_set {
            let _ = self.send(
                chat_id,
                "✅ Triplefault latch released. You can re-arm it \
                 (`/triplefault restart` or `/triplefault shutdown`) and confirm it. \
                 I still won't retry anything on my own.",
            );
        } else {
            let _ = self.send(
                chat_id,
                "ℹ️ No triplefault has fired yet: the latch was clear. \
                 You can arm `/triplefault restart|shutdown` directly.",
            );
        }
    }

    /// Execute a confirmed control: send the kernel command to the module.
    fn execute_control(&self, chat_id: i64, pending: PendingControl) {
        let label = pending.kind.label();
        log::warn!(
            "telegram: control CONFIRMED and executing in chat {chat_id}: {:?}",
            pending.kind
        );

        // Latch a triplefault BEFORE it reaches the kernel: one per daemon
        // session, no retries, no loops. The machine is expected to go down
        // right now; if it somehow survives, only a human can re-arm.
        let is_triplefault = matches!(
            pending.kind,
            ControlKind::TripleFaultRestart | ControlKind::TripleFaultShutdown
        );
        if is_triplefault {
            self.state.lock().expect("bot state mutex").triplefault_fired = true;
        }

        // Tell the user BEFORE the kernel does it — once reboot/poweroff runs
        // this daemon (and the machine) may go down mid-reply.
        let _ = self.send(chat_id, &format!("⚡ Executing: `{label}` …"));

        let command = pending.kind.kernel_command();
        if let Err(e) = kernel_snap::KernelSnapshot::send_command(&command) {
            log::error!("telegram: control execution FAILED ({command}): {e}");
            let _ = self.send(chat_id, &format!("❌ Execution failed: {e}"));
        } else if matches!(
            pending.kind,
            ControlKind::TripleFaultRestart | ControlKind::TripleFaultShutdown | ControlKind::KernelPanic
        ) {
            let what = if pending.kind == ControlKind::KernelPanic {
                "⚡ Kernel panic fired: the machine stops (or reboots per `panic=N`). \
                 It's terminal — I won't retry it on my own here."
            } else {
                "⚡ Triplefault sent: expect a reset/power-off within seconds. \
                 If it doesn't happen, tell me — and remember I won't retry it on my own here."
            };
            log::warn!(
                "telegram: terminal control ({command}) sent — expecting immediate \
                 reset/panic; no retry will be issued"
            );
            let _ = self.send(chat_id, what);
        }
    }

    /// Execute a confirmed SELinux allow: build + load the policy module.
    fn execute_selinux_allow(&self, chat_id: i64, pending: PendingSelinuxAllow) {
        let id = pending.denial.id;
        log::warn!(
            "telegram: SELinux allow CONFIRMED (chat {chat_id}) for denial #{id}"
        );

        let _ = self.send(
            chat_id,
            &format!("⚡ Permitiendo el acceso de la denial `#{id}` …"),
        );

        match selinux::apply_allow(&pending.denial, &format!("allow{id}")) {
            Ok(msg) => {
                log::info!("telegram: SELinux policy module loaded for #{id}");
                let _ = self.send(chat_id, &msg);
            }
            Err(e) => {
                log::error!("telegram: SELinux allow FAILED for #{id}: {e:#}");
                let _ = self.send(chat_id, &format!("❌ Failed to permit `#{id}`:\n{e:#}"));
            }
        }
    }

    /// Report the current value of a control register to the paired chat.
    fn report_control_register(&self, chat_id: i64, reg: u8) {
        match kernel_snap::KernelSnapshot::current_cr(reg) {
            Some(v) => {
                let mut msg = format!("Control register cr{reg}: `{v:#016x}`");
                if reg == 0 {
                    let wp = (v >> 16) & 1 == 1;
                    msg.push_str(&format!(
                        "  (CR0.WP write-protect: {})",
                        if wp { "✅ ON" } else { "⚠️ OFF" }
                    ));
                }
                let _ = self.send(chat_id, &msg);
            }
            None => {
                let hint = crate::ring3::load_hint();
                let _ = self.send(
                    chat_id,
                    &format!(
                        "/proc/sysentinel_metrics is not readable (kernel module not \
                         loaded or has no CR support), so no ring-0 register read is \
                         possible. Load the module first.{hint}"
                    ),
                );
            }
        }
    }

    // ── Commands ──────────────────────────────────────────────────────────────

    /// `/start` — show the main options menu.
    fn cmd_start(&self, chat_id: i64) {
        let text = "\
🖥 *sysentinel* — your PC companion is online\n\
\n\
*What can I do for you?*\n\
  1️⃣  Ask me anything about your machine — just type your question.\n\
  2️⃣  /status — uptime, CPU load, memory\n\
  3️⃣  /hardware — lscpu, GPU (nvidia-smi if present), PCI, TSC\n\
  4️⃣  /lsblk /lsusb /lsmod /pci — block devices, USB, modules, graphics\n\
  5️⃣  /alerts — dmesg: OOM, panics, segfaults, SIGILL, core dumps\n\
  6️⃣  /selinux — SELinux AVC denials: explain, allow (confirm), deny\n\
  7️⃣  /firmware — Intel ME / AMD PSP firmware info\n\
  8️⃣  /cr0 /cr3 /cr4 /cr8 — read control registers\n\
  9️⃣  /reboot /poweroff /triplefault /kernelpanic — (confirm required) reboot, shutdown, hard reset, panic\n\
  🔟  /memory /showmemory /remember — conversation & long-term memory\n\
  1️⃣1️⃣  /settings — choose what I notify you about\n\
  1️⃣2️⃣  /llm — switch LLM: openai, deepseek, claude, gemini, llama.cpp, local, none\n\
  1️⃣3️⃣  /model /models — pick the model (API vision / local gguf)\n\
  1️⃣4️⃣  /resetcontext — clear the conversation history (context.txt)\n\
  1️⃣5️⃣  /help — full command list\n\
  1️⃣6️⃣  /unpair — disconnect this chat\n\
\n\
🗣 Ask me about anything in plain language. I mirror my mood from the \
machine's live state (load, memory, temperature, PMU).\n\
\n\
⚠️ *Anything privileged needs your OK*: control-register writes, reboot, \
poweroff, triplefault and SELinux policy changes only run after \
`confirm`, never silently."; 
        let _ = self.send_markdown(chat_id, text);
    }

    fn cmd_help(&self, chat_id: i64) {
        let text = "\
🖥 *sysentinel* — your PC companion\n\
\n\
*System:*\n\
  /status        — uptime, CPU load, memory\n\
  /hardware      — CPU (lscpu), GPU (nvidia-smi if any), PCI, TSC/rdtscp\n\
  /lsblk         — block devices\n\
  /lsusb         — USB devices\n\
  /lsmod         — loaded kernel modules\n\
  /pci           — display adapters (graphics)\n\
  /firmware      — Intel ME / AMD PSP firmware (HAL ring −3)\n\
  /definehome    — define/check that THIS is your PC (hardware fingerprint + ring −3 silicon)\n\
  /definehome status — saved HOME profile + firmware drift (same PC, reflashes)\n\
  /definehome hal    — ring −3 coprocessor detail (ME/HECI/MKHI · PSP · TPM · chipset)\n\
  /definehome audit  — bootkit audit (alias `/bootkit`)\n\
  /definehome delete — forget the saved PC (you changed machines)\n\
  /bootkit       — bootkit audit: UEFI, Secure Boot, lockdown, taint, LSTAR, ring −3\n\
\n\
*Login / session management:*\n\
  When someone logs in (GUI or SSH) I let you know. You reply:\n\
    `si fui yo` (it was me) → keep it, `no` → close it.\n\
  /login kill <pid> — manually arm closing a session\n\
  /login list        — same as /logins\n\
\n\
*Foreign modules:*\n\
  If a module from outside the official tree is loaded, I'll ask:\n\
    `sácalo` (remove it) → unload it, `déjalo` (leave it) → keep it, `no estoy seguro` (not sure) → I analyse it.\n\n\
*SELinux denials:*\n\
  /selinux              — list pending denials\n\
  /selinux explain <id> — what the denial is about\n\
  /selinux allow <id>   — arm the policy change (then `confirm`)\n\
  /selinux deny <id>    — ignore this denial\n\
\n\
*Memory:*\n\
  /memory        — show rolling conversation window (context.txt)\n\
  /showmemory    — show long-term memory (memory.txt)\n\
  /remember <t>  — record a durable fact\n\
  /resetcontext  — clear conversation history\n\
\n\
*Notifications:*\n\
  /settings             — view my notification categories\n\
  /settings <cat> on|off — flip one (kernel, selinux, thermal, memory, load, htop, pmu, battery, tsc, diag, control, login, hypercall, modwatch, proactive)\n\
\n\
*LLM engine:*\n\
  /llm           — show current LLM backend + list\n\
  /llm <name>    — switch live: openai, deepseek, anthropic (claude), gemini, llama (llama.cpp server), local, none\n\
  /model         — show active model (provider/selection)\n\
  /model <name>  — API vision (e.g. deepseek-v4-flash-vision-exp) or local gguf\n\
  /models [name] — list local models (recursive, with mmproj/mtp) or generate the llama-server command\n\
  /settings llama_ctx <tokens> — llama.cpp context length (n_ctx, ≤ server `-c`; 0 = default)\n\
  /settings local_ctx <tokens> — in-process local context (0 = config default)\n\
  /settings context_entries <n> — conversation turns kept in context.txt\n\
\n\
*Control registers (read, no confirm):*\n\
  /cr0 /cr2 /cr3 /cr4 /cr8\n\
\n\
*Privileged (ARM then CONFIRM — never auto-executed):*\n\
   /reboot                 → arm reboot\n\
   /poweroff               → arm shutdown\n\
   /triplefault            → arm hard CPU reset (bogus IDT + int3)\n\
   /triplefault restart    → same, explicit\n\
   /triplefault shutdown   → arm forced kernel_power_off()\n\
   /triplefault allow      → re-arm after one fired (still needs confirm)\n\
   /kernelpanic            → arm a deliberate kernel panic (panic())\n\
   /cr0 wp on|off          → arm CR0 write-protect toggle\n\
   /crX=0x… (X=0,3,4,8)    → arm writing a control register\n\
   confirm                 → execute the armed control / SELinux allow\n\
   cancel                  → abort the armed control / SELinux allow\n\
 \n\
 Triplefault fires exactly ONCE per boot and is never retried: the module \
 latches it per-boot (-EBUSY on any duplicate) and the daemon latches it per \
 session. After a real reboot everything re-arms itself; it is never \
 re-looped. `kernelpanic` is terminal by itself: the \
 machine halts (or reboots once per `panic=N`) — it is not \
 retried either.\n\
 Controls expire after 60 s if not confirmed. They cost no LLM tokens.\n\
 SELinux policy modules, reboots, power-offs, triplefaults, kernel panics \
 and CR writes always ask for your `confirm` first.\n\
\n\
Or just ask me anything about your machine in plain language.\n\
I mirror my mood from the machine's live state (load, memory, temperature, \
PMU).";
        let _ = self.send_markdown(chat_id, text);
    }

    /// `/resetcontext` — wipe the rolling conversation history (context.txt).
    /// Long-term memory (memory.txt) is NOT touched.
    fn cmd_reset_context(&self, chat_id: i64) {
        match self.memory.reset_context() {
            Ok(()) => {
                log::info!("telegram: conversation context reset by paired user (chat={chat_id})");
                let _ = self.send(
                    chat_id,
                    "🧹 Conversation history cleared. \
                     I still remember everything in *memory.txt*, though.",
                );
            }
            Err(e) => {
                log::error!("telegram: failed to reset context: {e:#}");
                let _ = self.send(
                    chat_id,
                    "❌ Could not clear the context file. Check daemon logs.",
                );
            }
        }
    }

    fn cmd_status(&self, chat_id: i64) {
        match gather_system_snapshot() {
            Ok(snap) => { let _ = self.send_markdown(chat_id, &snap); }
            Err(e)   => { let _ = self.send(chat_id, &format!("Error reading system status: {e:#}")); }
        }
    }

    fn cmd_alerts(&self, chat_id: i64) {
        let alerts: Vec<String> = {
            let guard = self.state.lock().expect("bot state mutex");
            guard.recent_alerts.iter().cloned().collect()
        };
        if alerts.is_empty() {
            let _ = self.send(chat_id, "✅ No kernel alerts recorded since daemon start.");
        } else {
            let mut msg = format!("⚠️ *Last {} kernel alert(s):*\n\n", alerts.len());
            for (i, a) in alerts.iter().enumerate() {
                msg.push_str(&format!("{}\\. `{}`\n", i + 1, escape_markdown(a)));
            }
            let _ = self.send_markdown(chat_id, &msg);
        }
    }

    fn cmd_firmware(&self, chat_id: i64) {
        let status = mei::query_firmware_status();

        // Enrich with the ring-0 kernel-module view (authoritative platform
        // + co-processor presence, correct on both Intel ME and AMD PSP hosts).
        let mut msg = format!("{status}");
        match kernel_snap::KernelSnapshot::read() {
            Some(snap) => {
                if let Some(h) = &snap.hypervisor {
                    msg.push_str(&format!("\nPlatform/hypervisor (ring-0): {h}"));
                }
                if let Some(p) = &snap.psp {
                    msg.push_str(&format!("\nAMD PSP (ring-0): {p}"));
                }
            }
            None => {
                msg.push_str(&format!(
                    "\n(kernel module not loaded — platform detected in ring-3: {})",
                    crate::ring3::hypervisor_detect(),
                ));
            }
        }
        let _ = self.send(chat_id, &msg);
    }

    /// `/selinux` — list, explain, allow (needs `confirm`) or deny denials.
    fn cmd_selinux(&self, chat_id: i64, text: &str) {
        let rest = text.trim().strip_prefix("/selinux").unwrap_or("").trim();
        let sub = rest
            .split(|c: char| c.is_whitespace())
            .next()
            .unwrap_or("")
            .to_lowercase();
        let arg = rest.split_once(|c: char| c.is_whitespace()).map(|x| x.1)
            .unwrap_or("")
            .trim()
            .to_string();

        // ── No argument: list the pending denials ────────────────────────────
        if rest.is_empty() || matches!(sub.as_str(), "list" | "ls" | "lista" | "pending") {
            let denials: Vec<AvcDenial> = {
                let guard = self.state.lock().expect("bot state mutex");
                guard.recent_selinux.iter().cloned().rev().collect()
            };
            if denials.is_empty() {
                let _ = self.send(
                    chat_id,
                    "✅ No SELinux denials recorded since daemon start.\n\
                     When one arrives I will walk you through it with `/selinux`.",
                );
                return;
            }
            let mut msg = format!("⛔ *SELinux denials pending:* {} this boot\n\n", denials.len());
            for d in &denials {
                msg.push_str(&format!("{}\n\n", selinux::render(d)));
            }
            msg.push_str(
                "Actions: `/selinux explain <id>` · `/selinux allow <id>` (requires \
                 your `confirm`) · `/selinux deny <id>`",
            );
            let _ = self.send_markdown(chat_id, &msg);
            return;
        }

        let Some(id) = arg.parse::<u32>().ok() else {
            let _ = self.send(
                chat_id,
                "Usage:\n  `/selinux` — list pending denials\n  \
                 `/selinux explain <id>` — what the denial is about\n  \
                 `/selinux allow <id>` — arm the policy change (then `confirm`)\n  \
                 `/selinux deny <id>` — ignore this denial",
            );
            return;
        };

        match sub.as_str() {
            "explain" | "show" | "info" | "explicar" | "que" => {
                let denial = {
                    let guard = self.state.lock().expect("bot state mutex");
                    guard.get_selinux(id)
                };
                let Some(denial) = denial else {
                    let _ = self.send(chat_id, &format!("❌ No denial with id `#{id}` recorded."));
                    return;
                };
                match selinux::explain_rule(&denial) {
                    Ok(rule) => {
                        let _ = self.send_markdown(
                            chat_id,
                            &format!("📖 *Denial #{id}*\n{}\n\n*Rule that would permit it:*\n```\n{rule}\n```\n\nAllow it? → `/selinux allow {id}`", selinux::render(&denial)),
                        );
                    }
                    Err(e) => {
                        log::warn!("audit2allow unavailable for #{id}: {e:#}");
                        let _ = self.send(
                            chat_id,
                            &format!(
                                "📖 *Denial #{id}*\n{}\n\nCould not generate the allow \
                                 rule: `audit2allow` is missing (install \
                                 `policycoreutils-python-utils`).",
                                selinux::render(&denial)
                            ),
                        );
                    }
                }
            }
            "allow" | "permitir" | "permit" => {
                let denial = {
                    let guard = self.state.lock().expect("bot state mutex");
                    guard.get_selinux(id)
                };
                let Some(denial) = denial else {
                    let _ = self.send(chat_id, &format!("❌ No denial with id `#{id}` recorded."));
                    return;
                };
                {
                    let mut guard = self.state.lock().expect("bot state mutex");
                    guard.pending_selinux = Some(PendingSelinuxAllow::new(denial, chat_id));
                }
                log::warn!("telegram: SELinux allow ARMED by chat {chat_id} for #{id}");
                let _ = self.send(
                    chat_id,
                    &format!(
                        "⚠️ *SELinux allow armed* for `#{id}`: I will build and load a \
                         policy module that permits this exact access.\n\
                         Establishing a policy module changes the SELinux policy and \
                         persists across reboots.\n\
                         Reply `confirm` within {} s to apply, or `cancel`.",
                        PendingSelinuxAllow::CONFIRMATION_WINDOW.as_secs()
                    ),
                );
            }
            "deny" | "denegar" | "block" => {
                let denied = {
                    let mut guard = self.state.lock().expect("bot state mutex");
                    guard.deny_selinux(id)
                };
                match denied {
                    Some(_) => {
                        log::info!("telegram: SELinux denial #{id} ignored by user (chat {chat_id})");
                        let _ = self.send(
                            chat_id,
                            &format!(
                                "🔕 Denial `#{id}` ignored. SELinux keeps its default \
                                 posture (deny) — I simply won't bother you about it again."
                            ),
                        );
                    }
                    None => {
                        let _ = self.send(chat_id, &format!("❌ No denial with id `#{id}` recorded."));
                    }
                }
            }
            _ => {
                let _ = self.send(
                    chat_id,
                    "Usage:\n  `/selinux` — list pending denials\n  \
                     `/selinux explain <id>` — what the denial is about\n  \
                     `/selinux allow <id>` — arm the policy change (then `confirm`)\n  \
                     `/selinux deny <id>` — ignore this denial",
                );
            }
        }
    }

    /// `/settings` — view or flip a notification category.
    fn cmd_settings(&self, chat_id: i64, rest: &str) {
        let mut guard = self.settings.lock().expect("settings mutex");
        if rest.is_empty() {
            let _ = self.send_markdown(chat_id, &guard.to_table());
            return;
        }

        let mut it = rest.splitn(2, |c: char| c.is_whitespace());
        let cat = it.next().unwrap_or("").to_lowercase();
        let on  = it.next().unwrap_or("").to_lowercase();

        if guard.enabled(&cat).is_none()
            && cat != "llama_ctx"
            && cat != "context_entries"
            && cat != "local_ctx"
            && cat != "login_timeout"
            && cat != "exec_timeout"
            && cat != "exec_max_jobs"
            && cat != "luks_timeout"
            && cat != "luks_deny"
            && cat != "backends"
        {
            let _ = self.send(
                chat_id,
                &format!(
                    "❌ Unknown category `{cat}`. Known: {} + numeric (llama_ctx, \
                     local_ctx, context_entries, login_timeout, exec_timeout, \
                     luks_timeout) + luks_deny + backends",
                    crate::settings::CATEGORIES.join(", ")
                ),
            );
            return;
        }

        // `/settings backends <a,b,c>` — the ordered LLM fallback chain.
        // Empty name list resets to the `[llm].backend` chain from config.
        if cat == "backends" {
            let names: Vec<String> = on
                .split(|c: char| c == ',' || c.is_whitespace())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
                .collect();
            let unknown: Vec<&String> = names
                .iter()
                .filter(|n| !crate::llm::PROVIDER_NAMES.contains(&n.as_str()))
                .collect();
            if !unknown.is_empty() {
                let _ = self.send(
                    chat_id,
                    &format!(
                        "❌ Unknown provider(s): {}. Known: {}",
                        unknown
                            .iter()
                            .map(|n| n.as_str())
                            .collect::<Vec<_>>()
                            .join(", "),
                        crate::llm::PROVIDER_NAMES.join(", ")
                    ),
                );
                return;
            }
            guard.llm_backends = names.clone();
            guard.llm_provider.clear();
            let path = std::path::Path::new(&self.config.general.settings_file);
            if let Err(e) = guard.save(path) {
                log::error!("failed to persist backends: {e:#}");
            }
            drop(guard);

            let prefs = self.llm_prefs();
            match llm::build_chain(&self.config, &names, &prefs) {
                Ok(b) => self.llm.swap(b),
                Err(e) => log::warn!("applying /settings backends rebuild failed: {e:#}"),
            }
            let reply = if names.is_empty() {
                "🔀 Backends reset to `[llm].backend` from the config."
            } else {
                &format!(
                    "🔀 Fallback chain now: `{}`. Tried in order; if one fails, it falls through to the next.",
                    names.join("` → `")
                )
            };
            let _ = self.send_markdown(chat_id, reply);
            return;
        }

        // Numeric keys — the "contexto" knobs, adjustable live:
        //   /settings llama_ctx <tokens>        (0 = llama-server default)
        //   /settings local_ctx <tokens>        (0 = config default)
        //   /settings context_entries <turns>   (0 = config default)
        //   /settings login_timeout <secs>      (0 = no timeout → keep open)
        //   /settings exec_timeout <secs>       (0 = no timeout → keep open)
        //   /settings luks_timeout <secs>       (0 = reset to 120 s default)
        if cat == "llama_ctx"
            || cat == "context_entries"
            || cat == "local_ctx"
            || cat == "login_timeout"
            || cat == "exec_timeout"
            || cat == "exec_max_jobs"
            || cat == "luks_timeout"
        {
            let parsed: Result<usize, _> = on.parse();
            let value = match parsed {
                Ok(n) => n,
                Err(_) => {
                    let _ = self.send_markdown(
                        chat_id,
                        &format!(
                            "ℹ️ `{cat}` is a number. Usage:\n  `/settings {cat} <value>`\n\
                             (0 = use server/config default)"
                        ),
                    );
                    return;
                }
            };
            match cat.as_str() {
                "llama_ctx"    => guard.llama_ctx = value as u32,
                "local_ctx"    => guard.local_ctx = value as u32,
                "context_entries" => guard.context_entries = value,
                "login_timeout" => guard.login_timeout = value as u64,
                "exec_timeout" => guard.exec_timeout = value as u64,
                "exec_max_jobs" => guard.exec_max_jobs = value as u64,
                "luks_timeout" => {
                    guard.luks_timeout = if value == 0 {
                        120 // default_luks_timeout()
                    } else {
                        value as u64
                    }
                }
                _ => unreachable!(),
            }
            let path = std::path::Path::new(&self.config.general.settings_file);
            if let Err(e) = guard.save(path) {
                log::error!("failed to persist settings: {e:#}");
            }
            drop(guard);

            let what = match cat.as_str() {
                "llama_ctx" => "llama.cpp context (n_ctx)",
                "local_ctx" => "in-process local context (n_ctx)",
                "login_timeout" => "login verdict window (seconds)",
                "exec_timeout" => "max /exec foreground run (seconds)",
                "exec_max_jobs" => "max concurrent /exec background jobs",
                "luks_timeout" => "LUKS \"is it me?\" answer window (seconds)",
                _           => "conversation turns kept (context.txt)",
            };
            let _ = self.send_markdown(
                chat_id,
                &format!(
                    "⚙️ `{cat}` is now `{value}` ({what}).{}\n",
                    if value == 0 {
                        " Back to server/config default.".to_string()
                    } else {
                        String::new()
                    }
                ),
            );

            // Apply it: context_entries touches the live MemoryStore; the ctx
            // knobs rebuild the active LLM backend with the new n_ctx. The
            // timeout knobs (login/exec/luks) only affect the watchers.
            if cat == "context_entries" {
                self.memory.set_max_entries(if value == 0 {
                    self.config.memory.context_max_entries
                } else {
                    value
                });
            } else if cat == "llama_ctx" || cat == "local_ctx" {
                let chain = self.current_llm_chain();
                let prefs = self.llm_prefs();
                match llm::build_chain(&self.config, &chain, &prefs) {
                    Ok(b) => self.llm.swap(b),
                    Err(e) => log::warn!("applying {cat} rebuild failed: {e:#}"),
                }
            }
            return;
        }

        // `/settings luks_deny poweroff|triplefault|none` — the LUKS deny
        // action applied when the owner answers `no` (or the ask times out).
        if cat == "luks_deny" {
            let value = on.trim();
            if !matches!(value, "poweroff" | "triplefault" | "none") {
                let _ = self.send(
                    chat_id,
                    "Usage: `/settings luks_deny poweroff|triplefault|none`\n\
                     `poweroff` = ACPI orderly power-off, `triplefault` = forced \
                     power-down (CPU reset), `none` = log only.",
                );
                return;
            }
            guard.luks_deny_action = value.to_string();
            let path = std::path::Path::new(&self.config.general.settings_file);
            if let Err(e) = guard.save(path) {
                log::error!("failed to persist settings: {e:#}");
            }
            let _ = self.send(
                chat_id,
                &format!(
                    "🔓 `luks_deny_action` is now `{}`. Applied if the owner replies \
                     `no` (or the `luks_timeout` expires) to an \"is it me?\" ask.",
                    guard.luks_deny_action
                ),
            );
            return;
        }

        let value = match on.as_str() {
            "on" | "true" | "yes" | "sí" | "si" | "1" => Some(true),
            "off" | "false" | "no" | "0" => Some(false),
            _ => {
                let _ = self.send(
                    chat_id,
                    &format!("Usage: `/settings {} on|off` (currently `{}`).", cat,
                             if guard.enabled(&cat).unwrap() { "on" } else { "off" }),
                );
                return;
            }
        };
        let value = value.unwrap();
        guard.set_enabled(&cat, value);
        let path = std::path::Path::new(&self.config.general.settings_file);
        if let Err(e) = guard.save(path) {
            log::error!("failed to persist settings: {e:#}");
        }
        let _ = self.send(
            chat_id,
            &format!(
                "🔔 `{cat}` is now `{}`. It persists; flip it again any time with `/settings`.",
                if value { "ON" } else { "OFF" }
            ),
        );
    }

    /// `/llm` — view or switch the LLM provider live (openai, deepseek,
    /// anthropic/claude, gemini, llama.cpp, local, none). `/llm <name>`
    /// switches to a single provider; `/settings backends a,b,c` sets the
    /// full fallback chain. Both persist to the settings file.
    fn cmd_llm(&self, chat_id: i64, rest: &str) {
        if rest.is_empty() {
            let chain = self.current_llm_chain();
            let mut lines = format!(
                "🧠 *LLM backend chain* — now: `{}`\n\nAvailable:\n",
                chain.join("` → `")
            );
            for (name, hint) in crate::llm::PROVIDER_HINTS {
                lines.push_str(&format!("  ▪ `{name}` — {hint}\n"));
            }
            lines.push_str("\nSingle switch: `/llm <name>`\nWhole chain: `/settings backends a,b,c`");
            let _ = self.send_markdown(chat_id, &truncate_for_telegram(&lines));
            return;
        }

        let name = rest.trim().to_lowercase();
        if !crate::llm::PROVIDER_NAMES.contains(&name.as_str()) {
            let _ = self.send(
                chat_id,
                &format!(
                    "❌ Unknown provider `{name}`. Known: {}",
                    crate::llm::PROVIDER_NAMES.join(", ")
                ),
            );
            return;
        }

        let backend = match llm::build_chain(&self.config, std::slice::from_ref(&name), &self.llm_prefs()) {
            Ok(b) => b,
            Err(e) => {
                let _ = self.send(chat_id, &format!("⚠️ Can't switch to `{name}`: {e:#}"));
                return;
            }
        };

        self.llm.swap(backend);
        {
            let mut guard = self.settings.lock().expect("settings mutex");
            guard.llm_provider = name.clone();
            let path = std::path::Path::new(&self.config.general.settings_file);
            if let Err(e) = guard.save(path) {
                log::error!("failed to persist llm provider: {e:#}");
            }
        }
        let _ = self.send(
            chat_id,
            &format!(
                "⚡ Switched brains: now I talk through `{name}` and it's persisted \
                 (survives restarts). Same persona, different larynx."
            ),
        );
    }

    /// Where the local model inventory lives (`[llm.local].model_path`, a
    /// directory or a bare file → we scan its parent).
    fn local_models_root(&self) -> Option<std::path::PathBuf> {
        let lc = self.config.llm.local.as_ref()?;
        let p = std::path::Path::new(&lc.model_path);
        Some(if p.is_dir() {
            p.to_path_buf()
        } else {
            p.parent().map(|d| d.to_path_buf()).unwrap_or_else(|| p.to_path_buf())
        })
    }

    /// `/models [name]` — list the local GGUF models discovered recursively
    /// (with their vision mmproj / mtp companions), and for a named model the
    /// ready-to-run `llama-server` command.
    fn cmd_models(&self, chat_id: i64, rest: &str) {
        let Some(root) = self.local_models_root() else {
            let _ = self.send(
                chat_id,
                "❌ No `[llm.local]` model_path configured — nothing to scan.",
            );
            return;
        };
        let entries = llm::models::scan(&root);
        if entries.is_empty() {
            let _ = self.send(
                chat_id,
                &format!(
                    "🗑️ No `.gguf` models found under `{}` (recursive scan).",
                    root.display()
                ),
            );
            return;
        }

        if let Some(want) = rest.split_whitespace().next() {
            let Some(entry) = llm::models::find(&entries, want) else {
                let names: Vec<String> = entries.iter().map(|e| e.name.clone()).collect();
                let _ = self.send(
                    chat_id,
                    &format!("❌ No modelo `{}`. Tengo: {}", want, names.join(", ")),
                );
                return;
            };
            let ctx = self.effective_llama_ctx().max(8192);
            let cmd = llm::models::server_command(entry, ctx, 99);
            let mut msg = format!("📦 *Modelo:* `{}`\n\n```bash\n{cmd}\n```", entry.name);
            msg.push_str("\n\nArranca con eso y luego `/llm llama`.");
            let _ = self.send_markdown(chat_id, &msg);
            return;
        }

        let selected = {
            let guard = self.settings.lock().expect("settings mutex");
            guard.local_model.clone()
        };
        let mut lines = format!(
            "📦 *Modelos locales* en `{}` ({}, recursivo):\n\n",
            root.display(),
            entries.len()
        );
        for e in &entries {
            let mark = if e.name == selected { " ✅" } else { "" };
            lines.push_str(&format!(
                "• {} *`{}`* ({:.1} GB){}",
                if e.name == selected { "●" } else { "○" },
                e.name,
                e.size_mb as f64 / 1024.0,
                mark,
            ));
            if e.projector.is_some() {
                lines.push_str(" 🌄");
            }
            if e.mtp.is_some() {
                lines.push_str(" ⚡mtp");
            }
            lines.push('\n');
        }
        lines.push_str("\nPick one: `/model <name>`\n");
        lines.push_str("Ready command: `/models <name>`\n");
        lines.push_str("Local provider: `/llm local`");
        let _ = self.send_markdown(chat_id, &truncate_for_telegram(&lines));
    }

    /// `/model [<provider>] [<m1,m2>]` — show or switch the working model(s).
    ///
    /// * no args → shows the current chain, per-provider model lists and the
    ///   global API/local model override;
    /// * `/model <name>` (no provider) → legacy single override (API → `llm_model`,
    ///   local → `local_model`);
    /// * `/model <provider> m1,m2` → sets an ordered model chain for that
    ///   provider (persisted in settings.json, `llm_models`). Examples:
    ///   `/model gemini gemini-2.5-pro,gemini-2.5-flash`
    ///   `/model deepseek deepseek-chat,deepseek-reasoner`
    ///   `/model local qwen3.5-2b,qwen3.5-0.8b`
    fn cmd_model(&self, chat_id: i64, rest: &str) {
        let chain = self.current_llm_chain();
        let current = chain.join("` → `");
        if rest.trim().is_empty() {
            let guard = self.settings.lock().expect("settings mutex");
            let mut by_provider: Vec<String> = guard
                .llm_models
                .iter()
                .filter(|(_, ms)| !ms.is_empty())
                .map(|(p, ms)| format!("`{p}`: `{}`", ms.join("` → `")))
                .collect();
            by_provider.sort();
            let model_list = if by_provider.is_empty() {
                let cur = if guard.llm_model.is_empty() {
                    self.config.llm.model.clone()
                } else {
                    guard.llm_model.clone()
                };
                format!(
                    "API global: `{cur}`\nlocal: `{}`",
                    if guard.local_model.is_empty() {
                        "auto (single model)".to_string()
                    } else {
                        guard.local_model.clone()
                    }
                )
            } else {
                format!("por provider:\n{}", by_provider.join("\n"))
            };
            let _ = self.send_markdown(
                chat_id,
                &format!(
                    "🧬 *Modelo activo*  ·  chain: `{current}`\n{model_list}\n\n\
                     Cambia con:\n`/model <name>` (override global)\n\
                     `/model <provider> m1,m2` (cadena por provider)\n\
                     Ej: `/model gemini gemini-2.5-pro,gemini-2.5-flash`"
                ),
            );
            return;
        }
        let want = rest.trim();
        let path = std::path::Path::new(&self.config.general.settings_file);

        // Form: `/model <provider> m1,m2` — split on first whitespace.
        let mut provider_arg: Option<String> = None;
        let mut models: Vec<String> = Vec::new();
        if let Some((prov, mstr)) = want.split_once(char::is_whitespace) {
            let prov = prov.trim();
            if PROVIDER_NAMES.contains(&prov) {
                provider_arg = Some(prov.to_string());
                models = mstr
                    .split(',')
                    .map(str::trim)
                    .filter(|m| !m.is_empty())
                    .map(str::to_string)
                    .collect();
            }
        }

        let mut guard = self.settings.lock().expect("settings mutex");

        if let Some(prov) = provider_arg {
            if models.is_empty() {
                // `/model <provider>` without models → clear the per-provider list.
                guard.llm_models.remove(&prov);
                if let Err(e) = guard.save(path) {
                    log::error!("failed to persist model selection: {e:#}");
                }
                drop(guard);
                let prefs = self.llm_prefs();
                if let Ok(b) = llm::build_chain(&self.config, &chain, &prefs) {
                    self.llm.swap(b);
                }
                let _ = self.send(
                    chat_id,
                    &format!(
                        "🗑️ Cadena de modelos de `{prov}` borrada; usa `[llm].model` global."
                    ),
                );
                return;
            }
            guard.llm_models.insert(prov.clone(), models.clone());
            if let Err(e) = guard.save(path) {
                log::error!("failed to persist model selection: {e:#}");
            }
            drop(guard);

            // Rebuild the active backend so the change applies right now.
            let prefs = self.llm_prefs();
            match llm::build_chain(&self.config, &chain, &prefs) {
                Ok(b) => self.llm.swap(b),
                Err(e) => log::warn!("applying /model rebuild failed: {e:#}"),
            }
            let _ = self.send(
                chat_id,
                &format!(
                    "✅ Proveedor `{prov}` con modelos `{}` activo (chain `{}`), persistido.",
                    models.join("` → `"),
                    chain.join("` → `")
                ),
            );
            return;
        }

        // Legacy single-model form: `/model <name>`.
        let want = want.to_string();
        // For the local provider, validate against the inventory and store in
        // `local_model`; otherwise it's an API model name → `llm_model`.
        let is_local_provider = chain.iter().any(|b| b == "local");
        let mut ok_local = false;
        if is_local_provider {
            if let Some(root) = self.local_models_root() {
                ok_local = llm::models::find(&llm::models::scan(&root), &want).is_some();
            }
        }
        if is_local_provider && !ok_local {
            let _ = self.send(
                chat_id,
                &format!(
                    "❌ No local model `{want}`. See `/models` (recursive scan of `{}`).",
                    self.local_models_root().map(|r| r.display().to_string()).unwrap_or_default()
                ),
            );
            return;
        }

        if is_local_provider {
            guard.local_model = want.clone();
        } else {
            guard.llm_model = want.clone();
        }
        if let Err(e) = guard.save(path) {
            log::error!("failed to persist model selection: {e:#}");
        }
        drop(guard);

        // Rebuild the active backend so the change applies right now.
        let prefs = self.llm_prefs();
        match llm::build_chain(&self.config, &chain, &prefs) {
            Ok(b) => self.llm.swap(b),
            Err(e) => log::warn!("applying /model rebuild failed: {e:#}"),
        }

        let _ = self.send(
            chat_id,
            &format!(
                "✅ Modelo `{want}` activo (chain `{}`), persistido.",
                chain.join("` → `")
            ),
        );
    }

    /// The active fallback chain in order of preference: `/llm` single
    /// selection wins, then the `/settings backends` chain, then
    /// `[llm].backend` from config.
    fn current_llm_chain(&self) -> Vec<String> {
        let guard = self.settings.lock().expect("settings mutex");
        guard.llm_chain(&self.config.llm.backend)
    }

    /// `/memory` — dump the rolling conversation window (context.txt).
    fn cmd_dump_context(&self, chat_id: i64) {
        let text = self.memory.load_context();
        if text.trim().is_empty() {
            let _ = self.send(chat_id, "🧠 context.txt is empty (no conversation yet).");
            return;
        }
        let text = truncate_for_telegram(&text);
        let _ = self.send_markdown(chat_id, &format!("🧠 *Conversation context:*\n```\n{text}\n```"));
    }

    /// `/showmemory` — dump the long-term memory (memory.txt).
    fn cmd_dump_memory(&self, chat_id: i64) {
        let text = self.memory.load_memory();
        if text.trim().is_empty() {
            let _ = self.send(
                chat_id,
                "💾 memory.txt is empty. Add facts with `/remember <text>`.",
            );
            return;
        }
        let text = truncate_for_telegram(&text);
        let _ = self.send_markdown(chat_id, &format!("💾 *Long-term memory:*\n```\n{text}\n```"));
    }

    /// `/remember <text>` — append a durable fact to memory.txt.
    fn cmd_remember(&self, chat_id: i64, text: &str) {
        let fact = text.trim();
        if fact.is_empty() {
            let _ = self.send(chat_id, "Usage: `/remember <fact>`");
            return;
        }
        match self.memory.append_memory(fact) {
            Ok(()) => {
                log::info!("telegram: user recorded fact: {fact}");
                let _ = self.send(chat_id, &format!("🧠 Recorded to memory.txt:\n`{fact}`"));
            }
            Err(e) => {
                log::error!("failed to append memory: {e:#}");
                let _ = self.send(chat_id, "❌ Could not write memory.txt.");
            }
        }
    }

    /// `/hardware` — lscpu-style CPU, GPU (nvidia-smi if present), PCI, TSC.
    fn cmd_hardware(&self, chat_id: i64) {
        log::info!("telegram: hardware inventory requested (chat {chat_id})");
        let report = crate::hwinfo::hardware_report();
        let _ = self.send_markdown(chat_id, &report);
    }

    fn cmd_pci(&self, chat_id: i64) {
        let _ = self.send_markdown(chat_id, &crate::hwinfo::display_report());
    }

    fn cmd_lsblk(&self, chat_id: i64) {
        let _ = self.send_markdown(chat_id, &crate::hwinfo::block_report());
    }

    fn cmd_lsusb(&self, chat_id: i64) {
        let _ = self.send_markdown(chat_id, &crate::hwinfo::usb_report());
    }

    fn cmd_lsmod(&self, chat_id: i64) {
        let _ = self.send_markdown(chat_id, &crate::hwinfo::modules_report());
    }

    fn cmd_unpair(&self, chat_id: i64, username: &str) {
        {
            let mut guard = self.state.lock().expect("bot state mutex");
            guard.paired_chat_id = None;
        }
        let state = PersistedState { paired_chat_id: None };
        if let Err(e) = state.save(&self.config) {
            log::error!("failed to clear pairing state: {e:#}");
        }
        log::info!("telegram: unpaired user '{}' (chat_id={})", username, chat_id);
        let _ = self.send(
            chat_id,
            "🔓 Unpaired. The bot will no longer accept messages from this chat.\n\
             Restart the daemon and use the new pairing token to re-pair.",
        );
    }

    /// `/definehome` / `/detecthome` — bind or re-check "this is my PC".
    ///
    /// * `/definehome` — show this machine's fingerprint; with no saved
    ///   profile it defines THIS PC as home.
    /// * `/definehome status` — show the saved HOME profile + ring −3
    ///   firmware drift (silicon is stable, fw moves).
    /// * `/definehome hal` — the HAL / ring −3 coprocessor detail
    ///   (Intel ME via HECI/MKHI, AMD PSP, HECI bus, TPM chips, chipset,
    ///   hypervisor truth).
    /// * `/definehome audit` — bootkit auditor (alias of `/bootkit`).
    /// * `/definehome delete` — forget the saved profile (you changed PCs).
    fn cmd_definehome(&self, chat_id: i64, rest: &str) {
        use crate::detecthome;

        let identity = detecthome::collect_identity();
        let fp = identity.fingerprint();
        let home = detecthome::profile_path(&self.config.general.settings_file);

        let sub = rest.trim().to_lowercase();

        match sub.as_str() {
            // ── Forget the saved profile ─────────────────────────────────────
            "clear" | "delete" | "borrar" | "borrame" => {
                detecthome::clear_profile(&home);
                log::warn!("definehome: home profile cleared (chat {chat_id})");
                let _ = self.send_markdown(
                    chat_id,
                    &format!(
                        "🗑️ *Home profile deleted* (`{}`).\n\nNo machine is defined as yours anymore. \
                         When you have the new one, run `/definehome` on it.",
                        home.display()
                    ),
                );
                return;
            }
            // ── Saved-profile status + firmware drift ────────────────────────
            "status" | "info" | "perfil" => {
                match detecthome::load_profile(&home) {
                    Some(profile) => {
                        let (silicon_stable, changed) =
                            detecthome::silicon_drift(&profile, &identity);
                        let mut msg = format!(
                            "💾 *Home profile* (captured {})\nhostname: `{}`\n\n`{}`",
                            profile.captured_at,
                            profile.hostname,
                            profile.summary,
                        );
                        if !silicon_stable {
                            msg.push_str("\n\n⚠️ *The silicon changed!* The ring −3 tokens no longer \
                                 match the saved profile — this is NOT (just) a firmware \
                                 update. Review `/definehome`; if this is your new PC, run \
                                 `/definehome delete` and re-define.");
                        } else if changed.is_empty() {
                            msg.push_str("\n\n✅ Firmware unchanged since capture.");
                        } else {
                            msg.push_str("\n\n🔁 *Firmware reflashed* (same PC, it got updated):\n");
                            for c in &changed {
                                msg.push_str(&format!("  · {c}\n"));
                            }
                        }
                        // TPM key ("es tu PC"): unseal + AEAD open against the
                        // live fingerprint, or state the fingerprint-only fallback.
                        if let Some(base) = home.parent() {
                            if let Some(line) = detecthome::tpm_key_line(&profile, &fp, base) {
                                msg.push_str(&line);
                            }
                        }
                        let _ = self.send_markdown(chat_id, &msg);
                    }
                    None => {
                        let _ = self.send_markdown(
                            chat_id,
                            "No home profile saved yet. Run `/definehome` on the machine \
                             you want to define as yours.",
                        );
                    }
                }
                return;
            }
            // ── HAL / ring −3 coprocessor detail ─────────────────────────────
            "hal" | "ring-3" | "ring3" | "me" | "psp" | "firmware" => {
                let hal = crate::hal::hal_info();
                let _ = self.send_markdown(chat_id, &hal.render_markdown());
                return;
            }
            // ── Presence evidence ladder (works with no camera at all) ───────
            "presencia" | "presence" | "sensores" | "sensors" => {
                let base = crate::presence::default_baseline_path(&self.config.face.path);
                let ev = crate::presence::PresenceEvidence::collect(&base);
                let _ = self.send(chat_id, &format!("```\n{}```", ev.render()));
                return;
            }
            // ── Accept the current USB set as normal ─────────────────────────
            "baseline" | "linea-base" | "normal" => {
                let base = crate::presence::default_baseline_path(&self.config.face.path);
                let msg = match crate::presence::record_baseline(&base) {
                    Ok(n) => format!(
                        "✅ Línea base USB registrada: *{n}* dispositivo(s) aceptados como \
                         normales.\nA partir de ahora avisaré de cualquiera que aparezca."
                    ),
                    Err(e) => format!("❌ No pude escribir la línea base: {e}"),
                };
                let _ = self.send_markdown(chat_id, &msg);
                return;
            }
            // ── Full MEI/HECI client directory ───────────────────────────────
            "mei" | "heci" | "clients" | "surface" | "superficie" => {
                let surface = crate::meiclients::enumerate();
                let _ = self.send(chat_id, &format!("```\n{}```", surface.render()));
                return;
            }
            // ── Bootkit audit ────────────────────────────────────────────────
            "audit" | "bootkit" | "scan" | "verificar" => {
                self.cmd_bootkit(chat_id);
                return;
            }
            _ => {}
        }

        // ── Normal define/check flow ─────────────────────────────────────────
        let saved = detecthome::load_profile(&home).map(|p| {
            let (silicon_stable, changed) = detecthome::silicon_drift(&p, &identity);
            let fp_match = p.fingerprint == fp;
            (p, silicon_stable, changed, fp_match)
        });

        match saved {
            Some((profile, silicon_stable, changed, true)) => {
                let mut msg = format!(
                    "✅ *This is your PC.*\n\n`{}`\n\nHash: `{fp}` — matches the saved profile.\n\n🔩 Silicon (ring −3): `{}`",
                    identity.summary_table(),
                    identity
                        .silicon_ids
                        .iter()
                        .map(|s| s.to_string())
                        .collect::<Vec<_>>()
                        .join(" · "),
                );
                // Firmware drift is normal (updates) — say it, don't cry wolf.
                if silicon_stable && !changed.is_empty() {
                    msg.push_str("\n\n🔁 Firmware reflashed since capture (same PC):\n");
                    for c in changed.iter().take(4) {
                        msg.push_str(&format!("  · {c}\n"));
                    }
                } else if !silicon_stable {
                    msg.push_str("\n\n⚠️ *Silicon differs from the saved profile* — but the hash matches... \
                         this suggests an unstable token, check `/definehome status`.");
                }
                // TPM key: re-verify (unseal + AEAD open). No clone alarm — an
                // identical PC that fails to open the key is a normal sight
                // (e.g. a friend's matching machine); the status line says it.
                if let Some(base) = home.parent() {
                    if let Some(line) = detecthome::tpm_key_line(&profile, &fp, base) {
                        msg.push_str(&line);
                    }
                }
                let _ = self.send_markdown(chat_id, &msg);
            }
            Some((profile, _silicon, _changed, false)) => {
                let _ = self.send_markdown(
                    chat_id,
                    &format!(
                        "⚠️ *This is NOT your PC.*\n\nThis machine:\n`{}`\n\nSaved (HOME): `{}`\n\nI wrote nothing.\nIf this is your new PC: `/definehome delete` and then `/definehome` here.",
                        identity.summary_table(),
                        profile.fingerprint
                    ),
                );
            }
            None => {
                // Nothing saved: this is the moment to bind this machine as HOME.
                match detecthome::save_profile(&home, &identity) {
                    Ok(_) => {
                        log::info!("definehome: saved home profile (fingerprint {fp})");
                        let _ = self.send_markdown(
                            chat_id,
                            &format!(
                                "🔐 *Defined this PC as your HOME.*\n\n`{}`\n\nHash: `{}`\n\nSaved in `{}`. From now on, if a login comes from other hardware I'll let you know.\n\n🔩 Silicon (ring −3): `{}`",
                                identity.summary_table(),
                                fp,
                                home.display(),
                                identity
                                    .silicon_ids
                                    .iter()
                                    .map(|s| s.to_string())
                                    .collect::<Vec<_>>()
                                    .join(" · "),
                            ),
                        );
                    }
                    Err(e) => {
                        log::error!("definehome: save failed: {e:#}");
                        let _ = self.send(chat_id, "❌ Could not save the HOME profile.");
                    }
                }
            }
        }
    }

    /// `/bootkit` — run the bootkit auditor over the whole boot chain
    /// (UEFI vars, Secure Boot, lockdown, kernel taint, LSTAR hook, hypervisor,
    /// ME/PSP ring −3, dmesg). Alias: `/definehome audit`.
    fn cmd_bootkit(&self, chat_id: i64) {
        log::info!("bootkit: running audit (chat {chat_id})");
        let audit = crate::bootkit_audit::run();
        let _ = self.send_markdown(chat_id, &audit.report());
    }

    /// `/logins` — snapshot of recent USER_PROCESS records from wtmp.
    fn cmd_logins(&self, chat_id: i64) {
        let evs = crate::loginwatch::current_logins(20);
        if evs.is_empty() {
            let _ = self.send_markdown(chat_id, "👤 *Sesiones recientes*: ninguna en wtmp.");
            return;
        }
        let mut lines = String::from("👤 *Sesiones recientes (wtmp)*\n");
        for e in evs {
            let host = if e.host.is_empty() {
                "-".to_string()
            } else {
                format!("`{}`", e.host)
            };
            lines.push_str(&format!(
                "  · {} `{}` via {}  pid={}  host={}\n",
                e.channel.emoji(),
                e.user,
                e.channel.label(),
                e.pid,
                host
            ));
        }
        let _ = self.send_markdown(chat_id, &lines);
    }

    /// `/mods` — what's loaded right now, flagging foreign modules.
    fn cmd_mods(&self, chat_id: i64) {
        let mods = crate::modulewatch::read_modules();
        if mods.is_empty() {
            let _ = self.send(chat_id, "Could not read `/proc/modules`.");
            return;
        }
        let mut lines = String::from("🧩 *Loaded modules*\n");
        for m in mods.iter().take(40) {
            let flag = if crate::modulewatch::modinfo_filename(&m.name).is_none() {
                "  ⚠️ *OUT OF TREE*"
            } else {
                ""
            };
            lines.push_str(&format!(
                "  · `{}` {} kB{}{}\n",
                m.name,
                m.size_kb,
                if m.used_by == "-" { String::new() } else { format!(" (used by: {})", m.used_by) },
                flag
            ));
        }
        if mods.len() > 40 {
            lines.push_str(&format!("  … and {} more", mods.len() - 40));
        }
        let _ = self.send_markdown(chat_id, &lines);
    }

    /// `/dmesg` — read the kernel ring buffer and report what matters, saved
    /// from having to run `dmesg` yourself.
    fn cmd_dmesg(&self, chat_id: i64) {
        let raw = crate::dmesg::read_dmesg();
        let raw = match raw {
            Some(r) if !r.is_empty() => r,
            _ => {
                // Degrade to what the kmsg watcher already caught.
                let fallback = {
                    let g = self.state.lock().expect("bot state mutex");
                    g.recent_alerts.iter().cloned().collect::<Vec<_>>()
                };
                if fallback.is_empty() {
                    let _ = self.send_markdown(
                        chat_id,
                        "Could not read dmesg (user without CAP_SYSLOG?) and no \
                         recent alerts in the watcher. All quiet — or the daemon has \
                         no permission.",
                    );
                    return;
                }
                self.voice_in_persona(
                    chat_id,
                    &format!(
                        "The user asked me to read dmesg for them (lazy to type it). I \
                         couldn't reach the ring buffer directly, but here are the alerts \
                         my own kernel watcher already caught:\n{}",
                        fallback.join("\n")
                    ),
                );
                return;
            }
        };

        let notable = crate::dmesg::notable_lines(&raw, 40);
        if notable.is_empty() {
            let last: Vec<String> = raw.iter().take(6).cloned().collect();
            self.voice_in_persona(
                chat_id,
                &format!(
                    "I just read the kernel log (dmesg). There's nothing alarming right \
                     now. Tell the user briefly, in YOUR voice, that all is quiet — and \
                     casually mention the few latest lines so they feel informed:\n{}",
                    last.join("\n")
                ),
            );
            return;
        }

        let block = truncate_for_telegram(&format!("```\n{}\n```", notable.join("\n")));
        self.voice_in_persona(
            chat_id,
            &format!(
                "The user asked me to read dmesg for them (they're too lazy to run it \
                 themselves). Here is what I found — tell them what matters, in YOUR \
                 voice, in their language: is anything wrong? What should they look \
                 at? Be brief (3-5 lines), no log formatting. Evidence:\n{}",
                notable.join("\n")
            ),
        );
        let _ = self.send_markdown(chat_id, &block);
    }

    /// `/undervolt` — honest V/F curve status. Never lets the persona claim an
    /// undervolt/overvolt that isn't verified.
    fn cmd_undervolt(&self, chat_id: i64) {
        let vendor = crate::undervolt::cpu_vendor_id().unwrap_or_else(|| "?".to_string());
        let truth = crate::undervolt::describe();
        self.voice_in_persona(
            chat_id,
            &format!(
                "The user asked about my undervolt/overvolt status. Be 100% honest and \
                 direct about this — it's a fact-check. You must NOT claim any V/F curve \
                 shift unless the evidence below says it is active. Report plainly: if \
                 stock, say you're running at stock voltage; if undetectable, say you \
                 can't verify. One short paragraph, their language, no hedging. \
                 Evidence:\nVendor: {vendor}\n{truth}",
            ),
        );
    }

    /// `/secureboot` — verified firmware state + what it means for the module.
    fn cmd_secureboot(&self, chat_id: i64) {
        let uefi = if crate::secureboot::is_uefi() { "UEFI" } else { "BIOS/legacy" };
        let truth = crate::secureboot::describe();
        let guidance = crate::secureboot::module_load_guidance();

        self.voice_in_persona(
            chat_id,
            &format!(
                "The user asked about Secure Boot. Report the state below truthfully \
                 and flatly — never invent firmware facts. If it's on, explain that \
                 unsigned kernel modules are refused and what that means for my \
                 kernel module; if off/legacy, say the module can be insmodded \
                 without signing. Their language, 2-4 lines. Facts:\nFirmware: {uefi}\n{truth}",
            ),
        );
        let block = format!("⚠️ Secure Boot\n\n{truth}{guidance}");
        let _ = self.send_markdown(chat_id, &block);
    }

    /// `/battery` — current battery state, or "no aplica" on a desktop tower.
    fn cmd_battery(&self, chat_id: i64) {
        let line = crate::battery::describe();
        if crate::battery::has_battery() {
            self.voice_in_persona(
                chat_id,
                &format!(
                    "The user asked about the battery. Report the current state \
                     (percentage, charging/discharging, and if discharging how much \
                     time is roughly left) in YOUR voice, their language, 1-2 lines. \
                     Fact: {line}",
                ),
            );
        } else {
            let _ = self.send_markdown(chat_id, &line);
        }
    }

    /// `/face register [N]` — enrobar el rostro del dueño: envía 1..N fotos y
    /// sólo se guardan los hashes pHash/wHash de 64 bits (jamás la imagen).
    fn cmd_face(&self, chat_id: i64, text: &str) {
        let rest = text.trim().strip_prefix("/face").unwrap_or("").trim();
        let mut it = rest.split_whitespace();
        match it.next() {
            Some("register") => {
                let n = it
                    .next()
                    .and_then(|s| s.parse::<u32>().ok())
                    .unwrap_or(3)
                    .clamp(1, 20);
                {
                    let mut g = self.state.lock().expect("bot state mutex");
                    g.face_pending = n;
                }
                let flag = if self.config.face.enabled { ": white_check_mark:" } else { "" };
                let _ = self.send(
                    chat_id,
                    &format!(
                        "Mándame las *{n}* fotos de tu rostro ahora (una por mensaje). \
                         Guardaré los hashes perceptuales (pHash + wHash, 64 bits) y, si \
                         el tool del initramfs está instalado, el vector facial 128-D para \
                         que el arranque te reconozca antes de descifrar. Nunca guardo la \
                         imagen.{}\nNota: las fotos se procesan en el momento y se borran.",
                        flag,
                    ),
                );
            }
            Some("status") => {
                let store = crate::fhash::FaceStore::load(std::path::Path::new(&self.config.face.path));
                match store {
                    Ok(s) => {
                        let msg = if s.is_empty() {
                            "No hay ningún rostro registrado. Usa `/face register`.".to_string()
                        } else {
                            let vecs = s.entries.iter().filter(|e| e.embedding.is_some()).count();
                            let head: Vec<String> = s
                                .entries
                                .iter()
                                .map(|e| format!("`p{:08x}` `w{:08x}`", e.p_hash, e.w_hash))
                                .collect();
                            // Say which engine actually decides a login here:
                            // the two are not equally strong evidence.
                            let engine = if crate::facenn::available(&self.config.face) {
                                if vecs > 0 {
                                    format!(
                                        "🧠 Motor activo: *red neuronal* (coseno ≥ {:.2} = dueño, \
                                         ≥ {:.2} = dudoso)",
                                        self.config.face.nn_owner, self.config.face.nn_ambiguous
                                    )
                                } else {
                                    "⚠️ Motor activo: *hash perceptual* — hay tool pero ningún \
                                     enroll tiene vector 128-D; vuelve a registrar con \
                                     `/face register`"
                                        .to_string()
                                }
                            } else {
                                format!(
                                    "⚠️ Motor activo: *hash perceptual* (más débil) — falta \
                                     `{}`. El hash describe la foto entera, así que un \
                                     desconocido en tu silla y tu fondo se le parece.",
                                    self.config.face.tool_path
                                )
                            };
                            format!(
                                "{} enroll(s) registrados ({} con vector 128-D para el \
                                 initramfs):\n{}\n\n{}",
                                s.len(),
                                vecs,
                                head.join("\n"),
                                engine
                            )
                        };
                        let _ = self.send(chat_id, &msg);
                    }
                    Err(e) => {
                        let _ = self.send(chat_id, &format!("No pude leer el store de caras: {e:#}"));
                    }
                }
            }
            Some("forget") => {
                if let Ok(mut store) =
                    crate::fhash::FaceStore::load(std::path::Path::new(&self.config.face.path))
                {
                    store.clear();
                    let _ = store.save();
                    store.mirror_to_esp();
                }
                let _ = self.send(chat_id, "Rostros registrados borrados.");
            }
            Some("cancel") => {
                self.state.lock().expect("bot state mutex").face_pending = 0;
                let _ = self.send(chat_id, "Registro de rostro cancelado.");
            }
            _ => {
                let _ = self.send(
                    chat_id,
                    "`/face register [N]` — registrar tu rostro (envía N fotos)\n\
                     `/face status` — cuántos hashes hay guardados\n\
                     `/face forget` — borrar todos los hashes\n\
                     `/face cancel` — cancelar un registro en curso",
                );
            }
        }
    }

    /// Consume one incoming photo while `/face register` is arming: compute the
    /// two perceptual hashes locally and persist them. Never stores the image.
    fn enroll_face_photo(&self, chat_id: i64, msg: &TgMessage) {
        let cancel = |bot: &TelegramBot, chat_id: i64, why: &str| {
            bot.state.lock().expect("bot state mutex").face_pending = 0;
            let _ = bot.send(chat_id, &format!("Aborté el registro: {why}"));
        };
        let Some(photo) = msg.photo.iter().max_by_key(|p| p.width * p.height) else {
            return cancel(self, chat_id, "sin foto descargable");
        };
        let bytes = match fetch_file_bytes(&self.bot_token, &photo.file_id) {
            Ok(b) => b,
            Err(e) => return cancel(self, chat_id, &format!("no pude descargar la foto: {e:#}")),
        };
        let img = match image::load_from_memory(&bytes) {
            Ok(i) => i,
            Err(e) => return cancel(self, chat_id, &format!("no pude decodificar la foto: {e:#}")),
        };
        let mut store = match crate::fhash::FaceStore::load(std::path::Path::new(&self.config.face.path))
        {
            Ok(s) => s,
            Err(e) => return cancel(self, chat_id, &format!("store de caras ilegible: {e:#}")),
        };
        // 128-D embedding opcional: lo calcula el tool estático del initramfs
        // (detect→align→embed). Si el tool falta o no hay cara, el enroll cae
        // al veredicto por hashes y el pipeline NN se queda sin template.
        let embedding = self.face_embedding(&bytes);
        let (p, w) = store.add_image_with_embedding(&img, embedding);
        if let Err(e) = store.save() {
            return cancel(self, chat_id, &format!("no pude guardar los hashes: {e:#}"));
        }
        store.mirror_to_esp();
        let remaining = {
            let mut g = self.state.lock().expect("bot state mutex");
            g.face_pending = g.face_pending.saturating_sub(1);
            g.face_pending
        };
        log::info!("face register: +1 enroll p={p:08x} w={w:08x} ({} left)", remaining);
        if remaining == 0 {
            let _ = self.send(
                chat_id,
                "Rostro registrado. De aquí en adelante, al iniciar sesión compararé la \
                 cámara contra estos hashes (pHash/wHash + Hamming). No guardo fotos. \
                 Los templates faciales se espejan al ESP para que el initramfs te \
                 reconozca en el arranque antes de descifrar (umbral cosine 0.5).",
            );
        } else {
            let _ = self.send(chat_id, &format!("Recibida. Quedan *{remaining}* foto(s)."));
        }
    }

    /// 128-D embedding de una foto vía el tool estático del initramfs
    /// (`sysentinel-face --embed`), usado como template del veredicto NN.
    /// `None` cuando el tool no está instalado, no hay cara o algo falló.
    fn face_embedding(&self, bytes: &[u8]) -> Option<Vec<f32>> {
        #[derive(serde::Deserialize)]
        struct ToolOut {
            faces: Vec<ToolFace>,
        }
        #[derive(serde::Deserialize)]
        struct ToolFace {
            embedding: Option<Vec<f32>>,
        }
        let tool = "/usr/libexec/sysentinel-face";
        if !std::path::Path::new(tool).is_file() {
            log::debug!("face: {tool} absent — no NN template for this enroll");
            return None;
        }
        let tmp = std::env::temp_dir().join(format!("sysentinel-face-enroll-{}.jpg", std::process::id()));
        let _ = std::fs::write(&tmp, bytes);
        let out = std::process::Command::new(tool)
            .arg("--embed")
            .arg(&tmp)
            .output()
            .ok();
        let _ = std::fs::remove_file(&tmp);
        let out = out?;
        if !out.status.success() {
            log::warn!(
                "face: {tool} failed ({}): {}",
                out.status,
                String::from_utf8_lossy(&out.stderr).trim()
            );
            return None;
        }
        let parsed: ToolOut = match serde_json::from_slice(&out.stdout) {
            Ok(o) => o,
            Err(e) => {
                log::warn!("face: {tool} output unparseable: {e}");
                return None;
            }
        };
        match parsed.faces.into_iter().next().and_then(|f| f.embedding) {
            Some(emb) if emb.len() == 128 => Some(emb),
            _ => {
                log::warn!("face: no usable embedding produced for the enrolled photo");
                None
            }
        }
    }

    /// `/login list` / `/login kill <pid>` — manual take-over of the ritual.
    fn cmd_login(&self, chat_id: i64, rest: &str) {
        let mut it = rest.split_whitespace();
        match it.next() {
            Some("list") => self.cmd_logins(chat_id),
            Some("kill") => {
                let Some(pid_s) = it.next() else {
                    let _ = self.send(chat_id, "Usage: `/login kill <pid>`");
                    return;
                };
                let Ok(pid) = pid_s.parse::<i32>() else {
                    let _ = self.send(chat_id, "❌ That pid is not valid.");
                    return;
                };
                let ev = crate::loginwatch::current_logins(500)
                    .into_iter()
                    .find(|e| e.pid == pid)
                    .unwrap_or_else(|| crate::loginwatch::LoginEvent {
                        user: "pid".to_string(),
                        channel: crate::loginwatch::LoginChannel::Tty,
                        host: String::new(),
                        line: "?".to_string(),
                        pid,
                        when_label: String::new(),
                    });
                let timeout = self.settings.lock().expect("settings mutex").login_timeout;
                crate::loginwatch::arm_manual_kill(&self.state, chat_id, &ev, timeout);
                let _ = self.send(
                    chat_id,
                    &format!(
                        "🔫 pid={pid} (`{}`) armed — reply `no` to close it or `si fui yo` (it was me) to keep it.",
                        ev.user
                    ),
                );
            }
            _ => {
                let _ = self.send(chat_id, "Usage: `/login kill <pid>` or `/login list`");
            }
        }
    }

    /// The system prompt actually used this turn, honouring a persisted
    /// `/systemprompt <text>` override (else the default builder).
    fn resolved_system_prompt(&self) -> String {
        let override_txt = {
            let g = self.settings.lock().expect("settings mutex");
            g.system_prompt_override.clone()
        };
        llm::effective_system_prompt(&self.config, override_txt.as_deref())
    }

    /// `/systemprompt` — inspect, set or clear the full system-prompt override.
    ///
    /// * `/systemprompt`             → show current state
    /// * `/systemprompt <text>`      → replace the ENTIRE prompt (persona+hardware)
    /// * `/systemprompt clear`       → drop the override, back to defaults
    fn cmd_system_prompt(&self, chat_id: i64, rest: &str) {
        let path = std::path::Path::new(&self.config.general.settings_file);
        let mut guard = self.settings.lock().expect("settings mutex");

        let want = rest.trim();
        if want.is_empty() {
            match guard.system_prompt_override.as_deref() {
                Some(s) if !s.trim().is_empty() => {
                    let _ = self.send_markdown(
                        chat_id,
                        &format!(
                            "📝 *System prompt override:*\n```\n{}\n```\n\n\
                             `/systemprompt clear` to go back to default.",
                            s
                        ),
                    );
                }
                _ => {
                    let _ = self.send_markdown(
                        chat_id,
                        "📝 *System prompt:* default\n\
                         (persona from config + real hardware).\n\
                         `/systemprompt <text>` replaces it entirely;\n\
                         `/systemprompt clear` restores it.",
                    );
                }
            }
            return;
        }

        if want == "clear" {
            let was = guard.system_prompt_override.take().is_some();
            if let Err(e) = guard.save(path) {
                log::error!("failed to persist system prompt: {e:#}");
            }
            drop(guard);
            let _ = self.send(
                chat_id,
                if was {
                    "🗑️ Override cleared — system prompt back to default (persona + real hardware)."
                } else {
                    "There was no override; staying with the default."
                },
            );
            return;
        }

        guard.system_prompt_override = Some(want.to_string());
        if let Err(e) = guard.save(path) {
            log::error!("failed to persist system prompt: {e:#}");
        }
        drop(guard);
        let _ = self.send(
            chat_id,
            "✅ System prompt override saved and active for the next turn.\n\
             `/systemprompt` shows it; `/systemprompt clear` removes it.",
        );
    }

    /// Forward the user's free-form question to the LLM with system context,
    /// long-term memory, and the rolling conversation history.
    fn cmd_chat(&self, chat_id: i64, text: &str, username: &str) {
        log::info!("telegram: LLM query from '{}': {:?}", username, text);

        // Resolve persona + prompt fresh each turn so `/systemprompt` (and the
        // auto-derived emotion/undervolt/chatty flags) apply immediately,
        // without a daemon restart.
        let persona = llm::resolved_persona(&self.config);
        let system_prompt = self.resolved_system_prompt();

        // Build live system context.
        let system_context = build_system_context(&self.state, &persona);

        // Load long-term memory + rolling conversation history.
        let memory        = self.memory.load_memory();
        let conversation  = self.memory.load_context();

        let request = ChatRequest {
            system_prompt:       &system_prompt,
            system_context:      &system_context,
            memory:              &memory,
            conversation_history: &conversation,
            user_message:        text,
            max_tokens:          self.max_tokens,
        };

        match self.llm.chat(&request) {
            Ok(reply) => {
                // Conversational control-order detection: a strict `[ARM:…]`
                // prefix (emitted by the LLM for an imperative order in ANY
                // language/dialect) only ARMS the control — nothing fires. The
                // reply text is part of the handshake, not the answer, so it
                // is discarded; execution still requires the language-free
                // `CONFIRM-XXXXXX` code from the armed notice, or the legacy
                // `confirm` word.
                if let Some(kind) = parse_arm_marker(&reply) {
                    log::warn!(
                        "telegram: conversational control order recognized ({:?}) from '{}' (chat={chat_id})",
                        kind, username
                    );
                    self.arm_conversational_control(chat_id, kind);
                    return;
                }
                // Persist this turn into context.txt so the bot "remembers"
                // the conversation across messages.
                if let Err(e) = self.memory.append_turn(text, &reply) {
                    log::error!("failed to append conversation turn to context.txt: {e:#}");
                }
                let _ = self.send(chat_id, &reply);
            }
            Err(e) => {
                log::error!("LLM chat failed: {e:#}");
                let _ = self.send(
                    chat_id,
                    "❌ The LLM backend returned an error. Check daemon logs.",
                );
            }
        }
    }

    // ── Telegram send helpers ─────────────────────────────────────────────────

    fn send(&self, chat_id: i64, text: &str) -> Result<()> {
        send_message(&self.bot_token, chat_id, text, None)
    }

    fn send_markdown(&self, chat_id: i64, text: &str) -> Result<()> {
        send_message(&self.bot_token, chat_id, text, Some("Markdown"))
    }
}

/// Low-level Telegram `sendMessage` call. Exported so `TelegramNotifier`
/// can reuse it without depending on the full bot struct.
///
/// Automatically splits messages longer than 4096 chars (Telegram's limit)
/// at newline boundaries so nothing is silently truncated.
pub fn send_message(
    bot_token: &str,
    chat_id:   i64,
    text:      &str,
    parse_mode: Option<&str>,
) -> Result<()> {
    const TG_LIMIT: usize = 4096;

    if text.len() <= TG_LIMIT {
        return send_single(bot_token, chat_id, text, parse_mode);
    }

    // Split on newlines, trying to keep chunks under the limit.
    let mut chunks: Vec<String> = Vec::new();
    let mut current = String::new();

    for line in text.split('\n') {
        // +1 for the newline we're about to add (or already implicit).
        if !current.is_empty() && current.len() + 1 + line.len() > TG_LIMIT {
            chunks.push(std::mem::take(&mut current));
        }
        if !current.is_empty() {
            current.push('\n');
        }
        current.push_str(line);

        // Single line longer than the limit — hard-split it.
        while current.len() > TG_LIMIT {
            let mut end = TG_LIMIT;
            while end > 0 && !current.is_char_boundary(end) {
                end -= 1;
            }
            let part: String = current.drain(..end).collect();
            chunks.push(part);
        }
    }
    if !current.is_empty() {
        chunks.push(current);
    }

    for chunk in &chunks {
        send_single(bot_token, chat_id, chunk, parse_mode)?;
    }
    Ok(())
}

fn send_single(
    bot_token: &str,
    chat_id:   i64,
    text:      &str,
    parse_mode: Option<&str>,
) -> Result<()> {
    let url  = format!("https://api.telegram.org/bot{bot_token}/sendMessage");
    let body = SendMessageBody {
        chat_id,
        text,
        parse_mode,
        disable_web_page_preview: true,
    };
    ureq::post(&url)
        .timeout(Duration::from_secs(10))
        .send_json(&body)
        .context("sendMessage request to Telegram")?;
    Ok(())
}

/// Low-level Telegram `sendPhoto` call (multipart/form-data built by hand —
/// ureq 2.x has no file-upload helper). Same split policy as [`send_message`]:
/// the caption rides along in the same multipart body.
pub fn send_photo(
    bot_token: &str,
    chat_id:   i64,
    caption:   &str,
    photo_path: &Path,
) -> Result<()> {
    let bytes = std::fs::read(photo_path)
        .with_context(|| format!("reading photo {}", photo_path.display()))?;
    let filename = photo_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "evidence.jpg".to_string());

    const TG_LIMIT: usize = 1024;
    let cap: String;
    let caption: &str = if caption.len() <= TG_LIMIT {
        caption
    } else {
        cap = caption.chars().take(TG_LIMIT).collect::<String>() + "…";
        &cap
    };

    let boundary = format!("----sysentinel{:016x}", std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0));
    let mut body: Vec<u8> = Vec::with_capacity(bytes.len() + 1024);
    push_form_text(&mut body, &boundary, "chat_id", &chat_id.to_string());
    push_form_text(&mut body, &boundary, "caption", caption);
    push_form_text(&mut body, &boundary, "parse_mode", "Markdown");
    push_form_file(&mut body, &boundary, "photo", &filename, "image/jpeg", &bytes);
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());

    let url = format!("https://api.telegram.org/bot{bot_token}/sendPhoto");
    let resp = ureq::post(&url)
        .timeout(Duration::from_secs(60))
        .set("Content-Type", &format!("multipart/form-data; boundary={boundary}"))
        .send(body.as_slice())
        .context("sendPhoto request to Telegram")?;
    anyhow::ensure!(
        resp.status() == 200,
        "Telegram sendPhoto returned non-200 status: {}",
        resp.status()
    );
    Ok(())
}

/// Download a Telegram file by `file_id` (getFile → file path → bytes).
fn fetch_file_bytes(bot_token: &str, file_id: &str) -> Result<Vec<u8>> {
    use std::io::Read as _;
    let url = format!("https://api.telegram.org/bot{bot_token}/getFile");
    let meta = ureq::get(&url)
        .query("file_id", file_id)
        .timeout(Duration::from_secs(30))
        .call()
        .context("getFile request to Telegram")?
        .into_string()
        .context("reading getFile answer")?;
    let v: serde_json::Value =
        serde_json::from_str(&meta).context("parsing getFile answer")?;
    anyhow::ensure!(v["ok"].as_bool().unwrap_or(false), "getFile failed: {v}");
    let path = v["result"]["file_path"]
        .as_str()
        .context("getFile returned no file_path")?;
    let dl = format!("https://api.telegram.org/file/bot{bot_token}/{path}");
    let mut reader = ureq::get(&dl)
        .timeout(Duration::from_secs(60))
        .call()
        .context("downloading Telegram file")?
        .into_reader();
    let mut buf = Vec::new();
    reader.read_to_end(&mut buf).context("reading Telegram file body")?;
    anyhow::ensure!(!buf.is_empty(), "downloaded file is empty");
    Ok(buf)
}

/// Low-level Telegram `sendAudio` call — same hand-built multipart as
/// [`send_photo`]. MIME is chosen from the file extension (oga/ogg, wav, mp3).
/// Used by the evidence-delivery loop (first-network upload of the intruder
/// audio); kept alive until that milestone lands.
#[allow(dead_code)]
pub fn send_audio(
    bot_token: &str,
    chat_id:   i64,
    caption:   &str,
    audio_path: &Path,
) -> Result<()> {
    let bytes = std::fs::read(audio_path)
        .with_context(|| format!("reading audio {}", audio_path.display()))?;
    let filename = audio_path
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "evidence.oga".to_string());
    let mime = match audio_path.extension().and_then(|e| e.to_str()) {
        Some("oga" | "ogg" | "opus") => "audio/ogg",
        Some("wav") => "audio/wav",
        Some("mp3") => "audio/mpeg",
        _ => "application/octet-stream",
    };
    const TG_LIMIT: usize = 1024;
    let cap: String;
    let caption: &str = if caption.len() <= TG_LIMIT {
        caption
    } else {
        cap = caption.chars().take(TG_LIMIT).collect::<String>() + "…";
        &cap
    };

    let boundary = format!("----sysentinel{:016x}", std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0));
    let mut body: Vec<u8> = Vec::with_capacity(bytes.len() + 1024);
    push_form_text(&mut body, &boundary, "chat_id", &chat_id.to_string());
    push_form_text(&mut body, &boundary, "caption", caption);
    push_form_text(&mut body, &boundary, "parse_mode", "Markdown");
    push_form_file(&mut body, &boundary, "audio", &filename, mime, &bytes);
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());

    let url = format!("https://api.telegram.org/bot{bot_token}/sendAudio");
    let resp = ureq::post(&url)
        .timeout(Duration::from_secs(300))
        .set("Content-Type", &format!("multipart/form-data; boundary={boundary}"))
        .send(body.as_slice())
        .context("sendAudio request to Telegram")?;
    anyhow::ensure!(
        resp.status() == 200,
        "Telegram sendAudio returned non-200 status: {}",
        resp.status()
    );
    Ok(())
}

fn push_form_text(body: &mut Vec<u8>, boundary: &str, name: &str, value: &str) {
    body.extend_from_slice(format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
    ).as_bytes());
}

fn push_form_file(
    body: &mut Vec<u8>,
    boundary: &str,
    name: &str,
    filename: &str,
    mime: &str,
    data: &[u8],
) {
    body.extend_from_slice(format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"; filename=\"{filename}\"\r\nContent-Type: {mime}\r\n\r\n"
    ).as_bytes());
    body.extend_from_slice(data);
    body.extend_from_slice(b"\r\n");
}

// ── System context builder ────────────────────────────────────────────────────

/// Parse a control-register number from the canonical forms "0".."8".
fn parse_control_register(s: &str) -> Option<u8> {
    match s.trim() {
        "0" => Some(0),
        "2" => Some(2),
        "3" => Some(3),
        "4" => Some(4),
        "8" => Some(8),
        _ => None,
    }
}

/// Parse the strict `[ARM:…]` marker that conversational control orders start
/// with. If present, the message was recognized as a direct imperative order in
/// ANY language/dialect — but this only arms the control; `confirm` is still
/// required before anything runs. Strictness matters: the marker must be the
/// very first token and must end on a word boundary, so an honest sentence like
/// "I said [ARM:reboot]" or a normal reply can never trip it.
fn parse_arm_marker(reply: &str) -> Option<ControlKind> {
    let t = reply.trim_start();
    const MARKERS: [(&str, ControlKind); 5] = [
        ("[ARM:kernelpanic]", ControlKind::KernelPanic),
        ("[ARM:triplefault-shutdown]", ControlKind::TripleFaultShutdown),
        ("[ARM:triplefault-restart]", ControlKind::TripleFaultRestart),
        ("[ARM:reboot]", ControlKind::Reboot),
        ("[ARM:poweroff]", ControlKind::PowerOff),
    ];
    for (marker, kind) in MARKERS {
        if let Some(rest) = t.strip_prefix(marker) {
            let boundary = rest.chars().next().map(|c| !c.is_alphanumeric()).unwrap_or(true);
            if boundary {
                return Some(kind);
            }
        }
    }
    None
}

/// Recognize a deliberate kernel-panic order, slash or conversational.
///
/// Slash-command parser for the kernel panic control. The primary,
/// language-agnostic order recognition runs inside the LLM turn (see
/// `control_order_protocol()`, which groks any dialect/language); this just
/// catches the explicit `/kernelpanic` command at zero token cost. Whether the
/// order came from the LLM or the slash command, the ARM → `CONFIRM-XXXXXX`
/// ritual is still required before anything fires.
fn parse_kernelpanic_order(lower: &str) -> Option<ControlKind> {
    let lower = lower.trim().to_lowercase();

    if lower.starts_with("/kernelpanic") {
        return Some(ControlKind::KernelPanic);
    }

    None
}

/// Slash-command parser for the triplefault control. Conversational orders are
/// recognized by the LLM (`control_order_protocol()`), never by hardcoded word
/// lists; this parser only covers `/triplefault restart|shutdown`. Execution
/// still requires the language-free `CONFIRM-XXXXXX` code.
fn parse_triplefault_order(lower: &str) -> Option<ControlKind> {
    let lower = lower.trim().to_lowercase();

    // `/triplefault allow` is a re-arm command, never an order.
    if lower.starts_with("/triplefault allow") {
        return None;
    }

    let mut rest = lower.strip_prefix("/triplefault")?;
    rest = rest.trim();
    if rest == "shutdown" || rest == "poweroff" || rest == "off" {
        Some(ControlKind::TripleFaultShutdown)
    } else {
        // `/triplefault` alone or `/triplefault restart` → restart.
        Some(ControlKind::TripleFaultRestart)
    }
}

/// Build a short text summary of the system state for the LLM context window.
fn build_system_context(
    state: &Arc<Mutex<SharedBotState>>,
    persona: &crate::config::PersonaConfig,
) -> String {
    let alerts: Vec<String> = {
        let guard = state.lock().expect("bot state mutex");
        guard.recent_alerts.iter().cloned().collect()
    };

    let mut ctx = String::new();

    // The machine's current emotional state — this is what the persona
    // mirrors. Injected first so it colours everything that follows. One
    // single short line: cheap on cache tokens.
    if persona.emotions {
        ctx.push_str(&crate::mood::compute(persona));
        ctx.push('\n');
    }

    // /proc/uptime
    if let Ok(raw) = std::fs::read_to_string("/proc/uptime") {
        let secs: f64 = raw.split_whitespace().next()
            .and_then(|s| s.parse().ok())
            .unwrap_or(0.0);
        let hours = (secs / 3600.0) as u64;
        let mins  = ((secs % 3600.0) / 60.0) as u64;
        ctx.push_str(&format!("Uptime: {hours}h {mins}m\n"));
    }

    // /proc/loadavg
    if let Ok(raw) = std::fs::read_to_string("/proc/loadavg") {
        ctx.push_str(&format!("Load average: {}\n", raw.trim()));
    }

    // /proc/meminfo: MemTotal, MemAvailable
    if let Ok(raw) = std::fs::read_to_string("/proc/meminfo") {
        let mut total_kb: u64 = 0;
        let mut avail_kb: u64 = 0;
        for line in raw.lines() {
            if let Some(v) = line.strip_prefix("MemTotal:") {
                total_kb = v.split_whitespace().next()
                    .and_then(|s| s.parse().ok()).unwrap_or(0);
            }
            if let Some(v) = line.strip_prefix("MemAvailable:") {
                avail_kb = v.split_whitespace().next()
                    .and_then(|s| s.parse().ok()).unwrap_or(0);
            }
        }
        if total_kb > 0 {
            let used_mb  = (total_kb - avail_kb) / 1024;
            let total_mb = total_kb / 1024;
            ctx.push_str(&format!("Memory: {used_mb} MB used / {total_mb} MB total\n"));
        }
    }

    // CPU model + vendor — keeps the models from guessing the platform.
    if let Ok(raw) = std::fs::read_to_string("/proc/cpuinfo") {
        if let Some(line) = raw.lines().find(|l| l.starts_with("model name")) {
            if let Some(name) = line.split_once(':').map(|x| x.1) {
                ctx.push_str(&format!("CPU: {}\n", name.trim()));
            }
        }
        if let Some(line) = raw.lines().find(|l| l.starts_with("vendor_id")) {
            if let Some(v) = line.split_once(':').map(|x| x.1) {
                ctx.push_str(&format!("CPU vendor: {}\n", v.trim()));
            }
        }
    }

    // Kernel version
    if let Ok(raw) = std::fs::read_to_string("/proc/version") {
        let ver = raw.split_whitespace().nth(2).unwrap_or("unknown");
        ctx.push_str(&format!("Kernel: {ver}\n"));
    }

    // ME / PSP / platform — prefer the ring-0 kernel-module snapshot over
    // best-effort sysfs/fallback data.
    let fw = mei::query_firmware_status();
    match kernel_snap::KernelSnapshot::read() {
        Some(snap) => {
            let s = snap.summary();
            if !s.is_empty() {
                ctx.push_str(&s);
            }
        }
        None => {
            if let Some(ref me) = fw.intel_me {
                ctx.push_str(&format!("Intel ME firmware: {me}\n"));
            }
            if let Some(ref psp) = fw.amd_psp {
                ctx.push_str(&format!("AMD PSP: {psp}\n"));
            }
            // Ring-3 fallbacks for everything the module would have provided.
            ctx.push_str(&crate::ring3::module_fallback_block());
            ctx.push_str(&format!("{}\n", crate::battery::describe()));
        }
    }

    // TPM / LSM / lockdown notes (sysfs; labels are vendor-accurate).
    for note in &fw.notes {
        ctx.push_str(&format!("  {note}\n"));
    }

    // Recent alerts
    if alerts.is_empty() {
        ctx.push_str("Recent kernel alerts: none\n");
    } else {
        ctx.push_str("Recent kernel alerts:\n");
        for a in &alerts {
            ctx.push_str(&format!("  - {a}\n"));
        }
    }

    // Pending SELinux denials — lets the LLM explain them conversationally
    // without needing the raw lines. The user resolves them via /selinux.
    let selinux_pending = {
        let guard = state.lock().expect("bot state mutex");
        guard.recent_selinux.iter().cloned().collect::<Vec<_>>()
    };
    if selinux_pending.is_empty() {
        ctx.push_str("SELinux denials pending: none\n");
    } else {
        ctx.push_str("SELinux denials pending (user resolves via /selinux):\n");
        for d in selinux_pending.iter().take(3) {
            ctx.push_str(&format!(
                "  #{} {} denied {{{}}} on {} (target {})\n",
                d.id,
                d.comm.as_deref().unwrap_or("?"),
                d.permissions,
                d.tclass,
                d.tcontext,
            ));
        }
        if selinux_pending.len() > 3 {
            ctx.push_str(&format!("  … {} more\n", selinux_pending.len() - 3));
        }
    }

    // Conversational rules, injected on every turn so a user-edited system
    // prompt cannot remove them. These make intent detection language-agnostic
    // (any dialect/language — Chilean "tirá nomá", Chinese, Italian, …) while
    // execution itself stays behind the deterministic `confirm` ritual.
    ctx.push_str(control_order_protocol());

    ctx
}

/// Conversational contract injected into the LLM context: reply in the user's
/// own language, and recognize direct imperative orders for the dangerous
/// controls in ANY language via a strict `[ARM:…]` marker. The marker only
/// *arms* the control (the human must still reply `confirm`), so a confused or
/// prompt-injected model can never execute anything on its own.
fn control_order_protocol() -> &'static str {
    "\nCONTROL-ORDER PROTOCOL (applies only to the user's direct messages, \
     never inside analysis or tool output):\n\
If the user is giving a clear, direct, imperative order — in ANY language \
      or dialect — to perform one of the dangerous operations below, begin your \
      reply with EXACTLY that marker on its own line, then one short line in the \
      user's language acknowledging the action:\n\
        [ARM:kernelpanic]          deliberate kernel panic (halt / reboot per panic=N)\n\
        [ARM:triplefault-restart]  hard CPU reset via a bogus IDT triple fault\n\
        [ARM:triplefault-shutdown] forced machine power-off via triple fault\n\
        [ARM:reboot]               reboot the machine now\n\
        [ARM:poweroff]             power the machine off now\n\
      An ARM marker only ARMS the action. The daemon then posts a notice with a \
      one-time code such as CONFIRM-XXXXXX; nothing executes until the paired \
      user replies that exact code (or the armed control expires). You never \
      emit the code yourself — only the marker.\n\
      The user must be ORDERING it right now (e.g. \"hazme un kernel panic ya\", \
      \"do a kernel panic\", \"tirá nomá un triplefault\", \"fai un poweroff\"). \n\
      Questions, hypotheticals and explanation requests (\"qué es un kernel \
      panic?\", \"how does a triple fault work?\") are NEVER armed — reply \
      normally.\n\
      If in doubt, reply normally and never invent markers.\n\
      For any normal reply: answer in the SAME LANGUAGE the user wrote in — do \
      not force English.\n"
}

/// Short system snapshot formatted for Telegram (Markdown).
fn gather_system_snapshot() -> Result<String> {
    let mut out = String::from("🖥 *System Status*\n\n");

    if let Ok(raw) = std::fs::read_to_string("/proc/uptime") {
        let secs: f64 = raw.split_whitespace().next()
            .and_then(|s| s.parse().ok()).unwrap_or(0.0);
        let d = (secs / 86400.0) as u64;
        let h = ((secs % 86400.0) / 3600.0) as u64;
        let m = ((secs % 3600.0)  / 60.0)   as u64;
        out.push_str(&format!("⏱ Uptime: {d}d {h}h {m}m\n"));
    }

    if let Ok(raw) = std::fs::read_to_string("/proc/loadavg") {
        out.push_str(&format!("📊 Load: `{}`\n", raw.trim()));
    }

    if let Ok(raw) = std::fs::read_to_string("/proc/meminfo") {
        let mut total_kb: u64 = 0;
        let mut avail_kb: u64 = 0;
        for line in raw.lines() {
            if let Some(v) = line.strip_prefix("MemTotal:") {
                total_kb = v.split_whitespace().next()
                    .and_then(|s| s.parse().ok()).unwrap_or(0);
            }
            if let Some(v) = line.strip_prefix("MemAvailable:") {
                avail_kb = v.split_whitespace().next()
                    .and_then(|s| s.parse().ok()).unwrap_or(0);
            }
        }
        if let Some(used_pct) = total_kb.checked_sub(avail_kb)
            .and_then(|used| (used * 100).checked_div(total_kb))
        {
            let avail_mb = avail_kb / 1024;
            let total_mb = total_kb / 1024;
            out.push_str(&format!("💾 Memory: {avail_mb} MB free / {total_mb} MB ({used_pct}% used)\n"));
        }
    }

    if let Ok(raw) = std::fs::read_to_string("/proc/version") {
        let ver = raw.split_whitespace().nth(2).unwrap_or("?");
        out.push_str(&format!("🐧 Kernel: `{ver}`\n"));
    }

    if let Ok(raw) = std::fs::read_to_string("/proc/cpuinfo") {
        if let Some(line) = raw.lines().find(|l| l.starts_with("model name")) {
            if let Some(name) = line.split(':').nth(1) {
                out.push_str(&format!("🔲 CPU: {}\n", name.trim()));
            }
        }
    }

    // Ring-0 kernel-module view: bare-metal/VM truth + co-processors.
    // Works on both Intel ME and AMD PSP hosts.
    if let Some(snap) = kernel_snap::KernelSnapshot::read() {
        if let Some(h) = &snap.hypervisor {
            out.push_str(&format!("🧠 Platform: `{}`\n", escape_markdown(h)));
        }
        if let Some(m) = &snap.me_fw {
            out.push_str(&format!("🔒 Intel ME firmware: `{}`\n", escape_markdown(m)));
        }
        if let Some(p) = &snap.psp {
            out.push_str(&format!("🔐 AMD PSP: `{}`\n", escape_markdown(p)));
        }
        if let Some(k) = &snap.kvm_features {
            out.push_str(&format!("🧪 KVM CPU features: `{}`\n", escape_markdown(k)));
        }
    } else {
        // Module absent (no Secure Boot signing, not loaded…) → ring-3 fallback.
        // Report what the machine IS, say clearly what we can't read, never fake
        // a ring-0 fact.
        let fb = crate::ring3::module_fallback_block();
        out.push_str(&fb);
        let battery = crate::battery::describe();
        out.push_str(&format!("{battery}\n"));
    }

    Ok(out)
}

/// Escape special characters for Telegram Markdown v1.
fn escape_markdown(s: &str) -> String {
    s.replace('_', "\\_")
     .replace('*', "\\*")
     .replace('[', "\\[")
     .replace('`', "\\`")
}

/// Keep a report under Telegram's message limit (4096 chars), cutting at the
/// last newline so we never split a markdown block.
fn truncate_for_telegram(s: &str) -> String {
    const LIMIT: usize = 3900;
    if s.len() <= LIMIT {
        return s.to_string();
    }
    let mut end = LIMIT;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    let mut cut = s[..end].rfind('\n').unwrap_or(end);
    while cut > 0 && !s.is_char_boundary(cut) {
        cut -= 1;
    }
    let mut out = s[..cut].to_string();
    out.push_str("\n… (truncated)\n");
    out
}

// ── Pairing token announcement ────────────────────────────────────────────────

/// Generate a pairing token **bound to the authorised user**, store it in
/// `state`, and log it clearly.
///
/// Called once from `main()` at startup. The token is also announced to the
/// previously-paired chat_id (if any) so the user can see it in Telegram.
///
/// # Binding
///
/// The token is minted for `config.telegram.telegram_id`. If that
/// whitelist is `None`, the token **cannot** be securely bound (there is no
/// user to bind to) and we refuse to mint one, logging a security warning
/// instead. This preserves the guarantee: "only my Telegram id can pair."
pub fn announce_pairing_token(
    state:     &Arc<Mutex<SharedBotState>>,
    config:    &Config,
    bot_token: &str,
) {
    // ── We must know the authorised user to bind the token to them ───────────
    let Some(telegram_id) = config.telegram.telegram_id.filter(|&id| id != 0) else {
        log::warn!(
            "telegram: REFUSING to generate a pairing token because \
             [telegram].telegram_id is not set. A token that is not bound \
             to your Telegram user id could be used by anyone who reads the \
             log. Set `telegram_id` in config.toml (get your id via \
             @userinfobot) and restart."
        );
        return;
    };

    let token = PairingToken::generate(telegram_id);
    let token_str    = token.token.clone();
    let secs         = token.seconds_remaining();

    {
        let mut guard = state.lock().expect("bot state mutex");
        guard.pairing_token = Some(token);
    }

    // Always log — visible via journalctl even if Telegram is not configured.
    log::info!(
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    );
    log::info!("  sysentinel PAIRING TOKEN: {token_str}");
    log::info!("  Valid for {secs} seconds. Send this token to your Telegram bot.");
    log::info!("  Bound to Telegram user id: {telegram_id} (only this account can use it)");
    log::info!(
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    );

    // If there's a previously-paired chat_id, notify it there too.
    if let Some(chat_id) = config.telegram.chat_id.filter(|&id| id != 0) {
        let msg = format!(
            "🔑 *New pairing token*: `{token_str}`\n\
             Valid for {} minutes. Send it to this bot to (re-)pair.",
            secs / 60
        );
        if let Err(e) = send_message(bot_token, chat_id, &msg, Some("Markdown")) {
            log::warn!("could not send pairing token via Telegram: {e:#}");
        }
    }
}

/// Load the persisted paired chat_id (if any) from the state file.
pub fn load_paired_chat_id(config: &Config) -> Option<i64> {
    PersistedState::load(config)?.paired_chat_id
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_verifies_with_argon2id() {
        let token = PairingToken::generate(42);
        // Correct token → true.
        assert!(token.verify(&token.token));
        // It must survive whitespace and case variations the user might type.
        assert!(token.verify(&format!("  {}  ", token.token.to_lowercase())));
        // Any other string → false.
        assert!(!token.verify("SYN-WRONG1"));
        assert!(!token.verify(""));
    }

    #[test]
    fn token_hash_is_not_plaintext() {
        let token = PairingToken::generate(7);
        // The stored blob must never contain the token string.
        assert!(!token.token_hash.contains(&token.token));
        // And it must be a PHC argon2id string.
        assert!(token.token_hash.starts_with("$argon2id$"));
        // Salt is random: two tokens must never share a hash string.
        let other = PairingToken::generate(7);
        assert_ne!(token.token_hash, other.token_hash);
    }

    #[test]
    fn token_format() {
        let token = PairingToken::generate(1);
        // SYN- + 8 unambiguous chars.
        assert_eq!(token.token.len(), 12);
        assert!(token.token.starts_with("SYN-"));
        assert!(token.token[4..].chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()));
    }

    #[test]
    fn token_binds_to_user() {
        let token = PairingToken::generate(999);
        assert!(token.matches_user(999));
        assert!(!token.matches_user(1000));
    }

    #[test]
    fn burn_out_stops_after_max_failures() {
        let mut token = PairingToken::generate(5);
        // Remaining attempts start at the max.
        assert_eq!(token.remaining_attempts(), 5);
        let mut burned = false;
        for _ in 0..5 {
            burned = token.record_failure();
        }
        assert!(burned);           // 5th failure trips the burn flag
        token.burn();
        assert!(!token.is_valid()); // and the token is dead
    }

    #[test]
    fn confirmation_phrases() {
        assert!(TelegramBot::is_confirmation_phrase("YES"));
        assert!(TelegramBot::is_confirmation_phrase("sí"));
        assert!(TelegramBot::is_confirmation_phrase(" confirmar "));
        assert!(!TelegramBot::is_confirmation_phrase("ya"));

        assert!(TelegramBot::is_denial_phrase("no"));
        assert!(TelegramBot::is_denial_phrase("DENY"));
        assert!(!TelegramBot::is_denial_phrase("nope"));
    }

    #[test]
    fn selinux_state_assigns_ids_and_deduplicates() {
        let raw = "audit(...): avc: denied { open read } for pid=1 comm=\"a\" \
                   scontext=u:r:a_t:s0 tcontext=u:object_r:b_t:s0 tclass=file";
        let mut state = SharedBotState::new(None);

        let first = state.push_selinux(raw).expect("first denial");
        assert_eq!(first.id, 1);
        // Same fingerprint repeated → suppressed.
        assert!(state.push_selinux(raw).is_none());
        // A different denial gets the next id.
        let raw2 = raw.replace("{ open read }", "{ write }");
        let second = state.push_selinux(&raw2).expect("second denial");
        assert_eq!(second.id, 2);

        // deny removes it and future repeats stay silent.
        assert!(state.deny_selinux(2).is_some());
        assert!(state.get_selinux(2).is_none());
        assert!(state.push_selinux(&raw2).is_none());
        assert_eq!(state.recent_selinux.len(), 1);
    }

    #[test]
    fn triplefault_orders_parse() {
        assert_eq!(parse_triplefault_order("/triplefault"), Some(ControlKind::TripleFaultRestart));
        assert_eq!(parse_triplefault_order("/triplefault restart"), Some(ControlKind::TripleFaultRestart));
        assert_eq!(parse_triplefault_order("/triplefault shutdown"), Some(ControlKind::TripleFaultShutdown));
        assert_eq!(parse_triplefault_order("/triplefault poweroff"), Some(ControlKind::TripleFaultShutdown));
        assert_eq!(parse_triplefault_order("/triplefault off"), Some(ControlKind::TripleFaultShutdown));
        assert_eq!(parse_triplefault_order("/triplefault  restart"), Some(ControlKind::TripleFaultRestart));

        // Conversational orders are handled by the LLM now — the deterministic
        // parser must NOT understand free text in any language.
        assert_eq!(parse_triplefault_order("hacé un triplefault restart"), None);
        assert_eq!(parse_triplefault_order("triplefault shutdown por favor"), None);
        assert_eq!(parse_triplefault_order("dame un reinicio forzado"), None);

        // Queries / passive mentions must NOT be treated as orders.
        assert_eq!(parse_triplefault_order("¿qué es un triplefault?"), None);
        assert_eq!(parse_triplefault_order("explicame triplefault"), None);
        assert_eq!(parse_triplefault_order("apagado"), None); // no slash command
        assert_eq!(parse_triplefault_order("hola"), None);
        // Other slash commands never become triplefault orders.
        assert_eq!(parse_triplefault_order("/reboot"), None);
        assert_eq!(parse_triplefault_order("/status"), None);
    }

    #[test]
    fn triplefault_slash_allow_is_not_an_order() {
        assert_eq!(parse_triplefault_order("/triplefault allow"), None);
    }

    #[test]
    fn kernelpanic_orders_parse() {
        assert_eq!(
            parse_kernelpanic_order("/kernelpanic"),
            Some(ControlKind::KernelPanic)
        );
        assert_eq!(
            parse_kernelpanic_order("/kernelpanic for testing the watchdog"),
            Some(ControlKind::KernelPanic)
        );
        // Conversational orders are handled by the LLM now — the deterministic
        // parser must NOT understand free text in any language.
        assert_eq!(parse_kernelpanic_order("hacé un kernel panic forzado"), None);
        assert_eq!(parse_kernelpanic_order("trigger a kernelpanic now"), None);
        // Queries / passive mentions.
        assert_eq!(parse_kernelpanic_order("¿qué es un kernel panic?"), None);
        assert_eq!(parse_kernelpanic_order("explicame kernelpanic"), None);
        assert_eq!(parse_kernelpanic_order("hola"), None);
    }

    #[test]
    fn confirm_nonces_are_one_time_codes() {
        // Fresh nonce has the expected shape and no ambiguous characters.
        let a = fresh_confirm_nonce();
        let b = fresh_confirm_nonce();
        assert!(a.starts_with("CONFIRM-"), "nonce: {a}");
        assert!(b.starts_with("CONFIRM-"), "nonce: {b}");
        assert_eq!(a.len(), "CONFIRM-".len() + 6);
        let tail = &a["CONFIRM-".len()..];
        assert!(tail.chars().all(|c| c.is_ascii_alphanumeric()));
        assert!(!tail.contains('O') && !tail.contains('0'));

        // PendingControl mints its code at ARM time and it is stable.
        let p1 = PendingControl::new(ControlKind::Reboot, 7);
        assert!(p1.nonce.starts_with("CONFIRM-"));
        let p1b = PendingControl::new(ControlKind::Reboot, 7);
        assert_ne!(p1.nonce, p1b.nonce, "each ARM gets a fresh code");
    }

    #[test]
    fn arm_markers_parse_strictly() {
        assert_eq!(parse_arm_marker("[ARM:kernelpanic] listo"), Some(ControlKind::KernelPanic));
        assert_eq!(
            parse_arm_marker("[ARM:triplefault-shutdown]\nEnseguida."),
            Some(ControlKind::TripleFaultShutdown)
        );
        assert_eq!(
            parse_arm_marker("[ARM:triplefault-restart] un momento"),
            Some(ControlKind::TripleFaultRestart)
        );
        assert_eq!(parse_arm_marker("[ARM:reboot] ok"), Some(ControlKind::Reboot));
        assert_eq!(parse_arm_marker("[ARM:poweroff]"), Some(ControlKind::PowerOff));
        assert_eq!(parse_arm_marker("  [ARM:reboot] vamos"), Some(ControlKind::Reboot));

        // Strict boundary: a marker must START the reply, and must not be a
        // prefix of an unrelated token.
        assert_eq!(parse_arm_marker("I said [ARM:reboot] to a friend"), None);
        assert_eq!(parse_arm_marker("[ARM:rebootable] no"), None);
        assert_eq!(parse_arm_marker("[ARM:reboot2] fast"), None);
        assert_eq!(parse_arm_marker("[ARM:reboot]s no"), None);
        assert_eq!(parse_arm_marker("just chatting"), None);
        assert_eq!(parse_arm_marker(""), None);
        assert_eq!(parse_arm_marker("[ARM:kernelpanicx] no"), None);
    }
}
