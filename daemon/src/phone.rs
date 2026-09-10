// SPDX-License-Identifier: Apache-2.0
//!
//! The phone as the daemon's channel — the one that replaces Telegram.
//!
//! # What this buys, and what it costs
//!
//! Against a Telegram bot it removes three real problems: there is no bearer
//! token that speaks as the machine if it leaks, no endpoint a stranger can
//! reach and be rejected only *after* arriving, and no third party that sees
//! who talked to whom and when.
//!
//! It costs something, and pretending otherwise would be worse than the
//! problem: **Telegram's relay is what made the phone reachable from
//! anywhere.** This is a direct connection. On a LAN it works; across the
//! internet it needs a path you supply — WireGuard, Tailscale, a VPN home.
//! Without one, the daemon can queue but not deliver while the owner is out,
//! which is exactly when a machine is most likely to be touched. That is the
//! honest trade: a third party you must trust, in exchange for reachability you
//! would otherwise arrange yourself.
//!
//! # The queue is the point
//!
//! A watchdog whose alerts evaporate because the phone was asleep is barely
//! better than one that cannot speak. Everything is written to disk first and
//! delivered when the phone next connects, so "nobody was listening" delays an
//! alert instead of destroying it. Deliveries are only dropped from the queue
//! once the phone acknowledges them.
//!
//! # Opening a port is itself a decision
//!
//! This makes a root daemon listen on a socket, which is a surface that did not
//! exist before. It is off unless configured, the bind address must be written
//! out explicitly rather than defaulted to something convenient, and the first
//! frame on any connection must authenticate or the connection is dropped
//! without a reply — an unauthenticated peer learns nothing, not even that the
//! protocol was understood.
//!
//! Frames are sealed with the paired key using the same AEAD choice the rest of
//! the daemon makes: AES-256-GCM where the CPU has hardware AES, ChaCha20-
//! Poly1305 where it does not.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{Context, Result};
use aws_lc_rs::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey, NONCE_LEN};
use serde::{Deserialize, Serialize};

use crate::channel::Notifier;

/// Largest frame the daemon will read from a peer, before authentication or
/// after. A length prefix is an invitation to ask for a gigabyte.
const MAX_FRAME: usize = 1 << 20;

/// How long a silent peer may hold a connection.
const IO_TIMEOUT: Duration = Duration::from_secs(30);

/// One thing waiting to reach the owner.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QueuedAlert {
    /// Monotonic within a queue file; the phone acknowledges by id.
    pub id: u64,
    pub unix_time: i64,
    pub text: String,
    /// Photo path, when there is evidence attached.
    pub photo: Option<String>,
}

/// Alerts that have not yet been acknowledged, persisted so a restart — or a
/// phone that was simply asleep — delays delivery instead of losing it.
#[derive(Debug)]
pub struct AlertQueue {
    path: PathBuf,
    items: VecDeque<QueuedAlert>,
    next_id: u64,
    /// Oldest-first cap, so a phone left off for a month cannot fill the disk.
    capacity: usize,
}

impl AlertQueue {
    pub fn load(path: &Path, capacity: usize) -> Self {
        let items: VecDeque<QueuedAlert> = std::fs::read_to_string(path)
            .ok()
            .and_then(|raw| serde_json::from_str(&raw).ok())
            .unwrap_or_default();
        let next_id = items.iter().map(|a| a.id).max().unwrap_or(0) + 1;
        AlertQueue { path: path.to_path_buf(), items, next_id, capacity: capacity.max(1) }
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Queue an alert and persist immediately. Persisting before delivery is
    /// deliberate: a crash between "observed" and "delivered" must not lose the
    /// observation.
    pub fn push(&mut self, text: &str, photo: Option<&Path>) -> u64 {
        let id = self.next_id;
        self.next_id += 1;
        self.items.push_back(QueuedAlert {
            id,
            unix_time: now_unix(),
            text: text.to_string(),
            photo: photo.map(|p| p.display().to_string()),
        });
        // Drop the oldest rather than the newest: recent events are the ones
        // that still matter, and an unbounded queue is a disk-filling bug.
        while self.items.len() > self.capacity {
            self.items.pop_front();
        }
        self.persist();
        id
    }

    /// Everything still waiting, oldest first.
    pub fn pending(&self) -> Vec<QueuedAlert> {
        self.items.iter().cloned().collect()
    }

    /// Drop everything up to and including `id`. Called only when the phone
    /// says it has them.
    pub fn acknowledge(&mut self, id: u64) -> usize {
        let before = self.items.len();
        self.items.retain(|a| a.id > id);
        let dropped = before - self.items.len();
        if dropped > 0 {
            self.persist();
        }
        dropped
    }

    fn persist(&self) {
        use std::os::unix::fs::PermissionsExt;
        if let Some(parent) = self.path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        match serde_json::to_string(&self.items) {
            Ok(json) => {
                if let Err(e) = std::fs::write(&self.path, json) {
                    log::error!("phone: cannot persist the alert queue: {e}");
                    return;
                }
                // The queue holds what the machine saw; it is not world-readable.
                let _ = std::fs::set_permissions(
                    &self.path,
                    std::fs::Permissions::from_mode(0o600),
                );
            }
            Err(e) => log::error!("phone: cannot serialise the alert queue: {e}"),
        }
    }
}

fn now_unix() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

// ── Framing ───────────────────────────────────────────────────────────────────

/// AEAD used for frames. Same rule as `tpmkey.rs`: hardware AES where the CPU
/// has it, ChaCha where it does not.
fn frame_alg() -> &'static aead::Algorithm {
    // Reusing tpmkey's detection rather than writing a second one: it already
    // handles both x86 (aes/vaes) and aarch64 (the aes feature bit), and two
    // copies of that rule would eventually disagree.
    if crate::tpmkey::aes_accelerated() {
        &aead::AES_256_GCM
    } else {
        &aead::CHACHA20_POLY1305
    }
}

/// Seal one frame: `nonce || ciphertext||tag`.
///
/// A fresh random nonce per frame, never a counter. A counter would have to
/// survive restarts to stay unique, and a nonce reused across a restart with
/// the same key is the failure that breaks GCM outright.
pub fn seal(key: &[u8; 32], plaintext: &[u8]) -> Result<Vec<u8>> {
    let alg = frame_alg();
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce)
        .map_err(|e| anyhow::anyhow!("phone: no entropy for a frame nonce: {e}"))?;

    let unbound = UnboundKey::new(alg, key).map_err(|_| anyhow::anyhow!("bad frame key"))?;
    let mut buf = plaintext.to_vec();
    LessSafeKey::new(unbound)
        .seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::empty(),
            &mut buf,
        )
        .map_err(|_| anyhow::anyhow!("phone: sealing failed"))?;

    let mut out = Vec::with_capacity(NONCE_LEN + buf.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&buf);
    Ok(out)
}

/// Open a frame produced by [`seal`]. Fails on a wrong key, a tampered frame,
/// or one too short to contain a nonce.
pub fn open(key: &[u8; 32], frame: &[u8]) -> Result<Vec<u8>> {
    if frame.len() <= NONCE_LEN {
        anyhow::bail!("phone: frame too short");
    }
    let (nonce, body) = frame.split_at(NONCE_LEN);
    let mut nonce_arr = [0u8; NONCE_LEN];
    nonce_arr.copy_from_slice(nonce);

    let alg = frame_alg();
    let unbound = UnboundKey::new(alg, key).map_err(|_| anyhow::anyhow!("bad frame key"))?;
    let mut buf = body.to_vec();
    let opened = LessSafeKey::new(unbound)
        .open_in_place(
            Nonce::assume_unique_for_key(nonce_arr),
            Aad::empty(),
            &mut buf,
        )
        .map_err(|_| anyhow::anyhow!("phone: frame did not authenticate"))?;
    Ok(opened.to_vec())
}

/// Read a length-prefixed frame.
fn read_frame(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut len = [0u8; 4];
    stream.read_exact(&mut len)?;
    let n = u32::from_be_bytes(len) as usize;
    if n == 0 || n > MAX_FRAME {
        anyhow::bail!("phone: refusing a {n}-byte frame");
    }
    let mut buf = vec![0u8; n];
    stream.read_exact(&mut buf)?;
    Ok(buf)
}

fn write_frame(stream: &mut TcpStream, frame: &[u8]) -> Result<()> {
    stream.write_all(&(frame.len() as u32).to_be_bytes())?;
    stream.write_all(frame)?;
    stream.flush()?;
    Ok(())
}

// ── Protocol ──────────────────────────────────────────────────────────────────

/// What the phone sends.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum FromPhone {
    /// First frame on every connection. Sealing it correctly *is* the
    /// channel authentication — a peer without the paired key cannot produce
    /// one. It says nothing about *which handset* is on the other end; that is
    /// what [`FromPhone::Identify`] answers.
    Hello { app_version: String },
    /// Prove this is the paired handset by signing the challenge from
    /// [`ToPhone::Welcome`] with the device key.
    ///
    /// The pairing key proves somebody knows a secret, and a secret can be
    /// copied. This proves a specific piece of hardware is present, because the
    /// private half never leaves it. See `phonehome.rs`.
    Identify {
        /// SubjectPublicKeyInfo DER of the device signing key.
        public_key: Vec<u8>,
        /// Signature over the welcome challenge.
        signature: Vec<u8>,
        /// What the phone says backed the key. A claim, graded elsewhere.
        backing: String,
        /// Context for the audit line. Never used to decide identity: a
        /// friend's identical handset matches on every one of these.
        model: String,
        manufacturer: String,
    },
    /// Give me everything still waiting.
    Fetch,
    /// I have everything up to `id`; stop keeping it.
    Ack { id: u64 },
    /// A reply typed by the owner.
    Say { text: String },
}

/// What the daemon sends back.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ToPhone {
    Welcome {
        host: String,
        queued: usize,
        /// Fresh per connection, for the handset to sign. Random and never
        /// reused, so a recorded signature cannot be replayed by something
        /// holding no key at all.
        challenge: Vec<u8>,
    },
    /// The answer to "is this still my phone?".
    Identity { verdict: String, detail: String },
    Alerts { alerts: Vec<QueuedAlert> },
    Ok,
    Error { message: String },
}

// ── The channel ───────────────────────────────────────────────────────────────

/// The phone, as a [`Notifier`].
pub struct PhoneChannel {
    queue: Arc<Mutex<AlertQueue>>,
    enabled: bool,
}

impl PhoneChannel {
    pub fn new(enabled: bool, queue: Arc<Mutex<AlertQueue>>) -> Self {
        PhoneChannel { queue, enabled }
    }
}

impl Notifier for PhoneChannel {
    fn name(&self) -> &'static str {
        "phone"
    }

    /// Ready whenever it is switched on.
    ///
    /// Note this says nothing about the phone being *connected*: queueing is
    /// delivery here, because the queue survives until acknowledged. Reporting
    /// "not ready" while the owner's phone is asleep would make the daemon
    /// think it was deaf and skip composing alerts it can perfectly well keep.
    fn ready(&self) -> bool {
        self.enabled
    }

    /// No. That is the entire point of this channel: no endpoint a stranger can
    /// reach, no relay that sees the traffic, no token that speaks for the
    /// machine if it leaks.
    fn third_party_reachable(&self) -> bool {
        false
    }

    fn send_text(&self, text: &str) -> Result<()> {
        self.queue.lock().expect("phone queue").push(text, None);
        Ok(())
    }

    fn send_photo(&self, caption: &str, photo: &Path) -> Result<()> {
        self.queue.lock().expect("phone queue").push(caption, Some(photo));
        Ok(())
    }
}

/// Bring the phone channel up: load the queue, start the listener, and hand
/// back the [`Notifier`] the rest of the daemon speaks through.
///
/// Fails loudly rather than silently degrading. A channel the owner asked for
/// and did not get is exactly the thing that must not pass unnoticed — they
/// would believe they were covered.
pub fn start(
    config: &crate::config::Config,
    on_command: impl Fn(&str) + Send + Sync + 'static,
) -> Result<PhoneChannel> {
    let bind = config
        .phone
        .bind
        .clone()
        .context("phone: [phone] bind is not set — say which address to listen on")?;
    let Some(key_hex) = config.phone.pairing_key.clone() else {
        // Pairing is the first thing anyone hits, so make it a usable
        // instruction rather than an error to go look up.
        let suggested = fresh_pairing_key().unwrap_or_default();
        anyhow::bail!(
            "phone: [phone] pairing_key is not set.\n\
             Aquí tienes una recién generada — ponla en config.toml y en la app:\n\n\
             \t[phone]\n\tpairing_key = \"{suggested}\"\n\n\
             Sellar un frame con ella ES la autenticación, así que es todo el \
             secreto: trátala como tal."
        );
    };
    let key = parse_key(&key_hex)?;

    let queue = Arc::new(Mutex::new(AlertQueue::load(
        Path::new(&config.phone.queue_path),
        config.phone.queue_capacity,
    )));
    {
        let q = queue.lock().expect("phone queue");
        if !q.is_empty() {
            log::info!("phone: {} alert(s) still waiting from before this start", q.len());
        }
    }

    let listener_queue = Arc::clone(&queue);
    let bind_for_thread = bind.clone();
    let profile = crate::phonehome::profile_path(&config.phone.queue_path);
    std::thread::Builder::new()
        .name("phone".to_string())
        .spawn(move || {
            run_phone_loop(&bind_for_thread, key, listener_queue, profile, on_command)
        })
        .context("spawning the phone listener")?;

    Ok(PhoneChannel::new(true, queue))
}

/// Parse the 64-hex-character pairing key.
fn parse_key(hex: &str) -> Result<[u8; 32]> {
    let hex = hex.trim();
    if hex.len() != 64 {
        anyhow::bail!("phone: pairing_key must be 64 hex characters, got {}", hex.len());
    }
    let mut key = [0u8; 32];
    for (i, byte) in key.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16)
            .map_err(|_| anyhow::anyhow!("phone: pairing_key is not hexadecimal"))?;
    }
    Ok(key)
}

/// Mint a fresh pairing key for the owner to copy into the app.
pub fn fresh_pairing_key() -> Result<String> {
    let mut key = [0u8; 32];
    getrandom::getrandom(&mut key)
        .map_err(|e| anyhow::anyhow!("phone: no entropy for a pairing key: {e}"))?;
    Ok(key.iter().map(|b| format!("{b:02x}")).collect())
}

// ── Listener ──────────────────────────────────────────────────────────────────

/// Serve the phone until the process ends.
pub fn run_phone_loop(
    bind: &str,
    key: [u8; 32],
    queue: Arc<Mutex<AlertQueue>>,
    profile_path: PathBuf,
    on_command: impl Fn(&str) + Send + Sync + 'static,
) {
    let listener = match TcpListener::bind(bind) {
        Ok(l) => l,
        Err(e) => {
            log::error!("phone: cannot listen on {bind}: {e} — the phone channel is down");
            return;
        }
    };
    log::info!("phone: listening on {bind} — direct, no relay, no third party");

    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                if let Err(e) = serve(s, &key, &queue, &profile_path, &on_command) {
                    // Deliberately terse: a peer that fails to authenticate is
                    // told nothing and logged at debug, so a port scan does not
                    // fill the log or learn that it found the right protocol.
                    log::debug!("phone: connection ended: {e}");
                }
            }
            Err(e) => log::warn!("phone: accept failed: {e}"),
        }
    }
}

fn serve(
    mut stream: TcpStream,
    key: &[u8; 32],
    queue: &Arc<Mutex<AlertQueue>>,
    profile_path: &Path,
    on_command: &(impl Fn(&str) + Send + Sync),
) -> Result<()> {
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))?;

    // The first frame must open with the paired key. A peer that cannot
    // produce one gets no reply at all.
    let first = read_frame(&mut stream)?;
    let plain = open(key, &first).context("unauthenticated peer")?;
    let hello: FromPhone = serde_json::from_slice(&plain)?;
    let FromPhone::Hello { app_version } = hello else {
        anyhow::bail!("first frame was not a hello");
    };
    log::info!("phone: authenticated client (app {app_version})");

    let queued = queue.lock().expect("phone queue").len();
    let host = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .unwrap_or_default()
        .trim()
        .to_string();
    // The challenge the handset must sign to prove it is the paired one.
    // Held for this connection only.
    let challenge = crate::phonehome::fresh_challenge()?;
    respond(
        &mut stream,
        key,
        &ToPhone::Welcome { host, queued, challenge: challenge.to_vec() },
    )?;

    loop {
        let frame = match read_frame(&mut stream) {
            Ok(f) => f,
            Err(_) => return Ok(()), // peer went away; normal
        };
        let plain = open(key, &frame).context("frame did not authenticate")?;
        let msg: FromPhone = serde_json::from_slice(&plain)?;

        let reply = match msg {
            FromPhone::Fetch => {
                let alerts = queue.lock().expect("phone queue").pending();
                ToPhone::Alerts { alerts }
            }
            FromPhone::Ack { id } => {
                let dropped = queue.lock().expect("phone queue").acknowledge(id);
                log::info!("phone: acknowledged up to {id} ({dropped} delivered)");
                ToPhone::Ok
            }
            FromPhone::Say { text } => {
                // Straight into the command layer. Replies come back through
                // `channel::notify`, which means they land in this same queue
                // and reach the phone on its next fetch — commands and alerts
                // travel the same road.
                on_command(&text);
                ToPhone::Ok
            }
            FromPhone::Identify { public_key, signature, backing, model, manufacturer } => {
                identify_handset(
                    profile_path,
                    &challenge,
                    &public_key,
                    &signature,
                    &backing,
                    &model,
                    &manufacturer,
                )
            }
            FromPhone::Hello { .. } => ToPhone::Error {
                message: "already said hello".to_string(),
            },
        };
        respond(&mut stream, key, &reply)?;
    }
}

fn respond(stream: &mut TcpStream, key: &[u8; 32], msg: &ToPhone) -> Result<()> {
    let json = serde_json::to_vec(msg)?;
    let sealed = seal(key, &json)?;
    write_frame(stream, &sealed)
}

/// Decide whether the handset on the line is the paired one, and record it the
/// first time — the phone's `/definehome`.
///
/// A first pairing is accepted and remembered. A later connection with a
/// different device key is *reported*, not silently accepted and not silently
/// re-bound: re-pairing is the owner's decision, and quietly adopting whatever
/// handset turns up would give away the only thing this check buys.
#[allow(clippy::too_many_arguments)]
fn identify_handset(
    profile_path: &Path,
    challenge: &[u8],
    public_key: &[u8],
    signature: &[u8],
    backing: &str,
    model: &str,
    manufacturer: &str,
) -> ToPhone {
    use crate::phonehome::{self, PhoneVerdict};

    // Signing comes first: a public key travels, so presenting one proves
    // nothing at all until it is used.
    if !phonehome::verify_challenge(public_key, challenge, signature) {
        log::warn!("phone: a client presented a device key it could not sign with");
        return ToPhone::Identity {
            verdict: "rejected".to_string(),
            detail: "la firma del desafío no verifica: quien está al otro lado no \
                     tiene la clave privada de ese dispositivo"
                .to_string(),
        };
    }

    let saved = phonehome::load(profile_path);
    match phonehome::identify(saved.as_ref(), public_key) {
        PhoneVerdict::SameDevice => {
            let detail = saved.map(|p| p.describe()).unwrap_or_default();
            log::info!("phone: paired handset confirmed — {detail}");
            ToPhone::Identity { verdict: "same_device".to_string(), detail }
        }
        PhoneVerdict::NotPaired => {
            let profile = phonehome::PhoneProfile {
                public_key_der: public_key.to_vec(),
                claimed_backing: backing.to_string(),
                // Verified separately once attestation parsing lands; recorded
                // as unproven so a later upgrade shows up as a change.
                attestation_verified: false,
                model: model.to_string(),
                manufacturer: manufacturer.to_string(),
                paired_at_unix: now_unix(),
            };
            let detail = profile.describe();
            match phonehome::save(profile_path, &profile) {
                Ok(()) => {
                    log::warn!("phone: HOME HANDSET DEFINED — {detail}");
                    ToPhone::Identity { verdict: "paired".to_string(), detail }
                }
                Err(e) => ToPhone::Error {
                    message: format!("no pude guardar el perfil del teléfono: {e}"),
                },
            }
        }
        PhoneVerdict::DifferentDevice => {
            log::error!(
                "phone: a DIFFERENT handset answered with a valid pairing key — \
                 the pairing secret may have been copied"
            );
            ToPhone::Identity {
                verdict: "different_device".to_string(),
                detail: PhoneVerdict::DifferentDevice.describe().to_string(),
            }
        }
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("sysentinel-phone-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn a_frame_round_trips_and_a_wrong_key_cannot_open_it() {
        let key = [7u8; 32];
        let sealed = seal(&key, b"hola").unwrap();
        assert_eq!(open(&key, &sealed).unwrap(), b"hola");

        let wrong = [8u8; 32];
        assert!(open(&wrong, &sealed).is_err(), "a wrong key must not open a frame");

        // Tampering anywhere must fail the tag, not silently alter the message.
        let mut tampered = sealed.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(open(&key, &tampered).is_err());
        let mut flipped_nonce = sealed.clone();
        flipped_nonce[0] ^= 1;
        assert!(open(&key, &flipped_nonce).is_err());
    }

    #[test]
    fn every_frame_uses_a_fresh_nonce() {
        // A repeated nonce under one key breaks GCM outright, so this is not a
        // nicety. Random per frame, never a counter that a restart could reset.
        let key = [3u8; 32];
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            let f = seal(&key, b"same plaintext every time").unwrap();
            assert!(seen.insert(f[..NONCE_LEN].to_vec()), "nonce reused");
        }
        // Identical plaintext must not produce identical ciphertext either.
        let a = seal(&key, b"x").unwrap();
        let b = seal(&key, b"x").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn a_short_or_empty_frame_is_rejected_not_panicked_on() {
        let key = [1u8; 32];
        assert!(open(&key, &[]).is_err());
        assert!(open(&key, &[0u8; NONCE_LEN]).is_err(), "nonce with no body");
        assert!(open(&key, &[0u8; NONCE_LEN - 1]).is_err());
    }

    #[test]
    fn the_queue_survives_a_restart() {
        // The whole reason the queue exists: an alert observed while the phone
        // was asleep must be delayed, not lost.
        let dir = tmpdir("persist");
        let path = dir.join("queue.json");

        let mut q = AlertQueue::load(&path, 100);
        assert!(q.is_empty());
        q.push("alguien tocó el equipo", None);
        q.push("y conectó un disco", Some(Path::new("/tmp/shot.jpg")));

        // A fresh load is what a restarted daemon sees.
        let q2 = AlertQueue::load(&path, 100);
        assert_eq!(q2.len(), 2);
        let pending = q2.pending();
        assert_eq!(pending[0].text, "alguien tocó el equipo");
        assert_eq!(pending[1].photo.as_deref(), Some("/tmp/shot.jpg"));
        // Ids must not restart, or an ack would drop the wrong things.
        assert!(pending[1].id > pending[0].id);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn only_an_acknowledgement_drops_an_alert() {
        let dir = tmpdir("ack");
        let path = dir.join("queue.json");
        let mut q = AlertQueue::load(&path, 100);
        let first = q.push("uno", None);
        let second = q.push("dos", None);
        q.push("tres", None);

        // Fetching changes nothing: delivery is not acknowledgement.
        assert_eq!(q.pending().len(), 3);
        assert_eq!(q.pending().len(), 3);

        assert_eq!(q.acknowledge(second), 2);
        assert_eq!(q.len(), 1);
        assert_eq!(q.pending()[0].text, "tres");
        // Acking something already gone is harmless.
        assert_eq!(q.acknowledge(first), 0);

        // And it persisted.
        assert_eq!(AlertQueue::load(&path, 100).len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_phone_left_off_for_a_month_cannot_fill_the_disk() {
        let dir = tmpdir("cap");
        let path = dir.join("queue.json");
        let mut q = AlertQueue::load(&path, 3);
        for i in 0..10 {
            q.push(&format!("alerta {i}"), None);
        }
        assert_eq!(q.len(), 3);
        // The newest survive: a month-old alert matters less than this morning's.
        assert_eq!(q.pending()[0].text, "alerta 7");
        assert_eq!(q.pending()[2].text, "alerta 9");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn queueing_counts_as_delivery_for_this_channel() {
        // If `ready()` went false whenever the phone was asleep, the daemon
        // would believe it was deaf and skip composing alerts it could keep.
        let dir = tmpdir("notifier");
        let q = Arc::new(Mutex::new(AlertQueue::load(&dir.join("q.json"), 10)));
        let ch = PhoneChannel::new(true, q.clone());

        assert!(ch.ready());
        assert!(!ch.third_party_reachable(), "this channel exists to have no relay");
        ch.send_text("algo pasó").unwrap();
        ch.send_photo("con foto", Path::new("/tmp/x.jpg")).unwrap();
        assert_eq!(q.lock().unwrap().len(), 2);

        let off = PhoneChannel::new(false, q);
        assert!(!off.ready());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_pairing_key_must_be_exactly_thirty_two_bytes_of_hex() {
        let good = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff";
        assert_eq!(parse_key(good).unwrap()[0], 0x00);
        assert_eq!(parse_key(good).unwrap()[31], 0xff);
        // Whitespace from a copy-paste is forgiven; anything else is not.
        assert!(parse_key(&format!("  {good}\n")).is_ok());
        assert!(parse_key("").is_err());
        assert!(parse_key("abc").is_err());
        assert!(parse_key(&"z".repeat(64)).is_err());
    }

    #[test]
    fn a_minted_key_is_fresh_and_usable() {
        let a = fresh_pairing_key().unwrap();
        let b = fresh_pairing_key().unwrap();
        assert_eq!(a.len(), 64);
        assert_ne!(a, b, "each pairing gets its own key");
        let key = parse_key(&a).unwrap();
        assert_eq!(open(&key, &seal(&key, b"prueba").unwrap()).unwrap(), b"prueba");
    }

    /// Cross-language check against the JVM's `javax.crypto`, which is what the
    /// Android client uses.
    ///
    /// Two implementations agreeing about AEAD is not something to assume: a
    /// mismatched tag length or nonce convention produces code that works
    /// perfectly on each side and never once interoperates. Driven by
    /// `scripts/phone-interop-check.sh`, which runs the Java half.
    #[test]
    fn frames_interoperate_with_the_jvm() {
        let key = [0x42u8; 32];

        // Hand a frame to the JVM to open.
        if let Ok(path) = std::env::var("SYSENTINEL_INTEROP_OUT") {
            let sealed = seal(&key, b"desde rust").unwrap();
            let hex: String = sealed.iter().map(|b| format!("{b:02x}")).collect();
            std::fs::write(&path, hex).unwrap();
        }

        // Open one the JVM produced.
        if let Ok(path) = std::env::var("SYSENTINEL_INTEROP_IN") {
            let hex = std::fs::read_to_string(&path).unwrap();
            let bytes: Vec<u8> = hex
                .trim()
                .as_bytes()
                .chunks(2)
                .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
                .collect();
            let opened = open(&key, &bytes).expect("the JVM's frame must authenticate");
            assert_eq!(
                String::from_utf8(opened).unwrap(),
                "desde java",
                "the JVM sealed something other than what we expect"
            );
            println!("interop: opened the JVM's frame");
        }

        // And the device key: a signature the JVM produced with an EC P-256
        // Keystore-shaped key must verify here. Two ECDSA stacks agreeing on
        // the ASN.1 encoding is as unsafe to assume as two AEAD stacks
        // agreeing on a tag length.
        if let (Ok(c), Ok(pk), Ok(sg)) = (
            std::env::var("SYSENTINEL_INTEROP_CHALLENGE"),
            std::env::var("SYSENTINEL_INTEROP_PUBKEY"),
            std::env::var("SYSENTINEL_INTEROP_SIG"),
        ) {
            let unhex = |p: &str| -> Vec<u8> {
                std::fs::read_to_string(p)
                    .unwrap()
                    .trim()
                    .as_bytes()
                    .chunks(2)
                    .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
                    .collect()
            };
            let challenge = unhex(&c);
            let pubkey = unhex(&pk);
            let sig = unhex(&sg);
            assert!(
                crate::phonehome::verify_challenge(&pubkey, &challenge, &sig),
                "the JVM's ECDSA signature must verify here"
            );
            // And it must not verify against something else.
            assert!(!crate::phonehome::verify_challenge(&pubkey, b"otro desafio", &sig));
            println!("interop: verified the JVM's device-key signature");
        }
    }

    #[test]
    fn the_protocol_round_trips() {
        let hello = FromPhone::Hello { app_version: "0.1.0".into() };
        let json = serde_json::to_string(&hello).unwrap();
        assert_eq!(json, r#"{"op":"hello","app_version":"0.1.0"}"#);
        assert_eq!(serde_json::from_str::<FromPhone>(&json).unwrap(), hello);

        let ack = serde_json::from_str::<FromPhone>(r#"{"op":"ack","id":7}"#).unwrap();
        assert_eq!(ack, FromPhone::Ack { id: 7 });

        let w = ToPhone::Welcome {
            host: "laptop".into(),
            queued: 3,
            challenge: vec![0u8; 32],
        };
        assert!(serde_json::to_string(&w).unwrap().contains("\"queued\":3"));
    }
}
