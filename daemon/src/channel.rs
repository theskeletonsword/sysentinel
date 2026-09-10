// SPDX-License-Identifier: Apache-2.0
//!
//! How the daemon reaches its owner — as a pluggable channel, not a hardcoded
//! one.
//!
//! Everything this daemon does is worthless if it cannot tell anyone. The
//! duress alert, the "¿fuiste tú?" question about a new disk, the LUKS
//! tripwire, the ARM → confirm ritual: all of it is a conversation with a
//! person who is somewhere else. That conversation needs a transport, and
//! *which* transport is a security decision in its own right.
//!
//! # Why this is an abstraction and not just Telegram
//!
//! A Telegram bot has properties that matter here, and not in a good way:
//!
//! - **The bot token is a bearer credential.** Anyone who reads it from the
//!   config, a backup or a process dump can speak as the machine.
//! - **The endpoint is reachable by strangers.** A bot can be found and
//!   messaged by anyone; the daemon's whitelist rejects them *after* they have
//!   already reached it.
//! - **The messages transit somebody else's servers**, which see who is talking
//!   to whom, and when — the exact metadata a tripwire produces.
//!
//! None of that makes Telegram useless: it is out of band, it works on every
//! phone, and it needs no infrastructure. It is a fine floor. It is a poor
//! ceiling, which is why [`Notifier::third_party_reachable`] exists — a channel
//! is asked to admit what it exposes, and [`Channels::exposure_note`] says so
//! out loud rather than leaving it implied.
//!
//! # Going deaf is a failure mode, not a hardening
//!
//! Turning every channel off does not reduce the attack surface of a watchdog;
//! it turns it into a device that observes and can never report. [`Channels`]
//! therefore tracks whether *anything* can reach the owner, and
//! [`Channels::is_deaf`] is the condition worth refusing to be in silently.
//!
//! The intended endpoint is the phone app, which can hold a key this machine
//! cannot reach and needs no third party to route a message. Until it exists
//! and is verified, removing the channel that does work would leave the daemon
//! watching with no way to speak.

use std::path::Path;

use anyhow::Result;

/// One way of reaching the owner.
pub trait Notifier: Send + Sync {
    /// Short name for logs and the exposure note.
    fn name(&self) -> &'static str;

    /// Whether this channel could deliver something right now — configured,
    /// paired, and switched on.
    fn ready(&self) -> bool;

    /// Whether a stranger can reach this channel's endpoint, or observe that a
    /// message passed through it.
    ///
    /// Answered honestly by each channel; the daemon reports it rather than
    /// ranking channels for the owner.
    fn third_party_reachable(&self) -> bool;

    fn send_text(&self, text: &str) -> Result<()>;

    fn send_photo(&self, caption: &str, photo: &Path) -> Result<()>;
}

/// Every channel the daemon may speak through.
pub struct Channels {
    notifiers: Vec<Box<dyn Notifier>>,
}

impl Channels {
    pub fn new(notifiers: Vec<Box<dyn Notifier>>) -> Self {
        Channels { notifiers }
    }

    /// True when nothing can reach the owner. A watchdog in this state is not
    /// hardened, it is mute.
    pub fn is_deaf(&self) -> bool {
        !self.notifiers.iter().any(|n| n.ready())
    }

    /// Names of the channels that could deliver right now.
    pub fn ready_names(&self) -> Vec<&'static str> {
        self.notifiers.iter().filter(|n| n.ready()).map(|n| n.name()).collect()
    }

    /// What the owner is exposing by using the channels that are on, or `None`
    /// when nothing reachable by strangers is enabled.
    pub fn exposure_note(&self) -> Option<String> {
        let exposed: Vec<&str> = self
            .notifiers
            .iter()
            .filter(|n| n.ready() && n.third_party_reachable())
            .map(|n| n.name())
            .collect();
        if exposed.is_empty() {
            return None;
        }
        Some(format!(
            "canal(es) alcanzables por terceros: {} — el endpoint existe para \
             cualquiera que lo encuentre, y quien pase por ahí ve que hablaste, \
             cuándo y con quién",
            exposed.join(", ")
        ))
    }

    /// Deliver to every ready channel, best effort.
    ///
    /// Best effort on purpose: one channel failing must not silence the others,
    /// because the whole point of having more than one is that they fail
    /// independently. Returns how many actually delivered.
    pub fn notify(&self, text: &str) -> usize {
        let mut delivered = 0;
        for n in self.notifiers.iter().filter(|n| n.ready()) {
            match n.send_text(text) {
                Ok(()) => delivered += 1,
                Err(e) => log::warn!("channel {}: delivery failed: {e:#}", n.name()),
            }
        }
        if delivered == 0 {
            log::error!(
                "no channel delivered this alert — the daemon saw something and \
                 could not tell anyone: {}",
                text.lines().next().unwrap_or(text)
            );
        }
        delivered
    }

    /// Deliver a photo where the channel supports it, falling back to the
    /// caption alone where it does not. Evidence is better than nothing.
    pub fn notify_photo(&self, caption: &str, photo: &Path) -> usize {
        let mut delivered = 0;
        for n in self.notifiers.iter().filter(|n| n.ready()) {
            let sent = match n.send_photo(caption, photo) {
                Ok(()) => true,
                Err(e) => {
                    log::warn!(
                        "channel {}: photo failed ({e:#}) — sending the text alone",
                        n.name()
                    );
                    n.send_text(caption).is_ok()
                }
            };
            if sent {
                delivered += 1;
            }
        }
        delivered
    }
}

// ── The process's channels ────────────────────────────────────────────────────
//
// A process-wide registry, in the shape a logger has, and for the same reason:
// "how this program reaches its owner" is a property of the process, not
// something each watcher should be handed and could forget to use. Set once at
// startup; every alert path then reads it without threading a parameter through
// seven loops.

static CHANNELS: std::sync::OnceLock<Channels> = std::sync::OnceLock::new();

/// Install the process's channels. Later calls are ignored — the transport is
/// decided at startup, and a watcher must not be able to swap it.
pub fn init(channels: Channels) {
    if CHANNELS.set(channels).is_err() {
        log::warn!("channel: already initialised — ignoring the second attempt");
    }
}

/// Reach the owner. Zero means nobody was reached, which is logged loudly by
/// [`Channels::notify`].
pub fn notify(text: &str) -> usize {
    match CHANNELS.get() {
        Some(c) => c.notify(text),
        None => {
            log::error!("channel: not initialised — alert dropped: {text}");
            0
        }
    }
}

/// Reach the owner with evidence attached.
pub fn notify_photo(caption: &str, photo: &Path) -> usize {
    match CHANNELS.get() {
        Some(c) => c.notify_photo(caption, photo),
        None => {
            log::error!("channel: not initialised — photo alert dropped");
            0
        }
    }
}

/// Names of the channels that could deliver right now.
pub fn ready_names() -> Vec<&'static str> {
    CHANNELS.get().map(|c| c.ready_names()).unwrap_or_default()
}

/// Whether nothing can currently reach the owner.
pub fn is_deaf() -> bool {
    CHANNELS.get().map(|c| c.is_deaf()).unwrap_or(true)
}

/// What the live channels expose to third parties, if anything.
pub fn exposure_note() -> Option<String> {
    CHANNELS.get().and_then(|c| c.exposure_note())
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    struct Fake {
        name: &'static str,
        ready: bool,
        exposed: bool,
        fail: bool,
        sent: AtomicUsize,
    }

    impl Fake {
        fn new(name: &'static str, ready: bool, exposed: bool, fail: bool) -> Self {
            Fake { name, ready, exposed, fail, sent: AtomicUsize::new(0) }
        }
    }

    impl Notifier for Fake {
        fn name(&self) -> &'static str { self.name }
        fn ready(&self) -> bool { self.ready }
        fn third_party_reachable(&self) -> bool { self.exposed }
        fn send_text(&self, _t: &str) -> Result<()> {
            if self.fail {
                anyhow::bail!("nope");
            }
            self.sent.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
        fn send_photo(&self, _c: &str, _p: &Path) -> Result<()> {
            if self.fail {
                anyhow::bail!("nope");
            }
            self.sent.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    #[test]
    fn no_ready_channel_means_deaf() {
        // The state worth refusing to be in silently: a watchdog that observes
        // and cannot report is not a hardened one.
        let c = Channels::new(vec![]);
        assert!(c.is_deaf());
        assert_eq!(c.notify("algo pasó"), 0);

        let c = Channels::new(vec![Box::new(Fake::new("off", false, true, false))]);
        assert!(c.is_deaf(), "a configured-but-not-ready channel is not a channel");
        assert!(c.ready_names().is_empty());
    }

    #[test]
    fn one_failing_channel_does_not_silence_the_others() {
        // The whole reason to have more than one is that they fail apart.
        let c = Channels::new(vec![
            Box::new(Fake::new("broken", true, false, true)),
            Box::new(Fake::new("works", true, false, false)),
        ]);
        assert!(!c.is_deaf());
        assert_eq!(c.notify("alerta"), 1);
    }

    #[test]
    fn exposure_is_reported_only_for_channels_actually_in_use() {
        // An exposed channel that is switched off exposes nothing.
        let c = Channels::new(vec![Box::new(Fake::new("telegram", false, true, false))]);
        assert!(c.exposure_note().is_none());

        let c = Channels::new(vec![Box::new(Fake::new("telegram", true, true, false))]);
        let note = c.exposure_note().expect("an exposed live channel must be declared");
        assert!(note.contains("telegram"), "{note}");
        assert!(note.contains("terceros"), "{note}");

        // A channel nobody else can reach raises no note.
        let c = Channels::new(vec![Box::new(Fake::new("phone", true, false, false))]);
        assert!(c.exposure_note().is_none());
        assert_eq!(c.ready_names(), vec!["phone"]);
    }

    #[test]
    fn a_photo_that_will_not_send_falls_back_to_its_caption() {
        // Evidence beats nothing: losing the image must not lose the alert.
        let c = Channels::new(vec![Box::new(Fake::new("text-only", true, false, true))]);
        assert_eq!(c.notify_photo("intruso", Path::new("/nonexistent.jpg")), 0);

        let c = Channels::new(vec![Box::new(Fake::new("ok", true, false, false))]);
        assert_eq!(c.notify_photo("intruso", Path::new("/nonexistent.jpg")), 1);
    }

}
