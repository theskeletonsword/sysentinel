// SPDX-License-Identifier: Apache-2.0
//!
//! Text that came from somewhere else, made safe to show.
//!
//! # Where these strings come from
//!
//! A surprising amount of what this daemon repeats back to its owner is chosen
//! by somebody else:
//!
//! - `ut_host` in `wtmp` is whatever the remote end of an SSH session called
//!   itself;
//! - the product name of a USB device is a string in its descriptor, and a
//!   device that lies about being a keyboard is not going to be honest about
//!   its name either;
//! - the version a phone reports at the start of a connection is whatever the
//!   client sent.
//!
//! All three end up in a log an operator reads, in an alert on a phone, and in
//! the context handed to a language model.
//!
//! # What that costs if it is not cleaned
//!
//! A newline forges log lines: `\n2026-09-11 03:14 INFO login accepted` reads
//! exactly like the daemon's own output to anyone skimming, which is how an
//! intrusion gets buried under its own alert. Terminal escapes go further — a
//! `\x1b[2K\r` can rewrite the line that was just printed, so the record of
//! what happened is the attacker's to compose. And a device name of a hundred
//! kilobytes is a cheap way to fill a queue that is supposed to hold alerts.
//!
//! Stripping control characters and capping the length costs nothing for the
//! honest cases, which are short printable names.

/// Longest a label from outside is allowed to be.
///
/// Real values are short: a hostname, a device product string, a version.
/// Anything past this is padding, and padding in an alert queue is somebody
/// else deciding how much of the owner's disk to use.
const MAX_LABEL: usize = 96;

/// Clean a label that came from outside for display, logging or an LLM prompt.
///
/// Keeps printable text — accents, CJK, emoji in a device name all survive —
/// and removes what can lie about the shape of the output.
pub fn label(s: &str) -> String {
    let cleaned: String = s
        .chars()
        // `is_control` covers C0, C1 and DEL, which is where ESC, CR and LF
        // all live.
        .filter(|c| !c.is_control())
        .take(MAX_LABEL)
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        "?".to_string()
    } else {
        trimmed.to_string()
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_forged_log_line_cannot_survive() {
        let ssh_host = "evil\n2026-09-11 03:14 INFO login accepted for skels";
        let out = label(ssh_host);
        assert!(!out.contains('\n'), "{out}");
        assert!(out.starts_with("evil"), "{out}");
    }

    #[test]
    fn terminal_escapes_are_removed() {
        // \x1b[2K\r erases the line just written, letting a USB device's
        // product string rewrite the record of its own arrival.
        let device = "\u{1b}[2K\rTeclado del dueño";
        let out = label(device);
        assert!(!out.contains('\u{1b}'), "{out:?}");
        assert!(!out.contains('\r'), "{out:?}");
        assert_eq!(out, "[2KTeclado del dueño");
    }

    #[test]
    fn ordinary_names_are_left_alone() {
        for name in [
            "Logitech USB Receiver",
            "AT Translated Set 2 keyboard",
            "Teclado español (ñ, á)",
            "デバイス",
        ] {
            assert_eq!(label(name), name);
        }
    }

    #[test]
    fn a_name_cannot_be_used_as_padding() {
        let huge = "A".repeat(10_000);
        assert_eq!(label(&huge).len(), MAX_LABEL);
    }

    #[test]
    fn nothing_at_all_still_reads_as_something() {
        // An empty or control-only name must not render as a blank gap in an
        // alert, where it reads as though the daemon failed to say anything.
        assert_eq!(label(""), "?");
        assert_eq!(label("\u{0}\u{1}\u{2}"), "?");
        assert_eq!(label("   "), "?");
    }
}
