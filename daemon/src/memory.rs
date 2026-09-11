// SPDX-License-Identifier: Apache-2.0
//!
//! Long-term memory and rolling conversation context for the bot.
//!
//! Two plain-text files are managed (paths from `[memory]` in config.toml):
//!
//! | File          | Purpose                                              |
//! |---------------|------------------------------------------------------|
//! | `memory.txt`  | **Long-term memory.** Everything you want the bot to remember forever (preferences, names, instructions). Read-only from the bot's perspective: edit it by hand. Its contents are injected into every LLM turn. |
//! | `context.txt` | **Rolling context window.** Conversation history, one `[USER]`/`[ASSISTANT]` turn per entry, pruned to the last `context_max_entries` turns. Cleared with `/resetcontext`. |
//!
//! # File format (`context.txt`)
//!
//! ```text
//! # 2026-09-06 12:01:03
//! [USER]
//! what's the CPU load right now?
//! [ASSISTANT]
//! Load average is 0.35 — mostly idle.
//! [END]
//! ```
//!
//! The `#` line is a human-readable timestamp; it is regenerated on every
//! append and ignored by the parser.

use anyhow::{Context, Result};
use std::fs;
use std::io::Write as IoWrite;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

/// A single conversational turn held in the context file.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Turn {
    User(String),
    Assistant(String),
}

/// Thread-safe front door to the two memory files.
///
/// The internal `Mutex` serialises file I/O; the bot runs on a single thread
/// but sharing it through `Arc<MemoryStore>` keeps every access race-free.
pub struct MemoryStore {
    memory_file: PathBuf,
    context_file: PathBuf,
    max_entries: AtomicUsize,
    lock: Mutex<()>,
}

/// Longest a single stored entry may be.
///
/// The context file is read back into *every* prompt, so one huge turn is
/// paid for on every request that follows it — and `/remember` appends
/// forever. A few KB is more than any real fact or answer.
const MAX_ENTRY: usize = 4 * 1024;

/// Trim and cut an entry on a character boundary.
fn clamp(text: &str) -> String {
    let t = text.trim();
    if t.len() <= MAX_ENTRY {
        return t.to_string();
    }
    let mut cut = MAX_ENTRY;
    while cut > 0 && !t.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}…", &t[..cut])
}

impl MemoryStore {
    pub fn new(memory_file: &str, context_file: &str, max_entries: usize) -> Self {
        Self {
            memory_file: PathBuf::from(memory_file),
            context_file: PathBuf::from(context_file),
            max_entries: AtomicUsize::new(max_entries.max(2)),
            lock: Mutex::new(()),
        }
    }

    /// Change the rolling-context size live (`/settings context_entries`).
    /// The next `append_turn` prunes to the new cap; existing turns stay.
    pub fn set_max_entries(&self, n: usize) {
        self.max_entries.store(n.max(2), Ordering::Relaxed);
    }

    fn ensure_parents(path: &Path) -> Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| anyhow::anyhow!("creating dir {}: {e}", parent.display()))?;
        }
        Ok(())
    }

    /// Read the long-term memory file. Missing/empty file → empty string.
    pub fn load_memory(&self) -> String {
        let _guard = self.lock.lock().expect("memory mutex");
        fs::read_to_string(&self.memory_file).unwrap_or_default()
    }

    /// Read the rolling context window (conversation history).
    /// Missing/empty file → empty string.
    pub fn load_context(&self) -> String {
        let _guard = self.lock.lock().expect("memory mutex");
        fs::read_to_string(&self.context_file).unwrap_or_default()
    }

    /// Append a user+assistant turn to the context file, pruning to the last
    /// `max_entries` turns. Creates the file (and its directory) if needed.
    pub fn append_turn(&self, user_msg: &str, assistant_msg: &str) -> Result<()> {
        let _guard = self.lock.lock().expect("memory mutex");

        Self::ensure_parents(&self.context_file)?;

        let mut turns = Self::parse_context(
            &fs::read_to_string(&self.context_file).unwrap_or_default(),
        );

        // Bounded per turn, not only by count. The context file is read back
        // into every prompt, so one enormous turn is paid for on every
        // request that follows it, forever.
        turns.push(Turn::User(clamp(user_msg)));
        turns.push(Turn::Assistant(clamp(assistant_msg)));

        // Keep only the most recent `max_entries` turns.
        if turns.len() > self.max_entries.load(Ordering::Relaxed) {
            let drop = turns.len() - self.max_entries.load(Ordering::Relaxed);
            turns.drain(0..drop);
        }

        let serialized = Self::serialize(&turns);
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .open(&self.context_file)
            .with_context(|| format!("opening {}", self.context_file.display()))?;
        file.write_all(serialized.as_bytes())
            .with_context(|| format!("writing {}", self.context_file.display()))?;

        Ok(())
    }

    /// Clear the conversation context entirely. Backing file becomes empty.
    pub fn reset_context(&self) -> Result<()> {
        let _guard = self.lock.lock().expect("memory mutex");
        fs::write(&self.context_file, "")
            .with_context(|| format!("resetting {}", self.context_file.display()))
    }

    /// Append a user-provided long-term fact to memory.txt (`/remember`).
    /// Creates the file (and its directory) if needed.
    pub fn append_memory(&self, text: &str) -> Result<()> {
        let _guard = self.lock.lock().expect("memory mutex");
        Self::ensure_parents(&self.memory_file)?;
        let trimmed = clamp(text);
        if trimmed.is_empty() {
            return Ok(());
        }
        let trimmed = trimmed.as_str();
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.memory_file)
            .with_context(|| format!("opening {}", self.memory_file.display()))?;
        writeln!(file, "- {trimmed}")
            .with_context(|| format!("appending to {}", self.memory_file.display()))
    }

    // ── Parsing / serialising ─────────────────────────────────────────────────

    /// Parse the context file into a list of turns, ignoring timestamps.
    fn parse_context(raw: &str) -> Vec<Turn> {
        let mut turns = Vec::new();
        let mut current: Option<Turn> = None;
        let mut block = String::new();

        let flush = |current: &mut Option<Turn>, block: &mut String, turns: &mut Vec<Turn>| {
            if let Some(turn) = current.take() {
                let text = std::mem::take(block);
                match turn {
                    Turn::User(_)  if !text.trim().is_empty() => turns.push(Turn::User(text.trim().to_string())),
                    Turn::Assistant(_) if !text.trim().is_empty() => turns.push(Turn::Assistant(text.trim().to_string())),
                    _ => {}
                }
            } else {
                block.clear();
            }
        };

        for line in raw.lines() {
            let trimmed = line.trim_end();
            match trimmed {
                "[USER]" => { flush(&mut current, &mut block, &mut turns); current = Some(Turn::User(String::new())); }
                "[ASSISTANT]" => { flush(&mut current, &mut block, &mut turns); current = Some(Turn::Assistant(String::new())); }
                "[END]" => { flush(&mut current, &mut block, &mut turns); }
                comment if comment.starts_with('#') => continue,
                _ => {
                    if current.is_some() {
                        block.push_str(trimmed);
                        block.push('\n');
                    }
                }
            }
        }
        flush(&mut current, &mut block, &mut turns);

        turns
    }

    /// Serialise turns back into the context file format.
    fn serialize(turns: &[Turn]) -> String {
        let mut out = String::new();
        for turn in turns {
            match turn {
                Turn::User(text) => {
                    out.push_str(&format!(
                        "# {}\n[USER]\n{}\n[END]\n",
                        timestamp_now(),
                        text.trim()
                    ));
                }
                Turn::Assistant(text) => {
                    out.push_str(&format!(
                        "# {}\n[ASSISTANT]\n{}\n[END]\n",
                        timestamp_now(),
                        text.trim()
                    ));
                }
            }
        }
        out
    }
}

/// RFC-2822-ish local timestamp for the human-readable `#` comment lines.
fn timestamp_now() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days = now / 86400;
    let (y, m, d) = civil_from_days(days as i64);
    let secs_of_day = now % 86400;
    format!("{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}",
        secs_of_day / 3600,
        (secs_of_day % 3600) / 60,
        secs_of_day % 60)
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    // Howard Hinnant's civil_from_days algorithm (public domain).
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = (z - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_enormous_turn_cannot_be_paid_for_forever() {
        // The context file is read back into every prompt. Storing a megabyte
        // once means sending a megabyte on every request after it — at the
        // owner's cost, until something else prunes it out.
        let huge = "x".repeat(200_000);
        let kept = clamp(&huge);
        assert!(kept.len() <= MAX_ENTRY + 4, "{}", kept.len());
        assert!(kept.ends_with('…'), "the cut must be visible");

        // Ordinary text is untouched, including multi-byte characters.
        assert_eq!(clamp("  hola, ¿qué tal?  "), "hola, ¿qué tal?");
        assert_eq!(clamp(""), "");

        // And the cut never lands inside a character.
        let accented = "á".repeat(MAX_ENTRY);
        let cut = clamp(&accented);
        assert!(cut.chars().all(|c| c == 'á' || c == '…'), "cut mid-character");
    }

    #[test]
    fn parse_round_trip() {
        let turns = vec![Turn::User("hola".into()), Turn::Assistant("hola tú".into())];
        let ser = MemoryStore::serialize(&turns);
        assert_eq!(MemoryStore::parse_context(&ser), turns);
    }

    #[test]
    fn prune_keeps_last_n() {
        let mut turns: Vec<Turn> = (0..10).map(|i| Turn::User(format!("m{i}"))).collect();
        if turns.len() > 4 {
            turns.drain(0..turns.len() - 4);
        }
        assert_eq!(turns, vec![
            Turn::User("m6".into()),
            Turn::User("m7".into()),
            Turn::User("m8".into()),
            Turn::User("m9".into()),
        ]);
    }

    #[test]
    fn timestamp_is_sane() {
        let ts = timestamp_now();
        // YYYY-MM-DD HH:MM:SS
        assert_eq!(ts.len(), 19);
        assert_eq!(ts.as_bytes()[4], b'-');
        assert_eq!(ts.as_bytes()[7], b'-');
        assert_eq!(ts.as_bytes()[13], b':');
    }
}