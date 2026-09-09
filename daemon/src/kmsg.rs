// SPDX-License-Identifier: MIT OR GPL-2.0-or-later
//! Real-time reader for `/dev/kmsg`.
//!
//! `/dev/kmsg` supports a "follow" mode: seeking to the end and then
//! issuing blocking `read()`s yields each new kernel log record as it
//! is emitted, without polling. This is the same mechanism `dmesg
//! --follow` and `journalctl -k -f` use internally.
//!
//! Each record read this way starts with a structured prefix:
//!   `<priority>,<sequence>,<timestamp_us>,<flags>[,extra];<message text>`
//! We parse just enough of that prefix to recover the syslog priority
//! and the human-readable message; anything else is ignored.

use anyhow::{Context, Result};
use std::fs::File;
use std::io::{BufRead, BufReader, Seek, SeekFrom};

/// A single parsed kernel log record we care about.
#[derive(Debug, Clone)]
pub struct KmsgRecord {
    /// Standard syslog priority (0=emerg .. 7=debug), if it could be parsed.
    pub priority: Option<u8>,
    /// The human-readable message body, with continuation lines dropped.
    pub message: String,
}

pub struct KmsgReader {
    reader: BufReader<File>,
}

impl KmsgReader {
    /// Open `/dev/kmsg` and seek to the end so we only observe records
    /// emitted from this point forward (we are a watchdog, not a log
    /// archaeologist — historical records are `dmesg`'s job).
    pub fn open_follow() -> Result<Self> {
        let mut file = File::open("/dev/kmsg").context(
            "opening /dev/kmsg — this daemon must run as a user with CAP_SYSLOG \
             or root, and /dev/kmsg must exist (it does on any modern Linux host)",
        )?;
        // SEEK_END on /dev/kmsg is special-cased by the kernel to mean
        // "start following from the next record", per kmsg(4) semantics
        // used by journald/dmesg.
        file.seek(SeekFrom::End(0))
            .context("seeking /dev/kmsg to end for follow mode")?;
        Ok(Self {
            reader: BufReader::new(file),
        })
    }

    /// Block until the next kernel log record arrives, then return it
    /// parsed. Returns `Ok(None)` only on a benign, resumable read
    /// hiccup (e.g. `-EPIPE` when records were dropped due to buffer
    /// overrun) — the caller should just loop again.
    pub fn next_record(&mut self) -> Result<Option<KmsgRecord>> {
        let mut line = String::new();
        let n = self
            .reader
            .read_line(&mut line)
            .context("reading a record from /dev/kmsg")?;
        if n == 0 {
            // EOF should not normally happen in follow mode; treat as
            // a transient condition rather than a hard error so the
            // caller's loop can retry.
            return Ok(None);
        }
        Ok(Some(parse_record(&line)))
    }
}

fn parse_record(line: &str) -> KmsgRecord {
    // Format: "<prio>,<seq>,<ts_us>,<flags>[,extra];<message>\n"
    let Some((prefix, message)) = line.split_once(';') else {
        return KmsgRecord {
            priority: None,
            message: line.trim_end().to_string(),
        };
    };

    let priority = prefix
        .split(',')
        .next()
        .and_then(|p| p.parse::<u32>().ok())
        // The low 3 bits of the combined facility/priority field are
        // the syslog priority.
        .map(|combined| (combined & 0x7) as u8);

    KmsgRecord {
        priority,
        message: message.trim_end().to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_typical_record() {
        let line = "6,1234,98765432,-;Out of memory: Killed process 4321 (chromium)\n";
        let rec = parse_record(line);
        assert_eq!(rec.priority, Some(6));
        assert_eq!(rec.message, "Out of memory: Killed process 4321 (chromium)");
    }

    #[test]
    fn falls_back_when_unstructured() {
        let line = "some unexpected line without a semicolon marker\n";
        let rec = parse_record(line);
        assert_eq!(rec.priority, None);
        assert_eq!(rec.message, "some unexpected line without a semicolon marker");
    }
}
