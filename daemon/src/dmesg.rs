// SPDX-License-Identifier: Apache-2.0
//!
//! On-demand dmesg reading — because running `dmesg | less` is someone else's
//! problem. The bot reads the kernel ring buffer (via the `dmesg` binary, or
//! `journalctl -k` as a fallback) and reports only the lines that matter.
//!
//! Reading the ring buffer needs root/CAP_SYSLOG (see `sysentinel.service`,
//! which runs the daemon as `sysentinel` with `AmbientCapabilities=CAP_SYSLOG`
//! and `CAP_DAC_READ_SEARCH`). When neither source is available we degrade to
//! the alerts the kmsg watcher already captured in shared state.

/// Try `dmesg -T` (human timestamps). Returns the raw lines, newest first.
pub fn read_dmesg() -> Option<Vec<String>> {
    let out = std::process::Command::new("dmesg")
        .arg("-T")
        .output()
        .ok()?;
    if !out.status.success() {
        return read_journal_k();
    }
    let text = String::from_utf8_lossy(&out.stdout);
    Some(lines_newest_first(&text))
}

/// systemd fallback: the journal also mirrors kernel messages.
fn read_journal_k() -> Option<Vec<String>> {
    let out = std::process::Command::new("journalctl")
        .args(["-k", "-n", "400", "--no-pager"])
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8_lossy(&out.stdout);
    Some(lines_newest_first(&text))
}

fn lines_newest_first(text: &str) -> Vec<String> {
    let mut lines: Vec<String> = text.lines().map(|s| s.to_string()).collect();
    lines.reverse();
    lines
}

/// Word patterns that usually mean "the machine noticed something".
pub fn is_notable(line: &str) -> bool {
    let l = line.to_lowercase();
    [
        "oom", "out of memory", "panic", " oops", "bug:", "segfault", "sigsegv",
        "general protection fault", "unable to handle", "kasan", "use-after-free",
        "hung_task", "blocked for more than", "watchdog", "soft lockup", "hard lockup",
        "call trace", "rip:", "gpf", "warning:", "firmware", "thermal", "temperature",
        "critical", "error", "failed", "timeout", "disconnect", "not regist",
        "i2c error", "usb", "nvrm", "nouveau", "amdgpu", "i915", "nvidia", "gpu",
        "coredump", "core dumped", "killed process", "sigill", "sigbus",
        "out of memory", "low memory", "memory corruption", "tpm", "ucsi",
        "dropped", "invalid", "corrupt", "exception", "fault", "abort",
        "unknown", "bad", "tapping", "iommu", "reset", "overheat",
    ]
    .iter()
    .any(|pat| l.contains(pat))
}

/// Filter raw lines down to the notable ones, newest first, capped.
pub fn notable_lines(all: &[String], max: usize) -> Vec<String> {
    all.iter().filter(|l| is_notable(l)).take(max).cloned().collect()
}