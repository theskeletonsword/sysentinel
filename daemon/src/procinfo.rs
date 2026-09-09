// SPDX-License-Identifier: Apache-2.0
//!
//! Live process table (htop-style) and TSC/`rdtscp` probing.
//!
//! Everything here reads `/proc` plus the TSC timestamp counter used by the
//! kernel. Nothing requires root.

use anyhow::Result;
use std::collections::HashMap;
use std::fs;
use std::time::{Duration, Instant};

/// One process row for the htop-style report.
#[derive(Debug, Clone)]
pub struct ProcRow {
    pub pid: i32,
    pub comm: String,
    /// CPU usage over the sampling window, 0..100 per core (may exceed 100).
    pub cpu_pct: f32,
    /// Resident set size in MiB.
    pub rss_mb: f32,
}

/// Read /proc/stat (idle+u+s+n totals) plus every /proc/<pid>/stat
/// (utime+stime ticks, rss pages). Returns (total_cpu_ticks, rows).
fn read_proc_stat() -> Result<(i64, Vec<(i32, i64, usize)>)> {
    let stat = fs::read_to_string("/proc/stat")?;
    let first = stat.lines().next().unwrap_or_default();
    let fields: Vec<&str> = first.split_whitespace().collect();
    if fields.len() < 5 || fields[0] != "cpu" {
        return Err(anyhow::anyhow!("unexpected /proc/stat cpu line"));
    }
    let user: i64 = fields[1].parse()?;
    let nice: i64 = fields[2].parse()?;
    let system: i64 = fields[3].parse()?;
    let idle: i64 = fields[4].parse()?;
    let total = user + nice + system + idle;

    let mut procs = Vec::new();
    for entry in fs::read_dir("/proc")? {
        let pid: i32 = match entry?.file_name().to_string_lossy().parse() {
            Ok(pid) => pid,
            Err(_) => continue,
        };
        let path = format!("/proc/{pid}/stat");
        let Ok(raw) = fs::read_to_string(&path) else { continue };
        trace_stats(&raw, pid, &mut procs);
    }
    Ok((total, procs))
}

/// Parse a single /proc/<pid>/stat line: utime (14), stime (15), rss (24).
/// The comm inside the parentheses may itself contain `)`, so we locate the
/// *last* closing paren instead of naive splitting.
fn trace_stats(raw: &str, pid: i32, out: &mut Vec<(i32, i64, usize)>) {
    let Some(end) = raw.rfind(')') else { return };
    let Some(rest) = raw.get(end + 1..) else { return };

    let v: Vec<&str> = rest.trim_start().split_whitespace().collect();
    // After ")" the first field is field 3 (state); utime is field 14 → index
    // 14-3 = 11, stime → 12, rss is field 24 → 21.
    if v.len() <= 21 {
        return;
    }
    let utime: i64 = match v[11].parse() { Ok(x) => x, Err(_) => return };
    let stime: i64 = match v[12].parse() { Ok(x) => x, Err(_) => return };
    let rss_pages: usize = match v[21].parse() { Ok(x) => x, Err(_) => return };
    out.push((pid, utime + stime, rss_pages));
}

/// Sample the process table twice `sleep_ms` apart and return the top-N by
/// CPU%, with resident memory. This is the htop-style view used by the
/// watcher and the `/status` command; called off the hot path.
pub fn top_processes(n: usize, sleep_ms: u64) -> Vec<ProcRow> {
    let (total0, p0) = match read_proc_stat() {
        Ok(x) => x,
        Err(_) => return Vec::new(),
    };
    let wake = Instant::now() + Duration::from_millis(sleep_ms);
    loop {
        let now = Instant::now();
        if now >= wake {
            break;
        }
        std::thread::sleep(wake.saturating_duration_since(now));
    }
    let (total1, p1) = match read_proc_stat() {
        Ok(x) => x,
        Err(_) => return Vec::new(),
    };

    let dt = (total1 - total0).max(1) as f32;
    let first: HashMap<i32, i64> = p0.into_iter().map(|(pid, t, _)| (pid, t)).collect();

    let mut rows: Vec<ProcRow> = Vec::new();
    for (pid, ticks, rss_pages) in p1 {
        let Some(prev) = first.get(&pid) else { continue };
        let d = (ticks - prev).max(0) as f32;
        if d <= 0.0 {
            continue;
        }
        let comm = fs::read_to_string(format!("/proc/{pid}/comm"))
            .unwrap_or_default()
            .trim_end()
            .to_string();
        rows.push(ProcRow {
            pid,
            comm,
            cpu_pct: d / dt * 100.0,
            rss_mb: rss_pages as f32 * 4096.0 / (1024.0 * 1024.0),
        });
    }

    rows.sort_by(|a, b| b.cpu_pct.total_cmp(&a.cpu_pct));
    rows.truncate(n);
    rows
}

/// `rdtscp`/TSC sanity probe, powering the `tsc` notification category.
///
/// We sleep through two windows reading `__rdtscp` and compare the TSC deltas
/// against `CLOCK_MONOTONIC`. If /sys exposes the nominal TSC frequency we
/// validate the measured one; divergence beyond the tolerance flags
/// instability (common under VMs, aggressive cpufreq, or buggy firmware).
pub struct TscStatus {
    /// Nominal kHz from `/sys/devices/system/cpu/cpu0/tsc_freq_khz` (0 if unavailable).
    pub nominal_khz: u64,
    /// Measured kHz over the probe window.
    pub measured_khz: f64,
    /// True when the measured frequency matches the nominal within 2%,
    /// or (with no nominal reference) falls in a sane 1–4 GHz range.
    pub stable: bool,
}

pub fn tsc_status() -> TscStatus {
    let nominal_khz = read_tsc_khz();

    let t0 = Instant::now();
    let ts0 = read_tsc();
    std::thread::sleep(Duration::from_millis(100));
    let ts1 = read_tsc();
    let wall = t0.elapsed().as_secs_f64();

    let ticks = ts1 - ts0;
    let measured_khz = if ticks > 0.0 && wall > 0.0 {
        ticks / wall / 1000.0
    } else {
        0.0
    };

    let stable = if nominal_khz > 0 {
        let drift = (measured_khz - nominal_khz as f64) / nominal_khz as f64;
        drift.abs() <= 0.02
    } else {
        (1.0e6..4.0e6).contains(&measured_khz)
    };

    TscStatus { nominal_khz, measured_khz, stable }
}

/// Read the current TSC value via `rdtscp` (no sleeps).
#[inline(never)]
fn read_tsc() -> f64 {
    #[cfg(target_arch = "x86_64")]
    {
        let mut aux: u32 = 0;
        (unsafe { std::arch::x86_64::__rdtscp(&mut aux) }) as f64
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos() as f64)
            .unwrap_or(0.0)
    }
}

fn read_tsc_khz() -> u64 {
    fs::read_to_string("/sys/devices/system/cpu/cpu0/tsc_freq_khz")
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_stat_line_with_parens_in_comm() {
        // comm "(TmplWorker)" ends with `)`, forcing the rfind() path.
        let raw = "1234 (TmplWorker) S 1 1 1 0 -1 4194560 4096 0 1000 0 \
                   750 640 2 0 20 0 1 0 998 2359296 2042 18446744073709551615 \
                   1 1 0 0 0 0 0 0 0 9000 0 0 0 17 0 0 0 0 0 0";
        let mut out = Vec::new();
        trace_stats(raw, 1234, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].0, 1234);
        assert_eq!(out[0].1, 750 + 640);
        assert_eq!(out[0].2, 2042);
    }

    #[test]
    fn proc_stat_reads_current_system() {
        let (total, procs) = read_proc_stat().expect("proc stat readable");
        assert!(total > 0);
        assert!(!procs.is_empty());
    }

    #[test]
    fn tsc_status_runs_on_this_machine() {
        let s = tsc_status();
        assert!(s.measured_khz > 0.0);
    }
}