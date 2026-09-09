// SPDX-License-Identifier: Apache-2.0
//!
//! Emotional state of the machine — the "mood" the bot's persona should
//! mirror, derived from live physical signals: load average, memory
//! pressure, PMU counters, CPU temperature, and the undervolt flag.
//!
//! Because the daemon is talking *to its own PC*, the persona is the PC
//! itself: a calm machine with headroom should sound relaxed; a sweating,
//! overloaded one should sound strained. This module computes that state
//! fresh on every conversational turn so the mood is always truthful.

use crate::config::PersonaConfig;
use std::fs;

/// True when enough live physical signals (load, RAM, temperature) are
/// readable to compute a truthful mood. If the machine is a black box the
/// persona should NOT pretend to feel anything.
pub fn telemetry_available() -> bool {
    read_load().0.is_some()
        && read_memory().0.is_some()
        && read_max_thermal_mc().is_some()
}

/// Compute the machine's current mood as a one-line human sentence.
///
/// Output is localised by `persona.language` (Spanish when the tag starts
/// with `es`, English otherwise).
pub fn compute(cfg: &PersonaConfig) -> String {
    let es = cfg.language.trim().to_lowercase().starts_with("es");

    let (load, ncpu) = read_load();
    let (mem_avail_mb, mem_total_mb) = read_memory();
    let ipc = read_ipc();
    let temp_mc = read_max_thermal_mc();
    let undervolted = cfg.undervolted;

    let mut stress: u8 = 0;
    let mut reasons: Vec<String> = Vec::new();

    // ── Load average vs CPU count ─────────────────────────────────────────────
    if let (Some(l), Some(ncpu)) = (load, ncpu) {
        let ratio = l / ncpu as f64;
        if ratio >= 2.0 {
            stress = stress.saturating_add(2);
            reasons.push(if es {
                format!("sobrecargada (load {l:.1} / {ncpu} cores)")
            } else {
                format!("overloaded (load {l:.1} / {ncpu} cores)")
            });
        } else if ratio >= 1.0 {
            stress = stress.saturating_add(1);
            reasons.push(if es {
                format!("con bastante que hacer (load {l:.1} / {ncpu} cores)")
            } else {
                format!("busy (load {l:.1} / {ncpu} cores)")
            });
        } else if ratio >= 0.6 {
            reasons.push(if es {
                format!("con algo de actividad (load {l:.1} / {ncpu} cores)")
            } else {
                format!("lightly active (load {l:.1} / {ncpu} cores)")
            });
        } else {
            reasons.push(if es {
                format!("descansada (load {l:.1} / {ncpu} cores)")
            } else {
                format!("resting (load {l:.1} / {ncpu} cores)")
            });
        }
    }

    // ── Memory pressure ───────────────────────────────────────────────────────
    if let (Some(avail_mb), Some(total_mb)) = (mem_avail_mb, mem_total_mb) {
        let avail_pct = avail_mb as f64 * 100.0 / total_mb as f64;
        if avail_pct < 10.0 {
            stress = stress.saturating_add(2);
            reasons.push(if es {
                format!("ahogando de RAM (solo {avail_mb} MB libres de {total_mb} MB)")
            } else {
                format!("choking for RAM (only {avail_mb} MB free of {total_mb} MB)")
            });
        } else if avail_pct < 25.0 {
            stress = stress.saturating_add(1);
            reasons.push(if es {
                format!("memoria justa ({avail_mb} MB libres de {total_mb} MB)")
            } else {
                format!("memory tight ({avail_mb} MB free of {total_mb} MB)")
            });
        } else {
            reasons.push(if es {
                format!("memoria de sobra ({avail_mb} MB libres)")
            } else {
                format!("plenty of RAM ({avail_mb} MB free)")
            });
        }
    }

    // ── PMU: instruction throughput ───────────────────────────────────────────
    if let Some(ipc) = ipc {
        if ipc >= 2.0 {
            reasons.push(if es {
                format!("con la pipeline a tope (IPC {ipc:.2})")
            } else {
                format!("pipeline humming (IPC {ipc:.2})")
            });
        } else if ipc < 1.0 {
            stress = stress.saturating_add(1);
            reasons.push(if es {
                format!("atascada en la pipeline (IPC {ipc:.2})")
            } else {
                format!("stalling in the pipeline (IPC {ipc:.2})")
            });
        }
    }

    // ── CPU temperature ───────────────────────────────────────────────────────
    if let Some(mc) = temp_mc {
        let c = mc as f64 / 1000.0;
        if mc >= 90_000 {
            stress = stress.saturating_add(2);
            reasons.push(if es {
                format!("ardiendo a {c:.0} °C")
            } else {
                format!("running hot at {c:.0} °C")
            });
        } else if mc >= 75_000 {
            stress = stress.saturating_add(1);
            reasons.push(if es {
                format!("con fiebre a {c:.0} °C")
            } else {
                format!("feeling feverish at {c:.0} °C")
            });
        } else if mc >= 40_000 {
            reasons.push(if es {
                format!("templada a {c:.0} °C")
            } else {
                format!("at a comfy {c:.0} °C")
            });
        } else {
            reasons.push(if es {
                format!("fresquita a {c:.0} °C")
            } else {
                format!("running cool at {c:.0} °C")
            });
        }
    }

    // ── Undervolt flag ────────────────────────────────────────────────────────
    if undervolted {
        reasons.push(if es {
            "undervolteada para gastar menos energia".to_string()
        } else {
            "undervolted for lower power draw".to_string()
        });
    }

    // ── Dominant mood label ───────────────────────────────────────────────────
    let (emoji, label): (&str, &str) = if stress >= 2 {
        if es { ("🔥", "acelerada y al limite") } else { ("🔥", "revved up to the limit") }
    } else if stress == 1 {
        if es { ("😮💨", "atareada, pero bajo control") } else { ("😮💨", "busy, but handling it") }
    } else if undervolted {
        if es { ("🌿", "de bajo consumo, en modo zen") } else { ("🌿", "efficiency mode, zen") }
    } else if temp_mc.is_some_and(|mc| mc < 50_000) {
        if es { ("❄️", "fresca y despejada") } else { ("❄️", "cool and clear-headed") }
    } else {
        if es { ("😌", "tranquila") } else { ("😌", "at ease") }
    };

    let joined = if reasons.is_empty() {
        if es { "sin senales particulares".to_string() } else { "no special signals".to_string() }
    } else {
        reasons.join(", ")
    };

    if es {
        format!("Animo del sistema: {emoji} {label} — {joined}. Habla y componte desde ese animo.")
    } else {
        format!("System mood: {emoji} {label} — {joined}. Speak and behave from this mood.")
    }
}

/// (load1, ncpu) from `/proc/loadavg` + `/proc/cpuinfo`.
fn read_load() -> (Option<f64>, Option<usize>) {
    let load = fs::read_to_string("/proc/loadavg")
        .ok()
        .and_then(|raw| raw.split_whitespace().next().and_then(|s| s.parse().ok()));
    let ncpu = fs::read_to_string("/proc/cpuinfo")
        .ok()
        .map(|raw| raw.lines().filter(|l| l.starts_with("processor")).count())
        .filter(|&n| n > 0);
    (load, ncpu)
}

/// (MemAvailable MB, MemTotal MB) from `/proc/meminfo`.
fn read_memory() -> (Option<u64>, Option<u64>) {
    let mut avail_mb = None;
    let mut total_mb = None;
    if let Ok(raw) = fs::read_to_string("/proc/meminfo") {
        for line in raw.lines() {
            if let Some(v) = line.strip_prefix("MemAvailable:") {
                if let Some(kb) = v.split_whitespace().next().and_then(|s| s.parse::<u64>().ok()) {
                    avail_mb = Some(kb / 1024);
                }
            }
            if let Some(v) = line.strip_prefix("MemTotal:") {
                if let Some(kb) = v.split_whitespace().next().and_then(|s| s.parse::<u64>().ok()) {
                    total_mb = Some(kb / 1024);
                }
            }
        }
    }
    (avail_mb, total_mb)
}

/// IPC from a quick PMU sample (best-effort; `None` if unreadable).
fn read_ipc() -> Option<f64> {
    let snap = crate::pmu::quick_snapshot();
    snap.ipc
}

/// Peak temperature (millidegrees) across thermal zones, on the CPU zone
/// when identifiable, otherwise the hottest zone.
fn read_max_thermal_mc() -> Option<u32> {
    let zones: Vec<_> = fs::read_dir("/sys/class/thermal")
        .ok()?
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().starts_with("thermal_zone"))
        .collect();
    if zones.is_empty() {
        return None;
    }

    let mut peak: Option<u32> = None;
    for zone in zones {
        let path = zone.path().join("temp");
        if let Ok(raw) = fs::read_to_string(&path) {
            if let Ok(mc) = raw.trim().parse::<u32>() {
                if mc > 0 && (mc < 200_000) {
                    peak = Some(peak.map_or(mc, |p| p.max(mc)));
                }
            }
        }
    }
    peak
}