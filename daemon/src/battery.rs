// SPDX-License-Identifier: Apache-2.0
//!
//! Battery truth — read `/sys/class/power_supply` and tell the user whether
//! this machine runs on battery (notebook/laptop) or not (desktop tower /
//! "pc de mesa"). On a desktop there is **no battery** and nothing to report:
//! the bot must say "no aplica".
//!
//! The daemon watches the battery on notebooks and pushes an alert
//! as it drains: low (≤20%), critical (≤10%), drained/agotada (≤5%).

use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::llm;

/// Snapshot of the primary battery.
#[derive(Debug, Clone)]
pub struct Battery {
    /// power_supply name, e.g. "BAT0".
    pub name: String,
    /// Charge level 0-100 (`capacity` file).
    pub percent: Option<i32>,
    /// Raw status string: Charging / Discharging / Full / Not charging.
    pub status: Option<String>,
    /// Remaining energy, µWh (`energy_now`), when exposed.
    pub energy_now: Option<u64>,
    /// Full capacity, µWh (`energy_full`), when exposed.
    pub energy_full: Option<u64>,
    /// Current draw, µW (`power_now`), when exposed.
    pub power_now: Option<u64>,
}

impl Battery {
    pub fn is_discharging(&self) -> bool {
        self.status.as_deref() == Some("Discharging")
    }

    /// Estimated seconds left until drained (discharging only).
    pub fn seconds_left(&self) -> Option<u64> {
        if !self.is_discharging() {
            return None;
        }
        if let (Some(e), Some(p)) = (self.energy_now, self.power_now) {
            if e > 0 && p > 0 {
                return Some(e * 3600 / p);
            }
        }
        None
    }

    pub fn minutes_left_label(&self) -> String {
        match self.seconds_left() {
            Some(s) if s >= 3600 => {
                format!("~{}h {}m", s / 3600, (s % 3600) / 60)
            }
            Some(s) => format!("~{}m", s.max(60) / 60),
            None => "?".to_string(),
        }
    }
}

/// Is there a battery at all? If yes ⇒ notebook/laptop; if no ⇒ desktop tower
/// ("torre / pc de mesa") and battery alerts "no aplican".
pub fn has_battery() -> bool {
    find_power_supplies().iter().any(|d| battery_in_dir(d))
}

/// The battery most worth reporting. Multiple batteries: the most drained one
/// determines the real remaining time, so pick the lowest percentage.
pub fn primary_battery() -> Option<Battery> {
    let dirs = find_power_supplies();
    let mut bats: Vec<Battery> = dirs
        .iter()
        .filter(|d| battery_in_dir(d))
        .filter_map(|d| read_battery_from_dir(d))
        .collect();
    bats.sort_by_key(|b| b.percent.unwrap_or(101));
    bats.into_iter().next()
}

/// /battery command answer in the persona's language.
pub fn describe() -> String {
    match primary_battery() {
        Some(b) => {
            let pct = b.percent.map(|p| format!("{p}%")).unwrap_or_else(|| "?%".into());
            let st = b
                .status
                .as_deref()
                .map(translate_status)
                .unwrap_or_else(|| "unknown");
            let full = b
                .energy_full
                .map(|wh| format!(" of {:.1} Wh", wh as f64 / 1_000_000.0))
                .unwrap_or_default();
            let time = if b.is_discharging() {
                format!(", {} left", b.minutes_left_label())
            } else {
                String::new()
            };
            format!("🔋 Battery `{}`: **{pct}** ({st}{time}){full}", b.name)
        }
        None => "🚫 No battery on this machine — it's a desktop tower, so the \
                battery topic **does not apply**."
            .to_string(),
    }
}

// ── Watcher ────────────────────────────────────────────────────────────────────

/// Notification bands, lowest first (most urgent crossed last on the way down).
const BANDS: [i32; 3] = [5, 10, 20];
/// Above this percent an alert band is disarmed again (allows re-arming after
/// a partial recharge without re-alerting constant recharges).
const REARM_PCT: i32 = 25;

/// Edge-triggered battery watcher. Only meaningful on notebooks: when no
/// `power_supply` of type Battery exists (desktop tower / "pc de mesa") this
/// loop stays silent — battery alerts "no aplican".
pub fn run_battery_loop(
    config: &crate::config::Config,
    // Unused since alerts go through `channel`, which resolves its own
    // destination; kept so every watcher keeps the same signature.
    _state: &Arc<Mutex<crate::bot::SharedBotState>>,
    settings: &Arc<Mutex<crate::settings::Settings>>,
    llm: &dyn llm::LlmBackend,
    dry_run: bool,
) {
    if !has_battery() {
        log::info!("battery-watch: no power_supply Battery → desktop, battery alerts N/A");
        return;
    }
    log::info!("battery-watch: forwarding battery drain alerts on this notebook");

    let mut armed: i32 = 0; // no band armed yet
    loop {
        std::thread::sleep(Duration::from_secs(30));

        let on = settings.lock().expect("settings mutex").battery;
        if !on {
            armed = 0;
            continue;
        }

        let Some(b) = primary_battery() else {
            continue;
        };
        let Some(pct) = b.percent else {
            continue;
        };

        if b.status.as_deref() == Some("Charging") {
            armed = 0;
            continue;
        }
        if !b.is_discharging() {
            // Full / Not charging / Unknown: nothing draining right now.
            armed = 0;
            continue;
        }

        // Re-arm when it recovered above the rearm line.
        if pct > REARM_PCT {
            armed = 0;
            continue;
        }

        let band = BANDS.iter().copied().find(|&t| pct <= t);
        let Some(band) = band else {
            continue;
        };
        if band <= armed {
            continue; // already alerted for this (or a worse) band
        }
        armed = band;

        // No chat id to look up: the channel resolves its own destination, so
        // a watcher never has to know which transport is carrying this.
        if crate::channel::is_deaf() {
            continue;
        }

        let text = speak_battery_persona(config, settings, llm, &b, band);
        if dry_run {
            log::info!("battery-watch (dry): {text}");
            continue;
        }
        crate::channel::notify(&text);
    }
}

/// Passive drain alert → persona voice. Falls back to the canned line when
/// the LLM is off or errors (a low-battery ping must never block on the LLM).
fn speak_battery_persona(
    config: &crate::config::Config,
    settings: &Arc<Mutex<crate::settings::Settings>>,
    llm: &dyn llm::LlmBackend,
    b: &Battery,
    band: i32,
) -> String {
    if !config.llm.llm_enabled() {
        return battery_alert_text(b, band);
    }
    let persona = llm::resolved_persona(config);
    let override_txt = {
        let g = settings.lock().expect("settings mutex");
        g.system_prompt_override.clone()
    };
    let sys_prompt = llm::effective_system_prompt(config, override_txt.as_deref());
    let mut facts = format!(
        "The battery is draining: {}% left ({})",
        b.percent.unwrap_or(0),
        b.name
    );
    if b.is_discharging() {
        facts.push_str(&format!(", {} left", b.minutes_left_label()));
    }
    let directive = format!(
        "These are live facts / things that just happened on this machine. You ARE \
         the machine. The battery is running low — tell the user about it in YOUR \
         voice, spontaneously, short and clear, NEVER a formatted log line, NEVER\n\
         inventing anything beyond what's here.\n\
         IMPORTANT: this is a PASSIVE notice — urgent, but it needs no confirmation\n\
         and no drastic action from the user beyond plugging in.\n\
         language: {}\ntone: {}\n\
         Write in {}, with the persona above. Be brief (max 3 lines), no titles,\n\
         no preamble:\n\n{}",
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
        log::warn!("battery persona voice dropped ({e:#}); forwarding raw alert");
        battery_alert_text(b, band)
    })
}

fn battery_alert_text(b: &Battery, band: i32) -> String {
    let time = if b.is_discharging() {
        format!(" • {} left", b.minutes_left_label())
    } else {
        String::new()
    };
    match band {
        5 => format!(
            "⚡🏃💀 *BATTERY IS DYING* — {}% ({}){}. Plug in the charger NOW!",
            b.percent.unwrap_or(0),
            b.name,
            time,
        ),
        10 => format!("⚠️ *Critical battery* — {}% ({}){}.", b.percent.unwrap_or(0), b.name, time),
        _ => format!("🔋 *Low battery* — {}% ({}){}.", b.percent.unwrap_or(0), b.name, time),
    }
}

fn translate_status(s: &str) -> &'static str {
    match s {
        "Charging" => "charging",
        "Discharging" => "discharging",
        "Full" => "full (100%)",
        "Not charging" => "not charging",
        _ => "unknown",
    }
}

fn find_power_supplies() -> Vec<std::path::PathBuf> {
    let base = Path::new("/sys/class/power_supply");
    let Ok(rd) = std::fs::read_dir(base) else {
        return Vec::new();
    };
    rd.filter_map(|e| e.ok()).map(|e| e.path()).collect()
}

fn battery_in_dir(dir: &std::path::Path) -> bool {
    read_trim(dir.join("type")).as_deref() == Some("Battery")
}

fn read_battery_from_dir(dir: &std::path::Path) -> Option<Battery> {
    let name = dir.file_name()?.to_string_lossy().into_owned();
    Some(Battery {
        name,
        percent: read_u32(dir.join("capacity")).map(|v| v as i32),
        status: read_trim(dir.join("status")).filter(|s| !s.is_empty()),
        energy_now: read_u64(dir.join("energy_now")),
        energy_full: read_u64(dir.join("energy_full")),
        power_now: read_u64(dir.join("power_now")),
    })
}

fn read_trim(p: std::path::PathBuf) -> Option<String> {
    std::fs::read_to_string(p).ok().map(|s| s.trim().to_string())
}

fn read_u32(p: std::path::PathBuf) -> Option<u32> {
    read_trim(p)?.parse().ok()
}

fn read_u64(p: std::path::PathBuf) -> Option<u64> {
    read_trim(p)?.parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desktop_has_no_battery_to_report() {
        // On a battery-less CI box has_battery() must stay truthful.
        // (If a test runner ever has a battery, there's nothing to assert here.)
        if !crate::battery::has_battery() {
            assert!(primary_battery().is_none());
        }
    }

    #[test]
    fn minutes_label_from_energy_power() {
        let b = Battery {
            name: "BAT0".into(),
            percent: Some(50),
            status: Some("Discharging".into()),
            energy_now: Some(20_000_000), // 20 Wh
            energy_full: Some(40_000_000),
            power_now: Some(10_000_000), // 10 W → 2h
        };
        assert_eq!(b.seconds_left(), Some(2 * 3600));
        assert_eq!(b.minutes_left_label(), "~2h 0m");
        assert!(b.is_discharging());
    }

    #[test]
    fn no_time_when_charging() {
        let b = Battery {
            name: "BAT0".into(),
            percent: Some(80),
            status: Some("Charging".into()),
            energy_now: Some(30_000_000),
            energy_full: Some(40_000_000),
            power_now: Some(8_000_000),
        };
        assert!(b.seconds_left().is_none());
        assert!(!b.is_discharging());
    }

    #[test]
    fn translate_maps_status() {
        assert_eq!(translate_status("Discharging"), "discharging");
        assert_eq!(translate_status("Charging"), "charging");
        assert_eq!(translate_status("Weird"), "unknown");
    }
}