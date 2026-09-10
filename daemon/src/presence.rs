// SPDX-License-Identifier: Apache-2.0
//!
//! Who is at the machine, when the machine cannot see them.
//!
//! # The ladder
//!
//! Face recognition answers "who is there" only while a camera exists. Plenty
//! of machines have none: a desktop, a server, a laptop with the camera taped
//! over or disabled in firmware. The question does not go away, so the answer
//! degrades instead of disappearing:
//!
//! | Rung | Needs | Answers |
//! |------|-------|---------|
//! | [`EvidenceRung::Face`] | a capture-capable `/dev/video*` | *who* is there |
//! | [`EvidenceRung::Voice`] | an ALSA capture device | *who* is there, less certainly |
//! | [`EvidenceRung::Circumstantial`] | nothing | *what the situation looks like* |
//!
//! The rungs are not interchangeable and the report never pretends otherwise:
//! a frame of someone's face and "an unfamiliar keyboard was plugged in" are
//! different kinds of claim, and the alert says which one it is holding.
//!
//! # When there is no microphone either
//!
//! This is the question the ladder exists to answer, and the honest reply is
//! that you stop trying to identify the *person* and start describing the
//! *situation*. The machine can still observe a great deal about itself:
//!
//! - **Input hardware that appeared.** A USB keyboard on a laptop that has its
//!   own, or any new HID, is somebody bringing their own way in. This is the
//!   single most useful cameraless signal, because the interesting attacks need
//!   to type.
//! - **Storage that appeared.** Someone attaching a disk to an unattended
//!   machine is copying, not browsing.
//! - **Power and place.** Moved to another desk, unplugged, on a network it has
//!   never seen.
//! - **The hour.** An unlock at a time this machine is never used is not proof
//!   of anything, and is worth saying out loud anyway.
//!
//! None of that identifies anyone. It is not meant to: it is meant to give the
//! owner enough to recognise their own ordinary Tuesday and notice when it is
//! not one.
//!
//! # The rung below the bottom
//!
//! There is one more, and it is the only one that is not a heuristic: **ask the
//! owner.** The paired chat needs no sensor on the host at all, cannot be
//! forged by whoever is holding the machine, and already has an identity proof
//! behind it. Every rung above it is an optimisation that saves the owner from
//! being asked; when they all fail, the question simply goes to the person who
//! can actually answer it.
//!
//! That is why nothing here returns a verdict. It returns evidence.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

/// The best kind of evidence this host can collect about who is present.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum EvidenceRung {
    /// Nothing but the machine's own circumstances.
    Circumstantial,
    /// A microphone exists: a voice can be captured.
    Voice,
    /// A camera exists: a face can be captured.
    Face,
}

impl EvidenceRung {
    pub fn describe(&self) -> &'static str {
        match self {
            EvidenceRung::Face =>
                "cámara disponible — se puede identificar el rostro",
            EvidenceRung::Voice =>
                "sin cámara, pero hay micrófono — queda la voz",
            EvidenceRung::Circumstantial =>
                "sin cámara ni micrófono — solo circunstancias, no identidad",
        }
    }
}

/// What sensors this host actually has, and therefore which rung it is on.
#[derive(Debug, Clone, Default)]
pub struct SensorInventory {
    /// Capture-capable V4L2 nodes, with their names.
    pub cameras: Vec<String>,
    /// ALSA capture PCMs.
    pub microphones: Vec<String>,
}

impl SensorInventory {
    pub fn rung(&self) -> EvidenceRung {
        if !self.cameras.is_empty() {
            EvidenceRung::Face
        } else if !self.microphones.is_empty() {
            EvidenceRung::Voice
        } else {
            EvidenceRung::Circumstantial
        }
    }

    /// Read the sensor hardware from sysfs and devfs.
    pub fn detect() -> Self {
        let mut inv = SensorInventory::default();

        // A V4L2 node is not necessarily a camera: the same driver publishes
        // metadata and output nodes. Only capture devices can see anyone.
        if let Ok(entries) = fs::read_dir("/sys/class/video4linux") {
            for e in entries.flatten() {
                let dir = e.path();
                let node = e.file_name().to_string_lossy().into_owned();
                let name = fs::read_to_string(dir.join("name"))
                    .unwrap_or_default()
                    .trim()
                    .to_string();
                // `index` 0 plus a name is the usual shape of a capture node;
                // metadata nodes advertise themselves in the name.
                let lower = name.to_lowercase();
                if lower.contains("metadata") || lower.contains("output") {
                    continue;
                }
                if !Path::new(&format!("/dev/{node}")).exists() {
                    continue;
                }
                inv.cameras.push(if name.is_empty() {
                    format!("/dev/{node}")
                } else {
                    format!("/dev/{node} ({name})")
                });
            }
        }

        // ALSA capture PCMs end in 'c'; playback-only cards have none, which is
        // exactly the "speakers but no microphone" case.
        if let Ok(entries) = fs::read_dir("/dev/snd") {
            for e in entries.flatten() {
                let n = e.file_name().to_string_lossy().into_owned();
                if n.starts_with("pcmC") && n.ends_with('c') {
                    inv.microphones.push(format!("/dev/snd/{n}"));
                }
            }
        }

        inv.cameras.sort();
        inv.microphones.sort();
        inv
    }
}

/// A USB device, reduced to what identifies it across reboots.
fn usb_fingerprints() -> BTreeSet<String> {
    crate::hwinfo::usb_devices()
        .into_iter()
        .map(|d| fingerprint(&d.vendor, &d.product))
        .collect()
}

/// Fingerprints of the USB devices that present a keyboard interface.
///
/// HID class `03`, boot protocol `01` — the descriptor a keyboard shows so a
/// BIOS can use it before any driver loads. An attacker's own keyboard and a
/// keystroke-injection dongle both have to advertise it in order to work.
///
/// Returned as device fingerprints rather than a count, because a bare count is
/// useless: measured on this laptop, the *built-in* keyboard already presents
/// two such interfaces over internal USB. What matters is whether a keyboard
/// appeared that was not there before, which only a comparison against the
/// baseline can answer.
fn usb_keyboard_fingerprints() -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let Ok(entries) = fs::read_dir("/sys/bus/usb/devices") else {
        return out;
    };
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        // Only interface directories carry a class; "1-1:1.0" belongs to "1-1".
        let Some((parent, _)) = name.split_once(':') else {
            continue;
        };
        let dir = e.path();
        let class = fs::read_to_string(dir.join("bInterfaceClass")).unwrap_or_default();
        let proto = fs::read_to_string(dir.join("bInterfaceProtocol")).unwrap_or_default();
        if class.trim() != "03" || proto.trim() != "01" {
            continue;
        }
        // Fingerprint the owning device the same way the baseline does.
        let base = Path::new("/sys/bus/usb/devices").join(parent);
        let vendor = fs::read_to_string(base.join("idVendor")).unwrap_or_default().trim().to_string();
        let product = fs::read_to_string(base.join("product")).unwrap_or_default().trim().to_string();
        if vendor.is_empty() {
            continue;
        }
        out.insert(fingerprint(&vendor, &product));
    }
    out
}

/// One shape for a USB device, used by both the baseline and the keyboard scan
/// so the two sets can actually be intersected.
fn fingerprint(vendor: &str, product: &str) -> String {
    let product = if product.is_empty() { "?" } else { product };
    format!("{vendor}:{product}")
}

/// What the machine can say about its own situation without any sensor.
#[derive(Debug, Clone, Default)]
pub struct Circumstance {
    /// USB devices present now that were not in the saved baseline.
    pub new_usb: Vec<String>,
    /// USB devices in the baseline that are now gone.
    pub missing_usb: Vec<String>,
    /// Newly appeared devices that present a keyboard interface — someone
    /// brought their own way to type. Empty unless a baseline exists.
    pub new_keyboards: Vec<String>,
    /// Running on battery rather than mains.
    pub on_battery: Option<bool>,
    /// DMI chassis type, as a word where one is known.
    pub chassis: Option<String>,
    /// True when no baseline had been recorded yet, so `new_usb` is not a
    /// change — it is simply everything.
    pub baseline_missing: bool,
}

impl Circumstance {
    /// Observations worth putting in front of a person. Facts only: this rung
    /// cannot identify anyone and does not try.
    pub fn notes(&self) -> Vec<String> {
        let mut out = Vec::new();

        if self.baseline_missing {
            out.push(
                "sin línea base de USB todavía — se registra ahora; los avisos de \
                 'dispositivo nuevo' empiezan a partir del próximo arranque"
                    .to_string(),
            );
        } else if !self.new_usb.is_empty() {
            out.push(format!(
                "⚠️ {} dispositivo(s) USB nuevo(s) desde la última línea base: {}",
                self.new_usb.len(),
                self.new_usb.join(", ")
            ));
        }

        if !self.new_keyboards.is_empty() {
            out.push(format!(
                "⚠️ teclado(s) que no estaban antes: {} — alguien trajo su forma de escribir",
                self.new_keyboards.join(", ")
            ));
        }

        if !self.missing_usb.is_empty() {
            out.push(format!(
                "{} dispositivo(s) USB que ya no están: {}",
                self.missing_usb.len(),
                self.missing_usb.join(", ")
            ));
        }

        match self.on_battery {
            Some(true) => out.push("funcionando con batería — desconectada de la red".to_string()),
            Some(false) => out.push("conectada a la corriente".to_string()),
            None => {}
        }

        if let Some(c) = &self.chassis {
            out.push(format!("chasis: {c}"));
        }

        out
    }

    /// Collect the circumstances, comparing USB against `baseline_path`.
    pub fn observe(baseline_path: &Path) -> Self {
        let now = usb_fingerprints();
        let baseline = load_baseline(baseline_path);

        let (new_usb, missing_usb, baseline_missing) = match &baseline {
            Some(base) => (
                now.difference(base).cloned().collect(),
                base.difference(&now).cloned().collect(),
                false,
            ),
            None => (Vec::new(), Vec::new(), true),
        };

        let keyboards = usb_keyboard_fingerprints();
        let new_usb: Vec<String> = new_usb;
        let new_keyboards = new_usb
            .iter()
            .filter(|f| keyboards.contains(*f))
            .cloned()
            .collect();

        Circumstance {
            new_usb,
            missing_usb,
            new_keyboards,
            on_battery: on_battery(),
            chassis: chassis_label(),
            baseline_missing,
        }
    }
}

/// True on battery, false on mains, `None` when there is no power-supply class
/// (a desktop with no ACPI battery reports nothing).
fn on_battery() -> Option<bool> {
    let entries = fs::read_dir("/sys/class/power_supply").ok()?;
    for e in entries.flatten() {
        let dir = e.path();
        let kind = fs::read_to_string(dir.join("type")).unwrap_or_default();
        if kind.trim() != "Mains" {
            continue;
        }
        let online = fs::read_to_string(dir.join("online")).ok()?;
        return Some(online.trim() == "0");
    }
    None
}

/// DMI chassis type as a word. The numbers are the SMBIOS chassis-type
/// enumeration; only the shapes this daemon is likely to run on are named, and
/// anything else keeps its raw code rather than being guessed at.
fn chassis_label() -> Option<String> {
    let raw = fs::read_to_string("/sys/class/dmi/id/chassis_type").ok()?;
    let n: u32 = raw.trim().parse().ok()?;
    Some(
        match n {
            3 => "desktop".to_string(),
            4 => "low-profile desktop".to_string(),
            6 => "mini tower".to_string(),
            7 => "tower".to_string(),
            8 => "portable".to_string(),
            9 => "laptop".to_string(),
            10 => "notebook".to_string(),
            11 => "hand held".to_string(),
            13 => "all-in-one".to_string(),
            14 => "sub notebook".to_string(),
            23 => "rack mount".to_string(),
            30 => "tablet".to_string(),
            31 => "convertible".to_string(),
            32 => "detachable".to_string(),
            other => format!("chassis type {other}"),
        },
    )
}

// ── USB baseline ──────────────────────────────────────────────────────────────

fn load_baseline(path: &Path) -> Option<BTreeSet<String>> {
    let raw = fs::read_to_string(path).ok()?;
    serde_json::from_str::<BTreeSet<String>>(&raw).ok()
}

/// Record the current USB set as "normal". Called when the owner confirms the
/// machine is in a state they recognise — never automatically, or an attacker's
/// device would quietly become part of the baseline.
pub fn record_baseline(path: &Path) -> anyhow::Result<usize> {
    use std::os::unix::fs::PermissionsExt;
    let set = usb_fingerprints();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_string_pretty(&set)?)?;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    Ok(set.len())
}

/// Default location for the USB baseline, beside the other daemon state.
pub fn default_baseline_path(face_path: &str) -> PathBuf {
    Path::new(face_path)
        .parent()
        .unwrap_or(Path::new("/var/lib/sysentinel"))
        .join("usb-baseline.json")
}

// ── The whole picture ─────────────────────────────────────────────────────────

/// Everything this host can say about who is at it right now.
#[derive(Debug, Clone)]
pub struct PresenceEvidence {
    pub sensors: SensorInventory,
    pub circumstance: Circumstance,
}

impl PresenceEvidence {
    pub fn collect(baseline_path: &Path) -> Self {
        PresenceEvidence {
            sensors: SensorInventory::detect(),
            circumstance: Circumstance::observe(baseline_path),
        }
    }

    pub fn rung(&self) -> EvidenceRung {
        self.sensors.rung()
    }

    /// Report for the chat. Leads with what kind of evidence this is, because
    /// the difference between "I saw them" and "an unfamiliar keyboard appeared"
    /// is the whole point.
    pub fn render(&self) -> String {
        let mut out = String::from("Evidencia de presencia:\n");
        let _ = writeln!(out, "  Nivel: {}", self.rung().describe());

        if !self.sensors.cameras.is_empty() {
            let _ = writeln!(out, "  Cámaras: {}", self.sensors.cameras.join(", "));
        }
        if !self.sensors.microphones.is_empty() {
            let _ = writeln!(out, "  Micrófonos: {}", self.sensors.microphones.len());
        }

        let notes = self.circumstance.notes();
        if !notes.is_empty() {
            out.push_str("  Circunstancias:\n");
            for n in notes {
                let _ = writeln!(out, "    - {n}");
            }
        }

        if self.rung() == EvidenceRung::Circumstantial {
            out.push_str(
                "\n  Nada de lo anterior identifica a nadie: son circunstancias, no \
                 identidad.\n  Con este hardware la única respuesta fiable a \"¿eres tú?\" \
                 es esta conversación.\n",
            );
        }
        out
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_ladder_is_ordered_by_how_much_it_can_claim() {
        assert!(EvidenceRung::Face > EvidenceRung::Voice);
        assert!(EvidenceRung::Voice > EvidenceRung::Circumstantial);
    }

    #[test]
    fn rung_follows_the_hardware_that_exists() {
        let cam = SensorInventory {
            cameras: vec!["/dev/video0".into()],
            microphones: vec![],
        };
        assert_eq!(cam.rung(), EvidenceRung::Face);

        // Speakers but no capture PCM is the ordinary "no microphone" case.
        let mic_only = SensorInventory {
            cameras: vec![],
            microphones: vec!["/dev/snd/pcmC0D0c".into()],
        };
        assert_eq!(mic_only.rung(), EvidenceRung::Voice);

        let headless = SensorInventory::default();
        assert_eq!(headless.rung(), EvidenceRung::Circumstantial);

        // A camera outranks a microphone when both exist.
        let both = SensorInventory {
            cameras: vec!["/dev/video0".into()],
            microphones: vec!["/dev/snd/pcmC0D0c".into()],
        };
        assert_eq!(both.rung(), EvidenceRung::Face);
    }

    #[test]
    fn a_headless_host_says_it_cannot_identify_anyone() {
        let ev = PresenceEvidence {
            sensors: SensorInventory::default(),
            circumstance: Circumstance::default(),
        };
        let text = ev.render();
        assert!(text.contains("sin cámara ni micrófono"), "{text}");
        assert!(text.contains("identifica a nadie"), "{text}");
        // It must point at the rung that actually works.
        assert!(text.contains("esta conversación"), "{text}");
    }

    #[test]
    fn a_missing_baseline_is_not_reported_as_a_change() {
        // Everything being "new" on first run would cry wolf immediately.
        let c = Circumstance { baseline_missing: true, ..Default::default() };
        let notes = c.notes();
        assert!(notes.iter().any(|n| n.contains("línea base")), "{notes:?}");
        assert!(!notes.iter().any(|n| n.contains("nuevo(s)")), "{notes:?}");
    }

    #[test]
    fn a_new_usb_device_is_called_out() {
        let c = Circumstance {
            new_usb: vec!["1234:Rubber Ducky".into()],
            new_keyboards: vec!["1234:Rubber Ducky".into()],
            ..Default::default()
        };
        let notes = c.notes();
        assert!(notes.iter().any(|n| n.contains("Rubber Ducky")), "{notes:?}");
        assert!(notes.iter().any(|n| n.contains("teclado")), "{notes:?}");

        // A keyboard that was always there is NOT a finding: this laptop's own
        // built-in keyboard presents two boot-protocol HID interfaces.
        let steady = Circumstance::default();
        assert!(
            !steady.notes().iter().any(|n| n.contains("teclado")),
            "an unchanged keyboard must not raise anything"
        );
    }

    #[test]
    fn baseline_round_trips_and_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("sysentinel-presence-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let p = dir.join("usb-baseline.json");

        // Nothing recorded yet: the difference must be "unknown", not "all new".
        assert!(load_baseline(&p).is_none());
        let c = Circumstance::observe(&p);
        assert!(c.baseline_missing);
        assert!(c.new_usb.is_empty());

        let n = record_baseline(&p).unwrap();
        let mode = fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the baseline lists this machine's hardware");

        // Straight after recording, nothing is new.
        let c = Circumstance::observe(&p);
        assert!(!c.baseline_missing);
        assert!(c.new_usb.is_empty(), "just-recorded baseline reported changes: {:?}", c.new_usb);
        assert_eq!(load_baseline(&p).map(|s| s.len()), Some(n));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn baseline_path_sits_beside_the_other_state() {
        let p = default_baseline_path("/var/lib/sysentinel/faces.json");
        assert_eq!(p, Path::new("/var/lib/sysentinel/usb-baseline.json"));
        // A bare filename must not resolve to the filesystem root.
        let p = default_baseline_path("faces.json");
        assert!(p.to_string_lossy().ends_with("usb-baseline.json"));
    }

    #[test]
    fn this_machine_reports_something_coherent() {
        let dir = std::env::temp_dir().join(format!("sysentinel-presence-live-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let ev = PresenceEvidence::collect(&dir.join("baseline.json"));
        println!("{}", ev.render());
        // Whatever the hardware, the rung must match what was detected.
        match ev.rung() {
            EvidenceRung::Face => assert!(!ev.sensors.cameras.is_empty()),
            EvidenceRung::Voice => {
                assert!(ev.sensors.cameras.is_empty());
                assert!(!ev.sensors.microphones.is_empty());
            }
            EvidenceRung::Circumstantial => {
                assert!(ev.sensors.cameras.is_empty());
                assert!(ev.sensors.microphones.is_empty());
            }
        }
        let _ = fs::remove_dir_all(&dir);
    }
}
