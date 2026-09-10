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
        .map(|d| {
            let product = if d.product.is_empty() { "?".to_string() } else { d.product };
            format!("USB/{}:{}", d.vendor, product)
        })
        .collect()
}

// ── Input devices, on every bus ───────────────────────────────────────────────
//
// `BUS_*` identifiers from `linux/input.h`. That header carries
// `GPL-2.0 WITH Linux-syscall-note`, whose exception covers using kernel
// services through their normal interfaces — the same basis as the perf
// constants; see NOTICE. Only the transports a keyboard realistically arrives
// on are named, and an unrecognised bus keeps its number rather than a guess.
//
// There is deliberately no `BUS_I3C`: the header defines none. An I3C HID
// controller surfaces through the input layer as I2C or HOST, and the raw
// device still shows up in the I3C bus scan below, so nothing is lost by not
// inventing a constant for it.
const BUS_USB: u16 = 0x03;
const BUS_BLUETOOTH: u16 = 0x05;
const BUS_I8042: u16 = 0x11;
const BUS_ISA: u16 = 0x10;
const BUS_RS232: u16 = 0x13;
const BUS_I2C: u16 = 0x18;
const BUS_HOST: u16 = 0x19;
const BUS_SPI: u16 = 0x1c;

fn bus_name(bus: u16) -> String {
    match bus {
        BUS_USB => "USB".to_string(),
        BUS_BLUETOOTH => "Bluetooth".to_string(),
        // The one a built-in laptop keyboard usually is, and QEMU's default.
        BUS_I8042 => "PS/2 (i8042)".to_string(),
        BUS_ISA => "ISA".to_string(),
        BUS_RS232 => "serial".to_string(),
        BUS_I2C => "I2C".to_string(),
        BUS_HOST => "host/platform".to_string(),
        BUS_SPI => "SPI".to_string(),
        other => format!("bus {other:#06x}"),
    }
}

/// One entry from `/proc/bus/input/devices`.
///
/// That file is the right source precisely because it is transport-agnostic:
/// PS/2, USB, I2C, Bluetooth and virtio keyboards all appear in it the same
/// way. Scanning USB sysfs, as this module first did, misses the keyboard on
/// most laptops and every default QEMU guest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InputDevice {
    pub name: String,
    pub bus: u16,
    pub vendor: String,
    pub product: String,
    /// True when the kernel gave it a `kbd` handler.
    pub has_kbd_handler: bool,
    /// How many distinct keys it can emit, counted from the `B: KEY=` bitmap.
    pub key_count: u32,
}

/// Keys a device must be able to emit before it counts as something a person
/// could type on.
///
/// The `kbd` handler alone is far too broad: measured on this laptop, the power
/// button, the video-bus hotkeys and even the PC speaker all carry it, because
/// they emit key events. Counting the `KEY=` bitmap separates them cleanly —
/// real keyboards here report 70, 72 and 170 keys, while the power button
/// reports 2, a touchpad 7, the video bus 8 and the vendor hotkey block 21.
/// Anything in that lower group is a button, not a way in.
const MIN_TYPING_KEYS: u32 = 32;

impl InputDevice {
    /// True when this device could actually be typed on — see
    /// [`MIN_TYPING_KEYS`] for why the `kbd` handler is not enough.
    pub fn is_keyboard(&self) -> bool {
        self.has_kbd_handler && self.key_count >= MIN_TYPING_KEYS
    }

    /// Stable identity across reboots: bus, ids and name. Deliberately not the
    /// event node number, which shuffles.
    pub fn fingerprint(&self) -> String {
        format!(
            "{}/{}:{} {}",
            bus_name(self.bus),
            self.vendor,
            self.product,
            self.name
        )
    }
}

/// Parse `/proc/bus/input/devices`. Empty on a kernel without it.
pub fn input_devices() -> Vec<InputDevice> {
    let Ok(raw) = fs::read_to_string("/proc/bus/input/devices") else {
        return Vec::new();
    };
    parse_input_devices(&raw)
}

/// Split out so the parser can be tested against captured fixtures — including
/// the QEMU and PS/2 shapes this host cannot produce.
fn parse_input_devices(raw: &str) -> Vec<InputDevice> {
    let mut out = Vec::new();
    let mut cur: Option<InputDevice> = None;

    for line in raw.lines() {
        let line = line.trim_end();
        if line.is_empty() {
            if let Some(d) = cur.take() {
                out.push(d);
            }
            continue;
        }
        let Some((tag, rest)) = line.split_once(": ") else { continue };
        match tag {
            "I" => {
                // "Bus=0011 Vendor=0001 Product=0001 Version=ab83"
                let mut dev = InputDevice {
                    name: String::new(),
                    bus: 0,
                    vendor: String::new(),
                    product: String::new(),
                    has_kbd_handler: false,
                    key_count: 0,
                };
                for field in rest.split_whitespace() {
                    match field.split_once('=') {
                        Some(("Bus", v)) => dev.bus = u16::from_str_radix(v, 16).unwrap_or(0),
                        Some(("Vendor", v)) => dev.vendor = v.to_string(),
                        Some(("Product", v)) => dev.product = v.to_string(),
                        _ => {}
                    }
                }
                if let Some(prev) = cur.replace(dev) {
                    out.push(prev);
                }
            }
            "N" => {
                if let Some(d) = cur.as_mut() {
                    d.name = rest
                        .trim_start_matches("Name=")
                        .trim_matches('"')
                        .to_string();
                }
            }
            "H" => {
                if let Some(d) = cur.as_mut() {
                    // "Handlers=sysrq kbd event3 leds"
                    d.has_kbd_handler = rest
                        .trim_start_matches("Handlers=")
                        .split_whitespace()
                        .any(|h| h == "kbd");
                }
            }
            "B" => {
                if let Some(d) = cur.as_mut() {
                    if let Some(bitmap) = rest.strip_prefix("KEY=") {
                        d.key_count = bitmap
                            .split_whitespace()
                            .filter_map(|w| u64::from_str_radix(w, 16).ok())
                            .map(|w| w.count_ones())
                            .sum();
                    }
                }
            }
            _ => {}
        }
    }
    if let Some(d) = cur.take() {
        out.push(d);
    }
    out
}

/// Fingerprints of every input device, whatever bus it arrived on.
fn input_fingerprints() -> BTreeSet<String> {
    input_devices().iter().map(|d| d.fingerprint()).collect()
}

/// Fingerprints of the input devices that can type.
fn keyboard_fingerprints() -> BTreeSet<String> {
    input_devices()
        .iter()
        .filter(|d| d.is_keyboard())
        .map(|d| d.fingerprint())
        .collect()
}

/// Storage that has appeared. A disk attached to an unattended machine is not
/// somebody looking around — it is somebody copying.
fn storage_fingerprints() -> BTreeSet<String> {
    crate::hwinfo::block_devices()
        .into_iter()
        // Virtual devices churn on their own and would drown the signal.
        .filter(|b| !matches!(b.kind, "zram" | "loop" | "md"))
        .map(|b| format!("{} {} {}GB", b.name, b.kind, b.bytes / 1_000_000_000))
        .collect()
}

/// Describe a newly attached disk by what is actually on it. "A disk was
/// attached" is a weak alert; "a LUKS container was attached" is not.
///
/// Requires privilege to read the device head, so it degrades to the bare
/// fingerprint rather than failing.
fn describe_storage(fingerprint: &str) -> String {
    let Some(name) = fingerprint.split_whitespace().next() else {
        return fingerprint.to_string();
    };
    match crate::fsprobe::probe_block(name) {
        Some(kind) => {
            let mut s = format!("{fingerprint} — {}", kind.label());
            if let Some(note) = kind.note() {
                s.push_str(&format!(" ({note})"));
            }
            // The two facts that change what attaching it means.
            if kind.is_encrypted() {
                s.push_str(" [cerrado: no se puede saber qué lleva dentro]");
            } else if kind.is_mountable_filesystem() {
                s.push_str(" [montable ya mismo: se puede copiar a él sin más]");
            }
            s
        }
        None => fingerprint.to_string(),
    }
}

/// USB devices exposing a still-image / MTP interface — a phone or camera in
/// file-transfer mode.
///
/// These never appear as block devices, so the storage scan cannot see them: an
/// Android phone in MTP mode is a USB device that speaks a file protocol, not a
/// disk the kernel exposes. Missing that would leave the most convenient way to
/// walk data out of a room entirely unwatched.
///
/// USB interface class `06` is Still Image Capture, which is what PTP and MTP
/// both present (USB-IF class codes; MTP is PTP with extensions).
fn mtp_fingerprints() -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    let Ok(entries) = fs::read_dir("/sys/bus/usb/devices") else {
        return out;
    };
    for e in entries.flatten() {
        let name = e.file_name().to_string_lossy().into_owned();
        let Some((parent, _)) = name.split_once(':') else { continue };
        if fs::read_to_string(e.path().join("bInterfaceClass"))
            .unwrap_or_default()
            .trim()
            != "06"
        {
            continue;
        }
        let base = Path::new("/sys/bus/usb/devices").join(parent);
        let vendor = fs::read_to_string(base.join("idVendor")).unwrap_or_default().trim().to_string();
        let product = fs::read_to_string(base.join("product")).unwrap_or_default().trim().to_string();
        if vendor.is_empty() {
            continue;
        }
        let product = if product.is_empty() { "?".to_string() } else { product };
        out.insert(format!("USB/{vendor}:{product}"));
    }
    out
}

/// Raw I3C devices. The input layer has no I3C bus id, so an I3C peripheral is
/// tracked here by its own bus rather than being missed entirely.
fn i3c_fingerprints() -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    if let Ok(entries) = fs::read_dir("/sys/bus/i3c/devices") {
        for e in entries.flatten() {
            out.insert(format!("i3c/{}", e.file_name().to_string_lossy()));
        }
    }
    out
}

/// Everything worth watching for appearance, across every transport.
fn all_fingerprints() -> BTreeSet<String> {
    let mut set = input_fingerprints();
    set.extend(usb_fingerprints());
    set.extend(storage_fingerprints());
    set.extend(i3c_fingerprints());
    set
}

/// What the machine can say about its own situation without any sensor.
#[derive(Debug, Clone, Default)]
pub struct Circumstance {
    /// Devices present now that were not in the saved baseline — any bus.
    pub new_devices: Vec<String>,
    /// Devices in the baseline that are now gone.
    pub missing_devices: Vec<String>,
    /// Newly appeared devices that can type, on whatever bus they arrived —
    /// USB, PS/2, I2C, Bluetooth. Someone brought their own way in.
    pub new_keyboards: Vec<String>,
    /// Newly appeared storage. Somebody is copying, not browsing.
    pub new_storage: Vec<String>,
    /// Newly appeared phones or cameras in file-transfer mode. Not disks, and
    /// just as good for carrying data out.
    pub new_mtp: Vec<String>,
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
                "sin línea base de dispositivos todavía — se registra ahora; los avisos de \
                 'dispositivo nuevo' empiezan a partir del próximo arranque"
                    .to_string(),
            );
        } else if !self.new_devices.is_empty() {
            out.push(format!(
                "⚠️ {} dispositivo(s) nuevo(s) desde la última línea base: {}",
                self.new_devices.len(),
                self.new_devices.join(", ")
            ));
        }

        if !self.new_keyboards.is_empty() {
            out.push(format!(
                "⚠️ teclado(s) que no estaban antes: {} — alguien trajo su forma de escribir",
                self.new_keyboards.join(", ")
            ));
        }

        if !self.new_mtp.is_empty() {
            out.push(format!(
                "⚠️ teléfono o cámara en modo transferencia: {} — no es un disco, pero \
                 se lleva archivos igual de bien",
                self.new_mtp.join(", ")
            ));
        }

        if !self.new_storage.is_empty() {
            out.push(format!(
                "⚠️ almacenamiento nuevo: {} — conectar un disco a una máquina desatendida \
                 no es curiosear, es copiar",
                self.new_storage.join(", ")
            ));
        }

        if !self.missing_devices.is_empty() {
            out.push(format!(
                "{} dispositivo(s) que ya no están: {}",
                self.missing_devices.len(),
                self.missing_devices.join(", ")
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

    /// Collect the circumstances, comparing every bus against `baseline_path`.
    pub fn observe(baseline_path: &Path) -> Self {
        let now = all_fingerprints();
        let baseline = load_baseline(baseline_path);

        let (new_devices, missing_devices, baseline_missing): (Vec<String>, Vec<String>, bool) =
            match &baseline {
                Some(base) => (
                    now.difference(base).cloned().collect(),
                    base.difference(&now).cloned().collect(),
                    false,
                ),
                None => (Vec::new(), Vec::new(), true),
            };

        // Which of the newcomers can type, and which can hold a copy.
        let keyboards = keyboard_fingerprints();
        let storage = storage_fingerprints();
        let new_keyboards = new_devices.iter().filter(|f| keyboards.contains(*f)).cloned().collect();
        let new_storage = new_devices.iter().filter(|f| storage.contains(*f)).cloned().collect();
        let mtp = mtp_fingerprints();
        let new_mtp = new_devices.iter().filter(|f| mtp.contains(*f)).cloned().collect();

        Circumstance {
            new_devices,
            missing_devices,
            new_keyboards,
            new_storage,
            new_mtp,
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
    let set = all_fingerprints();
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_string_pretty(&set)?)?;
    let _ = fs::set_permissions(path, fs::Permissions::from_mode(0o600));
    Ok(set.len())
}

/// Default location for the device baseline, beside the other daemon state.
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

// ── The watcher ───────────────────────────────────────────────────────────────

/// Speak a passive observation in the configured persona.
///
/// Every alert this daemon raises on its own — as opposed to answering a
/// question — goes through here, so the machine sounds like itself rather than
/// like a log file. The facts are handed over verbatim and the model is told to
/// deliver *those*, not to embellish: a persona is a voice, not a licence to
/// invent hardware that was never plugged in.
///
/// Falls back to the raw facts whenever the LLM is off or errors. An alert that
/// cannot be phrased still has to arrive.
pub fn speak(
    config: &crate::config::Config,
    settings: &std::sync::Arc<std::sync::Mutex<crate::settings::Settings>>,
    llm: &dyn crate::llm::LlmBackend,
    headline: &str,
    facts: &str,
) -> String {
    if !config.llm.llm_enabled() {
        return format!("{headline}\n\n{facts}");
    }
    let persona = crate::llm::resolved_persona(config);
    let override_txt = {
        let g = settings.lock().expect("settings mutex");
        g.system_prompt_override.clone()
    };
    let sys_prompt = crate::llm::effective_system_prompt(config, override_txt.as_deref());
    let directive = format!(
        "These are live facts about hardware that just appeared on this machine. \
         You ARE the machine. Tell the owner what you noticed, in YOUR voice, \
         calmly and briefly — NEVER a formatted log line, and NEVER inventing any \
         device beyond the ones listed here.\n\
         IMPORTANT: this is a PASSIVE observation, not a panic. Say what changed \
         and why it might matter, and let them decide.\n\
         language: {}\ntone: {}\n\
         Write in {}, with the persona above. Be brief (max 3 lines), no titles, \
         no preamble:\n\n{}",
        persona.language, persona.tone, persona.language, facts
    );
    llm.explain(&crate::llm::ExplainRequest {
        system_prompt: &sys_prompt,
        event_text: &directive,
        max_tokens: config.llm.max_tokens,
    })
    .unwrap_or_else(|e| {
        log::warn!("presence persona voice dropped ({e:#}); forwarding raw facts");
        format!("{headline}\n\n{facts}")
    })
}

/// How often to look for new hardware.
const POLL: std::time::Duration = std::time::Duration::from_secs(20);

/// Watch every input and storage bus for devices that appear, and say so.
///
/// Only two kinds of newcomer are worth interrupting someone for, and both are
/// about capability rather than novelty: something that can **type**, and
/// something that can **hold a copy**. A newly appeared monitor is not a
/// finding; a keyboard that was not there a minute ago is.
///
/// Runs against the same accepted baseline as [`Circumstance::observe`], and
/// re-reads it every pass so a `/definehome baseline` takes effect without a
/// restart.
pub fn run_device_loop(
    config: &crate::config::Config,
    state: &std::sync::Arc<std::sync::Mutex<crate::bot::SharedBotState>>,
    settings: &std::sync::Arc<std::sync::Mutex<crate::settings::Settings>>,
    llm: &dyn crate::llm::LlmBackend,
    dry_run: bool,
) {
    let baseline_path = default_baseline_path(&config.face.path);
    log::info!(
        "device-watch: watching input (USB, PS/2, I2C, Bluetooth…) and storage against {}",
        baseline_path.display()
    );

    // Devices already reported, so one plugged-in disk is announced once and
    // not every twenty seconds until it is removed.
    let mut announced: BTreeSet<String> = BTreeSet::new();

    loop {
        std::thread::sleep(POLL);

        let c = Circumstance::observe(&baseline_path);
        if c.baseline_missing {
            continue; // nothing to compare against yet
        }

        let mut fresh: Vec<(&str, &String)> = Vec::new();
        for k in &c.new_keyboards {
            if !announced.contains(k) {
                fresh.push(("teclado", k));
            }
        }
        for d in &c.new_storage {
            if !announced.contains(d) {
                fresh.push(("almacenamiento", d));
            }
        }
        for d in &c.new_mtp {
            if !announced.contains(d) {
                fresh.push(("teléfono/cámara (MTP)", d));
            }
        }
        if fresh.is_empty() {
            continue;
        }
        for (_, f) in &fresh {
            announced.insert((*f).clone());
        }

        let facts = fresh
            .iter()
            .map(|(kind, f)| match *kind {
                "almacenamiento" => format!("- {kind} nuevo: {}", describe_storage(f)),
                _ => format!("- {kind} nuevo: {f}"),
            })
            .collect::<Vec<_>>()
            .join("\n");
        let facts = format!(
            "Hardware que no estaba en la línea base aceptada por el dueño:\n{facts}\n\
             Puede que lo haya conectado el propio dueño: esto es una PREGUNTA, no una \
             acusación. Pregúntale si fue él, en tu voz, y termina con una pregunta clara."
        );

        log::warn!("device-watch: new capability attached, asking the owner:\n{facts}");
        if dry_run {
            continue;
        }

        let chat_id = {
            let g = state.lock().expect("bot state mutex");
            g.paired_chat_id
        };
        let Some(chat_id) = chat_id else {
            log::warn!("device-watch: nobody paired — alert not delivered");
            continue;
        };

        // Park the question so a plain "sí" from the owner is understood as
        // "I plugged that in" — and accepted into the baseline.
        {
            let mut g = state.lock().expect("bot state mutex");
            g.pending_devices = fresh.iter().map(|(_, f)| (*f).clone()).collect();
        }

        let text = speak(config, settings, llm, "🔌 ¿Conectaste algo?", &facts);
        let text = format!(
            "{text}\n\n_Responde *sí* si fuiste tú (lo acepto como normal) o *no* si no._"
        );
        if let Err(e) = crate::bot::send_message(
            &config.telegram.bot_token,
            chat_id,
            &text,
            Some("Markdown"),
        ) {
            log::warn!("device-watch: alert failed: {e:#}");
        }
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
            new_devices: vec!["USB/1234:Rubber Ducky".into()],
            new_keyboards: vec!["USB/1234:Rubber Ducky".into()],
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

    /// Captured from a real machine and from a default QEMU guest. Both shapes
    /// matter: a laptop's own keyboard is PS/2, and so is QEMU's.
    const FIXTURE: &str = "\
I: Bus=0011 Vendor=0001 Product=0001 Version=ab83
N: Name=\"AT Translated Set 2 keyboard\"
P: Phys=isa0060/serio0/input0
H: Handlers=sysrq kbd event3 leds
B: KEY=402000000 3803078f800d001 feffffdfffefffff fffffffffffffffe

I: Bus=0003 Vendor=046d Product=c31c Version=0110
N: Name=\"Logitech USB Keyboard\"
P: Phys=usb-0000:00:14.0-3/input0
H: Handlers=sysrq kbd event5 leds
B: KEY=1000000000007 ff9f207ac14057ff febeffdfffefffff fffffffffffffffe

I: Bus=0018 Vendor=06cb Product=ce44 Version=0100
N: Name=\"SYNA8004:00 06CB:CE44 Touchpad\"
P: Phys=i2c-SYNA8004:00
H: Handlers=mouse0 event7
B: KEY=e520 10000 0 0 0 0

I: Bus=0005 Vendor=05ac Product=0267 Version=0110
N: Name=\"Magic Keyboard\"
P: Phys=aa:bb:cc:dd:ee:ff
H: Handlers=sysrq kbd event9
B: KEY=e080ffdf01cfffff fffffffffffffffe

I: Bus=0019 Vendor=0000 Product=0001 Version=0000
N: Name=\"Power Button\"
P: Phys=PNP0C0C/button/input0
H: Handlers=kbd event0
B: KEY=10000000000000 0
";

    #[test]
    fn the_parser_sees_every_bus_not_just_usb() {
        let devs = parse_input_devices(FIXTURE);
        assert_eq!(devs.len(), 5, "{devs:#?}");

        // The one the original USB-only scan missed: a laptop's built-in
        // keyboard, and QEMU's default, are both PS/2.
        let ps2 = &devs[0];
        assert_eq!(ps2.bus, BUS_I8042);
        assert!(ps2.is_keyboard(), "keys={}", ps2.key_count);
        assert!(bus_name(ps2.bus).contains("PS/2"));
        assert!(ps2.fingerprint().contains("PS/2"), "{}", ps2.fingerprint());

        assert_eq!(devs[1].bus, BUS_USB);
        assert!(devs[1].is_keyboard());

        // A touchpad is on I2C and is not a keyboard: it must be tracked but
        // must not raise "someone brought a keyboard".
        assert_eq!(devs[2].bus, BUS_I2C);
        assert!(!devs[2].is_keyboard());
        assert_eq!(bus_name(devs[2].bus), "I2C");

        // Bluetooth keyboards type just as well as wired ones.
        assert_eq!(devs[3].bus, BUS_BLUETOOTH);
        assert!(devs[3].is_keyboard());

        // A power button carries the kbd handler too, and is not a keyboard.
        // Measured on this laptop: 2 keys against a real keyboard's 70+.
        let power = &devs[4];
        assert!(power.has_kbd_handler, "the handler alone is not the test");
        assert!(!power.is_keyboard(), "keys={}", power.key_count);

        // Three buses, three keyboards; the touchpad and the button are not.
        assert_eq!(devs.iter().filter(|d| d.is_keyboard()).count(), 3);
    }

    #[test]
    fn fingerprints_are_stable_and_bus_qualified() {
        let devs = parse_input_devices(FIXTURE);
        // Two devices could share vendor:product across buses; the bus keeps
        // them distinct.
        let fps: BTreeSet<String> = devs.iter().map(|d| d.fingerprint()).collect();
        assert_eq!(fps.len(), devs.len(), "fingerprints collided");
        // The event node number is deliberately absent: it shuffles on reboot.
        assert!(fps.iter().all(|f| !f.contains("event")), "{fps:?}");
    }

    #[test]
    fn a_truncated_or_empty_file_is_survivable() {
        assert!(parse_input_devices("").is_empty());
        // A record cut off mid-way must still yield what it had.
        let devs = parse_input_devices("I: Bus=0011 Vendor=0001 Product=0001\nN: Name=\"half\"");
        assert_eq!(devs.len(), 1);
        assert_eq!(devs[0].name, "half");
        assert!(!devs[0].is_keyboard(), "no Handlers line means no kbd claim");
        // Junk must not panic.
        assert!(parse_input_devices("garbage\n\nmore garbage").is_empty());
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
        assert!(c.new_devices.is_empty());

        let n = record_baseline(&p).unwrap();
        let mode = fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "the baseline lists this machine's hardware");

        // Straight after recording, nothing is new.
        let c = Circumstance::observe(&p);
        assert!(!c.baseline_missing);
        assert!(c.new_devices.is_empty(), "just-recorded baseline reported changes: {:?}", c.new_devices);
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
