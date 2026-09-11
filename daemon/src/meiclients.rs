// SPDX-License-Identifier: Apache-2.0
//!
//! The ring −3 service surface: every MEI/HECI client the Management Engine
//! publishes, and who on this host can reach it.
//!
//! # What this is for
//!
//! Intel's ME is not one thing you talk to — it is a bus with a *directory* of
//! clients, each a separate firmware service with its own protocol, message
//! size and connection limit. `MKHI` answers firmware-version queries; others
//! do HDCP, protected media, firmware update, and on vPro parts remote
//! management. The kernel publishes that whole directory under
//! `/sys/bus/mei/devices/`, readable without privilege.
//!
//! For a machine's owner the interesting questions are not "what version is the
//! ME" but:
//!
//! - **How large is the surface?** Every client is a firmware service reachable
//!   from this host.
//! - **Which ones is nothing using?** A client with no bound kernel driver is
//!   still reachable by anyone who can open `/dev/mei0` — the host simply is
//!   not using it.
//! - **Who can open `/dev/mei0`?** That node is the user-space door to all of
//!   them. Its ownership and mode decide whether that means "root" or "anyone".
//! - **Is our own ring-0 channel live?** The `sysentinel_metrics` module binds
//!   MKHI, so seeing `sysentinel` as its driver is direct proof the ring 0 →
//!   ring −3 path is the one answering.
//!
//! None of this requires root, opening `/dev/mei0`, or sending a single HECI
//! message — it is all read from sysfs, so it cannot disturb a client another
//! driver is using.
//!
//! # Naming discipline, and why most clients stay unnamed
//!
//! A GUID is only as good as the source that names it. Names here come from
//! exactly two kinds of source, both safe for an Apache-2.0 file:
//!
//! - **Intel's own `metee` library** (Apache-2.0, the same licence as this
//!   daemon), which publishes the MKHI and firmware-update client GUIDs.
//! - **This machine, observed.** When a kernel driver has claimed a client,
//!   sysfs says which one, and that binding names the client as a fact about
//!   the running system rather than a lookup in anyone's table.
//!
//! Deliberately *not* used: the GUID tables in the Linux MEI drivers. They
//! would name several more of the clients below, but this file is Apache-2.0
//! and the kernel is GPL-2.0, so an unnamed client is the honest outcome. An
//! unidentified service is also not a useless finding — "this ME exposes a
//! client nothing on the host claims" is exactly the sort of thing worth
//! reporting.
//!
//! See `metee` in the references and the NOTICE file for provenance.

use std::fmt::Write as _;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// Where a client's human name came from. Carried so a reader can weigh it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameSource {
    /// Published in Intel's Apache-2.0 `metee` library.
    IntelMetee,
    /// Inferred from the kernel driver bound to it on this machine.
    BoundDriver,
    /// No permissively-sourced name; the GUID is reported as-is.
    Unidentified,
}

impl NameSource {
    pub fn describe(&self) -> &'static str {
        match self {
            NameSource::IntelMetee    => "named by Intel's metee",
            NameSource::BoundDriver   => "named by the driver bound to it here",
            NameSource::Unidentified  => "unidentified",
        }
    }
}

/// Client GUIDs published by Intel's `metee` (Apache-2.0). Only these two are
/// taken from a table; everything else is observed or left unnamed.
const METEE_KNOWN: &[(&str, &str, &str)] = &[
    (
        "8e6a6715-9abc-4043-88ef-9e39c6f63e0f",
        "MKHI",
        "management-engine kernel host interface — firmware version and platform queries",
    ),
    (
        "87d90ca5-3495-4559-8105-3fbfa37b8b79",
        "FWU",
        "firmware update service",
    ),
];

/// One MEI client as sysfs describes it.
#[derive(Debug, Clone)]
pub struct MeiClient {
    /// Client GUID, lowercase.
    pub uuid: String,
    /// PCI address of the HECI controller publishing it (`0000:00:16.0`).
    pub device: String,
    /// Short name, when one could be sourced honestly.
    pub name: Option<String>,
    /// What that name rests on.
    pub name_source: NameSource,
    /// One-line purpose, when known.
    pub purpose: Option<&'static str>,
    /// Client protocol version.
    pub protocol_version: Option<u32>,
    /// Largest message the client accepts, in bytes.
    pub max_msg_len: Option<u32>,
    /// Simultaneous connections allowed. Zero on fixed-address clients.
    pub max_connections: Option<u32>,
    /// Non-zero for a fixed-address client, which needs no connect handshake.
    pub fixed_address: Option<u32>,
    /// Client supports virtual tagging.
    pub vtag: bool,
    /// Kernel driver that has claimed it, if any.
    pub driver: Option<String>,
}

impl MeiClient {
    /// A client no kernel driver has claimed. Still reachable from user-space
    /// by whoever can open `/dev/mei0`.
    pub fn unclaimed(&self) -> bool {
        self.driver.is_none()
    }

    /// Fixed-address clients are addressed directly, with no connect handshake.
    pub fn is_fixed_address(&self) -> bool {
        self.fixed_address.is_some_and(|f| f != 0)
    }

    /// Display label: the sourced name where there is one, else the GUID.
    pub fn label(&self) -> String {
        match &self.name {
            Some(n) => n.clone(),
            None => self.uuid.clone(),
        }
    }
}

/// Who can reach the ME from user-space, read off the `/dev/mei*` nodes.
#[derive(Debug, Clone)]
pub struct MeiDeviceNode {
    pub path: String,
    /// Permission bits (the low 12 of `st_mode`).
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
}

impl MeiDeviceNode {
    /// True when someone other than the owner and group can open it — i.e. any
    /// local user can start talking to ring −3.
    pub fn world_accessible(&self) -> bool {
        self.mode & 0o006 != 0
    }

    /// True when a group beyond root can open it.
    pub fn group_accessible(&self) -> bool {
        self.mode & 0o060 != 0 && self.gid != 0
    }

    pub fn render(&self) -> String {
        format!(
            "{} mode {:04o} uid {} gid {}",
            self.path,
            self.mode & 0o7777,
            self.uid,
            self.gid
        )
    }
}

/// The whole ring −3 service surface of this machine.
#[derive(Debug, Clone, Default)]
pub struct MeiSurface {
    pub clients: Vec<MeiClient>,
    pub nodes: Vec<MeiDeviceNode>,
}

impl MeiSurface {
    /// Clients no kernel driver has claimed.
    pub fn unclaimed(&self) -> Vec<&MeiClient> {
        self.clients.iter().filter(|c| c.unclaimed()).collect()
    }

    /// The client `sysentinel_metrics` has bound, if it is loaded and attached.
    /// Its presence is direct evidence the ring-0 → ring −3 path is ours.
    pub fn our_client(&self) -> Option<&MeiClient> {
        self.clients
            .iter()
            .find(|c| c.driver.as_deref() == Some("sysentinel"))
    }

    /// True when the MEI bus published nothing — no ME, or no `mei` driver.
    pub fn is_empty(&self) -> bool {
        self.clients.is_empty()
    }

    /// Posture observations worth a line in a report. Facts and their direct
    /// consequences only — no verdicts.
    pub fn notes(&self) -> Vec<String> {
        let mut out = Vec::new();
        if self.clients.is_empty() {
            out.push(
                "no MEI clients published — no Intel ME on this platform, or the \
                 mei driver is not loaded"
                    .to_string(),
            );
            return out;
        }

        out.push(format!(
            "{} firmware service(s) published on the MEI bus",
            self.clients.len()
        ));

        let unclaimed = self.unclaimed();
        if !unclaimed.is_empty() {
            out.push(format!(
                "{} of them have no kernel driver bound — nothing on this host uses \
                 them, but they stay reachable through /dev/mei0",
                unclaimed.len()
            ));
        }

        let fixed = self.clients.iter().filter(|c| c.is_fixed_address()).count();
        if fixed > 0 {
            out.push(format!(
                "{fixed} are fixed-address clients, addressed with no connect handshake"
            ));
        }

        match self.our_client() {
            Some(c) => out.push(format!(
                "sysentinel_metrics holds {} — the ring 0 → ring −3 channel is ours",
                c.label()
            )),
            None => out.push(
                "sysentinel_metrics holds no MEI client — ME answers here come from \
                 sysfs only, not a live ring-0 handshake"
                    .to_string(),
            ),
        }

        // The user-space door to every client above.
        for node in &self.nodes {
            if node.world_accessible() {
                out.push(format!(
                    "⚠ {} is world-accessible — any local user can talk to the ME",
                    node.render()
                ));
            } else if node.group_accessible() {
                out.push(format!(
                    "{} is group-accessible (gid {}) — members of that group can talk \
                     to the ME",
                    node.path, node.gid
                ));
            } else {
                out.push(format!("{} is root-only", node.render()));
            }
        }

        out
    }

    /// Full multi-line report for `/definehome hal` and the diagnostics dump.
    pub fn render(&self) -> String {
        let mut out = String::from("Ring −3 service surface (Intel ME / MEI bus):\n");

        if self.clients.is_empty() {
            out.push_str("  no MEI clients published\n");
            return out;
        }

        // Some platforms expose more than one HECI controller; say which one is
        // publishing, so two identical GUIDs on different controllers are not
        // read as duplicates.
        let mut controllers: Vec<&str> = self.clients.iter().map(|c| c.device.as_str()).collect();
        controllers.sort_unstable();
        controllers.dedup();
        let _ = writeln!(out, "  HECI controller(s): {}", controllers.join(", "));

        for c in &self.clients {
            // Pad only when a GUID follows; an unnamed client is its own GUID
            // and needs no column of trailing space.
            match &c.name {
                Some(n) => { let _ = writeln!(out, "  {n:<32} [{}]", c.uuid); }
                None    => { let _ = writeln!(out, "  {}", c.uuid); }
            }

            let mut bits: Vec<String> = Vec::new();
            if let Some(v) = c.protocol_version {
                bits.push(format!("proto v{v}"));
            }
            if let Some(l) = c.max_msg_len {
                bits.push(format!("max msg {l} B"));
            }
            match c.max_connections {
                Some(0) => bits.push("no connect handshake".to_string()),
                Some(n) => bits.push(format!("{n} connection(s)")),
                None => {}
            }
            if c.is_fixed_address() {
                bits.push(format!("fixed addr {}", c.fixed_address.unwrap_or(0)));
            }
            if c.vtag {
                bits.push("vtag".to_string());
            }
            if !bits.is_empty() {
                let _ = writeln!(out, "      {}", bits.join(", "));
            }

            let claim = match &c.driver {
                Some(d) => format!("driver: {d}"),
                None => "driver: none — unused by this host, reachable via /dev/mei0".to_string(),
            };
            let _ = writeln!(out, "      {claim}  ({})", c.name_source.describe());
            if let Some(p) = c.purpose {
                let _ = writeln!(out, "      {p}");
            }
        }

        out.push_str("\n  Notes:\n");
        for n in self.notes() {
            let _ = writeln!(out, "    - {n}");
        }
        out
    }
}

// ── Reading sysfs ─────────────────────────────────────────────────────────────

fn read_u32(dir: &Path, file: &str) -> Option<u32> {
    let raw = fs::read_to_string(dir.join(file)).ok()?;
    let t = raw.trim();
    // `version` is published as a zero-padded decimal ("02"); the rest are plain.
    t.parse::<u32>().ok()
}

/// Split a client directory name into its PCI device and GUID halves. The
/// kernel names them `<pci address>-<uuid>`, and the GUID's own dashes mean a
/// naive split on '-' will not do.
fn split_client_dirname(name: &str) -> Option<(String, String)> {
    // A GUID is 36 characters: 8-4-4-4-12.
    if name.len() < 38 {
        return None;
    }
    let split_at = name.len() - 36;
    // `split_at` panics on a byte index inside a character. The kernel names
    // these in ASCII, so this is about the function staying total rather than
    // about a name that exists today.
    if !name.is_char_boundary(split_at) {
        return None;
    }
    let (dev, uuid) = name.split_at(split_at);
    let dev = dev.strip_suffix('-')?;
    let uuid = uuid.to_ascii_lowercase();
    // Cheap shape check: dashes exactly where a GUID has them.
    let ok = uuid.len() == 36
        && uuid.as_bytes()[8] == b'-'
        && uuid.as_bytes()[13] == b'-'
        && uuid.as_bytes()[18] == b'-'
        && uuid.as_bytes()[23] == b'-'
        && uuid.chars().all(|c| c.is_ascii_hexdigit() || c == '-');
    ok.then(|| (dev.to_string(), uuid))
}

/// Name a client from the only two sources this file accepts.
fn name_client(uuid: &str, driver: Option<&str>) -> (Option<String>, NameSource, Option<&'static str>) {
    if let Some((_, name, purpose)) = METEE_KNOWN.iter().find(|(g, _, _)| *g == uuid) {
        return (Some((*name).to_string()), NameSource::IntelMetee, Some(*purpose));
    }
    // A bound driver names the client as an observed fact about this machine.
    match driver {
        // Our own module binding MKHI is already covered above; anything else
        // takes the driver's name, which is what the kernel says is using it.
        Some(d) if d != "sysentinel" => (
            Some(format!("{d} client")),
            NameSource::BoundDriver,
            None,
        ),
        _ => (None, NameSource::Unidentified, None),
    }
}

/// Enumerate the ME's published clients and the `/dev/mei*` nodes that reach
/// them. Never fails: a machine with no ME simply yields an empty surface.
pub fn enumerate() -> MeiSurface {
    let mut surface = MeiSurface::default();

    if let Ok(entries) = fs::read_dir("/sys/bus/mei/devices") {
        for entry in entries.flatten() {
            let dir = entry.path();
            let dirname = entry.file_name().to_string_lossy().into_owned();
            let Some((device, uuid)) = split_client_dirname(&dirname) else {
                continue;
            };

            // The driver symlink is the ground truth for who has claimed it.
            let driver = fs::read_link(dir.join("driver"))
                .ok()
                .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()));

            let (name, name_source, purpose) = name_client(&uuid, driver.as_deref());

            surface.clients.push(MeiClient {
                uuid,
                device,
                name,
                name_source,
                purpose,
                protocol_version: read_u32(&dir, "version"),
                max_msg_len:      read_u32(&dir, "max_len"),
                max_connections:  read_u32(&dir, "max_conn"),
                fixed_address:    read_u32(&dir, "fixed"),
                vtag:             read_u32(&dir, "vtag").is_some_and(|v| v != 0),
                driver,
            });
        }
    }

    // Named clients first, then by GUID, so the report reads consistently.
    surface.clients.sort_by(|a, b| {
        b.name.is_some().cmp(&a.name.is_some()).then(a.uuid.cmp(&b.uuid))
    });

    surface.nodes = mei_device_nodes();
    surface
}

/// The `/dev/mei*` character devices, with the permissions that decide who can
/// reach every client above.
fn mei_device_nodes() -> Vec<MeiDeviceNode> {
    let mut out = Vec::new();
    let Ok(entries) = fs::read_dir("/dev") else {
        return out;
    };
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with("mei") {
            continue;
        }
        let Ok(md) = entry.metadata() else { continue };
        out.push(MeiDeviceNode {
            path: format!("/dev/{name}"),
            mode: md.mode(),
            uid:  md.uid(),
            gid:  md.gid(),
        });
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    out
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enumerating_never_panics() {
        let s = enumerate();
        println!("{}", s.render());
    }

    #[test]
    fn splits_client_directory_names() {
        let (dev, uuid) =
            split_client_dirname("0000:00:16.0-8e6a6715-9abc-4043-88ef-9e39c6f63e0f").unwrap();
        assert_eq!(dev, "0000:00:16.0");
        assert_eq!(uuid, "8e6a6715-9abc-4043-88ef-9e39c6f63e0f");

        // Uppercase GUIDs normalise, so table lookups cannot miss on case.
        let (_, uuid) =
            split_client_dirname("0000:00:16.0-8E6A6715-9ABC-4043-88EF-9E39C6F63E0F").unwrap();
        assert_eq!(uuid, "8e6a6715-9abc-4043-88ef-9e39c6f63e0f");

        // Nonsense must be rejected rather than half-parsed.
        assert!(split_client_dirname("").is_none());
        assert!(split_client_dirname("0000:00:16.0").is_none());
        assert!(split_client_dirname("0000:00:16.0-not-a-guid-at-all-xxxx").is_none());
    }

    #[test]
    fn only_permissive_sources_name_a_client() {
        // metee publishes MKHI, so it is named and attributed.
        let (n, src, purpose) = name_client("8e6a6715-9abc-4043-88ef-9e39c6f63e0f", None);
        assert_eq!(n.as_deref(), Some("MKHI"));
        assert_eq!(src, NameSource::IntelMetee);
        assert!(purpose.is_some());

        // An unknown GUID with a driver bound is named from that observation.
        let (n, src, _) = name_client("11111111-2222-3333-4444-555555555555", Some("mei_pxp"));
        assert_eq!(n.as_deref(), Some("mei_pxp client"));
        assert_eq!(src, NameSource::BoundDriver);

        // An unknown GUID with nothing bound stays unnamed. It must NOT acquire
        // a name from any other table — that is the whole discipline here.
        let (n, src, _) = name_client("11111111-2222-3333-4444-555555555555", None);
        assert!(n.is_none());
        assert_eq!(src, NameSource::Unidentified);
    }

    #[test]
    fn device_node_permissions_are_classified() {
        let root_only = MeiDeviceNode { path: "/dev/mei0".into(), mode: 0o600, uid: 0, gid: 0 };
        assert!(!root_only.world_accessible());
        assert!(!root_only.group_accessible());

        let world = MeiDeviceNode { path: "/dev/mei0".into(), mode: 0o666, uid: 0, gid: 0 };
        assert!(world.world_accessible());

        let grouped = MeiDeviceNode { path: "/dev/mei0".into(), mode: 0o660, uid: 0, gid: 992 };
        assert!(!grouped.world_accessible());
        assert!(grouped.group_accessible());

        // gid 0 with group bits is still just root.
        let root_group = MeiDeviceNode { path: "/dev/mei0".into(), mode: 0o660, uid: 0, gid: 0 };
        assert!(!root_group.group_accessible());
    }

    #[test]
    fn empty_surface_says_so_without_guessing() {
        let empty = MeiSurface::default();
        assert!(empty.is_empty());
        assert!(empty.our_client().is_none());
        let notes = empty.notes();
        assert_eq!(notes.len(), 1);
        assert!(notes[0].contains("no MEI clients"));
        assert!(empty.render().contains("no MEI clients"));
    }

    #[test]
    fn surface_reports_this_machine_consistently() {
        let s = enumerate();
        if s.is_empty() {
            println!("no MEI bus here — nothing to cross-check");
            return;
        }
        for c in &s.clients {
            assert_eq!(c.uuid.len(), 36, "malformed uuid {}", c.uuid);
            assert!(!c.device.is_empty());
            // A client named from a driver must actually have one.
            if c.name_source == NameSource::BoundDriver {
                assert!(c.driver.is_some(), "{} claims a driver name", c.uuid);
            }
            // Fixed-address clients take no connections.
            if c.is_fixed_address() {
                assert_eq!(c.max_connections, Some(0), "{} is fixed but connectable", c.uuid);
            }
        }
        assert!(!s.notes().is_empty());
        println!("{}", s.render());
    }
}
