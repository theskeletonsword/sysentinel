// SPDX-License-Identifier: Apache-2.0
//!
//! Finding the EFI System Partition — and, more to the point, *not* finding
//! everything else.
//!
//! # The bug this replaces
//!
//! Two places needed the ESP: the initramfs mirrors its LUKS evidence there
//! (the daemon reads it after boot), and the face template DB is copied there
//! so the initramfs can recognise the owner before any root filesystem exists.
//! Both asked the same question of `/proc/mounts` — *"is the filesystem
//! vfat?"* — and treated every answer as the ESP.
//!
//! Nearly every USB stick in the world is vfat. On a desktop that automounts
//! removable media, plugging one in therefore handed an attacker two things:
//!
//! - **A way to feed the daemon evidence.** Drop `sysentinel/luks/luks_*.txt`
//!   on a stick, plug it in, and the daemon reads it as proof that someone
//!   unlocked the disk — an alert the owner never caused, and with
//!   `luks_deny_action = poweroff`, a machine that switches itself off when a
//!   stranger walks past with a USB stick.
//! - **A copy of the owner's face.** The mirror wrote the biometric template
//!   database to *every* vfat mount it could see, so the stick went home with
//!   the embeddings on it.
//!
//! # What identifies the real one
//!
//! Three things have to agree, and each removes a different attack:
//!
//! 1. **The mount point is one of the conventional ESP locations.** An
//!    automounted stick lands under `/run/media/...` or `/media/...`, never at
//!    `/boot/efi`, so this alone rules out the drive-by case.
//! 2. **It looks like an ESP**: a vfat filesystem with an `EFI` directory in
//!    its root. A vfat filesystem deliberately mounted at `/boot` that is not
//!    an ESP does not qualify.
//! 3. **The device is not removable.** `/sys/class/block/<dev>/removable`
//!    answers this for the whole disk, and it is the check that survives
//!    somebody mounting their stick exactly where the ESP belongs.
//!
//! A machine with no ESP (BIOS boot, or an encrypted `/boot`) gets an empty
//! list, which is the correct answer rather than a fallback to guessing.

use std::path::{Path, PathBuf};

/// Where an ESP is conventionally mounted. Anything else is not one, whatever
/// it claims: automounted removable media never lands here.
const CONVENTIONAL: &[&str] = &["/boot/efi", "/efi", "/boot/EFI", "/boot"];

/// One line of `/proc/mounts`, as far as we care about it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mount {
    pub device: String,
    pub mount_point: String,
    pub fstype: String,
    /// The comma-separated option list, verbatim (`rw,relatime,…`).
    pub options: String,
}

/// Parse `/proc/mounts`.
///
/// Mount points with awkward characters are octal-escaped by the kernel — a
/// path with a space arrives as `/mnt/my\040disk`. Reading the field raw meant
/// building a path that does not exist, so the escapes are undone here.
pub fn parse_mounts(text: &str) -> Vec<Mount> {
    text.lines()
        .filter_map(|line| {
            let mut f = line.split(' ');
            let device = unescape(f.next()?);
            let mount_point = unescape(f.next()?);
            let fstype = f.next()?.to_string();
            let options = f.next().unwrap_or("").to_string();
            if mount_point.is_empty() {
                return None;
            }
            Some(Mount { device, mount_point, fstype, options })
        })
        .collect()
}

/// Undo the kernel's octal escaping (`\040` → space, `\134` → backslash).
fn unescape(field: &str) -> String {
    if !field.contains('\\') {
        return field.to_string();
    }
    let bytes = field.as_bytes();
    let mut out = String::with_capacity(field.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'\\' && i + 3 < bytes.len() {
            let digits = &field[i + 1..i + 4];
            if let Ok(code) = u8::from_str_radix(digits, 8) {
                out.push(code as char);
                i += 4;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

/// Whether this mount is a plausible ESP, judged on everything except the
/// hardware (which [`mount_points`] checks separately, since it needs sysfs).
///
/// `root` prefixes the filesystem lookups so this is testable against a
/// synthetic tree rather than only on a machine that happens to have an ESP.
fn looks_like_esp(m: &Mount, root: &Path) -> bool {
    if m.fstype != "vfat" {
        return false;
    }
    if !CONVENTIONAL.contains(&m.mount_point.as_str()) {
        return false;
    }
    // An ESP has an EFI directory. vfat is case-insensitive, but the kernel
    // reports names in one case per mount, so check both rather than assume.
    let base = root.join(m.mount_point.trim_start_matches('/'));
    base.join("EFI").is_dir() || base.join("efi").is_dir()
}

/// Whether the block device behind this mount sits on removable media.
///
/// This is the check that stops "I mounted my USB stick at /boot". Unknown
/// answers count as removable: not being able to tell is not a reason to trust
/// something with the owner's biometrics.
fn on_fixed_media(device: &str, sys_class_block: &Path) -> bool {
    let Some(name) = Path::new(device).file_name().and_then(|n| n.to_str()) else {
        return false;
    };
    let entry = sys_class_block.join(name);
    if !entry.exists() {
        // Not a block device we can reason about — a bind mount, a loop
        // device, something in a container. Not the ESP.
        return false;
    }
    // A partition points at its parent disk, and `removable` lives there.
    let disk = if entry.join("partition").exists() {
        // `/sys/class/block/sda1/..` is the disk in the real sysfs layout;
        // fall back to trimming digits when that is not available (tests).
        let parent = entry.join("..");
        if parent.join("removable").exists() {
            parent
        } else {
            sys_class_block.join(name.trim_end_matches(|c: char| c.is_ascii_digit()))
        }
    } else {
        entry
    };
    match std::fs::read_to_string(disk.join("removable")) {
        Ok(v) => v.trim() == "0",
        Err(_) => false,
    }
}

/// Whether a mount is currently read-only, so a caller that remounts it can
/// put it back the way it found it.
pub fn is_read_only(m: &Mount) -> bool {
    m.options.split(',').any(|o| o == "ro")
}

/// Every mount that really is an EFI System Partition.
pub fn mount_points() -> Vec<PathBuf> {
    let Ok(text) = std::fs::read_to_string("/proc/mounts") else {
        return Vec::new();
    };
    mount_points_from(&text, Path::new("/"), Path::new("/sys/class/block"))
}

fn mount_points_from(mounts: &str, root: &Path, sys_class_block: &Path) -> Vec<PathBuf> {
    parse_mounts(mounts)
        .into_iter()
        .filter(|m| looks_like_esp(m, root))
        .filter(|m| on_fixed_media(&m.device, sys_class_block))
        .map(|m| root.join(m.mount_point.trim_start_matches('/')))
        .collect()
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// A synthetic root: an ESP at /boot/efi on a fixed disk, plus a USB stick
    /// automounted the way a desktop does it.
    struct Fake {
        root: PathBuf,
    }

    impl Fake {
        fn new(tag: &str) -> Self {
            let root = std::env::temp_dir()
                .join(format!("sysentinel-esp-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(root.join("boot/efi/EFI/BOOT")).unwrap();
            std::fs::create_dir_all(root.join("run/media/skels/USB/EFI")).unwrap();
            std::fs::create_dir_all(root.join("boot/stick/EFI")).unwrap();
            // sysfs: sda is fixed, sdz is a stick.
            std::fs::create_dir_all(root.join("sys/class/block/sda1")).unwrap();
            std::fs::write(root.join("sys/class/block/sda1/partition"), "1").unwrap();
            std::fs::create_dir_all(root.join("sys/class/block/sda")).unwrap();
            std::fs::write(root.join("sys/class/block/sda/removable"), "0\n").unwrap();
            std::fs::create_dir_all(root.join("sys/class/block/sdz1")).unwrap();
            std::fs::write(root.join("sys/class/block/sdz1/partition"), "1").unwrap();
            std::fs::create_dir_all(root.join("sys/class/block/sdz")).unwrap();
            std::fs::write(root.join("sys/class/block/sdz/removable"), "1\n").unwrap();
            Fake { root }
        }

        fn resolve(&self, mounts: &str) -> Vec<PathBuf> {
            mount_points_from(mounts, &self.root, &self.root.join("sys/class/block"))
        }
    }

    impl Drop for Fake {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    #[test]
    fn the_real_esp_is_found() {
        let f = Fake::new("real");
        let mounts = "/dev/sda1 /boot/efi vfat rw,relatime 0 0\n\
                      /dev/sda2 / ext4 rw,relatime 0 0\n";
        assert_eq!(f.resolve(mounts), vec![f.root.join("boot/efi")]);
    }

    #[test]
    fn an_automounted_usb_stick_is_not_an_esp() {
        // The drive-by case: a vfat stick with an EFI directory on it, mounted
        // where a desktop automounts. It used to qualify on "fstype == vfat"
        // alone, which is how a stranger got to feed the daemon evidence and
        // carry the owner's face templates away.
        let f = Fake::new("usb");
        let mounts = "/dev/sdz1 /run/media/skels/USB vfat rw,nosuid,relatime 0 0\n";
        assert!(f.resolve(mounts).is_empty());
    }

    #[test]
    fn a_stick_mounted_where_the_esp_belongs_is_still_a_stick() {
        // Deliberate version of the same attack: mount removable media at a
        // conventional ESP path. The mount point stops lying; `removable` does
        // not.
        let f = Fake::new("planted");
        let mounts = "/dev/sdz1 /boot/stick vfat rw 0 0\n\
                      /dev/sdz1 /boot vfat rw 0 0\n";
        assert!(f.resolve(mounts).is_empty());
    }

    #[test]
    fn vfat_alone_is_not_enough_and_neither_is_the_path() {
        let f = Fake::new("mixed");
        // Right path, wrong filesystem.
        assert!(f.resolve("/dev/sda1 /boot/efi ext4 rw 0 0\n").is_empty());
        // Right filesystem and device, but no EFI directory at that path.
        std::fs::create_dir_all(f.root.join("efi")).unwrap();
        assert!(f.resolve("/dev/sda1 /efi vfat rw 0 0\n").is_empty());
        // Add the directory and it qualifies.
        std::fs::create_dir_all(f.root.join("efi/EFI")).unwrap();
        assert_eq!(f.resolve("/dev/sda1 /efi vfat rw 0 0\n"), vec![f.root.join("efi")]);
    }

    #[test]
    fn an_unknown_device_is_treated_as_removable() {
        // Cannot tell is not a reason to trust it with the owner's biometrics.
        let f = Fake::new("unknown");
        let mounts = "/dev/nope9 /boot/efi vfat rw 0 0\n";
        assert!(f.resolve(mounts).is_empty());
    }

    #[test]
    fn mount_points_with_spaces_survive_the_kernels_escaping() {
        // `/proc/mounts` octal-escapes awkward characters. Reading the field
        // raw builds a path that does not exist.
        let parsed = parse_mounts("/dev/sdb1 /mnt/my\\040disk vfat rw 0 0\n");
        assert_eq!(parsed[0].mount_point, "/mnt/my disk");
        assert_eq!(parsed[0].device, "/dev/sdb1");
        // And a backslash in a name is itself escaped.
        let parsed = parse_mounts("/dev/sdb1 /mnt/back\\134slash vfat rw 0 0\n");
        assert_eq!(parsed[0].mount_point, "/mnt/back\\slash");
        // Ordinary lines are untouched.
        let parsed = parse_mounts("proc /proc proc rw 0 0\n");
        assert_eq!(parsed[0].mount_point, "/proc");
        // And the options come through for the read-only check.
        let parsed = parse_mounts("/dev/sda1 /boot/efi vfat ro,relatime 0 0\n");
        assert!(is_read_only(&parsed[0]));
        let parsed = parse_mounts("/dev/sda1 /boot/efi vfat rw,relatime 0 0\n");
        assert!(!is_read_only(&parsed[0]));
    }

    #[test]
    fn a_machine_with_no_esp_gets_an_empty_answer() {
        // BIOS boot, or an encrypted /boot. Nothing to fall back to, and
        // guessing would be how this went wrong in the first place.
        let f = Fake::new("none");
        assert!(f.resolve("/dev/sda2 / ext4 rw 0 0\n").is_empty());
        assert!(f.resolve("").is_empty());
    }
}
