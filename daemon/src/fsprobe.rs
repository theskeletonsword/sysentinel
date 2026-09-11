// SPDX-License-Identifier: Apache-2.0
//!
//! What kind of volume is that, without mounting it.
//!
//! "A disk was attached" is a weak alert. *Which* disk matters: a FAT stick
//! someone used to move a photo and a LUKS container someone brought to copy
//! your home directory into are the same event to a device watcher and very
//! different events to you.
//!
//! Identification is by on-disk signature — the magic every format writes at a
//! fixed offset — read from the first 68 KB of the device. Nothing is mounted,
//! no kernel driver is asked to probe, and a volume the daemon cannot name is
//! reported as unnamed rather than guessed at.
//!
//! # The one that has no signature, on purpose
//!
//! VeraCrypt and TrueCrypt containers, and plain `dm-crypt` volumes, write no
//! magic at all: their header is ciphertext, and being indistinguishable from
//! random data is the feature. There is nothing to match, so matching is the
//! wrong tool.
//!
//! What such a volume does have is *entropy*. Real filesystems put structure in
//! their first blocks — zeroed reserved fields, ASCII labels, repeated
//! bookkeeping — and structure is compressible. Ciphertext is not. So a device
//! with no recognised signature **and** near-maximal entropy is reported as
//! [`VolumeKind::Opaque`]: encrypted with a header that hides itself, or wiped
//! with random data. That is an observation, not an accusation, and the report
//! says so — a securely-erased disk looks identical, because it is supposed to.
//!
//! # Provenance
//!
//! Every offset and magic below comes from the format's own published
//! specification — the ext4 disk layout, Microsoft's exFAT and NTFS
//! documentation, Apple's APFS reference, the LUKS on-disk format spec, and so
//! on. They are interface facts about a byte on a disk. No filesystem probing
//! code was consulted; `blkid`'s table in particular is GPL-2.0 and this file is
//! Apache-2.0.

use std::fs::File;
use std::io::Read;
use std::path::Path;

/// How much of the device head to read.
///
/// Sized by the furthest signature this module looks for: the ZFS uberblock at
/// 0x20000, which is 128 KB in. btrfs at 0x10040 is the next furthest. Getting
/// this wrong is silent — a signature past the window simply never matches —
/// so a test plants every magic at its own offset and requires a hit.
pub const PROBE_BYTES: usize = 132 * 1024;

/// Entropy, in bits per byte, above which an unsignatured volume is called
/// opaque. Ciphertext sits within a hair of 8.0; even a compressed archive's
/// container leaves structure in its first blocks.
const OPAQUE_ENTROPY: f64 = 7.5;

/// What the head of a volume says it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VolumeKind {
    Luks1,
    Luks2,
    Ext,
    Btrfs,
    Xfs,
    F2fs,
    Ntfs,
    ExFat,
    Fat32,
    Fat16,
    Fat12,
    Hfs,
    HfsPlus,
    Apfs,
    Iso9660,
    Udf,
    Squashfs,
    Swap,
    Lvm2,
    Zfs,
    /// No known signature and near-random content: an encrypted container that
    /// hides its header (VeraCrypt, TrueCrypt, plain dm-crypt), or a disk wiped
    /// with random data. The two are not distinguishable from outside, and this
    /// module does not pretend otherwise.
    Opaque,
    /// No known signature and ordinary-looking content. Blank, unpartitioned,
    /// or a format this module does not know.
    Unknown,
}

impl VolumeKind {
    /// Short label for a report.
    pub fn label(&self) -> &'static str {
        match self {
            VolumeKind::Luks1 => "LUKS1",
            VolumeKind::Luks2 => "LUKS2",
            VolumeKind::Ext => "ext2/3/4",
            VolumeKind::Btrfs => "btrfs",
            VolumeKind::Xfs => "XFS",
            VolumeKind::F2fs => "F2FS",
            VolumeKind::Ntfs => "NTFS",
            VolumeKind::ExFat => "exFAT",
            VolumeKind::Fat32 => "FAT32",
            VolumeKind::Fat16 => "FAT16",
            VolumeKind::Fat12 => "FAT12",
            VolumeKind::Hfs => "HFS",
            VolumeKind::HfsPlus => "HFS+",
            VolumeKind::Apfs => "APFS",
            VolumeKind::Iso9660 => "ISO 9660",
            VolumeKind::Udf => "UDF",
            VolumeKind::Squashfs => "SquashFS",
            VolumeKind::Swap => "swap",
            VolumeKind::Lvm2 => "LVM2 PV",
            VolumeKind::Zfs => "ZFS",
            VolumeKind::Opaque => "sin firma, contenido aleatorio",
            VolumeKind::Unknown => "sin identificar",
        }
    }

    /// True when the volume's contents are encrypted at rest.
    pub fn is_encrypted(&self) -> bool {
        matches!(self, VolumeKind::Luks1 | VolumeKind::Luks2 | VolumeKind::Opaque)
    }

    /// Whether this is a filesystem someone can drop files onto right now,
    /// as opposed to a container, an image or swap.
    pub fn is_mountable_filesystem(&self) -> bool {
        matches!(
            self,
            VolumeKind::Ext
                | VolumeKind::Btrfs
                | VolumeKind::Xfs
                | VolumeKind::F2fs
                | VolumeKind::Ntfs
                | VolumeKind::ExFat
                | VolumeKind::Fat32
                | VolumeKind::Fat16
                | VolumeKind::Fat12
                | VolumeKind::Hfs
                | VolumeKind::HfsPlus
                | VolumeKind::Apfs
        )
    }

    /// A sentence for the owner about what this being attached means.
    pub fn note(&self) -> Option<&'static str> {
        match self {
            VolumeKind::Luks1 | VolumeKind::Luks2 =>
                Some("contenedor cifrado LUKS: alguien trajo su propio disco cerrado"),
            VolumeKind::Opaque => Some(
                "sin ninguna firma y con contenido indistinguible de datos aleatorios: \
                 encaja con VeraCrypt/TrueCrypt o dm-crypt plano, y también con un disco \
                 borrado a conciencia. Desde fuera son lo mismo",
            ),
            VolumeKind::Apfs | VolumeKind::HfsPlus | VolumeKind::Hfs =>
                Some("formato de Apple: viene de un Mac"),
            VolumeKind::Ntfs => Some("formato de Windows"),
            VolumeKind::Iso9660 | VolumeKind::Udf =>
                Some("imagen óptica: un disco o una ISO montada"),
            VolumeKind::Squashfs => Some("imagen de solo lectura"),
            _ => None,
        }
    }
}

/// Shannon entropy of a buffer, in bits per byte (0.0 to 8.0).
fn entropy(buf: &[u8]) -> f64 {
    if buf.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for &b in buf {
        counts[b as usize] += 1;
    }
    let len = buf.len() as f64;
    -counts
        .iter()
        .filter(|&&c| c > 0)
        .map(|&c| {
            let p = c as f64 / len;
            p * p.log2()
        })
        .sum::<f64>()
}

/// True when `buf` holds `needle` at `offset`.
fn at(buf: &[u8], offset: usize, needle: &[u8]) -> bool {
    buf.len() >= offset + needle.len() && &buf[offset..offset + needle.len()] == needle
}

/// Identify a volume from the head of its device.
///
/// Pure function over bytes so every format below is testable without a disk.
pub fn identify(buf: &[u8]) -> VolumeKind {
    // Encrypted containers first: a LUKS header sits at offset 0 and would
    // otherwise be mistaken for nothing at all.
    if at(buf, 0, b"LUKS\xba\xbe") {
        // Version is a big-endian u16 right after the magic.
        return match buf.get(6..8) {
            Some([0, 2]) => VolumeKind::Luks2,
            _ => VolumeKind::Luks1,
        };
    }

    if at(buf, 0x10040, b"_BHRfS_M") {
        return VolumeKind::Btrfs;
    }
    if at(buf, 0, b"XFSB") {
        return VolumeKind::Xfs;
    }
    if at(buf, 0, b"hsqs") || at(buf, 0, b"sqsh") {
        return VolumeKind::Squashfs;
    }
    if at(buf, 0x200, b"LABELONE") {
        return VolumeKind::Lvm2;
    }
    // ext superblock magic 0xEF53, little-endian at 0x438.
    if at(buf, 0x438, &[0x53, 0xEF]) {
        return VolumeKind::Ext;
    }
    // F2FS superblock magic 0xF2F52010, little-endian at 0x400.
    if at(buf, 0x400, &[0x10, 0x20, 0xF5, 0xF2]) {
        return VolumeKind::F2fs;
    }
    if at(buf, 0x400, b"H+") {
        return VolumeKind::HfsPlus;
    }
    if at(buf, 0x400, b"HX") {
        return VolumeKind::HfsPlus;
    }
    if at(buf, 0x400, b"BD") {
        return VolumeKind::Hfs;
    }
    if at(buf, 0x20, b"NXSB") {
        return VolumeKind::Apfs;
    }
    if at(buf, 0x8001, b"CD001") {
        return VolumeKind::Iso9660;
    }
    if at(buf, 0x8001, b"BEA01") || at(buf, 0x8001, b"NSR02") || at(buf, 0x8001, b"NSR03") {
        return VolumeKind::Udf;
    }
    // ZFS uberblock magic 0x00bab10c, little-endian, in the label area.
    if at(buf, 0x20000, &[0x0c, 0xb1, 0xba, 0x00]) {
        return VolumeKind::Zfs;
    }
    // The swap header lives at the end of the first page.
    if at(buf, 0xFF6, b"SWAPSPACE2") || at(buf, 0xFF6, b"SWAP-SPACE") {
        return VolumeKind::Swap;
    }

    // The FAT family shares a boot sector; the type string's offset moves
    // between FAT32 and its smaller relatives.
    if at(buf, 3, b"NTFS    ") {
        return VolumeKind::Ntfs;
    }
    if at(buf, 3, b"EXFAT   ") {
        return VolumeKind::ExFat;
    }
    if at(buf, 0x52, b"FAT32   ") {
        return VolumeKind::Fat32;
    }
    if at(buf, 0x36, b"FAT16   ") {
        return VolumeKind::Fat16;
    }
    if at(buf, 0x36, b"FAT12   ") {
        return VolumeKind::Fat12;
    }

    // Nothing matched. Entropy is the only question left: a header that hides
    // itself looks like noise, and noise is what we can measure.
    if entropy(buf) >= OPAQUE_ENTROPY {
        VolumeKind::Opaque
    } else {
        VolumeKind::Unknown
    }
}

/// Read the head of a block device and identify it.
///
/// `None` when the device cannot be opened — which on a running system usually
/// means "not root", not "no such disk".
pub fn probe_device(path: &Path) -> Option<VolumeKind> {
    let mut f = File::open(path).ok()?;
    let mut buf = vec![0u8; PROBE_BYTES];
    // A device smaller than the probe window is fine: identify what arrived.
    let n = match f.read(&mut buf) {
        Ok(0) => return None,
        Ok(n) => n,
        Err(e) => {
            log::debug!("fsprobe: cannot read {}: {e}", path.display());
            return None;
        }
    };
    // One read may return short; top it up rather than judging a partial head.
    let mut total = n;
    while total < buf.len() {
        match f.read(&mut buf[total..]) {
            Ok(0) => break,
            Ok(n) => total += n,
            Err(_) => break,
        }
    }
    buf.truncate(total);
    Some(identify(&buf))
}

/// Identify a block device by name (`sda`, `nvme0n1`).
///
/// The name is checked rather than trusted. Today's only caller walks sysfs,
/// where the kernel chose the names — but this builds a path out of a string,
/// and a caller that one day passes something with a `/` in it would be
/// reading a file somewhere else entirely. Cheap to refuse here, invisible to
/// find later.
pub fn probe_block(name: &str) -> Option<VolumeKind> {
    let plausible = !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');
    if !plausible {
        log::warn!("fsprobe: refusing to probe a device named {name:?}");
        return None;
    }
    probe_device(Path::new(&format!("/dev/{name}")))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a probe buffer with `magic` planted at `offset`.
    fn head_with(offset: usize, magic: &[u8]) -> Vec<u8> {
        let mut b = vec![0u8; PROBE_BYTES];
        b[offset..offset + magic.len()].copy_from_slice(magic);
        b
    }

    #[test]
    fn a_device_name_cannot_become_a_path() {
        // Nothing passes user input here today. This is the guard that keeps
        // it that way, because "/dev/{name}" is one careless caller away from
        // reading an arbitrary file.
        for bad in ["../etc/shadow", "sda/../../proc/self/mem", "", "sd a", "sda\n"] {
            assert!(probe_block(bad).is_none(), "{bad:?} was accepted");
        }
        // Real names still work their way through (the probe itself returns
        // None without permission, which is a different answer).
        let _ = probe_block("sda");
        let _ = probe_block("nvme0n1");
    }

    #[test]
    fn every_signature_is_recognised_at_its_own_offset() {
        let cases: &[(usize, &[u8], VolumeKind)] = &[
            (0, b"LUKS\xba\xbe\x00\x01", VolumeKind::Luks1),
            (0, b"LUKS\xba\xbe\x00\x02", VolumeKind::Luks2),
            (0x438, &[0x53, 0xEF], VolumeKind::Ext),
            (0x10040, b"_BHRfS_M", VolumeKind::Btrfs),
            (0, b"XFSB", VolumeKind::Xfs),
            (0x400, &[0x10, 0x20, 0xF5, 0xF2], VolumeKind::F2fs),
            (3, b"NTFS    ", VolumeKind::Ntfs),
            (3, b"EXFAT   ", VolumeKind::ExFat),
            (0x52, b"FAT32   ", VolumeKind::Fat32),
            (0x36, b"FAT16   ", VolumeKind::Fat16),
            (0x36, b"FAT12   ", VolumeKind::Fat12),
            (0x400, b"H+", VolumeKind::HfsPlus),
            (0x400, b"HX", VolumeKind::HfsPlus),
            (0x400, b"BD", VolumeKind::Hfs),
            (0x20, b"NXSB", VolumeKind::Apfs),
            (0x8001, b"CD001", VolumeKind::Iso9660),
            (0x8001, b"NSR03", VolumeKind::Udf),
            (0, b"hsqs", VolumeKind::Squashfs),
            (0xFF6, b"SWAPSPACE2", VolumeKind::Swap),
            (0x200, b"LABELONE", VolumeKind::Lvm2),
            (0x20000, &[0x0c, 0xb1, 0xba, 0x00], VolumeKind::Zfs),
        ];
        for (offset, magic, want) in cases {
            let got = identify(&head_with(*offset, magic));
            assert_eq!(got, *want, "{:?} at {offset:#x}", want.label());
        }
    }

    #[test]
    fn luks_versions_are_distinguished() {
        assert_eq!(identify(&head_with(0, b"LUKS\xba\xbe\x00\x01")), VolumeKind::Luks1);
        assert_eq!(identify(&head_with(0, b"LUKS\xba\xbe\x00\x02")), VolumeKind::Luks2);
        assert!(VolumeKind::Luks2.is_encrypted());
        assert!(!VolumeKind::Luks2.is_mountable_filesystem());
    }

    #[test]
    fn a_veracrypt_style_header_reads_as_opaque_not_unknown() {
        // No signature anywhere, and ciphertext-grade entropy. This is the case
        // signature matching cannot solve, because there is nothing to match.
        let mut rng: u64 = 0x2545F4914F6CDD1D;
        let random: Vec<u8> = (0..PROBE_BYTES)
            .map(|_| {
                rng ^= rng << 13;
                rng ^= rng >> 7;
                rng ^= rng << 17;
                (rng >> 24) as u8
            })
            .collect();
        assert!(entropy(&random) > 7.9, "fixture is not random enough");
        assert_eq!(identify(&random), VolumeKind::Opaque);
        assert!(VolumeKind::Opaque.is_encrypted());
        // And the wording must not accuse: a wiped disk looks identical.
        let note = VolumeKind::Opaque.note().unwrap();
        assert!(note.contains("VeraCrypt"), "{note}");
        assert!(note.contains("borrado"), "{note}");
    }

    #[test]
    fn a_blank_disk_is_unknown_not_opaque() {
        // All zeros is the opposite of ciphertext: an empty disk must not be
        // reported as a hidden encrypted container.
        let blank = vec![0u8; PROBE_BYTES];
        assert_eq!(entropy(&blank), 0.0);
        assert_eq!(identify(&blank), VolumeKind::Unknown);
        assert!(!VolumeKind::Unknown.is_encrypted());
    }

    #[test]
    fn low_entropy_junk_is_not_mistaken_for_encryption() {
        // Repetitive data with no signature: structured, so not opaque.
        let repetitive: Vec<u8> = (0..PROBE_BYTES).map(|i| (i % 4) as u8).collect();
        assert!(entropy(&repetitive) < OPAQUE_ENTROPY);
        assert_eq!(identify(&repetitive), VolumeKind::Unknown);
    }

    #[test]
    fn a_short_read_does_not_panic_or_misidentify() {
        // A device smaller than the probe window, and a truncated one.
        assert_eq!(identify(&[]), VolumeKind::Unknown);
        assert_eq!(identify(b"LUKS"), VolumeKind::Unknown, "partial magic must not match");
        assert_eq!(identify(b"LUKS\xba\xbe\x00\x02"), VolumeKind::Luks2);
        // A 512-byte head cannot reach the ext offset; that must not panic.
        let tiny = vec![0u8; 512];
        assert_eq!(identify(&tiny), VolumeKind::Unknown);
    }

    #[test]
    fn encrypted_and_mountable_are_disjoint_and_labelled() {
        for k in [
            VolumeKind::Luks1, VolumeKind::Luks2, VolumeKind::Ext, VolumeKind::Btrfs,
            VolumeKind::Xfs, VolumeKind::F2fs, VolumeKind::Ntfs, VolumeKind::ExFat,
            VolumeKind::Fat32, VolumeKind::Fat16, VolumeKind::Fat12, VolumeKind::Hfs,
            VolumeKind::HfsPlus, VolumeKind::Apfs, VolumeKind::Iso9660, VolumeKind::Udf,
            VolumeKind::Squashfs, VolumeKind::Swap, VolumeKind::Lvm2, VolumeKind::Zfs,
            VolumeKind::Opaque, VolumeKind::Unknown,
        ] {
            assert!(!k.label().is_empty(), "{k:?} has no label");
            assert!(
                !(k.is_encrypted() && k.is_mountable_filesystem()),
                "{k:?} cannot be both a sealed container and a ready filesystem"
            );
        }
    }
}
