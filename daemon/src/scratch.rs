// SPDX-License-Identifier: Apache-2.0
//!
//! Private scratch space for things that must never touch `/tmp`.
//!
//! # Why this exists
//!
//! Several parts of this daemon hand a *path* to an external tool and let the
//! tool create the file: `tpm2_unseal -o …`, `audit2allow -M …`, a decompressed
//! `.ko` for `objdump`. Every one of them used a predictable name in the shared
//! `/tmp`, and that is two bugs at once:
//!
//! - **The name is guessable.** `sysentinel-unseal-<pid>.bin` can be
//!   pre-created by any local user as a symlink. The tool follows it, and the
//!   file lands wherever the attacker pointed — which for the unseal path means
//!   the 32-byte key that protects the machine fingerprint is written into
//!   somebody else's directory. `std::fs::write` follows symlinks too, so the
//!   same trick turns a decompressed module into an arbitrary file overwrite.
//! - **The mode is whatever the tool chose.** A key written by an external
//!   process with the default umask is world-readable for as long as it exists,
//!   and "we delete it straight after" is a race, not a permission.
//!
//! The daemon's unit sets `PrivateTmp=false` on purpose — the module analyser
//! has to see the *system* `/tmp` to find an intruder's dropped `.ko` — so
//! there is no sandbox quietly saving us here.
//!
//! # What replaces it
//!
//! One directory, `0700`, owned by the daemon user, under the daemon's own
//! state directory rather than anywhere shared, holding files with
//! unpredictable names. A local attacker cannot enumerate it, cannot pre-create
//! a name inside it, and cannot read what lands there — the directory
//! permission does that work, instead of hoping the tool got its umask right.
//!
//! Names come from the OS CSPRNG rather than the pid, because a pid is both
//! guessable and reused.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// Where scratch files live. Beside the rest of the daemon's state, so it
/// inherits the same ownership and the same backup/exclusion decisions.
const DEFAULT_ROOT: &str = "/var/lib/sysentinel/scratch";

/// A scratch file that removes itself.
///
/// The path is handed to whatever needs to write it. Dropping the guard
/// unlinks the file — and for anything that held a secret, [`ScratchFile::wipe`]
/// overwrites it first so the bytes do not outlive the daemon in the page
/// cache or on a copy-on-write filesystem.
#[derive(Debug)]
pub struct ScratchFile {
    path: PathBuf,
    /// Overwrite before unlinking, for paths that hold key material.
    sensitive: bool,
}

impl ScratchFile {
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The path as a `&str`, for the many tools that take one.
    pub fn as_str(&self) -> &str {
        // Names are generated from hex, and the root is ASCII, so this cannot
        // fail in practice; the fallback keeps it total rather than panicking
        // inside an error path.
        self.path.to_str().unwrap_or(DEFAULT_ROOT)
    }

    /// Mark this file as holding key material, so dropping it overwrites first.
    pub fn sensitive(mut self) -> Self {
        self.sensitive = true;
        self
    }

    /// Overwrite then unlink, now rather than at drop.
    pub fn wipe(&self) {
        if let Ok(len) = std::fs::metadata(&self.path).map(|m| m.len()) {
            // A single pass of zeroes. On a journalling or CoW filesystem this
            // is not a guarantee that the old blocks are gone — nothing in
            // userspace can promise that — but it does clear the page cache
            // copy and the obvious read-after-delete.
            let _ = std::fs::write(&self.path, vec![0u8; len as usize]);
        }
        let _ = std::fs::remove_file(&self.path);
    }
}

impl Drop for ScratchFile {
    fn drop(&mut self) {
        if self.sensitive {
            self.wipe();
        } else {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Create the scratch directory, `0700`, and return it.
///
/// Takes the root explicitly so the tests can use a throwaway one. There is
/// deliberately no environment override: where the daemon puts unsealed keys
/// is not something a caller should be able to redirect at runtime.
fn prepare(dir: &Path) -> Result<PathBuf> {
    use std::os::unix::fs::MetadataExt;
    use std::os::unix::fs::PermissionsExt;

    let dir = dir.to_path_buf();
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("scratch: creating {}", dir.display()))?;
    // Tighten every time rather than only at creation: a directory that
    // already existed with a loose mode is exactly the case worth fixing.
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
        .with_context(|| format!("scratch: securing {}", dir.display()))?;

    // Writing secrets into something another user owns is the bug this module
    // exists to prevent, so ownership is checked rather than assumed.
    let md = std::fs::metadata(&dir)
        .with_context(|| format!("scratch: stat {}", dir.display()))?;
    anyhow::ensure!(md.is_dir(), "scratch: {} is not a directory", dir.display());
    // SAFETY: geteuid takes no arguments and cannot fail.
    let me = unsafe { libc::geteuid() };
    anyhow::ensure!(
        md.uid() == me,
        "scratch: {} belongs to uid {} and we are {me} — refusing to use it",
        dir.display(),
        md.uid()
    );
    Ok(dir)
}

/// The root actually in use: the daemon's state directory when it is writable,
/// otherwise a private directory made once for this process.
///
/// The fallback is for running outside the service — the test suite, a manual
/// `--dry-run` as an ordinary user — where `/var/lib/sysentinel` is not ours to
/// write. It is still not `/tmp/<predictable>`: the *directory* carries a
/// random name and `create_dir` fails rather than following or reusing anything
/// already at that path, so its `0700` is what protects the files inside.
fn effective_root() -> Result<PathBuf> {
    static ROOT: std::sync::OnceLock<Option<PathBuf>> = std::sync::OnceLock::new();

    if let Ok(dir) = prepare(Path::new(DEFAULT_ROOT)) {
        return Ok(dir);
    }
    let cached = ROOT.get_or_init(|| {
        let mut bytes = [0u8; 12];
        if getrandom::getrandom(&mut bytes).is_err() {
            return None;
        }
        let tag: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
        let dir = std::env::temp_dir().join(format!("sysentinel-scratch-{tag}"));
        // `create_dir`, not `create_dir_all`: it must fail if anything is
        // already there, including a symlink somebody planted.
        std::fs::create_dir(&dir).ok()?;
        prepare(&dir).ok()
    });
    cached
        .clone()
        .context("scratch: no private directory available for staging")
}

/// Reserve a scratch path that does not exist yet.
///
/// The file is *not* created: the callers hand the path to a tool that creates
/// it (`tpm2_unseal -o`, `audit2allow -M`). Safety comes from the directory
/// being `0700` and the name being unguessable, not from pre-creating a file
/// the tool would then have to be told to overwrite.
pub fn reserve(prefix: &str) -> Result<ScratchFile> {
    let root = effective_root()?;
    reserve_in(&root, prefix)
}

fn reserve_in(root: &Path, prefix: &str) -> Result<ScratchFile> {
    let dir = prepare(root)?;
    let mut bytes = [0u8; 12];
    getrandom::getrandom(&mut bytes)
        .map_err(|e| anyhow::anyhow!("scratch: no entropy for a scratch name: {e}"))?;
    let tag: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let path = dir.join(format!("{prefix}-{tag}"));
    // Unguessable, in a directory nobody else can list: a collision would mean
    // the CSPRNG repeated, and an existing file would mean somebody is already
    // inside a directory they cannot open.
    anyhow::ensure!(
        !path.exists(),
        "scratch: {} already exists — refusing to reuse it",
        path.display()
    );
    Ok(ScratchFile { path, sensitive: false })
}

/// Write `bytes` to a fresh scratch file, `0600`, failing if anything is
/// already at the path.
pub fn write(prefix: &str, bytes: &[u8]) -> Result<ScratchFile> {
    let root = effective_root()?;
    write_in(&root, prefix, bytes)
}

fn write_in(root: &Path, prefix: &str, bytes: &[u8]) -> Result<ScratchFile> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;

    let f = reserve_in(root, prefix)?;
    let mut handle = std::fs::OpenOptions::new()
        .write(true)
        // O_CREAT|O_EXCL: refuses to follow a symlink and refuses to reuse an
        // existing file, which is the whole point.
        .create_new(true)
        .mode(0o600)
        .open(f.path())
        .with_context(|| format!("scratch: creating {}", f.path().display()))?;
    handle
        .write_all(bytes)
        .with_context(|| format!("scratch: writing {}", f.path().display()))?;
    Ok(f)
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;

    /// A throwaway root per test. Passed explicitly rather than through the
    /// environment, so tests running in parallel cannot stamp on each other.
    fn temp_root(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "sysentinel-scratch-test-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn the_directory_is_owner_only_even_if_it_already_existed_wide_open() {
        let dir = temp_root("mode");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o777)).unwrap();

        let f = write_in(&dir, "thing", b"hola").unwrap();
        let dmode = std::fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(dmode, 0o700, "a pre-existing loose directory must be tightened");
        let fmode = std::fs::metadata(f.path()).unwrap().permissions().mode() & 0o777;
        assert_eq!(fmode, 0o600);
        drop(f);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn names_are_unguessable_and_never_repeat() {
        let dir = temp_root("names");
        let mut seen = std::collections::HashSet::new();
        for _ in 0..200 {
            let f = reserve_in(&dir, "seal").unwrap();
            let name = f.path().file_name().unwrap().to_string_lossy().to_string();
            // 12 random bytes of hex after the prefix: not the pid, which is
            // both guessable and reused.
            assert!(name.starts_with("seal-"), "{name}");
            assert_eq!(name.len(), "seal-".len() + 24, "{name}");
            assert!(seen.insert(name.clone()), "name repeated: {name}");
            assert!(!f.path().exists(), "reserve must not create the file");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_scratch_file_disappears_when_dropped() {
        let dir = temp_root("drop");
        let path = {
            let f = write_in(&dir, "gone", b"x").unwrap();
            f.path().to_path_buf()
        };
        assert!(!path.exists(), "drop must unlink");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_sensitive_file_is_overwritten_before_it_is_unlinked() {
        // Not a promise about the physical blocks — nothing in userspace can
        // make that promise — but the page-cache copy must be gone.
        let dir = temp_root("wipe");
        let f = write_in(&dir, "key", b"SECRET-KEY-MATERIAL").unwrap().sensitive();
        let path = f.path().to_path_buf();
        f.wipe();
        assert!(!path.exists());
        // Wiping twice, or dropping after a wipe, must not panic.
        f.wipe();
        drop(f);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn the_fallback_root_is_private_and_unguessable() {
        // Running outside the service (tests, a manual --dry-run) must not
        // silently downgrade to a predictable /tmp path.
        let f = write("fallback", b"x").expect("a scratch file is always available");
        let dir = f.path().parent().unwrap();
        let mode = std::fs::metadata(dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o700, "{}", dir.display());
        let name = dir.file_name().unwrap().to_string_lossy();
        if name.starts_with("sysentinel-scratch-") {
            // 12 random bytes of hex; nothing derived from the pid.
            assert_eq!(name.len(), "sysentinel-scratch-".len() + 24, "{name}");
            assert!(!name.contains(&std::process::id().to_string()), "{name}");
        }
    }

    #[test]
    fn a_directory_owned_by_someone_else_is_refused() {
        // /tmp is owned by root and we are not, in the environment where this
        // matters. Skip when the test happens to run as root, where the check
        // cannot trigger and proves nothing.
        // SAFETY: geteuid takes no arguments and cannot fail.
        if unsafe { libc::geteuid() } == 0 {
            return;
        }
        // /tmp is root-owned and 1777. Either check is allowed to be the one
        // that fires — tightening its mode fails first for a non-root process —
        // but it must never come back as a usable scratch root.
        let err = prepare(Path::new("/tmp")).expect_err("must refuse a directory we do not own");
        let said = format!("{err:#}");
        assert!(
            said.contains("refusing to use") || said.contains("securing"),
            "{said}"
        );
    }

    #[test]
    fn an_existing_file_is_never_written_through() {
        // O_EXCL is what must refuse a pre-existing path (a planted symlink,
        // say), not a name check.
        let dir = temp_root("excl");
        let f = reserve_in(&dir, "collide").unwrap();
        std::fs::write(f.path(), b"someone else was here").unwrap();
        use std::os::unix::fs::OpenOptionsExt;
        let again = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(f.path());
        assert!(again.is_err(), "create_new must refuse an existing path");
        drop(f);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
