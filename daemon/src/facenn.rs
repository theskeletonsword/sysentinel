// SPDX-License-Identifier: Apache-2.0
//!
//! Neural face verification for the daemon — the glibc side of the pair.
//!
//! # Why this exists
//!
//! Enrollment already stored two very different things per face: a pair of
//! 64-bit perceptual hashes (pHash + wHash) and a 128-D MobileFaceNet
//! embedding produced by `sysentinel-face`. Only the initramfs ever used the
//! embedding. The daemon — with a full system underneath it — decided live
//! logins with the perceptual hashes alone.
//!
//! That is the weaker half, and not merely by degree. A perceptual hash
//! describes a *picture*, not a face: it reduces the whole frame, background
//! included, to 64 bits of low-frequency structure. Two consequences follow,
//! and the second is the dangerous one:
//!
//! - The same person under different light or at a different angle moves far
//!   enough in hash space to read as a stranger.
//! - **A different person in the same chair, against the same wall, at the same
//!   framing, does not.** The hash is dominated by the scene, so an intruder
//!   sitting where the owner sits is exactly the case it handles worst — and
//!   exactly the case this daemon exists to catch.
//!
//! An embedding comparison has no such failure mode: it is computed from an
//! aligned 112×112 crop of the face itself, so the background contributes
//! nothing.
//!
//! So the daemon now asks the network first and keeps the hashes as the
//! fallback for hosts where the tool is not installed. Both verdicts say which
//! method produced them, because they are not equally strong evidence.
//!
//! # musl inside, glibc outside
//!
//! `sysentinel-face` is built static-musl so it can run inside the initramfs,
//! where there is no libc to load. The daemon is a normal glibc build. Rather
//! than compile the models into the daemon a second time, it *runs the same
//! binary* — a static executable runs perfectly well on a glibc host, so one
//! artifact serves both worlds and the two paths can never disagree about what
//! a face is. It costs a fork per verification, which against a login event is
//! nothing.
//!
//! # Thresholds
//!
//! Cosine similarity over L2-normalised embeddings: 1.0 is the same image,
//! 0.0 is unrelated. Measured on this project's own models, an identical image
//! scores 1.000000, while six genuinely different faces scored −0.03, 0.0005,
//! 0.069, 0.10, 0.10 and **0.46**.
//!
//! That 0.46 is why [`NnThresholds::default`] does not sit at the 0.45 often
//! quoted for MobileFaceNet: a stranger already reached it here. `owner` is set
//! at 0.62 and `ambiguous` at 0.50, both above every impostor observed.
//!
//! Be aware of what that sample does *not* contain: several impostors but no
//! second photograph of the same person, so the genuine-match distribution was
//! not measured, only its upper bound of 1.0. Anyone deploying this should
//! enroll a few times and check where their own repeat photographs land, then
//! tune `[face] nn_owner` / `nn_ambiguous` to taste. The defaults err towards
//! calling a real owner "ambiguous" rather than calling a stranger the owner.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::config::FaceConfig;
use crate::fhash::FaceStore;

/// How the daemon decided. Distinct from [`crate::fhash::FaceVerdict`] because
/// it carries the outcomes a detector can produce that a hash cannot.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NnVerdict {
    /// Cosine at or above the owner threshold.
    Owner,
    /// Between the two thresholds — worth a human look.
    Ambiguous,
    /// A face was found and it is not an enrolled one.
    Unknown,
    /// The detector found no face at all in the frame.
    NoFace,
}

/// Cosine thresholds. See the module docs for where the numbers come from.
#[derive(Debug, Clone, Copy)]
pub struct NnThresholds {
    /// At or above this, the probe is the owner.
    pub owner: f32,
    /// At or above this (but below `owner`), it is a possible owner.
    pub ambiguous: f32,
}

impl Default for NnThresholds {
    fn default() -> Self {
        Self { owner: 0.62, ambiguous: 0.50 }
    }
}

/// What one verification produced.
#[derive(Debug, Clone)]
pub struct NnOutcome {
    pub verdict: NnVerdict,
    /// Best cosine against any enrolled template. `None` when no face was found.
    pub best_cosine: Option<f32>,
    /// Faces the detector found in the frame.
    pub faces_detected: usize,
    /// Detector confidence for the face that produced `best_cosine`.
    pub detection_score: Option<f32>,
}

impl NnOutcome {
    /// A second face in frame is its own signal: someone is standing behind
    /// whoever is at the keyboard.
    pub fn extra_faces(&self) -> usize {
        self.faces_detected.saturating_sub(1)
    }

    /// One line for the Telegram alert. Always names the method, since a
    /// network verdict and a hash verdict are not equal evidence.
    pub fn verdict_text(&self) -> String {
        let cos = match (self.best_cosine, self.detection_score) {
            (Some(c), Some(d)) => format!("coseno {c:.3}, detección {d:.2}"),
            (Some(c), None) => format!("coseno {c:.3}"),
            (None, Some(d)) => format!("sin coseno, detección {d:.2}"),
            (None, None) => "sin coseno".to_string(),
        };
        let mut line = match self.verdict {
            NnVerdict::Owner => format!("👤 Cara del dueño — red neuronal, {cos}"),
            NnVerdict::Ambiguous => {
                format!("👤 Rostro parecido al dueño, no concluyente — red neuronal, {cos}")
            }
            NnVerdict::Unknown => {
                format!("🚨 Rostro **NO registrado** — red neuronal, {cos}")
            }
            NnVerdict::NoFace => {
                "👤 Ninguna cara detectada en el encuadre — red neuronal".to_string()
            }
        };
        if self.extra_faces() > 0 {
            line.push_str(&format!(
                "\n⚠️ {} cara(s) más en el encuadre — alguien acompaña",
                self.extra_faces()
            ));
        }
        line
    }
}

/// Where the static face tool lives, and whether it is usable.
pub fn tool_path(cfg: &FaceConfig) -> PathBuf {
    PathBuf::from(&cfg.tool_path)
}

/// Whether neural verification can run at all on this host.
pub fn available(cfg: &FaceConfig) -> bool {
    tool_path(cfg).is_file()
}

/// JSON the tool prints for `--embed`. Only the fields we consume.
#[derive(serde::Deserialize)]
struct ToolOut {
    #[serde(default)]
    faces: Vec<ToolFace>,
}

#[derive(serde::Deserialize)]
struct ToolFace {
    #[serde(default)]
    score: f32,
    #[serde(default)]
    matched: Option<ToolMatch>,
}

#[derive(serde::Deserialize)]
struct ToolMatch {
    #[serde(default)]
    cosine: f32,
}

/// Verify `probe` against the enrolled templates with the neural pipeline.
///
/// `None` means "could not run" — tool missing, no enrolled embeddings, or the
/// tool failed — and the caller should fall back to perceptual hashing. It does
/// *not* mean "not the owner"; that is [`NnVerdict::Unknown`].
///
/// The template database is written to a private temporary file for the child
/// to read and removed immediately afterwards. It holds embeddings only, never
/// pixels.
pub fn verify(cfg: &FaceConfig, store: &FaceStore, probe: &Path) -> Option<NnOutcome> {
    let tool = tool_path(cfg);
    if !tool.is_file() {
        log::debug!("face: {} absent — falling back to perceptual hashes", tool.display());
        return None;
    }
    if !store.entries.iter().any(|e| e.embedding.is_some()) {
        log::debug!("face: no enrolled embeddings — falling back to perceptual hashes");
        return None;
    }

    let db_path = std::env::temp_dir().join(format!("sysentinel-face-db-{}.json", std::process::id()));
    let db = store.esp_db();
    if let Err(e) = write_private(&db_path, db.as_bytes()) {
        log::warn!("face: cannot stage the template DB: {e}");
        return None;
    }

    // `--thresh -1` so the tool always reports its best match rather than
    // applying a cut of its own: the thresholds that matter are ours, and a
    // low cosine is information, not an absence.
    let out = Command::new(&tool)
        .arg("--embed")
        .arg(probe)
        .arg("--match")
        .arg(&db_path)
        .arg("--thresh")
        .arg("-1")
        .output();
    let _ = std::fs::remove_file(&db_path);

    let out = match out {
        Ok(o) => o,
        Err(e) => {
            log::warn!("face: cannot run {}: {e}", tool.display());
            return None;
        }
    };
    if !out.status.success() {
        log::warn!(
            "face: {} failed ({}): {}",
            tool.display(),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        );
        return None;
    }

    let parsed: ToolOut = match serde_json::from_slice(&out.stdout) {
        Ok(p) => p,
        Err(e) => {
            log::warn!("face: unparseable output from {}: {e}", tool.display());
            return None;
        }
    };

    Some(classify(&parsed, thresholds(cfg)))
}

/// Thresholds from config, clamped to the meaningful cosine range and kept in
/// order, so a mistyped config cannot invert the verdict ladder.
pub fn thresholds(cfg: &FaceConfig) -> NnThresholds {
    let owner = cfg.nn_owner.clamp(-1.0, 1.0);
    let ambiguous = cfg.nn_ambiguous.clamp(-1.0, owner);
    NnThresholds { owner, ambiguous }
}

/// Turn the tool's report into a verdict. Split out so the decision is testable
/// without a camera, a model or a child process.
fn classify(out: &ToolOut, thr: NnThresholds) -> NnOutcome {
    if out.faces.is_empty() {
        return NnOutcome {
            verdict: NnVerdict::NoFace,
            best_cosine: None,
            faces_detected: 0,
            detection_score: None,
        };
    }

    // The strongest match across every face in frame: if the owner is present
    // at all, this is the owner's frame — an extra stranger beside them is
    // reported separately rather than overriding the identification.
    let best = out
        .faces
        .iter()
        .max_by(|a, b| {
            let ca = a.matched.as_ref().map_or(f32::MIN, |m| m.cosine);
            let cb = b.matched.as_ref().map_or(f32::MIN, |m| m.cosine);
            ca.total_cmp(&cb)
        })
        .expect("faces is non-empty");

    let cosine = best.matched.as_ref().map(|m| m.cosine);
    let verdict = match cosine {
        Some(c) if c >= thr.owner => NnVerdict::Owner,
        Some(c) if c >= thr.ambiguous => NnVerdict::Ambiguous,
        // A detected face with no match at all is still a detected face.
        _ => NnVerdict::Unknown,
    };

    NnOutcome {
        verdict,
        best_cosine: cosine,
        faces_detected: out.faces.len(),
        detection_score: Some(best.score),
    }
}

/// Write owner-only (0600), creating the file fresh so a pre-existing symlink
/// cannot redirect the template database somewhere readable.
fn write_private(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let _ = std::fs::remove_file(path);
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    f.write_all(bytes)
}

/// The daemon's live verdict line: the network when it can run, the perceptual
/// hashes when it cannot, and always a word about which one spoke.
///
/// `None` when nothing is enrolled, or neither method could produce anything.
pub fn verdict_line(cfg: &FaceConfig, probe: &Path) -> Option<String> {
    let store = FaceStore::load(Path::new(&cfg.path)).ok()?;
    if store.is_empty() {
        return None;
    }

    if let Some(outcome) = verify(cfg, &store, probe) {
        return Some(outcome.verdict_text());
    }

    // Fallback: whole-image perceptual hashing. Say so — it is weaker, and a
    // reader deciding whether to trust "es el dueño" needs to know which
    // method said it.
    let thr = crate::fhash::FaceThresholds {
        p_owner:     cfg.p_owner,
        w_owner:     cfg.w_owner,
        p_ambiguous: cfg.p_ambiguous,
        w_ambiguous: cfg.w_ambiguous,
    };
    let line = crate::fhash::verdict_text(&thr, Path::new(&cfg.path), probe)?;
    Some(format!("{line}\n_(hash perceptual: sin `sysentinel-face` instalado)_"))
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    fn face(score: f32, cosine: Option<f32>) -> ToolFace {
        ToolFace { score, matched: cosine.map(|c| ToolMatch { cosine: c }) }
    }

    #[test]
    fn no_face_is_not_an_unknown_face() {
        // "nobody in frame" and "a stranger in frame" are different events and
        // must not collapse into one verdict.
        let o = classify(&ToolOut { faces: vec![] }, NnThresholds::default());
        assert_eq!(o.verdict, NnVerdict::NoFace);
        assert_eq!(o.faces_detected, 0);
        assert!(o.best_cosine.is_none());
        assert!(o.verdict_text().contains("Ninguna cara"));
    }

    #[test]
    fn thresholds_place_the_measured_samples_correctly() {
        let t = NnThresholds::default();
        // The identical-image case measured 1.000000.
        assert_eq!(classify(&ToolOut { faces: vec![face(0.83, Some(1.0))] }, t).verdict,
                   NnVerdict::Owner);
        // The six impostors measured here: none may reach Owner. The highest
        // was 0.46, which is exactly why `ambiguous` sits at 0.50.
        for imp in [-0.032_582, 0.000_487, 0.069_125, 0.101_513, 0.101_558, 0.460_905] {
            let v = classify(&ToolOut { faces: vec![face(0.8, Some(imp))] }, t).verdict;
            assert_eq!(v, NnVerdict::Unknown, "impostor at {imp} was not rejected");
        }
        // Just inside the band is ambiguous, not owner.
        assert_eq!(classify(&ToolOut { faces: vec![face(0.8, Some(0.55))] }, t).verdict,
                   NnVerdict::Ambiguous);
        // Exactly on a threshold counts as meeting it.
        assert_eq!(classify(&ToolOut { faces: vec![face(0.8, Some(0.62))] }, t).verdict,
                   NnVerdict::Owner);
        assert_eq!(classify(&ToolOut { faces: vec![face(0.8, Some(0.50))] }, t).verdict,
                   NnVerdict::Ambiguous);
    }

    #[test]
    fn a_detected_face_with_no_match_is_unknown() {
        // The DB may be empty of comparable templates; a face was still there.
        let o = classify(&ToolOut { faces: vec![face(0.9, None)] }, NnThresholds::default());
        assert_eq!(o.verdict, NnVerdict::Unknown);
        assert_eq!(o.faces_detected, 1);
        assert!(o.best_cosine.is_none());
    }

    #[test]
    fn the_owner_is_still_the_owner_with_a_stranger_behind_them() {
        // Strongest match decides the identification; the extra face is
        // reported alongside instead of masking it.
        let out = ToolOut { faces: vec![face(0.7, Some(0.10)), face(0.9, Some(0.88))] };
        let o = classify(&out, NnThresholds::default());
        assert_eq!(o.verdict, NnVerdict::Owner);
        assert_eq!(o.best_cosine, Some(0.88));
        assert_eq!(o.faces_detected, 2);
        assert_eq!(o.extra_faces(), 1);
        let text = o.verdict_text();
        assert!(text.contains("dueño"), "{text}");
        assert!(text.contains("acompaña"), "{text}");
    }

    #[test]
    fn one_face_alone_reports_no_companions() {
        let o = classify(&ToolOut { faces: vec![face(0.9, Some(0.9))] }, NnThresholds::default());
        assert_eq!(o.extra_faces(), 0);
        assert!(!o.verdict_text().contains("acompaña"));
    }

    #[test]
    fn config_thresholds_cannot_invert_the_ladder() {
        // A config that puts "ambiguous" above "owner" would otherwise make
        // Ambiguous unreachable and mislabel strangers.
        let mut cfg = crate::config::FaceConfig {
            nn_owner: 0.5,
            nn_ambiguous: 0.9,
            ..Default::default()
        };
        let t = thresholds(&cfg);
        assert!(t.ambiguous <= t.owner, "ambiguous {} > owner {}", t.ambiguous, t.owner);

        // Out-of-range values are clamped into the cosine domain.
        cfg.nn_owner = 42.0;
        cfg.nn_ambiguous = -99.0;
        let t = thresholds(&cfg);
        assert!((-1.0..=1.0).contains(&t.owner));
        assert!((-1.0..=1.0).contains(&t.ambiguous));
    }

    #[test]
    fn template_db_is_written_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("sysentinel-facenn-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("db.json");
        write_private(&p, b"{}").unwrap();
        let mode = std::fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "template DB must not be readable by others");
        // Writing again over an existing file must still succeed.
        write_private(&p, b"{\"faces\":[]}").unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "{\"faces\":[]}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// End-to-end through the real binary and the real models.
    ///
    /// Opt-in, because it needs the built tool and two photographs that this
    /// repository does not ship:
    ///
    /// ```sh
    /// SYSENTINEL_FACE_TOOL=ramdisk/target/release/sysentinel-face \
    /// SYSENTINEL_FACE_OWNER=/path/owner.jpg \
    /// SYSENTINEL_FACE_OTHER=/path/stranger.jpg \
    ///   cargo test --manifest-path daemon/Cargo.toml facenn -- --nocapture
    /// ```
    #[test]
    fn end_to_end_against_the_real_models() {
        let (Ok(tool), Ok(owner)) = (
            std::env::var("SYSENTINEL_FACE_TOOL"),
            std::env::var("SYSENTINEL_FACE_OWNER"),
        ) else {
            println!("set SYSENTINEL_FACE_TOOL and SYSENTINEL_FACE_OWNER to run this");
            return;
        };
        if !Path::new(&tool).is_file() || !Path::new(&owner).is_file() {
            println!("tool or owner photo missing — skipping");
            return;
        }

        let dir = std::env::temp_dir().join(format!("sysentinel-e2e-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = crate::config::FaceConfig {
            enabled: true,
            path: dir.join("faces.json").to_string_lossy().into_owned(),
            tool_path: tool.clone(),
            ..Default::default()
        };

        // Enroll exactly as `/face register` does: hashes plus the 128-D vector.
        let img = image::open(&owner).expect("owner photo decodes");
        let emb = {
            let out = Command::new(&tool).arg("--embed").arg(&owner).output().unwrap();
            let parsed: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
            parsed["faces"][0]["embedding"]
                .as_array()
                .map(|a| a.iter().filter_map(|v| v.as_f64().map(|f| f as f32)).collect::<Vec<_>>())
        };
        let emb = emb.expect("the owner photo must contain a detectable face");
        assert_eq!(emb.len(), 128);

        let mut store = FaceStore::load(Path::new(&cfg.path)).unwrap();
        store.add_image_with_embedding(&img, Some(emb));
        store.save().unwrap();

        // The enrolled photo must come back as the owner.
        let store = FaceStore::load(Path::new(&cfg.path)).unwrap();
        let me = verify(&cfg, &store, Path::new(&owner)).expect("verification runs");
        println!("owner vs itself: {:?} cos={:?}", me.verdict, me.best_cosine);
        assert_eq!(me.verdict, NnVerdict::Owner);
        assert!(me.best_cosine.unwrap() > 0.99, "same image should be ~1.0");

        // And a different face must not.
        if let Ok(other) = std::env::var("SYSENTINEL_FACE_OTHER") {
            if Path::new(&other).is_file() {
                let them = verify(&cfg, &store, Path::new(&other)).expect("verification runs");
                println!("stranger: {:?} cos={:?}", them.verdict, them.best_cosine);
                assert_ne!(them.verdict, NnVerdict::Owner, "a different face was accepted");
            }
        }

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_tool_declines_rather_than_accusing() {
        // With no tool installed, verify() must return None so the caller falls
        // back — never Unknown, which would read as "stranger at the keyboard".
        let cfg = crate::config::FaceConfig {
            tool_path: "/nonexistent/sysentinel-face".to_string(),
            ..Default::default()
        };
        assert!(!available(&cfg));
        let store = FaceStore::load(Path::new("/nonexistent/faces.json")).unwrap();
        assert!(verify(&cfg, &store, Path::new("/nonexistent/probe.jpg")).is_none());
    }
}
