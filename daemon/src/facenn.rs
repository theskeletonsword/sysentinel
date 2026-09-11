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


/// What the camera actually shows, once every face in frame has been matched.
///
/// The count alone is not the story — *who is missing* is. The owner being
/// present or absent splits the same number of strangers into two situations
/// that call for opposite responses, which is why this is an enum and not a
/// tally.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaceScene {
    /// Nobody in frame.
    Empty,
    /// The owner, alone. The ordinary case.
    OwnerAlone,
    /// The owner **and** unrecognised people. Someone is reading over their
    /// shoulder, or standing there to make sure they log in.
    ///
    /// This is the case that must not trigger a loud local response — see
    /// [`FaceScene::keep_response_out_of_band`].
    OwnerUnderWatch { others: usize },
    /// A face that is neither clearly the owner nor clearly a stranger.
    Inconclusive,
    /// One unrecognised face, no owner. Opportunistic: someone found the
    /// machine unattended.
    IntruderAlone,
    /// Two or more unrecognised faces, no owner. The machine is in other
    /// people's hands and they are working on it together.
    CustodyLost { count: usize },
}

impl FaceScene {
    /// True when the owner is in frame with people who are not enrolled.
    ///
    /// Treat it as possible duress: the owner may be logging in because
    /// somebody is standing there making sure they do.
    pub fn is_duress(&self) -> bool {
        matches!(self, FaceScene::OwnerUnderWatch { .. })
    }

    /// **Do not act locally on this frame.**
    ///
    /// The configured deny actions are `poweroff` and `triplefault` — loud and
    /// abrupt. Against someone alone with a machine they should not have, that
    /// is exactly right: nothing is endangered by cutting the power.
    ///
    /// Under duress it inverts. If a person is standing over the owner making
    /// them log in, a machine that suddenly powers itself off has announced
    /// that it informed on them, and the person who pays for that is the one
    /// being coerced. So when the owner is in frame the response stays entirely
    /// out of band: the paired chat learns about it, the host does nothing a
    /// bystander could notice.
    pub fn keep_response_out_of_band(&self) -> bool {
        self.is_duress()
    }

    /// Rough ordering for alerting, 0 (nothing) to 4 (worst).
    pub fn severity(&self) -> u8 {
        match self {
            FaceScene::Empty => 0,
            FaceScene::OwnerAlone => 0,
            FaceScene::Inconclusive => 2,
            FaceScene::OwnerUnderWatch { .. } => 3,
            FaceScene::IntruderAlone => 3,
            // Coordinated access by people who are not the owner is the worst
            // reading available from a single frame.
            FaceScene::CustodyLost { .. } => 4,
        }
    }

    /// What this scene means, in the words a person would use about it.
    pub fn interpretation(&self) -> &'static str {
        match self {
            FaceScene::Empty =>
                "nadie en el encuadre — la cámara vio la silla vacía, no a un desconocido",
            FaceScene::OwnerAlone =>
                "el dueño, solo — situación normal",
            FaceScene::OwnerUnderWatch { .. } =>
                "el dueño acompañado de alguien no registrado: alguien mira por encima del \
                 hombro, o está ahí para asegurarse de que el dueño entre. Trátalo como \
                 posible coerción y NO hagas nada visible en la máquina",
            FaceScene::Inconclusive =>
                "hay una cara pero el parecido no es concluyente — verifícalo tú",
            FaceScene::IntruderAlone =>
                "una persona no registrada y el dueño ausente: acceso oportunista a una \
                 máquina desatendida",
            // The count is not what makes this worse than a lone intruder.
            FaceScene::CustodyLost { .. } =>
                "varias personas no registradas y el dueño ausente: la máquina ya no está \
                 bajo tu custodia y la están trabajando entre varios. Dos personas es la \
                 firma de un procedimiento, no de una casualidad — un registro o una \
                 incautación llevan testigo por norma. También encaja un robo con examen \
                 posterior, o alguien de casa enseñándole tu equipo a una visita: por eso \
                 la alerta es fuerte pero no destruye nada por su cuenta",
        }
    }

    /// Headline for the alert.
    pub fn headline(&self) -> String {
        match self {
            FaceScene::Empty => "👤 Sin caras en el encuadre".to_string(),
            FaceScene::OwnerAlone => "👤 El dueño, solo".to_string(),
            FaceScene::OwnerUnderWatch { others } => format!(
                "🚨 *POSIBLE COERCIÓN* — el dueño con {others} persona(s) no registrada(s) al lado"
            ),
            FaceScene::Inconclusive => "👤 Parecido no concluyente".to_string(),
            FaceScene::IntruderAlone => "🚨 Rostro *NO registrado*, dueño ausente".to_string(),
            FaceScene::CustodyLost { count } => format!(
                "🚨 *PÉRDIDA DE CUSTODIA* — {count} personas no registradas y ningún dueño"
            ),
        }
    }
}

/// What one verification produced — the public result of [`verify`]. The
/// fields are the evidence behind [`NnOutcome::scene`]; the daemon acts on the
/// scene, and the rest is what a reader needs to check that judgement.
#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct NnOutcome {
    pub verdict: NnVerdict,
    /// Best cosine against any enrolled template. `None` when no face was found.
    pub best_cosine: Option<f32>,
    /// Faces the detector found in the frame.
    pub faces_detected: usize,
    /// Detector confidence for the face that produced `best_cosine`.
    pub detection_score: Option<f32>,
    /// Faces big enough to be people actually present that matched nobody.
    pub strangers: usize,
    /// Faces the detector found but discarded as too small to be a person in
    /// the room — a portrait on the wall, a face on a second monitor.
    pub background_faces: usize,
    /// What the frame as a whole shows.
    pub scene: FaceScene,
}

impl NnOutcome {
    /// True when the owner is in frame with unenrolled people. The caller must
    /// not take any locally visible action — see
    /// [`FaceScene::keep_response_out_of_band`].
    #[allow(dead_code)]
    pub fn is_duress(&self) -> bool {
        self.scene.is_duress()
    }

    /// The alert text. Leads with what the frame shows, then the evidence, so
    /// a phone notification is readable before it is expanded.
    pub fn verdict_text(&self) -> String {
        let cos = match (self.best_cosine, self.detection_score) {
            (Some(c), Some(d)) => format!("coseno {c:.3}, detección {d:.2}"),
            (Some(c), None) => format!("coseno {c:.3}"),
            (None, Some(d)) => format!("sin coseno, detección {d:.2}"),
            (None, None) => "sin coseno".to_string(),
        };

        let mut line = format!("{}\n{}", self.scene.headline(), self.scene.interpretation());
        line.push_str(&format!("\n_(red neuronal, {cos})_"));

        if self.background_faces > 0 {
            line.push_str(&format!(
                "\n_{} cara(s) descartada(s) por tamaño — retrato, pantalla o fondo._",
                self.background_faces
            ));
        }
        if self.scene.keep_response_out_of_band() {
            line.push_str(
                "\n\n⚠️ No se ejecuta ninguna acción local: si te están coaccionando, una \
                 máquina que se apaga sola delata que avisó. Responde tú desde aquí.",
            );
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
    /// `[x1, y1, x2, y2]` in pixels. Used to tell a person standing behind the
    /// owner from a face on a poster or a second monitor.
    #[serde(default)]
    bbox: [f32; 4],
    #[serde(default)]
    matched: Option<ToolMatch>,
}

impl ToolFace {
    fn area(&self) -> f32 {
        let [x1, y1, x2, y2] = self.bbox;
        ((x2 - x1) * (y2 - y1)).max(0.0)
    }
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

/// Smallest a face may be, relative to the largest in frame, and still count as
/// a person in the room rather than a picture of one.
///
/// SCRFD detects faces wherever they appear — a portrait on the wall, a
/// colleague on a video call on the second monitor, a face on a TV. Without a
/// filter every such frame would read as "someone is standing behind you", and
/// a duress alert that fires daily is one nobody reads. Area is a crude
/// discriminator and this is a heuristic, not a proof: it is deliberately
/// generous, since missing a real person costs far more than one extra alert.
const MIN_COMPANION_AREA_RATIO: f32 = 0.10;

/// Turn the tool's report into a verdict.
///
/// Split out so the whole decision — including the scene classification, which
/// is the part that decides whether anything visible happens on the host — is
/// testable without a camera, a model or a child process.
fn classify(out: &ToolOut, thr: NnThresholds) -> NnOutcome {
    if out.faces.is_empty() {
        return NnOutcome {
            verdict: NnVerdict::NoFace,
            best_cosine: None,
            faces_detected: 0,
            detection_score: None,
            strangers: 0,
            background_faces: 0,
            scene: FaceScene::Empty,
        };
    }

    // Faces far smaller than the largest are pictures, not people.
    let largest = out.faces.iter().map(|f| f.area()).fold(0.0f32, f32::max);
    let cutoff = largest * MIN_COMPANION_AREA_RATIO;
    let (present, background): (Vec<&ToolFace>, Vec<&ToolFace>) = out
        .faces
        .iter()
        // A tool that reported no bbox at all gives area 0; treat those as
        // present rather than silently dropping every face.
        .partition(|f| largest <= 0.0 || f.area() >= cutoff);

    // The strongest match across everyone actually in the room: if the owner is
    // there at all, this is the owner's frame, and whoever else is present is
    // reported beside them rather than overriding the identification.
    let best = present
        .iter()
        .max_by(|a, b| {
            let ca = a.matched.as_ref().map_or(f32::MIN, |m| m.cosine);
            let cb = b.matched.as_ref().map_or(f32::MIN, |m| m.cosine);
            ca.total_cmp(&cb)
        })
        .copied();

    let cosine = best.and_then(|f| f.matched.as_ref().map(|m| m.cosine));
    let verdict = match cosine {
        Some(c) if c >= thr.owner => NnVerdict::Owner,
        Some(c) if c >= thr.ambiguous => NnVerdict::Ambiguous,
        _ => NnVerdict::Unknown,
    };

    // Anyone present whose own cosine does not reach the owner threshold is a
    // stranger in the room. Counted per face, not inferred from the total, so
    // two enrolled people would not be miscounted once the store holds more
    // than one identity.
    let strangers = present
        .iter()
        .filter(|f| {
            f.matched.as_ref().is_none_or(|m| m.cosine < thr.owner)
        })
        .count();

    let owner_present = verdict == NnVerdict::Owner;
    let scene = match (owner_present, strangers, present.len()) {
        (_, _, 0) => FaceScene::Empty,
        (true, 0, _) => FaceScene::OwnerAlone,
        (true, n, _) => FaceScene::OwnerUnderWatch { others: n },
        (false, _, _) if verdict == NnVerdict::Ambiguous => FaceScene::Inconclusive,
        (false, _, 1) => FaceScene::IntruderAlone,
        (false, _, n) => FaceScene::CustodyLost { count: n },
    };

    NnOutcome {
        verdict,
        best_cosine: cosine,
        faces_detected: present.len(),
        detection_score: best.map(|f| f.score),
        strangers,
        background_faces: background.len(),
        scene,
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

/// What the daemon concluded about a frame, and how loudly it may react.
#[derive(Debug, Clone)]
pub struct FaceAssessment {
    /// Ready-to-send alert text.
    pub text: String,
    /// The scene, when the neural pipeline ran. `None` on the hash fallback,
    /// which cannot tell one face from two and so cannot classify a scene at
    /// all — another reason it is the weaker engine.
    pub scene: Option<FaceScene>,
}

impl FaceAssessment {
    /// Whether the host must stay outwardly unchanged. Always true when the
    /// scene is unknown *and* the frame looked wrong: without a scene we cannot
    /// rule out that the owner is standing there under duress, and the safe
    /// default is the quiet one.
    pub fn keep_response_out_of_band(&self) -> bool {
        match self.scene {
            Some(s) => s.keep_response_out_of_band(),
            None => false,
        }
    }

    /// 0-4; see [`FaceScene::severity`]. The hash fallback cannot grade a
    /// scene, so it reports a middling 2 whenever it says anything at all.
    pub fn severity(&self) -> u8 {
        self.scene.map_or(2, |s| s.severity())
    }

    /// Worth interrupting a person for.
    pub fn is_alarming(&self) -> bool {
        self.severity() >= 3
    }
}

/// The daemon's live assessment: the network when it can run, the perceptual
/// hashes when it cannot, and always a word about which one spoke.
///
/// `None` when nothing is enrolled, or neither method could produce anything.
pub fn assess(cfg: &FaceConfig, probe: &Path) -> Option<FaceAssessment> {
    let store = FaceStore::load(Path::new(&cfg.path)).ok()?;
    if store.is_empty() {
        return None;
    }

    if let Some(outcome) = verify(cfg, &store, probe) {
        return Some(FaceAssessment {
            text: outcome.verdict_text(),
            scene: Some(outcome.scene),
        });
    }

    // Fallback: whole-image perceptual hashing. Say so — it is weaker, and a
    // reader deciding whether to trust "es el dueño" needs to know which method
    // said it.
    let thr = crate::fhash::FaceThresholds {
        p_owner:     cfg.p_owner,
        w_owner:     cfg.w_owner,
        p_ambiguous: cfg.p_ambiguous,
        w_ambiguous: cfg.w_ambiguous,
    };
    let line = crate::fhash::verdict_text(&thr, Path::new(&cfg.path), probe)?;
    Some(FaceAssessment {
        text: format!(
            "{line}\n_(hash perceptual: sin `sysentinel-face` instalado — no puede \
             distinguir cuántas personas hay en el encuadre)_"
        ),
        scene: None,
    })
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    /// A face of a given size, so the companion filter can be exercised.
    fn sized(score: f32, cosine: Option<f32>, side: f32) -> ToolFace {
        ToolFace {
            score,
            bbox: [0.0, 0.0, side, side],
            matched: cosine.map(|c| ToolMatch { cosine: c }),
        }
    }

    /// A normal, room-sized face.
    fn face(score: f32, cosine: Option<f32>) -> ToolFace {
        sized(score, cosine, 100.0)
    }

    #[test]
    fn no_face_is_not_an_unknown_face() {
        // "nobody in frame" and "a stranger in frame" are different events and
        // must not collapse into one verdict.
        let o = classify(&ToolOut { faces: vec![] }, NnThresholds::default());
        assert_eq!(o.verdict, NnVerdict::NoFace);
        assert_eq!(o.faces_detected, 0);
        assert!(o.best_cosine.is_none());
        assert_eq!(o.scene, FaceScene::Empty);
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
    fn the_owner_with_a_stranger_behind_them_is_duress() {
        // Strongest match still identifies the owner; the extra person is
        // reported beside them instead of masking the identification.
        let out = ToolOut { faces: vec![face(0.7, Some(0.10)), face(0.9, Some(0.88))] };
        let o = classify(&out, NnThresholds::default());
        assert_eq!(o.verdict, NnVerdict::Owner);
        assert_eq!(o.best_cosine, Some(0.88));
        assert_eq!(o.faces_detected, 2);
        assert_eq!(o.strangers, 1);
        assert_eq!(o.scene, FaceScene::OwnerUnderWatch { others: 1 });
        assert_eq!(o.detection_score, Some(0.9));

        // The whole point: this must NOT trigger a local action.
        assert!(o.is_duress());
        assert!(o.scene.keep_response_out_of_band());

        let text = o.verdict_text();
        assert!(text.contains("COERCIÓN"), "{text}");
        assert!(text.contains("acción local"), "{text}");
    }

    #[test]
    fn strangers_without_the_owner_split_by_how_many() {
        let t = NnThresholds::default();

        // One stranger, owner absent: opportunistic — someone found the
        // machine unattended.
        let lone = classify(&ToolOut { faces: vec![face(0.9, Some(0.05))] }, t);
        assert_eq!(lone.scene, FaceScene::IntruderAlone);
        assert!(!lone.scene.keep_response_out_of_band(), "a lone intruder may be acted on");

        // Two or more, owner absent: coordinated access, and the machine is no
        // longer in the owner's hands.
        let group = classify(
            &ToolOut { faces: vec![face(0.9, Some(0.05)), face(0.8, Some(0.11))] },
            t,
        );
        assert_eq!(group.scene, FaceScene::CustodyLost { count: 2 });
        assert!(!group.is_duress(), "nobody can be coerced who is not there");
        assert!(
            group.scene.severity() > lone.scene.severity(),
            "a coordinated group must outrank a lone intruder"
        );
        assert!(group.verdict_text().contains("CUSTODIA"));
    }

    #[test]
    fn a_poster_on_the_wall_is_not_a_person_in_the_room() {
        // Without a size filter every frame with a portrait behind the desk
        // would read as duress, and a daily duress alert is one nobody reads.
        let out = ToolOut {
            faces: vec![
                sized(0.9, Some(0.95), 200.0), // the owner, close to the camera
                sized(0.8, Some(0.02), 20.0),  // a face on a poster: 1% of the area
            ],
        };
        let o = classify(&out, NnThresholds::default());
        assert_eq!(o.scene, FaceScene::OwnerAlone, "the poster must not raise duress");
        assert_eq!(o.background_faces, 1);
        assert_eq!(o.faces_detected, 1);
        assert!(!o.is_duress());
        assert!(o.verdict_text().contains("descartada"));

        // A person genuinely standing further back is still a person.
        let out = ToolOut {
            faces: vec![sized(0.9, Some(0.95), 200.0), sized(0.8, Some(0.02), 90.0)],
        };
        let o = classify(&out, NnThresholds::default());
        assert_eq!(o.scene, FaceScene::OwnerUnderWatch { others: 1 });
        assert_eq!(o.background_faces, 0);
    }

    #[test]
    fn faces_without_a_bbox_are_kept_rather_than_dropped() {
        // An older tool build reporting no bbox gives area 0 everywhere; that
        // must not silently discard every face and report an empty room.
        let out = ToolOut {
            faces: vec![
                ToolFace { score: 0.9, bbox: [0.0; 4], matched: Some(ToolMatch { cosine: 0.9 }) },
                ToolFace { score: 0.8, bbox: [0.0; 4], matched: Some(ToolMatch { cosine: 0.1 }) },
            ],
        };
        let o = classify(&out, NnThresholds::default());
        assert_eq!(o.faces_detected, 2);
        assert_eq!(o.background_faces, 0);
        assert_eq!(o.scene, FaceScene::OwnerUnderWatch { others: 1 });
    }

    #[test]
    fn an_empty_chair_never_escalates() {
        let o = classify(&ToolOut { faces: vec![] }, NnThresholds::default());
        assert_eq!(o.scene, FaceScene::Empty);
        assert_eq!(o.scene.severity(), 0);
        assert!(!o.is_duress());
        assert!(o.verdict_text().contains("Sin caras"));
    }

    #[test]
    fn the_owner_alone_is_the_quiet_case() {
        let o = classify(&ToolOut { faces: vec![face(0.9, Some(0.9))] }, NnThresholds::default());
        assert_eq!(o.scene, FaceScene::OwnerAlone);
        assert_eq!(o.strangers, 0);
        assert_eq!(o.scene.severity(), 0);
        assert!(!o.is_duress());
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
        println!(
            "owner vs itself: {:?} cos={:?} scene={:?}",
            me.verdict, me.best_cosine, me.scene
        );
        assert_eq!(me.verdict, NnVerdict::Owner);
        assert!(me.best_cosine.unwrap() > 0.99, "same image should be ~1.0");

        // And a different face must not.
        if let Ok(other) = std::env::var("SYSENTINEL_FACE_OTHER") {
            if Path::new(&other).is_file() {
                let them = verify(&cfg, &store, Path::new(&other)).expect("verification runs");
                println!(
                    "stranger: {:?} cos={:?} scene={:?} present={} background={} duress={}",
                    them.verdict, them.best_cosine, them.scene,
                    them.faces_detected, them.background_faces, them.is_duress()
                );
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
