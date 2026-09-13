// SPDX-License-Identifier: Apache-2.0
//!
//! Local model inventory.
//!
//! `[llm.local].model_path` may point to a **single** `.gguf` file or to a
//! **directory** holding several models (e.g. `/opt/sysentinel/models/`).
//! When it's a directory we scan it **recursively** for:
//!
//! * main model files — `*.gguf` (any local model; vision-capable local
//!   models are supplied by llama.cpp as a base model + `-mmproj-` projector),
//! * vision projectors — files whose name contains `-mmproj-` (the `.gguf`
//!   llama.cpp uses to attach an image encoder to a local base model),
//! * MTP model files — `*.mtp` (multi-token-prediction companions).
//!
//! Each main model is paired with the projector / MTP files that share its
//! name prefix, so `/models` and `/model <name>` can flip between GGUF models
//! live, and the `local` backend knows where the vision/MTP companions live.
//!
//! Note: cloud vision models (e.g. `deepseek-v4-flash-vision-exp` on the
//! DeepSeek API) are NOT projectors — they are ordinary model names handled
//! by the API backends; see `/model <name>`.

use crate::config::LocalLlmConfig;
use anyhow::{bail, Result};
use std::path::{Path, PathBuf};

/// A main model plus the auxiliary files that belong to it.
#[derive(Debug, Clone)]
pub struct ModelEntry {
    /// File stem without extension, e.g. `deepseek-v4-flash-vision-exp`.
    pub name: String,
    pub path: PathBuf,
    pub size_mb: u64,
    /// Vision projector (`*-mmproj-*.gguf`) sharing the model's prefix.
    pub projector: Option<PathBuf>,
    /// Multi-token-prediction companion (`*.mtp`) sharing the prefix.
    pub mtp: Option<PathBuf>,
}

fn stem_of(path: &Path) -> String {
    path.file_stem()
        .map(|s| s.to_string_lossy().to_string())
        .unwrap_or_default()
}

/// Vision projectors are named `mmproj-….gguf`, `…-mmproj-….gguf` or just
/// `mmproj-F32.gguf` (as in gemma-packages).
fn is_projector(stem: &str) -> bool {
    let lower = stem.to_ascii_lowercase();
    lower.starts_with("mmproj") || lower.contains("-mmproj") || lower.ends_with("mmproj")
}

/// MTP companions are `*.mtp` or GGUF named `mtp-<model>.gguf`.
fn is_mtp(stem: &str) -> bool {
    let lower = stem.to_ascii_lowercase();
    lower.starts_with("mtp")
        || lower.contains("-mtp-")
        || lower.ends_with("-mtp")
}

fn size_mb(path: &Path) -> u64 {
    std::fs::metadata(path)
        .map(|m| m.len() / (1024 * 1024))
        .unwrap_or(0)
}

/// Recursively walk `root`, classifying `.gguf` / `.mtp` files.
fn walk(root: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(root) else {
        return;
    };
    for entry in rd.flatten() {
        let path = entry.path();
        if path.is_dir() {
            walk(&path, out);
        } else if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if ext.eq_ignore_ascii_case("gguf") || ext.eq_ignore_ascii_case("mtp") {
                out.push(path);
            }
        }
    }
}

/// Discover every main model under `model_path` (a file, or a directory that
/// is walked recursively). Projectors/MTP are attached to the main model that
/// shares their **directory** — that's how gguf packages are laid out (each
/// model in its own folder with its `mmproj-…` / `mtp-…` companions).
pub fn scan(model_path: &Path) -> Vec<ModelEntry> {
    let mut files = Vec::new();
    if model_path.is_dir() {
        walk(model_path, &mut files);
    } else if model_path.is_file() {
        files.push(model_path.to_path_buf());
    }

    let mut mains: Vec<ModelEntry> = Vec::new();
    let mut projectors: Vec<PathBuf> = Vec::new();
    let mut mtps: Vec<PathBuf> = Vec::new();

    for f in files {
        let stem = stem_of(&f);
        if is_mtp(&stem) {
            mtps.push(f);
        } else if is_projector(&stem) {
            projectors.push(f);
        } else {
            let size = size_mb(&f);
            mains.push(ModelEntry {
                name: stem,
                path: f,
                size_mb: size,
                projector: None,
                mtp: None,
            });
        }
    }

    for m in &mut mains {
        let Some(dir) = m.path.parent() else { continue };
        if let Some(p) = projectors.iter().find(|p| p.parent() == Some(dir)) {
            m.projector = Some(p.clone());
        }
        if let Some(t) = mtps.iter().find(|t| t.parent() == Some(dir)) {
            m.mtp = Some(t.clone());
        }
    }

    mains.sort_by(|a, b| a.name.cmp(&b.name));
    mains
}

/// Resolve the main model file to load for the `local` backend.
///
/// * `model_path` is a file → that file.
/// * `model_path` is a directory → the model named `selected`, or the single
///   discovered model, or an error explaining `/models` exists.
#[cfg_attr(not(feature = "local-llm"), allow(dead_code))]
pub fn resolve_main_path(
    cfg: &LocalLlmConfig,
    selected: Option<&str>,
) -> Result<PathBuf> {
    let p = Path::new(&cfg.model_path);
    if p.is_file() {
        return Ok(p.to_path_buf());
    }
    if !p.is_dir() {
        bail!(
            "no such model path: {} (set `[llm.local] model_path` to a .gguf file \
             or a directory of models)",
            cfg.model_path
        );
    }

    let mut entries = scan(p);
    let exact = |want: &str| {
        entries
            .iter()
            .find(|e| e.name == want || e.name.starts_with(&format!("{want}-")))
            .map(|e| e.path.clone())
    };

    match selected.and_then(exact) {
        Some(path) => Ok(path),
        None if entries.len() == 1 => Ok(entries[0].path.clone()),
        None => {
            let names: Vec<String> = entries.iter().map(|e| e.name.clone()).collect();
            if names.is_empty() {
                bail!(
                    "no .gguf models found under {} (check the recursive scan with \
                     `/models`)",
                    cfg.model_path
                );
            }
            entries.sort_by_key(|e| e.size_mb);
            let picked = &entries[0];
            log::warn!(
                "multiple local models found ({}), auto-selected smallest: {} ({} MB) — \
                 change with `/model local <name>`",
                names.len(),
                picked.name,
                picked.size_mb,
            );
            Ok(picked.path.clone())
        }
    }
}

/// Resolve the auxiliary vision/MTP companions for the selected model.
/// Returns `(projector, mtp)` as `None` when absent.
#[cfg_attr(not(feature = "local-llm"), allow(dead_code))]
pub fn resolve_extras(
    cfg: &LocalLlmConfig,
    selected: Option<&str>,
) -> Result<(Option<PathBuf>, Option<PathBuf>)> {
    let p = Path::new(&cfg.model_path);
    let root: Option<PathBuf> = if p.is_dir() {
        Some(p.to_path_buf())
    } else {
        p.parent().map(|d| d.to_path_buf())
    };
    let entries = match &root {
        Some(dir) => scan(dir),
        None => Vec::new(),
    };

    // For a bare-file path, pin to exactly that file's entry (its companions
    // live in the same folder); for a directory, honour `/model <name>`.
    let target = if p.is_file() {
        entries.iter().position(|e| e.path == p)
    } else {
        selected
            .and_then(|s| {
                entries.iter().position(|e| e.name == s || e.name.starts_with(&format!("{s}-")))
            })
            .or_else(|| (entries.len() == 1).then_some(0))
    };

    match target {
        Some(i) => Ok((entries[i].projector.clone(), entries[i].mtp.clone())),
        None => Ok((None, None)),
    }
}

/// The ready-to-run `llama-server` command for `entry`, wiring its own mmproj
/// (vision) and mtp (draft) companions — the exact structure llama.cpp v10335
/// expects: `-md <mtp.gguf>` + `--spec-type draft-mtp` for MTP, `-mm` for the
/// projector.
pub fn server_command(entry: &ModelEntry, ctx: u32, ngl: u32) -> String {
    let mut s = format!("llama-server -m {}", entry.path.display());
    if let Some(p) = &entry.projector {
        s.push_str(&format!(" -mm {}", p.display()));
    }
    if let Some(m) = &entry.mtp {
        s.push_str(&format!(
            " -md {} --spec-type draft-mtp --spec-draft-n-max 3",
            m.display()
        ));
    }
    s.push_str(&format!(" -ngl {ngl} -c {ctx} --port 8080"));
    s
}

/// Find an entry by loose name match (`/model <name>`).
pub fn find<'a>(entries: &'a [ModelEntry], want: &str) -> Option<&'a ModelEntry> {
    entries
        .iter()
        .find(|e| e.name == want || e.name.starts_with(&format!("{want}-")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_real_layout() {
        let dir = std::env::temp_dir().join(format!("sysentinel-models-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);

        // Per-model folder like the user's gemma package:
        std::fs::create_dir_all(dir.join("gemma-4-12b-it-Q4_K_M")).unwrap();
        std::fs::write(
            dir.join("gemma-4-12b-it-Q4_K_M").join("gemma-4-12b-it-Q4_K_M.gguf"),
            vec![0u8; 1024 * 1024],
        )
        .unwrap();
        std::fs::write(
            dir.join("gemma-4-12b-it-Q4_K_M").join("mmproj-F32.gguf"),
            vec![0u8; 1024 * 1024],
        )
        .unwrap();
        std::fs::write(
            dir.join("gemma-4-12b-it-Q4_K_M").join("mtp-gemma-4-12b-it.gguf"),
            vec![0u8; 1024 * 1024],
        )
        .unwrap();

        // Vision package whose mmproj shares the model stem:
        std::fs::create_dir_all(dir.join("model-vision-Q8_K_P")).unwrap();
        std::fs::write(
            dir.join("model-vision-Q8_K_P").join("model-vision-Q8_K_P.gguf"),
            vec![0u8; 1024 * 1024],
        )
        .unwrap();
        std::fs::write(
            dir.join("model-vision-Q8_K_P")
                .join("mmproj-model-vision-f16.gguf"),
            vec![0u8; 1024 * 1024],
        )
        .unwrap();

        // Flat model at the root, no companions:
        std::fs::write(dir.join("qwen-q4_0.gguf"), vec![0u8; 1024 * 1024]).unwrap();

        let entries = scan(&dir);
        assert_eq!(entries.len(), 3, "mmproj/mtp must not count as main models");

        let gemma = entries.iter().find(|e| e.name.contains("4-12b-it")).unwrap();
        assert!(gemma.projector.is_some(), "gemma pairs with mmproj-F32 in its dir");
        assert!(gemma.mtp.is_some(), "gemma pairs with mtp-* in its dir");

        let vision = entries.iter().find(|e| e.name.contains("model-vision")).unwrap();
        assert!(vision.projector.is_some(), "vision model pairs with its mmproj");

        let flat = entry_by_name(&entries, "qwen-q4_0");
        assert!(flat.projector.is_none() && flat.mtp.is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn scans_real_ai_models_folder_if_present() {
        // Probe a real models folder on this dev machine.
        let candidates = [Path::new("/opt/sysentinel/models")];
        let Some(dir) = candidates.iter().find(|d| d.is_dir()) else {
            return;
        };
        let entries = scan(dir);
        assert!(
            !entries.is_empty(),
            "{} should hold models",
            dir.display()
        );
        let names: Vec<String> = entries.iter().map(|e| e.name.clone()).collect();
        for e in &entries {
            assert_eq!(e.name, stem_of(&e.path), "names derive from the file stem");
            eprintln!("  model: {}", e.name);
        }
        eprintln!("  total: {} models: {}", entries.len(), names.join(", "));
    }

    fn entry_by_name<'a>(entries: &'a [ModelEntry], name: &str) -> &'a ModelEntry {
        entries.iter().find(|e| e.name == name).unwrap()
    }
}