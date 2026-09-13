// SPDX-License-Identifier: Apache-2.0
//!
//! Translations, kept out of the code.
//!
//! # The rule this enforces
//!
//! The source is English — every comment, every identifier, every string as it
//! appears in the file. Anything the *owner* reads can also exist in their own
//! language, and that copy lives in `lang/<tag>.toml` rather than in the middle
//! of a function. One language in the code, every language in one directory.
//!
//! # Why the English stays inline
//!
//! A call reads:
//!
//! ```ignore
//! t("face.owner_alone", "👤 The owner, alone")
//! ```
//!
//! The key finds the translation; the second argument *is* the English text.
//! That means the code still says what it will print — you can read the file
//! and know the output without opening a catalogue — and a missing, damaged or
//! partial `lang/` directory costs nothing at all: every lookup falls back to
//! the English that is already right there. A translation system that can
//! leave the daemon silent, or printing a key name at somebody, would be a
//! worse bug than the one it set out to fix.
//!
//! # What is not translated
//!
//! Log lines. They are written for whoever is reading `journalctl` at three in
//! the morning, they end up pasted into bug reports, and they are the one
//! surface where a single language is worth more than a familiar one. The same
//! goes for error text inside `anyhow` chains.
//!
//! The persona's own voice is not translated here either — that is the model's
//! job, and it already answers in `[persona] language`. This catalogue is for
//! the fixed text the daemon says on its own: menus, verdicts, refusals.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Where catalogues are looked for, in order.
///
/// The installed location first, then the repository layout, so a checkout
/// behaves the same as an install without anybody setting a variable.
const SEARCH: &[&str] = &["/usr/share/sysentinel/lang", "lang", "../lang"];

static CATALOGUE: OnceLock<HashMap<String, String>> = OnceLock::new();

/// Load the catalogue for `tag` (a BCP-47 tag like `es-CL`).
///
/// Called once at startup. `es-CL` looks for `es-CL.toml` and then `es.toml`,
/// so a regional tag inherits its language without every region needing a
/// file of its own.
pub fn init(tag: &str) {
    let map = load(tag).unwrap_or_default();
    if !map.is_empty() {
        log::info!("lang: {} phrase(s) loaded for '{tag}'", map.len());
    }
    let _ = CATALOGUE.set(map);
}

fn load(tag: &str) -> Option<HashMap<String, String>> {
    let tag = tag.trim().to_lowercase();
    if tag.is_empty() || tag.starts_with("en") {
        // English is what the source already says.
        return None;
    }
    let base = tag.split(['-', '_']).next().unwrap_or(&tag).to_string();
    for dir in SEARCH {
        for candidate in [format!("{tag}.toml"), format!("{base}.toml")] {
            let path = Path::new(dir).join(&candidate);
            if let Some(map) = read_catalogue(&path) {
                log::debug!("lang: using {}", path.display());
                return Some(map);
            }
        }
    }
    log::debug!("lang: no catalogue for '{tag}' — staying in English");
    None
}

fn read_catalogue(path: &PathBuf) -> Option<HashMap<String, String>> {
    let raw = std::fs::read_to_string(path).ok()?;
    match toml::from_str::<HashMap<String, String>>(&raw) {
        Ok(map) => Some(map),
        Err(e) => {
            // Loud, because a broken catalogue is a file somebody edited and
            // expects to see the effect of — silently ignoring it would look
            // like the translation simply did not apply.
            log::warn!("lang: {} is not a flat key = \"value\" table: {e}", path.display());
            None
        }
    }
}

/// The phrase for `key`, or `english` when there is no translation.
///
/// `english` is the text as it appears in the source, so this is always safe:
/// with no catalogue, a missing key, or a catalogue that failed to parse, the
/// daemon says exactly what the code says.
pub fn t(key: &str, english: &str) -> String {
    match CATALOGUE.get().and_then(|m| m.get(key)) {
        Some(translated) => translated.clone(),
        None => english.to_string(),
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_english_in_the_call_is_what_ships_without_a_catalogue() {
        // The property that makes this safe to use anywhere: no catalogue, no
        // behaviour change. A translation layer that can leave the daemon mute
        // would be worse than the untranslated text it replaced.
        assert_eq!(t("nothing.like.this", "👤 The owner, alone"), "👤 The owner, alone");
        assert_eq!(t("", "fallback"), "fallback");
    }

    #[test]
    fn a_regional_tag_falls_back_to_its_language() {
        // es-CL should find es.toml: nobody wants to ship a file per region to
        // get the same Spanish.
        let dir = std::env::temp_dir().join(format!("sysentinel-lang-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("es.toml"), "\"face.owner_alone\" = \"👤 El dueño, solo\"\n").unwrap();

        let found = read_catalogue(&dir.join("es.toml")).expect("a flat table parses");
        assert_eq!(found.get("face.owner_alone").map(String::as_str), Some("👤 El dueño, solo"));

        // A damaged catalogue is refused rather than half-applied.
        std::fs::write(dir.join("bad.toml"), "this is not toml = = =").unwrap();
        assert!(read_catalogue(&dir.join("bad.toml")).is_none());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn every_shipped_catalogue_matches_the_keys_in_the_code() {
        // A translation file drifts out of step the moment somebody renames a
        // key, and the failure is silent: the daemon quietly speaks English at
        // a person who configured Spanish. Cheaper to fail here.
        //
        // Skipped when the catalogues are not beside the source (an installed
        // build, a packaging tree) rather than failing on their absence.
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../lang");
        if !root.is_dir() {
            return;
        }

        let mut used = std::collections::BTreeSet::new();
        let src = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut stack = vec![src];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).expect("reading src").flatten() {
                let path = entry.path();
                if path.is_dir() {
                    stack.push(path);
                    continue;
                }
                if path.extension().is_some_and(|e| e == "rs") {
                    let text = std::fs::read_to_string(&path).expect("reading a source file");
                    // `lang::t(` then a string literal, possibly on the next line.
                    let mut rest = text.as_str();
                    while let Some(at) = rest.find("lang::t(") {
                        rest = &rest[at + "lang::t(".len()..];
                        if let Some(open) = rest.find('"') {
                            // Only if nothing but whitespace precedes the quote.
                            if rest[..open].chars().all(char::is_whitespace) {
                                if let Some(close) = rest[open + 1..].find('"') {
                                    used.insert(rest[open + 1..open + 1 + close].to_string());
                                }
                            }
                        }
                    }
                }
            }
        }
        assert!(!used.is_empty(), "no translated strings found — did the call shape change?");

        for entry in std::fs::read_dir(&root).expect("reading lang/").flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "toml") {
                let map = read_catalogue(&path)
                    .unwrap_or_else(|| panic!("{} does not parse", path.display()));
                let keys: std::collections::BTreeSet<String> = map.keys().cloned().collect();
                let stale: Vec<_> = keys.difference(&used).cloned().collect();
                assert!(
                    stale.is_empty(),
                    "{} translates keys the code no longer uses: {stale:?}",
                    path.display()
                );
                // The reverse is deliberately NOT an error: a partial
                // translation is a perfectly good translation, and every
                // missing key falls back to the English in the call.
            }
        }
    }

    #[test]
    fn english_never_looks_for_a_file() {
        // Asking for English is not a missing translation, it is the source.
        assert!(load("en").is_none());
        assert!(load("en-GB").is_none());
        assert!(load("").is_none());
    }
}
