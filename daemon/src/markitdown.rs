// SPDX-License-Identifier: Apache-2.0
//!
//! Optional document-to-Markdown conversion via Microsoft's `markitdown`.
//!
//! # Why it exists
//!
//! When the owner attaches a PDF, a Word document, or a picture of a page from
//! the phone, the expensive way to let the AI read it is to ship the raw file
//! to a vision model — every page is an image, and images are the priciest
//! tokens a provider sells. `markitdown` extracts the *text* locally and hands
//! the model Markdown instead, which for anything that is really text (a PDF, a
//! .docx, a spreadsheet, a slide deck, a scanned page with selectable text) is
//! a fraction of the tokens and often a better result.
//!
//! # It is a toggle, and off is a valid answer
//!
//! The phone sends a `markitdown` flag per attachment. It does not fit
//! everything — a photo of a person is a face to recognise, not a page to
//! transcribe — so the owner chooses per file. When the flag is off, or the
//! tool is not installed, this module says so and the caller decides what to do
//! with the raw file rather than pretending.
//!
//! # Install
//!
//! `markitdown` is a Python package, not something this daemon bundles:
//! `pip install markitdown` (or `pipx install markitdown`). [`available`]
//! reports whether it is on `PATH`.

use anyhow::{Context, Result};
use std::path::Path;

/// Is the `markitdown` CLI on `PATH`?
pub fn available() -> bool {
    which("markitdown").is_some()
}

/// One-line note on how to get it, for the bot to forward when it is missing.
pub const INSTALL_HINT: &str =
    "MarkItDown is not installed. Get it with `pip install markitdown` \
     (or `pipx install markitdown`) so attachments can be converted to text \
     locally instead of sent as images.";

/// Convert a file to Markdown text.
///
/// Runs `markitdown <path>` and returns its stdout. The tool auto-detects the
/// format from the content, so a `.pdf`, `.docx`, `.pptx`, `.xlsx`, `.html` or
/// an image all go through the same call.
///
/// The output is capped: a runaway conversion of a huge document must not be
/// force-fed to the LLM (or the frame queue) whole. The cap is generous enough
/// for real documents and cuts pathological ones off with a marker.
pub fn convert(path: &Path) -> Result<String> {
    const MAX_CHARS: usize = 200_000;

    let out = std::process::Command::new("markitdown")
        .arg(path)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .context("spawning markitdown (is it installed? `pip install markitdown`)")?;

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr).trim().to_string();
        anyhow::bail!("markitdown failed: {stderr}");
    }

    let mut text = String::from_utf8_lossy(&out.stdout).trim().to_string();
    if text.is_empty() {
        anyhow::bail!("markitdown produced no text (a scanned page with no OCR layer, perhaps)");
    }
    if text.len() > MAX_CHARS {
        text.truncate(MAX_CHARS);
        text.push_str("\n\n[…truncated: the document was longer than the conversion cap]");
    }
    Ok(text)
}

/// Minimal `PATH` lookup, so we do not add a crate for one function.
fn which(bin: &str) -> Option<std::path::PathBuf> {
    let path = std::env::var_os("PATH")?;
    for dir in std::env::split_paths(&path) {
        let cand = dir.join(bin);
        if cand.is_file() {
            return Some(cand);
        }
    }
    None
}
