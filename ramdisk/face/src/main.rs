// SPDX-License-Identifier: MIT OR GPL-2.0-or-later
//!
//! Model credits (Apache-2.0 — see ramdisk/face/models/{NOTICE,LICENSE}):
//!
//! * scrfd_2.5g_bnkps.onnx — SCRFD face *detector*: Jiankang Deng, Jianzhu
//!   Guo, Tongliang Liu, Anbang Yao, Song Zafeiriou (InsightFace); ONNX export
//!   by RuteNL/SCRFD-face-detection-ONNX (Apache-2.0).
//! * mobilefacenet.onnx — MobileFaceNet *embedder*: Sheng Chen, Yang Liu,
//!   Xiang Gao, Zhen Han (foamliu/MobileFaceNet; InsightFace) — Apache-2.0.
//!   Exported from `mobilefacenet_scripted.pt` with torch.onnx.
//!
//! sysentinel-face — local face identification over ONNX with tract, built
//! static against musl so it runs inside the initramfs (or after boot).
//!
//! # CLI
//!
//! ```text
//! sysentinel-face --info                 imprime inputs/outputs de ambos modelos
//! sysentinel-face --selfcheck            corre entradas de ceros en ambos
//! sysentinel-face --embed IMG.jpg        detect → align → 128-D embed, JSON
//!                     [--crop OUT]       (+ recorte alineado a disco)
//!                     [--match DB.json]  (+ nearest neighbour by cosine)
//!                     [--thresh 0.5]     (cosine threshold for a match)
//!                     [--brief]          (one line per face: score\tname\tcos)
//! ```
//!
//! # Exit codes
//!
//! | code | significado                                      |
//! |------|--------------------------------------------------|
//! | `0`  | ok                                               |
//! | `1`  | error de uso                                     |
//! | `2`  | load / optimisation / inference failed            |

mod align;
mod nn;
mod scrfd;

use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use tract_onnx::prelude::*;

use crate::nn::FaceNn;

const USAGE: &str = "usage:\n  sysentinel-face --info\n  sysentinel-face --selfcheck\n  sysentinel-face --embed IMG.jpg [--crop OUT.jpg] [--match DB.json] [--thresh 0.5] [--brief]";

#[derive(Serialize, Deserialize)]
struct EmbedOut {
    image: String,
    width: u32,
    height: u32,
    faces: Vec<FaceOut>,
}
#[derive(Serialize, Deserialize)]
struct FaceOut {
    score: f32,
    bbox: [f32; 4],
    kps: [[f32; 2]; 5],
    embedding: Option<Vec<f32>>,
    norm: Option<f32>,
    matched: Option<MatchOut>,
}
#[derive(Serialize, Deserialize)]
struct MatchOut {
    name: String,
    cosine: f32,
}

/// Enrolled identities — one embedding per face. Mirrored by the daemon to
/// the ESP so the initramfs can identify a suspect without any decrypted data.
#[derive(Serialize, Deserialize)]
pub struct FaceDb {
    pub faces: Vec<FaceTpl>,
}
#[derive(Serialize, Deserialize)]
pub struct FaceTpl {
    pub name: String,
    pub embedding: Vec<f32>,
}

#[derive(Default)]
struct Args {
    mode: Mode,
    image: Option<PathBuf>,
    crop: Option<PathBuf>,
    db: Option<PathBuf>,
    thresh: f32,
    brief: bool,
}
#[derive(PartialEq, Clone, Copy)]
#[derive(Default)]
enum Mode {
    #[default]
    Info,
    Selfcheck,
    Embed,
}

fn parse_args() -> Result<Args, i32> {
    let mut a = Args::default();
    let mut it = std::env::args().skip(1);
    while let Some(arg) = it.next() {
        match arg.as_str() {
            "--info" => a.mode = Mode::Info,
            "--selfcheck" => a.mode = Mode::Selfcheck,
            "--embed" => {
                a.mode = Mode::Embed;
                match it.next() {
                    Some(p) => a.image = Some(p.into()),
                    None => {
                        eprintln!("--embed needs an image path");
                        eprintln!("{USAGE}");
                        return Err(1);
                    }
                }
            }
            "--crop" => match it.next() {
                Some(p) => a.crop = Some(p.into()),
                None => {
                    eprintln!("--crop needs an output path");
                    return Err(1);
                }
            },
            "--match" => match it.next() {
                Some(p) => a.db = Some(p.into()),
                None => {
                    eprintln!("--match needs a template DB path");
                    return Err(1);
                }
            },
            "--thresh" => match it.next().and_then(|s| s.parse::<f32>().ok()) {
                Some(t) if t.is_finite() => a.thresh = t,
                _ => {
                    eprintln!("--thresh needs a float");
                    return Err(1);
                }
            },
            "--brief" => a.brief = true,
            "-h" | "--help" => {
                println!("{USAGE}");
                std::process::exit(0);
            }
            other => {
                eprintln!("sysentinel-face: unknown option: {other}");
                eprintln!("{USAGE}");
                return Err(1);
            }
        }
    }
    Ok(a)
}

fn main() {
    let args = match parse_args() {
        Ok(a) => a,
        Err(code) => std::process::exit(code),
    };
    let rc = match args.mode {
        Mode::Info => run_info(),
        Mode::Selfcheck => run_selfcheck(),
        Mode::Embed => run_embed(&args),
    };
    if let Err(e) = rc {
        eprintln!("sysentinel-face: {e:#}");
        std::process::exit(2);
    }
}

/// Print every input/output of the two embedded models.
fn run_info() -> anyhow::Result<()> {
    let models: [( &str, &[u8]); 2] = [("scrfd_2.5g_bnkps", include_bytes!("../models/scrfd_2.5g_bnkps.onnx")), ("mobilefacenet", include_bytes!("../models/mobilefacenet.onnx"))];
    for (name, bytes) in models {
        let model = tract_onnx::onnx().model_for_read(&mut &bytes[..])?;
        println!("=== {name} ({} bytes) ===", bytes.len());
        let inputs = model.input_outlets()?;
        println!("--- inputs ---");
        for (ix, out) in inputs.iter().enumerate() {
            println!("[{ix}] {} :: {:?}", model.node(out.node).name, model.input_fact(ix)?);
        }
        let outputs = model.output_outlets()?;
        println!("--- outputs ---");
        for (ix, out) in outputs.iter().enumerate() {
            println!("[{ix}] {} :: {:?}", model.node(out.node).name, model.output_fact(ix)?);
        }
    }
    Ok(())
}

/// Push zero tensors through both graphs and print output shapes.
fn run_selfcheck() -> anyhow::Result<()> {
    let nn = FaceNn::build()?;
    let plan = &nn.det;
    let input = tract_ndarray::Array4::<f32>::zeros((1, 3, 640, 640));
    let out = plan.run(tvec!(input.into_tensor().into()))?;
    println!("--- SCRFD (entrada de ceros, 640) ---");
    for (ix, t) in out.iter().enumerate() {
        println!("[{ix}] shape={:?} dtype={:?}", t.shape(), t.datum_type());
    }
    let plan = &nn.emb;
    let input = tract_ndarray::Array4::<f32>::zeros((1, 3, 112, 112));
    let out = plan.run(tvec!(input.into_tensor().into()))?;
    println!("--- MobileFaceNet (entrada de ceros, 112) ---");
    for (ix, t) in out.iter().enumerate() {
        println!("[{ix}] shape={:?} dtype={:?}", t.shape(), t.datum_type());
        let s = unsafe { t.as_slice_unchecked::<f32>() };
        println!("    first8: {:?}", &s[..8.min(s.len())]);
    }
    Ok(())
}

/// Largest image this tool will decode.
///
/// A few KB of JPEG can declare a 60000x60000 picture and an unbounded decoder
/// reserves the memory for it before anyone looks at the result. This one runs
/// as root in an initramfs where that is a failed boot, and it is also run by
/// the daemon on photographs that arrived from a phone.
const MAX_DIMENSION: u32 = 16_384;

/// Largest template database this will read. Real ones are a few KB per face.
const MAX_DB_BYTES: u64 = 8 * 1024 * 1024;

fn decode_bounded(path: &std::path::Path) -> anyhow::Result<image::DynamicImage> {
    use image::ImageReader;
    let mut reader = ImageReader::open(path)?.with_guessed_format()?;
    let mut limits = image::Limits::default();
    limits.max_image_width = Some(MAX_DIMENSION);
    limits.max_image_height = Some(MAX_DIMENSION);
    limits.max_alloc = Some((MAX_DIMENSION as u64) * (MAX_DIMENSION as u64) * 4);
    reader.limits(limits);
    Ok(reader.decode()?)
}

/// Read the template database, refusing one too large to be real.
///
/// It arrives from the ESP, which the initramfs hook now insists is fixed
/// media — but the file is still the one thing here that decides whose face
/// this is, so it gets a size it has to fit in.
fn read_db(path: &std::path::Path) -> anyhow::Result<FaceDb> {
    let meta = std::fs::metadata(path)?;
    anyhow::ensure!(
        meta.len() <= MAX_DB_BYTES,
        "{} is {} bytes; a template database is not that big",
        path.display(),
        meta.len()
    );
    let raw = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str::<FaceDb>(&raw)?)
}

/// Detect → (align + embed) every face → JSON on stdout.
fn run_embed(args: &Args) -> anyhow::Result<()> {
    let path = args.image.as_ref().expect("--embed checks the arg earlier");
    let img = decode_bounded(path)?.into_rgb8();
    let nn = FaceNn::build()?;

    let db = match &args.db {
        Some(p) => Some(read_db(p)?),
        None => None,
    };

    let faces = scrfd::detect(&nn, &img)?;
    let mut out = EmbedOut {
        image: path.display().to_string(),
        width: img.width(),
        height: img.height(),
        faces: Vec::new(),
    };
    for f in &faces {
        let crop = align::align_crop(&img, &f.kps, 112);
        if let Some(crop_path) = &args.crop {
            crop.save(crop_path)?;
        }
        let emb = nn::embed_crop(&nn, &crop)?;
        let norm = emb.iter().map(|x| x * x).sum::<f32>().sqrt();
        let matched = match &db {
            Some(db) => best_match(&emb, db, args.thresh),
            None => None,
        };
        if args.brief {
            match &matched {
                Some(m) => println!("{}\t{}\t{:.6}", f.score, m.name, m.cosine),
                None => println!("{}\tnone\t0.0", f.score),
            }
        }
        out.faces.push(FaceOut {
            score: f.score,
            bbox: f.bbox,
            kps: f.kps,
            embedding: Some(emb),
            norm: Some(norm),
            matched,
        });
    }
    if !args.brief {
        println!("{}", serde_json::to_string_pretty(&out)?);
    }
    Ok(())
}

/// Nearest enrolled identity by cosine similarity (embeddings are assumed L2
/// normalised). `None` when the DB is empty or nothing beats the threshold.
fn best_match(emb: &[f32], db: &FaceDb, thresh: f32) -> Option<MatchOut> {
    // Skip doubles every time this runs: move the candidate into iteration.
    let mut best: Option<MatchOut> = None;
    for tpl in &db.faces {
        let n = emb.len().min(tpl.embedding.len());
        if n == 0 {
            continue;
        }
        let dot: f32 = emb[..n].iter().zip(tpl.embedding[..n].iter()).map(|(a, b)| a * b).sum();
        if dot >= thresh && best.as_ref().is_none_or(|b: &MatchOut| dot > b.cosine) {
            best = Some(MatchOut { name: tpl.name.clone(), cosine: dot });
        }
    }
    best
}