// SPDX-License-Identifier: MIT OR GPL-2.0-or-later
//!
//! SCRFD-2.5G face detector postprocessing, faithful to insightface's
//! `tools/scrfd.py`:
//!
//! * letterbox pad into a 640×640 canvas (ratio preserved);
//! * one blob per stride (8/16/32): scores (sigmoid) + bbox + kps, multiplied
//!   by the stride;
//! * anchors = every grid-cell centre repeated twice (`num_anchors = 2`), in
//!   row-major order, coordinates in the 640-space;
//! * bbox decode = distance to left/top/right/bottom from the anchor centre;
//! * kps decode = anchor centre + per-keypoint distances;
//! * score threshold 0.5, classic sort-descending NMS with IoU 0.4;
//! * the final boxes/landmarks are divided back by `det_scale` so they land in
//!   the original image coordinate space.

use tract_onnx::prelude::*;

use crate::nn::{FaceNn, SCORE_THRESH, NMS_THRESH};

/// A single detected face with its 5 landmarks (detector-space → image-space).
#[derive(Clone, Debug)]
pub struct Face {
    pub score: f32,
    pub bbox: [f32; 4],     // x1, y1, x2, y2 (image pixels)
    pub kps: [[f32; 2]; 5], // image pixels
}

/// 5-point alignment template for 112×112 crops (ArcFace convention).
/// Mapping src-landmarks → this template == the transform applied at
/// enrolment and at inference, so embeddings from both sides match.
pub const ARCFACE_DST: [[f32; 2]; 5] = [
    [38.2946, 51.6963],
    [73.5318, 51.5014],
    [56.0252, 71.7366],
    [41.5493, 92.3655],
    [70.7299, 92.2041],
];

/// Step 1: decode the nine detector outputs into candidate faces.
fn decode_candidates(
    out: &TVec<TValue>,
    steps: usize,
    feat_stride: &[u64; 3],
    w: u32,  // 640 canvas width
    h: u32,  // 640 canvas height
) -> Vec<(f32, [f32; 4], [[f32; 2]; 5])> {
    let mut cands = Vec::new();
    for (idx, &stride) in feat_stride.iter().enumerate() {
        let n = (h / stride as u32) as usize * (w / stride as u32) as usize * 2; // K*2
        let scores = unsafe { out[idx].as_slice_unchecked::<f32>() };
        let bboxes = unsafe { out[idx + steps].as_slice_unchecked::<f32>() };
        let kpss_ = unsafe { out[idx + steps * 2].as_slice_unchecked::<f32>() };

        // Never trust the geometry over the tensors we actually got: a short
        // output would otherwise index out of bounds, and `panic = "abort"`
        // turns that into a dead initramfs tool rather than a skipped stride.
        let n = n
            .min(scores.len())
            .min(bboxes.len() / 4)
            .min(kpss_.len() / 10);

        // anchors: every cell-centre, repeated twice. Row-major grid.
        let stride_f = stride as f32;
        // `a` indexes three parallel tensors at different strides (1/4/10),
        // so the iterator rewrite clippy suggests does not apply.
        #[allow(clippy::needless_range_loop)]
        for a in 0..n {
            let score = scores[a];
            if score < SCORE_THRESH {
                continue;
            }
            let cell = a / 2;
            let r = (cell / (w as usize / stride as usize)) as f32;
            let c = (cell % (w as usize / stride as usize)) as f32;
            let cx = c * stride_f;
            let cy = r * stride_f;

            let b = a * 4;
            let x1 = cx - bboxes[b] * stride_f;
            let y1 = cy - bboxes[b + 1] * stride_f;
            let x2 = cx + bboxes[b + 2] * stride_f;
            let y2 = cy + bboxes[b + 3] * stride_f;

            let k = a * 10;
            let mut kps = [[0f32; 2]; 5];
            for p in 0..5 {
                kps[p] = [
                    cx + kpss_[k + p * 2] * stride_f,
                    cy + kpss_[k + p * 2 + 1] * stride_f,
                ];
            }
            cands.push((score, [x1, y1, x2, y2], kps));
        }
    }
    cands
}

/// Step 2: descending-sort + NMS (IoU <= NMS_THRESH keeps).
fn nms(mut cands: Vec<(f32, [f32; 4], [[f32; 2]; 5])>) -> Vec<(f32, [f32; 4], [[f32; 2]; 5])> {
    cands.sort_by(|a, b| b.0.partial_cmp(&a.0).unwrap_or(std::cmp::Ordering::Equal));
    let mut keep: Vec<(f32, [f32; 4], [[f32; 2]; 5])> = Vec::new();
    let mut active: Vec<bool> = vec![true; cands.len()];
    for i in 0..cands.len() {
        if !active[i] {
            continue;
        }
        let cand = cands[i];
        keep.push(cand);
        let b = cand.1;
        let area = (b[2] - b[0] + 1.0).max(0.0) * (b[3] - b[1] + 1.0).max(0.0);
        for j in (i + 1)..cands.len() {
            if !active[j] {
                continue;
            }
            let bj = cands[j].1;
            let xx1 = b[0].max(bj[0]);
            let yy1 = b[1].max(bj[1]);
            let xx2 = b[2].min(bj[2]);
            let yy2 = b[3].min(bj[3]);
            let w = (xx2 - xx1 + 1.0).max(0.0);
            let h = (yy2 - yy1 + 1.0).max(0.0);
            let inter = w * h;
            let areaj = (bj[2] - bj[0] + 1.0).max(0.0) * (bj[3] - bj[1] + 1.0).max(0.0);
            let iou = inter / (area + areaj - inter + 1e-9);
            if iou >= NMS_THRESH {
                active[j] = false;
            }
        }
    }
    keep
}

/// Normalised CHW f32 blob + fixed canvas size (640) for the detector.
/// Faithful to scrfd.py: letterbox pad, (px - 127.5) / 128, no channel swap
/// (input is already RGB; the reference reads BGR with cv2 and swapRB=True).
pub fn debug_blob(img: &image::RgbImage) -> (Vec<f32>, u32) {
    let (new_w, new_h) = letterbox_dims(img.width(), img.height(), 640);
    let resized = image::imageops::resize(img, new_w.clamp(1, 640), new_h.clamp(1, 640), image::imageops::FilterType::Triangle);
    let mut canvas = vec![0u8; (640 * 640 * 3) as usize];
    for (cy, row) in resized.as_raw().chunks_exact((new_w * 3) as usize).enumerate() {
        let dst = &mut canvas[cy * 640 * 3..(cy + 1) * 640 * 3];
        dst[..row.len()].copy_from_slice(row);
    }
    let mut blob = vec![0f32; 640 * 640 * 3];
    for p in 0..(640 * 640) as usize {
        let r = canvas[p * 3] as f32;
        let g = canvas[p * 3 + 1] as f32;
        let b = canvas[p * 3 + 2] as f32;
        blob[p] = (r - 127.5) / 128.0;
        blob[640 * 640 + p] = (g - 127.5) / 128.0;
        blob[640 * 640 * 2 + p] = (b - 127.5) / 128.0;
    }
    (blob, 640)
}

/// scrfd.py letterbox dims: fit the image into `s×s` preserving aspect ratio.
fn letterbox_dims(w: u32, h: u32, s: u32) -> (u32, u32) {
    if h as f32 / w as f32 > 1.0 {
        (w * s / h, s) // portrait: height fills, width scaled
    } else {
        (s, h * s / w) // landscape/square: width fills, height scaled
    }
}

/// Full detector pass over an arbitrary image. Returns faces in the original
/// image pixel space (top one first = highest score after NMS).
pub fn detect(nn: &FaceNn, img: &image::RgbImage) -> anyhow::Result<Vec<Face>> {
    let (w0, h0) = (img.width(), img.height());
    if w0 == 0 || h0 == 0 {
        return Ok(Vec::new());
    }
    let (new_w, new_h) = letterbox_dims(w0, h0, 640);
    let det_scale = new_h as f32 / h0 as f32;

    let (blob, dims) = debug_blob(img);
    let dims_u = dims as usize;
    let _ = (new_w,);

    let input =
        tract_ndarray::Array4::from_shape_vec((1, 3, dims_u, dims_u), blob)?.into_tensor().into();
    let out = nn.det.run(tvec!(input))?;

    let mut cands = decode_candidates(&out, 3, &[8, 16, 32], 640, 640);
    // crop to the canvas (the 640-space), then divide by det_scale.
    for c in cands.iter_mut() {
        c.1[0] = c.1[0].clamp(0.0, 639.0);
        c.1[1] = c.1[1].clamp(0.0, 639.0);
        c.1[2] = c.1[2].clamp(0.0, 639.0);
        c.1[3] = c.1[3].clamp(0.0, 639.0);
        for p in 0..5 {
            c.2[p][0] = c.2[p][0].clamp(0.0, 639.0);
            c.2[p][1] = c.2[p][1].clamp(0.0, 639.0);
        }
    }
    let keep = nms(cands);
    Ok(keep
        .into_iter()
        .map(|(s, b, k)| {
            let sx = 1.0 / det_scale;
            Face {
                score: s,
                bbox: [
                    (b[0] * sx).clamp(0.0, w0 as f32),
                    (b[1] * sx).clamp(0.0, h0 as f32),
                    (b[2] * sx).clamp(0.0, w0 as f32),
                    (b[3] * sx).clamp(0.0, h0 as f32),
                ],
                kps: [
                    [(k[0][0] * sx).clamp(0.0, w0 as f32), (k[0][1] * sx).clamp(0.0, h0 as f32)],
                    [(k[1][0] * sx).clamp(0.0, w0 as f32), (k[1][1] * sx).clamp(0.0, h0 as f32)],
                    [(k[2][0] * sx).clamp(0.0, w0 as f32), (k[2][1] * sx).clamp(0.0, h0 as f32)],
                    [(k[3][0] * sx).clamp(0.0, w0 as f32), (k[3][1] * sx).clamp(0.0, h0 as f32)],
                    [(k[4][0] * sx).clamp(0.0, w0 as f32), (k[4][1] * sx).clamp(0.0, h0 as f32)],
                ],
            }
        })
        .collect())
}