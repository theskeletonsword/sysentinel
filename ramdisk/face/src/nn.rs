// SPDX-License-Identifier: MIT OR GPL-2.0-or-later
//!
//! Model loading + shared inference plumbing. Both ONNX graphs are compiled
//! INTO the binary (include_bytes!) so a single static-musl executable works
//! on a bare ramdisk.

use std::sync::Arc;
use tract_onnx::prelude::*;

/// Insightface SCRFD bbox/kps thresholds used by `tools/scrfd.py`.
pub const SCORE_THRESH: f32 = 0.5;
pub const NMS_THRESH: f32 = 0.4;

/// Detector: SCRFD-2.5G bnkps (bbox + 5 kps), 640×640 input.
const DETECTOR: &[u8] = include_bytes!("../models/scrfd_2.5g_bnkps.onnx");
/// Embedder: MobileFaceNet (foamliu/InsightFace), 112×112 aligned → 128-D.
const EMBEDDER: &[u8] = include_bytes!("../models/mobilefacenet.onnx");

/// Both runnable models, ready for use.
pub struct FaceNn {
    pub det: Arc<TypedRunnableModel>,
    pub emb: Arc<TypedRunnableModel>,
}

fn load(bytes: &[u8]) -> anyhow::Result<Arc<TypedRunnableModel>> {
    let model = tract_onnx::onnx().model_for_read(&mut &bytes[..])?;
    let model = model.into_optimized()?;
    model.into_runnable()
}

impl FaceNn {
    /// Build (load + optimise + make runnable) both embedded models.
    pub fn build() -> anyhow::Result<FaceNn> {
        Ok(FaceNn { det: load(DETECTOR)?, emb: load(EMBEDDER)? })
    }
}

/// Run the embedder on an aligned 112×112 RGB crop; returns the L2-normalised
/// 128-D embedding. Input is fed as BGR (foamliu's training convention).
pub fn embed_crop(nn: &FaceNn, crop: &image::RgbImage) -> anyhow::Result<Vec<f32>> {
    let mut chw = vec![0f32; 112 * 112 * 3];
    for y in 0..112u32 {
        for x in 0..112u32 {
            let px = crop.get_pixel(x, y).0;
            let i = (y * 112 + x) as usize;
            // BGR channel order, (px - 127.5) / 128.
            chw[i] = (px[2] as f32 - 127.5) / 128.0;
            chw[112 * 112 + i] = (px[1] as f32 - 127.5) / 128.0;
            chw[112 * 112 * 2 + i] = (px[0] as f32 - 127.5) / 128.0;
        }
    }
    let input = tract_ndarray::Array4::from_shape_vec((1, 3, 112, 112), chw)?.into_tensor().into();
    let out = nn.emb.run(tvec!(input))?;
    debug_assert_eq!(out[0].datum_type(), f32::datum_type());
    let data = unsafe { out[0].as_slice_unchecked::<f32>() };
    let mut vec = data.to_vec();
    let norm: f32 = vec.iter().map(|x| x * x).sum::<f32>().sqrt();
    if norm > 1e-9 {
        for v in vec.iter_mut() {
            *v /= norm;
        }
    }
    Ok(vec)
}