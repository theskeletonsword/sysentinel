// SPDX-License-Identifier: MIT OR GPL-2.0-or-later
//!
//! 5-point face alignment (ArcFace convention), matching insightface's
//! `face_align.py`:
//!
//! 1. least-squares *similarity* transform (scale + rotation + translation)
//!    mapping the detected landmarks → the 112×112 ArcFace template;
//! 2. inverse affine warp with bilinear sampling and black border.

use crate::scrfd::ARCFACE_DST;

/// Least-squares similarity transform mapping `src` landmarks → `dst`
/// template, 2×3 matrix in cv2 `warpAffine` form.
///
/// Minimises Σ |z·p − q|² over complex z = s·e^{iθ} (rotation + uniform
/// scale; no reflection), giving the closed form
///
/// ```text
///   z = (Σ q·p* ) / (Σ |p|²),   t = dst̄ − z·src̄
/// ```
///
/// which for an isotropic scale equals Umeyama's rotation+scale result.
fn umeyama(src: &[[f32; 2]; 5], dst: &[[f32; 2]; 5]) -> [[f32; 3]; 2] {
    let n = src.len() as f32;
    let mut sbar = [0f32; 2];
    let mut dbar = [0f32; 2];
    for i in 0..5 {
        sbar[0] += src[i][0] / n;
        sbar[1] += src[i][1] / n;
        dbar[0] += dst[i][0] / n;
        dbar[1] += dst[i][1] / n;
    }
    let mut z_re = 0f32;
    let mut z_im = 0f32;
    let mut den = 0f32;
    for i in 0..5 {
        let px = src[i][0] - sbar[0];
        let py = src[i][1] - sbar[1];
        let qx = dst[i][0] - dbar[0];
        let qy = dst[i][1] - dbar[1];
        den += px * px + py * py;
        z_re += qx * px + qy * py;
        z_im += qy * px - qx * py;
    }
    if den <= 1e-9 {
        return [[1.0, 0.0, dbar[0] - sbar[0]], [0.0, 1.0, dbar[1] - sbar[1]]];
    }
    let (z_re, z_im) = (z_re / den, z_im / den);
    // t = dst̄ − z·src̄  (complex multiply)
    let tx = dbar[0] - (z_re * sbar[0] - z_im * sbar[1]);
    let ty = dbar[1] - (z_im * sbar[0] + z_re * sbar[1]);
    [[z_re, -z_im, tx], [z_im, z_re, ty]]
}

/// Warp the image region around the detected 5 landmarks into a `size`×`size`
/// aligned crop. Black pixels where the mapping leaves the image.
pub fn align_crop(img: &image::RgbImage, kps: &[[f32; 2]; 5], size: u32) -> image::RgbImage {
    let m = umeyama(kps, &ARCFACE_DST);
    let (w, h) = (img.width() as f32, img.height() as f32);
    // M = [[a, -b, tx], [b, a, ty]]. d = a²+b² (det of 3×3). Inverse:
    //   x = ( a·X − b·Y + b·ty − a·tx ) / d
    //   y = ( b·X + a·Y − a·ty − b·tx ) / d
    let (a, b, tx, ty) = (m[0][0], m[0][1], m[0][2], m[1][2]);
    let den = a * a + b * b;
    let mut out = image::RgbImage::new(size, size);
    for y in 0..size {
        for x in 0..size {
            let xf = x as f32;
            let yf = y as f32;
            let sx = (a * xf - b * yf + b * ty - a * tx) / den;
            let sy = (b * xf + a * yf - a * ty - b * tx) / den;
            out.put_pixel(x, y, sample_bilinear(img, sx, sy, w, h));
        }
    }
    out
}

fn sample_bilinear(img: &image::RgbImage, sx: f32, sy: f32, w: f32, h: f32) -> image::Rgb<u8> {
    if !(sx >= -0.0 && sy >= -0.0 && sx < w && sy < h) {
        return image::Rgb([0, 0, 0]);
    }
    let x0 = sx.floor().max(0.0) as u32;
    let y0 = sy.floor().max(0.0) as u32;
    let x1 = (x0 + 1).min(img.width() - 1);
    let y1 = (y0 + 1).min(img.height() - 1);
    let fx = sx - x0 as f32;
    let fy = sy - y0 as f32;
    let p00 = img.get_pixel(x0, y0).0;
    let p10 = img.get_pixel(x1, y0).0;
    let p01 = img.get_pixel(x0, y1).0;
    let p11 = img.get_pixel(x1, y1).0;
    let mut px = [0u8; 3];
    for c in 0..3 {
        let top = p00[c] as f32 + (p10[c] as f32 - p00[c] as f32) * fx;
        let bot = p01[c] as f32 + (p11[c] as f32 - p01[c] as f32) * fx;
        px[c] = (top + (bot - top) * fy).round().clamp(0.0, 255.0) as u8;
    }
    image::Rgb(px)
}