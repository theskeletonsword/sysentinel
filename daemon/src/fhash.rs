// SPDX-License-Identifier: Apache-2.0
//!
//! # Determinación local de rostro — sin tokens, sin guardar fotos
//!
//! La identidad se verifica LOCALMENTE con hashes perceptuales de 64 bits
//! (`u64`), sin modelo neuronal ni LLM, y en disco sólo viven los hashes:
//!
//!   * `p_hash` — pHash (DCT-II sobre el bloque 8×8 de bajas frecuencias):
//!     el más robusto contra re-compresión JPEG (el canal re-codifica las
//!     fotos), redimensionado y marcas de agua.
//!   * `w_hash` — wHash (Haar 2D separable a 2 niveles; 8×8 central de la
//!     sub-banda LL): robusto contra blur, ruido y ediciones pesadas.
//!
//! El parecido se mide con la distancia de Hamming de los dos `u64`. Un probe
//! se declara del propietario cuando pHash *o* wHash cae bajo el umbral fuerte
//! (voto OR: cada hash cubre una familia de degradación distinta y ambos se
//! guardaron al registrar la cara).

use std::path::Path;

use image::imageops;
use image::GenericImageView;

/// Una cara registrada: los dos hashes + cuándo se enroló + (opcional) el
/// vector 128-D del embedding MobileFaceNet que alimenta al veredicto NN del
/// initramfs (los hashes perceptuales siguen siendo el veredicto en vivo del
/// daemon y el fallback).
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct FaceEnroll {
    pub p_hash: u64,
    pub w_hash: u64,
    pub ts: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub embedding: Option<Vec<f32>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FaceVerdict {
    /// Distancias claramente bajo los umbrales de propietario.
    Owner,
    /// Cerca pero no concluyente — "posible propietario, verifica".
    Ambiguous,
    /// Ninguna cara registrada está cerca de este probe.
    Unknown,
}

#[derive(Debug, Clone, Copy)]
pub struct FaceThresholds {
    pub p_owner: u32,
    pub w_owner: u32,
    pub p_ambiguous: u32,
    pub w_ambiguous: u32,
}

impl Default for FaceThresholds {
    fn default() -> Self {
        Self { p_owner: 14, w_owner: 15, p_ambiguous: 20, w_ambiguous: 22 }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FaceMatch {
    pub p_dist: u32,
    pub w_dist: u32,
    pub verdict: FaceVerdict,
}

/// Registro persistente de caras — exclusivamente hashes, nunca píxeles.
pub struct FaceStore {
    pub entries: Vec<FaceEnroll>,
    path: std::path::PathBuf,
}

impl FaceStore {
    /// Carga el JSON de hashes (crea vacío si no existe).
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let entries = if path.exists() {
            let raw = std::fs::read_to_string(path)?;
            serde_json::from_str(&raw).unwrap_or_default()
        } else {
            Vec::new()
        };
        Ok(Self { entries, path: path.to_path_buf() })
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn clear(&mut self) {
        self.entries.clear();
    }

    /// Hash de una foto y añade el enroll (sin embedding). Devuelve el hash.
    // Enrollment helper used by the face tests.
    #[allow(dead_code)]
    pub fn add_image(&mut self, img: &image::DynamicImage) -> (u64, u64) {
        let (p, w) = hash_image(img);
        let ts = chrono::Utc::now().timestamp();
        self.entries.push(FaceEnroll { p_hash: p, w_hash: w, ts, embedding: None });
        (p, w)
    }

    /// Hash + embedding opcional de una foto y añade el enroll.
    pub fn add_image_with_embedding(
        &mut self,
        img: &image::DynamicImage,
        embedding: Option<Vec<f32>>,
    ) -> (u64, u64) {
        let (p, w) = hash_image(img);
        let ts = chrono::Utc::now().timestamp();
        self.entries.push(FaceEnroll { p_hash: p, w_hash: w, ts, embedding });
        (p, w)
    }

    /// Persiste sólo los hashes, con modo 0600.
    pub fn save(&self) -> anyhow::Result<()> {
        let json = serde_json::to_string_pretty(&self.entries)?;
        if let Some(dir) = self.path.parent() {
            std::fs::create_dir_all(dir)?;
        }
        std::fs::write(&self.path, json)?;
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&self.path, std::fs::Permissions::from_mode(0o600));
        Ok(())
    }

    /// MongoDB-style DB for the initramfs face tool (sysentinel-face --match):
    /// `{"faces": [{"name":"owner","embedding":[…128 f32…]}, …]}` — only the
    /// enrolls that carry a 128-D embedding. Single identity ("owner"): the
    /// initramfs veredicto names the owner or says "none".
    pub fn esp_db(&self) -> String {
        #[derive(serde::Serialize)]
        struct Db<'a> {
            faces: Vec<Tpl<'a>>,
        }
        #[derive(serde::Serialize)]
        struct Tpl<'a> {
            name: &'a str,
            embedding: &'a [f32],
        }
        let faces = self
            .entries
            .iter()
            .filter_map(|e| e.embedding.as_ref().map(|emb| Tpl { name: "owner", embedding: emb }))
            .collect::<Vec<_>>();
        serde_json::to_string_pretty(&Db { faces }).unwrap_or_else(|_| r#"{"faces":[]}"#.into())
    }

    /// Espeja el DB de embeddings a `<esp>/sysentinel/faces.json` en el ESP
    /// real, remontando rw si hace falta y volviendo a ro tras escribir.
    /// Best-effort: nunca falla la operación principal.
    ///
    /// # Por qué el ESP y NADA más
    ///
    /// Esto escribe plantillas biométricas. Antes el filtro era "el sistema de
    /// ficheros es vfat", y vfat es prácticamente todo pendrive que existe: en
    /// un escritorio que automonta, enchufar un USB se llevaba a casa la cara
    /// del dueño. [`crate::esp`] exige disco fijo y una ruta de ESP de las de
    /// verdad, así que un pendrive ya no cuenta aunque lo monten en /boot.
    pub fn mirror_to_esp(&self) {
        let targets = crate::esp::mount_points();
        if targets.is_empty() {
            log::debug!("face: no ESP to mirror the identity DB to");
            return;
        }
        let db = self.esp_db();
        log::info!(
            "face: mirroring ESP identity DB ({} templates) to {} ESP(s)",
            self.entries.iter().filter(|e| e.embedding.is_some()).count(),
            targets.len()
        );
        let mounted_ro = read_only_mounts();
        for mnt in targets {
            let key = mnt.display().to_string();
            let ro = mounted_ro.contains(&key);
            if ro {
                let _ = std::process::Command::new("mount").args(["-o", "remount,rw", &key]).output();
            }
            let dir = mnt.join("sysentinel");
            let _ = std::fs::create_dir_all(&dir);
            let _ = std::fs::write(dir.join("faces.json"), db.as_bytes());
            if ro {
                let _ = std::process::Command::new("mount").args(["-o", "remount,ro", &key]).output();
            }
        }
    }
}

/// Mount points currently mounted read-only, so the mirror can put them back
/// the way it found them.
fn read_only_mounts() -> std::collections::HashSet<String> {
    let Ok(text) = std::fs::read_to_string("/proc/mounts") else {
        return std::collections::HashSet::new();
    };
    crate::esp::parse_mounts(&text)
        .into_iter()
        .filter(crate::esp::is_read_only)
        .map(|m| m.mount_point)
        .collect()
}

/// Decodificar una imagen que viene de fuera, con techo.
///
/// # Por qué no `image::load_from_memory` a secas
///
/// Un JPEG de unos pocos KB puede declarar 60000×60000 píxeles. El decodificador
/// hace lo que le piden y reserva ~10 GB antes de que nadie mire el resultado:
/// el proceso muere por OOM y con él el vigilante. La foto la manda el teléfono
/// emparejado y la escribe la webcam, o sea que no es la superficie más
/// expuesta del sistema — pero "confío en quien me la manda" no es una razón
/// para no poner un límite que no le estorba a nadie: 64 megapíxeles son más
/// que cualquier cámara que vaya a haber al otro lado.
pub const MAX_PIXELS: u64 = 64 * 1024 * 1024;

fn limits() -> image::Limits {
    let mut l = image::Limits::default();
    // `image` razona en bytes de buffer; a 4 bytes por píxel esto es el techo
    // de píxeles de arriba, y además corta las asignaciones intermedias.
    l.max_alloc = Some(MAX_PIXELS * 4);
    l.max_image_width = Some(16384);
    l.max_image_height = Some(16384);
    l
}

/// Decode bytes that arrived from outside this machine.
pub fn decode_bounded(bytes: &[u8]) -> anyhow::Result<image::DynamicImage> {
    use image::ImageReader;
    let mut reader = ImageReader::new(std::io::Cursor::new(bytes))
        .with_guessed_format()
        .map_err(|e| anyhow::anyhow!("no pude reconocer el formato: {e}"))?;
    reader.limits(limits());
    reader
        .decode()
        .map_err(|e| anyhow::anyhow!("no pude decodificar la imagen: {e}"))
}

/// Same, for a file the daemon was pointed at (a webcam capture, an initramfs
/// evidence photo).
pub fn open_bounded(path: &Path) -> anyhow::Result<image::DynamicImage> {
    use image::ImageReader;
    let mut reader = ImageReader::open(path)
        .map_err(|e| anyhow::anyhow!("no pude abrir {}: {e}", path.display()))?
        .with_guessed_format()
        .map_err(|e| anyhow::anyhow!("no pude reconocer el formato: {e}"))?;
    reader.limits(limits());
    reader
        .decode()
        .map_err(|e| anyhow::anyhow!("no pude decodificar {}: {e}", path.display()))
}

// ── Hashing en sí ─────────────────────────────────────────────────────────────

/// Distancia de Hamming entre dos hashes de 64 bits.
pub fn hamming(a: u64, b: u64) -> u32 {
    (a ^ b).count_ones()
}

/// Los dos hashes de una imagen: `(p_hash, w_hash)`.
pub fn hash_image(img: &image::DynamicImage) -> (u64, u64) {
    let (p, w) = if img.dimensions().0 == 0 || img.dimensions().1 == 0 {
        (0, 0)
    } else {
        (p_hash(img), w_hash(img))
    };
    (p, w)
}

/// Centra, recorta a cuadrado y reduce a `size`×`size` en grises (0..=255).
fn grayscale_square(img: &image::DynamicImage, size: u32) -> Vec<u8> {
    let luma = img.to_luma8();
    let (iw, ih) = luma.dimensions();
    let s = iw.min(ih);
    let (x, y) = ((iw - s) / 2, (ih - s) / 2);
    let crop = image::imageops::crop_imm(&luma, x, y, s, s).to_image();
    let resized = image::imageops::resize(&crop, size, size, imageops::FilterType::Triangle);
    resized.into_raw()
}

/// pHash: DCT-II de 32×32, bloque 8×8 de bajas frecuencias (sin DC),
/// cada bit = valor por encima de la mediana.
fn p_hash(img: &image::DynamicImage) -> u64 {
    let px = grayscale_square(img, 32);
    let n = 32usize;
    let mut g = vec![0f32; n * n];
    for (i, &v) in px.iter().enumerate() {
        g[i] = v as f32 / 255.0;
    }
    dct2(n, &mut g);

    let mut vals = Vec::with_capacity(64);
    for y in 0..8 {
        for x in 0..8 {
            if x == 0 && y == 0 {
                continue; // DC
            }
            vals.push(g[y * n + x]);
        }
    }
    let mut sorted = vals.clone();
    sorted.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let median = sorted[sorted.len() / 2];

    pack_bits(&vals, |v| v > median)
}

/// wHash: 2D Haar separable a 2 niveles, 8×8 central de la sub-banda LL (16×16),
/// cada bit = celda por encima de la media del bloque.
fn w_hash(img: &image::DynamicImage) -> u64 {
    let px = grayscale_square(img, 64);
    let n = 64usize;
    let mut g = vec![0f32; n * n];
    for (i, &v) in px.iter().enumerate() {
        g[i] = v as f32 / 255.0;
    }
    haar_ll(&mut g, n, n);
    haar_ll(&mut g, n / 2, n);

    let ll = 16usize;
    let mut cell = [0f32; 64];
    let mut idx = 0usize;
    for y in 4..12 {
        for x in 4..12 {
            cell[idx] = g[y * ll + x];
            idx += 1;
        }
    }
    let mean = cell.iter().sum::<f32>() / 64.0;
    pack_bits(&cell, |v| v > mean)
}

fn pack_bits<F: Fn(f32) -> bool>(vals: &[f32], pred: F) -> u64 {
    let mut h = 0u64;
    for (bit, &v) in vals.iter().enumerate() {
        if pred(v) {
            h |= 1u64 << bit;
        }
    }
    h
}

/// DCT-II separable en el lugar (n×n, row-major). X = A·M·Aᵀ.
fn dct2(n: usize, g: &mut [f32]) {
    let mut a = vec![0f32; n * n];
    let scale0 = (1.0 / n as f32).sqrt();
    let scale = (2.0 / n as f32).sqrt();
    for k in 0..n {
        for i in 0..n {
            let c = (std::f32::consts::PI
                * (2.0 * i as f32 + 1.0)
                * k as f32
                / (2.0 * n as f32))
                .cos();
            a[k * n + i] = if k == 0 { scale0 * c } else { scale * c };
        }
    }

    let mut tmp = vec![0f32; n * n];
    for y in 0..n {
        for k in 0..n {
            let mut s = 0f32;
            for x in 0..n {
                s += a[k * n + x] * g[y * n + x];
            }
            tmp[y * n + k] = s;
        }
    }
    for k in 0..n {
        for m in 0..n {
            let mut s = 0f32;
            for y in 0..n {
                s += a[m * n + y] * tmp[y * n + k];
            }
            g[m * n + k] = s;
        }
    }
}

/// Un nivel 2D de Haar, manteniendo sólo la sub-banda LL en el tope-izquierda
/// de `stride`×`stride`; `n` es el lado del bloque actual.
fn haar_ll(g: &mut [f32], n: usize, stride: usize) {
    let half = n / 2;
    let mut tmp = vec![0f32; n * n];
    for y in 0..n {
        for i in 0..half {
            tmp[y * n + i] = (g[y * stride + 2 * i] + g[y * stride + 2 * i + 1]) * 0.5;
        }
    }
    for x in 0..half {
        for y in 0..half {
            g[y * stride + x] = (tmp[(2 * y) * n + x] + tmp[(2 * y + 1) * n + x]) * 0.5;
        }
    }
}

// ── Veredicto ─────────────────────────────────────────────────────────────────

/// Linea de texto con el veredicto facial de una foto capturada, si hay caras
/// registradas. `None` = no hay store / no se pudo leer (no modifica el aviso).
pub fn verdict_text(
    thr: &FaceThresholds,
    store_path: &Path,
    photo_path: &Path,
) -> Option<String> {
    let store = FaceStore::load(store_path).ok()?;
    if store.is_empty() {
        return None;
    }
    let img = open_bounded(photo_path).ok()?;
    let m = match_face(hash_image(&img), &store.entries, thr);
    use std::fmt::Write as _;
    let mut line = String::new();
    let _ = match m.verdict {
        FaceVerdict::Owner => write!(line, "👤 Cara del dueño (match local, Hamming {}/{})", m.p_dist, m.w_dist),
        FaceVerdict::Ambiguous => write!(line, "👤 Rostro parecido al dueño — verificar (Hamming {}/{})", m.p_dist, m.w_dist),
        FaceVerdict::Unknown => write!(line, "🚨 Rostro **NO registrado** en la cámara (Hamming {}/{})", m.p_dist, m.w_dist),
    };
    Some(line)
}

/// Compara un probe contra todas las caras registradas y devuelve las
/// distancias de Hamming mínimas + el veredicto.
pub fn match_face(
    probe: (u64, u64),
    entries: &[FaceEnroll],
    t: &FaceThresholds,
) -> FaceMatch {
    let mut p_min = u32::MAX;
    let mut w_min = u32::MAX;
    for e in entries {
        p_min = p_min.min(hamming(probe.0, e.p_hash));
        w_min = w_min.min(hamming(probe.1, e.w_hash));
    }
    let verdict = if p_min <= t.p_owner || w_min <= t.w_owner {
        FaceVerdict::Owner
    } else if p_min <= t.p_ambiguous || w_min <= t.w_ambiguous {
        FaceVerdict::Ambiguous
    } else {
        FaceVerdict::Unknown
    };
    FaceMatch { p_dist: p_min, w_dist: w_min, verdict }
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::RgbImage;

    fn test_gradient() -> image::DynamicImage {
        let mut img = RgbImage::new(96, 96);
        for (x, y, px) in img.enumerate_pixels_mut() {
            px.0 = [
                (x as u8).wrapping_mul(2),
                (y as u8).wrapping_mul(2),
                ((x + y) as u8).wrapping_mul(2),
            ];
        }
        image::DynamicImage::ImageRgb8(img)
    }

    fn random_bits() -> image::DynamicImage {
        let mut state = 0x9E3779B97F4A7C15u64;
        let mut img = RgbImage::new(64, 64);
        for (_, _, px) in img.enumerate_pixels_mut() {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            let v = state as u8;
            px.0 = [v, v ^ 0x55, !v];
        }
        image::DynamicImage::ImageRgb8(img)
    }

    #[test]
    fn an_oversized_image_is_refused_rather_than_allocated() {
        // The decompression bomb: a few KB of JPEG that decodes to something
        // enormous. Unbounded, the decoder reserves the memory first and asks
        // questions never — which kills the watchdog with a photo. Encoded at
        // 17000 px wide, which costs nothing to build and is over the cap.
        let wide = image::DynamicImage::new_rgb8(17_000, 8);
        let mut buf = std::io::Cursor::new(Vec::new());
        wide.write_to(&mut buf, image::ImageFormat::Jpeg).unwrap();
        assert!(buf.get_ref().len() < 100 * 1024, "the point is that it is small");

        let err = decode_bounded(buf.get_ref()).expect_err("must refuse");
        assert!(format!("{err:#}").contains("exceeds limit"), "{err:#}");

        // An ordinary photo still decodes.
        let small = image::DynamicImage::new_rgb8(64, 64);
        let mut ok = std::io::Cursor::new(Vec::new());
        small.write_to(&mut ok, image::ImageFormat::Jpeg).unwrap();
        assert!(decode_bounded(ok.get_ref()).is_ok());

        // And so does one read from disk, by the same route.
        let dir = std::env::temp_dir().join(format!("sysentinel-bomb-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("wide.jpg");
        std::fs::write(&path, buf.get_ref()).unwrap();
        assert!(open_bounded(&path).is_err(), "the file path must be bounded too");
        std::fs::write(&path, ok.get_ref()).unwrap();
        assert!(open_bounded(&path).is_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }


    #[test]
    fn embedding_roundtrip_and_esp_db() {
        let img = test_gradient();
        let dir = std::env::temp_dir().join(format!("sysentinel-face-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let path = dir.join("faces.json");

        let mut s = FaceStore::load(&path).expect("load");
        s.add_image_with_embedding(&img, Some(vec![1.0; 128]));
        s.save().expect("save");
        let db = s.esp_db();
        assert_eq!(db.matches("\"name\": \"owner\"").count(), 1);
        assert!(db.contains("1.0"));

        let loaded = FaceStore::load(&path).expect("reload");
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded.entries[0].embedding.as_ref().unwrap().len(), 128);

        s.clear();
        let expected = serde_json::to_string_pretty(&serde_json::json!({ "faces": [] })).unwrap();
        assert_eq!(s.esp_db(), expected);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn esp_db_skips_enrolls_without_embedding() {
        let img = test_gradient();
        let dir = std::env::temp_dir().join(format!("sysentinel-face-empty-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("tmpdir");
        let path = dir.join("faces.json");
        let mut s = FaceStore::load(&path).expect("load");
        s.add_image(&img); // hash-only enroll
        let db = s.esp_db();
        let expected = serde_json::to_string_pretty(&serde_json::json!({ "faces": [] })).unwrap();
        assert_eq!(db, expected);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn hamming_identity_and_symmetry() {
        assert_eq!(hamming(0xDEAD_BEEF_u64, 0xDEAD_BEEF), 0);
        assert_eq!(hamming(0, 0xFFFF_FFFF_FFFF_FFFF), 64);
        assert_eq!(hamming(0b1010, 0b1111), 2);
        let a = 0x0123_4567_89AB_CDEF_u64;
        let b = 0xFEDC_BA98_7654_3210;
        assert_eq!(hamming(a, b), hamming(b, a));
    }

    #[test]
    fn identical_image_hashes_equal() {
        let img = test_gradient();
        let (p1, w1) = hash_image(&img);
        let (p2, w2) = hash_image(&img);
        assert_eq!(p1, p2);
        assert_eq!(w1, w2);
        assert_eq!(hamming(p1, p2), 0);
        assert_eq!(hamming(w1, w2), 0);
    }

    #[test]
    fn mild_perturbation_stays_owner() {
        let base = test_gradient();
        let (bp, bw) = hash_image(&base);

        let brighter = base.brighten(40);
        let (bp2, bw2) = hash_image(&brighter);
        assert!(hamming(bp, bp2) <= FaceThresholds::default().p_owner,
            "pHash drifted too far on brightness: {}", hamming(bp, bp2));
        assert!(hamming(bw, bw2) <= FaceThresholds::default().w_owner,
            "wHash drifted too far on brightness: {}", hamming(bw, bw2));

        let resized = image::imageops::resize(&base.to_rgb8(), 48, 48, imageops::FilterType::Triangle);
        let (rp, rw) = hash_image(&image::DynamicImage::ImageRgb8(resized));
        assert!(hamming(bp, rp) <= FaceThresholds::default().p_owner,
            "pHash drifted too far on resize: {}", hamming(bp, rp));
        assert!(hamming(bw, rw) <= FaceThresholds::default().w_owner,
            "wHash drifted too far on resize: {}", hamming(bw, rw));

        let enrolls = vec![FaceEnroll { p_hash: bp, w_hash: bw, ts: 0, embedding: None }];
        let v = match_face((rp, rw), &enrolls, &FaceThresholds::default());
        assert_eq!(v.verdict, FaceVerdict::Owner);
    }

    #[test]
    fn jpeg_roundtrip_stays_owner() {
        let base = test_gradient();
        let (bp, bw) = hash_image(&base);

        let mut jpg = Vec::new();
        {
            let mut enc = image::codecs::jpeg::JpegEncoder::new_with_quality(&mut jpg, 70);
            enc.encode(&base.to_rgb8(), 96, 96, image::ExtendedColorType::Rgb8)
                .expect("encode jpeg");
        }
        let decoded = image::load_from_memory(&jpg).expect("decode jpeg");
        let (dp, dw) = hash_image(&decoded);
        let enrolls = vec![FaceEnroll { p_hash: bp, w_hash: bw, ts: 0, embedding: None }];
        let v = match_face((dp, dw), &enrolls, &FaceThresholds::default());
        assert_eq!(v.verdict, FaceVerdict::Owner,
            "re-encoded photo rejected: p={} w={}", v.p_dist, v.w_dist);
    }

    #[test]
    fn unrelated_image_is_unknown() {
        let face = test_gradient();
        let (fp, fw) = hash_image(&face);
        let noise = random_bits();
        let (np, nw) = hash_image(&noise);

        let enrolls = vec![FaceEnroll { p_hash: fp, w_hash: fw, ts: 0, embedding: None }];
        let v = match_face((np, nw), &enrolls, &FaceThresholds::default());
        assert_eq!(v.verdict, FaceVerdict::Unknown,
            "random pattern matched face: p={} w={}", v.p_dist, v.w_dist);
        assert!(v.p_dist > FaceThresholds::default().p_ambiguous);
        assert!(v.w_dist > FaceThresholds::default().w_ambiguous);
    }
}