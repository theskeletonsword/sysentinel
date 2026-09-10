#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR GPL-2.0-or-later
#
# Fetches/verifies the Apache-2.0 face models used by ramdisk/face
# (sysentinel-face). The ONNX files are gitignored: this script re-downloads
# them reproducibly and verifies integrity with sha256.
#
#   scripts/fetch-face-models.sh            → SCRFD detector (downloads)
#                                            → MobileFaceNet embedder (verifies)
#
# Sources (SEE ramdisk/face/models/NOTICE for full attribution):
#   SCRFD        — RuteNL/SCRFD-face-detection-ONNX (InsightFace, Apache-2.0)
#   MobileFaceNet— foamliu/MobileFaceNet + InsightFace (Apache-2.0); exported
#                  to ONNX locally with PyTorch (no upstream ONNX release),
#                  see the export recipe printed below.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="$REPO_ROOT/ramdisk/face/models"

#── SCRFD detector ────────────────────────────────────────────────────────────
hf_resolve () { # (<repo> <filename>)
    echo "https://huggingface.co/$1/resolve/main/$2"
}

SCRFD_URL="$(hf_resolve RuteNL/SCRFD-face-detection-ONNX 2.5g_bnkps.onnx)"
SCRFD_OUT="$OUT_DIR/scrfd_2.5g_bnkps.onnx"
SCRFD_SHA256="3f1ac54e769cb5fd76eda11ac3c088eed78d1f51a935a839d04d49b0e770219e"

EMBED_OUT="$OUT_DIR/mobilefacenet.onnx"
EMBED_SHA256="60306a4ed6af9da4f11dc3ac2ae96cf48580768e8854f3ec27158fd6db5b548c"

fetch_verify () { # (<url> <out> <sha256>)
    local url="$1" out="$2" want="$3"
    if [[ -f "$out" ]] && [[ "$(sha256sum "$out" | cut -d' ' -f1)" == "$want" ]]; then
        echo "ok: $out (cached)"
        return 0
    fi
    echo "downloading: $url"
    curl --fail --location --proto '=https' --tlsv1.3 -o "$out.tmp" "$url"
    mv "$out.tmp" "$out"
    local got
    got="$(sha256sum "$out" | cut -d' ' -f1)"
    [[ "$got" == "$want" ]] || { echo "error: sha256 mismatch for $out
  expected $want
  got      $got" >&2; exit 1; }
    echo "ok: $out (${got:0:12}…)"
}

mkdir -p "$OUT_DIR"
fetch_verify "$SCRFD_URL" "$SCRFD_OUT" "$SCRFD_SHA256"

#── MobileFaceNet embedder (local export; verify only) ───────────────────────
if [[ -f "$EMBED_OUT" ]] && \
   [[ "$(sha256sum "$EMBED_OUT" | cut -d' ' -f1)" == "$EMBED_SHA256" ]]; then
    echo "ok: $EMBED_OUT (cached)"
else
    cat >&2 <<'EOF'
error: MobileFaceNet embedder missing or wrong sha256.

Expected: ramdisk/face/models/mobilefacenet.onnx  (sha256 60306a4e…)

There is no upstream ONNX release, so export it once with PyTorch:
  pip install --user torch --index-url https://download.pytorch.org/whl/cpu
  python3 - <<'PY'
import torch
m = torch.jit.load("mobilefacenet_scripted.pt")   # foamliu/MobileFaceNet
m.eval()
torch.onnx.export(m, torch.randn(1, 3, 112, 112), "mobilefacenet.onnx",
                  input_names=["input"], output_names=["output"], dynamo=False,
                  opset_version=13)
PY
Then re-run this script to validate integrity.
EOF
    exit 1
fi