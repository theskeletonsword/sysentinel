#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR GPL-2.0-or-later
#
# Installs the sysentinel ramdisk pieces and regenerates the initramfs:
#
#   1. Builds ramdisk/{cam,face} statically for x86_64-unknown-linux-musl →
#      /usr/libexec/sysentinel-cam and (optional) /usr/libexec/sysentinel-face
#   2. Backs up the CURRENT initramfs to *.pre-sysentinel.bak (first backup
#      is never overwritten) — rollback = restore that file + dracut --force
#   3. Regenerates the CURRENT initramfs with the 91sysentinel module. The
#      module is exposed to dracut under modules.d only for the duration of
#      the run (removed again on exit via trap), so it ends up exclusively in
#      the image generated here — never applied to future regenerations.
#
# The old initramfs backup is the safety net if the implementation fails:
#   sudo cp /boot/initramfs-$(uname -r).img.pre-sysentinel.bak \
#           /boot/initramfs-$(uname -r).img && sudo dracut --force
#
# Since the module is not installed globally, any initramfs rebuilt by the
# system (kernel updates, etc.) will NOT carry sysentinel — re-run this script
# to re-apply it to the running kernel.
#
# sysentinel-face (the tract/ONNX tool) is built only when its model is
# present; obtain it first with: scripts/fetch-face-models.sh

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TARGET="x86_64-unknown-linux-musl"
CAM_BIN="$REPO_ROOT/ramdisk/target/$TARGET/release/sysentinel-cam"
FACE_BIN="$REPO_ROOT/ramdisk/target/$TARGET/release/sysentinel-face"
MOD_DIR="$REPO_ROOT/ramdisk/91sysentinel"
MOD_NAME="91sysentinel"
DRACUT_MODULES="/usr/lib/dracut/modules.d"
MODEL="$REPO_ROOT/ramdisk/face/models/scrfd_2.5g_bnkps.onnx"
EMBED_MODEL="$REPO_ROOT/ramdisk/face/models/mobilefacenet.onnx"

REGENERATE=1
if [[ "${1:-}" == "--no-regenerate" ]]; then
    REGENERATE=0
elif [[ $# -gt 0 ]]; then
    echo "usage: $0 [--no-regenerate]" >&2
    exit 1
fi

# ── build (does not need root) ────────────────────────────────────────────────
if ! command -v musl-gcc >/dev/null 2>&1; then
    echo "error: musl-gcc not found — install musl-tools / musl-gcc first" >&2
    exit 1
fi

needs_musl_build () { ! [[ -x "$1" ]]; }

if needs_musl_build "$CAM_BIN"; then
    echo "==> building sysentinel-cam (musl)…"
    (cd "$REPO_ROOT/ramdisk" \
        && CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc \
           cargo build --release --target "$TARGET" -p sysentinel-cam) \
        || { echo "error: cam build failed" >&2; exit 1; }
fi

if [[ -f "$MODEL" ]] && [[ -f "$EMBED_MODEL" ]]; then
    if needs_musl_build "$FACE_BIN"; then
        echo "==> building sysentinel-face (musl)…"
        (cd "$REPO_ROOT/ramdisk" \
            && CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_LINKER=musl-gcc \
               cargo build --release --target "$TARGET" -p sysentinel-face) \
            || { echo "error: face build failed" >&2; exit 1; }
    fi
else
    echo "  (face models not present — skipping sysentinel-face build)"
fi
[[ -x "$CAM_BIN" ]] || { echo "error: $CAM_BIN missing — build failed" >&2; exit 1; }
if [[ -x "$FACE_BIN" ]] && [[ (! -f "$MODEL") || (! -f "$EMBED_MODEL") ]]; then
    echo "warning: $FACE_BIN built but a model went missing; reinstalling the models"
    echo "  (scripts/fetch-face-models.sh) or purging the build output re-syncs it." >&2
fi

# ── root steps ────────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root for the install/regenerate steps." >&2
    exit 1
fi

echo "==> Installing sysentinel-cam → /usr/libexec/sysentinel-cam"
install -Dm755 "$CAM_BIN" /usr/libexec/sysentinel-cam
if [[ -x "$FACE_BIN" ]]; then
    echo "==> Installing sysentinel-face → /usr/libexec/sysentinel-face"
    install -Dm755 "$FACE_BIN" /usr/libexec/sysentinel-face
else
    echo "==> sysentinel-face not built (no model) — not installing"
fi

echo "==> Backing up current initramfs (.pre-sysentinel.bak)"
kver="$(uname -r)"
initimg=
for cand in "/boot/initramfs-${kver}.img" /boot/initramfs-*.img; do
    [[ -f "$cand" ]] || continue
    # prefer the running kernel's image; else the lexicographically last one
    [[ -z "$initimg" || "$cand" == "/boot/initramfs-${kver}.img" ]] && initimg="$cand"
done
if [[ -z "$initimg" ]]; then
    echo "error: no initramfs-*.img found in /boot — cannot back up" >&2
    exit 1
fi
bak="${initimg%.img}.pre-sysentinel.bak"
if [[ -e "$bak" ]]; then
    echo "    backup already exists: $bak (keeping it, not overwriting)"
else
    cp -a "$initimg" "$bak"
    echo "    backed up: $initimg → $bak"
fi

[[ -d "$MOD_DIR" ]] || { echo "error: dracut module dir not found: $MOD_DIR" >&2; exit 1; }

if [[ $REGENERATE -eq 1 ]]; then
    # dracut-ng has no --moddirs, and -l/--local would replace ALL system
    # modules. So: expose 91sysentinel under modules.d ONLY for the duration
    # of this run and remove it again on exit (trap). Net effect: the module
    # lives solely inside the image generated now — future automatic
    # regenerations never see it.
    # `${var:?}` so an empty variable can never turn this into `rm -rf /`.
    staged="${DRACUT_MODULES:?}/${MOD_NAME:?}"
    rm -rf "$staged"
    cp -a "$MOD_DIR" "$staged"
    chmod 755 "$staged/module-setup.sh"
    chmod 755 "$staged"/sysentinel-*.sh
    trap 'rm -rf "${DRACUT_MODULES:?}/${MOD_NAME:?}"' EXIT

    echo "==> Regenerating current initramfs ${initimg} (kernel ${kver})"
    dracut --force "$initimg"
    echo "==> 91sysentinel removed from modules.d — it only lives in ${initimg}"
fi

cat <<EOT

════════════════════════════════════════════════════════════
 Done. The next LUKS boot will snap a photo and drop it on
 the ESP:   <esp>/sysentinel/luks/
 Rollback:  sudo cp ${bak} ${initimg}
            && sudo dracut --force

 NOTE: 91sysentinel is included ONLY in the initramfs just generated
 (the module is exposed to dracut momentarily and removed on exit,
 it is never left under /usr/lib/dracut/modules.d). After a kernel
 update or any automatic initramfs rebuild it will no longer be
 present — run this script (as root) again to re-apply it.

 Binaries at /usr/libexec:
   sysentinel-cam  = V4L2 photo tool (used by the initramfs hook)
   sysentinel-face = tract/ONNX face tool (installed only if the
                     models were present at build time; identifies
                     the suspect in-initramfs via cosine match)
════════════════════════════════════════════════════════════
EOT