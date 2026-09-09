#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR GPL-2.0-or-later
#
# Installs the sysentinel ramdisk pieces and regenerates the initramfs:
#
#   1. Builds ramdisk/src → /usr/libexec/sysentinel-cam (the V4L2 photo tool)
#   2. Backs up the CURRENT initramfs to *.pre-sysentinel.bak (first backup
#      is never overwritten) — rollback = restore that file + dracut --force
#   3. Copies the 91sysentinel dracut module into /usr/lib/dracut/modules.d/
#   4. Regenerates the initramfs for the running kernel
#
# The old initramfs backup is the safety net if the implementation fails:
#   sudo cp /boot/initramfs-$(uname -r).img.pre-sysentinel.bak \
#           /boot/initramfs-$(uname -r).img && sudo dracut --force

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CAM_BIN="$REPO_ROOT/ramdisk/target/release/sysentinel-cam"
MOD_DIR="$REPO_ROOT/ramdisk/91sysentinel"
DRACUT_MODULES="/usr/lib/dracut/modules.d"
MOD_NAME="91sysentinel"

REGENERATE=1
if [[ "${1:-}" == "--no-regenerate" ]]; then
    REGENERATE=0
elif [[ $# -gt 0 ]]; then
    echo "usage: $0 [--no-regenerate]" >&2
    exit 1
fi

# ── build (does not need root) ────────────────────────────────────────────────
if [[ ! -f "$CAM_BIN" ]]; then
    echo "==> sysentinel-cam not built yet — building…"
    (cd "$REPO_ROOT/ramdisk" && cargo build --release)
fi
[[ -x "$CAM_BIN" ]] || { echo "error: $CAM_BIN missing — build failed" >&2; exit 1; }

# ── root steps ────────────────────────────────────────────────────────────────
if [[ $EUID -ne 0 ]]; then
    echo "This script must be run as root for the install/regenerate steps." >&2
    exit 1
fi

echo "==> Installing sysentinel-cam → /usr/libexec/sysentinel-cam"
install -Dm755 "$CAM_BIN" /usr/libexec/sysentinel-cam

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

echo "==> Installing dracut module ${MOD_NAME}"
rm -rf "$DRACUT_MODULES/$MOD_NAME"
cp -a "$MOD_DIR" "$DRACUT_MODULES/$MOD_NAME"
chmod 755 "$DRACUT_MODULES/$MOD_NAME/module-setup.sh"
chmod 755 "$DRACUT_MODULES/$MOD_NAME"/sysentinel-*.sh

if [[ $REGENERATE -eq 1 ]]; then
    echo "==> Regenerating initramfs for kernel ${kver} (dracut --force)"
    dracut --force
fi

echo
echo "════════════════════════════════════════════════════════════"
echo " Done. The next LUKS boot will snap a photo and drop it on"
echo " the ESP:   <esp>/sysentinel/luks/"
echo " Rollback:  sudo cp ${bak} ${initimg}"
echo "            && sudo dracut --force"
echo "════════════════════════════════════════════════════════════"