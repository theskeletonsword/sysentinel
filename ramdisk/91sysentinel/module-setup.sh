#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR GPL-2.0-or-later
# shellcheck disable=SC2154  # $moddir is injected by dracut's module loader.
#
# dracut module 91sysentinel — early control + intrusion webcam for LUKS.
#
# What it does in the initramfs:
#   1. pre-udev  : loads sysentinel_metrics (control/verdict channel) and
#                  uvcvideo so the webcam stack is up before login.
#   2. pre-trigger (BEFORE the LUKS password prompt): background job snaps
#                  whoever is at the keyboard and mirrors the evidence to
#                  every vfat ESP. Never blocks boot; a photo needs no
#                  ciphertext.
#   3. pre-pivot : FALLBACK ONLY — if the pre-prompt capture reached no ESP
#                  (camera-less desktop, ESP not yet enumerable), re-snaps
#                  post-decrypt and drops evidence on every vfat ESP plus the
#                  real root. Skipped when the early capture stamped
#                  /run/sysentinel-cam/.done (no double capture per boot).
#
# The photo is written to the ESP because dracut mounts it rw long before the
# main filesystem is available, and it survives a wipe of /, /boot, /var.

# Always install this module.
check() {
    return 255
}

# No hard dependency on the crypt hooks: pre-pivot naturally runs after
# 70crypt/90crypt has unlocked the volume.
depends() {
    return 0
}

installkernel() {
    # sysentinel_metrics: early real-time control (poweroff / triple-fault
    # / lock verdict). instmods resolves view=broadcast deps (on this
    # machine: mei, video, ...) automatically.
    instmods sysentinel_metrics
    # Generic USB + integrated webcam capture stack.
    instmods uvcvideo videobuf2-core videobuf2-v4l2 videobuf2-memops \
             videobuf2-vmalloc v4l2_common videodev
    # Some "Integrated Camera" sensors (Intel IPU/MIPI via uvcvideo) need
    # firmware to enumerate; pull whatever the uvcvideo module asks for.
    local _fw
    _fw=$(modinfo -F firmware uvcvideo 2>/dev/null || true)
    [ -n "$_fw" ] && inst_firmware $_fw
}

install() {
    # The photo tool — built from ramdisk/cam (install-dracut.sh, musl).
    local _cam="${SYSENTINEL_CAM:-/usr/libexec/sysentinel-cam}"
    if [[ -x "$_cam" ]]; then
        inst_binary "$_cam" /usr/libexec/sysentinel-cam
    else
        dfatal "sysentinel: camera tool not found at $_cam (build it: scripts/install-dracut.sh)"
    fi

    # Optional tract/ONNX face tool (ramdisk/face). Installed only when it
    # exists. When it is present AND the daemon has mirrored its enrolled
    # templates to <esp>/sysentinel/faces.json, the capture hooks name the
    # suspect right in the initramfs (detect→align→embed→cosine match) and
    # write face=<name> face_score=<cosine> into the evidence marker.
    local _face="${SYSENTINEL_FACE:-/usr/libexec/sysentinel-face}"
    if [[ -x "$_face" ]]; then
        inst_binary "$_face" /usr/libexec/sysentinel-face
    fi

    # blkid(8) to locate the vfat ESP(s). Fedora's initramfs usually ships a
    # busybox-blkid; prefer the real one when present.
    inst_binary blkid 2>/dev/null || :

    # Hook: load the kernel modules very early (before the udev coldplug).
    inst_hook pre-udev 00 "$moddir/sysentinel-init.sh"

    # Hook: pre-LUKS-prompt webcam evidence (backgrounded; never stalls boot).
    inst_hook pre-trigger 00 "$moddir/sysentinel-precrypt.sh"

    # Hook: post-decrypt webcam evidence — rescue fallback only, skipped when
    # sysentinel-precrypt.sh already stamped /run/sysentinel-cam/.done.
    inst_hook pre-pivot 90 "$moddir/sysentinel-luks.sh"
}