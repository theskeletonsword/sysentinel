#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR GPL-2.0-or-later
#
# dracut module 91sysentinel — early control + intrusion webcam for LUKS.
#
# What it does in the initramfs:
#   1. pre-udev  : loads sysentinel_metrics (control/verdict channel) and
#                  uvcvideo so the webcam stack is up before login.
#   2. pre-pivot : if this boot decrypted a LUKS volume, snaps a photo of
#                  whoever is at the keyboard and drops it on every vfat ESP
#                  (+ best-effort copy on the real root). The daemon picks it
#                  up post-boot, dedupes by boot_id and asks "¿fui yo?".
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
    # The photo tool — built from ramdisk/ (see Makefile "ramdisk" target).
    local _cam="${SYSENTINEL_CAM:-/usr/libexec/sysentinel-cam}"
    if [[ -x "$_cam" ]]; then
        inst_binary "$_cam" /usr/libexec/sysentinel-cam
    else
        dfatal "sysentinel: camera tool not found at $_cam (build it: make ramdisk)"
    fi

    # blkid(8) to locate the vfat ESP(s). Fedora's initramfs usually ships a
    # busybox-blkid; prefer the real one when present.
    inst_binary blkid 2>/dev/null || :

    # Hook: load the kernel modules very early (before the udev coldplug).
    inst_hook pre-udev 00 "$moddir/sysentinel-init.sh"

    # Hook: post-decrypt webcam evidence.
    inst_hook pre-pivot 90 "$moddir/sysentinel-luks.sh"
}