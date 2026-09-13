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
#
# 0, not 255: dracut reads 255 as "include ONLY when something explicitly asks
# for me" (--add sysentinel, or another module's depends()). With 255 here a
# plain `dracut --force` built an image with no hooks, no camera tool and no
# early control channel, and said nothing while doing it — the module was
# skipped, not failed, so there was no error to notice.
check() {
    return 0
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
    # sysentinel_metrics is built out-of-tree against ONE kernel version, and
    # this module is now included in every regeneration (check() returns 0). So
    # the first initramfs built for a freshly installed kernel will not find it.
    # Warn loudly and carry on: a missing control channel degrades this boot,
    # while a fatal instmods here would abort the whole initramfs build and
    # leave the new kernel without an image at all. Rebuild the module for the
    # new kernel (see kernel_module/) to get it back.
    if modinfo -k "$kernel" sysentinel_metrics > /dev/null 2>&1; then
        instmods sysentinel_metrics
    else
        dwarn "sysentinel: no sysentinel_metrics.ko for kernel $kernel —" \
              "early control channel will be absent from this initramfs"
    fi
    # Generic USB + integrated webcam capture stack.
    #
    # Asked for one by one, and only when the running kernel actually has it:
    # instmods is fatal on a name it cannot resolve, and the v4l2 stack is not
    # a stable set of module names. On 7.2.4 `videobuf2-core` and `v4l2_common`
    # no longer exist under those names (nor as builtins), and naming them
    # aborted installkernel — which took the whole module down with it, camera
    # stack and early control channel alike, over an optional webcam helper.
    local _m
    for _m in uvcvideo videobuf2-core videobuf2-v4l2 videobuf2-memops \
              videobuf2-vmalloc v4l2_common videodev; do
        if modinfo -k "$kernel" "$_m" > /dev/null 2>&1; then
            instmods "$_m"
        fi
    done
    # Some "Integrated Camera" sensors (Intel IPU/MIPI via uvcvideo) need
    # firmware to enumerate; pull whatever the uvcvideo module asks for.
    local _fw
    _fw=$(modinfo -k "$kernel" -F firmware uvcvideo 2>/dev/null || true)
    if [ -n "$_fw" ]; then
        # shellcheck disable=SC2086  # deliberate split: one firmware per word.
        inst_firmware $_fw
    fi

    # Return success explicitly. Without this the function's exit status is
    # whatever the firmware test left behind, and a uvcvideo that declares no
    # firmware — the normal case on 7.2.4 — made `[ -n "$_fw" ] && …` return 1.
    # dracut reads that as "installkernel failed" and drops the entire module,
    # so a webcam detail silently cost the early control channel.
    return 0
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