#!/bin/sh
# SPDX-License-Identifier: MIT OR GPL-2.0-or-later
# shellcheck disable=SC3043
#
# dracut pre-trigger hook (02) — video evidence at the LUKS prompt.
#
# Two capture modes (mutually exclusive):
#
#   1. LED-FREE (default): uses sysentinel-cam to grab one JPEG frame via
#      raw V4L2 mmap (VIDIOC_DQBUF) — the firmware only lights the webcam LED
#      once streaming begins via VIDIOC_STREAMON; sysentinel-cam never calls
#      that path.  This is the same tool used by sysentinel-precrypt.sh.
#
#   2. VIDEO (commented out): ffmpeg records a short MP4/MKV clip.  The LED
#      WILL light during this because ffmpeg opens the streaming API.
#      Uncomment only if a visible LED is acceptable at your threat model.
#
# Output:
#   <esp>/sysentinel/luks/video_<boot_id>.jpg   (LED-free single frame)
#   <esp>/sysentinel/luks/video_<boot_id>.mkv   (LED-on, if uncommented)
#
# This hook stamps /run/sysentinel-cam/.video_done so the post-decrypt hook
# does not re-capture.

set -u

_log() { echo "sysentinel-video: $*" >> /run/sysentinel-cam/video.log 2>/dev/null || true; }

_luks_boot() {
    case "$(cat /proc/cmdline 2>/dev/null)" in
        *rd.luks*|*rd.crypt*) return 0 ;;
    esac
    for m in /dev/mapper/luks-*; do
        [ -e "$m" ] && return 0
    done
    return 1
}

_wait_video() {
    local i=0
    while [ "$i" -lt 20 ]; do
        for d in /dev/video*; do
            [ -c "$d" ] 2>/dev/null && return 0
        done
        sleep 1; i=$((i+1))
    done
    return 1
}

_is_fixed_media() {
    local dev name base
    dev="$1"; name=${dev#/dev/}
    [ -e "/sys/class/block/$name" ] || return 1
    if [ -e "/sys/class/block/$name/partition" ]; then
        base=$(basename "$(readlink -f "/sys/class/block/$name/.." 2>/dev/null)" 2>/dev/null)
    else
        base=$name
    fi
    [ -n "$base" ] || return 1
    [ "$(cat "/sys/class/block/$base/removable" 2>/dev/null)" = "0" ] || return 1
}

_has_efi_dir() { [ -d "$1/EFI" ] || [ -d "$1/efi" ]; }

_existing_mountpoint() {
    mount 2>/dev/null | awk -v d="$1" '$1 == d { print $3; exit }'
}

_is_ro() {
    case "$(mount 2>/dev/null | awk -v d="$1" '$1 == d { print; exit }')" in
        *"(ro"*) return 0 ;;
        *) return 1 ;;
    esac
}

main() {
    _luks_boot || return 0
    [ -x /usr/libexec/sysentinel-cam ] || return 0

    mkdir -p /run/sysentinel-cam 2>/dev/null || true
    _wait_video || { _log "no video node appeared"; return 0; }

    local boot_id ts
    boot_id=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null) || return 0
    ts=$(date +%s 2>/dev/null || awk '{print $1}' /proc/uptime)

    # ── Mode 1: LED-free single JPEG frame ───────────────────────────────────
    local jpg_tmp="/run/sysentinel-cam/video_${boot_id}.jpg"
    local jpg_name="video_${boot_id}.jpg"
    local captured=none

    if /usr/libexec/sysentinel-cam \
           --out "$jpg_tmp" --width 640 --height 480 --timeout 5 \
           >/dev/null 2>&1; then
        captured=jpg
        _log "LED-free JPEG captured ($jpg_name)"
    fi

    # ── Mode 2: full video via ffmpeg (LED lights — disabled by default) ─────
    # Uncomment this block only when an illuminated LED at boot is acceptable.
    #
    # local mkv_tmp="/run/sysentinel-cam/video_${boot_id}.mkv"
    # local mkv_name="video_${boot_id}.mkv"
    # if [ -e /dev/video0 ] && command -v ffmpeg > /dev/null 2>&1; then
    #     ffmpeg -y -f v4l2 -input_format mjpeg -video_size 640x480 \
    #            -i /dev/video0 -t 30 -c copy "$mkv_tmp" 2>/dev/null &
    #     local ffpid=$!
    #     wait $ffpid 2>/dev/null || true
    #     [ -s "$mkv_tmp" ] && captured=mkv && _log "MKV captured ($mkv_name)"
    # fi

    [ "$captured" = none ] && { _log "no frame captured"; return 0; }

    # Mirror onto every fixed vfat ESP
    local mnt=/run/sysentinel-cam/video_mnt
    mkdir -p "$mnt" 2>/dev/null || true

    for dev in $(blkid -t TYPE=vfat -o device 2>/dev/null); do
        _is_fixed_media "$dev" || continue
        local mp was_ro=0
        mp=$(_existing_mountpoint "$dev")
        if [ -n "$mp" ] && _has_efi_dir "$mp"; then
            _is_ro "$dev" && mount -o remount,rw "$dev" 2>/dev/null && was_ro=1
            mkdir -p "$mp/sysentinel/luks" 2>/dev/null || true
            if [ "$captured" = jpg ]; then
                cp "$jpg_tmp" "$mp/sysentinel/luks/$jpg_name" 2>/dev/null || true
            fi
            # [ "$captured" = mkv ] && cp "$mkv_tmp" "$mp/sysentinel/luks/$mkv_name" 2>/dev/null || true
            sync 2>/dev/null || true
            [ "$was_ro" = 1 ] && mount -o remount,ro "$dev" 2>/dev/null || true
        elif mount -o rw "$dev" "$mnt" 2>/dev/null; then
            if _has_efi_dir "$mnt"; then
                mkdir -p "$mnt/sysentinel/luks" 2>/dev/null || true
                [ "$captured" = jpg ] && \
                    cp "$jpg_tmp" "$mnt/sysentinel/luks/$jpg_name" 2>/dev/null || true
                sync 2>/dev/null || true
            fi
            umount "$mnt" 2>/dev/null || true
        fi
    done

    rm -f "$jpg_tmp"
    # rm -f "$mkv_tmp"
    : > /run/sysentinel-cam/.video_done
}

# Bounded: never hang more than 45 s (video_size + write)
main &
_mainpid=$!
( sleep 45; kill "$_mainpid" 2>/dev/null ) &
exit 0
