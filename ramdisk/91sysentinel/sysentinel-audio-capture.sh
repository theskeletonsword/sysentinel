#!/bin/sh
# SPDX-License-Identifier: MIT OR GPL-2.0-or-later
# shellcheck disable=SC3043
#
# dracut pre-trigger hook (01) — ambient audio evidence at the LUKS prompt.
#
# Captures up to 60 seconds of audio using ALSA arecord, then encodes it to
# OGG/Opus (preferred) or OGG/Vorbis (fallback) and mirrors it to every vfat
# ESP.  Runs entirely in background so it never stalls boot.
#
# PRIVACY CONTRACT: this is NOT a keylogger.  No keystroke timing, no IMEI,
# no serial number.  Audio evidence only — ambient sound at the keyboard.
# The webcam LED is never turned on by this script (audio capture has no LED).
#
# Output: <esp>/sysentinel/luks/audio_<boot_id>.ogg
#
# Prerequisites in the initramfs:
#   - arecord (alsa-utils)
#   - opusenc (opus-tools) OR oggenc (vorbis-tools)
#   Both are installed by module-setup.sh when present on the build host.

set -u

_log() { echo "sysentinel-audio: $*" >> /run/sysentinel-cam/audio.log 2>/dev/null || true; }

_luks_boot() {
    case "$(cat /proc/cmdline 2>/dev/null)" in
        *rd.luks*|*rd.crypt*) return 0 ;;
    esac
    for m in /dev/mapper/luks-*; do
        [ -e "$m" ] && return 0
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
    command -v arecord > /dev/null 2>&1 || return 0

    mkdir -p /run/sysentinel-cam 2>/dev/null || true

    local boot_id ts
    boot_id=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null) || return 0
    ts=$(date +%s 2>/dev/null || awk '{print $1}' /proc/uptime)

    local wavtmp="/run/sysentinel-cam/luks_audio_${boot_id}.wav"
    local outtmp="/run/sysentinel-cam/luks_audio_${boot_id}.ogg"
    local outname="audio_${boot_id}.ogg"

    _log "starting arecord for boot $boot_id"

    # 16 kHz mono S16_LE, max 60 s — written to tmpfs, never touches disk
    arecord -q -D default -f S16_LE -r 16000 -c 1 -d 60 "$wavtmp" 2>/dev/null &
    local arecord_pid=$!

    # Wait for LUKS to succeed (this script exits first) OR the 60 s limit.
    # The hook framework kills child processes when this script exits on its
    # own, so we just wait — cryptsetup success triggers exit before 60 s.
    wait $arecord_pid 2>/dev/null || true

    if [ ! -s "$wavtmp" ]; then
        _log "no audio recorded (empty WAV)"
        return 0
    fi

    # Encode: opusenc is smaller and more accurate; oggenc is the fallback.
    if command -v opusenc > /dev/null 2>&1; then
        opusenc --bitrate 24 --quiet "$wavtmp" "$outtmp" 2>/dev/null || true
    elif command -v oggenc > /dev/null 2>&1; then
        oggenc -q 2 -o "$outtmp" "$wavtmp" 2>/dev/null || true
    else
        _log "no encoder found; keeping WAV"
        outtmp="$wavtmp"
        outname="audio_${boot_id}.wav"
    fi
    rm -f "$wavtmp"

    [ -s "$outtmp" ] || { _log "encoder produced empty file"; return 0; }

    # Mirror onto every fixed vfat ESP
    local mnt=/run/sysentinel-cam/audio_mnt
    mkdir -p "$mnt" 2>/dev/null || true

    for dev in $(blkid -t TYPE=vfat -o device 2>/dev/null); do
        _is_fixed_media "$dev" || continue
        local mp was_ro=0
        mp=$(_existing_mountpoint "$dev")
        if [ -n "$mp" ] && _has_efi_dir "$mp"; then
            _is_ro "$dev" && mount -o remount,rw "$dev" 2>/dev/null && was_ro=1
            mkdir -p "$mp/sysentinel/luks" 2>/dev/null || true
            cp "$outtmp" "$mp/sysentinel/luks/$outname" 2>/dev/null && \
                _log "audio written to $mp ($outname)" || true
            sync 2>/dev/null || true
            [ "$was_ro" = 1 ] && mount -o remount,ro "$dev" 2>/dev/null || true
        elif mount -o rw "$dev" "$mnt" 2>/dev/null; then
            if _has_efi_dir "$mnt"; then
                mkdir -p "$mnt/sysentinel/luks" 2>/dev/null || true
                cp "$outtmp" "$mnt/sysentinel/luks/$outname" 2>/dev/null && \
                    _log "audio written to $dev ($outname)" || true
                sync 2>/dev/null || true
            fi
            umount "$mnt" 2>/dev/null || true
        fi
    done

    rm -f "$outtmp"
}

# Bounded: never run more than 75 s total (60 s record + 15 s encode/write)
main &
_mainpid=$!
( sleep 75; kill "$_mainpid" 2>/dev/null ) &
exit 0
