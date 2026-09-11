#!/bin/sh
# SPDX-License-Identifier: MIT OR GPL-2.0-or-later
# shellcheck disable=SC3043  # dracut runs these hooks under a shell with `local`.
#
# dracut pre-trigger hook (00) — intrusion webcam evidence, STARTED BEFORE the
# LUKS password prompt.
#
# Why pre-trigger: the cryptsetup prompt happens after the udev coldplug that
# this hook precedes, so our process is up and waiting on the camera the moment
# someone is about to type the decryption password — the paydirt moment, not
# after decrypt (pre-pivot).
#
# Runs as a background job so boot is never stalled: it waits for a camera
# node (enumerated by the coldplug that follows), snaps whoever is at the
# keyboard, and mirrors the evidence to every vfat ESP. On success it stamps
# /run/sysentinel-cam/.done so the pre-pivot hook does not re-capture the same
# boot. If no ESP is reachable it exits WITHOUT the stamp and the pre-pivot
# hook (post-decrypt) remains the fallback, preserving the old behaviour.
#
# Evidence layout (same as the pre-pivot hook; read by the daemon after boot):
#   <esp>/sysentinel/luks/luks_<boot_id>.txt     key=value marker
#   <esp>/sysentinel/luks/cam_<boot_id>.jpg      the photo (if any)

set -u

_log() { echo "sysentinel-precrypt: $*" >> /run/sysentinel-cam/precrypt.log 2>/dev/null || true; }

# ── Only boots that will actually unlock LUKS ─────────────────────────────────
_luks_boot() {
    case "$(cat /proc/cmdline 2>/dev/null)" in
        *rd.luks*|*rd.crypt*) return 0 ;;
    esac
    for m in /dev/mapper/luks-*; do
        [ -e "$m" ] && return 0
    done
    return 1
}

# ── Wait (a bit) for a camera node — USB webcams enumerate late ──────────────
_wait_video() {
    local i=0
    while [ "$i" -lt 20 ]; do
        for d in /dev/video*; do
            [ -c "$d" ] 2>/dev/null && return 0
        done
        sleep 1
        i=$((i + 1))
    done
    return 1
}

# ── key=value marker so the daemon knows what happened ───────────────────────
_write_marker() {
    local dir="$1" boot_id="$2" photo="$3" cam="$4" ts="$5" face="$6" face_score="$7"
    mkdir -p "$dir" 2>/dev/null || return 1
    {
        echo "ok=1"
        echo "boot_id=$boot_id"
        echo "ts=$ts"
        echo "photo=$photo"
        echo "cam=$cam"
        echo "hostname=$(hostname 2>/dev/null | sed 's/[[:space:]]//g')"
        echo "face=$face"
        echo "face_score=$face_score"
    } > "$dir/luks_${boot_id}.txt" 2>/dev/null || return 1
    chmod 644 "$dir/luks_${boot_id}.txt" 2>/dev/null
}

# ── identify the face in a photo against the enrolled templates ──────────────
# The daemon mirrors its templates to <esp>/sysentinel/faces.json, so the
# initramfs can match a suspect BEFORE anything is decrypted. Absent templates
# or tool → "none 0". Outputs: face=<name> face_score=<cosine>
_identify() {
    local photo="$1" db="$2"
    [ -x /usr/libexec/sysentinel-face ] || { echo "none 0"; return 1; }
    [ -r "$db" ] || { echo "none 0"; return 1; }
    /usr/libexec/sysentinel-face --embed "$photo" --match "$db" --thresh 0.5 --brief 2>/dev/null | head -n1 | awk '{ n=$2; s=$3; if (n == "none") print "none 0"; else print n, s }'
}

# ── Is this vfat device the machine's own ESP, or somebody's USB stick? ──────
#
# `blkid -t TYPE=vfat` lists every vfat filesystem attached to the machine, and
# nearly every USB stick in existence is vfat. Taken at face value that means a
# stick left in the machine before boot gets to:
#
#   - supply `sysentinel/faces.json`, the template database this hook uses to
#     decide WHOSE face is at the keyboard, so an attacker can enrol their own
#     face as the owner's; and
#   - receive the marker and the photograph, so the picture of whoever unlocked
#     the disk goes home in their pocket.
#
# Removable media is refused. `/sys/class/block/<disk>/removable` is the same
# question the daemon asks in daemon/src/esp.rs, and not being able to answer
# counts as removable: "I could not tell" is not a reason to hand over the
# owner's face.
_is_fixed_media() {
    local dev name base
    dev="$1"
    name=${dev#/dev/}
    [ -e "/sys/class/block/$name" ] || return 1
    if [ -e "/sys/class/block/$name/partition" ]; then
        base=$(basename "$(readlink -f "/sys/class/block/$name/.." 2>/dev/null)" 2>/dev/null)
    else
        base=$name
    fi
    [ -n "$base" ] || return 1
    [ "$(cat "/sys/class/block/$base/removable" 2>/dev/null)" = "0" ] || return 1
    return 0
}

# A real ESP carries an EFI directory. Checked once it is reachable.
_has_efi_dir() {
    [ -d "$1/EFI" ] || [ -d "$1/efi" ]
}

# Is this device already mounted? prints its mountpoint ("" if not).
_existing_mountpoint() {
    mount 2>/dev/null | awk -v d="$1" '$1 == d { print $3; exit }'
}

# Is this device currently mounted read-only?
_is_ro() {
    case "$(mount 2>/dev/null | awk -v d="$1" '$1 == d { print; exit }')" in
        *"(ro"*) return 0 ;;
        *) return 1 ;;
    esac
}

main() {
    _luks_boot || return 0
    [ -x /usr/libexec/sysentinel-cam ] || return 0

    mkdir -p /run/sysentinel-cam /run/sysentinel-cam/mnt 2>/dev/null || true

    local boot_id ts
    boot_id=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null) || return 0
    ts=$(date +%s 2>/dev/null || awk '{print $1}' /proc/uptime 2>/dev/null)

    # Snap whoever is at the keyboard BEFORE they type the password.
    local cam=none photo=none out="/run/sysentinel-cam/cam_${boot_id}.jpg"
    if _wait_video && \
       /usr/libexec/sysentinel-cam --out "$out" --timeout 10 >/dev/null 2>&1; then
        photo="cam_${boot_id}.jpg"
        cam=$(/usr/libexec/sysentinel-cam --list 2>/dev/null | head -n1 | awk '{print $2}')
        [ -n "$cam" ] || cam=webcam
    fi

    # Mirror onto every vfat ESP, retrying: block nodes and ESP mounts only
    # exist after the coldplug that follows this hook (~1-2 s in).
    # Face identification runs once, against the first template set found on an
    # ESP; the verdict travels with the marker.
    local wrote=0 dev mp was_ro i face=none face_score=0
    for i in 1 2 3 4 5 6 7 8 9 10; do
        [ "$wrote" -gt 0 ] && break
        for dev in $(blkid -t TYPE=vfat -o device 2>/dev/null); do
            _is_fixed_media "$dev" || continue
            mp=$(_existing_mountpoint "$dev")
            if [ -n "$mp" ] && _has_efi_dir "$mp"; then
                if [ "$photo" != none ] && [ "$face" = none ] && [ -r "$mp/sysentinel/faces.json" ]; then
                    read -r face face_score <<-EOF
					$(_identify "$out" "$mp/sysentinel/faces.json")
					EOF
                fi
                was_ro=0
                _is_ro "$dev" && mount -o remount,rw "$dev" 2>/dev/null && was_ro=1
                if _write_marker "$mp/sysentinel/luks" "$boot_id" "$photo" "$cam" "$ts" "$face" "$face_score"; then
                    wrote=1
                    [ "$photo" != none ] && cp "$out" "$mp/sysentinel/luks/$photo" 2>/dev/null || true
                fi
                [ "$was_ro" = 1 ] && mount -o remount,ro "$dev" 2>/dev/null || true
            elif mount -o rw "$dev" /run/sysentinel-cam/mnt 2>/dev/null; then
                if ! _has_efi_dir /run/sysentinel-cam/mnt; then
                    umount /run/sysentinel-cam/mnt 2>/dev/null || true
                    continue
                fi
                if [ "$photo" != none ] && [ "$face" = none ] && [ -r "/run/sysentinel-cam/mnt/sysentinel/faces.json" ]; then
                    read -r face face_score <<-EOF
					$(_identify "$out" "/run/sysentinel-cam/mnt/sysentinel/faces.json")
					EOF
                fi
                if _write_marker "/run/sysentinel-cam/mnt/sysentinel/luks" "$boot_id" "$photo" "$cam" "$ts" "$face" "$face_score"; then
                    wrote=1
                    [ "$photo" != none ] && cp "$out" "/run/sysentinel-cam/mnt/sysentinel/luks/$photo" 2>/dev/null || true
                fi
                umount /run/sysentinel-cam/mnt 2>/dev/null || true
            fi
        done
        [ "$wrote" -gt 0 ] && break
        sleep 1
    done

    # Evidence landed on ≥1 ESP → tell pre-pivot to skip its post-decrypt
    # re-capture. Otherwise leave no stamp: pre-pivot keeps the fallback.
    if [ "$wrote" -gt 0 ]; then
        : > /run/sysentinel-cam/.done
        _log "evidence for boot $boot_id mirrored (photo=$photo, cam=$cam)"
    else
        _log "no ESP reached — deferring to pre-pivot fallback"
    fi
    rm -rf /run/sysentinel-cam/mnt
}

# The whole job, wall-clock bounded so it can never linger into switch_root.
main &
_mainpid=$!
( sleep 45; kill "$_mainpid" 2>/dev/null ) &
exit 0