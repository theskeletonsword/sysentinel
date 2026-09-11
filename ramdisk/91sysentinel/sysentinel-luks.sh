#!/bin/sh
# SPDX-License-Identifier: MIT OR GPL-2.0-or-later
# shellcheck disable=SC3043  # dracut runs these hooks under a shell with `local`.
#
# dracut pre-pivot hook (90) — post-decrypt intrusion webcam evidence.
#
# Runs once the real root has been decrypted+mounted but before switching to
# it, so nobody has logged in yet. If this boot used LUKS, we snap whoever is
# at the keyboard and mirror the evidence to every vfat ESP plus the real
# root. If no webcam is present we still drop a marker so the daemon can
# flag "LUKS unlocked with no photo available".
#
# Evidence layout (also read by the daemon after boot):
#   <esp>/sysentinel/luks/luks_<boot_id>.txt     key=value marker
#   <esp>/sysentinel/luks/cam_<boot_id>.jpg      the photo (if any)
#   /sysroot/var/lib/sysentinel/luks-evidence/…  best-effort copy
#
# Uses boot_id (unique per kernel boot) so the daemon can dedupe and ask
# a "was that me?" question on the phone.

set -u

# ── Only boots that actually unlocked LUKS ───────────────────────────────────
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
    } > "$dir/luks_${boot_id}.txt" 2>/dev/null
    chmod 644 "$dir/luks_${boot_id}.txt" 2>/dev/null
}

# ── identify the face in a photo against the enrolled templates ──────────────
# Templates are mirrored to <esp>/sysentinel/faces.json by the daemon, so the
# initramfs can still name a suspect even when the disk is still encrypted.
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
    # The pre-prompt capture (sysentinel-precrypt.sh) already mirrored evidence
    # to an ESP before the LUKS prompt — never re-capture the same boot.
    [ -e /run/sysentinel-cam/.done ] && return 0

    local boot_id
    boot_id=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null \
        || echo "boot-$(awk '{print $1}' /proc/uptime 2>/dev/null)")
    _luks_boot || return 0

    local tmp=/run/sysentinel-cam mnt=/run/sysentinel-cam/mnt
    rm -rf "$tmp"
    mkdir -p "$tmp" "$mnt" 2>/dev/null || true

    local ts
    ts=$(date +%s 2>/dev/null || awk '{print $1}' /proc/uptime 2>/dev/null)

    # Snap the frame (or record that we couldn't).
    local cam=none photo=none out="$tmp/cam_${boot_id}.jpg"
    if _wait_video && [ -x /usr/libexec/sysentinel-cam ] &&
       /usr/libexec/sysentinel-cam --out "$out" --timeout 10 >/dev/null 2>&1; then
        photo="cam_${boot_id}.jpg"
        cam=$(/usr/libexec/sysentinel-cam --list 2>/dev/null | head -n1 | awk '{print $2}')
        [ -n "$cam" ] || cam=webcam
    fi

    # Mirror onto every vfat ESP. Fedora's dracut mounts them from fstab
    # already — reuse those mountpoints, remounting rw if needed. Face
    # identification runs once, against the first template set found.
    local dev mp was_ro face=none face_score=0
    for dev in $(blkid -t TYPE=vfat -o device 2>/dev/null); do
        _is_fixed_media "$dev" || continue
        mp=$(_existing_mountpoint "$dev")
        if [ -n "$mp" ] && _has_efi_dir "$mp"; then
            if [ "$photo" != none ] && [ "$face" = none ] && [ -r "$mp/sysentinel/faces.json" ]; then
                read -r face face_score <<-EOF
					$(_identify "$out" "$mp/sysentinel/faces.json")
					EOF
            fi
            _is_ro "$dev" && mount -o remount,rw "$dev" 2>/dev/null && was_ro=1 || was_ro=0
            _write_marker "$mp/sysentinel/luks" "$boot_id" "$photo" "$cam" "$ts" "$face" "$face_score"
            [ "$photo" != none ] && cp "$out" "$mp/sysentinel/luks/$photo" 2>/dev/null || true
            [ "$was_ro" = 1 ] && mount -o remount,ro "$dev" 2>/dev/null || true
        elif mount -o rw "$dev" "$mnt" 2>/dev/null; then
            if ! _has_efi_dir "$mnt"; then
                umount "$mnt" 2>/dev/null || true
                continue
            fi
            if [ "$photo" != none ] && [ "$face" = none ] && [ -r "$mnt/sysentinel/faces.json" ]; then
                read -r face face_score <<-EOF
					$(_identify "$out" "$mnt/sysentinel/faces.json")
					EOF
            fi
            _write_marker "$mnt/sysentinel/luks" "$boot_id" "$photo" "$cam" "$ts" "$face" "$face_score"
            [ "$photo" != none ] && cp "$out" "$mnt/sysentinel/luks/$photo" 2>/dev/null || true
            umount "$mnt" 2>/dev/null || true
        fi
    done

    # Best-effort copy on the already-decrypted root (survives ESP loss).
    if [ "$photo" != none ] && [ -d /sysroot ]; then
        mkdir -p /sysroot/var/lib/sysentinel/luks-evidence 2>/dev/null || true
        cp "$out" /sysroot/var/lib/sysentinel/luks-evidence/"$photo" 2>/dev/null || true
        _write_marker /sysroot/var/lib/sysentinel/luks-evidence "$boot_id" "$photo" "$cam" "$ts" "$face" "$face_score" || true
    fi

    rm -rf "$tmp"
    return 0
}

main