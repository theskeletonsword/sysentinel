#!/bin/sh
# SPDX-License-Identifier: MIT OR GPL-2.0-or-later
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
# "¿fui yo?" via Telegram.

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
    local dir="$1" boot_id="$2" photo="$3" cam="$4" ts="$5"
    mkdir -p "$dir" 2>/dev/null || return 1
    {
        echo "ok=1"
        echo "boot_id=$boot_id"
        echo "ts=$ts"
        echo "photo=$photo"
        echo "cam=$cam"
        echo "hostname=$(hostname 2>/dev/null | sed 's/[[:space:]]//g')"
    } > "$dir/luks_${boot_id}.txt" 2>/dev/null
    chmod 644 "$dir/luks_${boot_id}.txt" 2>/dev/null
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
    local boot_id
    boot_id=$(cat /proc/sys/kernel/random/boot_id 2>/dev/null || echo boot-$(awk '{print $1}' /proc/uptime 2>/dev/null))
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
    # already — reuse those mountpoints, remounting rw if needed.
    local dev mp was_ro
    for dev in $(blkid -t TYPE=vfat -o device 2>/dev/null); do
        mp=$(_existing_mountpoint "$dev")
        if [ -n "$mp" ]; then
            _is_ro "$dev" && mount -o remount,rw "$dev" 2>/dev/null && was_ro=1 || was_ro=0
            _write_marker "$mp/sysentinel/luks" "$boot_id" "$photo" "$cam" "$ts"
            [ "$photo" != none ] && cp "$out" "$mp/sysentinel/luks/$photo" 2>/dev/null || true
            [ "$was_ro" = 1 ] && mount -o remount,ro "$dev" 2>/dev/null || true
        elif mount -o rw "$dev" "$mnt" 2>/dev/null; then
            _write_marker "$mnt/sysentinel/luks" "$boot_id" "$photo" "$cam" "$ts"
            [ "$photo" != none ] && cp "$out" "$mnt/sysentinel/luks/$photo" 2>/dev/null || true
            umount "$mnt" 2>/dev/null || true
        fi
    done

    # Best-effort copy on the already-decrypted root (survives ESP loss).
    if [ "$photo" != none ] && [ -d /sysroot ]; then
        mkdir -p /sysroot/var/lib/sysentinel/luks-evidence 2>/dev/null || true
        cp "$out" /sysroot/var/lib/sysentinel/luks-evidence/"$photo" 2>/dev/null || true
        _write_marker /sysroot/var/lib/sysentinel/luks-evidence "$boot_id" "$photo" "$cam" "$ts" || true
    fi

    rm -rf "$tmp"
    return 0
}

main