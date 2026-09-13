#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR GPL-2.0-or-later
#
# Install the sysentinel early-boot pieces into this machine's initramfs,
# whichever generator it uses.
#
#   dracut           Fedora, RHEL, openSUSE, Mageia, and Debian when chosen
#   initramfs-tools  Debian, Ubuntu and derivatives (update-initramfs)
#   mkinitcpio       Arch and derivatives
#
# The three generators share the runtime capture scripts verbatim — those are
# plain POSIX sh with no generator-specific helpers — and differ only in how
# each one is told when to run. That is why there is one installer and three
# thin adapters rather than three installers.
#
# WHAT GOES IN, AND WHY EARLY BOOT
#
#   sysentinel_metrics   the ring-0 control/verdict channel, so
#                        /proc/sysentinel_metrics exists before anything else
#   uvcvideo + v4l2      the webcam stack
#   sysentinel-cam       a static musl binary that takes the photo
#   three hooks          load the modules early; photograph whoever is at the
#                        keyboard BEFORE the LUKS prompt; and a post-decrypt
#                        fallback for when the early capture reached no ESP
#
# The photo is written to the EFI System Partition because the generator mounts
# it rw long before the real root is available, and it survives a wipe of /,
# /boot and /var.
#
# Usage:
#   sudo scripts/install-initramfs.sh [--generator dracut|initramfs-tools|mkinitcpio]
#                                     [--no-regenerate] [--all-kernels]

set -euo pipefail

GENERATOR=""
REGENERATE=1
ALL_KERNELS=0
while (( $# )); do
    case "$1" in
        --generator)     GENERATOR="${2:?--generator needs a value}"; shift 2 ;;
        --no-regenerate) REGENERATE=0; shift ;;
        --all-kernels)   ALL_KERNELS=1; shift ;;
        -h|--help) sed -n '2,33p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 1 ;;
    esac
done

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
RAMDISK="$REPO/ramdisk"
KVER="$(uname -r)"

say()  { printf '==> %s\n' "$*"; }
warn() { printf 'warning: %s\n' "$*" >&2; }
die()  { printf 'error: %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run me as root"

# ── detect ───────────────────────────────────────────────────────────────────
#
# Presence of the tool, not the distro name: Debian can be running dracut, and
# guessing from /etc/os-release would then install hooks nothing ever reads.
detect_generator() {
    # If an initramfs-tools config exists AND the tool is there, prefer it on
    # Debian-likes; dracut may also be installed but unused.
    if command -v update-initramfs > /dev/null && [[ -d /etc/initramfs-tools ]]; then
        echo initramfs-tools; return
    fi
    if command -v dracut > /dev/null; then echo dracut; return; fi
    if command -v mkinitcpio > /dev/null; then echo mkinitcpio; return; fi
    return 1
}

if [[ -z "$GENERATOR" ]]; then
    GENERATOR="$(detect_generator)" || die "no supported initramfs generator found
(looked for update-initramfs, dracut, mkinitcpio). Pass --generator to force one."
fi
say "initramfs generator: $GENERATOR"

# ── shared prerequisites ─────────────────────────────────────────────────────
[[ -x /usr/libexec/sysentinel-cam ]] \
    || warn "/usr/libexec/sysentinel-cam is missing — the image will carry the
  control channel but take no photo. Build it: scripts/install-dracut.sh builds
  ramdisk/cam for x86_64-unknown-linux-musl."

modinfo -k "$KVER" sysentinel_metrics > /dev/null 2>&1 \
    || warn "no sysentinel_metrics for $KVER — install it first (akmod or dkms),
  or the image will have no early control channel."

# The capture scripts are installed to a fixed path so all three generators can
# pick them up from one place.
say "installing shared capture scripts → /usr/libexec/sysentinel/"
install -d -m755 /usr/libexec/sysentinel
for s in sysentinel-precrypt.sh sysentinel-luks.sh; do
    install -m755 "$RAMDISK/91sysentinel/$s" "/usr/libexec/sysentinel/$s"
done

# ── back up whatever exists now ──────────────────────────────────────────────
#
# First backup is never overwritten: the point of a rollback image is that it
# predates every attempt, not just the most recent one.
backup_image() {
    local img="$1" bak="${1%.img}.pre-sysentinel.bak"
    [[ -f "$img" ]] || return 0
    if [[ -e "$bak" ]]; then
        say "backup already exists, keeping it: $bak"
    else
        cp -a "$img" "$bak"
        say "backed up: $img → $bak"
    fi
}

# ── per-generator install ────────────────────────────────────────────────────
case "$GENERATOR" in

dracut)
    MODDIR=/usr/lib/dracut/modules.d/91sysentinel
    say "installing dracut module → $MODDIR"
    rm -rf "$MODDIR"
    cp -a "$RAMDISK/91sysentinel" "$MODDIR"
    chmod 755 "$MODDIR" "$MODDIR"/*.sh
    chown -R root:root "$MODDIR"

    if (( REGENERATE )); then
        if (( ALL_KERNELS )); then
            say "dracut --force --regenerate-all"
            dracut --force --regenerate-all
        else
            img="/boot/initramfs-${KVER}.img"
            [[ -f "$img" ]] || img="$(ls -1 /boot/initramfs-*.img 2>/dev/null | tail -1)"
            [[ -n "$img" ]] || die "no initramfs image found in /boot"
            backup_image "$img"
            say "dracut --force $img"
            dracut --force "$img" "$KVER"
        fi
    fi
    ;;

initramfs-tools)
    say "installing initramfs-tools hooks → /etc/initramfs-tools/"
    install -D -m755 "$RAMDISK/initramfs-tools/hooks/sysentinel" \
        /etc/initramfs-tools/hooks/sysentinel
    for stage in init-top init-premount local-bottom; do
        install -D -m755 "$RAMDISK/initramfs-tools/scripts/$stage/sysentinel" \
            "/etc/initramfs-tools/scripts/$stage/sysentinel"
    done

    # initramfs-tools only auto-includes modules it thinks are needed to reach
    # root. Ours is not, so it has to be named explicitly.
    MODFILE=/etc/initramfs-tools/modules
    touch "$MODFILE"
    if ! grep -qx 'sysentinel_metrics' "$MODFILE"; then
        printf '\n# sysentinel: ring-0 control channel, needed before the LUKS prompt\nsysentinel_metrics\n' >> "$MODFILE"
        say "added sysentinel_metrics to $MODFILE"
    fi

    if (( REGENERATE )); then
        if (( ALL_KERNELS )); then
            say "update-initramfs -u -k all"
            update-initramfs -u -k all
        else
            backup_image "/boot/initrd.img-${KVER}"
            say "update-initramfs -u -k $KVER"
            update-initramfs -u -k "$KVER"
        fi
    fi
    ;;

mkinitcpio)
    say "installing mkinitcpio hooks → /etc/initcpio/"
    install -D -m755 "$RAMDISK/mkinitcpio/install/sysentinel" /etc/initcpio/install/sysentinel
    install -D -m755 "$RAMDISK/mkinitcpio/hooks/sysentinel"   /etc/initcpio/hooks/sysentinel

    # The hook has to sit BEFORE 'encrypt', or the capture races the passphrase
    # prompt it is supposed to precede. Editing HOOKS= is a change to a file
    # the user owns, so it is offered rather than done silently.
    CONF=/etc/mkinitcpio.conf
    if [[ -f "$CONF" ]] && ! grep -qE '^HOOKS=.*\bsysentinel\b' "$CONF"; then
        warn "add 'sysentinel' to HOOKS= in $CONF, BEFORE 'encrypt':"
        grep -nE '^HOOKS=' "$CONF" >&2 || true
        warn "then re-run with --no-regenerate removed, or: mkinitcpio -P"
        REGENERATE=0
    fi

    if (( REGENERATE )); then
        say "mkinitcpio -P"
        mkinitcpio -P
    fi
    ;;

*) die "unsupported generator: $GENERATOR" ;;
esac

# ── verify ───────────────────────────────────────────────────────────────────
#
# "The command exited 0" is not the question. The question is whether the
# module and the capture tool are actually inside the image.
verify_image() {
    local img="$1" listed=""
    [[ -f "$img" ]] || return 0
    if command -v lsinitrd > /dev/null; then
        listed="$(lsinitrd "$img" 2>/dev/null | grep -ci sysentinel || true)"
    elif command -v lsinitramfs > /dev/null; then
        listed="$(lsinitramfs "$img" 2>/dev/null | grep -ci sysentinel || true)"
    elif command -v lsinitcpio > /dev/null; then
        listed="$(lsinitcpio "$img" 2>/dev/null | grep -ci sysentinel || true)"
    else
        return 0
    fi
    if [[ "${listed:-0}" -gt 0 ]]; then
        say "verified: $listed sysentinel entries in $(basename "$img")"
    else
        die "$(basename "$img") contains no sysentinel entries — the hook did not run"
    fi
}

if (( REGENERATE )); then
    case "$GENERATOR" in
        dracut)          verify_image "/boot/initramfs-${KVER}.img" ;;
        initramfs-tools) verify_image "/boot/initrd.img-${KVER}" ;;
        mkinitcpio)      verify_image "/boot/initramfs-linux.img" ;;
    esac
fi

say "done"
