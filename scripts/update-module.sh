#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR GPL-2.0-or-later
#
# Re-sync the DKMS copy of sysentinel_metrics from this repo, and rebuild.
#
# Run this after pulling changes that touch kernel_module/. It replaces the
# source DKMS holds in /usr/src, rebuilds for the running kernel and reloads
# the module.
#
# WHY THE COPY IS WIPED RATHER THAN OVERWRITTEN
#
# Copying over a previous copy leaves whatever the last version had and this
# one no longer does. For a kbuild module that is not cosmetic: Kbuild globs
# and stale objects link. A file deleted in the repo would keep being compiled
# in from /usr/src, and the symptom is a module built from source that no
# longer exists anywhere — which is the single hardest kind of bug to believe.
# So: remove, then copy.
#
# WHAT IS NOT COPIED
#
# Build artefacts. The repo's kernel_module/ is also where `make` runs during
# development, so it accumulates *.o, .*.cmd, *.ko and friends. Shipping those
# into /usr/src makes the DKMS tree lie about what it is: `dkms build` would
# start from one machine's leftovers instead of from source.
#
# Usage:
#   sudo scripts/update-module.sh [--no-reload] [-k KERNELVER]

set -euo pipefail

RELOAD=1
KVER="$(uname -r)"
while (( $# )); do
    case "$1" in
        --no-reload) RELOAD=0; shift ;;
        -k) KVER="${2:?-k needs a kernel version}"; shift 2 ;;
        -h|--help) sed -n '2,25p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 1 ;;
    esac
done

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODSRC="$REPO/kernel_module"

say() { printf '==> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run me as root (I write /usr/src and call dkms)"
command -v dkms > /dev/null || die "dkms is not installed"
[[ -f "$MODSRC/dkms.conf" ]] || die "no dkms.conf in $MODSRC"

# dkms.conf is the single source of truth for name and version, so bumping the
# version there is all it takes — this script follows.
NAME="$(sed -n 's/^PACKAGE_NAME="\(.*\)"$/\1/p'    "$MODSRC/dkms.conf")"
VER="$(sed  -n 's/^PACKAGE_VERSION="\(.*\)"$/\1/p' "$MODSRC/dkms.conf")"
[[ -n "$NAME" && -n "$VER" ]] || die "could not read PACKAGE_NAME/PACKAGE_VERSION from dkms.conf"
DEST="/usr/src/${NAME}-${VER}"
say "$NAME $VER  (kernel $KVER)"

# ── 1. drop every version DKMS currently knows ───────────────────────────────
#
# Every version, not just the one we are about to write: after a version bump
# the old entry would otherwise stay registered and keep autoinstalling itself
# on the next kernel, so the machine would carry two modules of the same name.
if dkms status -m "$NAME" 2>/dev/null | grep -q .; then
    while read -r oldver; do
        [[ -n "$oldver" ]] || continue
        say "removing registered $NAME/$oldver"
        dkms remove -m "$NAME" -v "$oldver" --all > /dev/null 2>&1 || true
        # dkms leaves the source tree behind; that is what we are replacing.
        rm -rf "/usr/src/${NAME}-${oldver}"
    done < <(dkms status -m "$NAME" 2>/dev/null | sed -E 's|^'"$NAME"'[/,] *([^,:]+).*|\1|' | sort -u)
fi
rm -rf "$DEST"

# ── 2. copy the source, and only the source ──────────────────────────────────
say "copying source → $DEST"
install -d -m755 "$DEST"
rsync -a \
    --exclude='*.o' --exclude='*.ko' --exclude='*.ko.xz' --exclude='*.ko.zst' \
    --exclude='.*.cmd' --exclude='*.mod' --exclude='*.mod.c' \
    --exclude='modules.order' --exclude='Module.symvers' --exclude='modules.builtin*' \
    --exclude='.tmp_*' --exclude='*.rmeta' --exclude='*.rlib' --exclude='*.d' \
    --exclude='target/' --exclude='.cache.mk' --exclude='*.symvers' \
    "$MODSRC"/ "$DEST"/

# The excludes are a blacklist, so verify rather than assume: a new kind of
# artefact would otherwise ride along unnoticed for months.
if leaked="$(find "$DEST" \( -name '*.o' -o -name '*.ko*' -o -name '.*.cmd' -o -name '*.mod' \) -print -quit)" \
   && [[ -n "$leaked" ]]; then
    die "build artefacts leaked into $DEST (first: $leaked) — widen the rsync excludes"
fi
chmod +x "$DEST/build-module.sh"
say "copied $(find "$DEST" -type f | wc -l) files, $(du -sh "$DEST" | cut -f1)"

# ── 3. register, build, install ──────────────────────────────────────────────
say "dkms add"
dkms add -m "$NAME" -v "$VER" > /dev/null

say "dkms build ($KVER)"
if ! dkms build -m "$NAME" -v "$VER" -k "$KVER"; then
    die "build failed — the source in $DEST is kept so you can inspect it.
Log: /var/lib/dkms/$NAME/$VER/build/make.log"
fi

say "dkms install"
dkms install -m "$NAME" -v "$VER" -k "$KVER" --force > /dev/null

# ── 4. reload ────────────────────────────────────────────────────────────────
if (( RELOAD )) && [[ "$KVER" == "$(uname -r)" ]]; then
    if lsmod | grep -q '^sysentinel_metrics'; then
        users="$(awk '$1=="sysentinel_metrics" {print $3}' /proc/modules)"
        if [[ "${users:-0}" != "0" ]]; then
            say "module is in use (refcount $users) — not reloading; reboot to pick up the new one"
        else
            say "reloading"
            rmmod sysentinel_metrics || die "rmmod failed; the new module is installed but not live"
            modprobe sysentinel_metrics
        fi
    else
        say "loading"
        modprobe sysentinel_metrics
    fi
    # modprobe.d owns write_gid, so report what actually took effect rather
    # than what the file says.
    say "loaded: $(cat /sys/module/sysentinel_metrics/parameters/write_gid 2>/dev/null \
          | sed 's/^/write_gid=/' || echo 'not loaded')"
elif (( RELOAD )); then
    say "built for $KVER, which is not the running kernel — nothing to reload"
fi

say "done"
dkms status -m "$NAME"
