#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR GPL-2.0-or-later
#
# Build the sysentinel_metrics akmod source package and register it with
# akmods, so Fedora rebuilds the module whenever a new kernel is installed.
#
# akmods is Fedora's own mechanism and is wired into the kernel install path
# already; DKMS (scripts/update-module.sh) does the same job on everything
# else. Use whichever your distro ships — running both works but buys nothing.
#
# Usage:
#   sudo scripts/install-akmod.sh [--build-now] [--no-register]
#
#   --build-now    also build for the running kernel immediately, instead of
#                  waiting for the next kernel install
#   --no-register  build the SRPM but do not drop it in /usr/src/akmods

set -euo pipefail

BUILD_NOW=0
REGISTER=1
while (( $# )); do
    case "$1" in
        --build-now)   BUILD_NOW=1; shift ;;
        --no-register) REGISTER=0;  shift ;;
        -h|--help) sed -n '2,18p' "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 1 ;;
    esac
done

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MODSRC="$REPO/kernel/linux"
SPEC="$REPO/packaging/akmod/sysentinel_metrics-kmod.spec"

say() { printf '==> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

[[ -f "$SPEC" ]] || die "spec not found: $SPEC"
command -v rpmbuild  > /dev/null || die "rpm-build is not installed (dnf install rpm-build)"
command -v kmodtool  > /dev/null || die "kmodtool not found (dnf install akmods)"

# akmod and DKMS install the same module to DIFFERENT paths
# (extra/sysentinel_metrics/ vs extra/), so they do not collide at install
# time — depmod simply ends up knowing two modules called sysentinel_metrics
# and picking one by search order. For a module that can power the machine off,
# that is not a coin worth flipping.
if command -v dkms > /dev/null && dkms status -m sysentinel_metrics 2>/dev/null | grep -q .; then
    cat >&2 <<EOF
error: sysentinel_metrics is already registered with DKMS:

$(dkms status -m sysentinel_metrics)

Use one mechanism, not both. To switch to akmod:

    sudo dkms remove -m sysentinel_metrics -v 0.1.0 --all
    sudo rm -rf /usr/src/sysentinel_metrics-0.1.0
    sudo scripts/install-akmod.sh --build-now

To stay on DKMS, just do not run this script.
EOF
    exit 1
fi

NAME="sysentinel_metrics-kmod"
VER="$(sed -n 's/^Version:[[:space:]]*\(.*\)$/\1/p' "$SPEC" | head -1)"
[[ -n "$VER" ]] || die "could not read Version from the spec"
say "$NAME $VER"

# ── 1. source tarball ─────────────────────────────────────────────────────────
#
# Same exclusions as the DKMS copy, and for the same reason: kernel/linux/ is
# also a working build directory, and shipping one machine's *.o into a source
# package makes every later rebuild start from stale objects.
TOP="$(mktemp -d)"
trap 'rm -rf "$TOP"' EXIT
mkdir -p "$TOP"/{SOURCES,SPECS,BUILD,SRPMS,RPMS}
STAGE="$TOP/stage/$NAME-$VER"
mkdir -p "$STAGE"

say "staging source"
rsync -a \
    --exclude='*.o' --exclude='*.ko' --exclude='*.ko.xz' --exclude='*.ko.zst' \
    --exclude='.*.cmd' --exclude='*.mod' --exclude='*.mod.c' \
    --exclude='modules.order' --exclude='Module.symvers' --exclude='modules.builtin*' \
    --exclude='.tmp_*' --exclude='*.rmeta' --exclude='*.rlib' --exclude='*.d' \
    --exclude='target/' --exclude='.cache.mk' --exclude='*.symvers' \
    "$MODSRC"/ "$STAGE"/

if leaked="$(find "$STAGE" \( -name '*.o' -o -name '*.ko*' -o -name '.*.cmd' \) -print -quit)" \
   && [[ -n "$leaked" ]]; then
    die "build artefacts leaked into the tarball (first: $leaked)"
fi
chmod +x "$STAGE/build-module.sh"

tar -C "$TOP/stage" -cJf "$TOP/SOURCES/$NAME-$VER.tar.xz" "$NAME-$VER"
cp "$SPEC" "$TOP/SPECS/"
say "tarball: $(du -h "$TOP/SOURCES/$NAME-$VER.tar.xz" | cut -f1), $(find "$STAGE" -type f | wc -l) files"

# ── 2. source RPM ────────────────────────────────────────────────────────────
say "building SRPM"
rpmbuild --define "_topdir $TOP" -bs "$TOP/SPECS/$(basename "$SPEC")" > "$TOP/rpmbuild.log" 2>&1 \
    || { tail -20 "$TOP/rpmbuild.log" >&2; die "rpmbuild -bs failed"; }
SRPM="$(find "$TOP/SRPMS" -name '*.src.rpm' | head -1)"
[[ -n "$SRPM" ]] || die "rpmbuild produced no SRPM"
say "built $(basename "$SRPM")"

(( REGISTER )) || { cp "$SRPM" .; say "left $(basename "$SRPM") here (not registered)"; exit 0; }

# ── 3. register with akmods ──────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || die "run me as root to register (I write /usr/src/akmods)"

install -d -m755 /usr/src/akmods
# Drop any previous revision so the .latest symlink cannot point at a stale one.
rm -f /usr/src/akmods/"$NAME"-*.src.rpm /usr/src/akmods/"$NAME".latest
install -m644 "$SRPM" /usr/src/akmods/
ln -sf "$(basename "$SRPM")" "/usr/src/akmods/$NAME.latest"
say "registered: /usr/src/akmods/$NAME.latest -> $(basename "$SRPM")"

# ── 4. optionally build now ──────────────────────────────────────────────────
if (( BUILD_NOW )); then
    KVER="$(uname -r)"
    if [[ ! -r "/etc/sysentinel/kdir-$KVER" ]]; then
        say "WARNING: no prepared kernel tree recorded for $KVER."
        say "  akmods will fail until: sudo scripts/prepare-kernel-rust-tree.sh $KVER"
    fi
    say "akmods --force --kernels $KVER"
    # akmods exits 0 even when it reports [FAILED], so its exit status says
    # nothing. Ask the only question that matters instead: is the module there?
    akmods --force --kernels "$KVER" || true

    failed_log="$(find /var/cache/akmods/sysentinel_metrics -name "*for-${KVER}.failed.log" 2>/dev/null | head -1)"
    if ! modinfo -k "$KVER" sysentinel_metrics > /dev/null 2>&1; then
        [[ -n "$failed_log" ]] && { echo "--- last 15 lines of $failed_log ---" >&2; tail -15 "$failed_log" >&2; }
        die "akmods did not produce an installed module for $KVER"
    fi
    say "installed: $(modinfo -k "$KVER" -F filename sysentinel_metrics)"
fi

cat <<EOT

════════════════════════════════════════════════════════════
 akmod registered. On the next kernel install Fedora runs
 akmods, which rebuilds this module from the source package.

 It needs a prepared kernel tree for that kernel first:
   sudo scripts/prepare-kernel-rust-tree.sh <new-kernel-version>

 Build for a kernel by hand:
   sudo akmods --force --kernels <kernel-version>
════════════════════════════════════════════════════════════
EOT
