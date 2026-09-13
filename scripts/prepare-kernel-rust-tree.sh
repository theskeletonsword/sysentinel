#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR GPL-2.0-or-later
#
# Prepare a kernel source tree that an out-of-tree rust-for-linux module can
# actually be built against, and record where it went so DKMS finds it.
#
# WHY THIS IS NEEDED AT ALL
#
# `dnf install kernel-devel` is enough for a C module and useless for a Rust
# one. The package ships headers, scripts and Module.symvers, but its rust/
# directory contains a single Makefile and nothing else — no compiled `core`,
# no `kernel` crate, none of the .rmeta an external Rust module links against.
# Those artefacts only exist inside a tree where `make modules_prepare` has
# been run.
#
# Four things have to line up, and each one fails differently when it does not:
#
#   1. EXACT rustc BUILD. Not the version — the build. Vanilla 1.98.0 from
#      rustup and Fedora's 1.98.0 package compile identical source into
#      DIFFERENT crate hashes, and those hashes are inside every exported
#      symbol name. Get it wrong and the module links, installs, and then will
#      not load. So the rustc is taken from the same Koji build that produced
#      the running kernel.
#
#   2. EXTRAVERSION. Fedora patches the kernel Makefile during %build, not
#      %prep, so a tree prepared straight from the SRPM reports "7.2.4" where
#      the running kernel says "7.2.4-200.fc44.x86_64". That string feeds the
#      crate hashes too.
#
#   3. pahole. Without it `make olddefconfig` silently turns off
#      CONFIG_DEBUG_INFO_BTF_MODULES, which CHANGES sizeof(struct module).
#      The module then loads far enough to be rejected with
#      ".gnu.linkonce.this_module section size must match".
#
#   4. bindgen. Too old against a modern libclang and it emits every kernel
#      struct as an opaque `_address` blob; the kernel crate then fails to
#      compile with hundreds of "no field" errors that look like a source bug.
#
# Usage:
#   sudo scripts/prepare-kernel-rust-tree.sh [kernel-version]
#
# Defaults to the running kernel. Writes the tree path to
# /etc/sysentinel/kdir-<kver>, which dkms-build.sh reads.
#
# Cost: downloads a kernel SRPM (~160 MB) and expands it (several GB), then
# compiles the kernel's Rust crates. Budget ten minutes and 5 GB.

set -euo pipefail

KVER="${1:-$(uname -r)}"
BASE="${SYSENTINEL_BUILD_BASE:-/builddir/build/BUILD}"
TOOLCHAIN="/opt/sysentinel/toolchain"

say() { printf '==> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "run me as root (I install packages and write /etc and $BASE)"

# Split 7.2.4-200.fc44.x86_64 into version 7.2.4 and release 200.fc44
KVERSION="${KVER%%-*}"
_rest="${KVER#*-}"
KRELEASE="${_rest%.*}"           # 200.fc44
KARCH="${KVER##*.}"              # x86_64
NVR="kernel-${KVERSION}-${KRELEASE}"
say "target kernel: $KVER  (nvr $NVR, arch $KARCH)"

[[ -r "/boot/config-$KVER" ]] \
    || die "/boot/config-$KVER missing — that config is what the tree must match"

# ── 0. host tools ─────────────────────────────────────────────────────────────
say "checking host tools"
missing=()
for t in rpm rpm2cpio cpio dnf curl make gcc flex bison; do
    command -v "$t" > /dev/null || missing+=("$t")
done
(( ${#missing[@]} == 0 )) || die "missing host tools: ${missing[*]}"
# pahole decides CONFIG_DEBUG_INFO_BTF, which decides sizeof(struct module).
command -v pahole > /dev/null || { say "installing dwarves (pahole)"; dnf install -y dwarves; }

# ── 1. the exact rustc/bindgen this kernel was built with ────────────────────
#
# Koji records the buildroot of every package, so the authoritative answer to
# "which rustc built this kernel" is one query away rather than a guess.
if [[ -x "$TOOLCHAIN"/rustc-*/bin/rustc ]]; then
    say "toolchain already present in $TOOLCHAIN"
else
    say "resolving the toolchain the distro used for $NVR (via Koji)"
    kbuild_id=$(curl -sSL --max-time 60 \
        "https://koji.fedoraproject.org/koji/search?terms=${NVR}&type=build&match=exact" \
        | grep -oE 'buildinfo\?buildID=[0-9]+' | head -1 | cut -d= -f2) \
        || die "could not find $NVR in Koji"
    [[ -n "${kbuild_id:-}" ]] || die "could not find $NVR in Koji"

    task=$(curl -sSL --max-time 60 "https://koji.fedoraproject.org/koji/buildinfo?buildID=$kbuild_id" \
        | grep -oE 'taskinfo\?taskID=[0-9]+' | head -1 | cut -d= -f2)
    arch_task=$(curl -sSL --max-time 60 "https://koji.fedoraproject.org/koji/taskinfo?taskID=$task" \
        | grep -oE "taskinfo\?taskID=[0-9]+\"[^>]*>buildArch \([^,]+, ${KARCH}\)" \
        | grep -oE '[0-9]+' | head -1)
    root=$(curl -sSL --max-time 60 "https://koji.fedoraproject.org/koji/taskinfo?taskID=$arch_task" \
        | grep -oE 'buildrootinfo\?buildrootID=[0-9]+' | head -1 | cut -d= -f2)
    rust_nvr=$(for s in 0 50 100 150 200 250 300 350 400 450 500 550 600 650; do
        curl -sSL --max-time 60 "https://koji.fedoraproject.org/koji/rpmlist?buildrootID=${root}&type=component&start=$s"
    done | sed -E 's/<[^>]+>/ /g' | grep -oE 'rust-[0-9]+\.[0-9]+\.[0-9]+-[0-9]+\.fc[0-9]+' | head -1)
    [[ -n "$rust_nvr" ]] || die "could not determine the rust build from the kernel's buildroot"

    rv="${rust_nvr#rust-}"; rver="${rv%%-*}"; rrel="${rv#*-}"
    say "kernel was built with rust ${rver}-${rrel} — fetching that exact build"
    tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
    for pkg in "rust-${rver}-${rrel}.${KARCH}.rpm" "rust-std-static-${rver}-${rrel}.${KARCH}.rpm"; do
        curl -sSL --max-time 300 -o "$tmp/$pkg" \
            "https://kojipkgs.fedoraproject.org/packages/rust/${rver}/${rrel}/${KARCH}/${pkg}" \
            || die "download failed: $pkg"
    done
    curl -sSL --max-time 300 -o "$tmp/rust-src.rpm" \
        "https://kojipkgs.fedoraproject.org/packages/rust/${rver}/${rrel}/noarch/rust-src-${rver}-${rrel}.noarch.rpm"
    mkdir -p "$tmp/x"
    for r in "$tmp"/*.rpm; do (cd "$tmp/x" && rpm2cpio "$r" | cpio -idm --quiet); done
    install -d -m755 "$TOOLCHAIN"
    cp -a "$tmp/x/usr" "$TOOLCHAIN/rustc-${rver}"
    say "installed $TOOLCHAIN/rustc-${rver}"
fi

RUSTC=$(ls "$TOOLCHAIN"/rustc-*/bin/rustc | head -1)
export LD_LIBRARY_PATH="$(dirname "$RUSTC")/../lib64:${LD_LIBRARY_PATH:-}"

if [[ ! -x "$TOOLCHAIN/bin/bindgen" ]] && ! command -v bindgen > /dev/null; then
    say "installing bindgen-cli (0.72.1: new enough for libclang >= 19)"
    command -v cargo > /dev/null || dnf install -y cargo
    cargo install --locked bindgen-cli --version 0.72.1 --root "$TOOLCHAIN" \
        || die "bindgen install failed"
fi
export PATH="$TOOLCHAIN/bin:$PATH"

# ── 2. kernel source ─────────────────────────────────────────────────────────
SRCDIR="$BASE/kernel-${KVERSION}-build/kernel-${KVERSION}/linux-${KVERSION}-${KRELEASE}.${KARCH}"
if [[ -d "$SRCDIR" ]]; then
    say "source tree already present: $SRCDIR"
else
    say "downloading and unpacking the kernel source (this is the slow part)"
    tmp2=$(mktemp -d)
    (cd "$tmp2" && dnf download --source "$NVR" > /dev/null) || die "dnf download --source failed"
    rpm -ivh --force "$tmp2"/kernel-*.src.rpm > /dev/null 2>&1 || true
    # %prep dies on %py3_shebang_fix under a shell without job control. That
    # step only rewrites python shebangs in tools/ and Documentation/, none of
    # which the Rust build touches, so the tree it leaves behind is complete
    # for our purposes.
    rpmbuild -bp --nodeps "$HOME/rpmbuild/SPECS/kernel.spec" > /dev/null 2>&1 || true
    built="$HOME/rpmbuild/BUILD/kernel-${KVERSION}-build"
    [[ -d "$built" ]] || die "%prep produced no tree at $built"
    install -d -m755 "$BASE"
    rm -rf "$BASE/kernel-${KVERSION}-build"
    mv "$built" "$BASE/"
    rm -rf "$tmp2"
    [[ -d "$SRCDIR" ]] || die "expected tree not found at $SRCDIR"
fi

# ── 3. make it match the running kernel ──────────────────────────────────────
cd "$SRCDIR"
say "setting EXTRAVERSION (Fedora does this in %build, which %prep never reaches)"
sed -i "s/^EXTRAVERSION.*/EXTRAVERSION = -${KRELEASE}.${KARCH}/" Makefile
cp -f "/boot/config-$KVER" .config
say "resolving config with the real toolchain on PATH"
make olddefconfig RUSTC="$RUSTC" > /dev/null

got="$(make -s kernelrelease RUSTC="$RUSTC" 2>/dev/null | tail -1)"
[[ "$got" == "$KVER" ]] || die "kernelrelease is '$got', expected '$KVER' — the crate hashes would not match"
grep -q '^CONFIG_DEBUG_INFO_BTF_MODULES=y' .config \
    || die "CONFIG_DEBUG_INFO_BTF_MODULES got disabled — struct module would differ (is pahole installed?)"

# ── 4. build the kernel's Rust crates ────────────────────────────────────────
say "running modules_prepare (compiles core/alloc/kernel — a few minutes)"
make modules_prepare -j"$(nproc)" RUSTC="$RUSTC" HOSTRUSTC="$RUSTC" > /dev/null \
    || die "modules_prepare failed"
[[ -f rust/kernel.o ]] || die "modules_prepare finished but rust/kernel.o is missing"

# Module.symvers from the installed kernel-devel: the tree we just prepared
# only knows the symbols it compiled, not everything the running vmlinux
# exports.
if [[ -r "/usr/src/kernels/$KVER/Module.symvers" ]]; then
    cp -f "/usr/src/kernels/$KVER/Module.symvers" Module.symvers
else
    say "warning: no kernel-devel Module.symvers for $KVER; C-side symbols may not resolve"
fi

# ── 5. tell DKMS where it is ─────────────────────────────────────────────────
install -d -m755 /etc/sysentinel
printf '%s\n' "$SRCDIR" > "/etc/sysentinel/kdir-$KVER"

# Sanity-check the thing that actually matters: do our crate hashes match the
# symbols the running kernel exports?
if [[ -r "/usr/src/kernels/$KVER/Module.symvers" ]]; then
    ours=$(nm rust/kernel.o 2>/dev/null | grep -m1 -oE '_RNvNtCs[A-Za-z0-9_]+_6kernel5print11call_printk' || true)
    theirs=$(grep -m1 -oE '_RNvNtCs[A-Za-z0-9_]+_6kernel5print11call_printk' "/usr/src/kernels/$KVER/Module.symvers" || true)
    if [[ -n "$ours" && -n "$theirs" ]]; then
        if [[ "$ours" == "$theirs" ]]; then
            say "crate hashes match the running kernel — modules built here will load"
        else
            say "WARNING: crate hash mismatch. A module built here will not load."
            say "  ours:   $ours"
            say "  kernel: $theirs"
        fi
    fi
fi

cat <<EOT

════════════════════════════════════════════════════════════
 Ready. Tree recorded in /etc/sysentinel/kdir-$KVER

   $SRCDIR

 DKMS will now find it:
   sudo dkms build  -m sysentinel_metrics -v 0.1.0 -k $KVER
   sudo dkms install -m sysentinel_metrics -v 0.1.0 -k $KVER
════════════════════════════════════════════════════════════
EOT
