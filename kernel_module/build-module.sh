#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR GPL-2.0-or-later
#
# Kernel-module build wrapper for sysentinel_metrics, shared by DKMS and akmod.
#
# WHY THIS EXISTS INSTEAD OF `MAKE[0]="make ..."` IN dkms.conf
#
# This is a rust-for-linux module, and that breaks DKMS's core assumption:
# that /lib/modules/<kver>/build is enough to build against. It is not. A
# distro kernel-devel package ships headers and Module.symvers but NOT the
# compiled `core`/`kernel` Rust crates an out-of-tree Rust module links
# against — Fedora's ships an empty rust/Makefile stub and nothing else.
#
# Worse, the Rust crate hash that ends up in every exported symbol name is a
# function of the exact rustc BUILD. Vanilla rustc 1.98.0 from rustup and
# Fedora's rustc 1.98.0 package produce DIFFERENT symbol hashes from identical
# source, so a module built with the wrong one links cleanly and then refuses
# to load with "Invalid module format" or unresolved symbols.
#
# So the build needs two things DKMS cannot find on its own:
#   1. a kernel tree where `make modules_prepare` has ALREADY been run with
#      the right toolchain (so rust/kernel.o and friends exist)
#   2. the exact rustc build recorded in that tree's CONFIG_RUSTC_VERSION_TEXT
#
# This script locates both, verifies them, and refuses to build if either is
# wrong — because the failure mode of guessing is a module that installs
# successfully and cannot be loaded, which is discovered at the worst moment.
#
# Usage (called by dkms.conf and by the akmod spec):
#   ./dkms-build.sh build <kernelver>
#   ./dkms-build.sh clean

set -euo pipefail

ACTION="${1:-build}"
KVER="${2:-$(uname -r)}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

say()  { printf 'sysentinel/dkms: %s\n' "$*" >&2; }
die()  { printf 'sysentinel/dkms: ERROR: %s\n' "$*" >&2; exit 1; }

# ── 1. Our source must be intact ──────────────────────────────────────────────
#
# The point of shipping the source into /usr/src is that losing the git
# checkout never costs the ability to rebuild. The flip side is that a
# half-deleted /usr/src copy must NOT quietly produce a module: a Kbuild whose
# objects are missing can still link something, and "something" is the one
# outcome worth refusing. So every file the Kbuild names is checked up front.
require_sources() {
    local missing=() f
    local -a required=(
        Kbuild Makefile
        sysentinel_core.rs hypercall.rs mei_driver.rs psp.rs ring3.rs smm.rs
        src/mei_shim.c src/psp_shim.c src/smm_shim.c src/proc_entry.c
        src/hypercall_watcher.c src/rootkit_defender.c src/triplefault.c
        src/sysentinel_shared.h
    )
    for f in "${required[@]}"; do
        [[ -f "$HERE/$f" ]] || missing+=("$f")
    done
    if (( ${#missing[@]} )); then
        say "the module source in $HERE is incomplete."
        say "missing: ${missing[*]}"
        die "refusing to build a module from a partial source tree."
    fi
}

# ── 2. A kernel tree with the Rust artefacts already built ───────────────────
#
# Searched in order. The first entry lets a caller override everything; the
# /etc file is how the prepare script records where it put the tree.
find_kdir() {
    local cand candidates=()
    [[ -n "${SYSENTINEL_KDIR:-}" ]] && candidates+=("$SYSENTINEL_KDIR")
    [[ -r "/etc/sysentinel/kdir-$KVER" ]] && candidates+=("$(cat "/etc/sysentinel/kdir-$KVER")")
    candidates+=("/lib/modules/$KVER/build" "/usr/src/kernels/$KVER")

    for cand in "${candidates[@]}"; do
        [[ -n "$cand" && -d "$cand" ]] || continue
        # The tell: a prepared tree has the compiled kernel crate. Headers
        # alone (which is all kernel-devel gives) do not.
        if [[ -f "$cand/rust/kernel.o" || -f "$cand/rust/libkernel.rmeta" ]]; then
            printf '%s\n' "$cand"
            return 0
        fi
    done
    return 1
}

# ── 3. The rustc build that tree was prepared with ───────────────────────────
#
# Matched against CONFIG_RUSTC_VERSION_TEXT verbatim, including the trailing
# "(Fedora 1.98.0-1.fc44)" — that suffix is exactly what distinguishes the
# distro build from the upstream one, and getting it wrong is the silent
# failure this whole script exists to prevent.
find_rustc() {
    local kdir="$1" want cand
    want="$(sed -n 's/^CONFIG_RUSTC_VERSION_TEXT="\(.*\)"$/\1/p' "$kdir/.config" 2>/dev/null || true)"
    [[ -n "$want" ]] || { say "no CONFIG_RUSTC_VERSION_TEXT in $kdir/.config"; return 1; }

    local candidates=()
    [[ -n "${SYSENTINEL_RUSTC:-}" ]] && candidates+=("$SYSENTINEL_RUSTC")
    candidates+=(/opt/sysentinel/toolchain/*/bin/rustc /usr/bin/rustc)

    for cand in "${candidates[@]}"; do
        [[ -x "$cand" ]] || continue
        # LD_LIBRARY_PATH: a relocated distro rustc keeps librustc_driver next
        # to it rather than on the system loader path.
        if [[ "$("$cand" --version 2>/dev/null)" == "$want" ]] \
        || [[ "$(LD_LIBRARY_PATH="$(dirname "$cand")/../lib64" "$cand" --version 2>/dev/null)" == "$want" ]]; then
            printf '%s\n' "$cand"
            return 0
        fi
    done
    say "no rustc matching the kernel tree was found."
    say "  the tree was built with: $want"
    return 1
}

case "$ACTION" in
clean)
    make -C "$HERE" clean KDIR="${SYSENTINEL_KDIR:-/lib/modules/$KVER/build}" > /dev/null 2>&1 || true
    exit 0
    ;;
build) ;;
*) die "unknown action '$ACTION'" ;;
esac

require_sources

KDIR="$(find_kdir)" || die "$(cat <<EOF
no Rust-prepared kernel tree found for $KVER.

A distro kernel-devel package is NOT enough: this module links against the
kernel's compiled Rust crates, which that package does not ship. Prepare one:

    sudo scripts/prepare-kernel-rust-tree.sh $KVER

and it will record the path in /etc/sysentinel/kdir-$KVER for future rebuilds.
EOF
)"
say "kernel tree: $KDIR"

RUSTC="$(find_rustc "$KDIR")" || die "$(cat <<EOF
no matching rustc. Install the exact build the kernel was compiled with — the
prepare script fetches it into /opt/sysentinel/toolchain — or point
SYSENTINEL_RUSTC at it. Building with a different rustc produces a module that
links and then cannot load.
EOF
)"
say "rustc: $RUSTC"

command -v bindgen > /dev/null 2>&1 \
    || [[ -x /opt/sysentinel/toolchain/bin/bindgen ]] \
    || die "bindgen not found (needed by the kernel's Rust build)"
export PATH="/opt/sysentinel/toolchain/bin:$PATH"

# librustc_driver lives beside a relocated distro rustc.
_rustc_lib="$(dirname "$RUSTC")/../lib64"
[[ -d "$_rustc_lib" ]] && export LD_LIBRARY_PATH="$_rustc_lib:${LD_LIBRARY_PATH:-}"

say "building sysentinel_metrics for $KVER (MEI + PSP)"
make -C "$HERE" MEI=y PSP=y KDIR="$KDIR" RUSTC_BIN="$RUSTC"

[[ -f "$HERE/sysentinel_metrics.ko" ]] \
    || die "build reported success but produced no sysentinel_metrics.ko"
say "built: $HERE/sysentinel_metrics.ko"
