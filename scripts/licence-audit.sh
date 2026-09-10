#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR GPL-2.0-or-later
#
# Reproducible provenance check for the Apache-2.0 daemon.
#
# Compares every daemon source file against a GPL-licensed reference tree and
# reports overlapping word sequences. The point is not that overlap is always
# infringement — an ABI's constant names must match by definition — but that
# the overlap should be *small, enumerable and explainable*. A reviewer can run
# this and read every hit, rather than taking anyone's word for it.
#
# Usage:
#   scripts/licence-audit.sh /path/to/linux [ngram]
#
# Exits non-zero if any hit is not on the allowlist of expected categories.

set -euo pipefail

LINUX_SRC="${1:-}"
NGRAM="${2:-7}"

if [[ -z "$LINUX_SRC" || ! -d "$LINUX_SRC" ]]; then
    echo "usage: $0 /path/to/linux [ngram-size]" >&2
    echo "  (a Linux source tree to compare against; not shipped with this repo)" >&2
    exit 2
fi

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

python3 - "$LINUX_SRC" "$NGRAM" "$REPO_ROOT" <<'PY'
import re, sys, pathlib

linux, ngram, repo = pathlib.Path(sys.argv[1]), int(sys.argv[2]), pathlib.Path(sys.argv[3])

# Reference set: the subsystems this daemon talks to. Widen freely — a larger
# corpus only makes the check stricter.
files = []
for rel in [
    "include/uapi/linux/perf_event.h",
    "include/linux/perf_event.h",
    "kernel/events/core.c",
    "Documentation/admin-guide/sysctl/kernel.rst",
    "arch/arm64/include/asm/cputype.h",
]:
    p = linux / rel
    if p.exists():
        files.append(p)
for rel in ["arch/x86/events", "drivers/misc/mei", "drivers/crypto/ccp",
            "tools/perf/util", "tools/lib/perf"]:
    d = linux / rel
    if d.is_dir():
        files += [f for f in d.rglob("*") if f.suffix in (".c", ".h")]

if not files:
    print(f"no reference files found under {linux}", file=sys.stderr)
    raise SystemExit(2)

def normalise(text):
    return re.sub(r"\s+", " ", re.sub(r"[^a-z0-9 ]+", " ", text.lower()))

corpus = normalise("".join(f.read_text(errors="ignore") for f in files))
print(f"reference corpus: {len(corpus)//1024} KB from {len(files)} files under {linux}")
print(f"shingle size: {ngram} words\n")

# Hits that are expected and defensible. Each entry is a substring test plus the
# reason it is not a copyright concern.
ALLOWED = [
    ("gpl 2 0 with linux syscall note",
     "the licence identifier of the UAPI header, quoted in our provenance note"),
    ("format total time",
     "syscall ABI constant names (interface vocabulary, not expression)"),
    ("perf flag fd cloexec",
     "syscall ABI constant name"),
    ("perf type hardware",
     "syscall ABI constant name"),
    ("perf count",
     "syscall ABI constant name"),
    ("perf event ioc",
     "syscall ABI constant name"),
    ("perf attr",
     "syscall ABI constant name"),
    ("perf pmu type shift",
     "syscall ABI constant name"),
]

unexplained, explained = [], []
for f in sorted((repo / "daemon" / "src").rglob("*.rs")):
    words = normalise(f.read_text()).split()
    seen = set()
    for i in range(len(words) - ngram):
        sh = " ".join(words[i:i + ngram])
        if sh in seen or sh not in corpus:
            continue
        seen.add(sh)
        why = next((r for pat, r in ALLOWED if pat in sh), None)
        (explained if why else unexplained).append(
            (f.relative_to(repo), sh, why))

print(f"explained overlaps ({len(explained)}):")
for path, sh, why in explained:
    print(f"  {path}: ...{sh}...\n      -> {why}")

if unexplained:
    print(f"\nUNEXPLAINED overlaps ({len(unexplained)}) — review each one:")
    for path, sh, _ in unexplained:
        print(f"  {path}: ...{sh}...")
    raise SystemExit(1)

print("\nNo unexplained overlap: every match is an ABI identifier or a quoted licence name.")
PY
