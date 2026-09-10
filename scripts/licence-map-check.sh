#!/usr/bin/env bash
# SPDX-License-Identifier: MIT OR GPL-2.0-or-later
#
# Guard the per-directory licence map.
#
# This repository is deliberately NOT uniformly licensed: daemon/ is Apache-2.0
# while kernel_module/, ramdisk/ and scripts/ are MIT OR GPL-2.0-or-later. That
# only stays true if every new file says so, so this checks:
#
#   1. every source file carries an SPDX-License-Identifier;
#   2. it is the one its directory is declared to use;
#   3. the licence texts each directory promises are actually present, and are
#      real licences rather than placeholders.
#
# All three have drifted before. Run from anywhere; exits non-zero on any gap.

set -euo pipefail

cd "$(dirname "${BASH_SOURCE[0]}")/.."

APACHE="Apache-2.0"
DUAL="MIT OR GPL-2.0-or-later"

fail=0
note() { printf '  %s\n' "$*"; }
bad()  { printf '  ✗ %s\n' "$*"; fail=1; }

# ── 1 + 2: SPDX header on every source file, matching its directory ──────────
echo "SPDX headers:"
checked=0
while IFS= read -r f; do
    case "$f" in
        # Licence texts, docs and data carry no SPDX of their own.
        LICENSE|NOTICE|*/LICENSE|*/LICENSE-*|*/NOTICE|*.md|*.lock|*.toml.orig) continue ;;
        ramdisk/face/models/*) continue ;;
    esac
    case "$f" in
        *.rs|*.c|*.h|*.sh|*.toml|*.service|Makefile|*/Makefile|*/Kbuild) ;;
        *) continue ;;
    esac

    case "$f" in
        daemon/*)        want="$APACHE" ;;
        kernel_module/*) want="$DUAL" ;;
        ramdisk/*)       want="$DUAL" ;;
        scripts/*)       want="$DUAL" ;;
        *)               want="" ;;   # root files: accept either
    esac

    got=$(head -5 "$f" | sed -n 's/.*SPDX-License-Identifier:[[:space:]]*//p' | head -1)
    got="${got%%$'\r'*}"
    checked=$((checked + 1))

    if [[ -z "$got" ]]; then
        bad "$f has no SPDX-License-Identifier"
        continue
    fi
    # kernel_module's build files are GPL-2.0-only on purpose (kbuild glue).
    if [[ "$f" == kernel_module/Kbuild || "$f" == kernel_module/Makefile ]]; then
        [[ "$got" == "GPL-2.0-only" ]] || bad "$f: expected GPL-2.0-only, found '$got'"
        continue
    fi
    if [[ -n "$want" && "$got" != "$want" ]]; then
        bad "$f: expected '$want' for its directory, found '$got'"
    fi
done < <(git ls-files)
note "checked $checked files"

# ── 3: the licence texts each directory promises ─────────────────────────────
echo "Licence texts:"
require_licence() {
    local path="$1" min="$2" must="$3"
    if [[ ! -f "$path" ]]; then
        bad "$path is missing"
        return
    fi
    local lines
    lines=$(wc -l < "$path")
    if (( lines < min )); then
        bad "$path has only $lines lines — expected at least $min (a real licence, not a stub)"
        return
    fi
    if ! grep -qF "$must" "$path"; then
        bad "$path does not contain the expected text: $must"
        return
    fi
    if grep -qiE 'placeholder|obtain the official text' "$path"; then
        bad "$path is still a placeholder"
        return
    fi
    note "✓ $path ($lines lines)"
}

require_licence LICENSE                    190 "Apache License"
require_licence daemon/LICENSE             190 "Apache License"
require_licence kernel_module/LICENSE-MIT   15 "MIT License"
require_licence kernel_module/LICENSE-GPL  300 "GNU GENERAL PUBLIC LICENSE"
require_licence ramdisk/LICENSE-MIT         15 "MIT License"
require_licence ramdisk/LICENSE-GPL        300 "GNU GENERAL PUBLIC LICENSE"

# The GPL text must be the whole thing, not an excerpt.
for gpl in kernel_module/LICENSE-GPL ramdisk/LICENSE-GPL; do
    [[ -f "$gpl" ]] || continue
    grep -q "END OF TERMS AND CONDITIONS" "$gpl" \
        || bad "$gpl is truncated (no END OF TERMS AND CONDITIONS)"
    grep -q "NO WARRANTY" "$gpl" \
        || bad "$gpl is truncated (no NO WARRANTY section)"
done

# ── 4: every MODULE_LICENSE agrees with the dual licence ─────────────────────
echo "MODULE_LICENSE idents:"
while IFS= read -r decl; do
    file="${decl%%:*}"
    if [[ "$decl" != *'"Dual MIT/GPL"'* ]]; then
        bad "$file declares a MODULE_LICENSE other than \"Dual MIT/GPL\": ${decl#*:}"
    else
        note "✓ $file"
    fi
done < <(grep -rn 'MODULE_LICENSE(\|license: "' kernel_module --include='*.c' --include='*.rs' || true)

echo
if (( fail )); then
    echo "licence map: FAILED — see the ✗ lines above" >&2
    exit 1
fi
echo "licence map: OK — every file, licence text and module ident agrees."
