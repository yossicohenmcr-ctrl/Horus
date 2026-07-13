#!/usr/bin/env bash
#
# Documentation count guard (audit finding I6).
#
# The project's headline metrics — the number of Rust unit tests and the number
# of gated CI jobs — used to be hand-copied into half a dozen Markdown files and
# drifted out of sync (README said 20 jobs, docs/README said 11, LIMITATIONS said
# both). This script makes those two numbers self-enforcing: it derives the TRUE
# counts from the source of record (the Rust test attributes and ci.yml itself),
# compares them against the single source of truth declared in TESTS.md, and
# fails CI if any tracked doc disagrees. Update TESTS.md's marker and the tracked
# docs together, or the build breaks — no silent drift.
#
# Pure shell + grep/awk, no network and no writes: safe to run anywhere.

set -euo pipefail
cd "$(dirname "$0")/.."

fail() { printf '\033[31mdoc-count guard: %s\033[0m\n' "$*" >&2; exit 1; }

# --- Ground truth, derived from source --------------------------------------

# Rust unit tests: every #[test] in the crate. (cargo test would also work but
# needs a full toolchain build; counting the attribute is deterministic + fast.)
ACTUAL_TESTS=$(grep -rhoE '#\[test\]' rust/src | wc -l | tr -d ' ')

# CI jobs: the keys nested exactly one level under the top-level `jobs:` map in
# ci.yml (2-space indent). Restricting to the jobs section avoids counting the
# 2-space keys under `on:`/`permissions:` etc.
ACTUAL_JOBS=$(awk '
    /^jobs:[[:space:]]*$/ { in_jobs=1; next }
    in_jobs && /^[^[:space:]]/ { in_jobs=0 }          # dedent to col 0 ends the section
    in_jobs && /^  [A-Za-z0-9_-]+:[[:space:]]*$/ { n++ }
    END { print n+0 }
' .github/workflows/ci.yml)

[ "$ACTUAL_TESTS" -gt 0 ] || fail "counted 0 Rust #[test] attributes — is rust/src present?"
[ "$ACTUAL_JOBS" -gt 0 ] || fail "counted 0 CI jobs — did ci.yml layout change?"

# --- Single source of truth: the marker in TESTS.md -------------------------
#
# TESTS.md carries a machine-readable marker of the form:
#   <!-- doc-counts: rust_unit_tests=NN ci_jobs=MM -->
SSOT_FILE=TESTS.md
marker=$(grep -oE '<!--[[:space:]]*doc-counts:[^>]*-->' "$SSOT_FILE" || true)
[ -n "$marker" ] || fail "no '<!-- doc-counts: ... -->' marker found in $SSOT_FILE (the single source of truth)"

decl_tests=$(printf '%s' "$marker" | grep -oE 'rust_unit_tests=[0-9]+' | grep -oE '[0-9]+' || true)
decl_jobs=$(printf '%s'  "$marker" | grep -oE 'ci_jobs=[0-9]+'         | grep -oE '[0-9]+' || true)
[ -n "$decl_tests" ] || fail "marker in $SSOT_FILE is missing rust_unit_tests=N"
[ -n "$decl_jobs"  ] || fail "marker in $SSOT_FILE is missing ci_jobs=N"

[ "$decl_tests" = "$ACTUAL_TESTS" ] || fail \
    "$SSOT_FILE marker says rust_unit_tests=$decl_tests but rust/src has $ACTUAL_TESTS #[test] — update the marker and the docs."
[ "$decl_jobs" = "$ACTUAL_JOBS" ] || fail \
    "$SSOT_FILE marker says ci_jobs=$decl_jobs but ci.yml has $ACTUAL_JOBS jobs — update the marker and the docs."

# --- No tracked doc may state a different number ----------------------------
#
# The live docs that quote the counts. Both digit ("20 jobs") and English
# word-form ("twenty gated jobs") are checked, since the original drift hid a
# spelled-out "eleven jobs" from a digits-only scan. Historical records
# (CHANGES.md, the changelog) are intentionally out of scope — a past release
# legitimately reports the count it shipped with.
TRACKED_DOCS=(README.md SECURITY.md TESTS.md docs/README.md docs/LIMITATIONS.md docs/ROADMAP.md)

# English number words -> value, covering any realistic CI job count. A spelled
# count outside this range simply isn't matched (the digit form still is).
declare -A WORD2NUM=(
    [zero]=0 [one]=1 [two]=2 [three]=3 [four]=4 [five]=5 [six]=6 [seven]=7
    [eight]=8 [nine]=9 [ten]=10 [eleven]=11 [twelve]=12 [thirteen]=13
    [fourteen]=14 [fifteen]=15 [sixteen]=16 [seventeen]=17 [eighteen]=18
    [nineteen]=19 [twenty]=20 [thirty]=30 [forty]=40
)

for f in "${TRACKED_DOCS[@]}"; do
    [ -f "$f" ] || fail "tracked doc $f is missing"
    # Unit-test count in either order: "<n> unit tests" or "unit tests (<n>)".
    while read -r n; do
        [ "$n" = "$ACTUAL_TESTS" ] || fail "$f states $n unit tests but the real count is $ACTUAL_TESTS"
    done < <( { grep -oiE '[0-9]+ (rust )?unit tests' "$f" | grep -oE '^[0-9]+'
               grep -oiE 'unit tests \([0-9]+\)' "$f" | grep -oE '[0-9]+'; } || true)
    # Any digit "<n> ... jobs" (optionally 'gated'/'CI') must equal ACTUAL_JOBS.
    while read -r n; do
        [ "$n" = "$ACTUAL_JOBS" ] || fail "$f states '$n ... jobs' but the real count is $ACTUAL_JOBS"
    done < <(grep -oiE '[0-9]+ (gated |ci )*jobs' "$f" | grep -oE '^[0-9]+' || true)
    # Any word-form "<word> ... jobs" whose word is a known number must match too.
    while read -r w; do
        w=$(printf '%s' "$w" | tr '[:upper:]' '[:lower:]')
        v=${WORD2NUM[$w]:-}
        [ -z "$v" ] && continue          # not a number word (e.g. "all", "of") — ignore
        [ "$v" = "$ACTUAL_JOBS" ] || fail "$f states '$w jobs' (=$v) but the real count is $ACTUAL_JOBS"
    done < <(grep -oiE '[a-z]+ (gated |ci )*jobs' "$f" | grep -oiE '^[a-z]+' || true)
done

printf 'doc-count guard: OK — %s Rust unit tests, %s CI jobs (consistent across TESTS.md + tracked docs).\n' \
    "$ACTUAL_TESTS" "$ACTUAL_JOBS"
