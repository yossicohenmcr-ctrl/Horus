#!/usr/bin/env bash
#
# Zero-dependency guard (audit finding I5).
#
# Horus's security core is a #![no_std] staticlib that pulls in NO third-party
# crates on purpose: the entire Rust trusted base is the code in rust/src, so
# there is nothing to audit, pin, or trust beyond the compiler itself. This
# script enforces that policy mechanically. It reads the committed
# rust/Cargo.lock — the resolved dependency graph — and fails if it contains any
# package other than the crate itself. Adding a dependency to rust/Cargo.toml
# regenerates the lock with the new package, so the next commit trips this guard
# and the zero-dependency property cannot erode silently.
#
# Pair with `cargo ... --locked` in CI (the `rust` job) so a dependency added to
# Cargo.toml but not committed to the lock also fails, rather than silently
# rewriting the lock during the build.
#
# Pure shell + grep/awk, no network and no writes: safe to run anywhere.

set -euo pipefail
cd "$(dirname "$0")/.."

fail() { printf '\033[31mzero-dep guard: %s\033[0m\n' "$*" >&2; exit 1; }

LOCK=rust/Cargo.lock

# The only package permitted in the resolved graph. This is the crate itself;
# any other name is a third-party (or path/git) dependency and is forbidden.
ALLOWED=horus_shell

[ -f "$LOCK" ] || fail "$LOCK is missing — it must be committed (the zero-dep policy is enforced against it)."

# Every resolved package appears as a `name = "..."` line under a [[package]]
# table; `name =` occurs nowhere else in a lockfile, so a plain scan is exact.
PACKAGES=$(grep -E '^name = "' "$LOCK" | sed -E 's/^name = "(.*)"$/\1/')

[ -n "$PACKAGES" ] || fail "$LOCK lists no packages — is it truncated or malformed?"

# Anything that is not the allowed crate is a forbidden dependency.
EXTRA=$(printf '%s\n' "$PACKAGES" | grep -vxF "$ALLOWED" || true)

if [ -n "$EXTRA" ]; then
    printf '\033[31mzero-dep guard: rust/Cargo.lock gained forbidden package(s) beyond "%s":\033[0m\n' "$ALLOWED" >&2
    printf '  - %s\n' $EXTRA >&2
    printf 'Horus enforces a zero-third-party-dependency policy for its Rust trusted base.\n' >&2
    printf 'Remove the dependency, or (if it is genuinely required) update the ALLOWED list\n' >&2
    printf 'in tools/check_zero_deps.sh in the same reviewed commit that justifies it.\n' >&2
    exit 1
fi

COUNT=$(printf '%s\n' "$PACKAGES" | grep -c .)
printf 'zero-dep guard: OK — rust/Cargo.lock has %s package (%s) and no third-party dependencies.\n' \
    "$COUNT" "$ALLOWED"
