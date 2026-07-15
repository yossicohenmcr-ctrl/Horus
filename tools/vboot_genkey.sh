#!/usr/bin/env bash
# vboot_genkey.sh — generate an Ed25519 signing key and emit the C trust-anchor
# header the VBOOT_ENFORCE build compiles in.
#
# Usage: vboot_genkey.sh <out_private_key.pem> <out_anchor_header.h>
#
# The private key is EPHEMERAL for the CI smoke test and is never committed. For
# a real release the private key lives offline / in a hardware token and only the
# generated header (its public half) is fed to the build. See docs/BOOT_INTEGRITY.md.
set -euo pipefail

PRIV="${1:?usage: vboot_genkey.sh <priv.pem> <anchor.h>}"
HDR="${2:?usage: vboot_genkey.sh <priv.pem> <anchor.h>}"

mkdir -p "$(dirname "$PRIV")" "$(dirname "$HDR")"

# Ed25519 private key.
openssl genpkey -algorithm ed25519 -out "$PRIV" >/dev/null 2>&1

# Emit the trust-anchor header (public half) from the freshly generated key.
HERE="$(cd "$(dirname "$0")" && pwd)"
bash "$HERE/vboot_anchor_header.sh" "$PRIV" "$HDR"

echo "vboot_genkey: wrote $PRIV and $HDR"
