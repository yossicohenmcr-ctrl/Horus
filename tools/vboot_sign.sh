#!/usr/bin/env bash
# vboot_sign.sh — sign the loaded kernel image and patch the detached signature
# into its .vboot_sig slot (VBOOT_ENFORCE real-image verified boot).
#
# Usage: vboot_sign.sh <kernel.elf> <private_key.pem>
#
# The signed MESSAGE is exactly the bytes the kernel hashes at boot:
# [__image_start, __vboot_sig_start) of the single contiguous PT_LOAD (see
# linker64_vboot.ld). Because that segment is loaded verbatim by GRUB, the flat
# `objcopy -O binary` prefix here is byte-identical to what the kernel sees in
# memory. The 64-byte Ed25519 signature is written into the .vboot_sig section,
# which sits OUTSIDE the signed region.
set -euo pipefail

ELF="${1:?usage: vboot_sign.sh <kernel.elf> <priv.pem>}"
PRIV="${2:?usage: vboot_sign.sh <kernel.elf> <priv.pem>}"

OBJCOPY="${OBJCOPY:-objcopy}"
NM="${NM:-nm}"
BASE=0x100000   # kernel load / link address (linker64_vboot.ld)

TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

# Address of the signature slot; the hashed region is everything before it.
SIG_ADDR=$($NM "$ELF" | awk '$3=="__vboot_sig_start"{print $1}')
if [ -z "$SIG_ADDR" ]; then
    echo "vboot_sign: __vboot_sig_start not found in $ELF (build with VBOOT_ENFORCE=1?)" >&2
    exit 1
fi
SIG_OFFSET=$(( 0x$SIG_ADDR - BASE ))
if [ "$SIG_OFFSET" -le 0 ]; then
    echo "vboot_sign: computed non-positive signed-region length ($SIG_OFFSET)" >&2
    exit 1
fi

# Flat loaded image, then take exactly the signed prefix [0, SIG_OFFSET).
$OBJCOPY -O binary "$ELF" "$TMP/image.bin"
head -c "$SIG_OFFSET" "$TMP/image.bin" > "$TMP/region.bin"

# Ed25519 (PureEdDSA) signature over the region — one-shot, no pre-hash.
openssl pkeyutl -sign -inkey "$PRIV" -rawin -in "$TMP/region.bin" -out "$TMP/sig.bin"

SIG_LEN=$(wc -c < "$TMP/sig.bin")
if [ "$SIG_LEN" -ne 64 ]; then
    echo "vboot_sign: expected a 64-byte Ed25519 signature, got $SIG_LEN" >&2
    exit 1
fi

# Patch the signature into the .vboot_sig slot (same size, in place).
$OBJCOPY --update-section .vboot_sig="$TMP/sig.bin" "$ELF"

echo "vboot_sign: signed $SIG_OFFSET-byte image region and patched .vboot_sig in $ELF"
