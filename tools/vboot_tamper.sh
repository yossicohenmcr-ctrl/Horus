#!/usr/bin/env bash
# vboot_tamper.sh — flip one byte inside the SIGNED region of a signed kernel
# image, to prove the VBOOT_ENFORCE gate rejects a tampered image.
#
# Usage: vboot_tamper.sh <kernel.elf>
#
# The byte is flipped inside .rodata: it is part of the hashed region (so the
# signature no longer matches) but is not executed, so the kernel still reaches
# the verify and prints its FAIL marker rather than crashing first.
set -euo pipefail

ELF="${1:?usage: vboot_tamper.sh <kernel.elf>}"

# .rodata file offset + size (the section is loaded and hashed, never executed).
# readelf's "[ Nr]" index column shifts field positions, so locate ".rodata" by
# value and read the columns that follow it: Name Type Address Off Size ...
read -r OFF SIZE < <(readelf -SW "$ELF" | awk '{
    for (i = 1; i <= NF; i++)
        if ($i == ".rodata") { print $(i+3), $(i+4); exit }
}')
if [ -z "${OFF:-}" ] || [ -z "${SIZE:-}" ]; then
    echo "vboot_tamper: could not locate .rodata in $ELF" >&2
    exit 1
fi

# Flip a byte in the middle of .rodata (offset/size are hex from readelf).
TARGET=$(( 0x$OFF + 0x$SIZE / 2 ))

python3 - "$ELF" "$TARGET" <<'PY'
import sys
path, off = sys.argv[1], int(sys.argv[2])
with open(path, "r+b") as f:
    f.seek(off)
    b = f.read(1)
    f.seek(off)
    f.write(bytes([b[0] ^ 0x01]))
print(f"vboot_tamper: flipped one bit at file offset {off:#x} of {path}")
PY
