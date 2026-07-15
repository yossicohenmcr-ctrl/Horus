/*
 * linker64_vboot.ld — link script for VBOOT_ENFORCE (real-image verified boot).
 *
 * Identical section layout to linker64.ld, with two differences that make the
 * loaded kernel image a single, contiguous, deterministically-hashable blob:
 *
 *   1. A single PT_LOAD program header ("image", RWX) holds .text/.rodata/.data
 *      (and .bss). The default script emits three PT_LOADs (R E / R / RW) with
 *      alignment gaps between them; GRUB does not zero inter-segment memory, so
 *      those gaps would hash non-deterministically at boot. Packed into one
 *      segment, every ALIGN(4K) gap becomes in-file zero padding covered by the
 *      segment's filesz and loaded verbatim — so the bytes in memory over
 *      [__image_start, __vboot_sig_start) are byte-for-byte the bytes the release
 *      signer hashes from the ELF.
 *
 *   2. A `.vboot_sig` slot (64 bytes) sits at the end of the file-backed image,
 *      after .data and before .bss. It holds the detached Ed25519 signature,
 *      patched in post-build by tools/vboot_sign.sh. It is OUTSIDE the hashed
 *      region [__image_start, __vboot_sig_start) — a signature cannot cover the
 *      bytes that are itself.
 *
 * This script is used ONLY for VBOOT_ENFORCE builds (the signed release and the
 * smoke-vboot-image CI test); the default/ship kernel keeps linker64.ld and its
 * three-segment W^X layout unchanged.
 */
ENTRY(_start)

PHDRS
{
    image PT_LOAD FLAGS(7);   /* one RWX segment: no inter-segment memory gaps */
}

SECTIONS
{
    . = 0x100000;
    __image_start = .;

    .text : ALIGN(4K)
    {
        *(.multiboot)
        *(.text)
        *(.text.*)
    } :image

    .rodata : ALIGN(4K)
    {
        *(.rodata)
        *(.rodata.*)
    } :image

    /*
     * Signature slot: 64 file-backed bytes, sitting AFTER the immutable sections
     * (.text, .rodata) and BEFORE .data. The hashed region is therefore
     * [__image_start, __vboot_sig_start) = .text + .rodata only: the kernel's
     * executable code and its read-only constants, which are byte-for-byte
     * identical in the file and in memory at boot. `.data` (writable, initialised
     * globals) is deliberately excluded — early boot mutates some of it (e.g. the
     * terminal state) before the verify runs, so its runtime bytes would not
     * match the signed file. Tampering .text or .rodata — where all code and
     * constants live — is caught; see docs/BOOT_INTEGRITY.md for the residual.
     */
    .vboot_sig : ALIGN(64)
    {
        __vboot_sig_start = .;
        KEEP(*(.vboot_sig))
        __vboot_sig_end = .;
    } :image

    .data : ALIGN(4K)
    {
        *(.data)
        *(.data.*)
    } :image

    .bss : ALIGN(4K)
    {
        PROVIDE(kernel_bss_floor = .);
        *(COMMON)
        *(.bss)
        *(.bss.*)
    } :image

    /DISCARD/ : { *(.comment) *(.note.*) }
}
