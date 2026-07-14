/*
 * verified_boot.c — Ed25519 verified-boot gate (audit finding 3.3, runtime half).
 *
 * Demonstrates and CI-tests the runtime boot-integrity mechanism: the kernel
 * verifies an Ed25519 signature over a signed manifest against an EMBEDDED
 * public key (the fixed trust anchor) and refuses to proceed — halting — if the
 * signature does not verify. The verifier is safe Rust (rust/src/ed25519.rs),
 * validated against the RFC 8032 known-answer vectors AND against an
 * OpenSSL-produced signature (cross-implementation).
 *
 * Trust model (honest): the anchor is the public key + verifier compiled into
 * the kernel's early boot path. This defeats any tampering of the signed payload
 * by a party that cannot re-sign it (bit-rot, disk tampering without the private
 * key). It is DESIGNED to be anchored underneath by UEFI Secure Boot (Phase A)
 * or a write-protected boot medium, at which point the chain is hardware-rooted;
 * without that anchor it is boot-time integrity / defence-in-depth, not a
 * guarantee against an attacker who can also rewrite the kernel image. Production
 * verified boot signs the actual shipped image with an OFFLINE key and embeds
 * that key as the anchor — wired in .github/workflows/release.yml. See
 * docs/BOOT_INTEGRITY.md.
 *
 * This file's body is compiled only under VBOOT_SELFTEST; the Ed25519 verifier
 * itself is always available via the Rust staticlib.
 */
#include "kernel.h"

#ifdef VBOOT_SELFTEST

/* Fixed trust anchor: an Ed25519 public key (32 bytes). In the self-test this is
 * an ephemeral key whose signature below was produced by OpenSSL 3.x; in
 * production this is replaced by the release signing key's public half. */
static const uint8_t VBOOT_PUBKEY[32] = {
    0x4d, 0xc9, 0x01, 0x35, 0x6b, 0x99, 0x20, 0x13, 0x67, 0x8f, 0x02, 0x95, 0xd9, 0x7a, 0x90, 0x89,
    0xd7, 0xab, 0x5f, 0xd9, 0xaf, 0xfc, 0xff, 0xa2, 0xbd, 0x34, 0x60, 0x36, 0x0c, 0x83, 0xcb, 0xe9,
};

/* The signed manifest (the payload whose authenticity gates the boot). */
static const uint8_t VBOOT_PAYLOAD[] =
    "Horus verified-boot anchor v1: this signed manifest authorizes the kernel to proceed.";
#define VBOOT_PAYLOAD_LEN (sizeof(VBOOT_PAYLOAD) - 1) /* drop the NUL terminator */

/* The Ed25519 signature over VBOOT_PAYLOAD by VBOOT_PUBKEY (64 bytes: R||S),
 * produced offline by OpenSSL. */
static const uint8_t VBOOT_SIG[64] = {
    0x52, 0x40, 0xf2, 0xe7, 0x17, 0xbb, 0x4c, 0x13, 0x2e, 0x00, 0x1e, 0x80, 0xa4, 0x8d, 0xe3, 0xdd,
    0x03, 0x4c, 0x6a, 0x5f, 0x3e, 0x91, 0xe6, 0x18, 0xf2, 0x19, 0xfb, 0x28, 0xca, 0x67, 0x5e, 0x3c,
    0x87, 0x2a, 0x7f, 0xa7, 0x38, 0x30, 0xce, 0x21, 0x0e, 0x38, 0x91, 0xd5, 0x1f, 0x15, 0x73, 0xc9,
    0x39, 0x2c, 0x28, 0xf3, 0xfe, 0xf5, 0x90, 0xef, 0x77, 0x5d, 0x2e, 0x55, 0xcf, 0xac, 0x21, 0x07,
};

static void halt_forever(void) {
    for (;;) {
        __asm__ volatile ("cli; hlt" ::: "memory");
    }
}

void verified_boot_selftest(void) {
    /* Copy the payload so the tamper build can corrupt it after the anchor is
     * fixed — modelling an attacker flipping a byte of a signed image. */
    uint8_t payload[VBOOT_PAYLOAD_LEN];
    for (uint32_t i = 0; i < VBOOT_PAYLOAD_LEN; i++) payload[i] = VBOOT_PAYLOAD[i];

#ifdef VBOOT_TAMPER
    /* Reject path: corrupt the signed payload. Verification MUST fail and the
     * kernel MUST refuse to boot. */
    payload[0] ^= 0x01;
#endif

    int ok = rust_ed25519_verify(VBOOT_PUBKEY, VBOOT_SIG, payload, VBOOT_PAYLOAD_LEN);

#ifdef VBOOT_TAMPER
    if (ok) {
        /* A tampered payload verified — the gate is broken. */
        println("VBOOT_SELFTEST: FAIL tampered manifest was accepted");
    } else {
        println("VBOOT_SELFTEST: PASS tampered manifest rejected -- halting boot");
    }
#else
    if (ok) {
        println("VBOOT_SELFTEST: PASS manifest signature verified -- boot authorized");
    } else {
        println("VBOOT_SELFTEST: FAIL valid signature was rejected -- halting boot");
    }
#endif

    /* In both configurations the self-test ends by halting: the marker on serial
     * is what the CI harness asserts, and a real reject must not continue. */
    halt_forever();
}

#endif /* VBOOT_SELFTEST */
