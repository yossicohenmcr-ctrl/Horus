# Boot Integrity & Build Provenance

This document addresses audit finding **3.3**: reproducible builds prove *source
→ identical binary*, but until now nothing bound the *running* kernel to that
reviewed source, and the machine had no way to refuse a tampered image. Boot
integrity has two independent trust anchors; this document covers both and is
honest about which is implemented.

| Anchor | Question it answers | Status |
|---|---|---|
| **Build provenance** | "Did this `kernel.elf` come from this repo's CI, built from a reviewed commit?" | **Implemented** (`.github/workflows/release.yml`) |
| **Runtime verified boot** | "Will the machine refuse to run an image it cannot verify?" | **Phase B verifier implemented & CI-gated** (Ed25519 verify-or-halt, `src/kernel/verified_boot.c`); production image-anchoring pending (Phase A–C below) |

---

## 1. Build provenance (implemented)

`release.yml` runs on a `v*` tag and:

1. Builds `kernel.elf` via `make reproducible-build` (deterministic, pinned
   `SOURCE_DATE_EPOCH` + toolchain) and the bootable ISO.
2. Emits `SHA256SUMS` over the artifacts.
3. Generates a **SLSA build-provenance attestation** with
   `actions/attest-build-provenance`, signed **keyless** via Sigstore using the
   workflow's short-lived OIDC identity (no long-lived signing key exists to be
   stolen). The attestation binds each artifact's SHA-256 digest to the workflow
   run and the source commit, and is recorded in the repository's attestation
   store.
4. Publishes a signed GitHub Release with the artifacts, manifest, and (best
   effort) a CycloneDX SBOM.

### What this gives a relying party

```
gh attestation verify kernel.elf --repo yossicohenmcr-ctrl/Horus
sha256sum -c SHA256SUMS
```

The first command confirms the binary was produced by **this repository's CI at
a specific commit** (not substituted, not built elsewhere). Combined with the
reproducible build, an auditor can independently rebuild the byte-identical
`kernel.elf` from that commit and confirm it matches the attested digest — an
end-to-end chain from **reviewed source → CI → published binary**.

### Residual limits

Provenance answers "where did this binary come from," **not** "is the machine
running it." A local attacker who replaces the on-disk kernel defeats provenance
entirely, because nothing on the boot path checks it. That is Phase A–C.

---

## 2. Runtime verified boot (Phase B verifier implemented; anchoring in progress)

**Design principle — the verifier must be strictly more trusted than the
verified.** A kernel cannot meaningfully verify itself: if it is tampered, so is
its own check. Verification must live *below* the kernel (firmware / bootloader
/ a minimal first stage) and root in something the attacker cannot silently
replace (Secure Boot keys, or a key in write-protected/known-good storage).

### What is implemented now

The Ed25519 **verify-or-halt mechanism** exists and is gated in CI. On boot the
kernel verifies a signed manifest against a public key **embedded in the boot
path** (the trust anchor) and, on any signature failure, prints its marker and
**halts** — a tampered payload cannot proceed (`src/kernel/verified_boot.c`,
compiled under `VBOOT_SELFTEST`). The verifier is from-scratch **safe Rust**
(`rust/src/ed25519.rs` over `rust/src/sha512.rs`), consistent with the crate's
zero-dependency policy, and is validated against the **RFC 8032** known-answer
vectors *and* an **OpenSSL-generated** signature (cross-implementation). The
`smoke-vboot` CI job exercises both paths in QEMU: a valid manifest authorizes
boot, and a one-byte-tampered manifest is rejected and halts.

What remains for a full runtime guarantee is **anchoring the verifier to the
actual shipped image** under a root the attacker cannot rewrite — Phases A–C.
Today, with the payload embedded alongside the key, this is boot-time integrity /
defence-in-depth: it defeats a party who can tamper but not re-sign (bit-rot,
disk corruption, an image swap without the offline key), not one who can rewrite
the anchor itself.

### Phase A — UEFI Secure Boot chain (recommended; hardware root of trust)

```
UEFI firmware ──verifies──▶ shim (MS-signed or MOK-enrolled)
      shim   ──verifies──▶ GRUB (signed)
      GRUB   ──verifies──▶ kernel.elf (detached signature; GRUB check_signatures)
```

- **Root of trust:** platform firmware + enrolled keys (db / MOK).
- **Horus work:** ship a GRUB config with `check_signatures=enforce`, sign
  `kernel.elf` in `release.yml` with a GPG key whose public half is embedded in
  the signed GRUB image, and document MOK enrolment for self-managed keys.
- **Pros:** standard, transitive hardware-rooted chain; no custom crypto on the
  boot path. **Cons:** requires UEFI (Horus currently boots BIOS/Multiboot2 via
  GRUB) and key enrolment; a BIOS target gets no firmware anchor.

### Phase B — self-contained signed-image verification (no UEFI dependency)

For the current BIOS/Multiboot2 path, add a **minimal first-stage verifier**
that runs before the kernel proper:

1. `release.yml` signs `kernel.elf` with an **ed25519** key held offline / in a
   hardware token (never on a CI runner), producing a detached signature shipped
   as a Multiboot module.
2. A small first stage (or an extended `entry64.S` pre-`kmain` stub) verifies
   the ed25519 signature over the loaded kernel image against a **public key
   compiled into the first stage** before jumping to `kmain`. On mismatch it
   halts (and, once storage is up, records to the tamper-evident audit chain).
   The verify-or-halt call itself is already built and CI-gated
   (`src/kernel/verified_boot.c` → `rust_ed25519_verify`); what remains is
   feeding it the *actual loaded image bytes* and the offline-produced detached
   signature instead of the embedded self-test manifest.
3. **Done:** ed25519 verification (with its internal SHA-512) now lives in the
   safe-Rust core (`rust/src/ed25519.rs`, `rust/src/sha512.rs`) — a from-scratch,
   test-vector-gated `verify`, consistent with the crate's zero-dependency
   policy.

- **Root of trust:** the embedded public key in the first stage — only as strong
  as the first stage's own integrity (write-protected boot medium, or Phase A
  underneath). **Pros:** works on BIOS; small, auditable. **Cons:** weaker root
  than firmware Secure Boot unless the first stage is itself protected.

### Phase C — measured boot + remote attestation (defence in depth)

- Extend a **TPM PCR** with the kernel image measurement at load; export a PCR
  quote so a remote verifier can attest *what actually booted*.
- Bonus: seals the audit-log pepper (`SECURITY.md`) to a PCR, upgrading the
  audit log from **tamper-evident** to **remotely attestable** — closing the
  "attacker who reads the pepper can forge a consistent chain" limit for anyone
  holding the external quote.

### Sequencing

Phase B is the smallest self-contained increment for the current BIOS target and
reuses the existing crypto core; Phase A is the strongest anchor once a UEFI
target exists; Phase C composes with either and ties back into the audit-log
threat model. The Phase B **verifier** (Ed25519 verify-or-halt) is now built and
CI-gated; the remaining work is anchoring it to the shipped image (offline
signing in `release.yml` + a pre-`kmain` stage that verifies the real loaded
bytes) and, above that, Phase A/C. This document remains the design of record for
that anchoring so the work is scoped rather than improvised.
