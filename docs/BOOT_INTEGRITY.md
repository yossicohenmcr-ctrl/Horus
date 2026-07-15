# Boot Integrity & Build Provenance

This document addresses audit finding **3.3**: reproducible builds prove *source
→ identical binary*, but until now nothing bound the *running* kernel to that
reviewed source, and the machine had no way to refuse a tampered image. Boot
integrity has two independent trust anchors; this document covers both and is
honest about which is implemented.

| Anchor | Question it answers | Status |
|---|---|---|
| **Build provenance** | "Did this `kernel.elf` come from this repo's CI, built from a reviewed commit?" | **Implemented** (`.github/workflows/release.yml`) |
| **Runtime verified boot** | "Will the machine refuse to run an image it cannot verify?" | **Phase B implemented & CI-gated** — the kernel verifies its own loaded image (`.text`+`.rodata`) against an embedded Ed25519 anchor and halts on a mismatch (`src/kernel/verified_boot.c`, `VBOOT_ENFORCE`; accept + tamper-reject proven by `make smoke-vboot-image`). Hardware-rooting the anchor itself is Phase A / C below |

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

## 2. Runtime verified boot (Phase B implemented; hardware-rooting is Phase A/C)

**Design principle — the verifier must be strictly more trusted than the
verified.** A kernel cannot meaningfully verify itself: if it is tampered, so is
its own check. A hardware-rooted anchor must ultimately live *below* the kernel
(firmware / bootloader) and root in something the attacker cannot silently
replace (Secure Boot keys, or a key in write-protected storage).

### What is implemented now

Under `VBOOT_ENFORCE` the kernel verifies **its own loaded image** against an
Ed25519 signature over that image, anchored to a public key **compiled into the
image** — and **halts** on any mismatch, before any further init. This is real
verify-or-halt over the actual bytes GRUB loaded, not a placeholder manifest.

- **Hashed region:** `[__image_start, __vboot_sig_start)` — the kernel's `.text`
  (all executable code, including the Multiboot header) and `.rodata` (all
  read-only constants). `linker64_vboot.ld` packs these into a single contiguous
  PT_LOAD, so the bytes in memory are byte-for-byte the bytes the signer hashed
  (GRUB does not zero inter-segment gaps, so a multi-segment layout would hash
  non-deterministically). `.data` is **excluded** — early boot mutates some
  writable globals before the verify runs, so its runtime bytes would not match
  the file (see residual below).
- **Signature slot:** a 64-byte `.vboot_sig` section *outside* the hashed region
  (a signature cannot cover itself), patched post-build by `tools/vboot_sign.sh`.
- **Verifier:** from-scratch **safe Rust** (`rust/src/ed25519.rs` over
  `rust/src/sha512.rs`), zero-dependency, validated against **RFC 8032** and an
  **OpenSSL** signature. The signing key is offline; the kernel only ever holds
  the public anchor and verifies.
- **Proven in CI:** `make smoke-vboot-image` generates an ephemeral key, builds +
  signs the real image, and boots it twice in QEMU — the untouched image
  authorizes boot (`VBOOT_ENFORCE: PASS`), and one flipped byte in the signed
  region is rejected and halts (`VBOOT_ENFORCE: FAIL`). `release.yml` builds and
  ships this enforcing image (`kernel.vboot.elf`) when the offline key is set.
- The older `VBOOT_SELFTEST` path (a fixed embedded manifest) remains as a
  focused self-test of the verifier primitive; `smoke-vboot` runs both.

**Residuals (honest):** (1) the anchor is compiled into the same image it
guards, so this defeats a party who can tamper but not re-sign (bit-rot, disk
corruption, an image swap without the offline key) — **not** one who can also
rewrite the embedded anchor. Hardware-rooting the anchor is Phase A (UEFI Secure
Boot) / Phase C (TPM). (2) `.data` (≈14 KB of initialised writable globals) is
outside the signed region; extending coverage to it requires running the verify
before any `.data` write (a pre-`kmain` stub) — a natural Phase A/C companion.

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

### Phase B — self-contained signed-image verification (no UEFI dependency) — *implemented*

This is the anchor described in [§2 "What is implemented now"](#what-is-implemented-now)
above: for the current BIOS/Multiboot2 path, the kernel verifies its own loaded
image against an offline-signed Ed25519 signature before proceeding.

- `release.yml` signs the real `kernel.elf` bytes with an **ed25519** key held
  offline (never on a CI runner) and ships the enforcing `kernel.vboot.elf`.
- Under `VBOOT_ENFORCE` the kernel verifies the signature over the **actual
  loaded image bytes** against a **public key compiled into the image** before
  further init, and **halts** on mismatch. Ed25519 (with its internal SHA-512)
  lives in the safe-Rust core (`rust/src/ed25519.rs`, `rust/src/sha512.rs`) — a
  from-scratch, test-vector-gated `verify`, consistent with the crate's
  zero-dependency policy. Accept + tamper-reject are CI-gated by
  `make smoke-vboot-image`.

- **Root of trust:** the embedded public key — only as strong as the image's own
  integrity (write-protected boot medium, or Phase A underneath). **Pros:** works
  on BIOS; small, auditable. **Cons:** weaker root than firmware Secure Boot
  unless the image itself is protected, and the anchor sits inside the image it
  guards (so it stops tamper-without-re-sign, not an attacker who can rewrite the
  anchor). Hardware-rooting it is Phase A / C.

### Phase C — measured boot + remote attestation (defence in depth)

- Extend a **TPM PCR** with the kernel image measurement at load; export a PCR
  quote so a remote verifier can attest *what actually booted*.
- Bonus: seals the audit-log pepper (`SECURITY.md`) to a PCR, upgrading the
  audit log from **tamper-evident** to **remotely attestable** — closing the
  "attacker who reads the pepper can forge a consistent chain" limit for anyone
  holding the external quote.

### Sequencing

Phase B — self-contained Ed25519 verify-or-halt over the real signed image — is
**implemented and CI-gated** (see §2). It is the smallest self-contained increment
for the current BIOS target and reuses the existing crypto core. The work still
ahead is strengthening the *root* of that anchor and its *coverage*:

- **Phase A** (UEFI Secure Boot) is the strongest anchor once a UEFI target
  exists — it roots trust in firmware rather than in a key inside the image.
- **Phase C** (measured boot + TPM attestation) composes with either and ties
  back into the audit-log threat model.
- **Coverage:** extend the hashed region to `.data` by running the verify before
  any writable-global mutation (a pre-`kmain` stub) — a natural Phase A/C
  companion.

This document remains the design of record for that work so it is scoped rather
than improvised.
