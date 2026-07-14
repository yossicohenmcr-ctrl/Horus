# Boot Integrity & Build Provenance

This document addresses audit finding **3.3**: reproducible builds prove *source
→ identical binary*, but until now nothing bound the *running* kernel to that
reviewed source, and the machine had no way to refuse a tampered image. Boot
integrity has two independent trust anchors; this document covers both and is
honest about which is implemented.

| Anchor | Question it answers | Status |
|---|---|---|
| **Build provenance** | "Did this `kernel.elf` come from this repo's CI, built from a reviewed commit?" | **Implemented** (`.github/workflows/release.yml`) |
| **Runtime verified boot** | "Will the machine refuse to run an image it cannot verify?" | **Designed, not yet enforced** (this doc, Phase A–C) |

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

## 2. Runtime verified boot (design; not yet implemented)

**Design principle — the verifier must be strictly more trusted than the
verified.** A kernel cannot meaningfully verify itself: if it is tampered, so is
its own check. Verification must live *below* the kernel (firmware / bootloader
/ a minimal first stage) and root in something the attacker cannot silently
replace (Secure Boot keys, or a key in write-protected/known-good storage).

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
2. A small first stage (or an extended `entry64.S` pre-`kmain` stub) computes
   SHA-256 over the loaded kernel image and verifies the ed25519 signature
   against a **public key compiled into the first stage** before jumping to
   `kmain`. On mismatch it halts (and, once storage is up, records to the
   tamper-evident audit chain).
3. Horus already has SHA-256 in the safe-Rust core (`rust/src/sha256.rs`);
   ed25519 verification would be added there (a from-scratch, test-vector-gated
   `verify`, consistent with the crate's zero-dependency policy).

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
threat model. None is implemented yet — this document is the design of record so
the work is scoped rather than improvised.
