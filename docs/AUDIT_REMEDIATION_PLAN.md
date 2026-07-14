# Horus — Audit Remediation Plan

Durable execution plan derived from the high-assurance security & SSDLC audit
(2026-07-13). **Do the smallest, highest-impact tasks first.** Guiding
principle: use Rust only where it is *absolutely* more beneficial than C — the
security-critical logic already lives in safe Rust (`rust/src/*.rs`); low-level
plumbing stays C unless memory-safety or invariant enforcement makes Rust
decisively better.

## Audit verdict

Strong code-level security — the capability core, the `user_copy` boundary, the
safe-Rust AEAD/auth crypto, zero third-party Rust dependencies, and a
well-configured GitHub CI (read-only token, SHA-pinned actions,
checksum-verified tool downloads). The gap to high-assurance is one of
**assurance integrity**: decorative formal specs, imprecise revocation,
non-gating security scans, and a trusted base that was missing from the audited
clone.

## Ordered task queue

| # | ID | Area | Task | Lang |
|---|----|------|------|------|
| 1 | **K3** | capability | `cap_lookup` (`src/kernel/capability.c:151-163`): gate the `root_cnode` fallback on an explicit `task==0`; never resolve `slot >= cspace_size` into `root_cnode` (admin `CAP_USER` at slot 6). Closes a latent ring3→ring0 escalation. | C |
| 2 | **K1** | capability | `lineage_matches` (`rust/src/capability.rs:256`): drop the `c.object == to` clause so revocation follows the derivation tree only; add a regression test for two independent lineages to one shared object. Restores precise revocation. | Rust (existing) |
| 3 | **M1/M4** | cleanup | Delete dead `syscall_handler64` (`syscall.c:3-17`) and unused `is_user_address_valid` (`paging.c:493`). | C |
| 4 | **I6/I7** | docs | One source of truth for CI job/test counts (README/SECURITY/LIMITATIONS disagreed; CI has 20 jobs, 63 unit tests). TESTS.md is now canonical and `tools/check_doc_counts.sh` gates drift in CI. Moved `docs/security_report.md` → `.github/ISSUE_TEMPLATE/`. | docs |
| 5 | **I3** | CI | Make gitleaks + Semgrep-ERROR blocking (remove `continue-on-error`/`|| true` for those two). | CI |

## Larger follow-ups (later weeks)

- **K2** — replace the 4096-slot hashed `LINEAGE_GEN` with exact lineage identity (collisions cause spurious fail-closed revocation).
- **I2** — separate the lineage-link field from the semantic `badge` (collateral-revocation risk).
- **I1** — extend snapshot/revalidate (or lock-held lookup) beyond IPC to all authority-bearing syscalls (SMP TOCTOU on raw capability pointers).
- **P2** — ✅ done. Both TLA+ specs rewritten with real, falsifiable invariants and TLC-model-checked in CI (`tla` job, `make verify-tla`). `cap_algebra.tla` now models rights as sets (masking = intersection, fixing the logical-AND mis-model) and checks a genuine subset-rights non-escalation invariant (the old `NoEscalation` was a `rights <= 0xFFFFFFFF` tautology); `paging_isolation.tla` now gives each task its own page tables and checks that no user frame is mapped into two tasks and no user mapping reaches kernel memory (the old spec used a single global page table). Both invariants were confirmed non-trivial by falsification (union-mint and dropped owner-guard both make TLC fail).
- **I4** — ✅ done. `rust-toolchain.toml` pins the Rust compiler (1.96.1), the `clippy` component, and the `x86_64-unknown-none` target — rustup installs all three declaratively, so CI no longer floats on the runner's `stable`. CI runners pinned `ubuntu-latest` → `ubuntu-24.04` so the C toolchain (gcc/binutils/grub/xorriso) does not drift. Reproducible build verified byte-for-byte on the pinned toolchain. A full container/Nix seal (pinning apt patch versions too) is deliberately deferred as disproportionate — the pins above plus the Makefile's reproducibility flags already make the audited artifact deterministic (see docs/BUILDING.md).
- **I5** — CI deny-list: fail if `Cargo.lock` gains any package beyond `horus_shell` (enforce the zero-dependency policy).
- **Governance** — add `CODEOWNERS`, branch protection, signed commits; align local `make security` installs with CI's checksum-verified ones.
- **P1** — provide the complete trusted base (`.git`, `.github/`) to any evaluator; the audited clone lacked both.
