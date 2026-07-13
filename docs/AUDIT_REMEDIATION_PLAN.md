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
| 4 | **I6/I7** | docs | One source of truth for CI job/test counts (README/SECURITY/LIMITATIONS disagree; GitHub has 17 jobs). Move `docs/security_report.md` → `.github/ISSUE_TEMPLATE/`. | docs |
| 5 | **I3** | CI | Make gitleaks + Semgrep-ERROR blocking (remove `continue-on-error`/`|| true` for those two). | CI |

## Larger follow-ups (later weeks)

- **K2** — replace the 4096-slot hashed `LINEAGE_GEN` with exact lineage identity (collisions cause spurious fail-closed revocation).
- **I2** — separate the lineage-link field from the semantic `badge` (collateral-revocation risk).
- **I1** — extend snapshot/revalidate (or lock-held lookup) beyond IPC to all authority-bearing syscalls (SMP TOCTOU on raw capability pointers).
- **P2** — rewrite both TLA+ specs: real subset-rights invariant and real per-task isolation invariant; add a TLC/Apalache CI job. `NoEscalation` is currently a tautology, rights masking is mis-modeled as logical-AND, and `paging_isolation.tla` uses a global (non-per-task) page table.
- **I4** — pin the toolchain (`rust-toolchain.toml` + container/Nix) so the reproducible build is hermetic.
- **I5** — CI deny-list: fail if `Cargo.lock` gains any package beyond `horus_shell` (enforce the zero-dependency policy).
- **Governance** — add `CODEOWNERS`, branch protection, signed commits; align local `make security` installs with CI's checksum-verified ones.
- **P1** — provide the complete trusted base (`.git`, `.github/`) to any evaluator; the audited clone lacked both.
