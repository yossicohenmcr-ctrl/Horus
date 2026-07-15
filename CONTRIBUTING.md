# Contributing to Horus

Thank you for your interest. Horus is an early-stage research microkernel and there is meaningful work at every level — from fixing shell command stubs to hardening the SMP scheduler. Contributions of all sizes are welcome.

---

## Before you start

Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) to understand the design, and [SECURITY.md](SECURITY.md#known-limitations--current-status) to understand what is and is not working. This will save you time and help you choose work that fits the project's direction.

If you are planning something non-trivial, open an issue first to discuss the approach. This avoids parallel effort and conflicting designs.

---

## Setting up

```bash
git clone https://github.com/yossicohenmcr-ctrl/Horus
cd Horus

# Install build tools (Debian/Ubuntu)
sudo apt-get install build-essential gcc binutils make xorriso grub-pc-bin mtools qemu-system-x86

# Install Rust (version + bare-metal target are pinned by rust-toolchain.toml)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"
rustup target add x86_64-unknown-none

# Build and run
make
make run            # console on serial: nc localhost 4445
```

[docs/BUILDING.md](docs/BUILDING.md) is the full reference for build targets, flags, and troubleshooting — it is the canonical build doc, so this section stays deliberately short.

---

## Where help is needed

The [ROADMAP](docs/ROADMAP.md) lists planned work in priority order. Specific areas by skill set:

### C kernel work

- **SMP maturity** (`src/kernel/scheduler.c`): multi-core works behind `SMP=1` over a shared runnable pool. Per-CPU run queues, scheduling priorities/fairness, and making it default-on are the next steps.
- **Richer IPC** (`src/kernel/syscall_ipc.c`): endpoints are single-slot mailboxes serving one in-flight request; multiple-client service is layered on top via `SYS_IPC_REPLY_TO`, and async badge notifications (`SYS_NOTIFY`/`SYS_WAIT_NOTIFY`) work. A multi-slot mailbox or a worker-pool `fs_server` would allow genuine parallel request processing.
- **Larger volumes** (`src/kernel/storage.c`): the single 512-byte bitmap block caps a volume at 4096 blocks (2 MiB). Multi-block allocation bitmaps would lift the cap — currently a deliberate non-goal, so discuss in an issue first.

### Rust work

- **Argon2 intra-request threading** (`rust/src/argon2.rs`): multi-lane + configurable cost is done, but lanes are filled sequentially, so `p > 1` changes the hash without reducing wall-clock time on one core.
- **Property-based tests for the capability core**: the `fuzzrng.rs` harness already fuzzes mint/refcount/AEAD/Ed25519; extend the generators over transfer/grant/revoke to exercise the lineage and revocation invariants harder.
- **Kani / Verus verification**: apply a Rust verification tool to `capability.rs` to formally verify the revocation properties.

### Testing

- **Integration test suite**: `make smoke-session` (`tools/session_test.py`) drives the real ring-3 shell over serial and asserts on the responses. Broadening the scenarios (an ELF running under W^X, an IPC/FS round-trip, a capability revocation) and growing the assertion vocabulary is the next step.
- **Syscall fuzzer**: coverage-guided fuzzing of the syscall interface / FFI boundary (`cargo-fuzz` on the host, or `syzkaller` under QEMU/KVM). Note this needs third-party crates, so it lives *outside* the zero-dependency Rust crate.
- **More Rust unit tests**: the crate has **84 tests** today. Gaps worth filling: property-based generators over mint/transfer/grant/revoke (see above), and serial-wrap fuzzing beyond the current boundary example.

### Documentation

- Clarifications to [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) or [docs/BUILDING.md](docs/BUILDING.md)
- Annotated examples showing how to use the capability API from userspace
- TLA+ extensions to the existing specifications

---

## Code style

### C

- `snake_case` for functions and variables; `UPPER_CASE` for constants and macros; types end in `_t`
- Comments explain *why* (non-obvious invariants), not *what*
- No dynamic allocation in the kernel — everything is statically or stack-allocated
- Freestanding — no libc headers except via the kernel header

### Rust

- Standard `rustfmt` formatting
- All kernel-side Rust must be `no_std`, `no_alloc`
- FFI functions exposed to C are `unsafe extern "C"` with `#[no_mangle]`, carry a `# Safety` contract, and validate their arguments (fail closed)
- No `unsafe` in the logic of `capability.rs`, `memory.rs`, or `lib.rs` — unsafe belongs exclusively in the C-facing FFI shims

---

## Submitting a pull request

1. Fork the repository and create a branch from `main`
2. Make your changes. Keep commits focused — one logical change per commit
3. Ensure `make` succeeds with no new warnings, and `make test` passes
4. Run the self-test relevant to your change (`make smoke`, `smoke-proc`, `smoke-fs`, …)
5. If your change affects the architecture, update `docs/ARCHITECTURE.md` (and `docs/SYSCALLS.md` for a new syscall); if it changes the test or CI-job count, update the marker in [TESTS.md](TESTS.md) so `tools/check_doc_counts.sh` stays green
6. Open a pull request with a clear description of what changed and why (see the PR template)

Pull requests that break the build, introduce new warnings without justification, or touch security-critical paths without explanation will be held for discussion before merging.

### A note on security changes

The capability system, authentication, audit log, and the process-control authority model (`SYS_KILL`/`SYS_SIGNAL`/`SYS_CAP_GRANT` gating) are security-critical paths and receive closer review. If you are proposing a change that affects security properties — even positively — describe the invariant you are preserving or introducing, and explain why the change does not break existing guarantees.

If you find a security issue, please follow the disclosure process in [SECURITY.md](SECURITY.md).

---

## Change control on `main`

The repository, its CI/CD, and its branch protection are part of the **trusted base** of a high-assurance system: a weakness here can inject a runtime vulnerability that bypasses every code-level control. This is the governance posture of record.

**Every change to `main` is a pull request** that must pass the required status checks before it can merge, and this is **enforced for administrators** — there is no direct-push or admin-bypass path. The required gates are the core CI contexts:

- Rust unit tests + clippy (deny-warnings)
- Kernel + bootable ISO build
- QEMU smoke-boot
- Reproducible-build verification
- TLA+ model checking
- Security scans + SBOM (gitleaks + Semgrep-ERROR blocking)

`CODEOWNERS` designates the owner of every security-critical path. **Commits to `main` must be cryptographically signed** and are verified server-side, so an unsigned commit (e.g. from a compromised credential that cannot reproduce the signing key) is rejected. Force-pushes and branch deletion are disabled.

### Known residual risk: single maintainer (bus factor 1)

The project currently has **one maintainer**, who is also the sole code owner. GitHub does not let a PR author approve their own PR, and a single code owner cannot provide the independent review a `required_approving_review_count >= 1` gate implies — under enforced admin protection, requiring an approval a solo maintainer can never obtain would make the repository **unmergeable**. The posture therefore sets **required approvals to 0** while keeping the PR requirement, the CI gates, admin enforcement, and required signatures. The maintainer self-merges, but only through a PR whose CI gates are green and whose commits are signed — i.e. the *automated* trusted base is enforced against the maintainer even though *human* independent review is not yet possible.

The path to independent review is to add a second maintainer, then restore `required_approving_review_count = 1` and re-enable code-owner review, at which point human review becomes a binding gate on top of the automated ones.

The protected-branch settings above are configured on the GitHub repository, not in-tree; this document is the policy of record.
