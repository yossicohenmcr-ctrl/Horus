# Testing Horus

## Current state

<!-- doc-counts: rust_unit_tests=61 ci_jobs=20 -->
<!-- This file is the single source of truth for the two headline metrics below.
     `tools/check_doc_counts.sh` (a CI step in the `rust` job) derives the real
     numbers from rust/src and .github/workflows/ci.yml and fails the build if
     this marker, or any tracked doc, disagrees. Bump the marker here when the
     counts change and the guard will point you at any doc left out of sync. -->

The Rust security core has **61 unit tests**, and a CI pipeline gates every push and pull request (`.github/workflows/ci.yml`) with **20 jobs**. The **headless QEMU boot tests** run in CI: `make smoke` boots to the ring-3 login prompt with no fault, `make smoke-elf` boots a real multi-segment static-PIE ELF at a randomised base and asserts the loader enforced W^X **and** applied its `R_386_RELATIVE` relocation, `make smoke-preempt` asserts the timer time-slices two non-yielding ring-3 tasks, `make smoke-signal` faults a task on purpose and asserts its handler runs, `make smoke-proc` drives ring-3 process control (exit/kill/spawn/exec/grant/signal/wait/fault-wait), `make smoke-notify` asserts an async `SYS_NOTIFY` badge reaches a task blocked in `SYS_WAIT_NOTIFY`, `make smoke-smp` asserts the application processors come online and run tasks concurrently, and the filesystem/libc suite (`make smoke-fs`, plus `smoke-fs-persist`, `smoke-fs-perms`, `smoke-fs-conc`, `smoke-fs-wal`, `smoke-fs-large`, `smoke-newlib` for persistence, per-file permissions, multi-client concurrency, the write-ahead journal, large/double-indirect files, and the newlib libc port) is now gated too. Beyond the marker self-tests, `make smoke-session` drives the **real** ring-3 shell over serial through a scripted login/command session and asserts on the responses (`tools/session_test.py`). The delegated boot-through-`init` filesystem path (`smoke-init-fs`) remains a local target, and a coverage-guided fuzz harness is still the highest-value remaining contribution.

---

## Running the tests

### Rust unit tests

```bash
cargo test --manifest-path rust/Cargo.toml --release
```

This runs the unit tests across the security core:

- `capability.rs` — mint with a subset of rights (no escalation), transfer (full-rights copy sharing the parent lineage), system-wide / cross-task revocation, precise transitive revocation (a grandchild is revoked with its ancestor, while siblings, ancestors, and independent capabilities that merely share the same object survive), primordial-root revocation refusal, stale-generation rejection, lineage-generation wraparound (skips the reserved 0, invalidates pre-wrap caps), revoke-by-values invalidating a pre-revoke snapshot (the IPC TOCTOU guard), lineage low-bit collision safety, fresh-serial allocation across the u32 wrap boundary
- `memory.rs` — the refcount-table trust boundary (a wrong pointer or length is refused, not dereferenced), saturation, decrement-at-zero, valid-user-phys bounds, and the page alloc/free LIFO + exhaustion guards
- `lib.rs` — page-fault validation, capability-rights subset checks, demand-paging (COW / demand-zero) policy, FS-operation right enforcement, command dispatch, the W^X page policy (`rust_user_page_is_noexec`), and the signal-handler-address window (`rust_signal_handler_addr_ok`)
- `rng.rs` — ChaCha20 against the RFC 8439 vector, reseed behaviour
- `sha256.rs` — SHA-256 / HMAC / HKDF / PBKDF2 against published known-answer vectors
- `blake2b.rs` — BLAKE2b-512 against the RFC 7693 known-answer vector, plus multi-block/empty inputs
- `argon2.rs` — Argon2id against `argon2-cffi` reference tags, single-lane and multi-lane (`p=2`/`p=4`), incl. the kernel's exact 4 MiB / 3-pass / 1-lane config
- `aead.rs` — the ChaCha20 + HMAC-SHA256 Encrypt-then-MAC AEAD: seal/open round-trip, tampered-ciphertext and tampered-tag rejection (fail-closed), wrong-AAD rejection, and nonce separation
- `audit.rs` — the tamper-evident audit MACs: per-entry MAC determinism, sequence/content/key binding, domain-separated chain IV, order-sensitivity of the chain head, a full record-then-verify cycle with tamper detection, the constant-time MAC compare, and FFI null rejection
- `auth.rs` — auth/sudo lockout arithmetic, the anti-spray throttle, and least-privilege sudo frame rights
- `ps.rs` — task state-name labels

### Headless self-tests

```bash
make smoke          # SMOKE_TIMEOUT=<seconds> to override the default 40
```

Each self-test target clean-builds with the relevant flag, boots under QEMU with no display (`tools/smoke_test.sh`, software TCG so it needs no host KVM), captures the serial port, and asserts on a marker (and fails on any `PAGE FAULT` / CPU exception / `PANIC` / triple-fault). Reaching the login prompt proves the whole boot path end to end: kernel init, the loader, per-task paging including the W^X stack, dropping to ring 3, the syscall dispatch table servicing `SYS_WRITE`, and console output.

| Target | Marker |
|---|---|
| `make smoke` | reaches the ring-3 shell banner + login prompt |
| `make smoke-elf` | `ELF_SELFTEST: PASS` |
| `make smoke-preempt` | `PREEMPT_SELFTEST: PASS` |
| `make smoke-signal` | `SIGNAL_SELFTEST: PASS` |
| `make smoke-proc` | `PROC_SELFTEST: PASS exit+kill+spawn+exec+grant+signal` (+ `wait OK` / `fault-wait OK`) |
| `make smoke-notify` | `NOTIFY_SELFTEST: PASS` (async `SYS_NOTIFY` badge delivered to a blocked `SYS_WAIT_NOTIFY`) |
| `make smoke-smp` | `SMP_SELFTEST: PASS` |
| `make smoke-fs` | `FS_SELFTEST: PASS` (`STORAGE=ata` for a real disk) |
| `make smoke-fs-persist` | file written on boot 1 is present on boot 2 against the same disk image |
| `make smoke-fs-perms` | per-file POSIX ownership/permissions enforced against kernel-attested uid |
| `make smoke-fs-conc` | three concurrent clients each receive only their own replies |
| `make smoke-fs-wal` | a write committed then crashed pre-apply is replayed from the journal on the next mount |
| `make smoke-fs-large` | reads/writes across direct + single- + double-indirect blocks |
| `make smoke-newlib` | `NEWLIB_SELFTEST: PASS` |
| `make smoke-session` | `SESSION_TEST: PASS` — drives the real ring-3 shell over serial (auth + least-privilege) |

### Full build test

```bash
make test          # cargo tests, then a clean full build
```

### Manual testing under QEMU

The most useful end-to-end check is still booting and exercising Horus interactively:

```bash
make run            # then connect: nc localhost 4445
```

```
login: user
password: password
whoami
ls
help
```

---

## Continuous integration

`.github/workflows/ci.yml` runs **20 jobs**, all hard gates:

1. **rust** — `cargo test --release`, `cargo clippy --all-targets -- -D warnings`, and the `tools/check_doc_counts.sh` doc-count guard
2. **kernel** — builds `kernel.elf` and a bootable ISO (x86-64) and uploads them as artifacts
3. **altconfigs** — a build matrix over `DEBUG_SHELL=1` and `MINIMAL_SECURE=1`
4. **smoke** — `make smoke` (headless boot to the shell/login prompt, no fault)
5. **smoke-elf** — `make smoke-elf` (ELF loader + W^X + relocation self-test)
6. **smoke-preempt** — `make smoke-preempt` (two-task timer preemption)
7. **smoke-signal** — `make smoke-signal` (fault delivered to a registered handler)
8. **smoke-proc** — `make smoke-proc` (ring-3 exit/kill/spawn/exec/grant/signal/wait)
9. **smoke-notify** — `make smoke-notify` (async `SYS_NOTIFY` badge to a blocked `SYS_WAIT_NOTIFY`)
10. **smoke-smp** — `make smoke-smp` (application processors run tasks concurrently)
11. **smoke-fs** — `make smoke-fs` (encrypted filesystem server round-trip)
12. **smoke-fs-perms** — per-file POSIX ownership/permissions vs. kernel-attested uid
13. **smoke-fs-conc** — concurrent multi-client isolation
14. **smoke-fs-persist** — a file survives across a reboot against the same disk image
15. **smoke-fs-wal** — write-ahead journal crash-recovery replay
16. **smoke-fs-large** — direct + single- + double-indirect block I/O
17. **smoke-newlib** — `make smoke-newlib` (newlib libc over the POSIX fd layer)
18. **smoke-session** — `make smoke-session` (drives the real ring-3 shell over serial: auth + least-privilege enforcement)
19. **reproducible** — builds `kernel.elf` twice and fails if they are not byte-for-byte identical
20. **security** — Semgrep, Trivy, gitleaks, cppcheck, flawfinder, `cargo-audit`, and a CycloneDX SBOM (advisory)

That is three build/lint jobs, fourteen headless QEMU self-tests (items 4–17) plus the scripted `smoke-session` integration test, and the reproducible-build and security jobs. All but the security job use only first-party / pinned actions. **These counts are enforced:** `tools/check_doc_counts.sh` fails CI if the number of `#[test]`s or `ci.yml` jobs drifts from the marker at the top of this file or from any tracked doc.

---

## What still needs tests

The gaps that remain:

### Deeper booted-kernel integration tests

`make smoke-session` (`tools/session_test.py`) seeds this: it drives the serial port through a scripted login/shell session and asserts on the responses — a failed then successful login, the kernel-attested identity via `whoami`, and a capability-gated admin op allowed for root but denied for a standard user. The remaining work is to broaden the scenarios (an ELF running under W^X, an IPC/FS round-trip, a capability revocation) and grow the assertion vocabulary. A coverage-guided fuzz harness over the syscall/FFI boundary is still absent.

### TLA+ specs

`docs/cap_algebra.tla` and `docs/paging_isolation.tla` model the capability and paging invariants but are not model-checked in CI. Wiring TLC/Apalache into the pipeline would close the loop.

### A real C-side test harness

`tests/test_capability.c` is a standalone illustration that reimplements a simplified `cap_lookup`; it is **not** linked against the kernel's `capability.c` and is not built by the Makefile. A host harness linking the real `capability.c` with mocked `tasks[]` / `get_current_task()` would give the C guards genuine regression coverage.

### Fuzzing

The syscall interface and the Rust FFI boundary are the obvious targets. A `cargo-fuzz` target over the pointer-taking FFI entry points is cheap to stand up; `syzkaller` driving a privileged task under QEMU/KVM is the larger effort.

Contributions to any of the above are very welcome.
