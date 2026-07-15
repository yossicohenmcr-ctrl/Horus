# Security Policy

## Project security posture

Horus is a **research microkernel** in early development. It is not suitable for production or for handling sensitive workloads. The properties described in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) reflect the design intent; several are not yet fully realised. This document is honest about both what is enforced today and where the gaps are — the [Known limitations & current status](#known-limitations--current-status) section below is a candid, subsystem-by-subsystem account.

Where this document and the code disagree, **the code is the source of truth** — please open an issue.

Known weaknesses, in brief (detailed below):

- SMP works behind the `SMP=1` build gate but is not default-on; the multi-core scheduler shares a single runnable pool (no per-CPU run queues, no priorities), and there is no flush-on-switch between mutually distrusting tasks.
- Load-base ASLR is applied (userspace is static-PIE, relocated at a random base), but image-base entropy is bounded (~9 bits) by the 32-bit low-memory window userspace runs in.
- Encrypted storage is persistent when an ATA disk is present, but diskless boots use an ephemeral RAM vdisk and volumes are size-capped at 2 MiB by single-bitmap geometry.
- The audit log is tamper-*evident* (an HMAC chain detects modification), not tamper-*proof* — an attacker who can read the per-boot key can recompute a consistent chain.

These are documented, known limitations of an incomplete system, not undisclosed vulnerabilities.

---

## Hardening currently in place

The following are implemented and enforced today:

- **Hardware isolation:** Ring 0/3 separation with per-task page tables; **SMEP** and **SMAP** enabled when advertised (ring 0 cannot execute, and cannot casually read/write, user pages — user copies resolve the physical address under the kernel mapping rather than dereferencing a user virtual address).
- **W^X for user memory:** `EFER.NXE` is enabled and the kernel sets the PTE NX bit so a writable page is never executable. User stacks are mapped non-executable, and the ELF loader honours each `PT_LOAD` segment's `p_flags` (code read+execute, data/rodata no-execute). The shipped userspace is static-PIE and takes this path; a flat-binary fallback (kept executable) remains for non-ELF images.
- **Centralised syscall authorisation:** dispatch is a descriptor table that enforces each syscall's required capability at a single choke point; an unlisted syscall number fails closed, and a compile-time assertion prevents adding a syscall without a table slot.
- **No ambient authority:** capability revoke requires `CAP_RIGHT_REVOKE` on the target and mint/transfer require `CAP_RIGHT_MINT`; a non-kernel task with no cspace is refused rather than defaulting to the kernel root cnode. Revocation is system-wide (every task's cspace plus the kernel root) and bumps the lineage generation, so derived copies in other tasks cannot outlive their parent.
- **Least-privilege process control:** a spawned child returns its `CAP_TCB` only to the spawner. `SYS_KILL`, `SYS_SIGNAL`, and `SYS_CAP_GRANT` on a task are gated on holding that `CAP_TCB` (or `CAP_USER` admin), so a task cannot terminate, signal, or endow another task it was not given authority over. A supervisor delegates one cap slot at a time into a child's cspace with `SYS_CAP_GRANT`.
- **Use-after-revoke / TOCTOU:** per-lineage generation counters invalidate stale capabilities; a snapshot + revalidate-at-use guard is wired into the IPC send/recv paths so a revoke during a lookup/use window aborts the operation.
- **SMP capability-read integrity:** the lock-free `cap_lookup` is a seqlock reader over `cap_seq` (bumped odd on every `cap_lock` acquire, even on release), so a capability lookup on one CPU can never observe a torn `capability_t` (e.g. new rights with an old serial) or a half-nulled slot while a mint/transfer/revoke-sweep/grant mutates cspaces under `cap_lock` on another CPU. In-lock callers use a non-retrying `cap_lookup_locked` so nesting a lookup inside a `cap_lock` critical section cannot self-deadlock. The seqlock protocol is TLA+ model-checked (`docs/cap_seqlock.tla`): TLC exhaustively verifies that a committed lock-free read never observes a torn capability across all two-CPU interleavings.
- **FFI integrity:** the C and Rust capability layouts are pinned by mirrored compile-time assertions; the page refcount table is registered once and any later inc/dec presenting a different (pointer, length) is refused, not trusted. The highest-risk FFI entry points (the Ed25519 verifier, the AEAD, capability mint, the refcount trust boundary, and the address/policy validators) are additionally exercised by a **zero-dependency property/differential fuzz harness** in CI that asserts fail-closed and no-panic behaviour over large reproducible streams of random inputs.
- **Encryption-at-rest:** the block-storage layer uses one ChaCha20 + HMAC-SHA256 Encrypt-then-MAC AEAD in safe Rust (`rust/src/aead.rs`), with independent HKDF-SHA256 enc/mac subkeys, a fresh random per-write nonce, context bound as AAD, and constant-time fail-closed verification. It keys per block and binds `(ino, block)` as AAD, so a block cannot be replayed at a different offset or inode.
- **No ring-3 code in ring 0:** `SYS_REGISTER_STORAGE_BACKEND` — which used to register userspace function pointers the kernel called from ring 0 — fails closed; any userspace storage/FS provider must run as a ring-3 IPC server (as `fs_server` does).
- **Tamper-evident audit log:** every audit entry is bound by an HMAC keyed to the per-boot secret pepper (the MAC binds the entry's absolute sequence number, so an in-place edit, a ring-slot swap, or a replay no longer verifies), and a running hash-chain head commits to the *entire* ordered history — including entries already overwritten in the ring. `SYS_AUDIT_DIGEST` (a `CAP_AUDIT`-gated read) returns the event count, the chain-head MAC, and a constant-time verify status. The keyed-hash logic lives in safe Rust (`rust/src/audit.rs`).
- **Signals grant no new authority:** a task may register *its own* ring-3 handler (`SYS_SIGACTION`) so a fault or an async signal is delivered to it instead of killing it outright. The handler entry is validated to the user code window in safe Rust (fail-closed), a fault *inside* a handler is not re-delivered (no loops), and the handler runs at ring 3 with unchanged privileges. Async cross-task signalling (`SYS_SIGNAL`) requires a `CAP_TCB` on the target — the same authority as killing it — so it opens no new cross-task reach.
- **Capability space zeroed on task-slot reuse:** `cspace_pool` is a static array; when a task exits and its slot is reused, `create_task` zeroes all 256 capability slots before installing the new task's initial capabilities, preventing an inheriting task from acquiring the dead task's `CAP_USER`, `CAP_CONSOLE`, or `CAP_ENCRYPTED_STORAGE`.
- **Filesystem reference monitor (zero-trust ownership):** the ring-3 `fs_server` is the single filesystem and enforces per-file POSIX owner/group/other rwx and ownership against the caller's *kernel-attested* identity. `SYS_IPC_SENDER` returns the sending task's login uid/gid taken from `tasks[]` — set at login, never from anything the client puts in the request — so a client cannot forge who it is; root (uid 0) is the only ambient authority (`chmod` owner-or-root, `chown` root-only). Only the server holds the object-store capability, so a client cannot reach the store directly or bypass the checks. The earlier parallel in-memory capfs has been **removed** — its syscalls fail closed.
- **Account and password hygiene:** accounts created without an explicit initial password get a CSPRNG-random `pass_hash` that no Argon2id invocation can match (locked until `SYS_PASSWD`); password changes persist across reboots; `h_passwd`/`h_auth` scrub their cleartext buffers with `secure_zero` before returning.
- **Supply chain / CI:** every change is gated by a **22-job** pipeline — `cargo test`, `clippy` with all warnings denied, a kernel + ISO build, an alt-config build matrix (`DEBUG_SHELL=1`, `MINIMAL_SECURE=1`), a suite of headless QEMU self-tests (boot, ELF-loader + W^X, preemption, signals, process-control, async notifications, SMP, an Ed25519 verified-boot gate, and the encrypted-filesystem/libc suite), a scripted `smoke-session` integration test that drives the real ring-3 shell over serial, a byte-for-byte reproducible-build check, a security-scan job (Semgrep, Trivy, gitleaks, cppcheck, flawfinder, `cargo-audit`) that also emits a CycloneDX SBOM, and a **TLA+ model-checking job** that TLC-verifies five specs (capability-algebra non-escalation, paging isolation, the two-CPU seqlock, the IPC lookup/use TOCTOU, and SMP scheduling). gitleaks (full-history), Semgrep ERROR-severity findings, and any violated TLA+ invariant are **blocking gates**; the remaining scanners are advisory. The headline `84 tests` / `22 jobs` counts are enforced by `tools/check_doc_counts.sh` (see [TESTS.md](TESTS.md)).
- **Build provenance & signed releases:** tagged releases are built by `.github/workflows/release.yml`, which reproducibly builds `kernel.elf` + the ISO, generates a SLSA build-provenance attestation (keyless Sigstore signing via the workflow's OIDC identity) binding each artifact's SHA-256 digest to the source commit, and publishes a signed GitHub Release. `gh attestation verify kernel.elf --repo <repo>` confirms a binary came from this repo's CI at a reviewed commit; combined with the byte-for-byte reproducible build this binds the running image to reviewed source.
- **Runtime verified boot (enforced):** under `VBOOT_ENFORCE` the kernel verifies its own loaded image — `.text` + `.rodata` in `[__image_start, __vboot_sig_start)` — against an Ed25519 signature anchored to a public key compiled into the image, and **halts on mismatch before further init**. Both the accept and tamper-reject paths are proven headlessly in CI (`make smoke-vboot` on a fixed manifest, `make smoke-vboot-image` which signs the real kernel bytes with an ephemeral key and flips a byte to prove rejection). The design and the not-yet-implemented phases (UEFI Secure Boot hardware root; measured boot + remote attestation) are in [docs/BOOT_INTEGRITY.md](docs/BOOT_INTEGRITY.md).
- **Change control:** `main` is a protected branch — every change is a pull request that must pass the required CI gates, enforced for administrators (no direct-push/bypass), with signed commits required. See [CONTRIBUTING.md](CONTRIBUTING.md#change-control-on-main) for the full posture and its single-maintainer residual.

The security-critical primitives (capabilities, memory refcounting, hashing, RNG, FFI validation) live in safe `no_std` Rust and carry unit tests; the rest of the kernel is C and has **not** undergone systematic fuzzing or third-party review.

The Rust trusted base pulls in **zero third-party crates** — the entire Rust dependency graph is the `horus_shell` crate itself, so there is nothing to trust beyond the pinned compiler. This is enforced in CI: `tools/check_zero_deps.sh` fails the build if `rust/Cargo.lock` ever gains another package, and `cargo`'s `--locked` flag fails if the lock drifts from the manifest.

---

## Cryptography & entropy (current implementation)

The security-sensitive primitives are audited-standard algorithms implemented in safe Rust and validated against published known-answer vectors:

- **Password hashing:** Argon2id (RFC 9106), the memory-hard KDF, implemented from scratch in safe Rust on the crate's own BLAKE2b (`rust/src/argon2.rs`, `blake2b.rs`) and validated against the `argon2-cffi` reference vectors. Multi-lane capable (`p ≥ 1`, validated at p=2/p=4); cost is configurable (`ARGON2_M_COST_KIB`/`_T_COST`/`_P_COST` in `kernel.h`) and the kernel runs 4 MiB / 3 passes / 1 lane. A per-user random salt and a per-boot secret pepper are folded in; the raw 32-byte tag is stored.
- **User database integrity:** HMAC-SHA256 over the serialized records, keyed by the per-boot pepper.
- **Audit-log integrity:** each entry carries `HMAC(pepper, LE64(seq) || event)` and the log keeps a running chain head over every event ever appended (`rust/src/audit.rs`). This is an integrity *detector* and defence-in-depth: it defeats tampering by code that cannot read the pepper, and lets an external monitor recording the chain head detect drops, rewrites, and rollbacks. It is **not** a guarantee against a full kernel compromise that can read the pepper.
- **Key derivation** (per-file keys, per-block keys, user file master keys, volume key): HKDF-SHA256 (RFC 5869) with context binding.
- **Encryption-at-rest:** a ChaCha20 + HMAC-SHA256 Encrypt-then-MAC AEAD (`rust/src/aead.rs`), composed from the crate's RFC-tested ChaCha20 and HMAC primitives. Every write draws a fresh random 96-bit nonce, uses independent HKDF enc/mac subkeys, binds context as AAD, verifies the 128-bit tag in constant time, and fails closed (buffer zeroed) on any authentication failure. Its one caller is the **block-storage** layer, which keys per block and binds `(ino, block)` as AAD.
- **Signatures:** Ed25519 (`rust/src/ed25519.rs`) over the from-scratch SHA-512 (`sha512.rs`), validated against RFC 8032 and OpenSSL-generated vectors; used by the runtime verified-boot gate.
- **Randomness:** a single ChaCha20 fast-key-erasure CSPRNG, reseeded at boot from RDRAND (with retry + health check when advertised), TSC jitter, and boot counters. All salts, peppers, nonces, per-file keys, and the ASLR PRNG seed are drawn from this pool. Raw TSC is never used directly as randomness. The pool is asserted seeded at boot before any key material is derived.

---

## Side-channel threat model

Horus preempts and switches between mutually distrusting ring-3 tasks on a single core, and — under `SMP=1` — across cores. It does **not** claim resistance to microarchitectural side channels:

- **Timestamp counter (TSC):** `rdtsc` is readable from ring 3, so the kernel treats it as *public* and never uses it as a source of secret randomness — only as one whitened input to the CSPRNG. Disabling ring-3 `rdtsc` via `CR4.TSD` is a possible future mitigation but breaks userspace timing APIs.
- **Constant-time comparisons:** password-hash and MAC/tag comparisons use a data-independent accumulating compare (`constant_time_compare`) to avoid early-exit timing oracles.
- **Secret zeroization:** derived keys and intermediate key material are wiped with `secure_zero` (volatile, non-elidable) after use.
- **Cache partitioning / flush-on-context-switch:** not implemented. A context switch between distrusting tasks (single-core time-slicing or cross-core under SMP) should ideally flush or partition shared microarchitectural state (L1D, BTB); this is not yet done and is tracked as future hardening.
- **RNG health:** RDRAND draws are retried and rejected on the degenerate all-zeros / all-ones outputs a stuck hardware RNG would emit; the CSPRNG mixes hardware output with timing entropy so a single failed source cannot zero the pool.

---

## Known limitations & current status

An honest account of what Horus does and does not do, so no one draws incorrect conclusions about its readiness. Horus is a research and learning project and makes no claim to be a production OS.

### Fully working

Boot (Multiboot2 → x86-64 long mode, ring-3 `init` launches the shell); VGA terminal + serial + PS/2 keyboard; hardware isolation (Ring 0/3, per-task page tables, SMEP/SMAP when advertised); W^X for user memory; capability mint/transfer/grant/revoke with transitive cross-task revocation and lineage tracking; capability/FFI integrity (mirrored layout asserts, registered refcount table); user authentication (Argon2id, lockout + anti-spray, persisted password changes); the tamper-evident audit log; preemptive round-robin scheduling; ring-3 process control (spawn/exec/kill/exit/wait/grant); `init` supervision; fault and async signals with masking and alternate stacks; the ring-3 `fs_server` (per-file POSIX permissions vs kernel-attested identity, multi-client concurrency, crash-atomic write-ahead journal, large/double-indirect files); persistent encrypted storage on ATA with a RAM-vdisk fallback; the newlib userspace runtime; reproducible builds; and the enforced Ed25519 runtime verified-boot gate. Each is covered by a unit test and/or a headless self-test — see [TESTS.md](TESTS.md).

### Partial implementations

- **Userspace shell** — accepts input and dispatches commands; several are implemented end-to-end, others parse arguments but do little. Coverage is uneven.
- **IPC** — the endpoint `send`/`recv` cycle works (capability-gated). `SYS_IPC_SEND`/`RECV` are **non-blocking** (return a would-block code; the caller polls from ring 3); `SYS_IPC_CALL` can block on the full-context path. Each endpoint is a **single-slot mailbox** serving one in-flight request; concurrent multi-client service is layered on top via `SYS_IPC_REPLY_TO` (used by `fs_server`). A richer multi-slot / worker-pool IPC is a follow-up. Async notifications (`SYS_NOTIFY`/`SYS_WAIT_NOTIFY`) work end-to-end.
- **Copy-on-write paging** — the `PAGE_COW` flag and refcount infrastructure are in place and the page-fault handler calls into Rust to decide demand-zero vs COW-copy; the common cases work and the Rust logic is unit-tested, but the end-to-end paths are not stress-tested.
- **Disk volume geometry** — encrypted block storage over a real superblock/inode/bitmap layout is complete (per-block AEAD, journal, direct + single- + double-indirect mapping). The residual limit is *scale*: a single 512-byte bitmap block caps a volume at 4096 data blocks (2 MiB). Growing that is a pure capacity feature with no security value and is a deliberate non-goal for now.

### Not yet present

- **SMP as default** — multi-core works behind `SMP=1`, but the shipped kernel is single-core. The multi-core scheduler shares one runnable pool; there are no per-CPU run queues, priorities, or flush-on-switch. Capability resolution is already SMP-safe on the read side (the model-checked seqlock); what remains is scheduler maturity and microarchitectural flush-on-switch, not capability integrity.
- **ASLR entropy ceiling** — per-spawn stack, heap, and image base are all randomised from the CSPRNG, but userspace runs in the low ~8 MiB 32-bit window, so the image base has ~9 bits of entropy rather than the tens of bits a 64-bit userspace ABI would allow. This is an entropy limit, not a missing mechanism.

### Security limitations (for anyone evaluating Horus as a security system)

- **Encrypted storage is early.** The cipher is sound; residual limits are operational (diskless boots use the ephemeral RAM vdisk; volumes are capped at 2 MiB; ACLs beyond POSIX owner/group/other + a uid-0 superuser are a deliberate non-goal).
- **Audit log is tamper-evident, not tamper-proof.** Edits, swaps, replays, drops, and rollbacks are all *detectable* (including by an external monitor via `SYS_AUDIT_DIGEST`), but an attacker who fully compromises the kernel and reads the per-boot pepper can recompute a self-consistent chain.
- **No covert / cache side-channel mitigation** (see the side-channel threat model above).
- **No privilege separation within the kernel** — all kernel code runs at the same privilege with access to all kernel data; a bug in the terminal driver has the same blast radius as one in the capability system.

### Estimated completeness

Rough orientation only, not guarantees. The capability system is the most complete and most carefully reviewed part.

| Area | Estimate |
|---|---|
| Capability model (design + core implementation) | ~85% |
| Boot and hardware initialisation | ~85% |
| Process model (spawn/exec/kill/wait/signal, init) | ~85% |
| Memory management | ~55% |
| Task scheduling | ~60% (preemptive; SMP behind a gate; no priorities) |
| IPC | ~45% (send/recv + blocking call + async notifications; single-slot) |
| Filesystem | ~75% (persistent, per-file permissions, multi-client, journal, large files) |
| Cryptography | ~80% |
| Storage / disk I/O | ~75% (ATA + persisted crypto metadata + journal; volume-size cap remains) |
| SMP | ~55% (works behind `SMP=1`; shared run queue, no priorities) |
| Testing | ~50% (84 unit tests + 22 CI jobs, incl. headless self-tests, TLA+ model checking, and FFI fuzzing; no coverage-guided fuzz or deep integration) |

---

## Reporting a vulnerability

If you discover a security issue in Horus that is not already documented above, please report it responsibly rather than disclosing it publicly right away.

**How to report:** open a GitHub Security Advisory in this repository (Settings → Security → Advisories → New draft advisory). This creates a private thread visible only to repository maintainers.

Include:

- A description of the issue and the component it affects
- Steps to reproduce or a proof-of-concept if applicable
- Your assessment of the impact
- Whether you want to be credited in the fix

We will acknowledge the report within a few days and aim to respond substantively within two weeks.

---

## Scope

Given the project's status, the following are in scope for responsible disclosure:

- Bugs in the capability system that allow a task to bypass access control
- Memory safety issues in the C kernel or Rust FFI boundary
- Authentication bypass in the user authentication path
- Privilege escalation from Ring 3 to Ring 0
- A task terminating, signalling, or endowing another task without the required `CAP_TCB`

The following are out of scope for now, because they are known and documented above:

- Bounded load-base ASLR entropy (~9 bits, 32-bit userspace window)
- Absence of covert-channel / cache side-channel mitigations
- SMP scheduler maturity (works behind `SMP=1`; not default, no per-CPU queues/priorities)

---

## Supported versions

The current release is **v0.1.0** (2026-07-15) — a provenance-only milestone (reproducible build + Sigstore attestation). Security fixes are applied to the `main` branch, from which the next release is cut.

| Version | Supported |
|---|---|
| `main` (unreleased) | ✅ Active development; fixes land here first |
| v0.1.0 | ✅ Latest release |
| < v0.1.0 | — (no earlier releases) |
