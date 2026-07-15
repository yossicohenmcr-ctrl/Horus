# Changelog

All notable changes to Horus are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project aims to follow [Semantic Versioning](https://semver.org/).

See the git history for the individual commits behind each item.

---

## [Unreleased]

No changes yet since v0.1.0.

---

## [0.1.0] - 2026-07-15

First tagged release: a **provenance milestone**. The `kernel.elf` and ISO are built reproducibly (byte-for-byte deterministic) and carry a keyless **Sigstore** SLSA build-provenance attestation binding each artifact's SHA-256 digest to the source commit and CI workflow run, so a released binary can be traced back to reviewed source. Everything below is the capability set shipped in this release.

### Security core & access control

- **Capability-based access control** — mint, transfer, move, grant, and revoke with transitive cross-task invalidation; no ambient authority (cap operations from a task without its own cspace are refused); lineage generation counters prevent use-after-revoke; a snapshot + revalidate-at-use guard closes a lookup/use TOCTOU window in the IPC paths; primordial (root) capabilities cannot be revoked; C/Rust capability layout pinned by mirrored compile-time assertions.
- **Table-driven syscall dispatch** — one descriptor table (numbers 0–75) enforces each syscall's fixed capability at a single choke point; unlisted numbers fail closed; a compile-time assertion pins the table to the syscall number space.
- **Hardware isolation & W^X** — Ring 0/3, per-task page tables, SMEP/SMAP (when advertised), NX; non-executable stacks and ELF `PT_LOAD` `p_flags` honoured.
- **ASLR** — per-spawn stack, heap, and PIE image base (relocated at load via `R_386_RELATIVE`); ~9-bit image-base entropy in the 32-bit window.
- **User authentication** — login with lockout + anti-spray throttle, Argon2id memory-hard hashing; password changes persist across reboots.
- **Tamper-evident audit log** — per-entry HMAC (sequence-bound) + running hash-chain head, keyed by the per-boot pepper; `SYS_AUDIT_DIGEST` returns the digest + verify status.
- **Cryptography (safe `no_std` Rust)** — Argon2id/BLAKE2b, SHA-256/HMAC/HKDF/PBKDF2, from-scratch SHA-512 + Ed25519, a ChaCha20 + HMAC-SHA256 AEAD, and a ChaCha20 CSPRNG (RDRAND + timing-jitter seeded), all validated against published/reference vectors.
- **Capability space zeroed on task-slot reuse**, so a reused slot cannot inherit a dead task's `CAP_USER`/`CAP_CONSOLE`/`CAP_ENCRYPTED_STORAGE`.
- **Ring-3 storage backend callback removed** — `SYS_REGISTER_STORAGE_BACKEND` (which let userspace register function pointers the kernel called from ring 0) fails closed; the ABI slot is reserved.

### Boot integrity

- **Reproducible builds** — byte-for-byte deterministic `kernel.elf` across clean builds, verified in CI.
- **Build provenance** — tagged releases carry a Sigstore SLSA build-provenance attestation (see above).
- **Runtime verified boot** — under `VBOOT_ENFORCE` the kernel verifies its own loaded `.text`+`.rodata` against an embedded Ed25519 anchor and **halts on mismatch before init**. Accept and tamper-reject are both proven in CI (`make smoke-vboot` on a fixed manifest; `make smoke-vboot-image` on the real signed kernel bytes).

### Kernel & processes

- **Ring-3 process control** — `SYS_SPAWN` (spawn a named child, hands the caller its `CAP_TCB`), `SYS_EXEC_NAMED` (replace the caller's image in place), `SYS_SPAWN_IMAGE`/`SYS_EXEC_IMAGE` (execve-from-fd), `SYS_CAP_GRANT` (delegate a cap into a supervised child), `SYS_KILL`/`SYS_EXIT` (terminate, `CAP_TCB`-gated), `SYS_SIGNAL` (async task-to-task signal, `CAP_TCB`-gated), and `SYS_WAIT` (block until a task exits). The shell's `run <file>` reads a program from the `fs_server` and execs it. Proven by `make smoke-proc`.
- **Ring-3 `init` (PID 1)** — launches at boot, spawns the shell, endows it via `SYS_CAP_GRANT`, and blocking-supervises it with `SYS_WAIT`, relaunching on exit or fault.
- **Preemptive scheduling** — the PIT (100 Hz) preempts ring-3 tasks via a full-context kernel-stack switch; ring-0 ticks never switch. Blocking (`SYS_IPC_CALL`, `SYS_WAIT`, `SYS_WAIT_NOTIFY`) uses the same block/switch path. The legacy cooperative `schedule()`/`context_switch()` path is deleted. Proven by `make smoke-preempt`.
- **Signals** — fault signals (`SYS_SIGACTION`/`SYS_SIGRETURN`), async task-to-task signals (`SYS_SIGNAL`), signal masking (`SYS_SIGMASK`), and alternate signal stacks (`SYS_SIGALTSTACK`, `SS_ONSTACK`-guarded). Handler address validated in safe Rust; no re-delivery inside a handler; no new authority. Proven by `make smoke-signal` and `make smoke-proc`.
- **Symmetric multiprocessing** *(behind `SMP=1`)* — application-processor bringup, a per-CPU LAPIC-timer scheduler over a shared runnable pool, IPC/notification locking, and acknowledged TLB-shootdown IPIs. Proven by `make smoke-smp`.
- **Async notifications** — `SYS_NOTIFY` ORs a 32-bit badge into a notification slot and wakes any task blocked on it (accumulating the badge otherwise); `SYS_WAIT_NOTIFY` consumes a pending badge or blocks via the same full-context path as IPC. Gated by the slot-3 endpoint capability. Proven by `make smoke-notify`.

### Filesystem & storage

- **Filesystem** — a ring-3 `fs_server` over the kernel's encrypted object store (syscalls 56–61), reached over IPC; real `ls`/`cat`/`mkdir`/`rm`/`touch`/redirection. The encrypted `fs_server` is the system's **single** filesystem — the legacy in-memory capfs (`SYS_FS_*`, syscalls 38–45) was removed and its numbers reserved (attack-surface reduction).
- **Persistent by default** — the kernel probes for an ATA disk at boot (bounded, no hang on a diskless bus) and uses the encrypted store when one is present; files and their per-block crypto metadata survive a reboot; the disk comes up mounted-but-locked and is unwrapped at login (Argon2id-derived KEK). Falls back to an ephemeral in-RAM vdisk when no disk is attached. Proven by `make smoke-fs` and a two-boot `make smoke-fs-persist`.
- **Ownership & permissions (zero-trust)** — the `fs_server` enforces POSIX owner/group/other rwx against the caller's **kernel-attested** identity (`SYS_IPC_SENDER`, unforgeable), with root (uid 0) the only ambient authority; `chmod` owner-or-root, `chown` root-only. Only the server holds the storage cap. Proven by `make smoke-fs-perms`.
- **Crash-resilient (write-ahead journal)** — every multi-block update runs as one transaction staged in RAM, committed to an on-disk HMAC-authenticated redo journal, then applied; a crash mid-update is completed or discarded by replay at the next mount. Mount-time `fsck` reclaims orphans. On-disk format v5. Proven by `make smoke-fs-wal`.
- **Large files** — direct (12) + single-indirect (64) + double-indirect (64×64) block mapping; the volume is 4096 blocks (2 MiB). Proven by `make smoke-fs-large`.
- **Multi-client concurrency** — several clients use the single-threaded `fs_server` without their replies colliding, via `SYS_IPC_REPLY_TO` routing each reply to the request's kernel-recorded sender. Proven by `make smoke-fs-conc`.

### Userspace runtime

- **newlib libc port** — a demand-paged heap via `sbrk`/`brk`, a userspace `malloc`, and a newlib libc over a per-process POSIX fd layer, with real `open`/`write`/`unlink`/`stat`/`fstat` plumbed through to the `fs_server`. Proven by `make smoke-newlib`.
- **Boot / IO** — Multiboot2 via GRUB2 into x86-64 long mode; VGA terminal + serial mirror; PS/2 keyboard.

### Tests & CI

- **84 Rust unit tests** across the security core, plus a zero-dependency property/differential fuzz harness over the highest-risk FFI entry points.
- **GitHub Actions runs 22 gated jobs**: `cargo test` + `clippy -D warnings`, the zero-dependency and doc-count guards, a kernel/ISO build, an alt-config matrix, a suite of headless QEMU self-tests (smoke-boot, ELF/W^X, preemption, signals, process-control, async notifications, SMP, the Ed25519 verified-boot gate, and the filesystem/libc suite: fs, fs-perms, fs-conc, fs-persist, fs-wal, fs-large, newlib), the scripted `smoke-session` integration test that drives the real ring-3 shell over serial, a reproducible-build check, a security scan + SBOM, and a **TLA+ model-checking job** that TLC-verifies five specs: capability-algebra subset-rights non-escalation, per-task paging isolation, the two-CPU capability seqlock (no torn read), the IPC lookup/use TOCTOU (no use-after-revoke), and SMP scheduling (no task on two CPUs).
- **Scripted integration session** — `make smoke-session` (`tools/session_test.py`) drives the real ring-3 shell over serial as a black box: a wrong password is rejected, the right one accepted, `whoami` reports the kernel-attested uid, and a capability-gated admin op is allowed for root but denied for a standard user.

### Known incomplete at 0.1.0

- **IPC** — single-slot mailboxes, one in-flight request; multi-client service is layered on top via `SYS_IPC_REPLY_TO`, but a richer multi-slot / worker-pool IPC is not built.
- **SMP** — works behind `SMP=1` but not default-on; shared runnable pool, no per-CPU queues/priorities, no flush-on-switch.
- **Storage** — persistent-by-default on ATA and crash-atomic journalling are done; volume size is capped at 2 MiB by single-bitmap geometry (a deliberate non-goal). Diskless boots use the ephemeral RAM vdisk.
- **ASLR** — bounded ~9-bit load-base entropy from the 32-bit userspace window.
- Deeper booted-kernel integration tests (beyond the smoke self-tests) and coverage-guided fuzzing.

See [SECURITY.md](SECURITY.md#known-limitations--current-status) for the full, candid limitations breakdown.

[Unreleased]: https://github.com/yossicohenmcr-ctrl/Horus/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/yossicohenmcr-ctrl/Horus/releases/tag/v0.1.0
