# Horus — Current Limitations

This document is an honest account of what Horus does and does not do. The goal is to prevent anyone from drawing incorrect conclusions about its readiness or security properties.

Horus is a research and learning project. It is not a production operating system and makes no claim to be one. Where this document and the code disagree, the code is the source of truth — please open an issue.

---

## What actually works

These subsystems are functional in the current codebase:

- **Boot sequence** — Multiboot2 boot via GRUB2 into x86-64 long mode; a ring-3 `init` (PID 1) launches the shell.
- **VGA terminal** — text mode, colour output, kernel log buffer, serial mirror; PS/2 keyboard input.
- **Hardware isolation** — Ring 0/Ring 3 separation, per-task page tables, user/kernel memory split. SMEP and SMAP are enabled when the CPU advertises them (ring 0 cannot execute or casually read user pages; user copies go through a kernel mapping), brought up after feature detection.
- **W^X for user memory** — `EFER.NXE` is on and the kernel sets the PTE NX bit so writable pages are never executable: user stacks are mapped non-executable, and the ELF loader honours each `PT_LOAD` segment's `p_flags`. The policy decision lives in Rust and is unit-tested; the shipped static-PIE binaries take the ELF path and are covered by the smoke-boot and `smoke-elf` tests.
- **Capability mint, transfer, grant, and revoke** — the core operations work, including transitive revocation across every task's cspace and the kernel root cnode. Revocation requires `CAP_RIGHT_REVOKE`; mint/transfer require `CAP_RIGHT_MINT`; a "no ambient authority" guard refuses cap operations from any non-kernel task lacking its own cspace. `SYS_CAP_GRANT` delegates one slot from a supervisor into a child it spawned.
- **Lineage tracking** — use-after-revoke is prevented via per-lineage generation counters; a looked-up capability can be snapshotted and re-validated at point of use (wired into the IPC paths to close a lookup/use TOCTOU window).
- **Capability/FFI integrity** — the C `capability_t` and Rust `Capability` layouts are pinned by mirrored compile-time assertions; the refcount table is registered once and every later inc/dec must present the exact (pointer, length) or is refused.
- **User authentication** — login, lockout after failed attempts + anti-spray throttle, per-user UID assignment, Argon2id memory-hard hashing; password changes persist across reboots.
- **Audit log** — kernel-side circular buffer of security events. **Tamper-evident**: each entry is HMAC'd (binding its sequence number) and a running hash-chain head commits to the whole ordered history, keyed by the per-boot pepper (`rust/src/audit.rs`); `SYS_AUDIT_DIGEST` returns the digest + constant-time verify status. Detector, not tamper-proof (see below).
- **Preemptive round-robin scheduling** — the timer (PIT at 100 Hz) preempts ring-3 tasks via a full-context kernel-stack switch, so CPU-bound tasks time-share without cooperating. A tick in ring 0 never switches (the kernel stays effectively non-preemptible). Proven by `make smoke-preempt`. Blocking (`SYS_IPC_CALL`, `SYS_WAIT`), voluntary `SYS_YIELD`, first entry into a task (`sched_enter_user`), and boot of `init` all use the same full-context trap-frame path; the legacy cooperative `yield()`/`schedule()` switch has been removed.
- **Ring-3 process control** — a task can `SYS_SPAWN` a named child (receiving its `CAP_TCB`), replace its own image in place (`SYS_EXEC_NAMED`), delegate caps to a child (`SYS_CAP_GRANT`), terminate itself (`SYS_EXIT`) or a task it holds a `CAP_TCB` for (`SYS_KILL`), and block until a task exits (`SYS_WAIT`). Proven by `make smoke-proc`.
- **`init` supervision** — a ring-3 PID 1 spawns, capability-endows, and blocking-supervises the shell, relaunching it on exit or fault.
- **Fault signals** — a task registers its own handler (`SYS_SIGACTION`); a ring-3 fault (page fault → `SIG_SEGV`, `#UD` → `SIG_ILL`) is delivered to it (signal # in `ebx`, fault addr in `ecx`) instead of killing it, and `SYS_SIGRETURN` resumes the exact pre-signal context. The handler address is validated in safe Rust (fail-closed); a fault *inside* a handler is not re-delivered; the handler runs at ring 3 with unchanged privileges. Proven by `make smoke-signal`.
- **Async task-to-task signals** — `SYS_SIGNAL` (gated on a `CAP_TCB` to the target, same authority as `SYS_KILL`) queues a signal, redirected into the target's handler on its next return to ring 3, or taking the default terminate action when unhandled or for the uncatchable `SIG_KILL`. The pending set is a full 1..31 bitmask; `SYS_SIGMASK` blocks/unblocks signals (lowest unmasked delivered first, `SIG_KILL` never maskable); a signal to a `SYS_WAIT`-blocked target interrupts the wait (`SYS_ERR_INTR`) so it lands promptly; and `SYS_SIGALTSTACK` runs a handler on a registered alternate stack (`SS_ONSTACK` guard, so a corrupt or overflowed primary stack cannot stop the handler running). Proven by `make smoke-proc`.
- **Symmetric multiprocessing (behind `SMP=1`)** — application processors are brought up (LAPIC INIT-SIPI-SIPI), each runs its own LAPIC-timer preemption tick over a shared runnable pool, IPC/notification paths lock for cross-CPU safety, and TLB-shootdown IPIs are acknowledged. Proven by `make smoke-smp`. Off by default; see the SMP note below.
- **Filesystem server** — a ring-3 `fs_server` over the kernel's encrypted object store, reached over IPC; real `ls`/`cat`/`mkdir`/`rm`/`touch`/redirection from the shell, and the system's single filesystem (the legacy in-memory capfs is removed). It is the filesystem reference monitor: it enforces per-file POSIX owner/group/other rwx against the caller's *kernel-attested* uid/gid (`SYS_IPC_SENDER`, unforgeable by the client), serves multiple clients concurrently with replies routed to each caller by identity (`SYS_IPC_REPLY_TO`), makes every multi-block update crash-atomic through a write-ahead redo journal replayed by a mount-time `fsck`, and supports large files via double-indirect blocks. Proven by `make smoke-fs`, `smoke-fs-perms`, `smoke-fs-conc`, `smoke-fs-wal`, and `smoke-fs-large`.
- **Persistent encrypted storage (by default when a disk is present)** — at boot the kernel probes for an ATA disk (bounded probe; no hang on a diskless bus) and uses the encrypted store when one is present. Per-block crypto metadata (nonces/tags) is flushed on write and reloaded + HMAC-verified at mount, so files survive a reboot; the volume comes up mounted-but-locked and is unwrapped at login (Argon2id-derived KEK). With no disk attached the kernel falls back to an ephemeral in-RAM vdisk (auto-unlocked). Proven by `make smoke-fs-persist` (write on boot 1, verify on boot 2 against the same disk image).
- **Userspace runtime** — a demand-paged heap via `sbrk`/`brk`, a userspace `malloc`, and a newlib libc port over a per-process POSIX fd layer (`make smoke-newlib`).
- **Reproducible builds** — `make reproducible-build` yields a byte-for-byte identical `kernel.elf` across clean builds (verified in CI).

---

## Partial implementations

These subsystems compile and run but are incomplete:

### Userspace shell

The shell accepts input and dispatches commands. Several are implemented end-to-end; others parse their arguments but return errors or do little. Coverage is uneven.

### IPC

The endpoint-based `send`/`recv` cycle works (256-byte messages, capability-gated). `SYS_IPC_SEND`/`RECV` are **non-blocking** (return a would-block code `-2`; the caller polls from ring 3 where preemption interleaves it); `SYS_IPC_CALL` can block on the full-context path. Each endpoint is a **single-slot mailbox**, so it serves **one in-flight request at a time**. Concurrent multiple-client service is achieved above this primitive by `SYS_IPC_REPLY_TO`, which routes a server's reply to the request's kernel-recorded sender (used by `fs_server`); a richer multi-slot / parallel-worker IPC is still a follow-up. **Async notifications (`SYS_NOTIFY`/`SYS_WAIT_NOTIFY`) work**: `SYS_NOTIFY` ORs a 32-bit badge into a notification slot and wakes any task blocked on it (accumulating the badge otherwise); `SYS_WAIT_NOTIFY` consumes a pending badge or blocks via the same full-context path as IPC. Proven by `make smoke-notify`.

### Copy-on-write paging

The `PAGE_COW` flag and refcount infrastructure are in place, and the page-fault handler calls into Rust to decide demand-zero vs. COW-copy. The common cases work and the Rust logic is unit-tested, but the end-to-end paths have not been stress-tested and likely have edge cases.

### Disk-backed storage (volume geometry)

`storage.c` implements encrypted block storage — a ChaCha20 + HMAC-SHA256 AEAD with per-block HKDF keys, fresh per-write nonce, `(ino, block)` as AAD — over a real superblock/inode/bitmap layout, exercised end-to-end by `fs_server` via the encrypted object-store syscalls. The live backend is selected at boot: a real ATA disk (`ata.c`, 28-bit-LBA PIO) when one is present, otherwise the ephemeral RAM vdisk. Cross-reboot persistence of files *and* their per-block crypto metadata is in place on ATA, multi-block updates are crash-atomic through a write-ahead redo journal replayed by a mount-time `fsck`, and files map through direct + single- + double-indirect blocks. The remaining limit is volume *scale*: a single 512-byte bitmap block caps a volume at 4096 data blocks (2 MiB). Growing that cap needs multi-block bitmaps, which is a pure capacity feature with no security value and is a deliberate non-goal for now (the allocator already enforces the cap safely).

---

## What does not work / is not yet present

### SMP as default

Multi-core works behind `SMP=1`, but the shipped kernel is single-core. The multi-core scheduler shares one runnable pool with a per-CPU pull; there are no per-CPU run queues, no priorities or fairness, and no flush-on-switch. Retiring the gate and hardening the scheduler is Phase 3.

Capability resolution is now SMP-safe on the read side: `cap_lookup` is a seqlock reader over `cap_seq` (bumped odd/even by every `cap_lock` acquire/release), so a lock-free lookup on one CPU can no longer observe a torn capability or a half-nulled slot while a capability mutation (mint/transfer/revoke sweep/grant) runs under `cap_lock` on another CPU — it retries until it has a stable snapshot. The seqlock protocol is TLA+ model-checked (`docs/cap_seqlock.tla`) — TLC exhaustively confirms no committed lock-free read is ever torn across every two-CPU interleaving. This closes the lockless-`cap_lookup` data race. The separate lookup→use TOCTOU on the *returned* pointer remains closed as before (snapshot/revalidate on the IPC paths; the `SYS_KILL`/`SYS_SIGNAL`/`SYS_CAP_GRANT` `cap_lock` brackets). What is still outstanding for SMP is scheduler maturity (per-CPU queues, priorities) and microarchitectural flush-on-switch, not capability integrity.

### ASLR entropy ceiling (32-bit userspace window)

Per-spawn stack top, heap gap, and image load base are all randomised from the CSPRNG (userspace is static-PIE and relocated at load). The remaining limitation is *entropy*, not mechanism — userspace runs in 32-bit compatibility mode confined to the low ~8 MiB window, so the image base has ~9 bits of entropy rather than the tens of bits a 64-bit userspace ABI would allow.

---

## Security limitations

These matter specifically for anyone evaluating Horus as a security system:

### Encrypted storage is persistent, but still early

The block cipher is sound (ChaCha20 + HMAC-SHA256 AEAD, per-block HKDF subkeys, fresh per-write nonce), and on an attached ATA disk the store is the live backend with crypto metadata persisted across reboots (volume sealed until login), multi-block updates crash-atomic via a write-ahead redo journal, and per-file POSIX ownership/permissions enforced by the `fs_server` against the caller's kernel-attested identity. Residual limitations are operational rather than cryptographic: a diskless boot still uses the ephemeral RAM vdisk, and volume size is capped at 2 MiB by single-bitmap geometry (a deliberate non-goal to grow). Fuller ACLs (beyond POSIX owner/group/other + a uid-0 superuser) are also a deliberate non-goal.

### Bounded load-base ASLR entropy

Because userspace is confined to the low ~8 MiB 32-bit window, the load base has only ~9 bits of entropy, so a determined attacker with a memory-disclosure primitive faces a smaller search space than on a 64-bit-userspace system.

### Audit log is tamper-evident, not tamper-proof

Edits, ring-slot swaps, replays, drops, and rollbacks are all *detectable* (including by an external monitor recording the chain head via `SYS_AUDIT_DIGEST`). The residual limitation is that this is a **detector**: an attacker who fully compromises the kernel and reads the per-boot pepper can recompute a self-consistent chain — the same accepted trust boundary as the user-database tag.

### No covert / cache side-channel mitigation

The timer preempts and switches between mutually distrusting ring-3 tasks (and, under `SMP=1`, across cores), but there is no flush-on-switch or cache partitioning to limit microarchitectural leakage. Tracked in `SECURITY.md`.

### No privilege separation within the kernel

All kernel code runs at the same privilege level with access to all kernel data; a bug in the terminal driver has the same blast radius as one in the capability system.

---

## Code quality notes

- Compilation success is not evidence of correct runtime behaviour; some paths are partial.
- Error codes are a shared, descriptive, errno-aligned `SYS_ERR_*` set (`include/errno.h`) used by both kernel and userspace, with `sys_strerror()`. The dispatcher and the auth / user-copy paths return specific codes; some deeper helpers still use ad-hoc small negatives.
- The Rust crate is named `horus_shell` for historical reasons; it is the security core (capabilities, memory refcounting, the SHA-2/BLAKE2b/Argon2id/KDF/AEAD/RNG primitives, FFI validation).
- `src/kernel/minimal_secure_stubs.c` supplies the stubs for the `MINIMAL_SECURE=1` build; it is build configuration, not security logic.
- **Tests:** 84 Rust unit tests (capability engine, memory/refcount trust boundary, RNG and SHA-2 family vs. published vectors, the ChaCha20+HMAC AEAD, the tamper-evident audit MAC/chain, BLAKE2b + Argon2id vs. RFC 7693 / `argon2-cffi` vectors, the W^X page policy, the signal-handler-address window, FFI validation, the from-scratch SHA-512 + Ed25519 verifier vs. RFC 8032 and OpenSSL-generated vectors, and a zero-dependency property/differential fuzz harness over the highest-risk FFI entry points). CI runs **22 gated jobs** (`cargo test` + `clippy -D warnings`; kernel/ISO build; alt-config matrix; fifteen headless QEMU self-tests — smoke-boot, ELF/W^X, preemption, signals, process-control, async notifications, SMP, the filesystem/libc suite (fs, fs-perms, fs-conc, fs-persist, fs-wal, fs-large, newlib), and the Ed25519 verified-boot gate (accept + tamper-reject); a scripted `smoke-session` integration test that drives the real ring-3 shell over serial; a reproducible-build check; a security scan + SBOM; and a TLA+ model-checking job that TLC-verifies the capability and paging invariants). The scripted-session harness (`tools/session_test.py`) is a first, deliberately small integration test — broader scenarios (W^X violations, IPC/FS round-trips) are still ahead. Property/differential fuzzing of the FFI boundary now runs in CI; coverage-guided fuzzing (libFuzzer/AFL++) is intentionally excluded to preserve the zero-third-party-crate guard and the pinned hermetic toolchain.

---

## Estimated completeness

Rough orientation only, not guarantees. The capability system is the most complete and most carefully reviewed part of the project.

| Area | Estimate |
|---|---|
| Capability model (design and core implementation) | ~85% |
| Boot and hardware initialisation | ~85% |
| Process model (spawn/exec/kill/wait/signal, init) | ~85% (Phase 1 complete; mask + altstack + image exec) |
| Memory management | ~55% |
| Task scheduling | ~60% (preemptive; SMP behind a gate; no priorities) |
| IPC | ~45% (send/recv + blocking call + async notifications; single-slot) |
| Filesystem | ~75% (ring-3 server over encrypted store; persistent on ATA; per-file permissions, multi-client, crash-atomic journal, large files) |
| Cryptography (Argon2id/BLAKE2b + KDF/MAC/RNG + ChaCha20/HMAC AEAD) | ~80% |
| Storage / disk I/O | ~75% (ATA probe + persisted crypto metadata + crash-atomic journal; volume-size cap remains) |
| SMP | ~55% (works behind `SMP=1`; not default, shared run queue, no priorities) |
| Testing | ~50% (84 unit tests + 22 CI jobs, incl. fifteen headless boot self-tests, TLA+ model checking, and FFI property/differential fuzzing; no coverage-guided fuzz or deep integration) |
