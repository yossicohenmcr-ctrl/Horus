# Changelog

All notable changes to Horus are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

Horus has not yet reached a versioned release. Changes below reflect the state of the `main` branch. See the git history for the individual commits behind each item.

---

## Unreleased

### Working (current state of `main`)

- **Capability-based access control** — mint, transfer, move, grant, and revoke with transitive cross-task invalidation; no ambient authority (cap operations from a task without its own cspace are refused); lineage generation counters prevent use-after-revoke; a snapshot + revalidate-at-use guard closes a lookup/use TOCTOU window in the IPC paths; primordial (root) capabilities cannot be revoked; C/Rust capability layout pinned by mirrored compile-time assertions.
- **Ring-3 process control** — `SYS_SPAWN` (spawn a named child, hands the caller its `CAP_TCB`), `SYS_EXEC_NAMED` (replace the caller's image in place), `SYS_SPAWN_IMAGE` / `SYS_EXEC_IMAGE` (execve-from-fd: spawn or exec a program image the caller read from a file, validated by the same loader a named binary uses), `SYS_CAP_GRANT` (delegate a cap into a supervised child), `SYS_KILL` / `SYS_EXIT` (terminate, `CAP_TCB`-gated), `SYS_SIGNAL` (async task-to-task signal, `CAP_TCB`-gated), and `SYS_WAIT` (block until a task exits). The shell's `run <file>` reads a program from the `fs_server` and execs it. Proven by `make smoke-proc`.
- **Ring-3 `init` (PID 1)** — launches at boot, spawns the shell, endows it via `SYS_CAP_GRANT`, and blocking-supervises it with `SYS_WAIT`, relaunching on exit or fault.
- **Preemptive scheduling** — the PIT (100 Hz) preempts ring-3 tasks via a full-context kernel-stack switch; ring-0 ticks never switch. Blocking (`SYS_IPC_CALL`, `SYS_WAIT`, `SYS_WAIT_NOTIFY`) uses the same block/switch path. Proven by `make smoke-preempt`.
- **Signals** — fault signals (`SYS_SIGACTION`/`SYS_SIGRETURN`: a ring-3 fault is delivered to a registered handler instead of killing the task), async task-to-task signals (`SYS_SIGNAL`), and alternate signal stacks (`SYS_SIGALTSTACK`: a handler runs on a registered stack with an `SS_ONSTACK` guard, so a corrupt or overflowed primary stack cannot stop it running). Handler address validated in safe Rust; no re-delivery inside a handler; no new authority. Proven by `make smoke-signal` and `make smoke-proc`.
- **Symmetric multiprocessing** *(behind `SMP=1`)* — application-processor bringup, a per-CPU LAPIC-timer scheduler over a shared runnable pool, IPC/notification locking, and acknowledged TLB-shootdown IPIs. Proven by `make smoke-smp`.
- **Filesystem** — a ring-3 `fs_server` over the kernel's encrypted object store (syscalls 56–61), reached over IPC; real `ls`/`cat`/`mkdir`/`rm`/`touch`/redirection. **Persistent by default**: the kernel probes for an ATA disk at boot (bounded, no hang on a diskless bus) and uses the encrypted store when one is present — files and their per-block crypto metadata survive a reboot; the disk comes up mounted-but-locked and is unwrapped at login (Argon2id-derived KEK) — falling back to an ephemeral in-RAM vdisk (auto-unlocked, no login) when no disk is attached. Proven by `make smoke-fs` and a two-boot `make smoke-fs-persist` (write on boot 1, verify on boot 2 against the same disk image). A latent ATA-only deadlock (the sector r/w took `storage_lock`, which the crypto layer already held) is fixed with a dedicated `ata_lock`. The encrypted `fs_server` is the system's single filesystem — the legacy in-memory capfs (`SYS_FS_*`) has been removed (see below).
- **Filesystem ownership & permissions (zero-trust)** — the `fs_server` is the filesystem reference monitor: it enforces POSIX owner/group/other rwx and ownership against the caller's **kernel-attested** identity (`SYS_IPC_SENDER` returns the sending task's login uid/gid — a client cannot forge it or place it in the request), with root (uid 0) as the only ambient authority. New inodes are owned by their creator; `chmod` is owner-or-root and `chown` is root-only (`SYS_FS_SET_META` persists owner/mode, server-only). A client cannot access what its real uid disallows, cannot reach the store directly (only the server holds the storage cap), and cannot bypass the checks. Proven by `make smoke-fs-perms`.
- **Crash-resilient filesystem (write-ahead journal)** — every multi-block object-store update (block bitmap + inode + per-block crypto metadata + superblock `meta_hmac` + data) runs as one transaction: staged in RAM, committed to an on-disk **redo journal** with an HMAC-authenticated header (keyed by a `disk_key`-derived key, replay targets bounds-checked), then applied to home locations. A crash mid-update is completed or discarded by replay at the next mount, so the filesystem is always fully before or fully after the operation — and this closed a latent brick where a crash between a metadata-sector write and the superblock write desynced `meta_hmac` and refused to mount. Mount-time `fsck` reclaims orphaned inodes and leaked data blocks. On-disk format v5. Proven by `make smoke-fs-wal` (boot 1 commits a write then crashes before applying it; boot 2 replays it and the data survives).
- **Large files (double-indirect blocks)** — the object store's block mapping now implements the double-indirect region, so one inode maps blocks through direct (12) + single-indirect (64) + double-indirect (64×64) = up to 4172 blocks, and the volume was raised to 4096 blocks (2 MiB). Fixed a latent single-indirect bug along the way: the pointers-per-block count was `1024` instead of the correct `BLOCK_SIZE/8 = 64`, which indexed a 512-byte stack buffer out of bounds for any file past block 76 (never triggered because no test wrote a file that large). `storage_free_inode_blocks` now frees the double-indirect tree too. Proven by `make smoke-fs-large` (writes + reads blocks across every mapping region including deep double-indirect, frees a ~130-block file in one journal transaction — the bitmap clears coalesce so it never overflows the 16-sector journal — and checks an unwritten hole reads as absent).
- **Legacy capfs removed (attack-surface reduction)** — the parallel in-memory capability filesystem (`SYS_FS_*` syscalls 38–45, `fs_objects[]`, the `capfs_*` engine and its separate at-rest AEAD) was deleted. It was a second filesystem, reachable from ring 3, with its own permission model and no persistence — redundant with the encrypted `fs_server`. The syscalls now fail closed (their dispatch-table entries are gone) and the numbers are reserved. The encrypted `fs_server`, which enforces POSIX ownership/permissions against the caller's kernel-attested identity, is now the system's single filesystem. The load-bearing simple `ramfs` (which backs the sealed user-account database) is unaffected.
- **Multi-client filesystem concurrency** — several clients can use the one (single-threaded) `fs_server` at once without their replies colliding. The server replies with `SYS_IPC_REPLY_TO`, which routes each reply to the request's kernel-recorded sender — delivered directly into that client's blocked `SYS_IPC_CALL`, never via a shared reply endpoint another client could poll or overwrite (the old single-client hazard). Requests still serialise (one processed at a time). Proven by `make smoke-fs-conc` (three clients hammer the server concurrently, each verifying it receives only its own replies).
- **Userspace runtime** — a demand-paged heap via `sbrk`/`brk`, a userspace `malloc`, and a newlib libc port over a per-process POSIX fd layer. Proven by `make smoke-newlib`.
- **libc `unlink()`** — the newlib `unlink()` stub is now a real syscall path: `unlink` → `posix_unlink` (a new `path_parent` resolver → the `fs_server`'s permission-checked `FS_OP_DELETE`) with `errno` mapping (`ENOENT`/`EACCES`/`ENOTEMPTY`). This uncovered and fixed a latent bug where `posix.h`'s `O_*` flag values disagreed with newlib's (`O_CREAT` was `0x40` vs newlib's `0x200`), silently dropping `O_CREAT` on the newlib `open()` path — the first end-to-end exercise of `posix.c`'s file path (the shell has its own client). `make smoke-newlib` now spawns the `fs_server` and drives real `open`/`write`/`unlink` end-to-end.
- **libc `stat()`/`fstat()` real metadata** — `posix_stat`/`posix_fstat` now report the file's actual permission bits, uid and gid from the `fs_server`'s `FS_OP_STAT` reply (plumbed through to `struct stat` `st_mode`/`st_uid`/`st_gid`) instead of the previous hardcoded `0644`/`0755`. Covered by `make smoke-newlib` (a freshly created file stats as a regular file, mode `0644`, uid 0).
- **Table-driven syscall dispatch** — one descriptor table (numbers 0–75) enforces each syscall's fixed capability at a single choke point; unlisted numbers fail closed; a compile-time assertion pins the table to the syscall number space.
- **Hardware isolation & W^X** — Ring 0/3, per-task page tables, SMEP/SMAP (when advertised), NX; non-executable stacks and ELF `PT_LOAD` `p_flags` honoured.
- **ASLR** — per-spawn stack, heap, and PIE image base (relocated at load via `R_386_RELATIVE`); ~9-bit image-base entropy in the 32-bit window.
- **User authentication** — login with lockout + anti-spray throttle, Argon2id memory-hard hashing; password changes persist across reboots.
- **Tamper-evident audit log** — per-entry HMAC (sequence-bound) + running hash-chain head, keyed by the per-boot pepper; `SYS_AUDIT_DIGEST` returns the digest + verify status.
- **Cryptography (safe `no_std` Rust)** — Argon2id/BLAKE2b, SHA-256/HMAC/HKDF/PBKDF2, a ChaCha20 + HMAC-SHA256 AEAD, and a ChaCha20 CSPRNG (RDRAND + timing-jitter seeded), all validated against published/reference vectors.
- **Boot / IO** — Multiboot2 via GRUB2 into x86-64 long mode; VGA terminal + serial mirror; PS/2 keyboard.
- **Reproducible builds** — byte-for-byte deterministic `kernel.elf`.
- **Async notifications** — `SYS_NOTIFY` ORs a 32-bit badge into one of `MAX_NOTIFICATIONS` slots and wakes any task blocked on that slot (patching the accumulated badge into the waiter's saved trap frame, so no cross-address-space copy is needed); it accumulates the badge when no one is waiting. `SYS_WAIT_NOTIFY` returns a pending badge immediately or blocks via the same full-context path as IPC/`SYS_WAIT`, with the badge delivered in `ebx`. Gated by the endpoint capability in slot 3 (WRITE to notify, READ to wait). Proven by `make smoke-notify`.
- **Scripted integration session** — `make smoke-session` (`tools/session_test.py`) boots the shipped kernel and drives the **real** ring-3 shell over serial as a black box (no compiled-in assertion): it types at the login prompt and shell and asserts a wrong password is rejected, the right one accepted, `whoami` reports the kernel-attested uid, and a capability-gated admin op (`useradd`) is allowed for root but denied for a standard user (no ambient authority). The seed of the Phase 5 integration harness.
- **Tests / CI** — 62 Rust unit tests; GitHub Actions runs **twenty gated jobs** (rust test + `clippy -D warnings`, kernel/ISO build, alt-config matrix, fourteen QEMU self-tests — smoke-boot, ELF/W^X, preemption, signals, process-control, async notifications, SMP, and the filesystem/libc suite: fs, fs-perms, fs-conc, fs-persist, fs-wal, fs-large, newlib — the scripted `smoke-session` integration test, plus a reproducible-build check and a security scan + SBOM).

### Added — process lifecycle and control (Phase 1)

- **`SYS_EXIT` + capability-gated `SYS_KILL`**, with waiter wake-up and (SMP-safe) teardown.
- **Ring-3 `SYS_SPAWN`** — a task spawns a named embedded binary; the load runs in the kernel address space and the caller receives the child's `CAP_TCB`.
- **In-place `SYS_EXEC_NAMED`** — replace the caller's image (same task id, capabilities preserved), plus scheduler resume-frame hardening.
- **`SYS_CAP_GRANT`** — delegate one capability slot into a supervised child's cspace (fixes an ASLR/kernel-data aliasing issue in the same pass; the user heap is now bounded below the kernel's low-memory critical data).
- **Ring-3 `init`** — a PID-1 process that launches, endows, and supervises the shell; the kernel no longer spawns the shell directly. Converted to a *blocking* `SYS_WAIT` supervisor once the wait path was hardened.
- **`SYS_SIGNAL`** — async task-to-task signalling gated on a `CAP_TCB`, delivered into the target's registered handler (reusing the fault-signal path); default-terminates when unhandled or for the uncatchable `SIG_KILL`.

### Added — SMP (multi-core, behind `SMP=1`)

Application-processor bringup, a LAPIC-timer per-CPU preemptive scheduler, IPC + notification locking for cross-CPU safety, and TLB-shootdown IPIs with acknowledgement. Gated behind `SMP=1` with a `make smoke-smp` CI job.

### Added — userspace filesystem server & newlib

- **Encrypted object-store syscalls (56–61)** — a capability-gated inode/block API to ring 3 (`SYS_FS_INODE_ALLOC`/`_FREE`, `SYS_FBLOCK_READ`/`_WRITE`, `SYS_FS_STAT`, `SYS_FS_SET_SIZE`); AEAD keys never leave the kernel TCB.
- **`fs_server`** — a real hierarchical FS (directories as inode data, root = inode 0) over a versioned IPC protocol (`include/fs_proto.h`) on two well-known endpoints; RAM or ATA backend. `make smoke-fs`.
- **newlib port** — a libc over a per-process POSIX fd layer with `malloc`/`sbrk`/`brk`. `make smoke-newlib`.
- **IPC is non-blocking** — `SYS_IPC_SEND`/`RECV` return a would-block code instead of spinning; callers poll from ring 3 where preemption interleaves them.

### Fixed — this session (scheduler / login)

- **Intermittent login hang.** `console_getc()` (and `serial2_read_char()`) waited for input by calling the cooperative `yield()`/`schedule()`, which cannot context-switch two mid-syscall ring-3 tasks — it swaps CR3/current and returns on the caller's own kernel stack. Once `init` became an always-runnable second ring-3 task, this toggled the active address space between shell and init, so a keystroke's `copy_to_user` and syscall return could land in the wrong task. Console/serial input now spins in place (hardware wait) without the cooperative scheduler.
- **`SYS_WAIT` on the preemptive path.** `h_wait` used the same broken cooperative spin; it now marks the caller `TASK_BLOCKED_WAIT` and suspends it on the block/switch path, woken by the target's teardown.
- **Fault-death wakes waiters.** The ring-3 fault-kill path raw-set `state=0` without waking a `SYS_WAIT` waiter; it now routes through `task_teardown()` + `task_exit_switch()`, so a blocking `init` relaunches a shell that *faulted*, not only one that exited cleanly.

### Security — earlier hardening passes

- **Encryption-at-rest replaced.** The block-storage layer's hand-rolled "AES-128" (a broken AES-NI key schedule + an unaudited ARX fallback, neither actually AES) and the ramfs per-file XOR keystream were both replaced with one ChaCha20 + HMAC-SHA256 Encrypt-then-MAC AEAD (`rust/src/aead.rs`): fresh per-write nonce, independent HKDF subkeys, context as AAD, constant-time fail-closed verify.
- **Argon2id password hashing.** Replaced PBKDF2-HMAC-SHA256 with memory-hard Argon2id (RFC 9106), multi-lane + configurable cost, on an in-house BLAKE2b — validated against reference vectors.
- **Ring-3 storage backend callback removed.** `SYS_REGISTER_STORAGE_BACKEND` (which let userspace register function pointers the kernel called from ring 0) fails closed; the ABI slot is reserved.
- **Capability space zeroed on task-slot reuse**, so a reused slot cannot inherit a dead task's `CAP_USER`/`CAP_CONSOLE`/`CAP_ENCRYPTED_STORAGE`.
- **capfs generation checks** on every operation via `fs_resolve_cap()`; key material wiped on delete.
- **Account/password hygiene** — locked initial passwords for new accounts, password changes persist, cleartext buffers scrubbed after auth.
- **Table-driven syscall dispatch** with a fail-closed choke point and a compile-time table-size guard.
- **Tamper-evident audit log** added, with `SYS_AUDIT_DIGEST`.
- **W^X** enforced (non-executable stacks + ELF `p_flags`).
- **Full ASLR** — PIE userspace with a randomised load base.
- **Errno-aligned error codes** — a shared `SYS_ERR_*` vocabulary (`include/errno.h`) with `sys_strerror()`, distinguishing an unknown syscall from a missing capability.
- **32-bit kernel build removed** — the kernel is x86-64 long-mode only.

### Added — retire cooperative schedule (Phase 3)

- **Single full-context switch path** — `sched_enter_user` enters a task via its fabricated trap frame (pop+iretq, same epilogue as the ISR); boot of `init` and all self-test launches use it instead of `lretq`. `SYS_YIELD` requests a switch via `g_want_yield` and `sched_yield_switch` on the live trap frame. The cooperative `schedule()`/`context_switch()` path is deleted; idle is `kernel_idle` (sti; hlt). Page-fault kills use `task_teardown` + `task_exit_switch` like other fault paths.

### Added — concurrent-IPC publish order (Phase 3)

- **Save frame before waiter is visible** — `SYS_IPC_CALL` / `SYS_WAIT` / `SYS_WAIT_NOTIFY` only set `pending_block` (+ object fields). `ipc_block_switch` writes `saved_ksp`, barriers, then `ipc_publish_pending_block` publishes the waiter under the IPC lock. Cross-CPU replies/notifies/teardowns always patch a valid trap frame; a reply that arrives as a mailbox message before publish is consumed immediately.

### Known incomplete

- IPC: single-slot mailboxes, one in-flight request (multiple-client service is layered on top via `SYS_IPC_REPLY_TO`, but a richer multi-slot / worker-pool IPC is not built). Async notifications (`SYS_NOTIFY`/`SYS_WAIT_NOTIFY`) now work end-to-end (see above).
- Filesystem: Phase 2 is complete (persistent, per-file permissions, multi-client, crash-atomic journal, large files, single filesystem — legacy capfs removed). Residual limits are deliberate non-goals: volume size capped at 2 MiB by single-bitmap geometry, and full ACLs beyond POSIX owner/group/other + uid-0 superuser.
- Storage: persistent-by-default on ATA and crash-atomic journalling are done; the residual gap is larger volumes (a deferred non-goal). Diskless boots still use the ephemeral RAM vdisk.
- SMP: works behind `SMP=1` but not default-on; shared runnable pool, no per-CPU queues/priorities, no flush-on-switch.
- Bounded load-base ASLR entropy (~9 bits) from the 32-bit userspace window.
- Deeper booted-kernel integration tests (beyond the smoke self-tests) and fuzzing; `smoke-fs` / `smoke-newlib` are local targets, not yet gated in CI.

See [docs/LIMITATIONS.md](docs/LIMITATIONS.md) for detail.
