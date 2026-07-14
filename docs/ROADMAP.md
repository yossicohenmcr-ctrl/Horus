# Horus Roadmap

This document describes where Horus is **headed** — the work that is still ahead.
For what already exists, see the summary below, the git history, and
`docs/ARCHITECTURE.md`.

The phases are roughly ordered by dependency and priority, but they are largely
independent and can be picked up in any order. Nothing here is a commitment —
priorities shift as contributors join and the design evolves. If you want to work
on something, open an issue or start a discussion first; coordination saves
effort.

---

## Where things stand

The foundation is a working x86-64 capability microkernel that boots a ring-3
`init` supervising a ring-3 shell, and passes a headless boot smoke-test plus
five runtime self-tests in CI. Already in place:

- **Kernel core** — long-mode microkernel; capability-based access control with
  table-driven, fail-closed syscall dispatch; preemptive scheduling; ring-3
  fault signals delivered to a registered handler; per-spawn ASLR; W^X user
  memory; SMEP/SMAP; a tamper-evident HMAC-chained audit log.
- **Process control** — a ring-3 `init` (PID 1) launches at boot and spawns,
  capability-endows, and *blocking*-supervises the shell (`SYS_WAIT`). A task
  can spawn a child from ring 3 (`SYS_SPAWN`, which hands the caller a `CAP_TCB`
  to the child), replace its own image (`SYS_EXEC_NAMED`), delegate a capability
  to a child it supervises (`SYS_CAP_GRANT`), signal a task it holds a `CAP_TCB`
  for (`SYS_SIGNAL`), terminate itself (`SYS_EXIT`) or such a task (`SYS_KILL`),
  and block until one exits (`SYS_WAIT`), with waiter wake-up on both a clean
  exit and a fault. A task can also spawn/exec a program image it read from a
  file (`SYS_SPAWN_IMAGE` / `SYS_EXEC_IMAGE`, execve-from-fd) and run signal
  handlers on an alternate stack (`SYS_SIGALTSTACK`) (`make smoke-proc`).
- **Multiprocessing** — the application processors are brought up and run
  scheduled tasks across cores with acknowledged TLB-shootdown IPIs, behind an
  `SMP=1` build gate (`make smoke-smp`).
- **Cryptography** — from-scratch, test-vector-validated Argon2id password
  hashing, a ChaCha20 CSPRNG seeded from RDRAND, and a ChaCha20 + HMAC-SHA256
  AEAD for encryption-at-rest, all in safe `no_std` Rust.
- **Filesystem** — a ring-3 `fs_server` over an encrypted object store, reached
  over IPC; real `ls` / `cat` / `mkdir` / `rm` / `touch` / redirection from the
  shell. Persistent by default: the kernel probes for an ATA disk at boot and uses
  the encrypted store (files survive a reboot, unsealed at login) when one is
  present, falling back to an in-RAM disk when it is not. Per-file ownership and
  POSIX permissions are enforced by the server against the caller's kernel-attested
  identity, multiple clients can use it concurrently (replies routed to each caller
  by identity via `SYS_IPC_REPLY_TO`), and multi-block updates are crash-atomic via
  an HMAC-authenticated write-ahead redo journal replayed at mount (`make smoke-fs`,
  `smoke-fs-persist`, `smoke-fs-perms`, `smoke-fs-conc`, `smoke-fs-wal`).
- **Userspace runtime** — a demand-paged heap via `sbrk`/`brk`, a userspace
  `malloc`, and a newlib libc port over a per-process POSIX fd layer
  (`make smoke-newlib`).
- **CI** — 21 gated jobs: `rust` (`cargo test` + `clippy -D warnings`),
  `kernel` (build + ISO), `altconfigs` (DEBUG_SHELL/MINIMAL_SECURE matrix), the
  headless QEMU boot `smoke`, thirteen runtime self-tests (`smoke-elf`,
  `smoke-preempt`, `smoke-signal`, `smoke-proc`, `smoke-notify`, `smoke-smp`,
  `smoke-fs`, `smoke-fs-perms`, `smoke-fs-conc`, `smoke-fs-persist`,
  `smoke-fs-wal`, `smoke-fs-large`, `smoke-newlib`), the scripted
  `smoke-session` integration test, a `reproducible` build check, a
  `security` SAST/SBOM scan, and a `tla` TLA+ model-checking job (TLC verifies
  the capability-algebra, paging-isolation, and two-CPU seqlock invariants). The whole filesystem suite (persistence,
  permissions, concurrency, journal crash-recovery, large files), the newlib
  libc port, and async notifications are now CI-enforced, not local-only.

---

## Phase 1 — Process lifecycle and control — *complete*

The process model is complete; the remaining work has moved into the phases
below. For the record, the phase delivered:

- **Signals** — `SYS_SIGNAL` delivers async task-to-task signals into a
  registered handler, the pending set is a full 1..31 bitmask, `SYS_SIGMASK`
  blocks/unblocks signals (delivering the lowest unmasked one), a signal to a
  task parked in `SYS_WAIT` interrupts the wait (`SYS_ERR_INTR`) and delivers
  promptly, and `SYS_SIGALTSTACK` runs a handler on a registered alternate stack
  (an `SS_ONSTACK` guard, so a corrupt or overflowed primary stack cannot stop
  the handler running).
- **Full `argv`** — `SYS_SPAWN` and `SYS_EXEC_NAMED` marshal a full argument
  vector onto the child's stack, read back via `SYS_GET_ARGV`.
- **`exec` from a file** — `SYS_SPAWN_IMAGE` / `SYS_EXEC_IMAGE` spawn or exec a
  program image the caller supplies in its own memory (execve-from-fd): the
  caller reads the image from a file via the `fs_server` — the shell's `run
  <file>` does exactly this — and the kernel validates it with the same loader a
  named binary uses (`arm_image_from_user` → `try_elf_load`: W^X, bounds,
  fail-closed relocations), gated by the same slot-3 `WRITE|EXEC` capability. This
  decouples exec from any one filesystem and adds no kernel↔server IPC
  reentrancy.
- **`fork` — deliberately not adopted** — the ring-3 `SYS_SPAWN` +
  `SYS_CAP_GRANT` model already gives create-a-task and hand-it-capabilities
  without fork's whole-address-space aliasing and its least-privilege problem (a
  forked child would inherit *every* parent capability).
- **Init launches the servers** — the default boot brings up the system through
  `init`: it is endowed from the root cnode with a `CAP_USER` admin cap, two
  `CAP_ENDPOINT` caps and (via slot 9) the object-store cap, launches `fs_server`
  and provisions **all four** of its capabilities purely with `SYS_CAP_GRANT` —
  no direct root-cnode installs — then launches and supervises the shell
  alongside it. Spawned children inherit their spawner's uid (closing a latent
  "child comes up as uid 0" hole), and the root shell can see every task (`ps`)
  under the same uid==0 authority the object-store syscalls enforce.

Proven by `make smoke-proc` (exit + kill + spawn + exec + grant + image +
altstack + signal) and `make smoke-init-fs` (the delegated server driven by an
automated client end-to-end).

---

## Phase 2 — A production filesystem — *complete*

The filesystem persists by default, enforces per-file ownership and permissions,
serves multiple clients, is crash-atomic, supports large files, and is the
system's single filesystem (the legacy parallel capfs is gone).

**Persistence is done:** the shipped kernel probes for an ATA disk at boot and
uses the encrypted store when one is present (the per-block crypto metadata is
flushed on write and reloaded + HMAC-verified at login, so files survive a
reboot), falling back to the ephemeral RAM vdisk when no disk is attached; a
persistent disk comes up sealed and is unwrapped at login. Proven by
`make smoke-fs-persist`.

**Ownership and permissions are done:** the `fs_server` is the filesystem
reference monitor, enforcing POSIX owner/group/other rwx and ownership against the
caller's *kernel-attested* uid/gid — `SYS_IPC_SENDER` gives the server the sender's
login identity, never anything the client puts in the request — with root (uid 0)
as the only ambient authority. New inodes are owned by their creator; `chmod` is
owner-or-root, `chown` is root-only. Proven by `make smoke-fs-perms` (a non-root
client is denied what its real uid disallows and cannot claim to be another user).

**Multi-client concurrency is done:** several clients can use the one
(single-threaded) `fs_server` at once without their replies colliding. The server
replies with `SYS_IPC_REPLY_TO`, which routes each reply to the request's
kernel-recorded sender — delivered directly into that client's blocked
`SYS_IPC_CALL`, never via a shared reply endpoint that another client could poll
or overwrite. Requests still serialise through the server (one processed at a
time), which is appropriate for a single-core-default kernel; genuine parallel
processing (a worker pool) is a later step. Proven by `make smoke-fs-conc` (three
clients hammer the server concurrently, each verifying it receives only its own
replies).

**Crash resilience is done** (the atomicity core): every multi-block object-store
update runs inside a **write-ahead redo journal** (v5 on-disk layout) — the block
bitmap, inode, per-block crypto metadata, superblock `meta_hmac` and data all
commit together via an HMAC-authenticated journal header, then apply to their home
locations; a crash mid-update is completed (or discarded) by replay at the next
mount, so the filesystem is always fully before or fully after the operation. This
also closed a latent bug where a crash between a metadata-sector write and the
superblock write could desync `meta_hmac` and refuse to mount the whole volume.
The mount-time `fsck` reclaims both orphaned inodes and leaked data blocks. Proven
by `make smoke-fs-wal` (boot 1 commits a write then crashes before applying it;
boot 2 replays it and the data survives), alongside `smoke-fs` and
`smoke-fs-persist`.

**Large files are done:** double-indirect data blocks are implemented and the
volume is 4096 blocks (2 MiB), so a single file maps through the direct +
single-indirect + double-indirect range (up to 12 + 64 + 64×64 = 4172 blocks).
Proven by `make smoke-fs-large`, which also frees a ~130-block file in one journal
transaction (every freed block clears the same block-bitmap sector, so the writes
coalesce and the transaction stays well under the 16-sector journal limit — a
large-file free never overflows or aborts). This pass also fixed a latent
single-indirect fanout bug: the pointers-per-block count was 1024 instead of the
correct 64, which would have overrun a stack buffer for any file past block 76.

**The legacy capfs is gone:** the parallel in-memory capability filesystem
(`SYS_FS_*` 38–45, `fs_objects[]`, the `capfs_*` engine and its own at-rest AEAD)
has been removed — the syscalls fail closed, the numbers are reserved, and the
encrypted `fs_server` is the system's single filesystem. This shrinks the ring-3
attack surface to one, capability-mediated, permission-enforcing FS.

### Deliberate non-goals

- **Per-file ACLs — not adopted.** POSIX owner/group/other plus a `uid 0`
  superuser, enforced by the `fs_server` against the caller's kernel-attested
  identity, is a complete discretionary access-control model. Full ACLs would add
  a large, security-sensitive surface (on-disk ACL storage, evaluation, new proto
  ops) for no gain in what can be *expressed* securely with the existing model, so
  they are intentionally out of scope.
- **Multi-block allocation bitmaps — not adopted.** The single 512-byte bitmap
  block caps the volume at 4096 blocks, which the allocator already enforces
  safely (it never allocates past the cap). Growing the cap is a pure capacity
  feature with no security value; it is deferred rather than built.

---

## Phase 3 — SMP maturity

The SMP foundation is in place behind a build gate; this phase makes it
production-grade and default.

- **Default-on**: retire the `SMP=1` gate once the multi-core scheduler is
  hardened, so the shipped kernel uses every core.
- **Real per-CPU run queues**: replace the shared runnable pool with per-CPU
  queues plus explicit load-balancing/migration, and add scheduling priorities
  and fairness.
- **Finish retiring the cooperative switch** — *done*: boot of `init`, first
  entry of every task, `SYS_YIELD`, blocking IPC/`SYS_WAIT`, and preemption all
  use the full-context trap-frame path (`sched_enter_user` /
  `sched_yield_switch` / `ipc_block_switch` / `preempt_on_tick`). The legacy
  cooperative `schedule()`/`yield()` switch has been removed.
- **Concurrent-IPC correctness** — *done*: syscall handlers only set
  `pending_block`; `ipc_block_switch` writes `saved_ksp` first, barriers, then
  `ipc_publish_pending_block` publishes the waiter (endpoint / SYS_WAIT link /
  notification) so a cross-CPU wake always patches a valid trap frame. A reply
  that races into the mailbox before publish is consumed immediately.

---

## Phase 4 — Userspace ecosystem

With a libc and a heap in place, grow what runs on top.

- **Complete the libc surface**: `unlink()` is now wired end-to-end (libc
  `unlink` → `posix_unlink` → the `fs_server`'s permission-checked `FS_OP_DELETE`,
  with path resolution and `errno` mapping), and `stat()`/`fstat()` now report the
  file's real mode, uid and gid from the server instead of hardcoded `0644`/`0755`
  — both proven by `make smoke-newlib`. Wiring `unlink` also fixed a latent
  `posix.h`/newlib `O_*` flag-value mismatch that had silently dropped `O_CREAT`
  on the newlib `open()` path. `rename()` and `O_TRUNC`/`ftruncate()` are now
  wired too (new `FS_OP_RENAME` / `FS_OP_TRUNCATE` protocol ops, both
  permission-checked against the caller's attested uid; truncate zeroes the
  freed tail so a later grow can't read stale bytes) — the two BFD-critical file
  primitives, also proven by `make smoke-newlib`. Remaining for a real
  coreutils/binutils port: `getcwd`/`chdir`, an (empty) `environ`/`getenv`,
  `O_APPEND` honoured on write, `fcntl` (`F_GETFL`/`F_SETFL` no-ops), directory
  reads (`opendir`/`readdir` over `FS_OP_READDIR`), `mkstemp`/`tmpfile`, `link()`
  (needs hard-link/refcount support in the store, currently `ENOSYS`), and wiring
  signal delivery through `kill()` onto `SYS_SIGNAL` (blocked on the capability
  model — `SYS_SIGNAL` is `CAP_TCB`-gated, so a generic `kill(pid)` needs a
  pid→capability broker or a descendants-only restriction). The binding
  constraint beyond the libc surface is the 4 MiB userspace image window /
  1 MiB `MAX_PROGRAM_SIZE` (see the address-separation item in Phase 5) — a real
  binutils binary is several MB and does not fit until that is widened.
- **Port real programs**: bring up a subset of GNU coreutils/binutils against
  newlib now that `malloc`/`sbrk`/`brk` exist.
- **More servers**: a network-stack server, a block-device driver server, and a
  name server, each following the capability-delegation model.
- **`captest` expansion**: grow it into a comprehensive program exercising every
  syscall and every capability operation — usable as both a regression test and a
  demonstration.

---

## Phase 5 — Testing, verification and assurance

Cross-cutting work that should grow alongside every other phase.

- **Scripted integration harness**: beyond the boot smoke-test, drive scripted
  sessions (login, capability denials, W^X violations, IPC round-trips) and assert
  on the responses. *Seeded*: `make smoke-session` (`tools/session_test.py`) boots
  the shipped kernel and drives the **real** ring-3 shell over serial as a black
  box — asserting that a wrong password is rejected, the right one is accepted, the
  kernel-attested identity is what `whoami` reports, and a capability-gated admin
  op (`useradd`) is allowed for root but denied for a standard user (no ambient
  authority). Gated in CI. Remaining: broaden the scenarios (W^X violation, IPC/FS
  round-trips) and grow the assertion vocabulary.
- **Fuzzing**: coverage-guided fuzzing (libFuzzer or AFL++) of the syscall
  interface and the Rust FFI boundary.
- **Model checking**: TLC now checks three TLA+ specifications (`docs/cap_algebra.tla`
  subset-rights non-escalation, `docs/paging_isolation.tla` per-task frame isolation,
  `docs/cap_seqlock.tla` two-CPU seqlock no-torn-read) in CI (`tla` job). The next
  step is to extend them to cover IPC and the scheduler.
- **Formal verification**: apply Verus or Kani to the capability operations in
  `rust/src/capability.rs`.
- **User/kernel address separation**: the kernel is linked low (1 MiB) and its
  BSS extends past `USER_AREA_BASE` (4 MiB), so a task's low-memory mappings
  (image, heap) share virtual addresses with kernel data like `tasks[]`. Two
  interim guards are in place: image ASLR is pinned so the premap window can't
  reach the kernel globals (`choose_image_placement`), and the user heap is
  bounded below `kernel_lowmem_critical_floor()` (`h_sbrk`/`h_brk`). Residual
  gaps a determined program could still hit — the low user stack overlaps
  `kernel_stacks`, and a direct (non-`sbrk`) fault into the critical window isn't
  yet refused by the demand pager. The full fix is to move the user address space
  above the kernel image (or the kernel to the higher half) so no user mapping
  can ever shadow kernel state, which would also widen image-base ASLR entropy.

---

## Contributing

Phases 1 and 2 are complete. Phase 4 (userspace ecosystem) holds the most
self-contained items and is the recommended starting point for new contributors.
If you have kernel or systems experience and want something more involved, Phase
3 (SMP maturity) is a good target.

See [CONTRIBUTING.md](../CONTRIBUTING.md) for how to set up your environment and
submit work.
