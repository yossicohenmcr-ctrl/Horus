# Horus Roadmap

This document describes where Horus is **headed** — the work still ahead. For what
already exists, see the [status table](../README.md#status-at-a-glance) in the
README, the [current-status breakdown](../SECURITY.md#known-limitations--current-status)
in SECURITY.md, and the [CHANGELOG](../CHANGELOG.md).

The phases are roughly ordered by dependency and priority, but they are largely
independent and can be picked up in any order. Nothing here is a commitment —
priorities shift as contributors join and the design evolves. If you want to work
on something, open an issue or start a discussion first; coordination saves effort.

---

## Completed foundations

- **Phase 1 — Process lifecycle and control** *(complete)*. Ring-3 `init` (PID 1)
  supervision; `SYS_SPAWN`/`SYS_EXEC_NAMED`/`SYS_SPAWN_IMAGE`/`SYS_EXEC_IMAGE`
  (execve-from-fd); `SYS_CAP_GRANT` delegation; `SYS_KILL`/`SYS_EXIT`/`SYS_WAIT`;
  async signals with masking (`SYS_SIGMASK`) and alternate stacks
  (`SYS_SIGALTSTACK`); full `argv` marshalling. `fork` was deliberately *not*
  adopted — the ring-3 spawn + grant model gives create-a-task-and-endow-it
  without fork's whole-address-space aliasing and least-privilege problems. Proven
  by `make smoke-proc`.
- **Phase 2 — A production filesystem** *(complete)*. The ring-3 `fs_server` over
  an encrypted object store is the system's single filesystem: persistent by
  default on ATA, per-file POSIX ownership/permissions against a kernel-attested
  identity, multi-client concurrency via `SYS_IPC_REPLY_TO`, crash-atomic via an
  HMAC-authenticated write-ahead redo journal, and large files through
  double-indirect blocks. The legacy in-memory capfs was removed. Proven by the
  `smoke-fs*` suite.

Both phases' detail is in the [CHANGELOG](../CHANGELOG.md); the two deliberate
non-goals carried forward from Phase 2 are below.

### Deliberate non-goals (filesystem)

- **Per-file ACLs — not adopted.** POSIX owner/group/other plus a `uid 0`
  superuser, enforced against the caller's kernel-attested identity, is a complete
  discretionary access-control model. Full ACLs would add a large,
  security-sensitive surface (on-disk storage, evaluation, new proto ops) for no
  gain in what can be *expressed* securely, so they are out of scope.
- **Multi-block allocation bitmaps — not adopted.** The single 512-byte bitmap
  block caps the volume at 4096 blocks (2 MiB), which the allocator enforces
  safely. Growing the cap is a pure capacity feature with no security value; it is
  deferred rather than built.

---

## Phase 3 — SMP maturity

The SMP foundation is in place behind a build gate; this phase makes it
production-grade and default. The lock-free capability read path is already
SMP-safe (the model-checked `cap_seq` seqlock) and the cooperative scheduler is
already retired — every entry point uses the full-context trap-frame path — so the
remaining work is scheduler quality, not correctness:

- **Default-on**: retire the `SMP=1` gate once the multi-core scheduler is
  hardened, so the shipped kernel uses every core.
- **Real per-CPU run queues**: replace the shared runnable pool with per-CPU
  queues plus explicit load-balancing/migration, and add scheduling priorities
  and fairness.
- **Microarchitectural flush-on-switch**: flush or partition shared state
  (L1D, BTB) on a context switch between mutually distrusting tasks.

---

## Phase 4 — Userspace ecosystem

With a libc and a heap in place, grow what runs on top.

- **Complete the libc surface**: `unlink`, `stat`/`fstat` (real mode/uid/gid),
  `rename`, and `O_TRUNC`/`ftruncate` are wired end-to-end and permission-checked
  (`make smoke-newlib`). Remaining for a real coreutils/binutils port:
  `getcwd`/`chdir`, an (empty) `environ`/`getenv`, `O_APPEND` on write, `fcntl`
  (`F_GETFL`/`F_SETFL` no-ops), directory reads (`opendir`/`readdir` over
  `FS_OP_READDIR`), `mkstemp`/`tmpfile`, `link()` (needs hard-link/refcount
  support in the store, currently `ENOSYS`), and wiring `kill()` onto `SYS_SIGNAL`
  (blocked on the capability model — `SYS_SIGNAL` is `CAP_TCB`-gated, so a generic
  `kill(pid)` needs a pid→capability broker or a descendants-only restriction).
  The binding constraint beyond the libc surface is the 4 MiB userspace image
  window / 1 MiB `MAX_PROGRAM_SIZE` (see the address-separation item in Phase 5) —
  a real binutils binary is several MB and does not fit until that is widened.
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

- **Scripted integration harness**: `make smoke-session` (`tools/session_test.py`)
  drives the real ring-3 shell over serial and is CI-gated. Remaining: broaden the
  scenarios (a W^X violation, IPC/FS round-trips, a capability revocation) and grow
  the assertion vocabulary.
- **Fuzzing**: the FFI boundary already has a zero-dependency property/differential
  fuzz harness in CI. The next step is coverage-guided fuzzing (libFuzzer or AFL++)
  of the syscall interface and the Rust FFI boundary — which needs third-party
  crates and a nightly toolchain, so it lives *outside* the zero-dependency crate.
- **Model checking**: TLC checks five TLA+ specs in the `tla` job
  (`docs/cap_algebra.tla` subset-rights non-escalation, `docs/paging_isolation.tla`
  per-task frame isolation, `docs/cap_seqlock.tla` two-CPU seqlock no-torn-read,
  `docs/ipc_toctou.tla` IPC lookup/use no-use-after-revoke, `docs/sched_smp.tla`
  SMP run-pool no-double-run), each with a falsification switch. The next step is
  to extend the specs to the notification/wait paths and to model liveness (no lost
  wakeup), not just safety.
- **Formal verification**: apply Verus or Kani to the capability operations in
  `rust/src/capability.rs`.
- **User/kernel address separation**: the kernel is linked low (1 MiB) and its BSS
  extends past `USER_AREA_BASE` (4 MiB), so a task's low-memory mappings share
  virtual addresses with kernel data like `tasks[]`. Two interim guards are in
  place (image ASLR pinned away from the kernel globals; the user heap bounded
  below `kernel_lowmem_critical_floor()`), but residual gaps remain — the low user
  stack overlaps `kernel_stacks`, and a direct (non-`sbrk`) fault into the critical
  window isn't yet refused by the demand pager. The full fix is to move the user
  address space above the kernel image (or the kernel to the higher half), which
  would also widen image-base ASLR entropy.

---

## Contributing

Phases 1 and 2 are complete. Phase 4 (userspace ecosystem) holds the most
self-contained items and is the recommended starting point for new contributors.
If you have kernel or systems experience and want something more involved, Phase 3
(SMP maturity) is a good target.

See [CONTRIBUTING.md](../CONTRIBUTING.md) for how to set up your environment and
submit work.
