# Horus Architecture

This document describes the design and internals of the Horus microkernel. It is intended for contributors wanting to understand the system before working on it, and for anyone evaluating the design.

---

## Design philosophy

Horus is built around one principle: **no ambient authority**. A task cannot access any resource — files, other tasks, devices, memory — unless it holds an explicit capability token granting that access. The kernel enforces this at every system call boundary.

The secondary goal is **verifiability**: the most security-sensitive operations (capability manipulation, memory reference counting, the cryptographic primitives, the W^X policy) are implemented in safe Rust, where the type system statically rules out whole classes of memory safety bugs.

Horus is a microkernel. The kernel handles only what must run in Ring 0: memory management, capability enforcement, task scheduling, interrupt handling, and a thin encrypted block/inode store. Filesystem *semantics* and device policy live in userspace, communicating via IPC — the filesystem is a ring-3 server (`userspace/fs_server.c`).

---

## Target hardware

Horus targets **x86-64** exclusively.

- The kernel runs in 64-bit long mode: PML4 paging, 48-bit virtual addresses, `mcmodel=kernel`.
- Bootloader: **Multiboot2** compatible (GRUB2).
- CPU features detected at runtime: SMEP, SMAP, AES-NI, SSE2/SSE4.2, TSC, RDRAND.
- Multi-core: application processors are brought up via the LAPIC (INIT-SIPI-SIPI), each with its own LAPIC-timer preemption tick, behind the `SMP=1` build gate. The single-core PIT path is the default.

The ring-3 userspace binaries are the only 32-bit component: they are static-PIE `EM_386` images run in a compatibility-mode code segment beneath the 64-bit kernel. (An earlier 32-bit kernel build target existed but was removed — the kernel has run exclusively in long mode for a long time.)

---

## Memory layout

### 64-bit virtual address space

| Region | Virtual address | Notes |
|---|---|---|
| Recursive PML4 | `0xFFFFFFFFFFFFF000` | Page table self-map slot 510 |
| Recursive PDPT | `0xFFFFFFFFFFE00000` | |
| Recursive PD | `0xFFFFFFFFC0000000` | |
| Recursive PT | `0xFFFFFF8000000000` | |
| User text | `0x0000000000400000` | 4 MB initial window (PIE base randomised within the low window) |
| User heap | `0x0000000001000000` | Grows upward via `sbrk`/`brk`, bounded below the kernel's low-memory critical data |

The kernel is linked low (1 MiB) and its BSS extends past `USER_AREA_BASE` (4 MiB), so a task's low-memory mappings share virtual addresses with kernel data like `tasks[]`. Two guards keep user mappings off the kernel globals: image ASLR is pinned so the premap window can't reach them (`choose_image_placement`), and the user heap is bounded below `kernel_lowmem_critical_floor()` (`h_sbrk`/`h_brk`). The full fix — moving the user address space above the kernel image — is tracked in [ROADMAP.md](ROADMAP.md).

### Physical memory

| Region | Physical address | Purpose |
|---|---|---|
| User page pool | `0x01000000` | 16,384 × 4 KB pages (64 MB) |
| Kernel stacks | allocated at init | 64 × 32 KB, one per task slot |

### Paging

The kernel uses **recursive page table mapping**: PML4 entry 510 points back at the page table root, giving a fixed virtual window to read/write any page table entry.

**Copy-on-write** is implemented at the page level. Shared pages are marked `PAGE_COW`. On the first write fault, `rust_handle_demand_page_fault()` allocates a fresh physical page, copies the content, and remaps the faulting address (preserving the page's NX bit). Physical pages carry reference counts maintained in Rust (`rust_page_ref_inc`, `rust_page_ref_dec`). The COW-copy-vs-demand-zero decision logic is unit-tested.

**W^X**: `EFER.NXE` is enabled at boot and the kernel uses the PTE NX bit (63) to keep writable pages non-executable. User stacks (low and high ASLR) are mapped no-execute. The ELF loader honours each `PT_LOAD` segment's `p_flags`, mapping code read+execute and data/rodata read[+write]+NX; the policy decision (`rust_user_page_is_noexec`) lives in Rust and is unit-tested. The shipped userspace binaries are static-PIE ELFs and take this path; a flat-binary fallback remains for non-ELF images (loaded at the fixed base, image left executable).

**ASLR**: per-spawn stack top, heap gap, **and image load base** are randomised from the CSPRNG. Userspace is built static-PIE (`ET_DYN`); `do_spawn` picks a random page-aligned base and `try_elf_load` applies `R_386_RELATIVE` relocations there (failing closed on any other relocation type). Image-base entropy is bounded (~9 bits) because userspace runs in 32-bit compatibility mode confined to the low ~8 MiB window; wider randomisation would require a 64-bit userspace ABI.

---

## Capability system

The capability system is the core security mechanism. All other security properties derive from it.

### What a capability is

A capability is an unforgeable token residing in a task's **capability node (CNode)**. Each CNode has 256 slots. Low slots are reserved for kernel-assigned capabilities (see the endowment table below); higher slots are available to userspace. All 256 slots are **zeroed to `CAP_NULL` when a task slot is allocated** (`create_task` in `scheduler.c`), so a reused slot cannot inherit the dead task's capabilities.

```c
typedef struct capability {
    uint32_t type;     /* CAP_TCB, CAP_FRAME, CAP_FILE, CAP_ENDPOINT, ... */
    uint32_t rights;   /* bitmask: READ | WRITE | EXEC | GRANT | MINT | REVOKE | ... */
    uint64_t object;   /* identifies the governed object */
    uint32_t badge;    /* parent serial, used for revocation tracking */
    uint32_t serial;   /* unique per capability instance */
} capability_t;
```

### Capability types

| Type | Value | Governs |
|---|---|---|
| `CAP_NULL` | 0 | empty slot |
| `CAP_TCB` | 1 | a task (kill / signal / grant-into) |
| `CAP_NOTIFICATION` | 2 | a notification object |
| `CAP_ENDPOINT` | 3 | an IPC endpoint |
| `CAP_FRAME` | 4 | a physical frame |
| `CAP_USER` | 6 | admin authority over the user database |
| `CAP_AUDIT` | 7 | the audit log |
| `CAP_CONSOLE` | 8 | the console |
| `CAP_ENCRYPTED_STORAGE` | 9 | the file master key |
| `CAP_REVOCATION` | 10 | a revocation object |
| `CAP_BLOCK_DEV` | 11 | the raw block / encrypted object store |
| `CAP_DIR` / `CAP_FILE` | 12 / 13 | *reserved* — the legacy capfs directory / file objects they governed have been removed |

### Rights bitmask

| Right | Bit | Meaning |
|---|---|---|
| `CAP_RIGHT_READ` | `0x001` | Read the object |
| `CAP_RIGHT_WRITE` | `0x002` | Write to the object |
| `CAP_RIGHT_EXEC` | `0x004` | Execute or invoke |
| `CAP_RIGHT_GRANT` | `0x008` | Transfer a copy to another task |
| `CAP_RIGHT_MINT` | `0x010` | Derive a new capability with a subset of rights |
| `CAP_RIGHT_REVOKE` | `0x020` | Revoke this and all derived capabilities |
| `CAP_RIGHT_AUDIT_WRITE` | `0x040` | Append to the audit log |
| `CAP_RIGHT_FS_*` | `0x400+` | *reserved* — the legacy capfs rights (`LOOKUP`, `CREATE`, `DELETE`, `READ`, `WRITE`); no longer used now that capfs is removed |

### Capability operations

All capability operations live in `rust/src/capability.rs` (safe Rust) and are called from the C kernel over FFI.

| Operation | Effect |
|---|---|
| **Mint** | Creates a derived capability with a subset of the parent's rights. The new capability records the parent's serial as its badge. |
| **Transfer** | Copies a capability into another task's CNode with the same rights. |
| **Move** | Transfer, then immediately nullify the source slot. |
| **Grant** (`SYS_CAP_GRANT`) | A supervisor that holds a child's `CAP_TCB` copies one of its own cap slots into a chosen slot of that child's cspace — least-privilege delegation at spawn time. |
| **Revoke** | System-wide. `rust_cap_revoke_global` nullifies the target capability, then sweeps **every live task's CNode plus the kernel root cnode**, nullifying any capability whose serial/badge/object matches the revoked lineage, and bumps the lineage generation counter exactly once. |

### Revocation and lineage

Revocation is **complete, not caller-local**: the C wrapper `cap_revoke` (under `cap_lock`) builds the list of all live cspaces and passes it to `rust_cap_revoke_global`, which performs the entire sweep inside one Rust call. A derived capability copied into another task's CNode is therefore revoked together with its parent — there is no window in which another task retains access after revocation.

The system additionally prevents use-after-revoke via a **lineage table** (`LINEAGE_SLOTS` = 4,096 entries). Each entry is a generation counter, and the Rust table is the single source of truth. When a capability is minted it records the current generation for its lineage slot; at use time `rust_cap_lookup` checks whether the stored generation still matches. A revocation bumps the counter, so even a stale bit pattern that escaped the structural sweep fails the generation check immediately. The structural sweep and the generation bump are defence-in-depth for the same invariant.

**Primordial capabilities** — root capabilities assigned at boot, identified by the `0xC0DE` serial prefix — cannot be revoked. A serial-range check in the Rust revocation path enforces this.

---

## Task model

Horus supports up to 64 concurrent tasks. Each task has:

- A **Task Control Block (TCB)** with a saved trap frame / register state (`rip`, `rsp`, `cr3`, `saved_ksp`)
- A **capability node** (256 slots)
- A dedicated **kernel stack** (32 KB) used during syscall and interrupt handling
- A **user heap** tracked by `heap_start`, `heap_current`, `heap_end`
- A **UID and GID** login identity establishing its authentication context, which the kernel attests to servers (via `SYS_IPC_SENDER`) so a ring-3 filesystem can enforce ownership a client cannot forge
- A **signal handler** (`SYS_SIGACTION`) and a `pending_sig` slot for async delivery

A task's state is one of `TASK_DEAD` (0), `TASK_RUNNABLE` (1), `TASK_BLOCKED_IPC` (2), `TASK_BLOCKED_NOTIF` (3), or `TASK_BLOCKED_WAIT` (4).

### Scheduling

The scheduler is preemptive round-robin. The PIT fires at 100 Hz (BSP); under `SMP=1` each application processor runs its own LAPIC-timer tick. On a tick that interrupted **ring 3**, the timer ISR switches to the next runnable task by swapping the per-task kernel stack that holds its full interrupt trap frame — `preempt_on_tick` returns the kernel `%rsp` to resume on, and the ISR epilogue `iretq`s into it. A freshly spawned task gets a fabricated initial frame (`sched_prepare_user_context`) so the timer (or a block/switch) can `iretq` into it at its entry point. A tick that lands in **ring 0** (mid syscall or handler) never switches — the kernel is effectively non-preemptible, which sidesteps lock/reentrancy hazards.

**Blocking** (a blocking `SYS_IPC_CALL`, `SYS_WAIT_NOTIFY`, or `SYS_WAIT`) uses the *same* full-context mechanism: the handler marks the task blocked and returns, and the `int 0x80` epilogue saves its trap frame and switches to the next runnable task via `ipc_block_switch`. When the blocking condition clears (a reply arrives, or a target task's `task_teardown` wakes a `SYS_WAIT` waiter — on a clean exit **or** a fault), the task is made runnable again and resumes via its saved frame.

There is a single context-switch path: every task enters and resumes via a full interrupt trap frame on its kernel stack (`sched_prepare_user_context` at spawn, `sched_enter_user` for first entry / boot of `init`, timer preemption, `ipc_block_switch` for blocking syscalls, `sched_yield_switch` for `SYS_YIELD`). The legacy cooperative `yield()`/`schedule()` switch (which swapped CR3/current but returned on the caller's own kernel stack) has been deleted. Multi-core scheduling shares a single runnable pool with a per-CPU pull under a raw scheduler lock; per-CPU run queues and priorities are future work.

### Process control (ring-3, Phase 1)

Tasks are first-class from ring 3. A task can `SYS_SPAWN` a named embedded binary (the load runs in the kernel address space; the caller receives the child's `CAP_TCB`), replace its own image in place with `SYS_EXEC_NAMED` (same pid and cspace), delegate a capability into a supervised child with `SYS_CAP_GRANT`, terminate itself (`SYS_EXIT`) or a task it holds a `CAP_TCB` for (`SYS_KILL`), and block until another task exits (`SYS_WAIT`). Both spawn and exec take a full `argv`: the kernel copies the vector out of the caller's address space and lays the strings + a NULL-terminated pointer array on the child's initial stack, which the child reads back with `SYS_GET_ARGV`.

A ring-3 **`init` (PID 1)** launches at boot. The kernel endows it with `CAP_AUDIT` plus the `CAP_CONSOLE` and `CAP_ENCRYPTED_STORAGE` it hands to the shell. `init` spawns the shell, delegates those two caps with `SYS_CAP_GRANT` (authorised by the shell's `CAP_TCB` it holds from the spawn), and then **blocks in `SYS_WAIT`** on the shell — consuming no CPU while the shell runs — relaunching it if it ever exits or faults.

### Signals

A task registers its own handler with `SYS_SIGACTION`. Two delivery paths share it:

- **Fault signals.** When the task faults in ring 3 (a page fault or a CPU exception such as `#UD`), `try_deliver_fault_signal` (`idt.c`) — instead of killing it — saves the full trap frame in the TCB and rewrites the live frame to enter the handler at ring 3, passing the signal number in `ebx` and the faulting address in `ecx`. `SYS_SIGRETURN` (serviced directly in `interrupt_handler64`) restores the saved context for an exact resume.
- **Async task-to-task signals** (`SYS_SIGNAL`, gated on a `CAP_TCB` to the target — same authority as `SYS_KILL`). The sender queues `pending_sig`; the target is redirected into its handler on its next return to ring 3 (reusing the fault-signal path). An unhandled signal, or the uncatchable `SIG_KILL`, takes the default terminate action.

Pending signals are held in a full 1..31 bitmask, and `SYS_SIGMASK` blocks/unblocks signals (`SIG_KILL` excepted); `deliver_pending_signal` delivers the lowest-numbered *unmasked* pending signal, and a masked one stays queued until unblocked. A signal to a task parked in `SYS_WAIT` interrupts the wait (it returns `SYS_ERR_INTR`) and is delivered promptly rather than waiting on the awaited task.

The handler entry is validated to the user code window in safe Rust (`rust_signal_handler_addr_ok`), a fault *inside* a handler is not re-delivered (the `in_signal` guard prevents loops), and the handler runs at ring 3 with unchanged privileges — so signals add recovery/notification without granting any new authority. `SYS_SIGALTSTACK` registers an alternate signal stack: a signal delivered while the task is not already on it enters the handler on `[ss_sp, ss_sp+ss_size)` (`SS_ONSTACK`), so a corrupt or overflowed primary stack cannot stop the handler running; the alternate stack is cleared on `SYS_SIGRETURN`.

---

## IPC

IPC is endpoint-based. The kernel maintains 64 endpoints. A sending task writes a message to an endpoint; a task waiting on that endpoint receives it. Messages carry a small payload (up to 256 bytes) and a sender badge.

Each endpoint is a **single-slot mailbox**. `SYS_IPC_SEND`/`SYS_IPC_RECV` are **non-blocking** (they return a would-block code rather than spinning), so a userspace peer polls from ring 3 where the timer interleaves it with the other party. `SYS_IPC_CALL` may block the caller (`TASK_BLOCKED_IPC`) on the full-context block/switch path and is resumed when the reply arrives. This is enough for one in-flight request at a time; concurrent multi-client IPC with reply routing is future work. A snapshot + revalidate-at-use guard closes a lookup/use TOCTOU window across the send/recv paths.

**Block/wake publish order (SMP-safe):** the syscall handler only records a `pending_block` intent. `ipc_block_switch` then (1) stores the live trap frame in `saved_ksp`, (2) issues a full memory barrier, and (3) publishes the waiter under the IPC lock (`blocked_waiter` / `SYS_WAIT` link / notif waiter + `TASK_BLOCKED_*`). A notifier on another core therefore never patches a null or stale frame. If the event already arrived (reply in the mailbox, target already dead, badge pending), publish completes the wait immediately and resumes the same task.

**Notifications** (`SYS_NOTIFY`/`SYS_WAIT_NOTIFY`) complement endpoints with an async, badge-carrying signal. `SYS_NOTIFY` ORs a 32-bit badge into one of `MAX_NOTIFICATIONS` slots and, if a task is blocked waiting on that slot, wakes it — patching the accumulated badge into the waiter's saved trap frame (`rbx`) so no cross-address-space copy is needed; otherwise the badge accumulates until the next wait. `SYS_WAIT_NOTIFY` returns a pending badge immediately, or blocks via the same full-context path as IPC/`SYS_WAIT` (the badge comes back in `ebx`). Proven end-to-end by `make smoke-notify`.

### Userspace filesystem server

Filesystem *semantics* run in a ring-3 server (`userspace/fs_server.c`), which is the system's **single** filesystem and its reference monitor. The kernel provides only a **persistent, encrypted object store** — inode allocation and per-(inode, block) AEAD I/O via syscalls 56–61 (`SYS_FS_INODE_ALLOC`/`_FREE`, `SYS_FBLOCK_READ`/`_WRITE`, `SYS_FS_STAT`, `SYS_FS_SET_SIZE`) plus owner/mode persistence (`SYS_FS_SET_META`, 74), gated on `CAP_BLOCK_DEV` + uid 0. Encryption keys never leave the kernel TCB. The server builds directories (as inode data; root = inode 0), path resolution, and file sizes on top, and answers clients over IPC using the protocol in `include/fs_proto.h` (requests on endpoint 4, each client's reply-wait on 5). The block store (`storage.c`) probes for an ATA disk at boot and uses the encrypted ATA backend when one is present (files and per-block crypto metadata survive reboot; the volume is sealed until login), falling back to an ephemeral RAM vdisk when none is attached.

The server enforces **per-file POSIX owner/group/other rwx and ownership** against the caller's *kernel-attested* identity — `SYS_IPC_SENDER` returns the sending task's login uid/gid, which a client cannot forge or place in the request — with root (uid 0) the only ambient authority (`chmod` is owner-or-root, `chown` is root-only). It serves **multiple clients concurrently**: it replies with `SYS_IPC_REPLY_TO`, which routes each reply directly into the requesting client's blocked `SYS_IPC_CALL` by kernel-recorded sender, never via a shared reply endpoint another client could observe (requests still serialise one at a time). Every multi-block update is **crash-atomic** via a write-ahead redo journal (v5 on-disk format) with an HMAC-authenticated header, replayed at the next mount, and a mount-time `fsck` reclaims orphaned inodes and leaked blocks. Files map through direct + single-indirect + double-indirect blocks (up to 12 + 64 + 64×64 = 4172 blocks; the volume is 4096 blocks / 2 MiB). Proven end-to-end by `make smoke-fs`, `smoke-fs-persist`, `smoke-fs-perms`, `smoke-fs-conc`, `smoke-fs-wal`, and `smoke-fs-large`.

The earlier parallel **in-memory capfs** (`SYS_FS_*`, syscalls 38–45) has been **removed** — its engine and objects are gone, the syscall numbers fail closed and are reserved — leaving the encrypted `fs_server` as the one capability-mediated, permission-enforcing filesystem.

---

## Symmetric multiprocessing

Behind the `SMP=1` build gate, Horus brings up the application processors and runs scheduled tasks across cores:

- **AP bringup** via the LAPIC INIT-SIPI-SIPI sequence; each AP sets up long mode, its GDT/TSS/IDT, and enters the scheduler.
- **Per-CPU preemption** from the LAPIC timer (the legacy PIC IRQ0 only reaches the BSP); a shared runnable pool with a per-CPU pull under a raw scheduler lock is the load-balancing mechanism.
- **IPC + notification locking** so cross-CPU sends/receives serialise correctly.
- **TLB-shootdown IPIs** with acknowledgement, so a CPU that changes a shared mapping flushes the others' TLBs before proceeding.

The BSP is never pulled out of its ring-0 idle/kernel context by the timer, preserving the exact single-CPU boot flow; the APs do the multi-core work. Proven by `make smoke-smp`. Per-CPU run queues, priorities, and default-on multi-core are Phase 3 roadmap items.

---

## Syscall interface

Syscalls use `int 0x80`. The syscall number is in `eax`; arguments in `ebx, ecx, edx, esi, edi`. Numbers run `SYS_YIELD` = 0 through `SYS_IPC_REPLY_TO` = 75. See [SYSCALLS.md](SYSCALLS.md) for the per-syscall reference.

Dispatch is **table-driven**: `syscall_handler` indexes a `syscall_table[]` of descriptors `{ handler, slot, rights, type }`, validates the number, and — for syscalls whose authority is a single fixed capability — enforces that capability in one central place before calling the handler. A number with no entry fails closed. A `_Static_assert` pins the table size to the highest syscall number + 1, so a syscall cannot be added without a table slot. Syscalls with dynamic or self-authorising policy (the capability ops, the FS ops, auth/sudo, user management, kill/signal/grant) carry no fixed slot and authorise inside their handler.

Broad categories: **core/process** (yield, exit, get_line, sbrk/brk, read/write/open, wait, get_task_info, exec); **process control** (spawn, exec_named, spawn_image/exec_image, kill, cap_grant, signal, spawn_arg/get_argv); **IPC** (send/recv/call/reply, sender, reply_to; notify/wait_notify deliver async badges); **auth & audit** (getuid, auth, sudo, passwd, useradd/del, read_audit, audit_digest); **signals** (sigaction, sigreturn, sigmask, sigaltstack); **capabilities** (mint/transfer/move raw-numbered, revoke); **filesystem** (encrypted object store 56–61 + set_meta 74; capfs 38–45 removed/fail-closed); **block storage & server registration** (47–50; 46 removed/fails-closed). Numbers 1/`SYS_PRINT` and 20/`SYS_GETPID` are defined but not dispatched.

---

## User authentication and audit

### User database

Up to 32 users are stored in a kernel-managed table, serialised to the RAM filesystem as a `passwd` file. Each entry holds: username, UID, GID, home directory path, shell path, a random per-user salt, a password hash, and an authentication failure counter. The serialised table is authenticated with an HMAC-SHA256 tag keyed by the per-boot pepper. The default accounts are `root`/`rootpass` and `user`/`password`; password changes persist across reboots.

Password hashing is **Argon2id** (RFC 9106) — the memory-hard KDF — implemented from scratch in safe Rust (`rust/src/argon2.rs`) on the crate's own BLAKE2b (`rust/src/blake2b.rs`) and validated against the `argon2-cffi` reference vectors. It hashes the password with the per-user random salt and a per-boot secret pepper folded in; the raw 32-byte tag is stored. The implementation is multi-lane (`p ≥ 1`, validated against p=2/p=4 vectors); the cost profile (`m`, `t`, `p`) is set by `ARGON2_M_COST_KIB` / `ARGON2_T_COST` / `ARGON2_P_COST` in `kernel.h`, and the kernel runs 4 MiB / 3 passes / 1 lane. The fill buffer is a kernel static (no allocator); hashing runs non-preemptibly inside the syscall, so one shared buffer is safe. Verification runs in constant time and is equalised so a missing username cannot be distinguished by timing. Lockout arithmetic and a global anti-spray throttle live in `rust/src/auth.rs`.

### Audit log

The kernel maintains a 256-entry circular buffer. Each event records: event type, TSC timestamp, subject UID, object identifier, and result code. Types include authentication, sudo, user management, capability operations, file access, IPC, and filesystem events. The log is readable via `SYS_READ_AUDIT`.

The log is **tamper-evident**. Each entry is bound by `mac = HMAC(pepper, LE64(seq) || event)` (the sequence number defeats slot swaps and replays) and a running chain head advances as `head = HMAC(pepper, head || mac)`, committing to the whole ordered history — including entries the ring has already overwritten. The keyed-hash logic lives in safe Rust (`rust/src/audit.rs`); the C side owns the ring storage and seeds the chain in `users_init` as soon as the pepper exists. `SYS_AUDIT_DIGEST` returns the total event count, the current chain-head MAC, and a constant-time verify status of the retained window. This is an integrity detector keyed to a secret the log's readers do not hold — not a guarantee against an attacker who has already compromised the kernel and can read the pepper.

---

## Rust integration

The Rust crate at `rust/` compiles to a static library (`libhorus_shell.a`) linked into the kernel. It is a `no_std` crate — no allocator, no OS dependencies. Data crosses the C/Rust boundary as raw pointers and integers via the FFI shims in `src/kernel/rust_memory_stubs.c`.

| Module | Role |
|---|---|
| `capability.rs` | Capability mint, transfer, move, revoke, and lineage management |
| `memory.rs` | Physical page reference counting and validation |
| `lib.rs` | Page-fault validation, demand-paging decisions, W^X page policy (`rust_user_page_is_noexec`), signal-handler-address window, command token parsing |
| `sha256.rs` | SHA-256, HMAC-SHA256, HKDF-SHA256, PBKDF2-HMAC-SHA256 |
| `blake2b.rs` | BLAKE2b (RFC 7693) — the hash primitive under Argon2id |
| `argon2.rs` | Argon2id (RFC 9106) memory-hard password hashing |
| `rng.rs` | ChaCha20 fast-key-erasure CSPRNG; RDRAND + timing-jitter seeding |
| `aead.rs` | ChaCha20 + HMAC-SHA256 Encrypt-then-MAC AEAD (used by the block-storage layer for encryption-at-rest) |
| `audit.rs` | Tamper-evident audit log: per-entry HMAC (sequence-bound) + running hash-chain head |
| `auth.rs` | Auth/sudo lockout + anti-spray throttle; least-privilege sudo frame rights |
| `ps.rs` | Task state-name labels for the `ps` renderers |
| `crypto.rs` | Intentionally empty — the primitives live in the modules above |

The Rust code is safe Rust internally: the crate contains no `unsafe` blocks in its logic. The one unavoidable `unsafe` is the FFI boundary itself — the `rust_*` entry points the C kernel calls are `unsafe extern "C"` functions because they dereference C-supplied raw pointers. Each carries a documented `# Safety` contract, validates its arguments (null and length checks, fail-closed on bad input), and copies through fixed-size local buffers rather than trusting caller bounds. So the *surface* is the whole FFI API, but the *risk* is confined to those thin, contract-checked shims; all computation behind them is safe Rust.

---

## Reproducible builds

The build system sets `SOURCE_DATE_EPOCH=1609459200` (2021-01-01 UTC) and passes `-frandom-seed=horus` to GCC. The linker is invoked with `--build-id=none`. The Rust build uses `--locked`, `opt-level=z`, `lto=true`, and `codegen-units=1`. The result is a byte-for-byte identical `kernel.elf` across clean builds on the same toolchain version. `make reproducible-build` builds twice and diffs; reference checksums are recorded in `.build.sha` (and the historical `.build1.sha`/`.build2.sha`).

---

## Security properties

### What the design provides

- **No ambient authority** — a task cannot access a resource it does not hold a capability for, regardless of UID
- **Transitive revocation** — revoking a capability immediately invalidates all capabilities derived from it, across all tasks
- **Use-after-revoke prevention** — lineage generations make a revoked capability slot invalid even if its bit pattern is retained
- **Least-privilege delegation** — a supervisor grants a child exactly the caps it needs (`SYS_CAP_GRANT`); kill/signal are gated on holding the child's `CAP_TCB`
- **Primordial capability protection** — system-critical root capabilities cannot be revoked by any userspace path
- **Hardware user/kernel isolation** — Ring 0 / Ring 3 boundary; SMEP/SMAP enabled when advertised
- **W^X for user memory** — stacks are non-executable and ELF segments honour their `p_flags`
- **Centralised syscall authorisation** — one table-driven choke point; an unlisted syscall number fails closed
- **Signals grant no new authority** — a handler runs at ring 3 with unchanged privileges; async signalling requires a `CAP_TCB` on the target

### What the design does not yet provide

See [SECURITY.md](../SECURITY.md#known-limitations--current-status) for detail. Key gaps: IPC endpoints are single-slot mailboxes (one in-flight request; `fs_server` reply routing is layered on top via `SYS_IPC_REPLY_TO`, and async badge notifications `SYS_NOTIFY`/`SYS_WAIT_NOTIFY` work); SMP works behind a build gate but is not default-on and has no per-CPU run queues, priorities, or flush-on-switch between time-sliced tasks; and image-base ASLR entropy is bounded by the 32-bit low-memory window. (The filesystem is now persistent, multi-client, permission-enforcing, and crash-atomic — see the current-status filesystem note for the residual operational limits.)
