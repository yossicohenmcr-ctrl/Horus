<div align="center">

# Horus

**A capability-based microkernel with a safe-Rust security core.**

[![CI](https://github.com/yossicohenmcr-ctrl/Horus/actions/workflows/ci.yml/badge.svg)](https://github.com/yossicohenmcr-ctrl/Horus/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-informational.svg)](LICENSE)
[![Platform: x86-64](https://img.shields.io/badge/platform-x86--64-blue.svg)](docs/ARCHITECTURE.md)
[![Language: C + Rust](https://img.shields.io/badge/language-C%20%2B%20Rust-orange.svg)](docs/ARCHITECTURE.md)
[![Reproducible build](https://img.shields.io/badge/build-reproducible-success.svg)](docs/BUILDING.md)

[Architecture](docs/ARCHITECTURE.md) ·
[Security](SECURITY.md) ·
[Syscalls](docs/SYSCALLS.md) ·
[Building](docs/BUILDING.md) ·
[Limitations](docs/LIMITATIONS.md) ·
[Roadmap](docs/ROADMAP.md)

</div>

---

## Overview

Horus is an x86-64 microkernel that treats the **capability token** as its single, foundational security primitive. Every privileged operation — file access, IPC, task creation, signalling, device I/O — requires an explicit, unforgeable capability. Capabilities can be minted with reduced rights, delegated between tasks, and revoked instantly and transitively across the entire system.

The kernel is written in C. The security-critical core — the capability engine, physical-memory reference counting, the cryptographic primitives, the W^X page policy, and every FFI validation boundary — is implemented in **safe, `no_std` Rust**, where the type system statically rules out entire classes of memory-safety defects.

Horus is engineered as if it were destined for production even though it is not one: every change is gated by a CI pipeline that runs the unit-test suite, a linter with all warnings denied, a byte-for-byte **reproducible-build** check, **six headless QEMU self-tests**, and a supply-chain security scan with an SBOM.

> ### Project status — research / early development
> Horus boots, runs a ring-3 `init` that supervises a ring-3 shell, and enforces capability-based access control end to end. It has preemptive scheduling, a userspace filesystem server over an encrypted object store — persistent when an ATA disk is present, enforcing per-file POSIX ownership/permissions against a kernel-attested identity, serving multiple clients concurrently, and crash-atomic via a write-ahead journal — a newlib libc port, ring-3 process control (spawn/exec/kill/signal/wait, including masking and alternate stacks), and multi-core support behind a build gate. Some subsystems (SMP default-on, multi-slot IPC) are deliberately scaffolded rather than finished. This is a research and learning kernel, not a shipping OS. [docs/LIMITATIONS.md](docs/LIMITATIONS.md) is a candid, subsystem-by-subsystem account of exactly where the line sits.

---

## Why Horus

| Principle | How Horus applies it |
|---|---|
| **No ambient authority** | Access derives solely from held capabilities — never from UID, task identity, or global state. A task with no capability for an object cannot name it. |
| **Least privilege by construction** | Capabilities are minted with a *subset* of rights; a spawned task receives only the TCB, frame, and endpoints it needs — never the admin, block-device, or console capabilities. A parent delegates one slot at a time (`SYS_CAP_GRANT`) into a child it supervises. |
| **Verifiable core** | Security-sensitive logic lives in safe Rust with unit tests and known-answer cryptographic vectors; the C/Rust ABI is pinned by mirrored compile-time assertions. |
| **Defence in depth** | Hardware isolation (SMEP/SMAP, W^X/NX), a single centralized syscall-authorization choke point, transitive revocation, and a tamper-evident audit log reinforce one another. |
| **Provenance you can trust** | Reproducible builds and a first-party-only CI supply chain mean a released `kernel.elf` can be independently reproduced bit-for-bit. |

---

## Architecture

```
 ┌──────────────────────────────────────────────────────────┐
 │                   Userspace  (Ring 3)                    │
 │   init → shell     fs_server     hello     captest       │
 └──────────────────────┬───────────────────────────────────┘
                        │  syscalls (0-75, table-dispatched)
 ┌──────────────────────▼───────────────────────────────────┐
 │                  Horus Kernel  (Ring 0)                  │
 │                                                          │
 │  ┌────────────┐  ┌────────────┐  ┌─────────────────┐     │
 │  │ Capability │  │  Paging /  │  │  Scheduler /    │     │
 │  │  Engine    │  │  Memory    │  │  Task + Signals │     │
 │  └────────────┘  └────────────┘  └─────────────────┘     │
 │  ┌────────────┐  ┌────────────┐  ┌─────────────────┐     │
 │  │  Syscall   │  │  IPC /     │  │  Auth / Audit   │     │
 │  │  Dispatch  │  │  Endpoints │  │  (tamper-evid.) │     │
 │  └────────────┘  └────────────┘  └─────────────────┘     │
 │                                                          │
 │  ┌────────────────────────────────────────────────────┐  │
 │  │        Rust Security Core  (no_std, safe Rust)     │  │
 │  │  capability.rs  memory.rs  lib.rs (W^X)  ps.rs     │  │
 │  │  sha256.rs  blake2b.rs  argon2.rs  rng.rs          │  │
 │  │  aead.rs  auth.rs  audit.rs                        │  │
 │  └────────────────────────────────────────────────────┘  │
 │                                                          │
 │  ┌────────────┐  ┌────────────┐  ┌─────────────────┐     │
 │  │  Terminal  │  │  GDT / IDT │  │  ATA / RAM      │     │
 │  │  / Serial  │  │ / TSS/APIC │  │  block store    │     │
 │  └────────────┘  └────────────┘  └─────────────────┘     │
 └──────────────────────┬───────────────────────────────────┘
                        │
 ┌──────────────────────▼───────────────────────────────────┐
 │            Hardware  (x86-64, 1..N cores)                │
 └──────────────────────────────────────────────────────────┘
```

The kernel runs in 64-bit long mode. Ring-3 userspace binaries are the sole 32-bit component (static-PIE `EM_386` images run in compatibility mode). See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full design.

---

## Capabilities & security at a glance

- **Transitive, system-wide revocation.** Revoking a capability nullifies it and every derived copy across every task's cspace *and* the kernel root cnode in a single atomic Rust sweep, then bumps a lineage generation counter — so a stale bit pattern that escaped the structural sweep still fails at point of use. Task slots are **zeroed on reuse**, so a newly spawned task cannot inherit the dead task's capabilities.
- **Centralized authorization.** Syscall dispatch is a descriptor table that enforces each call's required capability at one choke point; an unlisted syscall number fails closed, and a compile-time assertion forbids adding a syscall without a table slot.
- **Least-privilege delegation.** A supervisor (e.g. `init`) holds a child's `CAP_TCB` from the spawn and hands it exactly the capabilities it needs with `SYS_CAP_GRANT`; `SYS_KILL` and `SYS_SIGNAL` are gated on holding that `CAP_TCB`.
- **Hardware isolation.** Ring 0/3 separation with per-task page tables; **SMEP** and **SMAP** engaged when advertised; **W^X** enforced via `EFER.NXE` and the PTE NX bit (non-executable stacks; ELF `PT_LOAD` segments honour their `p_flags`).
- **Modern cryptography, safe Rust.** Argon2id (RFC 9106) memory-hard password hashing on an in-house BLAKE2b, HKDF-SHA256 key derivation, a ChaCha20 + HMAC-SHA256 Encrypt-then-MAC AEAD for storage, and a ChaCha20 fast-key-erasure CSPRNG seeded from RDRAND and timing jitter — all validated against published/reference vectors.
- **Tamper-evident audit log.** Each event is bound by an HMAC keyed to a per-boot secret, and a running hash-chain head commits to the entire ordered history; `SYS_AUDIT_DIGEST` exposes the digest and verify status for an external monitor.

Full posture and threat model: **[SECURITY.md](SECURITY.md)**.

---

## Status at a glance

| Subsystem | State |
|---|---|
| Multiboot2 boot (x86-64 long mode) | ✅ Working |
| VGA terminal + serial output | ✅ Working |
| GDT / IDT / TSS, hardware user/kernel isolation | ✅ Working |
| Paging, per-task address spaces, memory isolation | ✅ Working |
| Capability mint / transfer / move / revoke | ✅ Working |
| Transitive cross-task revocation + lineage (use-after-revoke prevention) | ✅ Working |
| SMEP / SMAP hardening (when CPU advertises) | ✅ Working |
| W^X — non-executable stacks + ELF `p_flags` honoured | ✅ Working |
| ASLR — per-spawn stack, heap, **and PIE image base** (relocated at load; ~9-bit entropy in the 32-bit window) | ✅ Working |
| Table-driven syscall dispatch (central capability gate, 0–75) | ✅ Working |
| User authentication + lockout (Argon2id memory-hard hashing) | ✅ Working |
| Tamper-evident audit log (HMAC chain + `SYS_AUDIT_DIGEST`) | ✅ Working |
| Encryption-at-rest AEAD (ChaCha20 + HMAC-SHA256) | ✅ Working |
| PS/2 keyboard input | ✅ Working |
| Preemptive round-robin scheduling (timer-driven, ring-3) | ✅ Working |
| Fault signals (ring-3 handler on fault instead of kill) | ✅ Working |
| Async task-to-task signals (`SYS_SIGNAL` / `SYS_SIGMASK` / `SYS_SIGALTSTACK`, `CAP_TCB`-gated) | ✅ Working |
| Ring-3 process control — spawn/exec/kill/exit/wait/grant + image exec | ✅ Working |
| Ring-3 `init` (PID 1) — spawns, endows (`SYS_CAP_GRANT`) and blocking-supervises the shell | ✅ Working |
| Userspace filesystem server (ring-3 IPC server over encrypted object store) | ✅ Working |
| Per-file POSIX ownership & permissions (zero-trust, kernel-attested identity) | ✅ Working |
| Multi-client `fs_server` concurrency (identity-routed replies via `SYS_IPC_REPLY_TO`) | ✅ Working |
| Crash-atomic filesystem (write-ahead redo journal + mount-time `fsck`) | ✅ Working |
| Large files (direct + single- + double-indirect blocks, 2 MiB volume) | ✅ Working |
| Disk-backed persistent storage (ATA probe at boot; RAM vdisk fallback) | ✅ Working |
| newlib libc port over a per-process POSIX fd layer (`malloc`/`sbrk`/`brk`) | ✅ Working |
| Symmetric multiprocessing (AP bringup, per-CPU scheduler, TLB-shootdown IPIs) | ✅ Working *(behind `SMP=1`)* |
| Rust security-core unit tests (63) + GitHub Actions CI (21 gated jobs) | ✅ Working |
| Headless QEMU self-tests: boot, ELF/W^X, preemption, signals, process-control, notifications, SMP, fs (×6), newlib | ✅ Working |
| Scripted integration session: drives the real ring-3 shell over serial (auth + least privilege) | ✅ Working |
| Reproducible builds | ✅ Working |
| Userspace shell and commands | 🟡 Partial |
| Async notifications (`SYS_NOTIFY` / `SYS_WAIT_NOTIFY`, badge-carrying) | ✅ Working |
| Endpoint-based IPC (single-slot, non-blocking) | 🟡 Partial |
| Copy-on-write paging | 🟡 Partial |
| SMP as default (per-CPU run queues, priorities) | ⬜ Not yet (works behind `SMP=1`) |

---

## Quick start

### Prerequisites

```bash
# Debian / Ubuntu
sudo apt-get install build-essential gcc binutils make xorriso grub-pc-bin mtools qemu-system-x86

# Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
rustup target add x86_64-unknown-none
```

### Build and run

```bash
make          # produces kernel.elf
make run      # builds boot.iso and launches QEMU (console on serial; nc localhost 4445)
```

Default login: `user` / `password` (or `root` / `rootpass`).

### Verify it

```bash
make test               # Rust unit tests (63) + a clean full build
make smoke              # headless QEMU boot to the ring-3 login prompt, no fault
make smoke-proc         # ring-3 process control: exit/kill/spawn/exec/grant/signal/wait
make reproducible-build # byte-for-byte deterministic kernel.elf
```

### Build flags

| Flag | Default | Effect |
|---|---|---|
| `DEBUG_SHELL` | `0` | Enable the in-kernel debug shell |
| `MINIMAL_SECURE` | `0` | Strip non-essential kernel features (smaller attack surface) |
| `RUST_ENABLED` | `1` | Link the Rust security core (`0` uses C stub shims) |
| `SMP` | `0` | Bring up the application processors (multi-core) |
| `STORAGE_ATA` | `0` | Prefer the ATA path in smoke/self-test builds; runtime always probes for a disk and falls back to the RAM vdisk when none is present |
| `*_SELFTEST` | `0` | Boot-time self-tests: `ELF_`, `PREEMPT_`, `SIGNAL_`, `PROC_`, `FS_`, `NEWLIB_`, `SMP_` |

Horus is x86-64 only. See [docs/BUILDING.md](docs/BUILDING.md) for the full toolchain reference, all targets, and troubleshooting.

---

## Documentation

| Document | Contents |
|---|---|
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | Design decisions, subsystem internals, capability model, memory layout |
| [docs/SYSCALLS.md](docs/SYSCALLS.md) | Per-syscall reference: numbers, capability requirements, notes |
| [docs/BUILDING.md](docs/BUILDING.md) | Toolchain setup, build targets, build flags, QEMU configuration |
| [SECURITY.md](SECURITY.md) | Security posture, hardening in place, threat model, disclosure |
| [docs/LIMITATIONS.md](docs/LIMITATIONS.md) | Honest breakdown of what works and what does not |
| [docs/ROADMAP.md](docs/ROADMAP.md) | Planned milestones and open contribution areas |
| [TESTS.md](TESTS.md) | Test coverage today and what is still needed |
| [CHANGES.md](CHANGES.md) | Changelog (state of the `main` branch) |

---

## Contributing

Horus is at an early stage, and there is meaningful work across kernel C, safe Rust, and tooling. Contributions of all sizes are welcome — see [CONTRIBUTING.md](CONTRIBUTING.md) to get started, and [docs/ROADMAP.md](docs/ROADMAP.md) for prioritized areas.

## Security

Please report vulnerabilities responsibly via a GitHub Security Advisory rather than a public issue. Details and scope are in [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) — Copyright © 2026 The Horus Project.
