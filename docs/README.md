# Horus Documentation

This folder contains technical documentation for the Horus microkernel.

| Document | Contents |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Design philosophy, subsystem internals, capability model, task/process model, scheduling, signals, SMP, memory layout, Rust integration |
| [SYSCALLS.md](SYSCALLS.md) | Per-syscall reference (0–75): numbers, capability requirements, and notes |
| [BUILDING.md](BUILDING.md) | Toolchain requirements, build targets, build flags, QEMU setup, troubleshooting |
| [BOOT_INTEGRITY.md](BOOT_INTEGRITY.md) | Build provenance (Sigstore) and runtime verified boot (Ed25519 self-verify + halt) |
| [ROADMAP.md](ROADMAP.md) | Forward-looking milestones and open contribution areas |

The candid, subsystem-by-subsystem account of what works, what is partial, and the known security gaps lives in [SECURITY.md](../SECURITY.md#known-limitations--current-status) at the repository root.

Formal specifications:

| File | Contents |
|---|---|
| [cap_algebra.tla](cap_algebra.tla) | TLA+ spec of the capability algebra (mint/transfer/revoke); TLC-checked in CI against a real subset-rights non-escalation invariant (model in `cap_algebra.cfg`, run via `make verify-tla`) |
| [paging_isolation.tla](paging_isolation.tla) | TLA+ spec of per-task address-space isolation; TLC-checked in CI that no user frame is mapped into two tasks and no user mapping reaches kernel memory (model in `paging_isolation.cfg`) |
| [cap_seqlock.tla](cap_seqlock.tla) | TLA+ spec of the two-CPU `cap_seq` seqlock behind lock-free `cap_lookup` (audit finding 3.1); TLC-checked in CI that a committed lock-free read never observes a torn capability while another CPU mutates cspaces under `cap_lock` (model in `cap_seqlock.cfg`) |
| [ipc_toctou.tla](ipc_toctou.tla) | TLA+ spec of the IPC lookup→use TOCTOU guard (`cap_snapshot`/`cap_revalidate` in `syscall_ipc.c`); TLC-checked in CI that no IPC effect ever commits using authority revoked or re-minted during the window (model in `ipc_toctou.cfg`; falsifiable via `USE_REVALIDATE_GUARD`) |
| [sched_smp.tla](sched_smp.tla) | TLA+ spec of the SMP run-pool dispatch under `sched_raw_lock`; TLC-checked in CI that no task ever runs on two CPUs and the claim table (`task_running_cpu`) agrees with who is running each task (model in `sched_smp.cfg`; falsifiable via `USE_LOCK`) |

Templates:

| File | Contents |
|---|---|
| [pull_request_template.md](pull_request_template.md) | PR description + security-impact checklist |
| [.github/ISSUE_TEMPLATE/security_report.md](../.github/ISSUE_TEMPLATE/security_report.md) | Security-issue report template (surfaced in the GitHub "New issue" chooser) |

Project-level documents (at the repository root):

| Document | Contents |
|---|---|
| [README.md](../README.md) | Build quick start, status-at-a-glance table, project overview |
| [SECURITY.md](../SECURITY.md) | Security policy, posture, hardening, known limitations, threat model, reporting |
| [TESTS.md](../TESTS.md) | Test coverage today (89 Rust unit tests, 22 CI jobs) and what is still needed — the source of truth for both counts |
| [CONTRIBUTING.md](../CONTRIBUTING.md) | How to set up and submit work, code style, and change-control policy |
| [CHANGELOG.md](../CHANGELOG.md) | Release history |
