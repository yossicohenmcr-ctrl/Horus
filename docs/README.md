# Horus Documentation

This folder contains technical documentation for the Horus microkernel.

| Document | Contents |
|---|---|
| [ARCHITECTURE.md](ARCHITECTURE.md) | Design philosophy, subsystem internals, capability model, task/process model, scheduling, signals, SMP, memory layout, Rust integration |
| [SYSCALLS.md](SYSCALLS.md) | Per-syscall reference (0–75): numbers, capability requirements, and notes |
| [BUILDING.md](BUILDING.md) | Toolchain requirements, build targets, build flags, QEMU setup, troubleshooting |
| [LIMITATIONS.md](LIMITATIONS.md) | Honest account of what works, what is partial, and known security gaps |
| [ROADMAP.md](ROADMAP.md) | Forward-looking milestones and open contribution areas |

Formal specifications:

| File | Contents |
|---|---|
| [cap_algebra.tla](cap_algebra.tla) | TLA+ spec of the capability algebra (mint/transfer/revoke); TLC-checked in CI against a real subset-rights non-escalation invariant (model in `cap_algebra.cfg`, run via `make verify-tla`) |
| [paging_isolation.tla](paging_isolation.tla) | TLA+ spec of per-task address-space isolation; TLC-checked in CI that no user frame is mapped into two tasks and no user mapping reaches kernel memory (model in `paging_isolation.cfg`) |
| [cap_seqlock.tla](cap_seqlock.tla) | TLA+ spec of the two-CPU `cap_seq` seqlock behind lock-free `cap_lookup` (audit finding 3.1); TLC-checked in CI that a committed lock-free read never observes a torn capability while another CPU mutates cspaces under `cap_lock` (model in `cap_seqlock.cfg`) |

Templates:

| File | Contents |
|---|---|
| [pull_request_template.md](pull_request_template.md) | PR description + security-impact checklist |
| [.github/ISSUE_TEMPLATE/security_report.md](../.github/ISSUE_TEMPLATE/security_report.md) | Security-issue report template (surfaced in the GitHub "New issue" chooser) |

Project-level documents (at the repository root):

| Document | Contents |
|---|---|
| [README.md](../README.md) | Build quick start, status-at-a-glance table, project overview |
| [SECURITY.md](../SECURITY.md) | Security policy, current posture, hardening in place, reporting |
| [TESTS.md](../TESTS.md) | Test coverage today (63 Rust unit tests, 21 CI jobs) and what is still needed — the source of truth for both counts |
| [CONTRIBUTING.md](../CONTRIBUTING.md) | How to set up and submit work |
| [CHANGES.md](../CHANGES.md) | Changelog (`main` branch state) |
