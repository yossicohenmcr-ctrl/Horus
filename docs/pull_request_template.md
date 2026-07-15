## Description
<!-- Concise summary of the change. Link to related issue if applicable. -->

## Motivation / Rationale
<!-- Why is this change needed? What problem does it solve? -->

## Security Impact
**REQUIRED for any change touching the capability system, memory management, IPC, scheduler, process control (spawn/exec/kill/signal/grant/wait), crypto, auth, audit, build/CI, or the FFI boundary.**

- Does this change preserve all existing security invariants (capability lineage/revocation correctness, no ambient authority, `CAP_TCB`-gated kill/signal/grant, FFI safety, isolation guarantees)?
- What new attack surface or trust assumption is introduced?
- How was the change reviewed against the threat model in SECURITY.md and ARCHITECTURE.md?
- List any new capabilities, rights, kernel objects, or syscalls added.

<!-- Example answers:
- Yes, revocation sweep + generation bump still covers all derived caps.
- No new ambient authority paths; the new syscall is gated on a CAP_TCB in its handler.
- Tested with a new self-test step in userspace/proctest.c.
-->

## Testing Performed
- [ ] `make` builds cleanly (no new warnings)
- [ ] `make test` / `cargo test --release` passes
- [ ] `make reproducible-build` still produces identical artifacts
- [ ] `make smoke` passes (headless boot to the login prompt; required if userspace, the loader, paging, or boot changed)
- [ ] Relevant self-test passes: `smoke-elf` / `smoke-preempt` / `smoke-signal` / `smoke-proc` / `smoke-smp` / `smoke-fs` / `smoke-newlib`
- [ ] New or updated unit/self-tests added for security-critical logic
- [ ] Security scans (`make security`) reviewed; no new high-severity findings

## Checklist
- [ ] I have read `docs/ARCHITECTURE.md`, `SECURITY.md`, and `CONTRIBUTING.md`
- [ ] Changes to security-critical paths include explicit explanation of invariants preserved
- [ ] Documentation updated (`docs/ARCHITECTURE.md`, `docs/SYSCALLS.md` for a new syscall, `SECURITY.md` for a status/limitation change, `TESTS.md` if the test/CI-job count changed, code comments)
- [ ] No new external dependencies introduced without justification
- [ ] This PR does not increase the C unsafe surface or add `unsafe` in the logic of `rust/src/capability.rs`, `memory.rs`, or `lib.rs`

## Screenshots / Logs (if boot behaviour changed)
<!-- Optional but helpful for reviewers -->

## Related Issues / PRs
<!-- e.g. Closes #xx, Depends on #yy -->
