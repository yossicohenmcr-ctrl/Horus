# Governance

The repository, its CI/CD, and its branch protection are part of the **trusted
base** of a high-assurance system: a weakness here can inject a runtime
vulnerability that bypasses every code-level control. This document records the
governance posture and its known residual risk (audit finding **3.2**).

## Change control on `main`

Every change to `main` must be a **pull request** that passes the full set of
**required status checks** before it can merge, and this is **enforced for
administrators** — there is no direct-push or admin-bypass path. The required
gates are the six core CI contexts:

- Rust unit tests + clippy (deny-warnings)
- Kernel + bootable ISO build
- QEMU smoke-boot
- Reproducible-build verification
- TLA+ model checking (capability algebra + paging isolation)
- Security scans + SBOM (gitleaks + Semgrep-ERROR blocking)

`CODEOWNERS` designates the owner of every security-critical path.

## Commit authenticity

Commits to `main` are **cryptographically signed** and verified, so authorship
is authenticated and an unsigned commit (e.g. from a compromised credential that
cannot reproduce the signing key) is rejected.

## Known residual risk: single maintainer (bus factor 1)

The project currently has **one maintainer**, who is also the sole code owner.
This has a hard consequence for review independence:

- GitHub does not allow a PR author to approve their own PR, and a single code
  owner cannot provide the "review from someone else" that a
  `required_approving_review_count >= 1` gate implies. Under enforced admin
  protection, requiring an approval a solo maintainer can never obtain would make
  the repository **unmergeable**.
- The posture therefore sets **required approvals to 0** while keeping the PR
  requirement, the CI gates, and admin enforcement. The maintainer self-merges,
  but only through a PR whose CI gates are all green and whose commits are
  signed — i.e. the *automated* trusted base is enforced against the maintainer,
  even though *human* independent review is not yet possible.

This is the correct ceiling for a single-maintainer high-assurance project: it
enforces everything that can be enforced without a second person. **The path to
independent review is to add a second maintainer**, then restore
`required_approving_review_count = 1` and re-enable code-owner review — at which
point human review becomes a binding gate on top of the automated ones.

## Vulnerability disclosure

See [SECURITY.md](SECURITY.md). Sensitive reports go through a private GitHub
Security Advisory, never a public issue.

## Enablement

The protected-branch settings above (admin enforcement, mandatory PR + checks,
required signatures) are configured on the GitHub repository, not in-tree; this
document is the policy of record. Enabling *required signatures* additionally
requires the maintainer's commit-signing public key to be registered on their
GitHub account so signatures verify server-side.
