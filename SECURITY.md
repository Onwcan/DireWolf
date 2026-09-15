# Security policy

**Do not open a public issue for a security report.**

Use GitHub private security advisories on this repository. We aim to
acknowledge within 3 working days and to give an assessment within 10.

This file is the reporting policy. The security *posture* — what DireWolf
claims, why the boundary is where it is, what it does not defend against — is
[docs/SECURITY.md](docs/SECURITY.md), and the adversary model is
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

---

## Current status: no runtime exists

The repository is at milestone **M1**, the repository foundation. There is no
kernel, no policy engine, no sandbox and no agent loop; the daemons build and
refuse to run. **There is nothing here to attack yet**, and correspondingly
nothing here that should be trusted.

In particular: the architecture boundary checks in `architecture.toml` are
static analysis over source text. They are development hygiene. They are not
containment, and a passing check is not evidence of any security property.

Reports about the build system, CI configuration or supply chain are in scope
now. Reports about the runtime will become meaningful from M3.

## In scope

- Any path from model output, tool output, or external content to an
  unapproved side effect.
- Any capability escalation, including a child exceeding a parent.
- Approval replay, substitution, or binding bypass.
- Secret disclosure to the runtime, to a model, to a log, or to an artifact.
- Sandbox escape; filesystem escape from a workspace; SSRF past the egress
  guard.
- Audit log tampering that is not detected by the chain.
- **Any second enforcement path** — a way to cause a side effect that does not
  traverse the kernel's decision pipeline. **This is the highest-value class of
  report**, because the architecture's entire premise is that no such path
  exists.
- Compromise of the build or release path: CI configuration, dependency
  policy, anything that would let a third party get code into an artifact.

## Out of scope

- "I achieved prompt injection" with no chained consequence. Injection is
  assumed; it is in scope only when it produces an unapproved effect.
- Attacks requiring host root or physical access.
- Attacks requiring the operator to approve the malicious action — **unless the
  approval prompt itself misrepresented what would happen.** That *is* in
  scope, and is a serious bug.
- Denial of service by exhausting a budget the operator configured.
- Findings against a configuration that disabled a documented default, unless
  the disabling was possible without operator intent.

## Safe harbour

Good-faith research on your own installation is welcome and will not be met
with legal action. Do not test against other people's instances.

## Security in development

- A change to `crates/dwkd-authority/` or `crates/dwkd-broker/` requires a
  reviewer other than the author, and an ADR if it changes an interface.
- Every new DWKP operation requires a written argument for why it is not a
  second path from cognition to effect, reviewed by someone other than its
  author.
- `cargo-deny` and `pip-audit` run in CI. New dependencies in the authority
  plane require explicit review and a note on
  [ADR-0019](docs/adr/0019-language-rationale-v2.md).
- From M2.5 the security evaluation suite is a merge gate, not a nightly job.
- We publish evaluation results, including failures. A security posture nobody
  can check is a marketing claim.

The full development rules are in [CONTRIBUTING.md](CONTRIBUTING.md).
