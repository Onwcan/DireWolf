# Security policy

**Do not open a public issue for a security report.** Do not put a
vulnerability's details in a pull request, a commit message or a CI run either:
in this public repository, all three are public.

This file is the reporting policy. The security *posture* — what DireWolf
claims, why the boundary is where it is, what it does not defend against — is
[docs/SECURITY.md](docs/SECURITY.md), and the adversary model is
[docs/THREAT_MODEL.md](docs/THREAT_MODEL.md).

## How to report

Use GitHub's private vulnerability reporting:

1. Open the repository's **Security and quality** tab, choose **Advisories**,
   and click **Report a vulnerability** — or go straight to
   <https://github.com/Onwcan/DireWolf/security/advisories/new>. You need to be
   signed in to GitHub.
2. Fill in the form: a summary, the details, a proof of concept and the
   impact. Say which commit you tested and which part is affected — the
   authority, a broker, the sandbox, the protocol, CI or the build — and leave
   out real credentials and anyone else's data.
3. Submit it. The report becomes a draft security advisory that only you, the
   repository's maintainers and the people they add to it can see.

## What happens after a report

DireWolf has one maintainer, so these are targets, not guarantees:

- **Acknowledgement within 3 working days**, as a comment on the report. If
  none has arrived by then, add a comment to the report.
- **An assessment within 10 working days**: whether the report is in scope, how
  severe it is, and what follows — the report accepted as a draft advisory, a
  request for more information, or the report closed with the reason.
- **The fix is made in private**, in the advisory's temporary private fork,
  where you can follow and test it, or on the maintainer's own machine. Nothing
  about the vulnerability goes into a public issue, pull request or CI run
  before the fix is merged.
- **Disclosure is coordinated with you.** The advisory is published once the
  fix is on `main`, with a CVE where one is warranted, and it credits you unless
  you ask it not to.

---

## Current status: an authority plane, no agent runtime

The repository is through milestone **M5** ([ROADMAP](docs/ROADMAP.md)). The
authority plane exists and serves on Linux: the kernel's policy engine,
capabilities and audit chain; the filesystem, process and secret brokers; and
the sandbox — measured `oci-strict` execution environments, `PROXY_ONLY` egress
through the broker's CONNECT proxy, and the kernel's own `net.http`. There is
**no agent loop, no model provider and no approval flow** yet, so nothing here
should be trusted as an agent runtime.

The architecture boundary checks in `architecture.toml` are static analysis
over source text. They are development hygiene. They are not containment, and
a passing check is not evidence of any security property; the evidence is the
`make` campaigns and hosted CI jobs the [README](README.md) lists.

Reports about the authority, the brokers and the sandbox are in scope now, as
are reports about the build system, CI configuration and supply chain. Reports
about the agent runtime will become meaningful when it exists (M9).

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
