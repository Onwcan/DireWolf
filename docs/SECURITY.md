# Security Posture

The public statement of what DireWolf protects, what it does not, and how to report a problem. Detail lives in [THREAT_MODEL.md](THREAT_MODEL.md); mechanism lives in [CAPABILITIES.md](CAPABILITIES.md), [POLICY.md](POLICY.md), [APPROVALS.md](APPROVALS.md), [SANDBOX.md](SANDBOX.md), [NETWORK_SECURITY.md](NETWORK_SECURITY.md) and [SECRETS.md](SECRETS.md).

---

## 1. The claim, precisely

DireWolf claims:

> **The consequences of a compromised model, a compromised agent runtime, or hostile content are bounded by an authorization boundary that the compromised component cannot reach.**

DireWolf does **not** claim:

- that prompt injection can be prevented,
- that a model can be made to reliably refuse manipulation,
- that a sandboxed process cannot be made to do something unhelpful within its granted authority,
- that the system is secure against an attacker who already has root on the host,
- that OCI containers provide VM-grade isolation.

The distinction matters. We are not trying to make the agent behave. We are trying to make its misbehaviour survivable.

## 2. Why the boundary is where it is

Every in-process control — a permission check in the agent's own code, a scanner over its output, an LLM judging whether an action is risky — protects against *mistakes*, not against *adversaries*. If the component being constrained shares an address space with the component doing the constraining, the constraint is advisory.

DireWolf therefore places the authorization boundary at an **OS process and privilege boundary**:

- `dwkd` (the kernel) runs as its own OS user, holds the credentials, owns the policy files, owns the audit log, and performs every side effect.
- `direwolf-runtime` (the agent) runs as a different, lower-privileged user with no credentials, no network route, no filesystem handles and no ability to execute.
- The only channel between them is a typed socket where every message is canonicalised, policy-checked, capability-verified and audited.

A total compromise of the runtime — arbitrary code execution inside it — yields the attacker exactly the authority that run was already granted, and nothing more.

## 3. Secure by default

Defaults are the security posture. A system whose safe configuration is opt-in will be run unsafely by almost everyone.

| Setting | DireWolf default |
|---|---|
| Execution environment | Sandboxed (OCI). Host execution requires config + capability + per-invocation approval. |
| Network | Denied. Allowlist required. |
| Filesystem | Workspace only, read and write scoped separately. |
| Secrets | Never visible to the agent; egress-injected. |
| Approvals | Single-use, expiring, bound to a canonical action. |
| Durable memory writes | Human-gated when provenance touches untrusted content. |
| Learned skills | Untrusted until validated and approved. |
| Unattended runs | Anything that would require approval is denied instead. |
| Plugins | Not shipped in V1 (so they cannot be a default risk). |
| Audit | Always on. Not optional, not sampled. |

There is no `--yolo`. The nearest equivalent is the `POWER` profile, which is a bounded capability ceiling with a policy rule pack — not a bypass. Every profile still goes through the same single enforcement point.

## 4. Hardening guide

DireWolf's defaults are intended to be the recommended configuration; there is no separate hardening checklist to follow, which is itself a design goal. Beyond the defaults:

1. Run the kernel as a dedicated user; verify with `direwolf doctor` that the runtime user cannot write `kernel.db`, `audit.log` or `policy/`.
2. On Windows, run under WSL2. `doctor` will warn if you do not ([SANDBOX.md](SANDBOX.md) §5).
3. Use `SAFE` for anything that reads content you did not write.
4. Prefer `LOCAL_ONLY` privacy class for sensitive workspaces.
5. Export audit chain heads off-host if you need deletion-detection, not just tamper-detection.
6. Review `direwolf grant list` periodically; a standing grant you forgot is the most likely way you get hurt.
7. Keep `security.allow_host_execution` false unless a specific workflow requires it, and turn it back off afterwards.

## 5. Known limitations

Listed here rather than buried, because a security document that only lists strengths is an advertisement.

1. **Injection within granted authority is not prevented.** If a run may write to your workspace, hostile content can cause a bad write there. Narrow scopes and approvals for irreversible actions are the mitigation; there is no cure.
2. **Containers are not VMs.** A Linux kernel 0-day escapes `oci-strict`. A stronger `ExecutionEnvironment` is a deferred item, not a shipped one.
3. **Secret redaction is hygiene, not a control.** It cannot catch transformed or encoded values. We rely on secrets not being present, not on scrubbing them.
4. **Host root is game over.** Including deletion of the audit log; hash chaining detects tampering, not deletion, unless chain heads leave the host.
5. **The operator can approve anything.** We show the truth as clearly as we can. We do not override human decisions.
6. **Model providers see prompt content.** Unavoidable for remote inference; `privacy_class` and local models are the answer.
7. **Native Windows host execution has materially lower assurance** than Linux or macOS.
8. **Fail-closed reduces availability.** A kernel fault stops all agent work. This is deliberate.
9. **The TCB is small but not zero.** A compromised kernel dependency is a full compromise.
10. **As of M3d, the authority has durable state; as of M3e it has a process boundary** (see item 11). A DWKP message that decodes is well-formed and nothing more. The capability lattice (M3b) answers "is this within the authority held?", the policy engine (M3c) answers "should this be allowed?", and M3d gives both a durable subject: `kernel.db` holds fenced epochs, leases, admissions, grants and every policy input, and `audit.log` holds a hash chain written before any answer is returned ([ADR-0039](adr/0039-durable-authority-state.md)). There is no approval registry and no canonicaliser, so **no effect is authorised, no secret is protected and there is no sandbox** (M4–M6). Policy inputs whose real producers do not exist yet are derived in the restrictive direction — every run is unattended (`api`), taint starts at none and can only rise — and are not end-to-end proven. And no proposed action is decided over DWKP before M4: without a canonicaliser the kernel cannot know where an action would run or what it would reach, so `QueryAuthority` refuses the proposal (`NO_CANONICAL_ACTION`) rather than decide on invented facts ([ADR-0040](adr/0040-m3d-reconciliation-admission-across-tenures-and-undecidable-proposals.md)).
11. **As of M3e, the runtime cannot lie about who it is** ([ADR-0041](adr/0041-m3e-authenticated-dwkp-transport.md)). `dwkd-authority serve` listens on a Unix-domain socket — nothing else — and, before reading a byte, asks the kernel for the peer's uid (`SO_PEERCRED`) and refuses, unanswered and audited, any uid the operator did not list. The subject is the kernel's; the lease holder is minted once per accepted connection and never shared, so a second connection from the same uid is a different writer; the handshake comes first; the strict decoder refuses every undeclared field, so a runtime cannot assert a policy input; reserved operations have no handler. The socket's directory is the authority's and closed to writers, so the runtime cannot replace the socket to impersonate the authority. A completely compromised runtime can send arbitrary bytes and cannot choose its subject or holder, bypass the handshake or the decoder, use a stale epoch or another connection's holder, reach a reserved operation, or make `QueryAuthority` decide an action — each shown against the real process, and the cross-uid refusal with a real second OS user in CI. **Linux only**: macOS and native Windows have no server rather than a guessed identity. The authority is not memory-safe end to end: SQLite's C runs in its address space.
11. **The Rust and Python protocol readers are separate implementations.** Their agreement is tested with shared vectors, not guaranteed by construction. Neither consults a Unicode database, so the two cannot diverge because their hosts ship different Unicode versions ([ADR-0034](adr/0034-protocol-depends-on-no-unicode-database.md)); any other divergence is a bug a vector has not yet caught.
12. **The authority links SQLite's C.** Since M3d the authority compiles the SQLite 3.53.2 amalgamation — 269,376 lines of C — into its own process, to read and write `kernel.db`. `#![forbid(unsafe_code)]` governs DireWolf's Rust, which contains no `unsafe`; it does not make SQLite memory-safe. The file SQLite parses is authority-owned, in a private directory, opened without URI parsing or symlink following and with `DEFENSIVE` and `trusted_schema = OFF`, which narrows who can hand it hostile bytes; it does not remove the C.
13. **The audit chain is tamper-evident, not tamper-proof.** It detects modification, reordering, interior deletion and — compared with `kernel.db` — removal of acknowledged records. A local attacker who rewrites `audit.log` and every copy of the chain head in `kernel.db` together is not detected; that needs the head anchored off-host, which is operational work that does not exist yet (see §4 item 5).
14. **None of this has been tested at scale.** DireWolf has no deployment history. Every claim in this document is a design claim until the eval suite and outside review say otherwise.

## 6. Reporting a vulnerability

**Do not open a public issue for a security report.**

Use GitHub private security advisories on the repository (<https://github.com/Onwcan/DireWolf>), as described in [`SECURITY.md`](../SECURITY.md) at the repository root. We will acknowledge within 3 working days and aim to give an assessment within 10.

### In scope

- Any path from model output, tool output, or external content to an unapproved side effect.
- Any capability escalation, including a child exceeding a parent.
- Approval replay, substitution, or binding bypass.
- Secret disclosure to the runtime, to a model, to a log, or to an artifact.
- Sandbox escape; filesystem escape from a workspace; SSRF past the egress guard.
- Audit log tampering that is not detected by the chain.
- Any second enforcement path — i.e. a way to cause a side effect that does not traverse the kernel's decision pipeline. **This is the highest-value class of report**, because the architecture's entire premise is that no such path exists.

### Out of scope

- "I achieved prompt injection" with no chained consequence. Injection is assumed and in-scope only when it produces an unapproved effect.
- Attacks requiring host root or physical access.
- Attacks requiring the operator to approve the malicious action, unless the approval prompt itself misrepresented what would happen — *that* is in scope and is a serious bug.
- Denial of service by exhausting a budget the operator configured.
- Findings against a configuration that disabled a documented default, unless the disabling itself was possible without operator intent.

### Safe harbour

Good-faith research on your own installation is welcome and will not be met with legal action. Do not test against other people's instances.

## 7. Security in the development process

- Every change to `crates/dwkd-authority/`, `crates/dwkd-broker/` or `crates/dwk-proto/` requires review by someone other than the author, and an ADR note if it changes an interface. A change to an authority-facing DWKP operation answers the eight questions in [CONTRIBUTING.md](../CONTRIBUTING.md) "Changing the protocol".
- The security eval suite ([EVALS.md](EVALS.md)) is a merge gate, not a nightly job.
- Every invariant in [README.md](../README.md) has a named test that fails if the invariant is removed.
- `cargo-deny` and `pip-audit` run in CI; new authority-plane dependencies require explicit justification in a new ADR amending [ADR-0019](adr/0019-language-rationale-v2.md), never an edit to it; `dwcheck adr` checks that accepted records are unchanged, anchored to the revision in which each ADR became Accepted rather than to a digest file in the same working tree — see [`adr/README.md`](adr/README.md) rule 1 for why that distinction is the whole point. `cargo-deny` covers advisories, licences, bans, duplicates and sources; `cargo-audit` is deliberately not run as well, because it reads the same RustSec database and a second tool means a second place to suppress a finding ([ADR-0031](adr/0031-repository-layout-and-boundary-enforcement.md)).
- Fuzzing: the protocol parser (`dwk-proto` framing, strict JSON, canonical JSON, envelope/versions) has four libFuzzer targets, and the M3c policy loader has two — one over loading, one over loading and evaluating — because that loader is the first third-party parser inside the authority. All six run weekly and on pull requests that touch them, and a stable-Rust mutation harness runs both sets with every `cargo test`. The path canonicaliser gets targets at M4, when it exists. This is scheduled fuzzing, not continuous fuzzing.
- Generated protocol files (`schemas/`, the Python bindings, the operation inventory) are drift-checked in CI; a hand edit fails the build.
- There is no secret scanner in CI; the evaluation and the M4 revisit are in [CONTRIBUTING.md](../CONTRIBUTING.md) "Secrets". GitHub push protection is a repository setting this repository cannot demonstrate is enabled.
- We publish eval results, including failures. A security posture nobody can check is a marketing claim.
