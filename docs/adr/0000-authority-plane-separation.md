# ADR-0000: The authority boundary is an OS process boundary

**Status:** Accepted · amended by [ADR-0018](0018-authority-broker-split.md) · **Date:** 2026-09-11 · **Supersedes:** none

> **AMENDED by [ADR-0018](0018-authority-broker-split.md)** — the thesis of this ADR stands unchanged; the single privileged process it describes is now two (`dwkd-authority` + `dwkd-broker`). Read this for *why* the boundary exists, ADR-0018 for *where it is drawn*.

> Logically this ADR precedes ADR-0001. Every other decision in DireWolf is downstream of it.

## Context

Agent runtimes conventionally place authorization inside the process that runs the agent loop: a tool allowlist, a path check, an approval prompt, sometimes an auxiliary model judging risk. All of these live in the same address space as the component consuming untrusted model output, web content, tool results and MCP responses.

Two independent lines of evidence say this does not hold:

1. **A direct admission from a mature competitor.** Hermes Agent's own `SECURITY.md` states: "The only security boundary against an adversarial LLM is the operating system. Nothing inside the agent process constitutes containment." It then characterises its in-process controls as heuristics that "catch cooperative mistakes, not adversarial output."
2. **The observed failure record.** Across ~916 OpenClaw security advisories and the Hermes findings, the dominant class is not memory corruption or classical injection but *authorization boundaries drifting in scope or lifetime*: approvals outliving their reviewed directory, a gate enforced on one path and skipped on another, containment disabling approval as a side effect, credentials injected into the wrong endpoint, a diagnostics endpoint omitting an auth check. These are distributed-enforcement bugs.

Both point the same way. An in-process check protects against mistakes. It does not protect against an adversary who controls the process, and it erodes over time because it is implemented at many call sites in a fast-moving codebase.

## Decision

**Split the system into a Cognition Plane and an Authority Plane that are separate OS processes running as separate users.**

- `direwolf-runtime` (cognition) holds no credentials, has no network route, no filesystem handles, and cannot execute anything. It reasons and proposes.
- `dwkd` (authority) holds the credentials, owns the policy files and the audit log, performs every side effect, and is the only component that can grant anything.
- The sole channel between them is a typed socket where every message is canonicalised, policy-evaluated, capability-verified, budget-debited and audited.
- **There is exactly one path from cognition to effect, and no feature may add a second.**

## Consequences

**Positive.** A total compromise of the runtime yields only the authority that run already held. Budgets are enforceable rather than cooperative, because the kernel holds the provider credential and therefore meters every model call. Privacy routing is enforced at the credential-holding egress rather than trusted to a router. Approval prompts are rendered from kernel state and cannot be phished by model prose. Audit is written by a process the audited component cannot write to. The enforcement logic is small, stable, and can be fuzzed and property-tested as a unit.

**Negative.** A kernel round trip per tool call (budgeted p99 < 5 ms). A two-language build. Fail-closed reduces availability — a kernel fault stops all agent work. Contributors must understand the boundary. Some designs that would be natural in-process become awkward across it, and that awkwardness is a permanent tax.

**The risk we are accepting.** The boundary becomes a bottleneck that someone bypasses "just this once" for a feature. At that moment DireWolf becomes a slower version of its competitors with none of their advantages. This is why "any second enforcement path" is the highest-value class of security report in `SECURITY.md` §6.

## Alternatives considered

- **In-process checks (status quo).** Rejected on the evidence above.
- **Same process, different thread or module.** No privilege separation; an arbitrary-code-execution bug in the runtime reaches the checker's memory. Rejected.
- **FFI (kernel as a linked library, e.g. PyO3).** Would put secrets in the runtime's address space. This is the most tempting alternative because it removes the IPC cost, and it destroys the entire property. Explicitly rejected.
- **Sandbox the whole agent process instead.** A real and valid posture — and the one Hermes recommends. It contains the blast radius but cannot express per-action authority, cannot meter, and cannot produce a trustworthy audit trail from inside the sandbox. Complementary, not a substitute: we do both.

## Revisit if

Measurement shows kernel round trips dominate run latency for realistic workloads (> 15 % of wall clock), or two years of operation produce no incident class that the boundary prevented but an in-process check would not have.

