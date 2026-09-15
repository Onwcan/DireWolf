# ADR-0017: Audit and telemetry are separate systems with different owners

**Status:** Accepted · audit scope amended by [ADR-0027](0027-audit-scope-boundary.md) · **Date:** 2026-09-11

> **AMENDED by [ADR-0027](0027-audit-scope-boundary.md).** The two-system separation stands. The claim "the absence of a record means the action did not go through the kernel" is narrowed: activity inside an already-authorised `process.exec`, within its mounted workspace, is not individually brokered or audited.

## Context

A comparable system exports excellent OTLP telemetry that deliberately omits prompts, tool arguments, results, filenames and command output — correct for a privacy-preserving *monitoring* signal, and useless for answering "what did the agent actually do to my machine?" Another ships a real audit ledger but documents it as metadata-only and states that "absence of a row proves nothing" because queue saturation or a crash can silently drop records.

The mistake in both cases is letting one system serve two purposes. Telemetry wants to be sampled, lossy, privacy-minimal and cheap. Audit wants to be complete, durable, tamper-evident and detailed.

## Decision

**Two systems, different owners, different guarantees.**

| | Observability | Audit |
|---|---|---|
| Owner | runtime | **kernel** |
| Guarantee | best-effort, sampled | **complete, append-only, hash-chained** |
| Content | metrics, spans, structured logs | canonical actions, decisions, principals |
| Loss | acceptable | a bug |

- **Audit is written by the kernel at the moment of decision**, synchronously, before the effect. An audit record the audited process writes is a suggestion.
- Records carry the full canonical action, the matched rule with its source location, and the **`policy_hash`** — so a decision can be recomputed months later from the exact rule set in force.
- **No phone-home at any setting.** No version check, no usage statistics. A local-first runtime that quietly contacts a vendor on startup has conceded its premise.
- Exported OTLP carries metadata and metrics only by default; content export is opt-in with a warning.
- **`direwolf doctor` verifies facts, not settings** — it attempts the write that should fail rather than reading a config flag that claims it would.

## Consequences

Because there is exactly one path from cognition to effect (ADR-0000), we can make a stronger statement than "absence proves nothing": **the absence of an audit record means the action did not go through the kernel** — so it either did not happen, or the architecture's central invariant has been broken, which is itself the most important thing an operator could learn.

Cost: synchronous audit writes on the critical path (small, `fsync`-bounded, and only for side-effecting operations); two systems to maintain.

Honest limit: hash chaining detects tampering, not wholesale deletion by an attacker with kernel-user or root privilege. Detecting that requires exporting chain heads off-host, which we ship as a command and document rather than overclaim.

## Alternatives considered

- **One system serving both.** Either audit becomes lossy or telemetry becomes a privacy problem.
- **Runtime-written audit.** The audited component writing its own record.
- **Asynchronous audit with a queue.** Faster, and it introduces exactly the "queue saturation silently dropped records" failure a competitor documents.
