# ADR-0010: Hybrid — relational entities, append-only transcript, hash-chained audit

**Status:** Accepted · **Date:** 2026-09-11

## Context

Full event sourcing is architecturally attractive and expensive: every read becomes a projection, every schema change becomes a migration of history, and debugging requires reconstructing state. For a single-node personal runtime the costs are real and the benefits mostly are not — except in two places where append-only is exactly right.

## Decision

| Data | Home |
|---|---|
| Entities (session, run, task, approval, memory, artifact) | Relational tables, **authoritative** |
| Run timeline / transcript | Append-only event log |
| Security decisions | Append-only, **hash-chained** audit, kernel-written |
| UI timelines, usage rollups | Derived projections, rebuildable, never authoritative |

Envelope: `{event_id (UUIDv7), schema, schema_version, ts, seq, run_id, session_id, agent_id, causation_id, correlation_id, trust, payload}`.

Evolution rules: additive-only within a major version; **unknown events retained verbatim and skipped by projectors**; major bumps ship read-time upcasters; stored events are never rewritten; projections rebuildable on demand.

## Consequences

Queries stay simple and indexed. The transcript, which genuinely is an append-only sequence, gets append-only semantics. The audit log is tamper-evident and written by a process the audited component cannot write to. Forward compatibility means event files outlive the code that wrote them.

Honest limit on the audit chain: hashing detects *tampering*, not wholesale deletion by an attacker who can rewrite the chain. Detecting deletion requires exporting chain heads off-host, which we ship as a command and document as a limitation rather than overclaiming.

## Alternatives considered

- **Full event sourcing.** Rejected as cost without commensurate benefit here; also makes GDPR-style deletion genuinely hard.
- **Relational only.** Loses ordering guarantees and tamper evidence where they matter most.
- **Events in the same store as entities, runtime-writable.** Would let the audited component rewrite its own audit.

