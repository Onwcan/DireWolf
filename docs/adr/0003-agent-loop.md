# ADR-0003: Two-dimensional run state — lifecycle state plus a wait set

**Status:** Accepted · **Date:** 2026-09-11

## Context

The conventional run state machine is a flat enum: `RUNNING`, `WAITING_MODEL`, `WAITING_TOOL`, `WAITING_APPROVAL`, `WAITING_SUBAGENT`, and so on. This breaks under parallelism, which is the normal case: a run can simultaneously await one model call, three tools and two subagents. A single-valued enum cannot represent that, and adding a state per blocker combination is combinatorial.

## Decision

Two orthogonal dimensions.

**(a) Lifecycle state** — authoritative, persisted, single-valued, few:
`CREATED → QUEUED → ADMITTED → ACTIVE ⇄ SUSPENDED → DRAINING → {SUCCEEDED | FAILED | CANCELLED | EXPIRED}`

**(b) Wait set** — derived, multi-valued, not persisted as state:
`{ Awaitable{kind: model|tool|approval|subagent|timer|human|lease, id, since, deadline} }`

A run is blocked iff the wait set is non-empty and no step is runnable.

Three states carry specific weight:

- **`ADMITTED`** is where authority is frozen and budget reserved. Resume re-enters it, forcing re-preflight — so a run suspended for three days cannot resume on capabilities revoked yesterday.
- **`DRAINING`** is where cancellation lives: no *new* side effects, in-flight ones settled or marked `UNKNOWN`, compensations run.
- **`EXPIRED`** distinguishes "we chose to stop" from "we lost the right to resume."

## Consequences

`direwolf run status` can say "waiting on your approval for 2 things and a subagent," which is what an operator actually wants. Transitions stay few and testable. Parallelism needs no new states.

Cost: two concepts instead of one, and the wait set must be reconstructed on resume from durable records rather than restored from a state column.

## Alternatives considered

- **Flat enum including `WAITING_*`.** Rejected above.
- **Per-blocker sub-state machines.** More machinery than the problem needs.
- **Only a wait set, no lifecycle state.** Loses a single authoritative answer to "is this run alive?", which every query and every recovery path needs.

