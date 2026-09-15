# ADR-0011: Single-writer session actors with database leases and epoch fencing

**Status:** Accepted · **Date:** 2026-09-11

## Context

Two channel messages, a scheduler tick and a CLI command can hit the same session in the same second. Without a concrete answer this corrupts transcripts, double-executes tools and produces incoherent conversations. Both comparable systems converged on per-session serialisation independently — a turn lease in one, a command queue in the other — which is good evidence the shape is right.

## Decision

1. **Persisted ordered mailbox** per session; ingress idempotent on `(channel_id, external_id)` via a unique index, so redelivery is free.
2. **Database lease** acquired by one conditional `UPDATE` on `(lease_owner, lease_epoch, lease_expiry)`. Exactly one process wins; no lock service needed.
3. **Single writer** — only the lease holder mutates session state.
4. **Optimistic `revision`** on every mutable entity; a mismatch is an error, never a silent overwrite.
5. **Epoch fencing, with the kernel as epoch authority.** The epoch is *issued* by the kernel (`AcquireLease`) from a monotonic counter in `kernel.db`; every kernel request carries it; the kernel rejects any epoch below its current value. The copy in the runtime's `sessions` table is a cache — an epoch stored only in a runtime-writable table could be forged by the process it is meant to fence.
6. **Concurrency inside a run is encouraged** (parallel read-only tools, parallel subagents); concurrency *across* runs in a session is opt-in via child sessions, never by relaxing the writer rule.

## Consequences

Point 5 is what makes leases safe rather than merely convenient, and it is the part neither comparable system documents. A runtime that hangs past its lease expiry, then wakes and tries to act, is rejected by the kernel — so split-brain cannot produce duplicate side effects. `stale_epoch_rejections > 0` is an alertable metric.

Cost: strict ordering per session means a long-running turn delays the next message. Mitigated by cancellation, by fast acknowledgement, and by child sessions for genuinely parallel work.

## Alternatives considered

- **Optimistic concurrency only.** Loses the ordering users perceive in a conversation.
- **An actor framework.** A dependency for what is a conditional UPDATE and a queue.
- **Leases without fencing.** The common design, and it permits exactly the zombie-writer failure the fencing prevents.

