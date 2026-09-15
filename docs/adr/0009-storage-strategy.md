# ADR-0009: SQLite, two physically separate stores, no abstraction layer

**Status:** Accepted · **Date:** 2026-09-11

## Context

A local-first single-operator runtime needs durable state. The temptation is to add a database abstraction layer "in case we need Postgres."

## Decision

1. **SQLite in WAL mode.** Embedded (no daemon, no port, no auth surface), a single file, transactional, extremely well tested, ships FTS5.
2. **Two physically separate databases with different OS owners.** `runtime.db` (runtime-writable) and `kernel.db` + `audit.log` (kernel-only, runtime cannot write). **A process may not write the state that constrains it** — approvals and budgets in a runtime-writable database would silently undo ADR-0000. Startup refuses to proceed if permissions are wrong.
3. **No cross-store foreign keys.** Each store must function when the other is corrupt.
4. **Quarantine on structural corruption.** On `SQLITE_CORRUPT`/`SQLITE_NOTADB` the handle is poisoned in memory immediately, never reopens, and WAL checkpointing is skipped — adopted from an observed incident where writes continued ~50 minutes past the first error, compounding damage. Derived-index (FTS) corruption is handled separately with a stale marker and `LIKE` fallback, because losing search quality is survivable and losing writes is not.
5. **No ORM, no database abstraction layer.** Repository modules exist as code organisation, not as a portability layer.

## Consequences

Zero operational dependencies; backup is a file copy (via the backup API, not `cp`); the security boundary is enforced by the filesystem. Single-writer discipline keeps latency predictable.

Cost: single-node only. Multi-node would change the concurrency model and lease mechanism, not merely the driver — a redesign, not a swap. Saying so plainly is more useful than an abstraction that implies otherwise.

## Alternatives considered

- **Postgres from the start.** An operational dependency contradicting local-first, for scale we do not have.
- **One database with application-level separation.** Would put the constraining state where the constrained process can write it. Rejected.
- **An ORM.** Hidden query behaviour and migration magic in a component whose correctness matters.

