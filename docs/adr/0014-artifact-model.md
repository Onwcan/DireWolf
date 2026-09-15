# ADR-0014: Large output becomes a kernel-owned, content-addressed artifact

**Status:** Accepted · **Date:** 2026-09-11

## Context

Unbounded tool output is simultaneously a cost problem (a 500 MB log destroys a context window and a budget), a reliability problem (OOM), and a security problem (output is untrusted content that must be sanitised and scanned for secrets before it reaches the model).

## Decision

1. **Hard cap at `max_output_bytes`**; the process is killed if it exceeds it.
2. **Output above `inline_budget_bytes` (32 KiB) becomes an artifact**, stored content-addressed by sha256.
3. **The model receives a structure-aware excerpt** chosen by MIME — head/tail for logs, error-lines-first for compiler output, schema+sample for tabular, MIME/size/hash only for binary — plus a reference it can use to look closer.
4. **Artifact creation is kernel-side.** The runtime streams content to the kernel, which hashes, redacts, enforces quota and writes. A store the constrained process can write to would make recorded provenance meaningless.
5. **Downloads start quarantined**: never executed, never auto-opened, MIME sniffed not trusted, archives never auto-extracted, clearing quarantine is an explicit audited action.
6. **GC respects provenance reachability** — an artifact referenced by a taint explanation is never collected, or "why was this untrusted?" would decay into a dangling id.
7. **Excerpting is deterministic** and never splits a multi-byte character or escape sequence.

## Consequences

This is the single largest lever on context cost. Provenance gets a durable anchor: a taint source is an artifact id an operator can actually read. Code changes as `PATCH` artifacts become reviewable before application.

Cost: disk usage needs retention policies and reference-counted GC; excerpt strategies are per-MIME code that must be maintained.

## Alternatives considered

- **Truncate to N bytes.** Loses the errors at the end of a log — usually the only part that mattered.
- **Runtime-owned artifact store.** Cheaper, and it lets a compromised runtime forge provenance.
- **Stream everything to the model and let it cope.** Cost and context catastrophe.

