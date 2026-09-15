# ADR-0027: Audit covers brokered effects, not activity inside an authorised exec

**Status:** Accepted · **Date:** 2026-09-12 · **Amends:** [ADR-0017](0017-observability-vs-audit.md)

## Context

ADR-0017 made a strong claim, stronger than comparable systems make: *"the absence of a record means the action did not go through the kernel"* — and, since no other path to a side effect exists, either it did not happen or the central invariant is broken.

Review finding H7 shows the claim is too broad. The sandbox mounts the workspace at **directory granularity**. A process launched by an authorised `process.exec` reads and writes anywhere in that mount with no per-file capability check, no canonicalisation and no per-file audit record. One `process.exec` entry can cover a thousand file writes. A related consequence: sub-workspace `fs.*` scoping is unenforceable once `process.exec` is granted, and the shipped `BALANCED` profile grants it.

## Decision

The audit claim is narrowed to what is true:

> **Every effect crossing the authority/execution boundary is audited.** Filesystem activity performed *inside* an already-authorised `process.exec`, within its mounted workspace, is not individually brokered and therefore not individually audited. A single `process.exec` record may cover many internal filesystem changes.
>
> What remains guaranteed: **nothing crossed *out* of the sandbox unrecorded.** Network egress, credential use, artifact creation, process spawn, and every `fs.*` tool call are brokered and audited. The absence of such a record still means the effect did not cross the boundary.

Consequently `SANDBOX.md` §4a states plainly that `process.exec` argv scoping and executable hashing are **blast-radius and auditability controls, not confinement**, and that the sandbox — not the allowlist — is the boundary for code an interpreter loads from the workspace.

Everything else in ADR-0017 stands: audit and telemetry are separate systems with different owners and guarantees; audit is written by `dwkd-authority` synchronously before the effect; records carry the canonical action, matched rule and `policy_hash`; no phone-home at any setting; `doctor` verifies facts rather than settings.

## Consequences

**Positive.** The documentation now matches the mechanism. A reviewer reading the audit chain will not over-infer.

**Negative.** Forensics after a suspicious `process.exec` requires the workspace diff, not the audit log alone. Mitigations already specified: `require_artifact_capture` on workspace writes, workspace revision recorded in checkpoints, and `PATCH` artifacts for changes crossing a workspace boundary.

**Future option, not V1:** per-file visibility inside an exec would require intercepting filesystem syscalls in the sandbox (a FUSE overlay or seccomp-notify). That is a substantial subsystem with its own performance and correctness costs, and it is not justified by the current threat model, where the sandbox is the boundary.

## Alternatives considered

- **Keep the broad claim.** Overclaiming in the one document whose value is that it can be trusted.
- **Mount per-file rather than per-directory.** Not expressible with container mounts at the granularity capabilities use.
- **Deny `process.exec` when sub-workspace `fs.*` scoping is configured.** Defensible and very restrictive; recorded as a future policy option rather than a default.

