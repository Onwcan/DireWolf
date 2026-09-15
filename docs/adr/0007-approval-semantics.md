# ADR-0007: Approvals bind to a canonical action, are single-use, expiring and agent-bound

**Status:** **Superseded by [ADR-0021](0021-approval-binding-v2.md)** · **Date:** 2026-09-11

> **SUPERSEDED by [ADR-0021](0021-approval-binding-v2.md).** The eight binding fields below omit `taint_level`, `privacy_class` and `obligations`, which allowed an approval granted while a run was clean to be spent after it ingested hostile content (Phase 0 review H4). Retained as a historical record.

## Context

Approval systems fail in three specific ways, all observed in shipped systems: approvals outlive the scope they were reviewed for; approvals are reusable by a different agent than the one that requested them; and the human approves a description written by the model rather than the action that will execute.

## Decision

An approval authorises **one canonical action**, identified by

```
binding_hash = SHA256(canonical_cbor({verb, resource_identity, canonical_args,
                       workspace_id, environment_profile_id, credential_handles,
                       agent_id, scope_discriminant}))
```

with these properties:

- **`resource_identity`, not a path string** — inode+device for files, (path, sha256) for executables, resolved IP set for hosts. A swapped file is a different action.
- **`environment_profile_id` is inside the hash**, so an approval granted for sandboxed execution cannot be spent on host execution.
- **`agent_id` is inside the hash**, so a subagent cannot spend its parent's approval.
- **`not_after` is mandatory.** There is no representation for "forever."
- **`max_uses` defaults to 1**, burned atomically with execution.
- **Re-canonicalise and re-compare immediately before execution.** Drift → deny.
- **The prompt is rendered by the kernel from canonical data.** Model prose appears only in a visually separated region labelled untrusted.
- **No "always allow" checkbox.** Broadening requires `direwolf grant create` — a separate, listed, revocable, 90-day-capped `StandingGrant` that by default does not apply in a run that has ingested untrusted content.
- **Unattended `REQUIRE_APPROVAL` degrades to `DENY`**, never to allow.

## Consequences

Authority cannot drift across a long run: after 40 approvals, the run's capability set is byte-identical to admission, because approvals authorise actions rather than granting capabilities. Approval fatigue is a measured metric (`approval.latency` p50 < 2 s is an alarm), and the response is narrower policy scope rather than fewer prompts.

Cost: more prompts than systems with blanket grants. This is the friction the product is selling, and if it proves unusable the fix is better scoping, not a bypass.

## Alternatives considered

- **Session-scoped or "elevated mode" approvals.** Convenient, and the mechanism behind several published scope-drift advisories.
- **Approve by tool name.** Far too coarse: `process.exec` approved once is a shell.
- **Trust the model's description.** Direct path to approval phishing.

