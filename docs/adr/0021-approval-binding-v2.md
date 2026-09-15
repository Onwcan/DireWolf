# ADR-0021: Approval binding v2 — taint, privacy class and obligations are bound

**Status:** Accepted · **Date:** 2026-09-12 · **Supersedes:** [ADR-0007](0007-approval-semantics.md)

## Context

ADR-0007 bound an approval to `{verb, resource_identity, canonical_args, workspace_id, environment_profile_id, credential_handles, agent_id, scope_discriminant}`.

Review finding H4: the run's **provenance state** was absent. The attack is patient and simple — early in a run, while untainted, trigger a `REQUIRE_APPROVAL` action; the human sees a prompt with no taint warning and approves; the agent then reads a hostile page and spends the approval inside its TTL. Re-canonicalisation checks the *resource*, not the run's provenance, so no drift is detected. Since the approval UI calls taint "the single most decision-relevant fact," omitting it from the binding made the warning decorative.

Also absent: the **obligations** the ALLOW carried (`network_deny`, `read_only_workspace`), so an approval granted under a constrained rule could be spent under a later, looser match; and `privacy_class`.

## Decision

```
binding_hash = SHA256(canonical_cbor({
    verb,
    resource_identity,        // (dev,ino) for paths; (path,sha256) for executables;
                              // resolved IP set + SNI for hosts
    canonical_args,           // normalised argv / normalised request
    workspace_id,
    environment_profile_id,
    credential_handles,       // sorted
    agent_id,
    scope_discriminant,
    taint_level,              // NEW — the run's provenance state at grant time
    privacy_class,            // NEW
    obligations,              // NEW — sorted
}))
```

**Re-canonicalisation immediately before execution remains mandatory**, and now re-checks all eleven fields. Drift in any of them denies with `approval_binding_drift`.

Everything else in ADR-0007 stands: `not_after` mandatory with no "forever" representation, `max_uses` default 1 burned atomically, `agent_id` non-transferability, kernel-rendered prompts with model prose quarantined, unattended `REQUIRE_APPROVAL` degrading to `DENY`, standing grants as separate listed revocable 90-day-capped objects.

Two amendments from review, recorded here:

- **Scope breadth and `max_uses` scale together.** `max_uses = 1` on a *shape*-describing scope (`ExecutableAndArgv`) reintroduces the fatigue the broader scope existed to remove. The shipped profile uses `max_uses = 20` with a 1-hour TTL for that scope.
- **`PathSet` scope added** — one prompt, one binding over a sorted set of inode identities, so deleting three files is one decision. Adding a fourth file invalidates it.

## Consequences

An approval now means "this action, by this agent, in this environment, with these constraints, **while the run is in this provenance state**." Taint rising mid-run invalidates outstanding approvals granted while clean, which is the correct and slightly inconvenient behaviour.

Cost: more re-prompting in runs whose taint changes. Mitigated by taint being tiered and reversible ([ADR-0028](0028-policy-input-ownership.md), `CONTEXT.md` §5) rather than monotonic — without that, this binding change alone would have made long runs unusable.

## Alternatives considered

- **Bind only `taint_level` and not obligations.** Leaves the looser-later-match path open.
- **Warn on taint change rather than invalidate.** A warning nobody sees at 2 a.m. is not a control.
- **Re-prompt only for high-risk classes on taint change.** Plausible future refinement; needs M3.5 data on how often taint actually changes mid-run.

