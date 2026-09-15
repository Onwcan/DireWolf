# ADR-0020: Typed `ModelCall`; the kernel renders the provider request

**Status:** Accepted · **Date:** 2026-09-12 · **Supersedes:** [ADR-0002](0002-provider-abstraction.md)

## Context

ADR-0002 had provider adapters in the runtime build a complete `HttpRequestSpec` — method, path, headers, body — which the kernel forwarded after validating only the upstream origin.

Phase 0 security review (H1) showed this makes `model.call` a **transitive, unpoliced, bidirectional network capability**. A run holding no `network.*` at all could POST attacker-chosen bytes to an allowlisted vendor endpoint and read the reply, bypassing the egress pipeline, per-run byte and host budgets, output capping, MIME classification and redaction. The capability grammar never said `model.call` implied network access, and it should not have to.

## Decision

**The runtime supplies semantics. The provider profile supplies form. The kernel performs the call.**

```
ModelCall {
    provider_profile_id,
    model,
    messages[],            // typed, structured
    tool_schemas[],
    sampling_params,       // bounded, enumerated fields
    privacy_class, run_id, budget_lease
}
```

The runtime **cannot** express an arbitrary header, an arbitrary body, or an arbitrary endpoint through `model.call`.

`dwkd-broker` renders the provider-specific HTTP request from a **declarative provider profile** (path, method, header set, body template, usage JSON-pointers). `dwkd-authority` selects and authorises the origin, enforces the privacy class, authorises the credential, and meters and audits the result. Response bodies are subject to the same size caps, MIME classification, artifact spill and redaction as any other content crossing into the Cognition Plane — before this change, a provider response was the one input that skipped all of it.

Provider adapters remain in `runtime/direwolf/providers/` and remain the only place a provider is named. Their job narrows from *building a request* to *shaping semantics and parsing canonical deltas*.

## Consequences

**Positive.** `model.call` is no longer a network capability in disguise. Privacy-class enforcement is complete. A malicious or manipulated provider adapter cannot choose an endpoint or smuggle a header.

**Negative.** Adding a provider now requires a profile change in kernel-side configuration, not only a Python adapter — a slower path, deliberately. Providers whose request shape cannot be expressed as a declarative template need a profile-format extension, which is a reviewed change. Provider-format churn now touches configuration the kernel reads.

**Unchanged from ADR-0002:** the loop speaks only `CanonicalRequest`/`CanonicalDelta`; capability negotiation with declared degradation; a model without native tool use is *ineligible* for tool-bearing runs rather than shimmed; CI forbids provider names outside `providers/`.

## Alternatives considered

- **Keep `HttpRequestSpec`, add an allowlist of permitted headers.** A blocklist by another name; the body remains arbitrary.
- **Keep `HttpRequestSpec`, treat `model.call` as implying `network.*`.** Honest, and it makes every model-using run network-capable. Rejected — that is a much larger grant than the task needs.
- **Kernel builds requests in Rust code per provider.** Puts provider churn inside the TCB. The declarative profile is the compromise.

## Revisit if

A provider we need cannot be expressed declaratively without a profile format that is itself Turing-complete. At that point the profile has become code and should be reconsidered as such.

