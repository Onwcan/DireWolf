# ADR-0006: Capabilities are the vocabulary; policy is the decision; both are required

**Status:** Accepted · amended by [ADR-0028](0028-policy-input-ownership.md) · **Date:** 2026-09-11

> **AMENDED by [ADR-0028](0028-policy-input-ownership.md).** This ADR defines the decision function. ADR-0028 adds the requirement that every *input* to that function is derived and stored kernel-side — without which taint-, origin- and privacy-conditioned rules are advisory.

## Context

Two common models are each insufficient alone. Risk levels (`low`/`medium`/`high`) describe an action in the abstract and cannot express "may read this directory but not that one" — which is where the real distinctions live. Pure capability systems answer "may you do this?" but not "should you, right now, given this context, in this environment, with this taint level?"

## Decision

**Both gates, independently, always:**

```
final_allow = policy_allows ∧ capability_covers ∧ budget_permits ∧ binding_intact
```

- **Capabilities** are specific and scoped (`fs.write:/workspace/src?max_bytes=10485760`), form a `⊑` lattice, and delegate only by attenuation. Risk classes survive as *metadata policy rules may match on*, never as an authority source.
- **Policy** is a pure deterministic function over a canonical action returning `ALLOW | DENY | REQUIRE_APPROVAL` plus a rule id, source location and explanation.
- **Canonicalisation precedes policy.** Policy matches inode identity and resolved IP sets, never model-supplied strings.
- **No DSL in V1.** Ordered TOML rules, fixed typed predicate fields, deny-by-default, mandatory `default` rule, no loops or user functions.
- **No LLM anywhere in the decision path.** A model may summarise a request for a human; it may never decide.
- **Sandbox and policy are orthogonal.** Choosing isolation never skips a check.

## Consequences

Two independent things must be true for an action to proceed, so a bug in either is not a full bypass. Policy stays readable and auditable, and every decision is explainable with a file and line. Capability ceilings deny by shape rather than by blocklist — an agent with no `network.*` is immune to every exfiltration-by-request attack without anyone anticipating the specific attack.

Cost: two concepts to learn; some denials require reading both the capability set and the rule to understand, which the `policy explain` output is designed to present together.

## Alternatives considered

- **Rego / Cedar / CEL.** Capable, and each adds an evaluator to secure, a language to learn, a fuzz target, and the ability to write rules nobody can reason about. Deferred with explicit trigger conditions in POLICY.md §3.
- **Capabilities only.** Cannot express context-dependent conditions like taint level or unattended origin.
- **Policy only.** Every rule would have to re-derive scope, and scope is where the distinctions live.
- **LLM-judged approvals.** A comparable system shipped this as its default and it was defeated by interpolating attacker text into the reviewer's prompt. Categorically rejected.

