# ADR-0026: Tool visibility is fixed at admission and may only narrow

**Status:** Accepted · **Date:** 2026-09-12 · **Supersedes:** the visibility-timing portion of [ADR-0005](0005-tool-system.md)

## Context

ADR-0005 established that tool visibility is a policy output — denied tools' schemas are not sent to the model, so denial is structural rather than a request the model is asked to honour. That principle stands and is one of the better decisions in the package.

Its *timing* did not. ADR-0005 recomputed the visible set "before each model call," from a context including taint level, budget snapshot and environment availability — all of which move mid-run. Review finding C3: tool definitions sit at context section 4, which `CONTEXT.md` §3 declares **byte-stable for the life of a run**, with compaction "the only sanctioned cache break," enforced by a test asserting the prefix hash is constant across 50 turns. Recomputing visibility per turn mutates the cached prefix — a full prompt-cache invalidation on what the same document calls the single largest cost lever in a long-running agent.

## Decision

**Visibility is computed once, at run admission**, from the frozen capability grant and a policy preflight.

1. **At admission:** `dwkd-authority` returns the visible `ToolDefinition[]`. This set enters the stable prefix.
2. **During the run it may only narrow** — never widen. Widening would require a capability the run does not hold, which admission already froze.
3. **Narrowing does not take effect in the prefix immediately.** A tool removed mid-run (MCP server died, environment unavailable, budget dimension exhausted) stays visible to the model until the **next cache boundary** — a compaction, or run end. Removing it immediately would break the prefix for a saving that is at best cosmetic.
4. **Policy still evaluates every actual invocation at execution time.** Visibility is a *cost and guidance* optimisation. It has never been the enforcement mechanism and is not one now.

### Emergency revocation

**Revocation blocks execution immediately, regardless of what the model can still see.**

When a capability is revoked, a standing grant is withdrawn, or a budget is exhausted mid-run, `dwkd-authority` denies the affected invocations **from the next call onward**. The stale schema may remain in the model's context until the next compaction; calling it returns a structured denial naming the revocation. There is no window in which a revoked capability is honoured.

This is the correct trade: the model may waste one call on a tool that no longer works, and it learns why from the denial. The alternative — invalidating the prefix on every revocation — pays a large, certain cost to avoid a small, recoverable one.

## Consequences

**Positive.** Cache stability is real rather than aspirational. `ListVisibleTools` stops being a per-turn round trip. The security property is unchanged, because it never depended on visibility.

**Negative.** The model can hold a schema for a tool that will now be denied, so agents must handle denial gracefully — which the structured-denial design (ADR-0005) already requires. Environment-driven narrowing (a dead MCP server) surfaces as denials rather than as a shrinking tool list until the next boundary.

## Alternatives considered

- **Recompute per turn (status quo ante).** Destroys prompt caching.
- **Two-tier prompt with a volatile tool section after the cache boundary.** Possible, and it spends the tool block's ~2 500 tokens on every call instead of reading them from cache. Worse on both cost and complexity.
- **Invalidate the prefix on revocation.** Rare event, large cost, and the denial path already covers it correctly.

