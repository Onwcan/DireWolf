# ADR-0029: DireWolf ships as a complete runtime; the authority plane is decoupled but not a separate product

**Status:** Accepted · **Date:** 2026-09-12

## Context

Phase 0 review raised the sharpest product question in the package (B6): the genuinely novel artifact is the authority plane, while the cognitive runtime scores "B (planned)" against two mature competitors with a combined ~630 k GitHub stars. Both competitors state in their own documentation that only the OS is a real boundary; neither has built one. Shipping `dwkd` as a standalone authority daemon that other runtimes delegate to would turn competitors into distribution.

Against that: DWKP as drafted is coupled to DireWolf's own runtime shape (`ListVisibleTools`, `SpawnSubagent`, `McpOpen`, `ChannelSend` are agent-runtime operations, not authority primitives), and a security daemon with no first-party consumer has no forcing function for correctness.

## Decision

**DireWolf remains a complete autonomous agent runtime.** The first-party runtime is the flagship and the reference consumer. Phase 1 does not pivot to a standalone security-daemon product.

**But the authority plane is designed not to be unnecessarily coupled to it.** Three concrete obligations, testable at M3:

1. **Layer the DWKP surface.** Operations divide into:
   - **Authority primitives** — `AdmitRun`, `ReleaseRun`, `AcquireLease`, `ToolInvoke`, `ToolCancel`, `CanonicalPreview`, `QueryBudget`, `QueryAuthority`, `QueryInvocationStatus`, `ModelCall`, `CreateArtifact`, `ReadArtifact`, `Heartbeat`. Nothing here presumes DireWolf's loop, context engine or orchestration model.
   - **Runtime-shaped conveniences** — `ListVisibleTools`, `SpawnSubagent`, `McpOpen`/`McpClose`, `ChannelSend`. Useful, first-party, and explicitly marked as the non-primitive layer.
2. **No authority primitive may depend on a runtime-shaped concept.** `SpawnSubagent` must be expressible as `AdmitRun` plus an attenuation request; if it ever cannot be, the primitive layer has leaked and that is an ADR-worthy regression.
3. **`kernel.db` stores no runtime-model concepts.** It stores principals, agents, runs, capabilities, approvals, budgets, policy inputs and audit. It does not store turns, messages, context manifests or task graphs — those are `runtime.db`'s.

This is a *design constraint*, not a shipped second product. We are keeping the option open at low cost, not exercising it.

## Consequences

**Positive.** The team builds one coherent product with a real user. If the authority plane later proves more valuable than the runtime, extracting it is a packaging change rather than a rewrite. The layering also improves the first-party design: primitives that do not presume our loop are primitives we can reason about.

**Negative.** Some duplication between the layers. A small ongoing discipline cost in reviews ("is this a primitive or a convenience?"). We forgo the distribution play in the near term, which — if the competitors' security record continues as it has — may prove to have been the higher-value path. We accept that risk consciously rather than by omission.

**Not decided here:** whether to ever ship the authority plane separately. That needs evidence from M3.5 and from whether anyone outside the project asks for it.

## Alternatives considered

- **Pivot to a standalone authority daemon now.** Strongest distribution story, no first-party forcing function for correctness, and it asks two large projects to adopt a boundary neither has prioritised. Premature on zero evidence of demand.
- **Ignore decoupling; optimise purely for the first-party runtime.** Cheaper now; forecloses the option entirely, since retrofitting a general protocol onto a specialised one is a rewrite.
- **Ship both from day one.** Doubles the surface before either is proven.

## Revisit if

An external project asks to delegate to DWKP; or M3.5 shows the runtime is not differentiating while the authority plane is; or the primitive/convenience layering starts requiring exceptions.
