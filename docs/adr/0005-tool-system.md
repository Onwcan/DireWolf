# ADR-0005: Declarative tool registry, policy-driven visibility, no shell-string tool

**Status:** Accepted · visibility timing superseded by [ADR-0026](0026-tool-visibility-and-cache-stability.md) · **Date:** 2026-09-11

> **PARTIALLY SUPERSEDED by [ADR-0026](0026-tool-visibility-and-cache-stability.md).** Also note: point 4 below says "V1 ships ~15" tools. The frozen count is **18**, and the canonical inventory is [TOOL_SYSTEM.md](../TOOL_SYSTEM.md) §3 — the body text is left unedited because accepted ADRs are immutable. The principle — tool visibility is a policy output, denial is structural — stands and is unchanged. The *timing* ("before each model call") does not: recomputing per turn mutates the byte-stable cached prefix. Visibility is now fixed at admission and may only narrow, with narrowing taking effect at the next cache boundary.

## Context

Three recurring problems: import-time self-registration makes the tool set depend on import order and unanswerable statically; denied tools are usually handled by asking the model to refuse, which delegates enforcement to the untrusted component; and a `bash(command: string)` tool makes canonical argv — which approvals must bind to — impossible to compute reliably.

## Decision

1. **Explicit declarative registration.** `registry.register(definition, handler)` assembled at startup, dumpable with `direwolf tools list --json`. No import side effects.
2. **Tool visibility is a policy output.** Before each model call the kernel returns the currently-permitted tool set, and only those schemas are sent. A denied tool is *invisible*, not refused. `REQUIRE_APPROVAL` tools stay visible, annotated, so the agent can plan around the friction.
3. **No shell-string tool.** `process.exec` takes `argv` as an array. String-to-shell is argument injection with extra steps.
4. **Footprint ladder.** Every tool costs tokens on every turn forever. Before adding a core tool: existing tool → skill → MCP server → plugin → core tool with an ADR note. V1 ships ~15.
5. **Rich denials.** A denial returns the rule, the reason and the approval shape that would satisfy it — model-readable, so the agent stops retrying and asks the human for the right thing.

## Consequences

The model cannot call what it cannot see, which is structural rather than cooperative. Turn cost stays bounded. Approvals can bind to canonical argv. Denials become teaching signals.

Cost: a `ListVisibleTools` round trip per turn (cheap, cacheable within a turn); tool authors must express work as argv rather than shell pipelines, which is occasionally inconvenient and always safer.

## Alternatives considered

- **Send all schemas, let policy reject at call time.** Wastes turns, wastes tokens, and teaches the model that denial is negotiable.
- **Ask the model to honour a deny list in the prompt.** Enforcement by an untrusted component. Rejected.
- **Provide `bash` for convenience.** Rejected on approval-binding and injection grounds. Skills can compose multi-step work from argv calls.

