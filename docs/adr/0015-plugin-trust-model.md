# ADR-0015: No plugins in V1; when they ship, out-of-process with granted capabilities

**Status:** Accepted · **Date:** 2026-09-11

## Context

A plugin system is the fastest way to undo a security architecture. One comparable system concedes plainly that "native plugins run in-process and are not sandboxed" — at which point installing a plugin grants it everything the host process has, and the capability model becomes decorative.

## Decision

**V1 ships no plugin system.** Extension happens through MCP (already sandboxed and capability-scoped) and skills (already validated).

When plugins ship (V2 at the earliest):

1. **Installation grants no authority.** It registers declarations; authority arrives only through operator-granted capabilities.
2. **Out-of-process, always.** `kind = "inprocess"` is not an accepted manifest value. There is no escape hatch, because an escape hatch in a trust boundary is a door.
3. **Kernel-spawned and sandboxed**, with its own capability set, no network unless granted, no credentials (egress injection only).
4. **Plugin results are untrusted content** — same caps, sanitisation and provenance labelling as any tool output. A plugin is a tool provider, not a peer.
5. **Capability grants are per-plugin, per-capability, revocable, listed**, and a version bump requesting more triggers re-consent.
6. **A deliberately small host API.** No policy access, no capability minting, no approval creation, no kernel socket, no secret access, no execution-environment registration, and **no hook on the enforcement path** — `run.completed` is fine, `tool.about_to_execute` is not.
7. **No implicit updates.** An update is an operator action.

## Consequences

V1 has fewer extension points and a boundary that holds. MCP may prove sufficient, in which case **not shipping a plugin system is a success, not a gap.**

Cost: some integrations are inconvenient until V2; out-of-process hosting adds IPC overhead to plugin tools.

## Alternatives considered

- **In-process plugins with a review process.** Review does not constrain a malicious or compromised dependency at runtime.
- **WASM-only plugins.** Attractive for pure computation, insufficient for plugins needing IO. Reserved as a second host kind, not committed.
- **Ship plugins in V1.** Would mean shipping the largest risk surface before the boundary has been tested.

