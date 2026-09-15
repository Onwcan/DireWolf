# ADR-0016: Three protocols, additive evolution, forward-compatible readers

**Status:** Accepted · DWKP compatibility superseded by [ADR-0023](0023-dwkp-strict-schema.md) · **Date:** 2026-09-11

> **PARTIALLY SUPERSEDED by [ADR-0023](0023-dwkp-strict-schema.md).** Three separate protocols, version negotiation, canonical JSON for hashed bytes, and verbatim retention of unknown *events* all stand. The blanket "unknown fields preserved and ignored" rule does not apply to DWKP, which now rejects unknown fields and unknown operations.

## Context

Protocol and event data outlive the code that wrote them. A client from six months ago must not break against today's server, and an event file from last year must still be readable — including by a projector that has never heard of its schema.

## Decision

**Three protocols, deliberately separate** because they have different threat models: **DWKP** (runtime ⇄ kernel, the trust boundary), **DWCP** (clients ⇄ gateway, authenticates humans, carries no authority), **DWWP** (remote workers, deferred).

Rules:

1. **Unknown fields preserved and ignored.** Receivers never reject on an unknown key.
2. **Unknown message types logged and skipped**, never fatal.
3. **New fields optional with a documented default.** Removal or retype requires a `schema_version` bump.
4. **Explicit envelope version `v`** with negotiation at handshake; an unsupported version produces `PROTOCOL_VERSION_UNSUPPORTED` naming the supported range — a clean actionable failure rather than a parse error.
5. **Unknown events retained verbatim** in the log; major bumps ship read-time upcasters; **stored events are never rewritten** — rewriting history to fit new code is what an audit log must not do.
6. **Projections rebuildable** from the log at any time: the escape hatch for projection shape changes.
7. **Canonical JSON (RFC 8785)** wherever bytes are hashed, so key ordering cannot change a binding hash or break an audit chain.
8. **Compatibility tested both directions in CI**: a corpus of recorded events from every released version must parse on `main`, and a current client must interoperate with the oldest supported server.

JSON for V1; the framing layer carries a content-type byte so a binary encoding can be negotiated later without a protocol revision.

## Consequences

Old clients survive new servers, and when they cannot, they fail legibly. Event logs remain readable for years. Debugging is possible with `jq`.

Cost: JSON is larger and slower than a binary encoding (irrelevant at our message rates); upcasters accumulate and need a deprecation policy (two minor versions).

## Alternatives considered

- **One protocol for everything.** Would force the same auth and trust model on a human-facing channel and the authority boundary.
- **Protobuf/gRPC from the start.** Better wire efficiency, worse debuggability, heavier codegen, and a larger dependency in the TCB.
- **No versioning until needed.** Retrofitting version negotiation onto a deployed protocol is exactly the migration everyone regrets.

