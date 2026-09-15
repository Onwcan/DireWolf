# ADR-0023: DWKP rejects unknown fields; forward compatibility is for DWCP and the event log

**Status:** Accepted · **Date:** 2026-09-12 · **Supersedes:** the compatibility rules of [ADR-0016](0016-protocol-versioning.md) as applied to DWKP

## Context

ADR-0016 stated a single blanket rule across all three protocols: "unknown fields are preserved and ignored; receivers never reject on an unknown key."

Review finding M3: that is correct for a client protocol and for an event log that must outlive its code, and **wrong for the authority boundary**. On DWKP it is a parser-differential surface (duplicate keys, keys differing only by Unicode normalisation, fields one side interprets and the other ignores) and it makes field-addition downgrades silent. ADR-0016's own adversarial test list includes "duplicate keys," which is an admission that the blanket rule does not fit.

## Decision

Compatibility policy is now **per protocol**, because the protocols have different threat models.

| Protocol | Unknown fields | Unknown operations | Rationale |
|---|---|---|---|
| **DWKP** (runtime ⇄ authority) | **REJECT** — `PROTOCOL_SCHEMA_VIOLATION`, audited | **REJECT** | The authority boundary. Both peers ship together; there is no version skew to tolerate. Strictness removes a parser-differential class outright. |
| **DWCP** (clients ⇄ gateway) | Preserved and ignored | Logged and skipped | Third-party and older clients are real; skew is expected. |
| **Event log** | Retained verbatim | Retained verbatim, skipped by projectors | Events outlive the code that wrote them. Non-negotiable. |
| **DWWP** (remote workers) | **REJECT**, as DWKP | **REJECT** | Deferred, but the policy is fixed now so it cannot drift: a worker is an authority peer, not a client. |

Additional DWKP strictness: duplicate keys rejected; keys NFC-normalised before comparison and any key differing only by normalisation rejected; canonical JSON (RFC 8785) required for anything hashed; frames capped at 1 MiB; depth-limited.

Version negotiation is unchanged: the handshake picks the highest mutually supported version, and an unsupported version returns `PROTOCOL_VERSION_UNSUPPORTED` naming the supported range.

## Consequences

**Positive.** A whole bug class disappears from the boundary that matters most. Because runtime and authority ship as one release, strictness costs nothing operationally.

**Negative.** A DWKP change becomes a coordinated release rather than a rolling one. That is acceptable and arguably desirable for an authority protocol. Mixed-version runtime/kernel is now an error rather than a degraded mode — `doctor` detects and reports it.

**ROADMAP M2 acceptance changes accordingly:** "unknown fields preserved" is no longer a blanket acceptance criterion; M2 must demonstrate DWKP rejection *and* DWCP/event-log preservation as separate tests.

## Alternatives considered

- **Blanket strictness everywhere.** Breaks the event log's core requirement.
- **Blanket permissiveness.** The status quo ante; rejected above.
- **Strict DWKP with a negotiated "lenient mode."** A negotiable safety property is not a safety property.

