# ADR-0032: The wire contract — framing, strict JSON, and RFC 8785 as the one canonical encoding

**Status:** Accepted · **Date:** 2026-09-15 · **Amends:** [ADR-0021](0021-approval-binding-v2.md) and [ADR-0022](0022-approval-response-authentication.md) (the encoding under the hash and the MAC), [ADR-0023](0023-dwkp-strict-schema.md) (makes its strictness list concrete) · **Refines:** [ADR-0016](0016-protocol-versioning.md)

> ADR-0021, ADR-0022 and ADR-0023 stand. This record changes one word in the
> first two — `canonical_cbor` becomes `jcs` — and replaces the adjectives in
> the third ("depth-limited", "NFC-normalised", "1 MiB cap") with numbers,
> orderings and error codes that two implementations can be tested against.

## Context

M2 implements the wire. Implementing it exposed four places where the Phase 0/0.1
corpus disagreed with itself or was too vague to implement twice identically:

1. **Two canonical encodings.** [PROTOCOL.md](../PROTOCOL.md) §7 says RFC 8785
   canonical JSON is used "wherever bytes are hashed — binding hashes, audit
   chaining, capability MACs". ADR-0021 and [APPROVALS.md](../APPROVALS.md) §2
   specify `SHA256(canonical_cbor({...}))` for the binding hash, and ADR-0022
   specifies `HMAC(device_key, canonical_cbor({...}))` for the remote approval
   response. A binding hash computed two ways is two binding hashes; whichever
   was implemented second would silently disagree with the first.
2. **Two frame layouts.** PROTOCOL.md §2 describes "4-byte big-endian length +
   canonical JSON"; §7 says "the framing layer carries a content-type byte".
3. **Unspecified limits.** ADR-0023 says "depth-limited" without a depth, "keys
   NFC-normalised before comparison" without saying whether a key is rewritten
   or the message rejected, and nothing about numbers — where JSON
   implementations disagree most (Python reads `9007199254740993` exactly;
   JavaScript and a double-based Rust reader do not).
4. **No error model.** A malformed request must not be reported as a policy
   denial, and the two languages must fail the same input the same way, which
   requires naming the failures.

Nothing is hashed or MACed yet (approvals are M6, audit is M3). This is the last
point at which the choice costs nothing.

## Decision

### 1. Framing

```
+----------------------+-----------------+------------------------+
| length: u32, BE      | content type: u8| body: `length` bytes   |
+----------------------+-----------------+------------------------+
```

- `length` counts the body only; valid range **1 ..= 1 048 576** (1 MiB).
- Content type `0x01` is UTF-8 JSON, the only one defined.
- `length == 0` → `PROTOCOL_FRAME_EMPTY`. `length > 1 MiB` →
  `PROTOCOL_FRAME_TOO_LARGE`, decided **from the 5-byte header, before any body
  byte is buffered**. Any other content type → `PROTOCOL_CONTENT_TYPE_UNSUPPORTED`.
  End of stream inside a header or body → `PROTOCOL_FRAME_TRUNCATED`.
- A decoder that has reported an error is **poisoned**: every later call repeats
  the error. A length-prefixed stream has no resynchronisation point, and
  guessing one is how a peer smuggles a second frame. A framing error is
  connection-fatal.

### 2. Strict JSON, and the order faults are detected

Every family reads JSON with one lexer, in this order, stopping at the first fault:

| # | Rule | Error |
|---|---|---|
| 1 | Whole body is well-formed UTF-8; no lossy decoding | `PROTOCOL_INVALID_UTF8` |
| 2 | Exactly one RFC 8259 value; no byte-order mark, no comments, trailing commas, `NaN`/`Infinity`, raw control characters, or lone surrogate escapes (`\ud800` alone) | `PROTOCOL_INVALID_JSON` |
| 3 | Nesting depth ≤ **32** (a top-level object is depth 1), checked **before** descending | `PROTOCOL_MAX_DEPTH_EXCEEDED` |
| 4 | No two keys in one object that are byte-identical after unescaping, checked when the second key is read and **before its value is parsed** | `PROTOCOL_DUPLICATE_KEY` |
| 5 | No two keys in one object that are equal under Unicode **NFC** | `PROTOCOL_NORMALIZATION_COLLISION` |
| 6 | Numbers inside the family's domain (below) | `PROTOCOL_NUMBER_OUT_OF_DOMAIN` |

On rule 5: keys are **not rewritten**. A sender need not send NFC; what is
rejected is ambiguity — two members a reader in another language could merge.
String *values* are never normalised. A key that differs from a *declared* field
only by normalisation is also rejected (`PROTOCOL_NORMALIZATION_COLLISION`),
rather than reported as an unknown field, so the error names the actual attack.

**Number domains.**
- **DWKP:** integers only, written without fraction or exponent, magnitude
  ≤ 2^53 − 1. `1.0`, `1e3` and `9007199254740992` are rejected, not rounded.
  `-0` is read as `0`. Consequence: a DWKP value has one meaning in every
  language, and budgets, costs and limits carried by DWKP are integers in
  minor units.
- **DWCP and event records:** any finite I-JSON (RFC 7493) number, so extension
  data survives. An integral value within the safe range is always an integer
  after decoding, so `1.0` and `1` are one value. Known fields are still typed.

### 3. Compatibility is a property of the family, and of the decoder

| Family | Unknown field | Unknown message | Implemented by |
|---|---|---|---|
| DWKP | Reject — `PROTOCOL_SCHEMA_VIOLATION` / `UNKNOWN_FIELD` | Reject — `PROTOCOL_UNKNOWN_OPERATION` | per-type `reject` policy |
| DWCP | Preserved, re-emitted | Envelope validated, payload preserved | per-type `preserve` policy |
| Event log | Preserved | Record retained **byte for byte**, classified as unknown | raw bytes kept alongside any typed view |
| DWWP | Not implemented. ADR-0023's REJECT policy stands. | | |

There is no global unknown-field switch. The policy is part of each generated type.

### 4. RFC 8785 (JCS) is the only canonical encoding

- **Everything DireWolf hashes, MACs or compares as bytes is the JCS encoding of
  a decoded, typed value.** Received bytes are never hashed as received.
- **ADR-0021 amended:** `binding_hash = SHA256(jcs({...eleven fields...}))`.
  The eleven fields are unchanged. M2 does **not** encode the binding; M6 does,
  and must use JCS.
- **ADR-0022 amended:** `HMAC(device_key, jcs({request_id, binding_hash, decision,
  scope, ttl, max_uses, device_id, response_nonce, not_after}))`. Fields
  unchanged; not encoded in M2.
- A future content type (`0x02`, say MessagePack) may change *transport*
  encoding. It does not change what is hashed: hashes remain JCS over the
  logical value.
- Receivers do not require canonical input; encoders always emit it, and both
  DWKP encoders (Rust and Python) re-decode their own output before returning
  it, so neither can emit a message the other side's decoder would reject.

The implementation follows RFC 8785 exactly: keys sorted by UTF-16 code units;
only `"`, `\` and U+0000–U+001F escaped, using the short forms where they exist;
numbers by ECMAScript `Number.prototype.toString`, including round-half-even on
the one tie RFC 8785 Appendix B tests. It is verified against RFC 8785's
Appendix B and §3.2 examples and against 8,915 doubles serialised by V8
(`tests/protocol/`).

### 5. Error model

Thirteen codes — the six above plus `PROTOCOL_FRAME_EMPTY`, `_FRAME_TOO_LARGE`,
`_FRAME_TRUNCATED`, `_CONTENT_TYPE_UNSUPPORTED`, `_VERSION_UNSUPPORTED`,
`_UNKNOWN_OPERATION`, `_SCHEMA_VIOLATION` — and, for schema violations, eleven
violation kinds (`UNKNOWN_FIELD`, `MISSING_FIELD`, `FORBIDDEN_FIELD`,
`WRONG_TYPE`, `NULL_NOT_ALLOWED`, `OUT_OF_RANGE`, `TOO_LONG`, `INVALID_FORMAT`,
`UNKNOWN_VARIANT`, `TOO_MANY_ITEMS`, `INCONSISTENT`) with a JSON Pointer to the
offending member.

- Codes, violations and paths are the contract; both languages must produce the
  same triple for the same single-fault input, and the shared vectors test it.
  `detail` is diagnostic text, bounded at 512 characters, and not a stable API.
- `PROTOCOL_VERSION_UNSUPPORTED` carries the supported range.
- `null` is never a value: an optional field is omitted, not `null`.
- **A protocol error is not a policy denial.** `direwolf.protocol.error` means
  nothing was evaluated because there was nothing well-formed to evaluate. It is
  a different message from any future denial.

### 6. Versions

`v` (envelope) and `schema_version` (per message) are integers 1..=65535.
DWKP never treats an unsupported version as a supported one: an unsupported `v`
or `schema_version` is `PROTOCOL_VERSION_UNSUPPORTED`, naming the range. The
handshake picks the highest version both peers support and refuses anything
below the receiver's configured minimum. This build supports envelope version 1
only.

### 7. Reserved operations have no wire form

The DWKP operation inventory ([DWKP_OPERATIONS.md](../DWKP_OPERATIONS.md),
generated from `dwk-proto`) lists the operations Phase 0/0.1 justified. M2
**defines** four (`Handshake`, `Heartbeat`, `AcquireLease`, `ReleaseLease`) and
**reserves** sixteen. A reserved operation has no message name, no schema and no
decoder; sending anything named like one is `PROTOCOL_UNKNOWN_OPERATION`, exactly
as for an invented name. It gains a wire form only in its owning milestone,
through the review in [CONTRIBUTING.md](../../CONTRIBUTING.md) "Changing the protocol".

### 8. What decoding does not establish

Envelope identifiers are checked for **format** (a prefixed UUIDv7), not
uniqueness or existence. `ts` is advisory and never an input to ordering or
authority. `session_id` and `epoch` are **claims** compared against kernel state
from M3 ([ADR-0028](0028-policy-input-ownership.md)); no DWKP message carries a
field through which the runtime can assert taint, privacy class, origin, skill
trust or provenance, and a test asserts that none is declared.

## Consequences

**Positive.**
- One canonical encoding, one JSON reader, one error vocabulary. A parser
  differential between the two DWKP peers now needs a bug in the lexer, not a
  disagreement in the specification.
- Every limit in ADR-0023 is a number with a test on both sides of it.
- No CBOR codec enters the trusted computing base.

**Negative.**
- JCS is larger and slower to produce than deterministic CBOR. At DWKP message
  rates (thousands per second, PROTOCOL.md §7) this is not measurable; if it
  becomes so, §4 already separates transport from hashing.
- The DWKP integer-only domain means no fractional values on the authority
  wire, ever, without a new ADR. M6 budget design inherits "integers in minor
  units".
- Depth 32 caps future payload nesting. The deepest M2 message uses depth 3.
- A single bad frame closes the connection. Intended, and it means a buggy
  runtime fails loudly rather than degrading.
- JCS requires ECMAScript number formatting, which neither Rust's nor Python's
  standard formatter produces; both implementations carry a small, heavily
  tested formatter.
- Python's reader normalises with its interpreter's Unicode database (15.0.0 on
  3.12); `unicode-normalization` 0.1.25 uses 17.0.0. Keys built from characters
  assigned after 15.0 can collide in Rust and not in Python. For DWKP this does
  not change accept/reject — every declared key is ASCII, so such a key is
  rejected by both — but it can change which error is reported, and for DWCP it
  can change acceptance. Both versions are pinned by tests; moving either
  reopens this paragraph.

## Alternatives considered

- **Deterministic CBOR (RFC 8949 §4.2) for hashed structures, JSON on the wire.**
  The strongest alternative: compact, binary, well specified. Rejected because it
  puts a second codec and a second canonicalisation into the TCB for structures
  that already arrive as JSON, and because the value must then round-trip
  JSON → typed value → CBOR identically in two languages — a new differential
  surface created to save bytes nobody is short of.
- **Last-duplicate-wins or first-duplicate-wins.** Every JSON library picks one
  and they do not agree; that disagreement *is* the attack.
- **NFC-normalise keys and continue.** Rewrites what the sender sent and hides
  the ambiguity instead of rejecting it.
- **Arbitrary-precision numbers.** Python would accept, JavaScript clients
  would round, and a limit checked on one side would not be the limit enforced
  on the other.
- **Require canonical bytes on receipt.** Adds a rejection class with no security
  benefit once nothing is hashed as received, and makes debugging by hand harder.
- **A resynchronising frame format (magic bytes, escaping).** Useful on lossy
  links; a local socket is not one, and resynchronisation is a smuggling surface.

## Revisit if

- Profiling shows JSON encoding or decoding on the DWKP critical path (then add
  a content type; hashing stays JCS).
- A justified DWKP message needs a non-integer number or nesting deeper than 32.
- The Python runtime moves to an interpreter whose Unicode database matches
  `unicode-normalization`, which closes the gap described above.
