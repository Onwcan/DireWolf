# ADR-0034: No protocol decision consults a Unicode database; DWKP's unknown-field rule carries the property

**Status:** Accepted · **Date:** 2026-09-16 · **Amends:** [ADR-0032](0032-wire-contract-framing-strict-json-and-jcs.md) (retires its lexer rule 5 and the `PROTOCOL_NORMALIZATION_COLLISION` code), [ADR-0033](0033-protocol-source-of-truth-and-tcb-dependencies.md) (its §4 dependency review no longer applies: the reviewed crates are gone) · **Refines:** [ADR-0023](0023-dwkp-strict-schema.md)

> ADR-0023's requirement survives in full: on DWKP, a key that differs from a
> known key only by normalisation must not be interpreted as that key. What
> changes is the mechanism. Rejecting every undeclared member already provides
> it, without a Unicode table, so the table — and the divergence it caused
> between two implementations — is removed rather than pinned.

## Context

M2 implemented ADR-0023's "keys NFC-normalised before comparison" as a rule of
the shared lexer: in **every** protocol family, two keys equal under Unicode NFC
were rejected with `PROTOCOL_NORMALIZATION_COLLISION`. Two problems followed.

**1. The two implementations could disagree.** Normalisation is defined against
a Unicode version. The Rust crate normalised with `unicode-normalization`
(Unicode 17.0.0); the Python runtime normalised with its interpreter's database
(15.0.0 on CPython 3.12). For keys built from characters assigned after 15.0,
one side could see a collision the other did not. The M2 report recorded this
as a known limitation: DWKP accept/reject parity held (by the argument below),
but **DWCP acceptance could differ between languages** — unacceptable for a
protocol whose defining property is forward compatibility across independent
implementations.

**2. The rule was applied where ADR-0023 never put it.** ADR-0023 lists
normalisation strictness under "Additional **DWKP** strictness", beside the
1 MiB frame cap and the depth limit — properties of the authority boundary.
ADR-0032 generalised it to DWCP and to event records, which are required to
*preserve* what they do not understand. A rule that rejects a record because two
of its extension keys normalise alike is a rule that discards an unknown
extension: the opposite of the promise.

The obvious fixes were both unattractive. Pinning one Unicode version means
shipping a normalisation table with the protocol in two languages, and keeping
it in step forever. Restricting the rule to DWKP leaves DWKP's own decision
dependent on a table version, and leaves two implementations that can report
different errors for the same bytes.

## Decision

**No protocol decision in any family consults a Unicode database.**

1. **Duplicate keys are compared as text, byte for byte.** Two members of one
   object with identical names remain `PROTOCOL_DUPLICATE_KEY`, in every family,
   detected by the lexer before the second value is parsed. This is unchanged
   and needs no Unicode data.
2. **Normalisation is never performed on keys or values**, by either
   implementation. Keys that are equal only under NFC are two distinct members.
3. **DWKP rejects every member name it does not declare**
   (`PROTOCOL_SCHEMA_VIOLATION` / `UNKNOWN_FIELD`), which is what makes the
   ADR-0023 property hold: see the argument below.
4. **DWCP and event records preserve such members**, as they preserve any other
   member they do not declare, and re-emit both.
5. **`PROTOCOL_NORMALIZATION_COLLISION` is retired** from the error vocabulary,
   before any release, because nothing can emit it. The wire error set is now
   twelve codes.
6. The crates that existed only to serve the rule — `unicode-normalization`,
   `tinyvec`, `tinyvec_macros` — are removed. **`dwk-proto` has no third-party
   dependency**, so the TCB-destined closure is empty again and
   `architecture.toml`'s authority allowlist returns to `[]`.

### Why rejecting undeclared members is sufficient for DWKP

The property ADR-0023 asks for is that a key differing from a *known* key only
by normalisation must not be taken for that key, and that two keys a reader
might merge must not be accepted.

- Every name DWKP interprets is ASCII: the thirteen envelope members and every
  payload field of every message. Tests in both languages assert this over the
  emitted schemas, so a future non-ASCII field fails the build rather than
  quietly reopening this question.
- ASCII strings are unchanged by NFC, and no non-ASCII character normalises to
  a character that can appear in those names (in Unicode 15.0 exactly three
  characters normalise to ASCII at all: U+037E to `;`, U+1FEF to a backquote,
  and U+212A to `K`).
- Therefore a member name that is not byte-equal to a declared name cannot be
  made equal to one by normalisation. It is undeclared, and DWKP rejects it.
- Nothing merges members: both readers keep an object as an ordered list of
  distinct keys, and neither has "last key wins".

So on DWKP the outcome is the same as before — the message is rejected — and it
is now reached without consulting a table, which means both implementations
reach it identically, for every input, forever.

**The caveat.** This argument depends on DWKP containing no free-form map. Every
DWKP object today is a declared struct. If a DWKP message ever needs a
map-typed field (labels, arbitrary metadata), the question returns for that
field, and the answer must be decided then — most likely by restricting such
keys to ASCII, which is checkable without a Unicode table.

## Consequences

**Positive.**

- The invariant now holds by construction: *same bytes + same protocol version →
  same accept/reject decision, and the same preserved members*, in both
  languages, whatever Unicode version their hosts ship. Shared vectors cover
  DWKP rejection, DWCP preservation and event retention for a colliding pair.
- DWCP and event records keep the extension data they promised to keep.
- The trusted computing base loses its only third-party dependency: about
  30 000 lines of code, including the only `unsafe` in the closure.
  `dwkd-authority` and `dwk-proto` now link nothing third-party, which is the
  strongest form of the ADR-0019 claim.
- One fewer error code, one fewer rule, and no Unicode version to track.

**Negative.**

- A DWKP sender can no longer learn *why* two odd-looking keys were refused: it
  gets `UNKNOWN_FIELD` for the first one rather than a dedicated code. The
  message is still rejected, and the path names the member.
- Two keys that a careless *human* reads as the same string can both appear in a
  DWCP payload. Nothing downstream may treat them as one; that is a property of
  DWCP consumers, and DWCP has always had to treat extension keys as opaque.
- If DWKP later gains a map-typed field, this decision must be revisited (above).
- The M2 report's dependency review in ADR-0033 §4 now describes crates that are
  no longer present. That record stays as written — it is what was decided at
  the time — and this ADR is the amendment.

## Alternatives considered

- **Pin one Unicode version in both languages** (ship a generated table, or
  vendor a normalisation dataset). Correct, and heavy: a table in two languages,
  a regeneration pipeline, and a new question at every Unicode release — all to
  keep a rule that DWKP's field discipline already provides.
- **Restrict the rule to DWKP and keep the tables.** Fixes DWCP, leaves DWKP's
  decision dependent on two host libraries agreeing, and keeps three crates in
  the TCB for a rule that decides nothing DWKP had not already decided.
- **Normalise keys to NFC and continue.** Rejected by ADR-0032 and still
  rejected: it rewrites what the sender sent.
- **Require every DWKP member name to be ASCII as an explicit lexer rule.** The
  same outcome by a longer route: a new error class, a new lexical rule and a
  changed vocabulary, where the existing unknown-field rule already suffices.
  Worth revisiting only if DWKP gains free-form maps.

## Revisit if

- A DWKP message needs a field whose keys are not fixed by a schema.
- A declared name is ever non-ASCII (the tests fail; do not silence them).
- A DWCP consumer appears that cannot treat extension keys as opaque text.
