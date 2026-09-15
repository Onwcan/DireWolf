# ADR-0033: Protocol source of truth, code generation, and the dependencies `dwk-proto` brings into the TCB

**Status:** Accepted · **Date:** 2026-09-15 · **Amends:** [ADR-0019](0019-language-rationale-v2.md) (the authority dependency set is no longer empty) · **Refines:** [ADR-0031](0031-repository-layout-and-boundary-enforcement.md)

> ADR-0019's claim — "a genuinely small, enforceable dependency set: no HTTP
> client, no TLS stack, no container client, no content parsers" — survives.
> What changes is that the set is no longer empty, and this record is the
> review ADR-0019 requires for each addition.

## Context

M2 creates `crates/dwk-proto`, the wire contract. From M3 `dwkd-authority` links
it, and `dwkd-broker` will too, so four decisions made here are made for the
trusted computing base:

1. **Which side is the source of truth** for message shapes, and in which
   direction code is generated. [schemas/README.md](../../schemas/README.md)
   fixed ownership at M1 (Rust types) but not the mechanism.
2. **How the Python runtime gets its types** without a second hand-maintained
   copy of every schema, and without a large runtime dependency.
3. **Whether the DWKP JSON reader is a library or ours.** ADR-0023 requires
   duplicate keys and Unicode-normalisation collisions to be *rejected*; that
   must be observed on the lexical object, before any map merges two members.
4. **Which third-party crates** enter the authority closure, and how the
   repository keeps "shared protocol types" from becoming "shared privileged
   implementation".

## Decision

### 1. One direction: Rust → JSON Schema → Python

```
crates/dwk-proto (Rust types, wire_struct!/wire_int!/wire_text!/wire_enum!/wire_id!)
      │  tools/protogen          (make schema / make schema-check)
      ▼
schemas/{common,dwkp,dwcp,events}/*.schema.json  +  schemas/dwkp/operations.json
docs/DWKP_OPERATIONS.md
      │  scripts/gen_proto_python.py   (reads schemas/ ONLY)
      ▼
runtime/src/direwolf/proto/{dwkp,dwcp,events,operations}.py
```

- Each Rust message type is declared once, in a macro that generates its
  decoder, its encoder **and its schema** from the same field list, so the
  schema cannot describe a type other than the one that is decoded.
- Schemas are JSON Schema 2020-12, one self-contained file per message and
  version, with `x-direwolf-*` annotations for what JSON Schema cannot express
  (unknown-field policy, envelope presence rules, identifier prefixes, cross-field
  ordering). **JSON Schema is not claimed to enforce** duplicate-key rejection,
  normalisation collisions, frame limits, or any lexical property; those are
  parser rules ([ADR-0032](0032-wire-contract-framing-strict-json-and-jcs.md)),
  tested at the parser.
- The Python generator reads only `schemas/`, never Rust source — which is what
  proves the schemas are a sufficient contract. It accepts a **closed** set of
  schema keywords and fails on any other, because a keyword silently ignored is
  a rule Python silently does not enforce.
- All three outputs are committed and **never edited by hand**. Generation is
  deterministic: sorted inputs, fixed pretty-printing, LF, no timestamps, no
  absolute paths; the Python header records a SHA-256 digest of its input
  schemas. `make schema-check` regenerates in memory and compares byte for byte
  (and fails on a stray file in a generated directory); CI's `schema` job runs
  it and is required.

### 2. Python: generated dataclasses over a small stdlib wire layer

- **Generated** (`direwolf.proto`): one frozen, slotted dataclass per payload,
  with a decoder that applies the schema's bounds, patterns, enums and policy,
  and a registry per family. Only protocol representation: no networking, no
  decisions, no SDKs.
- **Hand-written, stdlib only** (`direwolf.wire`): the strict JSON reader (the
  standard library's C scanner with every ADR-0032 rule enforced through its
  hooks or around it), JCS, framing, field validators and the envelope decode
  order. This is mechanism, the same for every message.
- **No Pydantic.** It would add a compiled extension to the runtime, still need
  a custom reader for duplicate keys, and bring a second notion of strictness
  whose coercions (`"1"` → `1`) differ from the Rust decoder's.

The lexical layer and JCS necessarily exist in both languages. Their agreement
is not assumed from the specification: shared golden vectors
(`tests/protocol/vectors/`, run by both test suites) check the same accept/reject
decision and the same `(code, violation, path)` for every single-fault input, and
the canonical bytes come from an independent oracle (V8) rather than from either
implementation. Constants in `direwolf.wire` are tested against the emitted schemas.

### 3. The DWKP JSON reader is ours, and `serde_json` is its test oracle

`serde_json` was the default choice and was measured before being rejected for
the TCB. Its locked dependency set and a count of source lines and of lines
containing the token `unsafe` (all targets and features, so an upper bound on
what is compiled):

| Crate (locked) | Source lines | Lines with `unsafe` |
|---|---:|---:|
| `serde_json` 1.0.151 | 18 329 | 13 |
| `serde` 1.0.229 | 17 237 | 2 |
| `serde_core` 1.0.229 | 12 037 | 2 |
| `memchr` 2.8.3 | 15 824 | 333 |
| `zmij` 1.0.23 | 2 043 | 70 |
| `itoa` 1.0.18 | 488 | 13 |
| **Total** | **65 958** | **433** |
| `dwk-proto` `json` module (lexer, values, JCS, number formatting) | 1 030 | 0 — `#![forbid(unsafe_code)]` |

Size is not the argument on its own; function is. `serde_json::Value` resolves
duplicate keys by keeping the last, so duplicate *detection* would need a custom
`Deserializer`/`Visitor` over its tokenizer anyway, and seeing the exact lexeme of
an out-of-range integer (to reject it rather than round it) would need the
`arbitrary_precision` feature. At that point the library contributes a
tokenizer — the easy part — and ~66 k lines of trusted code, while the rules
ADR-0032 requires would still be ours.

The bespoke lexer is held to a higher test standard than a library would be:
recursion bounded by the depth limit; a differential test against `serde_json`
on a grammar-edge corpus (it may reject *more*, never accept something
`serde_json` calls ungrammatical, and must agree on every value both accept);
property tests; RFC 8785 and V8 vectors; and fuzzing through four targets under
libFuzzer and a stable mutation harness. `serde_json` is a **dev-dependency
only**.

### 4. TCB dependency review (the ADR-0019 note)

Linked closure of `dwk-proto`, and therefore of `dwkd-authority` from M3:

| | `unicode-normalization` 0.1.25 | `tinyvec` 1.13.2 | `tinyvec_macros` 0.1.1 |
|---|---|---|---|
| **Why** | ADR-0023 requires rejecting keys equal under NFC. The standard library has no Unicode normalisation; hand-written tables would be ~23 k lines of generated data to maintain against each Unicode release. | Required by `unicode-normalization` (small-vector buffer). | Required by `tinyvec` (`macro_rules!` only). |
| **Responsibility** | NFC of **object keys only**, to detect collisions. Values are never normalised; nothing is rewritten. | Buffer for combining-mark reordering. | None at run time. |
| **`unsafe`** | Not unsafe-free: 5 source lines (an `unsafe fn` and the blocks that call it or `char::from_u32_unchecked`), all in Hangul syllable (de)composition arithmetic and guarded by range checks immediately before them. Reviewed for this ADR; `#![deny(unsafe_code)]` elsewhere in the crate. | None — `#![forbid(unsafe_code)]`. | None — `#![forbid(unsafe_code)]`, `no_std`. |
| **Parser surface** | Receives keys the lexer has already validated as UTF-8 `str`; parses nothing. Worst case is a key of ~1 MiB of combining marks: reordering uses a stable `sort_by_key` over runs of non-starters, so cost is bounded by the frame limit. Not separately benchmarked at that size. | None. | None. |
| **Build script / proc macro** | None (`build = false`). | None (`build = false`). | None. |
| **Licence** | MIT OR Apache-2.0 | Zlib OR Apache-2.0 OR MIT | MIT OR Apache-2.0 OR Zlib |
| **Unicode version** | 17.0.0, pinned by a test; the Python runtime's database differs (ADR-0032). | — | — |

Enforcement, all in place at M2:

- `architecture.toml` `[authority]`: `crates = ["dwkd-authority", "dwk-proto"]`,
  `allowed_third_party = ["unicode-normalization", "tinyvec", "tinyvec_macros"]`.
  `dwk-proto` is checked as TCB **now**, before the M3 edge exists.
- `dwcheck` RS004 (manifest) and RS006 (transitive closure from `Cargo.lock`)
  exclude dev-dependencies — they are not linked — and its tests prove a normal
  or build dependency on the same crate *is* counted.
- `cargo deny` passes: advisories, licences, bans, sources.
- Adding to this list still requires a note here or on ADR-0019 and a reviewer
  other than the author ([CONTRIBUTING.md](../../CONTRIBUTING.md)
  "Security-sensitive changes"). `.github/CODEOWNERS` lists `architecture.toml`,
  `Cargo.lock`, `crates/dwk-proto/` and the generators, but it is not active
  until the reviewing teams exist, so it is not evidence that a review happened.

**Dev-only** (never linked; audited by `cargo deny`, excluded from RS004/RS006):
`proptest` 1.11 (`default-features = false, features = ["std"]`) and `serde_json`
1.0.151, with their transitive dependencies. The fuzz crate (`fuzz/`, its own
Cargo workspace and lockfile) adds `libfuzzer-sys` 0.4.13 and its build
dependencies; it is not a workspace member and `cargo deny` does not yet read
its lockfile.

### 5. `dwk-proto` stays narrow

- It is the only in-tree crate both daemons may link (`[crates].shared`, RS008),
  and it may link no in-tree crate (RS009), so it cannot carry a bridge between
  them. A fixture proves an arbitrary crate linked by both daemons is rejected.
- Its source may not name `std::fs`, `std::net`, `std::process`, `std::env`,
  `std::os` or `unsafe` (TX002; a text tripwire, not a proof, as ADR-0031 says of
  every `dwcheck` rule).
- It contains wire types and value objects: no policy, capability, approval,
  budget, secret, sandbox or orchestration logic, and no I/O.

## Consequences

**Positive.**
- A message shape changes in exactly one place, and CI fails if the schema, the
  inventory document or the Python bindings were not regenerated.
- The TCB gains ~30 k lines of third-party code, of which ~23 k are Unicode
  tables, instead of ~66 k.
- The authority closure is checked by tooling before M3 links it, so M3 inherits
  a verified set rather than discovering one.

**Negative.**
- We own a JSON lexer and an ECMAScript number formatter. A bug there is a TCB
  bug; the test and fuzz obligations above are the price, and they recur.
- The macro-based type declarations are less familiar than `serde` derives.
- The Python wire layer is hand-written, in parallel with the Rust one. Parity
  rests on the shared vectors and the constant-versus-schema tests, not on
  generation. A rule added to one lexer and not the other is caught only if a
  vector exercises it.
- The generator implements a closed subset of JSON Schema. A new schema feature
  means extending the generator on purpose.
- `cargo deny` does not cover `fuzz/Cargo.lock`.

## Alternatives considered

- **`schemars` to derive schemas from `serde` types.** Mature, but brings
  `serde` derives and proc-macro build dependencies into the TCB crate's build,
  and the schema would follow `serde` attributes rather than the decoder that
  enforces the rules — two descriptions of one type again.
- **JSON Schema as the source, Rust generated from it (`typify`).** The authority
  side must define the wire, and generated Rust loses the newtypes ADR-0019 (b)
  depends on.
- **An IDL (Protocol Buffers, Cap'n Proto).** The wire is JSON for reasons
  PROTOCOL.md §7 records, and IDL compatibility rules do not distinguish DWKP
  rejection from DWCP preservation.
- **`serde_json` in the TCB with a custom visitor.** See §3: the rules would
  still be ours, and the trusted code roughly 60 times larger.
- **Our own NFC tables.** Fewer crates, more code to keep correct across Unicode
  releases; dependency count is not the goal.
- **Pydantic, or `datamodel-code-generator`.** See §2; the latter also cannot
  carry the `x-direwolf-*` semantics.

## Revisit if

- A maintained JSON crate offers lexical duplicate reporting and exact number
  lexemes with a trusted footprint comparable to the `json` module.
- A fuzz or review finding shows a bug class in the bespoke lexer that a mature
  parser would not have had.
- The number of message types makes the macro declarations harder to review than
  derives would be.
