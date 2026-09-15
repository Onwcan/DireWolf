# Schemas

**Everything below this README is generated. Do not edit it by hand.**

Cross-language schemas are the mechanism that stops the Rust and Python halves
of DireWolf drifting apart. Since M2 they are emitted from the Rust types in
[`crates/dwk-proto`](../crates/dwk-proto) and are the only input to the Python
code generator ([ADR-0033](../docs/adr/0033-protocol-source-of-truth-and-tcb-dependencies.md)).

## Ownership and direction

| | |
|---|---|
| **Source of truth** | Rust types in `dwk-proto` (and its operation inventory, `src/dwkp/registry.rs`) |
| **This directory** | JSON Schema 2020-12 *emitted* from those types by `tools/protogen` |
| **Python types** | *Generated* from this directory into `runtime/src/direwolf/proto/` by `scripts/gen_proto_python.py`, which reads nothing else |

The direction matters. The authority plane defines the wire format, because it
is the side that must reject anything it does not understand
([ADR-0023](../docs/adr/0023-dwkp-strict-schema.md)). A schema hand-maintained
on both sides is a schema that disagrees with itself the first time someone is
in a hurry.

## Layout

```
schemas/
  common/envelope.v1.schema.json   the envelope with every optional field allowed;
                                   the reference for field formats
  dwkp/        kernel protocol   - strict: unknown fields and operations REJECTED
    direwolf.<name>.v<N>.schema.json   one self-contained file per message version
    operations.json                    the operation inventory (defined + reserved)
  dwcp/        client protocol   - forward-compatible: unknown fields preserved
  events/      event records     - retained verbatim, outlive the code that wrote them
```

There is no `dwwp/`: the worker protocol is not implemented. Its REJECT policy is
fixed by ADR-0023 regardless.

File names match the envelope: `schema` + `schema_version` →
`<family>/<schema>.v<schema_version>.schema.json`, with `$id`
`urn:direwolf:schema:<family>:<schema>:<version>`. Each message file contains the
whole envelope with that message's presence rules and its payload under
`$defs`, so one file is enough to read or validate one message.

The compatibility rule is **per protocol, not blanket** — the single most
important thing not to get wrong here — and it is visible in each file:
`additionalProperties: false` and `x-direwolf-unknown-fields: "reject"` in
`dwkp/`, `"preserve"` in `dwcp/` and `events/`.

## What JSON Schema does not enforce

A document can validate against these schemas and still be rejected on the wire.
The following are **parser rules**, enforced by the lexers in Rust and Python and
tested there, not by JSON Schema ([ADR-0032](../docs/adr/0032-wire-contract-framing-strict-json-and-jcs.md)):

- frame length (1 B – 1 MiB) and content type;
- well-formed UTF-8, strict RFC 8259 grammar, no lone surrogate escapes;
- nesting depth ≤ 32;
- duplicate keys, and keys that collide under Unicode NFC;
- the DWKP integer-only number domain;
- RFC 8785 canonical encoding.

`x-direwolf-*` annotations carry the rest of the contract the generator needs:
unknown-field policy, envelope field presence, identifier prefix, supported
version ranges, and cross-field checks such as
`"x-direwolf-check": {"kind": "ordered", "low": "min_version", "high": "max_version"}`.

## Generation policy

- Regenerate with `make schema`; check with `make schema-check`. The check
  regenerates in memory and compares byte for byte, and fails on a file in a
  generated directory that the generator did not produce. CI runs it as a
  required job.
- Output is deterministic: sorted, fixed formatting, LF line endings, no
  timestamps or paths. Running `make schema` twice changes nothing.
- A change to a DWKP schema is a coordinated release of both halves, not a
  rolling one ([PROTOCOL.md](../docs/PROTOCOL.md) §1).
- A change to an authority-facing DWKP operation answers the eight questions in
  [CONTRIBUTING.md](../CONTRIBUTING.md) "Changing the protocol", and its
  second-path argument lives in the generated
  [DWKP_OPERATIONS.md](../docs/DWKP_OPERATIONS.md).
