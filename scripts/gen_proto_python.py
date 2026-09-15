#!/usr/bin/env python3
"""Generate ``runtime/src/direwolf/proto/`` from ``schemas/``.

    python scripts/gen_proto_python.py            # write
    python scripts/gen_proto_python.py --check    # compare; exit 1 on drift

The generation direction is one-way: Rust types -> JSON Schema (``protogen``) ->
Python (this script). This script reads **only** the committed schemas, never
the Rust source, which is what proves the schemas are a sufficient contract.

It understands a small, closed subset of JSON Schema plus DireWolf's
``x-direwolf-*`` annotations, and **fails** on anything else. A schema feature
the generator silently ignored would be a validation rule Python silently did
not enforce.

Output is deterministic: sorted inputs, no timestamps, no absolute paths. The
header records a digest of the input schemas so a stale file is identifiable.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
import textwrap
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
SCHEMAS = ROOT / "schemas"
OUT = ROOT / "runtime" / "src" / "direwolf" / "proto"

FAMILIES = (
    ("dwkp", "DWKP -- the kernel protocol. Strict: unknown fields and operations are rejected."),
    ("dwcp", "DWCP -- the client protocol. Forward-compatible: unknown fields are preserved."),
    ("events", "Event-log records. Retained verbatim; unknown events are kept, not dropped."),
)

STRUCT_KEYS = {
    "type",
    "description",
    "properties",
    "required",
    "additionalProperties",
    "x-direwolf-unknown-fields",
    "x-direwolf-check",
}
FIELD_KEYS = {
    "type",
    "description",
    "minimum",
    "maximum",
    "minLength",
    "maxLength",
    "pattern",
    "enum",
    "$ref",
    "x-direwolf-type",
    "x-direwolf-format",
    "x-direwolf-id-prefix",
}
MESSAGE_KEYS = {
    "$schema",
    "$id",
    "title",
    "description",
    "type",
    "properties",
    "required",
    "additionalProperties",
    "not",
    "dependentRequired",
    "$defs",
    "x-direwolf-family",
    "x-direwolf-message-type",
    "x-direwolf-schema",
    "x-direwolf-schema-versions",
    "x-direwolf-envelope-versions",
    "x-direwolf-envelope",
    "x-direwolf-id-prefix",
    "x-direwolf-unknown-fields",
    "x-direwolf-payload",
}
KNOWN_FORMATS = {"uuid7-id", "rfc3339-utc-millis", None}


class SchemaError(Exception):
    """A schema uses something the generator does not understand."""


@dataclass
class Field:
    name: str
    required: bool
    annotation: str
    check_expr: str
    nested: str | None
    doc: str


@dataclass
class Struct:
    name: str
    doc: str
    preserve: bool
    fields: list[Field] = field(default_factory=list)
    ordered: tuple[str, str] | None = None


def load(path: Path) -> dict[str, Any]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise SchemaError(f"{path}: not an object")
    return data


def unexpected(where: str, node: dict[str, Any], allowed: set[str]) -> None:
    extra = sorted(set(node) - allowed)
    if extra:
        raise SchemaError(
            f"{where}: unsupported schema keywords {extra}; extend the generator deliberately"
        )


def field_of(struct: str, name: str, node: dict[str, Any], required: bool) -> Field:
    where = f"{struct}.{name}"
    unexpected(where, node, FIELD_KEYS)
    doc = str(node.get("description", ""))
    if "$ref" in node:
        ref = str(node["$ref"])
        if not ref.startswith("#/$defs/"):
            raise SchemaError(f"{where}: only local $defs references are supported")
        target = ref.removeprefix("#/$defs/")
        return Field(name, required, target, f"{target}.decode", target, doc)
    fmt = node.get("x-direwolf-format")
    if fmt not in KNOWN_FORMATS:
        raise SchemaError(f"{where}: unknown x-direwolf-format {fmt!r}")
    kind = node.get("type")
    if fmt == "uuid7-id":
        prefix = node.get("x-direwolf-id-prefix")
        return Field(name, required, "str", f"validate.identifier({prefix!r})", None, doc)
    if kind == "integer":
        return Field(
            name,
            required,
            "int",
            f"validate.integer({int(node['minimum'])}, {int(node['maximum'])})",
            None,
            doc,
        )
    if kind == "boolean":
        return Field(name, required, "bool", "validate.boolean", None, doc)
    if kind == "string" and "enum" in node:
        variants = tuple(str(v) for v in node["enum"])
        return Field(name, required, "str", f"validate.enumeration({variants!r})", None, doc)
    if kind == "string":
        return Field(
            name,
            required,
            "str",
            f"validate.text({int(node['maxLength'])}, {node.get('pattern')!r}, {fmt!r})",
            None,
            doc,
        )
    raise SchemaError(f"{where}: unsupported field shape {node}")


def struct_of(name: str, node: dict[str, Any]) -> Struct:
    unexpected(name, node, STRUCT_KEYS)
    if node.get("type") != "object":
        raise SchemaError(f"{name}: $defs entries must be objects")
    policy = node.get("x-direwolf-unknown-fields")
    if policy not in ("reject", "preserve"):
        raise SchemaError(f"{name}: x-direwolf-unknown-fields must be reject or preserve")
    if (policy == "reject") != (node.get("additionalProperties") is False):
        raise SchemaError(f"{name}: additionalProperties disagrees with x-direwolf-unknown-fields")
    required = set(node.get("required", []))
    struct = Struct(name, str(node.get("description", "")), policy == "preserve")
    for field_name, field_node in node.get("properties", {}).items():
        struct.fields.append(field_of(name, field_name, field_node, field_name in required))
    check = node.get("x-direwolf-check")
    if check is not None:
        if check.get("kind") != "ordered":
            raise SchemaError(f"{name}: unknown x-direwolf-check {check}")
        struct.ordered = (str(check["low"]), str(check["high"]))
    return struct


def py_doc(text: str, indent: str) -> list[str]:
    text = " ".join(text.split())
    if not text:
        return []
    wrapped = textwrap.wrap(text.replace('"""', "'''"), width=88 - len(indent))
    if len(wrapped) == 1:
        return [f'{indent}"""{wrapped[0]}"""']
    return [
        f'{indent}"""{wrapped[0]}',
        *[f"{indent}{line}" for line in wrapped[1:]],
        f'{indent}"""',
    ]


def render_struct(struct: Struct) -> Iterator[str]:
    upper = struct.name.upper()
    yield ""
    yield ""
    for f in struct.fields:
        if f.nested is None:
            yield f"_{upper}_{f.name.upper()} = {f.check_expr}"
    if any(f.nested is None for f in struct.fields):
        yield ""
        yield ""
    yield "@dataclass(frozen=True, slots=True, kw_only=True)"
    yield f"class {struct.name}:"
    yield from py_doc(struct.doc, "    ") or ['    """(undocumented)"""']
    yield ""
    for f in struct.fields:
        annotation = f.annotation if f.required else f"{f.annotation} | None = None"
        yield f"    {f.name}: {annotation}"
        yield from py_doc(f.doc, "    ")
    if struct.preserve:
        yield "    extensions: dict[str, JsonValue] = field(default_factory=dict)"
        yield '    """Members this version does not declare, preserved for re-emission."""'
    if struct.fields or struct.preserve:
        yield ""
    yield "    @classmethod"
    yield "    def decode(cls, value: JsonValue, cx: Cx) -> Self:"
    yield "        obj = validate.expect_object(value, cx)"
    names = ", ".join(repr(f.name) for f in struct.fields)
    declared = f"({names},)" if len(struct.fields) == 1 else f"({names})"
    known = "known" if struct.fields else "_known"
    ext = "extensions" if struct.preserve else "_extensions"
    yield f"        {known}, {ext} = validate.partition(obj, {declared}, {struct.preserve}, cx)"
    for f in struct.fields:
        take = "take_required" if f.required else "take_optional"
        check = f"{f.nested}.decode" if f.nested else f"_{upper}_{f.name.upper()}"
        yield f"        {f.name}_ = validate.{take}(known, {f.name!r}, cx, {check})"
    if struct.ordered:
        low, high = struct.ordered
        yield f"        validate.ordered({low!r}, {low}_, {high!r}, {high}_, cx)"
    args = [f"{f.name}={f.name}_" for f in struct.fields]
    if struct.preserve:
        args.append("extensions=extensions")
    yield f"        return cls({', '.join(args)})"
    yield ""
    yield "    def encode(self) -> dict[str, JsonValue]:"
    yield "        out: dict[str, JsonValue] = {}"
    for f in struct.fields:
        value = f"self.{f.name}.encode()" if f.nested else f"self.{f.name}"
        if f.required:
            yield f"        out[{f.name!r}] = {value}"
        else:
            yield f"        if self.{f.name} is not None:"
            yield f"            out[{f.name!r}] = {value}"
    if struct.preserve:
        yield "        for key, member in self.extensions.items():"
        yield "            out[key] = member"
    yield "        return out"


def generate_family(family: str, summary: str) -> tuple[str, list[Path]]:
    files = sorted((SCHEMAS / family).glob("*.schema.json"))
    structs: dict[str, tuple[str, Struct]] = {}
    specs: list[str] = []
    for path in files:
        doc = load(path)
        unexpected(path.name, doc, MESSAGE_KEYS)
        if doc.get("x-direwolf-family") != family:
            raise SchemaError(f"{path.name}: family annotation is {doc.get('x-direwolf-family')!r}")
        for name, node in doc.get("$defs", {}).items():
            if node.get("type") != "object":
                continue  # identifier and scalar helpers are inlined by the emitter
            canonical = json.dumps(node, sort_keys=True)
            if name in structs and structs[name][0] != canonical:
                raise SchemaError(f"{path.name}: $defs {name} differs from another schema's")
            structs.setdefault(name, (canonical, struct_of(name, node)))
        env = doc["x-direwolf-envelope"]
        versions = doc["x-direwolf-schema-versions"]
        rules = ", ".join(
            f"{env[k]!r}"
            for k in (
                "correlation_id",
                "causation_id",
                "session_id",
                "run_id",
                "epoch",
                "idempotency_key",
            )
        )
        mtype, name = doc["x-direwolf-message-type"], doc["x-direwolf-schema"]
        specs.append(
            f"    ({mtype!r}, {name!r}): MessageSpec(\n"
            f"        schema={name!r},\n"
            f"        message_type={mtype!r},\n"
            f"        versions=VersionRange({int(versions['min'])}, {int(versions['max'])}),\n"
            f"        rules=Rules({rules}),\n"
            f"        payload={doc['x-direwolf-payload']},\n"
            f"    ),"
        )

    lines = [
        f"# GENERATED by scripts/gen_proto_python.py from schemas/{family}/. DO NOT EDIT.",
        f"# Source digest: sha256:{digest(files)}",
        f'"""{summary}"""',
        "",
        "from __future__ import annotations",
        "",
        "from collections.abc import Mapping",
        "from dataclasses import dataclass, field"
        if any(s.preserve for _, s in structs.values())
        else "from dataclasses import dataclass",
        "from types import MappingProxyType",
        "from typing import Final, Self",
        "",
        "from direwolf.wire import envelope, validate",
        "from direwolf.wire.envelope import MessageSpec, Rules",
        "from direwolf.wire.errors import VersionRange",
        "from direwolf.wire.strict_json import JsonValue",
        "from direwolf.wire.validate import Cx",
        "",
        "__all__ = [",
        *[f'    "{name}",' for name in ["MESSAGES", *sorted(structs)]],
        "]",
    ]
    for _, (_, struct) in sorted(
        structs.items(), key=lambda kv: dependency_order(kv[1][1], structs)
    ):
        lines.extend(render_struct(struct))
    lines += [
        "",
        "",
        "MESSAGES: Final[Mapping[tuple[str, str], MessageSpec]] = MappingProxyType({",
        *specs,
        "})",
        '"""Every message of this family the build knows, keyed by (type, schema)."""',
    ]
    lines += family_api(family)
    return "\n".join(lines) + "\n", files


def dependency_order(struct: Struct, structs: dict[str, tuple[str, Struct]]) -> tuple[int, str]:
    """Structs referenced by others first, so annotations read top-down."""
    referenced = any(f.nested == struct.name for _, s in structs.values() for f in s.fields)
    return (0 if referenced else 1, struct.name)


def family_api(family: str) -> list[str]:
    if family == "dwkp":
        return [
            "",
            "",
            "def decode_body(data: bytes) -> envelope.DwkpMessage:",
            '    """Decode a DWKP frame body; rejects everything dwk-proto rejects."""',
            "    return envelope.decode_dwkp(data, MESSAGES)",
            "",
            "",
            "def encode(message: envelope.DwkpMessage) -> bytes:",
            '    """Canonical bytes for a message, verified by re-decoding."""',
            "    return envelope.encode_dwkp(message, MESSAGES)",
            "",
            "",
            "def to_frame(message: envelope.DwkpMessage) -> bytes:",
            '    """A complete frame for a message."""',
            "    return envelope.frame_dwkp(message, MESSAGES)",
        ]
    if family == "dwcp":
        return [
            "",
            "",
            "def decode(data: bytes) -> envelope.DwcpMessage:",
            '    """Decode a DWCP message, preserving undeclared members."""',
            "    return envelope.decode_dwcp(data, MESSAGES)",
            "",
            "",
            "def encode(message: envelope.DwcpMessage) -> bytes:",
            '    """Canonical bytes, re-emitting every preserved member."""',
            "    return envelope.encode_dwcp(message)",
        ]
    return [
        "",
        "",
        "def read(data: bytes) -> envelope.EventRecord:",
        '    """Read a record; its bytes are always retained verbatim."""',
        "    return envelope.read_event(data, MESSAGES)",
    ]


def generate_operations() -> tuple[str, list[Path]]:
    path = SCHEMAS / "dwkp" / "operations.json"
    doc = load(path)
    rows = []
    for op in doc["operations"]:
        responses = tuple(op["responses"])
        rows.append(
            "    Operation(\n"
            f"        name={op['name']!r},\n"
            f"        layer={op['layer']!r},\n"
            f"        status={op['status']!r},\n"
            f"        request={op['request']!r},\n"
            f"        responses={responses!r},\n"
            f"        semantics_owner={op['semantics_owner']!r},\n"
            f"        effect_bearing={op['effect_bearing']!r},\n"
            f"        authority_bearing={op['authority_bearing']!r},\n"
            "    ),"
        )
    text = "\n".join(
        [
            "# GENERATED by scripts/gen_proto_python.py from schemas/dwkp/operations.json."
            " DO NOT EDIT.",
            f"# Source digest: sha256:{digest([path])}",
            '"""The DWKP operation inventory. See docs/DWKP_OPERATIONS.md for the second-path',
            'argument behind each entry; this module carries only what code needs."""',
            "",
            "from __future__ import annotations",
            "",
            "from dataclasses import dataclass",
            "from typing import Final",
            "",
            "",
            "@dataclass(frozen=True, slots=True, kw_only=True)",
            "class Operation:",
            '    """One inventory entry."""',
            "",
            "    name: str",
            "    layer: str",
            "    status: str",
            "    request: str | None",
            "    responses: tuple[str, ...]",
            "    semantics_owner: str",
            "    effect_bearing: bool",
            "    authority_bearing: bool",
            "",
            "",
            "OPERATIONS: Final[tuple[Operation, ...]] = (",
            *rows,
            ")",
        ]
    )
    return text + "\n", [path]


def digest(files: list[Path]) -> str:
    h = hashlib.sha256()
    for f in sorted(files):
        h.update(f.relative_to(ROOT).as_posix().encode())
        h.update(b"\0")
        h.update(f.read_bytes().replace(b"\r\n", b"\n"))
    return h.hexdigest()


def generate() -> dict[Path, str]:
    outputs: dict[Path, str] = {}
    all_inputs: list[Path] = []
    for family, summary in FAMILIES:
        text, files = generate_family(family, summary)
        outputs[OUT / f"{family}.py"] = text
        all_inputs += files
    text, files = generate_operations()
    outputs[OUT / "operations.py"] = text
    all_inputs += files
    envelope_schema = SCHEMAS / "common" / "envelope.v1.schema.json"
    all_inputs.append(envelope_schema)
    outputs[OUT / "__init__.py"] = "\n".join(
        [
            "# GENERATED by scripts/gen_proto_python.py from schemas/. DO NOT EDIT.",
            '"""Generated DireWolf protocol types.',
            "",
            "Every module here is generated from the JSON Schemas in ``schemas/``, which are in",
            "turn emitted from the Rust crate ``dwk-proto``. To change a message, change the Rust",
            "type and run ``make schema``. Hand edits are overwritten, and CI rejects them.",
            '"""',
            "",
            "from __future__ import annotations",
            "",
            "from typing import Final",
            "",
            "from direwolf.proto import dwcp, dwkp, events, operations",
            "",
            '__all__ = ["SCHEMA_DIGEST", "dwcp", "dwkp", "events", "operations"]',
            "",
            f'SCHEMA_DIGEST: Final = "sha256:{digest(all_inputs)}"',
            '"""Digest of every schema these bindings were generated from."""',
            "",
        ]
    )
    return outputs


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--check", action="store_true", help="compare instead of writing")
    args = parser.parse_args(argv)
    try:
        outputs = generate()
    except (SchemaError, KeyError, ValueError) as exc:
        print(f"gen_proto_python: {exc}", file=sys.stderr)
        return 2
    expected = {p.name for p in outputs}
    existing = {p.name for p in OUT.glob("*.py")} if OUT.exists() else set()
    if args.check:
        drift = [
            f"missing or different: {p.relative_to(ROOT).as_posix()}"
            for p, text in outputs.items()
            if not p.exists() or p.read_text(encoding="utf-8") != text
        ]
        drift += [
            f"unexpected: runtime/src/direwolf/proto/{name}" for name in sorted(existing - expected)
        ]
        if drift:
            for line in drift:
                print(f"gen_proto_python: {line}", file=sys.stderr)
            print(
                "gen_proto_python: Python bindings have drifted from schemas/. Run `make schema`.",
                file=sys.stderr,
            )
            return 1
        print(f"gen_proto_python: {len(outputs)} generated modules match schemas/")
        return 0
    OUT.mkdir(parents=True, exist_ok=True)
    for name in sorted(existing - expected):
        (OUT / name).unlink()
        print(f"removed runtime/src/direwolf/proto/{name}")
    for path, text in outputs.items():
        if path.exists() and path.read_text(encoding="utf-8") == text:
            continue
        path.write_text(text, encoding="utf-8", newline="\n")
        print(f"wrote {path.relative_to(ROOT).as_posix()}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
