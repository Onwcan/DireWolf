"""The hand-written wire layer and the generated bindings against ``schemas/``.

``schemas/`` is emitted from Rust and is the only input to the Python
generator. These tests make any disagreement between the three a test failure
instead of a latent parity bug.
"""

from __future__ import annotations

import ast
import copy
import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from direwolf import proto
from direwolf.proto import dwcp, dwkp, events, operations
from direwolf.wire import envelope, errors
from direwolf.wire.errors import SCHEMA_VIOLATION, UNKNOWN_FIELD, ProtocolError

ROOT = Path(__file__).resolve().parents[3]
SCHEMAS = ROOT / "schemas"
GENERATOR = ROOT / "scripts" / "gen_proto_python.py"


def _schema(relative: str) -> dict[str, Any]:
    loaded: dict[str, Any] = json.loads((SCHEMAS / relative).read_text(encoding="utf-8"))
    return loaded


def _generator() -> ModuleType:
    spec = importlib.util.spec_from_file_location("gen_proto_python", GENERATOR)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules.setdefault("gen_proto_python", module)
    spec.loader.exec_module(module)
    return module


# ---- hand-written constants against the emitted schemas ---------------------------


def test_error_codes_and_violations_match_the_schema_enumerations() -> None:
    payload = _schema("dwkp/direwolf.protocol.error.v1.schema.json")["$defs"][
        "ProtocolErrorPayload"
    ]
    assert tuple(payload["properties"]["code"]["enum"]) == errors.ERROR_CODES
    assert tuple(payload["properties"]["violation"]["enum"]) == errors.VIOLATIONS
    assert payload["properties"]["path"]["maxLength"] == errors.MAX_ERROR_PATH_CHARS
    assert payload["properties"]["detail"]["maxLength"] == errors.MAX_ERROR_DETAIL_CHARS


def test_envelope_constants_match_the_common_envelope_schema() -> None:
    schema = _schema("common/envelope.v1.schema.json")
    props = schema["properties"]
    assert tuple(props) == envelope.ENVELOPE_KEYS
    assert tuple(props["type"]["enum"]) == envelope.MESSAGE_TYPES
    assert props["schema"]["pattern"] == envelope.SCHEMA_NAME_PATTERN
    assert props["ts"]["pattern"] == envelope.TIMESTAMP_PATTERN
    assert props["idempotency_key"]["pattern"] == envelope.IDEMPOTENCY_KEY_PATTERN
    assert schema["x-direwolf-id-prefixes"] == envelope.ID_PREFIX
    versions = schema["x-direwolf-envelope-versions"]
    assert errors.VersionRange(versions["min"], versions["max"]) == errors.SUPPORTED_ENVELOPE
    assert props["epoch"]["maximum"] == errors.MAX_SAFE_INTEGER
    assert schema["dependentRequired"] == {"epoch": ["session_id"]}


def test_each_generated_registry_is_exactly_its_schema_directory() -> None:
    for family, module in (("dwkp", dwkp), ("dwcp", dwcp), ("events", events)):
        on_disk = set()
        for path in sorted((SCHEMAS / family).glob("*.schema.json")):
            doc = json.loads(path.read_text(encoding="utf-8"))
            on_disk.add((doc["x-direwolf-message-type"], doc["x-direwolf-schema"]))
            versions = doc["x-direwolf-schema-versions"]
            specs = module.MESSAGES[(doc["x-direwolf-message-type"], doc["x-direwolf-schema"])]
            (spec,) = [
                s
                for s in specs
                if (s.versions.min, s.versions.max) == (versions["min"], versions["max"])
            ]
            assert spec.payload.__name__ == doc["x-direwolf-payload"], path.name
            envelope_rules = doc["x-direwolf-envelope"]
            assert dict(spec.rules.items()) == envelope_rules, path.name
            policy = doc["x-direwolf-unknown-fields"]
            assert policy == ("reject" if family == "dwkp" else "preserve"), path.name
        assert set(module.MESSAGES) == on_disk, family


def test_the_operation_inventory_matches_and_reserved_operations_are_not_on_the_wire() -> None:
    inventory = _schema("dwkp/operations.json")["operations"]
    assert [op["name"] for op in inventory] == [op.name for op in operations.OPERATIONS]
    wire = {schema for (_, schema) in dwkp.MESSAGES}
    for op in operations.OPERATIONS:
        if op.status == "defined":
            assert op.request in wire, op.name
            assert set(op.responses) <= wire, op.name
        else:
            assert op.request not in wire, f"reserved {op.name} must not decode"
    for op in inventory:
        for key in (
            "carries",
            "consumer",
            "second_path",
            "semantics_owner",
            "initiator",
            "receiver",
        ):
            assert str(op[key]).strip(), f"{op['name']} has no {key}"


def test_no_operation_is_a_generic_relay() -> None:
    banned = (
        "http",
        "request.raw",
        "exec",
        "shell",
        "eval",
        "proxy",
        "relay",
        "forward",
        "generic",
    )
    for op in operations.OPERATIONS:
        spelled = f"{op.name} {op.request or ''}".lower()
        assert not any(word in spelled for word in banned), op.name


# ---- the generator ------------------------------------------------------------------


def test_generation_is_deterministic_and_matches_the_committed_bindings() -> None:
    gen = _generator()
    first = gen.generate()
    second = gen.generate()
    assert first == second
    for path, text in first.items():
        assert path.read_text(encoding="utf-8") == text, f"{path.name} is stale; run make schema"
        assert text.startswith("# GENERATED by scripts/gen_proto_python.py"), path.name
    assert proto.SCHEMA_DIGEST in first[gen.OUT / "__init__.py"]


def test_check_mode_reports_no_drift() -> None:
    result = subprocess.run(
        [sys.executable, str(GENERATOR), "--check"], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr


@pytest.mark.parametrize(
    ("keyword", "value"),
    [
        ("format", "email"),
        ("multipleOf", 2),
        ("oneOf", []),
        ("default", 1),
        ("x-direwolf-new", True),
    ],
)
def test_the_generator_refuses_a_schema_keyword_it_does_not_implement(
    keyword: str, value: object
) -> None:
    gen = _generator()
    doc = _schema("dwkp/direwolf.handshake.v1.schema.json")
    node = copy.deepcopy(doc["$defs"]["Handshake"])
    node["properties"]["min_version"][keyword] = value
    with pytest.raises(gen.SchemaError, match=keyword):
        gen.struct_of("Handshake", node)
    struct_level = copy.deepcopy(doc["$defs"]["Handshake"])
    struct_level[keyword] = value
    with pytest.raises(gen.SchemaError, match=keyword):
        gen.struct_of("Handshake", struct_level)


# ---- Unicode independence (ADR-0034) ---------------------------------------------------


def test_no_protocol_decision_consults_a_unicode_database() -> None:
    """The wire layer must not import ``unicodedata``.

    Rust and Python ship different Unicode database versions -- 17.0.0 in
    `unicode-normalization`, 15.0.0 in CPython 3.12 -- so any decision that
    normalises can differ between the two implementations of the same protocol.
    ADR-0034 removes the dependence instead of pinning it: keys are compared as
    text, and DWKP's rejection of every undeclared member carries the property
    that NFC comparison used to.
    """
    offenders = []
    for module in sorted(Path("runtime/src/direwolf/wire").glob("*.py")):
        source = module.read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            names = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom):
                names = [node.module or ""]
            if any(n.split(".")[0] == "unicodedata" for n in names):
                offenders.append(module.name)
    assert offenders == [], f"the wire layer normalises Unicode in {offenders}"


def test_every_name_dwkp_interprets_is_ascii() -> None:
    """Why the rule above is safe: a key that is not equal to a declared name
    cannot be made equal to one by normalisation, because every declared name is
    ASCII. A non-ASCII DWKP field would reopen ADR-0034."""
    names = set(envelope.ENVELOPE_KEYS)
    for path in sorted(SCHEMAS.rglob("*.schema.json")):
        doc = json.loads(path.read_text(encoding="utf-8"))
        stack = [doc]
        while stack:
            node = stack.pop()
            if isinstance(node, dict):
                names.update(node.get("properties", {}))
                stack.extend(v for v in node.values() if isinstance(v, dict | list))
            elif isinstance(node, list):
                stack.extend(v for v in node if isinstance(v, dict | list))
    assert names, "no declared names found"
    assert all(n.isascii() for n in names), sorted(n for n in names if not n.isascii())


def test_colliding_keys_are_rejected_by_dwkp_and_preserved_by_dwcp() -> None:
    """The cross-language invariant: same bytes, same protocol version, same
    accept/reject decision -- and, when accepted, the same preservation. The
    Rust suite asserts the identical cases in ``tests/compatibility.rs``."""
    colliding = {"caf" + chr(0xE9): 1, "cafe" + chr(0x301): 2}
    msg = "msg_01M24BB8G0E87TVJX9GX248ADD"
    ses = "ses_01M24BB8G2E87V1ZPZXQ7DSCVW"
    ts = "2026-09-12T09:14:22.481Z"

    request = {
        "v": 1,
        "id": msg,
        "type": "request",
        "schema": "direwolf.heartbeat",
        "schema_version": 1,
        "ts": ts,
        "session_id": ses,
        "epoch": 47,
        "payload": dict(colliding),
    }
    with pytest.raises(ProtocolError) as caught:
        dwkp.decode_body(json.dumps(request, ensure_ascii=False).encode())
    assert caught.value.code == SCHEMA_VIOLATION
    assert caught.value.violation == UNKNOWN_FIELD
    assert caught.value.path == "/payload/caf" + chr(0xE9)

    response = {
        "v": 1,
        "id": msg,
        "type": "response",
        "schema": "direwolf.error",
        "schema_version": 1,
        "ts": ts,
        "causation_id": msg,
        "payload": {"code": "E", "detail": "d", "retryable": False, **colliding},
    }
    kept = dwcp.decode(json.dumps(response, ensure_ascii=False).encode())
    assert isinstance(kept.body, dwcp.ClientError)
    assert kept.body.extensions == colliding
    reemitted = json.loads(dwcp.encode(kept))
    assert {k: reemitted["payload"][k] for k in colliding} == colliding
