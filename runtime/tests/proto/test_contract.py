"""The hand-written wire layer and the generated bindings against ``schemas/``.

``schemas/`` is emitted from Rust and is the only input to the Python
generator. These tests make any disagreement between the three a test failure
instead of a latent parity bug.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import subprocess
import sys
import unicodedata
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from direwolf import proto
from direwolf.proto import dwcp, dwkp, events, operations
from direwolf.wire import envelope, errors

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
            spec = module.MESSAGES[(doc["x-direwolf-message-type"], doc["x-direwolf-schema"])]
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


# ---- Unicode ---------------------------------------------------------------------------


def test_unicode_database_versions_are_pinned() -> None:
    """Rust (unicode-normalization 0.1.25) normalises with Unicode 17.0.0; this
    interpreter with its own database. For keys built only from characters
    assigned by Unicode 15.0 the NFC results are identical (normalisation
    stability). Keys using later characters can collide in Rust and not here --
    see ADR-0032. DWKP accept/reject parity is unaffected because every
    declared DWKP key is ASCII. ``crates/dwk-proto/tests/lexer.rs`` pins the
    Rust side; a change to either pin must revisit the ADR.
    """
    assert unicodedata.unidata_version == "15.0.0"
