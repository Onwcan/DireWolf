"""The shared cross-language vectors, run against the Python bindings.

The Rust crate runs the same files (``crates/dwk-proto/tests/golden.rs``).
Expected canonical bytes come from an independent V8 oracle, so agreement means
both implementations match the standard, not merely each other.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from direwolf.proto import dwcp, dwkp, events
from direwolf.wire import frame
from direwolf.wire.envelope import InvalidEvent, KnownEvent, UnknownEvent
from direwolf.wire.errors import DUPLICATE_KEY, ProtocolError
from direwolf.wire.strict_json import IJSON, SAFE_INTEGER, parse

VECTORS = Path(__file__).resolve().parents[3] / "tests" / "protocol" / "vectors"


def _load(name: str) -> list[dict[str, Any]]:
    data = json.loads((VECTORS / name).read_text(encoding="utf-8"))
    vectors: list[dict[str, Any]] = data["vectors"]
    return vectors


def _bytes(vector: dict[str, Any]) -> bytes:
    if "input" in vector:
        return str(vector["input"]).encode("utf-8")
    return bytes.fromhex(str(vector["input_hex"]))


VALID = _load("valid.json")
INVALID = _load("invalid.json")


@pytest.mark.parametrize("vector", VALID, ids=[v["name"] for v in VALID])
def test_valid_vector(vector: dict[str, Any]) -> None:
    data = _bytes(vector)
    family = vector["family"]
    if family == "dwkp":
        message = dwkp.decode_body(data)
        canonical = dwkp.encode(message)
        assert canonical.decode("utf-8") == vector["canonical"]
        framed = dwkp.to_frame(message)
        assert framed.hex() == vector["frame_hex"]
        (only,) = frame.decode_all(framed)
        assert dwkp.decode_body(only.body) == message
    elif family == "dwcp":
        decoded = dwcp.decode(data)
        assert dwcp.encode(decoded).decode("utf-8") == vector["canonical"]
        expect = vector["expect"]
        assert (decoded.body is not None) == (expect == "error"), expect
    else:
        record = events.read(data)
        assert record.raw == data, "event records are retained byte for byte"
        kind = {KnownEvent: "known", UnknownEvent: "unknown", InvalidEvent: "invalid"}[
            type(record.view)
        ]
        assert kind == vector["expect"], record.view


@pytest.mark.parametrize("vector", INVALID, ids=[v["name"] for v in INVALID])
def test_invalid_vector(vector: dict[str, Any]) -> None:
    data = _bytes(vector)
    decoder = {"dwkp": dwkp.decode_body, "dwcp": dwcp.decode, "event": events.read}[
        vector["family"]
    ]
    with pytest.raises(ProtocolError) as caught:
        decoder(data)
    err = caught.value
    assert err.code == vector["code"], err.describe()
    if "violation" in vector:
        assert err.violation == vector["violation"], err.describe()
    if "path" in vector:
        assert err.path == vector["path"], err.describe()


def test_the_vector_files_are_substantial() -> None:
    # A truncated or emptied vector file would make every test above pass.
    assert len(VALID) >= 20
    assert len(INVALID) >= 80


@pytest.mark.parametrize(
    "vector",
    [v for v in INVALID if v["code"] == DUPLICATE_KEY],
    ids=lambda v: v["name"],
)
def test_key_ambiguity_is_rejected_by_the_reader_itself(vector: dict[str, Any]) -> None:
    profile = SAFE_INTEGER if vector["family"] == "dwkp" else IJSON
    with pytest.raises(ProtocolError) as caught:
        parse(_bytes(vector), profile)
    assert caught.value.code == vector["code"]
