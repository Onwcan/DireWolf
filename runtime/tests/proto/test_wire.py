"""Python wire mechanics: canonical JSON, framing, the strict reader, and the
three compatibility rules. Mirrors the Rust integration tests."""

from __future__ import annotations

import json
import struct
from pathlib import Path

import pytest

from direwolf.proto import dwcp, dwkp, events, operations
from direwolf.wire import frame, jcs
from direwolf.wire.envelope import KnownEvent, UnknownEvent
from direwolf.wire.errors import (
    CONTENT_TYPE_UNSUPPORTED,
    DUPLICATE_KEY,
    FRAME_EMPTY,
    FRAME_TOO_LARGE,
    FRAME_TRUNCATED,
    INVALID_JSON,
    MAX_DEPTH,
    MAX_DEPTH_EXCEEDED,
    MAX_FRAME_BODY,
    NUMBER_OUT_OF_DOMAIN,
    SCHEMA_VIOLATION,
    SUPPORTED_ENVELOPE,
    UNKNOWN_FIELD,
    UNKNOWN_OPERATION,
    VERSION_UNSUPPORTED,
    ProtocolError,
    VersionRange,
    negotiate,
)
from direwolf.wire.strict_json import IJSON, SAFE_INTEGER, JsonValue, parse

VECTORS = Path(__file__).resolve().parents[3] / "tests" / "protocol" / "vectors"
BACKSLASH = chr(92)
MSG = "msg_01M24BB8G0E87TVJX9GX248ADD"
SES = "ses_01M24BB8G2E87V1ZPZXQ7DSCVW"
EVT = "evt_01M24BB8G4EKX8P1DMZ95GB82V"
TS = "2026-09-12T09:14:22.481Z"


def _code(fn: object, *args: object) -> str:
    assert callable(fn)
    with pytest.raises(ProtocolError) as caught:
        fn(*args)
    return caught.value.code


# ---- canonical JSON -----------------------------------------------------------


def test_every_double_serialises_exactly_as_v8_does() -> None:
    corpus = json.loads((VECTORS / "numbers.json").read_text(encoding="utf-8"))
    vectors = corpus["vectors"]
    assert len(vectors) > 8000
    failures = []
    for v in vectors:
        (x,) = struct.unpack(">d", bytes.fromhex(v["bits"]))
        if jcs.format_es(x) != v["es"]:
            failures.append((v["bits"], v["es"], jcs.format_es(x)))
    assert not failures, f"{len(failures)} mismatches, first {failures[:1]}"


def test_rfc_8785_round_to_even_sample() -> None:
    (x,) = struct.unpack(">d", bytes.fromhex("43143ff3c1cb0959"))
    assert jcs.format_es(x) == "1424953923781206.2"


def test_keys_sort_by_utf16_code_units() -> None:
    emoji, dalet = chr(0x1F600), chr(0xFB33)
    assert jcs.canonicalize({dalet: 1, emoji: 2}) == f'{{"{emoji}":2,"{dalet}":1}}'.encode()


def test_string_escaping() -> None:
    raw = "".join(chr(c) for c in range(0x20)) + '"' + BACKSLASH + "/" + chr(0x7F) + chr(0x2028)
    out = jcs.canonicalize(raw).decode("utf-8")
    assert out.startswith('"' + BACKSLASH + "u0000")
    assert BACKSLASH + "b" in out and BACKSLASH + "t" in out and BACKSLASH + "n" in out
    assert BACKSLASH + "u001f" in out
    assert out.endswith(
        BACKSLASH + '"' + BACKSLASH + BACKSLASH + "/" + chr(0x7F) + chr(0x2028) + '"'
    )


def test_canonicalisation_is_idempotent_and_order_insensitive() -> None:
    a = parse(b'{ "b": [1, 2.50, {"z": null, "a": true}], "a": "x" }', IJSON)
    b = parse(b'{"a":"x","b":[1,2.5,{"a":true,"z":null}]}', IJSON)
    assert (
        jcs.canonicalize(a) == jcs.canonicalize(b) == b'{"a":"x","b":[1,2.5,{"a":true,"z":null}]}'
    )


@pytest.mark.parametrize(
    ("spelling", "canonical"),
    [
        ("1.0", "1"),
        ("1e0", "1"),
        ("-0", "0"),
        ("-0.0", "0"),
        ("5e-1", "0.5"),
        ("1e21", "1e+21"),
        ("9007199254740993", "9007199254740992"),
        ("1e-7", "1e-7"),
    ],
)
def test_one_canonical_form_per_number(spelling: str, canonical: str) -> None:
    assert jcs.canonicalize(parse(spelling.encode(), IJSON)).decode() == canonical


# ---- framing ------------------------------------------------------------------


def test_frame_limits() -> None:
    assert frame.decode_all(frame.encode(b" " * MAX_FRAME_BODY))[0].body == b" " * MAX_FRAME_BODY
    assert _code(frame.encode, b" " * (MAX_FRAME_BODY + 1)) == FRAME_TOO_LARGE
    assert (
        _code(frame.FrameDecoder().feed, struct.pack(">IB", MAX_FRAME_BODY + 1, 1))
        == FRAME_TOO_LARGE
    )
    assert _code(frame.FrameDecoder().feed, struct.pack(">IB", 2**32 - 1, 1)) == FRAME_TOO_LARGE
    assert _code(frame.decode_all, struct.pack(">IB", 0, 1)) == FRAME_EMPTY
    assert _code(frame.decode_all, struct.pack(">IB", 2, 2) + b"{}") == CONTENT_TYPE_UNSUPPORTED
    assert _code(frame.decode_all, b"\x00\x00\x00") == FRAME_TRUNCATED
    assert _code(frame.decode_all, frame.encode(b"{}") + b"\x00\x00") == FRAME_TRUNCATED


def test_chunking_does_not_matter_and_errors_poison() -> None:
    stream = frame.encode(b"[1]") + frame.encode(b"x" * 70_000) + frame.encode(b"{}")
    expected = frame.decode_all(stream)
    for size in (1, 2, 5, 13, 4096, len(stream)):
        decoder = frame.FrameDecoder()
        got = []
        for i in range(0, len(stream), size):
            rest = stream[i : i + size]
            while rest:
                used, f = decoder.feed(rest)
                if f is not None:
                    got.append(f)
                rest = rest[used:]
        decoder.finish()
        assert got == expected
    poisoned = frame.FrameDecoder()
    with pytest.raises(ProtocolError):
        poisoned.feed(struct.pack(">IB", 0, 1))
    assert _code(poisoned.feed, frame.encode(b"{}")) == FRAME_EMPTY


# ---- the strict reader --------------------------------------------------------------


def test_depth_limit_boundaries() -> None:
    assert parse(("[" * MAX_DEPTH + "]" * MAX_DEPTH).encode(), SAFE_INTEGER) is not None
    assert (
        _code(parse, ("[" * (MAX_DEPTH + 1) + "]" * (MAX_DEPTH + 1)).encode(), SAFE_INTEGER)
        == MAX_DEPTH_EXCEEDED
    )
    assert (
        _code(parse, ('{"a":[' * 17 + "0" + "]}" * 17).encode(), SAFE_INTEGER) == MAX_DEPTH_EXCEEDED
    )
    assert _code(parse, ("[" * 1_000_000).encode(), SAFE_INTEGER) == MAX_DEPTH_EXCEEDED
    # Brackets inside strings are not nesting.
    assert parse(json.dumps(["[" * 100]).encode(), SAFE_INTEGER) == ["[" * 100]


def test_keys_are_checked_before_a_dict_can_collapse_them() -> None:
    assert _code(parse, b'{"a":{"b":[{"c":1,"c":2}]}}', SAFE_INTEGER) == DUPLICATE_KEY
    escaped_v = '{"v":1,"' + BACKSLASH + 'u0076":2}'
    assert _code(parse, escaped_v.encode(), SAFE_INTEGER) == DUPLICATE_KEY
    # Keys equal only under Unicode NFC are two members, not a duplicate: no
    # reader normalises, so the decision cannot depend on which Unicode version
    # the host library ships (ADR-0034).
    collision = json.dumps({"caf" + chr(0xE9): 1, "cafe" + chr(0x301): 2}, ensure_ascii=False)
    assert len(parse(collision.encode(), SAFE_INTEGER)) == 2  # type: ignore[arg-type]
    kelvin = json.dumps({"K": 1, chr(0x212A): 2})
    assert len(parse(kelvin.encode(), SAFE_INTEGER)) == 2  # type: ignore[arg-type]
    assert parse(b'[{"a":1},{"a":2}]', SAFE_INTEGER) == [{"a": 1}, {"a": 2}]


def test_numbers_are_rejected_not_rounded() -> None:
    for n in ("1.0", "1e3", "9007199254740992", "-9007199254740992", "1E400", "1" * 5000):
        assert _code(parse, n.encode(), SAFE_INTEGER) == NUMBER_OUT_OF_DOMAIN, n
    assert _code(parse, b"1e400", IJSON) == NUMBER_OUT_OF_DOMAIN
    assert parse(b"-9007199254740991", SAFE_INTEGER) == -9007199254740991
    assert parse(b"true", SAFE_INTEGER) is True


def test_lone_surrogate_escapes_are_invalid() -> None:
    for body in ("ud800", "udc00", "udc00" + BACKSLASH + "ud800"):
        doc = '["' + BACKSLASH + body + '"]'
        assert _code(parse, doc.encode(), SAFE_INTEGER) == INVALID_JSON, body
    pair = '["' + BACKSLASH + "ud83d" + BACKSLASH + 'ude00"]'
    assert parse(pair.encode(), SAFE_INTEGER) == [chr(0x1F600)]


# ---- versions -------------------------------------------------------------------------


def test_negotiation() -> None:
    assert negotiate(VersionRange(1, 9), SUPPORTED_ENVELOPE, 1) == 1
    with pytest.raises(ProtocolError) as caught:
        negotiate(VersionRange(4, 6), SUPPORTED_ENVELOPE, 1)
    assert caught.value.code == VERSION_UNSUPPORTED
    assert caught.value.supported == VersionRange(1, 1)
    with pytest.raises(ProtocolError):
        negotiate(VersionRange(1, 2), VersionRange(1, 4), 3)  # the floor blocks a downgrade


# ---- the three compatibility rules (ADR-0023) -------------------------------------------


EXTENSION: dict[str, JsonValue] = {"x_future": {"retry_after_ms": 1500}}


def test_dwkp_rejects_the_unknown_field() -> None:
    doc = {
        "v": 1,
        "id": MSG,
        "type": "request",
        "schema": "direwolf.heartbeat",
        "schema_version": 1,
        "ts": TS,
        "session_id": SES,
        "epoch": 47,
        "payload": EXTENSION,
    }
    with pytest.raises(ProtocolError) as caught:
        dwkp.decode_body(json.dumps(doc).encode())
    assert (caught.value.code, caught.value.violation, caught.value.path) == (
        SCHEMA_VIOLATION,
        UNKNOWN_FIELD,
        "/payload/x_future",
    )


def test_dwcp_preserves_the_unknown_field() -> None:
    doc: dict[str, JsonValue] = {
        "v": 1,
        "id": MSG,
        "type": "response",
        "schema": "direwolf.error",
        "schema_version": 1,
        "ts": TS,
        "x_envelope": [1, 2.5],
        "payload": {"code": "RATE_LIMITED", "detail": "d", "retryable": True, **EXTENSION},
    }
    message = dwcp.decode(json.dumps(doc).encode())
    assert message.header_extensions == {"x_envelope": [1, 2.5]}
    assert jcs.canonicalize(parse(dwcp.encode(message), IJSON)) == jcs.canonicalize(doc)


def test_event_log_retains_unknown_data_as_bytes() -> None:
    known = (
        '{ "v":1, "id":"' + EVT + '", "type":"event", "schema":"direwolf.session.lease_acquired",'
        ' "schema_version":1, "ts":"' + TS + '", "session_id":"' + SES + '",'
        ' "payload":{"epoch":48,"x_future":{"a":1}} }\n'
    ).encode()
    record = events.read(known)
    assert record.raw == known
    assert isinstance(record.view, KnownEvent)
    unknown = b'{"v":7,"totally":"different","payload":{"f":1e-300}}'
    assert events.read(unknown).raw == unknown
    assert isinstance(events.read(unknown).view, UnknownEvent)


def test_dwkp_rejects_unknown_and_reserved_operations() -> None:
    # A reserved operation has no wire name at all until its milestone defines one.
    reserved = [op for op in operations.OPERATIONS if op.status != "defined"]
    assert reserved and all(op.request is None for op in reserved)
    # `direwolf.tool.invoke` is defined from M4b (ADR-0043); `tool.cancel` is
    # not, and neither is anything no milestone has named.
    for schema in ("direwolf.tool.cancel", "direwolf.exec.raw", "direwolf.session.created"):
        doc = {
            "v": 1,
            "id": MSG,
            "type": "request",
            "schema": schema,
            "schema_version": 1,
            "ts": TS,
            "payload": {},
        }
        with pytest.raises(ProtocolError) as caught:
            dwkp.decode_body(json.dumps(doc).encode())
        assert caught.value.code == UNKNOWN_OPERATION


def test_the_encoder_refuses_to_emit_what_the_decoder_would_reject() -> None:
    from direwolf.wire.envelope import DwkpMessage, Header

    header = Header(
        v=1, id=MSG, type="request", schema="direwolf.heartbeat", schema_version=1, ts=TS
    )
    with pytest.raises(ProtocolError):
        dwkp.encode(DwkpMessage(header, dwkp.HeartbeatPayload()))  # no session or epoch
