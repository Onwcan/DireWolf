"""Randomised round-trip properties for the Python wire layer.

The Rust crate checks the same properties with ``proptest``
(``crates/dwk-proto/tests/properties.rs``). Here they are generated with the
standard library's PRNG under fixed seeds, so a failure reproduces exactly and
no test dependency is added. There is no shrinking: a failure prints the seed
and the case index, and the case is re-derivable from those.
"""

from __future__ import annotations

import json
import random
import struct
from collections.abc import Callable
from typing import Final

import pytest

from direwolf.proto import dwcp, dwkp
from direwolf.wire import frame, jcs
from direwolf.wire.envelope import DwkpMessage, Header
from direwolf.wire.errors import (
    ERROR_CODES,
    MAX_SAFE_INTEGER,
    NUMBER_OUT_OF_DOMAIN,
    SCHEMA_VIOLATION,
    UNKNOWN_FIELD,
    VIOLATIONS,
    ProtocolError,
)
from direwolf.wire.strict_json import IJSON, SAFE_INTEGER, JsonValue, normalise_number, parse

SEEDS: Final = range(8)
CASES: Final = 250
CROCKFORD: Final = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


# ---- generators -----------------------------------------------------------------


def _char(rng: random.Random) -> str:
    """Any Unicode scalar value, weighted towards the awkward ones."""
    pick = rng.random()
    if pick < 0.3:
        return chr(rng.randrange(0x20, 0x7F))
    if pick < 0.4:
        return chr(rng.randrange(0x00, 0x20))  # control characters must be escaped
    if pick < 0.5:
        return rng.choice(['"', chr(92), "/", chr(0x7F), chr(0x2028), chr(0xFEFF)])
    if pick < 0.6:
        return chr(rng.randrange(0x300, 0x370))  # combining marks
    if pick < 0.8:
        return chr(rng.randrange(0x80, 0xD800))
    if pick < 0.9:
        return chr(rng.randrange(0xE000, 0x10000))
    return chr(rng.randrange(0x10000, 0x110000))  # astral: a UTF-16 surrogate pair


def _text(rng: random.Random, max_len: int) -> str:
    return "".join(_char(rng) for _ in range(rng.randrange(0, max_len + 1)))


def _double(rng: random.Random) -> float:
    while True:
        x: float = struct.unpack(">d", rng.getrandbits(64).to_bytes(8, "big"))[0]
        if x == x and abs(x) != float("inf"):
            return x


def _json(rng: random.Random, depth: int = 0, *, floats: bool = True) -> JsonValue:
    kinds = ["null", "bool", "int", "str"] + (["float"] if floats else [])
    if depth < 6:
        kinds += ["list", "dict", "dict"]
    kind = rng.choice(kinds)
    if kind == "null":
        return None
    if kind == "bool":
        return rng.random() < 0.5
    if kind == "int":
        return rng.randint(-MAX_SAFE_INTEGER, MAX_SAFE_INTEGER)
    if kind == "float":
        return normalise_number(_double(rng) if rng.random() < 0.7 else rng.uniform(-1e3, 1e3))
    if kind == "str":
        return _text(rng, 12)
    if kind == "list":
        return [_json(rng, depth + 1, floats=floats) for _ in range(rng.randrange(0, 5))]
    out: dict[str, JsonValue] = {}
    seen: set[str] = set()
    for _ in range(rng.randrange(0, 5)):
        key = _text(rng, 6)
        if key in seen:  # a duplicate is a separate property (test_wire.py)
            continue
        seen.add(key)
        out[key] = _json(rng, depth + 1, floats=floats)
    return out


def _uuid7_body(rng: random.Random) -> str:
    value = rng.getrandbits(128)
    value = (value & ~(0xF << 76)) | (0x7 << 76)  # version 7
    value = (value & ~(0b11 << 62)) | (0b10 << 62)  # RFC 4122 variant
    digits = []
    for _ in range(26):
        digits.append(CROCKFORD[value & 31])
        value >>= 5
    return "".join(reversed(digits))


def _id(rng: random.Random, prefix: str) -> str:
    return f"{prefix}_{_uuid7_body(rng)}"


def _timestamp(rng: random.Random) -> str:
    year = rng.randrange(1970, 2200)
    month = rng.randrange(1, 13)
    day = rng.randrange(1, 29)
    return (
        f"{year:04d}-{month:02d}-{day:02d}T{rng.randrange(24):02d}:"
        f"{rng.randrange(60):02d}:{rng.randrange(60):02d}.{rng.randrange(1000):03d}Z"
    )


def _version_pair(rng: random.Random) -> tuple[int, int]:
    a, b = rng.randrange(1, 65536), rng.randrange(1, 65536)
    return min(a, b), max(a, b)


def _payload(rng: random.Random, schema: str) -> object:
    if schema == "direwolf.handshake":
        lo, hi = _version_pair(rng)
        return dwkp.Handshake(min_version=lo, max_version=hi)
    if schema == "direwolf.handshake.accepted":
        return dwkp.HandshakeAccepted(version=rng.randrange(1, 65536))
    if schema == "direwolf.lease.grant":
        return dwkp.LeaseGrant(session_id=_id(rng, "ses"), epoch=rng.randint(1, MAX_SAFE_INTEGER))
    if schema == "direwolf.protocol.error":
        span = None
        if rng.random() < 0.5:
            lo, hi = _version_pair(rng)
            span = dwkp.VersionSpan(min=lo, max=hi)
        return dwkp.ProtocolErrorPayload(
            code=rng.choice(ERROR_CODES),
            violation=rng.choice([None, *VIOLATIONS]),
            path=rng.choice([None, "", "/" + _text(rng, 40)]),
            detail=_text(rng, 80),
            supported=span,
        )
    empty: dict[str, Callable[[], object]] = {
        "direwolf.heartbeat": dwkp.HeartbeatPayload,
        "direwolf.lease.acquire": dwkp.LeaseAcquire,
        "direwolf.lease.release": dwkp.LeaseRelease,
        "direwolf.ack": dwkp.Ack,
    }
    return empty[schema]()


def _message(rng: random.Random) -> DwkpMessage:
    (message_type, schema), spec = rng.choice(sorted(dwkp.MESSAGES.items()))
    fields: dict[str, str | int | None] = {}
    generators: dict[str, Callable[[], str | int]] = {
        "correlation_id": lambda: _id(rng, rng.choice(["msg", "run", "ses", "abcdefgh"])),
        "causation_id": lambda: _id(rng, "msg"),
        "session_id": lambda: _id(rng, "ses"),
        "run_id": lambda: _id(rng, "run"),
        "epoch": lambda: rng.randint(1, MAX_SAFE_INTEGER),
        "idempotency_key": lambda: (
            rng.choice("Aa0") + "".join(rng.choice("Az9._:-") for _ in range(rng.randrange(0, 40)))
        ),
    }
    for name, presence in spec.rules.items():
        if presence == "required" or (presence == "optional" and rng.random() < 0.5):
            fields[name] = generators[name]()
    if fields.get("epoch") is not None and fields.get("session_id") is None:
        fields["session_id"] = _id(rng, "ses")
    header = Header(
        v=1,
        id=_id(rng, "msg"),
        type=message_type,
        schema=schema,
        schema_version=1,
        ts=_timestamp(rng),
        **fields,  # type: ignore[arg-type]
    )
    return DwkpMessage(header, _payload(rng, schema))  # type: ignore[arg-type]


def _cases(seed: int) -> list[random.Random]:
    # Reproducibility, not unpredictability, is the requirement here.
    return [random.Random(f"{seed}:{i}") for i in range(CASES)]  # noqa: S311


# ---- properties ----------------------------------------------------------------------


@pytest.mark.parametrize("seed", SEEDS)
def test_canonical_json_round_trips_and_is_idempotent(seed: int) -> None:
    for i, rng in enumerate(_cases(seed)):
        value = _json(rng)
        once = jcs.canonicalize(value)
        reparsed = parse(once, IJSON)
        assert reparsed == value, (seed, i)
        assert jcs.canonicalize(reparsed) == once, (seed, i)
        # No insignificant whitespace survives: the canonical form of a
        # reformatted copy is the same bytes.
        spaced = json.dumps(value, indent=2, ensure_ascii=True).encode()
        assert jcs.canonicalize(parse(spaced, IJSON)) == once, (seed, i)


@pytest.mark.parametrize("seed", SEEDS)
def test_canonical_bytes_do_not_depend_on_member_order(seed: int) -> None:
    for i, rng in enumerate(_cases(seed)):
        value = _json(rng)
        if not isinstance(value, dict):
            continue
        items = list(value.items())
        rng.shuffle(items)
        assert jcs.canonicalize(dict(items)) == jcs.canonicalize(value), (seed, i)


@pytest.mark.parametrize("seed", SEEDS)
def test_every_generated_dwkp_message_round_trips_through_bytes_and_frames(seed: int) -> None:
    for i, rng in enumerate(_cases(seed)):
        message = _message(rng)
        data = dwkp.encode(message)
        assert dwkp.decode_body(data) == message, (seed, i)
        assert jcs.canonicalize(parse(data, SAFE_INTEGER)) == data, (seed, i)
        (only,) = frame.decode_all(dwkp.to_frame(message))
        assert only.body == data, (seed, i)


@pytest.mark.parametrize("seed", SEEDS)
def test_an_extra_payload_member_is_rejected_by_dwkp_and_kept_by_dwcp(seed: int) -> None:
    for i, rng in enumerate(_cases(seed)):
        message = _message(rng)
        doc = json.loads(dwkp.encode(message))
        key = "x_" + "".join(rng.choice("abcdefghijklmnopqrstuvwxyz_") for _ in range(8))
        # Integers only: a fraction would be rejected by the DWKP number domain
        # before the unknown field is ever seen, which is a different property.
        extra = _json(rng, floats=False)
        doc["payload"][key] = extra
        with pytest.raises(ProtocolError) as caught:
            dwkp.decode_body(json.dumps(doc, ensure_ascii=False).encode())
        err = caught.value
        assert (err.code, err.violation, err.path) == (
            SCHEMA_VIOLATION,
            UNKNOWN_FIELD,
            f"/payload/{key}",
        ), (seed, i)

        client: dict[str, JsonValue] = {
            "v": 1,
            "id": _id(rng, "msg"),
            "type": "response",
            "schema": "direwolf.error",
            "schema_version": 1,
            "ts": _timestamp(rng),
            "payload": {"code": "E", "detail": _text(rng, 20), "retryable": False, key: extra},
        }
        kept = dwcp.decode(json.dumps(client, ensure_ascii=False).encode())
        assert parse(dwcp.encode(kept), IJSON) == parse(jcs.canonicalize(client), IJSON), (seed, i)


@pytest.mark.parametrize("seed", SEEDS)
def test_frames_survive_any_chunking(seed: int) -> None:
    for i, rng in enumerate(_cases(seed)):
        bodies = [rng.randbytes(rng.randrange(1, 300)) for _ in range(rng.randrange(1, 6))]
        stream = b"".join(frame.encode(b) for b in bodies)
        decoder = frame.FrameDecoder()
        got = []
        pos = 0
        while pos < len(stream):
            piece = stream[pos : pos + rng.randrange(1, 64)]
            pos += len(piece)
            while piece:
                used, f = decoder.feed(piece)
                if f is not None:
                    got.append(f.body)
                piece = piece[used:]
        decoder.finish()
        assert got == bodies, (seed, i)


@pytest.mark.parametrize("seed", SEEDS)
def test_integers_outside_the_dwkp_domain_are_rejected_and_inside_accepted(seed: int) -> None:
    for i, rng in enumerate(_cases(seed)):
        inside = rng.randint(-MAX_SAFE_INTEGER, MAX_SAFE_INTEGER)
        assert parse(str(inside).encode(), SAFE_INTEGER) == inside, (seed, i)
        outside = (MAX_SAFE_INTEGER + 1 + rng.getrandbits(rng.randrange(1, 200))) * rng.choice(
            [-1, 1]
        )
        with pytest.raises(ProtocolError) as caught:
            parse(str(outside).encode(), SAFE_INTEGER)
        assert caught.value.code == NUMBER_OUT_OF_DOMAIN, (seed, i)
