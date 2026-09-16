"""Protocol suites: measure what the real decoder does with hostile input.

Every runner here calls the generated bindings in ``direwolf.proto`` and the
hand-written reader in ``direwolf.wire``. None of them re-implements a rule —
a suite that parsed messages itself would be measuring its own copy of the
protocol, which is how a green dashboard and a broken product coexist.

**What these suites establish:** malformed or hostile DWKP is structurally
rejected, DWCP preserves what it does not understand, event records keep their
bytes, and canonical encoding is stable. **What they do not:** anything about
authority. There is no kernel yet; nothing here is evidence that a request
would be authorised, and the suites that would measure that are pending (see
``direwolf_evals.inventory``).
"""

from __future__ import annotations

import json
import struct
from typing import TYPE_CHECKING, Any

from direwolf.proto import dwcp, dwkp, events, operations
from direwolf.wire import frame, jcs
from direwolf.wire.errors import (
    CONTENT_TYPE_UNSUPPORTED,
    FRAME_EMPTY,
    FRAME_TOO_LARGE,
    FRAME_TRUNCATED,
    MAX_FRAME_BODY,
    UNKNOWN_OPERATION,
    ProtocolError,
)
from direwolf.wire.strict_json import IJSON, JsonValue, parse
from direwolf_evals.fixtures import load_fixture
from direwolf_evals.model import Outcome, Status

if TYPE_CHECKING:  # pragma: no cover - import cycle only matters to type checkers
    from direwolf_evals.runners import Context

__all__ = [
    "canonical_determinism",
    "compatibility",
    "framing",
    "hostile_vectors",
    "reserved_operations",
]

_DECODERS = {"dwkp": dwkp.decode_body, "dwcp": dwcp.decode, "event": events.read}


def hostile_vectors(ctx: Context) -> Outcome:
    """Every shared invalid vector must be rejected with the expected code.

    Score: the fraction rejected exactly as specified. Anything below 1.0 is a
    parser that accepted, or mis-classified, an input the contract says it must
    refuse.
    """
    fixture = _fixture(ctx)
    vectors = fixture.require("vectors")
    classes: dict[str, int] = {}
    failures: list[str] = []
    for vector in vectors:
        family = vector["family"]
        data = _input_bytes(vector)
        classes[vector["code"]] = classes.get(vector["code"], 0) + 1
        try:
            _DECODERS[family](data)
        except ProtocolError as err:
            if err.code != vector["code"]:
                failures.append(f"{vector['name']}: expected {vector['code']}, got {err.code}")
            elif "violation" in vector and err.violation != vector["violation"]:
                failures.append(
                    f"{vector['name']}: expected violation {vector['violation']}, "
                    f"got {err.violation}"
                )
            elif "path" in vector and err.path != vector["path"]:
                failures.append(
                    f"{vector['name']}: expected path {vector['path']!r}, got {err.path!r}"
                )
        else:
            failures.append(f"{vector['name']}: ACCEPTED an input that must be rejected")

    total = len(vectors)
    rejected = total - len(failures)
    return Outcome(
        status=Status.PASS if not failures else Status.FAIL,
        metrics={
            "vectors": float(total),
            "rejected_as_specified": float(rejected),
            "rejection_rate": rejected / total if total else 0.0,
            "distinct_error_classes": float(len(classes)),
        },
        reason="" if not failures else f"{len(failures)} of {total} vectors decided wrongly",
        artifacts={"failures": "\n".join(failures[:20])} if failures else {},
    )


def framing(_ctx: Context) -> Outcome:
    """Frame-level hostility: sizes, truncation, desynchronisation, mixed streams.

    Score: the fraction of framing cases decided as specified.
    """
    body = b'{"v":1}'
    good = frame.encode(body)
    cases: list[tuple[str, bytes, str | None]] = [
        ("empty declared body", struct.pack(">IB", 0, 1), FRAME_EMPTY),
        ("one byte over the limit", struct.pack(">IB", MAX_FRAME_BODY + 1, 1), FRAME_TOO_LARGE),
        ("absurd declared length", struct.pack(">IB", 0xFFFFFFFF, 1), FRAME_TOO_LARGE),
        (
            "unknown content type",
            struct.pack(">IB", len(body), 0x02) + body,
            CONTENT_TYPE_UNSUPPORTED,
        ),
        ("truncated header", good[:3], FRAME_TRUNCATED),
        ("truncated body", good[:-1], FRAME_TRUNCATED),
        ("trailing garbage after a frame", good + b"\x00\x00", FRAME_TRUNCATED),
        ("two valid frames", good + good, None),
        ("valid frame after a malformed one", struct.pack(">IB", 0, 1) + good, FRAME_EMPTY),
    ]
    failures = []
    for name, data, expected in cases:
        try:
            frames = frame.decode_all(data)
        except ProtocolError as err:
            if expected is None:
                failures.append(f"{name}: rejected with {err.code}, expected acceptance")
            elif err.code != expected:
                failures.append(f"{name}: expected {expected}, got {err.code}")
        else:
            if expected is not None:
                failures.append(f"{name}: ACCEPTED ({len(frames)} frames), expected {expected}")

    # A stream that desynchronises must stay refused, not resynchronise onto a
    # frame boundary an attacker chose.
    decoder = frame.FrameDecoder()
    poisoned = True
    try:
        decoder.feed(struct.pack(">IB", 0, 1))
    except ProtocolError:
        try:
            decoder.feed(good)
        except ProtocolError:
            poisoned = True
        else:
            poisoned = False
    if not poisoned:
        failures.append("a poisoned decoder accepted a later frame")

    total = len(cases) + 1
    return Outcome(
        status=Status.PASS if not failures else Status.FAIL,
        metrics={
            "cases": float(total),
            "decided_as_specified": float(total - len(failures)),
            "rejection_rate": (total - len(failures)) / total,
        },
        reason="" if not failures else "; ".join(failures[:3]),
        artifacts={"failures": "\n".join(failures)} if failures else {},
    )


def reserved_operations(_ctx: Context) -> Outcome:
    """A reserved operation has no wire form: naming one must be refused.

    Score: the fraction of reserved operations refused with
    ``PROTOCOL_UNKNOWN_OPERATION``. M2's inventory reserves sixteen; each gains
    a payload only in the milestone that owns it, with the second-path review.
    """
    reserved = [op for op in operations.OPERATIONS if op.status != "defined"]
    invented = ["direwolf.exec.raw", "direwolf.tool.invoke", "direwolf.session.created"]
    names = [_schema_name(op.name) for op in reserved] + invented
    failures = []
    for name in names:
        doc = {
            "v": 1,
            "id": "msg_01M24BB8G0E87TVJX9GX248ADD",
            "type": "request",
            "schema": name,
            "schema_version": 1,
            "ts": "2026-09-12T09:14:22.481Z",
            "payload": {},
        }
        try:
            dwkp.decode_body(json.dumps(doc).encode())
        except ProtocolError as err:
            if err.code != UNKNOWN_OPERATION:
                failures.append(f"{name}: {err.code}, expected {UNKNOWN_OPERATION}")
        else:
            failures.append(f"{name}: ACCEPTED a reserved or invented operation")
    return Outcome(
        status=Status.PASS if not failures else Status.FAIL,
        metrics={
            "reserved_operations": float(len(reserved)),
            "names_tried": float(len(names)),
            "refused": float(len(names) - len(failures)),
        },
        reason="" if not failures else "; ".join(failures[:3]),
    )


def compatibility(_ctx: Context) -> Outcome:
    """The three compatibility rules, measured as three separate properties.

    Score: the fraction of the three that hold (ADR-0023 forbids collapsing
    them into one assertion, and a single number would hide which one broke).
    """
    msg = "msg_01M24BB8G0E87TVJX9GX248ADD"
    ses = "ses_01M24BB8G2E87V1ZPZXQ7DSCVW"
    evt = "evt_01M24BB8G4EKX8P1DMZ95GB82V"
    ts = "2026-09-12T09:14:22.481Z"
    extension: dict[str, JsonValue] = {"x_future": {"retry_after_ms": 1500}}
    checks: dict[str, bool] = {}
    detail: list[str] = []

    request = {
        "v": 1,
        "id": msg,
        "type": "request",
        "schema": "direwolf.heartbeat",
        "schema_version": 1,
        "ts": ts,
        "session_id": ses,
        "epoch": 47,
        "payload": dict(extension),
    }
    try:
        dwkp.decode_body(json.dumps(request).encode())
    except ProtocolError as err:
        checks["dwkp_rejects_unknown_field"] = err.path == "/payload/x_future"
        if not checks["dwkp_rejects_unknown_field"]:
            detail.append(f"DWKP rejected at {err.path!r}, expected /payload/x_future")
    else:
        checks["dwkp_rejects_unknown_field"] = False
        detail.append("DWKP accepted an unknown field")

    response: dict[str, JsonValue] = {
        "v": 1,
        "id": msg,
        "type": "response",
        "schema": "direwolf.error",
        "schema_version": 1,
        "ts": ts,
        "payload": {"code": "E", "detail": "d", "retryable": False, **extension},
    }
    raw = json.dumps(response).encode()
    try:
        kept = dwcp.decode(raw)
        reemitted = parse(dwcp.encode(kept), IJSON)
        checks["dwcp_preserves_unknown_field"] = reemitted == parse(
            jcs.canonicalize(response), IJSON
        )
    except ProtocolError as err:
        checks["dwcp_preserves_unknown_field"] = False
        detail.append(f"DWCP refused an extension: {err.describe()}")

    record = json.dumps(
        {
            "v": 1,
            "id": evt,
            "type": "event",
            "schema": "direwolf.session.lease_acquired",
            "schema_version": 1,
            "ts": ts,
            "session_id": ses,
            "payload": {"epoch": 48, **extension},
        }
    ).encode()
    try:
        held = events.read(record)
        checks["event_log_retains_bytes"] = held.raw == record
    except ProtocolError as err:
        checks["event_log_retains_bytes"] = False
        detail.append(f"the event log refused a record: {err.describe()}")

    held_count = sum(1 for ok in checks.values() if ok)
    return Outcome(
        status=Status.PASS if held_count == len(checks) else Status.FAIL,
        metrics={
            "properties": float(len(checks)),
            "held": float(held_count),
            **{name: float(ok) for name, ok in checks.items()},
        },
        reason="" if held_count == len(checks) else "; ".join(detail),
    )


def canonical_determinism(ctx: Context) -> Outcome:
    """Canonical encoding is stable, idempotent and order-independent.

    Score: the fraction of valid vectors whose canonical bytes match the
    independent oracle and survive a re-encode unchanged.
    """
    fixture = _fixture(ctx)
    checked = 0
    failures: list[str] = []
    for vector in fixture.require("vectors"):
        expected = vector.get("canonical")
        if not expected:
            continue
        checked += 1
        value = parse(vector["input"].encode(), IJSON)
        once = jcs.canonicalize(value)
        if once.decode() != expected:
            failures.append(f"{vector['name']}: canonical bytes differ from the oracle")
        elif jcs.canonicalize(parse(once, IJSON)) != once:
            failures.append(f"{vector['name']}: canonicalisation is not idempotent")
    return Outcome(
        status=Status.PASS if not failures else Status.FAIL,
        metrics={
            "vectors": float(checked),
            "stable": float(checked - len(failures)),
            "stability_rate": (checked - len(failures)) / checked if checked else 0.0,
        },
        reason="" if not failures else "; ".join(failures[:3]),
    )


def _fixture(ctx: Context) -> Any:
    if ctx.evaluation.fixture is None:
        raise ValueError(f"{ctx.evaluation.id} needs a fixture")
    return load_fixture(ctx.repo_root, ctx.evaluation.fixture)


def _input_bytes(vector: dict[str, Any]) -> bytes:
    if "input" in vector:
        return str(vector["input"]).encode("utf-8")
    return bytes.fromhex(str(vector["input_hex"]))


def _schema_name(operation: str) -> str:
    """A plausible wire name for a reserved operation, e.g. ToolInvoke ->
    direwolf.tool.invoke. Reserved operations have no name of their own, which
    is the point: any spelling must be refused."""
    parts: list[str] = []
    current = ""
    for char in operation:
        if char.isupper() and current:
            parts.append(current.lower())
            current = char
        else:
            current += char
    parts.append(current.lower())
    return "direwolf." + ".".join(parts)
