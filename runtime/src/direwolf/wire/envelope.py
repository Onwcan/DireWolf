"""The common envelope and the three family decoders.

Mirrors ``dwk-proto``'s ``envelope``, ``dwkp``, ``dwcp`` and ``events`` modules,
in the same decode order, so both implementations report the same failure for
the same single-fault input:

1. the document is an object;
2. ``v`` present, an integer, in range, and supported;
3. ``type``, ``schema``, ``schema_version``;
4. family lookup (DWKP rejects unknown operations; DWCP and events retain them);
5. undeclared envelope members (DWKP rejects; DWCP and events preserve);
6. ``id``, ``ts``, then the optional fields against the message's rules;
7. ``epoch`` requires ``session_id``; the ``id`` prefix matches the type;
8. ``payload`` present and an object, then decoded by its generated type.

The per-message rules and payload types are generated into
:mod:`direwolf.proto` and passed in; this module holds only the mechanism. The
field formats below are checked against ``schemas/common/envelope.v1.schema.json``
by the test suite.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Final, Literal, Protocol, Self

from direwolf.wire import frame, jcs, strict_json, validate
from direwolf.wire.errors import (
    FORBIDDEN_FIELD,
    FRAME_TOO_LARGE,
    INCONSISTENT,
    INVALID_FORMAT,
    MAX_MESSAGE_BYTES,
    MAX_SAFE_INTEGER,
    MISSING_FIELD,
    NULL_NOT_ALLOWED,
    OUT_OF_RANGE,
    SUPPORTED_ENVELOPE,
    UNKNOWN_OPERATION,
    VERSION_UNSUPPORTED,
    WRONG_TYPE,
    ProtocolError,
    VersionRange,
    schema_violation,
)
from direwolf.wire.strict_json import JsonValue
from direwolf.wire.validate import Cx

type Presence = Literal["required", "optional", "forbidden"]

ENVELOPE_KEYS: Final = (
    "v",
    "id",
    "type",
    "schema",
    "schema_version",
    "ts",
    "correlation_id",
    "causation_id",
    "session_id",
    "run_id",
    "epoch",
    "idempotency_key",
    "payload",
)

MESSAGE_TYPES: Final = ("request", "response", "event")
ID_PREFIX: Final = {"request": "msg", "response": "msg", "event": "evt"}

SCHEMA_NAME_PATTERN: Final = "^direwolf(\\.[a-z][a-z0-9_]{0,31}){1,6}$"
TIMESTAMP_PATTERN: Final = "^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}Z$"
IDEMPOTENCY_KEY_PATTERN: Final = "^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"

_VERSION = validate.integer(1, 65535)
_TYPE = validate.enumeration(MESSAGE_TYPES)
_SCHEMA = validate.text(128, SCHEMA_NAME_PATTERN, None)
_TS = validate.text(24, TIMESTAMP_PATTERN, "rfc3339-utc-millis")
_ANY_ID = validate.identifier(None)
_OPTIONAL_CHECKS: Final[dict[str, validate.Check[str] | validate.Check[int]]] = {
    "correlation_id": _ANY_ID,
    "causation_id": _ANY_ID,
    "session_id": validate.identifier("ses"),
    "run_id": validate.identifier("run"),
    "epoch": validate.integer(1, MAX_SAFE_INTEGER),
    "idempotency_key": validate.text(128, IDEMPOTENCY_KEY_PATTERN, None),
}


class Payload(Protocol):
    """What every generated payload type provides."""

    @classmethod
    def decode(cls, value: JsonValue, cx: Cx) -> Self: ...

    def encode(self) -> dict[str, JsonValue]: ...


@dataclass(frozen=True, slots=True)
class Rules:
    """Presence of the optional envelope fields for one message."""

    correlation_id: Presence
    causation_id: Presence
    session_id: Presence
    run_id: Presence
    epoch: Presence
    idempotency_key: Presence

    def items(self) -> tuple[tuple[str, Presence], ...]:
        return (
            ("correlation_id", self.correlation_id),
            ("causation_id", self.causation_id),
            ("session_id", self.session_id),
            ("run_id", self.run_id),
            ("epoch", self.epoch),
            ("idempotency_key", self.idempotency_key),
        )


PERMISSIVE: Final = Rules("optional", "optional", "optional", "optional", "optional", "optional")


@dataclass(frozen=True, slots=True)
class MessageSpec:
    """One message this build knows, as generated from its schema."""

    schema: str
    message_type: str
    versions: VersionRange
    rules: Rules
    payload: type[Payload]


type Registry = Mapping[tuple[str, str], MessageSpec]


@dataclass(frozen=True, slots=True)
class Header:
    """The decoded envelope. Its fields are claims, not facts (ADR-0028)."""

    v: int
    id: str
    type: str
    schema: str
    schema_version: int
    ts: str
    correlation_id: str | None = None
    causation_id: str | None = None
    session_id: str | None = None
    run_id: str | None = None
    epoch: int | None = None
    idempotency_key: str | None = None

    def encode(
        self, payload: JsonValue, extensions: Mapping[str, JsonValue]
    ) -> dict[str, JsonValue]:
        out: dict[str, JsonValue] = {
            "v": self.v,
            "id": self.id,
            "type": self.type,
            "schema": self.schema,
            "schema_version": self.schema_version,
            "ts": self.ts,
        }
        for name in (
            "correlation_id",
            "causation_id",
            "session_id",
            "run_id",
            "epoch",
            "idempotency_key",
        ):
            value = getattr(self, name)
            if value is not None:
                out[name] = value
        out["payload"] = payload
        for key, value in extensions.items():
            out[key] = value
        return out


@dataclass(frozen=True, slots=True)
class Preamble:
    v: int
    type: str
    schema: str
    schema_version: int


def read_preamble(value: JsonValue, supported: VersionRange = SUPPORTED_ENVELOPE) -> Preamble:
    if not isinstance(value, dict):
        raise schema_violation(
            WRONG_TYPE, "", f"a message is an object, found {validate.type_name(value)}"
        )
    v = _peek(value, "v", _VERSION)
    if not supported.contains(v):
        raise ProtocolError(
            VERSION_UNSUPPORTED,
            f"envelope version {v} is not supported",
            violation=OUT_OF_RANGE,
            path="/v",
            supported=supported,
        )
    message_type = _peek(value, "type", _TYPE)
    schema = _peek(value, "schema", _SCHEMA)
    schema_version = _peek(value, "schema_version", _VERSION)
    return Preamble(v, message_type, schema, schema_version)


def _peek[T](obj: dict[str, JsonValue], name: str, check: validate.Check[T]) -> T:
    if name not in obj:
        raise schema_violation(MISSING_FIELD, f"/{name}", f"missing envelope field {name!r}")
    cx = Cx()
    cx.push(name)
    raw = obj[name]
    if raw is None:
        raise cx.violation(NULL_NOT_ALLOWED, "null is not a value")
    return check(raw, cx)


def decode_header(
    obj: dict[str, JsonValue], preamble: Preamble, rules: Rules, preserve: bool
) -> tuple[Header, dict[str, JsonValue], dict[str, JsonValue]]:
    cx = Cx()
    known, extensions = validate.partition(obj, ENVELOPE_KEYS, preserve, cx)
    identifier = validate.take_required(known, "id", cx, _ANY_ID)
    ts = validate.take_required(known, "ts", cx, _TS)
    optional: dict[str, JsonValue] = {}
    for name, presence in rules.items():
        check = _OPTIONAL_CHECKS[name]
        if presence == "forbidden":
            if name in known:
                raise schema_violation(
                    FORBIDDEN_FIELD, f"/{name}", f"envelope field {name!r} is not permitted"
                )
        elif presence == "required":
            optional[name] = validate.take_required(known, name, cx, check)
        else:
            optional[name] = validate.take_optional(known, name, cx, check)
    if optional.get("epoch") is not None and optional.get("session_id") is None:
        raise schema_violation(INCONSISTENT, "/epoch", "session_id is required with epoch")
    if identifier.partition("_")[0] != ID_PREFIX[preamble.type]:
        raise schema_violation(
            INVALID_FORMAT, "/id", f"a {preamble.type} uses a {ID_PREFIX[preamble.type]}_ id"
        )
    if "payload" not in known:
        raise schema_violation(MISSING_FIELD, "/payload", "missing envelope field 'payload'")
    payload = known["payload"]
    if payload is None:
        raise schema_violation(NULL_NOT_ALLOWED, "/payload", "null is not a value")
    if not isinstance(payload, dict):
        raise schema_violation(
            WRONG_TYPE, "/payload", f"expected object, found {validate.type_name(payload)}"
        )

    def opt_str(name: str) -> str | None:
        value = optional.get(name)
        return value if isinstance(value, str) else None

    epoch = optional.get("epoch")
    header = Header(
        v=preamble.v,
        id=identifier,
        type=preamble.type,
        schema=preamble.schema,
        schema_version=preamble.schema_version,
        ts=ts,
        correlation_id=opt_str("correlation_id"),
        causation_id=opt_str("causation_id"),
        session_id=opt_str("session_id"),
        run_id=opt_str("run_id"),
        epoch=epoch if isinstance(epoch, int) else None,
        idempotency_key=opt_str("idempotency_key"),
    )
    return header, payload, extensions


def _decode_payload(spec: MessageSpec, payload: dict[str, JsonValue]) -> Payload:
    cx = Cx()
    cx.push("payload")
    return spec.payload.decode(payload, cx)


# ---- DWKP: strict ------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class DwkpMessage:
    header: Header
    body: Payload


def decode_dwkp(data: bytes, registry: Registry) -> DwkpMessage:
    """Decode a DWKP frame body. Rejects everything ``dwk-proto`` rejects."""
    value = strict_json.parse(data, strict_json.SAFE_INTEGER)
    preamble = read_preamble(value)
    spec = registry.get((preamble.type, preamble.schema))
    if spec is None:
        raise ProtocolError(
            UNKNOWN_OPERATION,
            f"no DWKP {preamble.type} named {preamble.schema} exists in this build",
            path="/schema",
        )
    if not spec.versions.contains(preamble.schema_version):
        raise ProtocolError(
            VERSION_UNSUPPORTED,
            f"{spec.schema} schema_version {preamble.schema_version} is not supported",
            violation=OUT_OF_RANGE,
            path="/schema_version",
            supported=spec.versions,
        )
    if not isinstance(value, dict):  # read_preamble has already rejected this
        raise schema_violation(WRONG_TYPE, "", "a message is an object")
    header, payload, _ = decode_header(value, preamble, spec.rules, preserve=False)
    return DwkpMessage(header, _decode_payload(spec, payload))


def encode_dwkp(message: DwkpMessage, registry: Registry) -> bytes:
    """Canonical bytes, re-decoded before return: never emit what would be rejected."""
    spec = registry.get((message.header.type, message.header.schema))
    if spec is None or not isinstance(message.body, spec.payload):
        raise schema_violation(
            INCONSISTENT, "/schema", "the header's type and schema do not match the body"
        )
    data = jcs.canonicalize(message.header.encode(message.body.encode(), {}))
    if decode_dwkp(data, registry) != message:
        raise schema_violation(INCONSISTENT, "", "message does not survive its own round trip")
    return data


def frame_dwkp(message: DwkpMessage, registry: Registry) -> bytes:
    return frame.encode(encode_dwkp(message, registry))


# ---- DWCP: forward-compatible ----------------------------------------------------


@dataclass(frozen=True, slots=True)
class DwcpMessage:
    header: Header
    header_extensions: dict[str, JsonValue] = field(default_factory=dict)
    body: Payload | None = None
    unknown_payload: dict[str, JsonValue] | None = None


def decode_dwcp(data: bytes, registry: Registry) -> DwcpMessage:
    """Decode a DWCP message, preserving what this build does not declare."""
    if len(data) > MAX_MESSAGE_BYTES:
        raise ProtocolError(FRAME_TOO_LARGE, f"message of {len(data)} bytes exceeds the limit")
    value = strict_json.parse(data, strict_json.IJSON)
    preamble = read_preamble(value)
    if not isinstance(value, dict):  # read_preamble has already rejected this
        raise schema_violation(WRONG_TYPE, "", "a message is an object")
    spec = registry.get((preamble.type, preamble.schema))
    if spec is not None and spec.versions.contains(preamble.schema_version):
        header, payload, extensions = decode_header(value, preamble, spec.rules, preserve=True)
        return DwcpMessage(header, extensions, _decode_payload(spec, payload))
    header, payload, extensions = decode_header(value, preamble, PERMISSIVE, preserve=True)
    return DwcpMessage(header, extensions, None, payload)


def encode_dwcp(message: DwcpMessage) -> bytes:
    if message.body is not None:
        payload: JsonValue = message.body.encode()
    else:
        payload = dict(message.unknown_payload or {})
    return jcs.canonicalize(message.header.encode(payload, message.header_extensions))


# ---- event records: retained verbatim ---------------------------------------------


@dataclass(frozen=True, slots=True)
class KnownEvent:
    header: Header
    header_extensions: dict[str, JsonValue]
    event: Payload


@dataclass(frozen=True, slots=True)
class UnknownEvent:
    schema: str | None
    schema_version: int | None
    reason: ProtocolError


@dataclass(frozen=True, slots=True)
class InvalidEvent:
    error: ProtocolError


@dataclass(frozen=True, slots=True)
class EventRecord:
    """A record's exact bytes and how far they were interpreted."""

    raw: bytes
    view: KnownEvent | UnknownEvent | InvalidEvent


def read_event(data: bytes, registry: Registry) -> EventRecord:
    """Read a record. Raises only if the bytes are not a record at all."""
    if len(data) > MAX_MESSAGE_BYTES:
        raise ProtocolError(FRAME_TOO_LARGE, f"record of {len(data)} bytes exceeds the limit")
    value = strict_json.parse(data, strict_json.IJSON)
    if not isinstance(value, dict):
        raise schema_violation(WRONG_TYPE, "", "an event record is an object")
    schema = value.get("schema")
    schema_version = value.get("schema_version")
    loose_schema = schema if isinstance(schema, str) else None
    loose_version = (
        schema_version
        if isinstance(schema_version, int)
        and not isinstance(schema_version, bool)
        and 0 <= schema_version <= 65535
        else None
    )
    try:
        preamble = read_preamble(value)
    except ProtocolError as reason:
        return EventRecord(data, UnknownEvent(loose_schema, loose_version, reason))
    if preamble.type != "event":
        error = schema_violation("UNKNOWN_VARIANT", "/type", 'an event record has type "event"')
        return EventRecord(data, InvalidEvent(error))
    spec = registry.get(("event", preamble.schema))
    if spec is None or not spec.versions.contains(preamble.schema_version):
        unknown = ProtocolError(
            UNKNOWN_OPERATION, "unknown event schema and version", path="/schema"
        )
        return EventRecord(data, UnknownEvent(loose_schema, loose_version, unknown))
    try:
        header, payload, extensions = decode_header(value, preamble, spec.rules, preserve=True)
        event = _decode_payload(spec, payload)
    except ProtocolError as error:
        return EventRecord(data, InvalidEvent(error))
    return EventRecord(data, KnownEvent(header, extensions, event))
