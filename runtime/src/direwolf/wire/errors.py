"""Protocol errors and limits, mirroring ``dwk-proto``'s ``error`` and ``limits``.

The wire spellings are fixed by ADR-0023 and ADR-0032. A test compares these
constants with the enumerations emitted into ``schemas/``, so a code added in
Rust cannot be missing here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

MAX_FRAME_BODY: Final = 1 << 20
MAX_MESSAGE_BYTES: Final = MAX_FRAME_BODY
MAX_DEPTH: Final = 32
MAX_SAFE_INTEGER: Final = (1 << 53) - 1
MAX_ERROR_PATH_CHARS: Final = 256
MAX_ERROR_DETAIL_CHARS: Final = 512

FRAME_EMPTY: Final = "PROTOCOL_FRAME_EMPTY"
FRAME_TOO_LARGE: Final = "PROTOCOL_FRAME_TOO_LARGE"
FRAME_TRUNCATED: Final = "PROTOCOL_FRAME_TRUNCATED"
CONTENT_TYPE_UNSUPPORTED: Final = "PROTOCOL_CONTENT_TYPE_UNSUPPORTED"
INVALID_UTF8: Final = "PROTOCOL_INVALID_UTF8"
INVALID_JSON: Final = "PROTOCOL_INVALID_JSON"
DUPLICATE_KEY: Final = "PROTOCOL_DUPLICATE_KEY"
MAX_DEPTH_EXCEEDED: Final = "PROTOCOL_MAX_DEPTH_EXCEEDED"
NUMBER_OUT_OF_DOMAIN: Final = "PROTOCOL_NUMBER_OUT_OF_DOMAIN"
VERSION_UNSUPPORTED: Final = "PROTOCOL_VERSION_UNSUPPORTED"
UNKNOWN_OPERATION: Final = "PROTOCOL_UNKNOWN_OPERATION"
SCHEMA_VIOLATION: Final = "PROTOCOL_SCHEMA_VIOLATION"

ERROR_CODES: Final = (
    FRAME_EMPTY,
    FRAME_TOO_LARGE,
    FRAME_TRUNCATED,
    CONTENT_TYPE_UNSUPPORTED,
    INVALID_UTF8,
    INVALID_JSON,
    DUPLICATE_KEY,
    MAX_DEPTH_EXCEEDED,
    NUMBER_OUT_OF_DOMAIN,
    VERSION_UNSUPPORTED,
    UNKNOWN_OPERATION,
    SCHEMA_VIOLATION,
)

UNKNOWN_FIELD: Final = "UNKNOWN_FIELD"
MISSING_FIELD: Final = "MISSING_FIELD"
FORBIDDEN_FIELD: Final = "FORBIDDEN_FIELD"
WRONG_TYPE: Final = "WRONG_TYPE"
NULL_NOT_ALLOWED: Final = "NULL_NOT_ALLOWED"
OUT_OF_RANGE: Final = "OUT_OF_RANGE"
TOO_LONG: Final = "TOO_LONG"
INVALID_FORMAT: Final = "INVALID_FORMAT"
UNKNOWN_VARIANT: Final = "UNKNOWN_VARIANT"
TOO_MANY_ITEMS: Final = "TOO_MANY_ITEMS"
INCONSISTENT: Final = "INCONSISTENT"

VIOLATIONS: Final = (
    UNKNOWN_FIELD,
    MISSING_FIELD,
    FORBIDDEN_FIELD,
    WRONG_TYPE,
    NULL_NOT_ALLOWED,
    OUT_OF_RANGE,
    TOO_LONG,
    INVALID_FORMAT,
    UNKNOWN_VARIANT,
    TOO_MANY_ITEMS,
    INCONSISTENT,
)


class ProtocolError(Exception):
    """The bytes did not form a valid message. Never a policy decision."""

    def __init__(
        self,
        code: str,
        detail: str,
        *,
        violation: str | None = None,
        path: str = "",
        supported: VersionRange | None = None,
    ) -> None:
        self.code = code
        self.violation = violation
        self.path = path[:MAX_ERROR_PATH_CHARS]
        self.detail = detail[:MAX_ERROR_DETAIL_CHARS]
        self.supported = supported
        super().__init__(self.describe())

    def describe(self) -> str:
        parts = [self.code]
        if self.violation:
            parts.append(f"({self.violation})")
        if self.path:
            parts.append(f"at {self.path}")
        return " ".join(parts) + f": {self.detail}"


def schema_violation(violation: str, path: str, detail: str) -> ProtocolError:
    """A ``PROTOCOL_SCHEMA_VIOLATION`` at ``path``."""
    return ProtocolError(SCHEMA_VIOLATION, detail, violation=violation, path=path)


@dataclass(frozen=True, slots=True)
class VersionRange:
    """An inclusive range of protocol versions. Version 0 does not exist."""

    min: int
    max: int

    def contains(self, v: int) -> bool:
        return self.min <= v <= self.max


SUPPORTED_ENVELOPE: Final = VersionRange(1, 1)


def negotiate(offered: VersionRange, supported: VersionRange, minimum: int) -> int:
    """Highest version both peers support at or above the receiver's floor."""
    low = max(offered.min, supported.min, minimum)
    high = min(offered.max, supported.max)
    if low <= high:
        return high
    floor = max(supported.min, minimum)
    advertised = VersionRange(floor, supported.max) if floor <= supported.max else supported
    raise ProtocolError(
        VERSION_UNSUPPORTED,
        f"offered {offered.min}..={offered.max} shares no version with "
        f"{advertised.min}..={advertised.max}",
        violation=OUT_OF_RANGE,
        path="/payload",
        supported=advertised,
    )
