"""The strict JSON reader, mirroring ``dwk-proto``'s lexer.

Built on the standard library's ``json`` (its C scanner), with every DireWolf
rule enforced through the scanner's hooks or around it:

* bytes must be well-formed UTF-8; no lossy decoding, no BOM;
* grammar is RFC 8259; ``NaN`` and ``Infinity`` are refused;
* nesting deeper than 32 is refused **before** parsing, by a scan that ignores
  brackets inside strings, so no deep structure is ever built;
* an object with two byte-identical keys is refused while its members are still
  a list -- ``object_pairs_hook`` sees them before any dict collapses them.
  Keys are compared as text, never normalised: no protocol decision consults a
  Unicode database, so this reader and the Rust one cannot disagree because
  their host libraries ship different Unicode versions (ADR-0034);
* numbers are restricted per profile, and each value has one representation:
  an integral value within +/-(2**53 - 1) is always an ``int``;
* lone surrogate escapes, which ``json`` accepts and Rust rejects, are refused.

Parity with the Rust lexer is exact for inputs with a single fault, which is
what the shared invalid-message vectors contain. An input with several faults is
rejected by both, but the two may name different faults first: the Rust lexer
works left to right in one pass, while this reader checks depth before grammar
and keys bottom-up.
"""

from __future__ import annotations

import json
import math
from typing import Final

from direwolf.wire.errors import (
    DUPLICATE_KEY,
    INVALID_JSON,
    INVALID_UTF8,
    MAX_DEPTH,
    MAX_DEPTH_EXCEEDED,
    MAX_SAFE_INTEGER,
    NUMBER_OUT_OF_DOMAIN,
    ProtocolError,
)

type JsonValue = bool | int | float | str | list[JsonValue] | dict[str, JsonValue] | None

SAFE_INTEGER: Final = "safe-integer"
"""DWKP: integers without fraction or exponent, magnitude at most 2**53 - 1."""

IJSON: Final = "i-json"
"""DWCP and event records: any finite I-JSON number."""

# More digits than the largest finite double has. Checked before int() so a
# hostile integer cannot trip CPython's int-string conversion limit, which would
# otherwise surface as a different error than the Rust lexer reports.
_MAX_NUMBER_DIGITS: Final = 309


def parse(data: bytes, profile: str) -> JsonValue:
    """Parse ``data`` as exactly one strict JSON value under ``profile``."""
    if profile not in (SAFE_INTEGER, IJSON):
        raise ValueError(f"unknown profile {profile!r}")
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ProtocolError(INVALID_UTF8, "body is not well-formed UTF-8") from exc
    _check_depth(text)
    try:
        value: JsonValue = json.loads(
            text,
            object_pairs_hook=_object,
            parse_int=_integer_hook(profile),
            parse_float=_float_hook(profile),
            parse_constant=_constant,
        )
    except ProtocolError:
        raise
    except (ValueError, TypeError) as exc:
        raise ProtocolError(INVALID_JSON, "not a single RFC 8259 JSON value") from exc
    _reject_lone_surrogates(value)
    return value


def _check_depth(text: str) -> None:
    """Refuse nesting beyond MAX_DEPTH without building the structure."""
    if text.count("[") + text.count("{") <= MAX_DEPTH:
        return
    depth = 0
    in_string = False
    escaped = False
    for ch in text:
        if in_string:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == '"':
                in_string = False
        elif ch == '"':
            in_string = True
        elif ch in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                raise ProtocolError(MAX_DEPTH_EXCEEDED, f"nesting exceeds the limit of {MAX_DEPTH}")
        elif ch in "]}":
            depth -= 1


def _object(pairs: list[tuple[str, JsonValue]]) -> dict[str, JsonValue]:
    out: dict[str, JsonValue] = {}
    for key, value in pairs:
        if not _is_scalar_text(key):
            raise ProtocolError(INVALID_JSON, "lone surrogate escape in an object key")
        if key in out:
            raise ProtocolError(DUPLICATE_KEY, f"duplicate key {key[:64]!r}")
        out[key] = value
    return out


def normalise_number(x: float) -> int | float:
    """One representation per value: integral and safe means ``int``."""
    if x.is_integer() and abs(x) <= MAX_SAFE_INTEGER:
        return int(x)
    return x


class _Hook:
    def __init__(self, profile: str) -> None:
        self.profile = profile


def _integer_hook(profile: str) -> _IntegerHook:
    return _IntegerHook(profile)


def _float_hook(profile: str) -> _FloatHook:
    return _FloatHook(profile)


class _IntegerHook(_Hook):
    def __call__(self, lexeme: str) -> int | float:
        if len(lexeme.lstrip("-")) > _MAX_NUMBER_DIGITS:
            raise ProtocolError(NUMBER_OUT_OF_DOMAIN, "number is not a finite double")
        value = int(lexeme)
        if abs(value) <= MAX_SAFE_INTEGER:
            return value
        if self.profile == SAFE_INTEGER:
            raise ProtocolError(NUMBER_OUT_OF_DOMAIN, "integer magnitude exceeds 2**53 - 1")
        try:
            return normalise_number(float(value))
        except OverflowError as exc:
            raise ProtocolError(NUMBER_OUT_OF_DOMAIN, "number is not a finite double") from exc


class _FloatHook(_Hook):
    def __call__(self, lexeme: str) -> int | float:
        if self.profile == SAFE_INTEGER:
            raise ProtocolError(NUMBER_OUT_OF_DOMAIN, "fraction or exponent not permitted")
        value = float(lexeme)
        if not math.isfinite(value):
            raise ProtocolError(NUMBER_OUT_OF_DOMAIN, "number is not a finite double")
        return normalise_number(value)


def _constant(name: str) -> JsonValue:
    raise ProtocolError(INVALID_JSON, f"{name} is not JSON")


def _is_scalar_text(s: str) -> bool:
    try:
        s.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _reject_lone_surrogates(value: JsonValue) -> None:
    stack: list[JsonValue] = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            if not _is_scalar_text(item):
                raise ProtocolError(INVALID_JSON, "lone surrogate escape in a string")
        elif isinstance(item, list):
            stack.extend(item)
        elif isinstance(item, dict):
            stack.extend(item.values())
