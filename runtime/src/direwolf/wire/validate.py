"""Field validators used by the generated bindings.

Each function mirrors a ``dwk-proto`` wire type and reports the same violation
at the same JSON Pointer. The generated code calls these; nothing else should
need to.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from typing import Final

from direwolf.wire.errors import (
    INCONSISTENT,
    INVALID_FORMAT,
    MISSING_FIELD,
    NULL_NOT_ALLOWED,
    OUT_OF_RANGE,
    TOO_LONG,
    TOO_MANY_ITEMS,
    UNKNOWN_FIELD,
    UNKNOWN_VARIANT,
    WRONG_TYPE,
    ProtocolError,
    schema_violation,
)
from direwolf.wire.strict_json import JsonValue

_CROCKFORD: Final = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


class Cx:
    """The current JSON Pointer while decoding."""

    __slots__ = ("_path",)

    def __init__(self) -> None:
        self._path: list[str] = []

    def push(self, segment: str) -> None:
        self._path.append(segment.replace("~", "~0").replace("/", "~1"))

    def pop(self) -> None:
        self._path.pop()

    def pointer(self) -> str:
        return "".join("/" + s for s in self._path)

    def child(self, segment: str) -> str:
        return self.pointer() + "/" + segment.replace("~", "~0").replace("/", "~1")

    def violation(self, violation: str, detail: str) -> ProtocolError:
        return schema_violation(violation, self.pointer(), detail)


def type_name(value: JsonValue) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "boolean"
    if isinstance(value, int):
        return "integer"
    if isinstance(value, float):
        return "number"
    if isinstance(value, str):
        return "string"
    if isinstance(value, list):
        return "array"
    return "object"


def expect_object(value: JsonValue, cx: Cx) -> dict[str, JsonValue]:
    if not isinstance(value, dict):
        raise cx.violation(WRONG_TYPE, f"expected object, found {type_name(value)}")
    return value


def partition(
    obj: dict[str, JsonValue], declared: tuple[str, ...], preserve: bool, cx: Cx
) -> tuple[dict[str, JsonValue], dict[str, JsonValue]]:
    """Split members into declared and undeclared, applying the policy.

    Undeclared members are examined before any declared field is interpreted,
    exactly as ``dwk-proto`` does. Names are compared as text: every declared
    name is ASCII (a test asserts it), so a key that is not equal to one cannot
    be made equal to one by Unicode normalisation, and no normalisation is
    performed anywhere (ADR-0034).
    """
    known: dict[str, JsonValue] = {}
    extensions: dict[str, JsonValue] = {}
    for key, value in obj.items():
        if key in declared:
            known[key] = value
            continue
        if not preserve:
            raise schema_violation(UNKNOWN_FIELD, cx.child(key), f"unknown field {key[:64]!r}")
        extensions[key] = value
    return known, extensions


type Check[T] = Callable[[JsonValue, Cx], T]


def take_required[T](known: dict[str, JsonValue], name: str, cx: Cx, check: Check[T]) -> T:
    if name not in known:
        raise schema_violation(MISSING_FIELD, cx.child(name), f"missing field {name!r}")
    return _present(known.pop(name), name, cx, check)


def take_optional[T](known: dict[str, JsonValue], name: str, cx: Cx, check: Check[T]) -> T | None:
    if name not in known:
        return None
    return _present(known.pop(name), name, cx, check)


def _present[T](value: JsonValue, name: str, cx: Cx, check: Check[T]) -> T:
    cx.push(name)
    try:
        if value is None:
            raise cx.violation(NULL_NOT_ALLOWED, "null is not a value; omit an optional field")
        return check(value, cx)
    finally:
        cx.pop()


# ---- scalar checks ---------------------------------------------------------


def integer(minimum: int, maximum: int) -> Check[int]:
    def check(value: JsonValue, cx: Cx) -> int:
        if isinstance(value, bool) or not isinstance(value, int):
            raise cx.violation(WRONG_TYPE, f"expected integer, found {type_name(value)}")
        if not minimum <= value <= maximum:
            raise cx.violation(OUT_OF_RANGE, f"must be within {minimum}..={maximum}")
        return value

    return check


def boolean(value: JsonValue, cx: Cx) -> bool:
    if not isinstance(value, bool):
        raise cx.violation(WRONG_TYPE, f"expected boolean, found {type_name(value)}")
    return value


def text(max_chars: int, pattern: str | None, fmt: str | None) -> Check[str]:
    compiled = re.compile(pattern) if pattern is not None else None

    def check(value: JsonValue, cx: Cx) -> str:
        if not isinstance(value, str):
            raise cx.violation(WRONG_TYPE, f"expected string, found {type_name(value)}")
        if len(value) > max_chars:
            raise cx.violation(TOO_LONG, f"exceeds {max_chars} characters")
        if compiled is not None and compiled.fullmatch(value) is None:
            raise cx.violation(INVALID_FORMAT, "is not correctly formatted")
        if fmt == "rfc3339-utc-millis" and not valid_timestamp(value):
            raise cx.violation(INVALID_FORMAT, "is not a valid UTC timestamp")
        return value

    return check


def identifier(prefix: str | None) -> Check[str]:
    """A prefixed UUIDv7. ``None`` accepts any two-to-eight letter prefix."""

    def check(value: JsonValue, cx: Cx) -> str:
        if not isinstance(value, str):
            raise cx.violation(WRONG_TYPE, f"expected string, found {type_name(value)}")
        if not valid_identifier(value, prefix):
            raise cx.violation(INVALID_FORMAT, "expected a prefixed UUIDv7 identifier")
        return value

    return check


def sequence[T](max_items: int, item: Check[T]) -> Check[list[T]]:
    """A bounded array, checked the way `BoundedList` checks it in Rust.

    The length is compared **before** any item is decoded, so a message
    declaring a hundred thousand items costs one comparison rather than a
    hundred thousand decodes on its way to being rejected.

    An item is never `null`: a shorter array is how an item is omitted, exactly
    as an absent key is how an optional field is omitted. One value, one
    encoding.
    """

    def check(value: JsonValue, cx: Cx) -> list[T]:
        if not isinstance(value, list):
            raise cx.violation(WRONG_TYPE, f"expected array, found {type_name(value)}")
        if len(value) > max_items:
            raise cx.violation(
                TOO_MANY_ITEMS, f"expected at most {max_items} items, found {len(value)}"
            )
        out: list[T] = []
        for index, element in enumerate(value):
            cx.push(str(index))
            try:
                if element is None:
                    raise cx.violation(
                        NULL_NOT_ALLOWED,
                        "null is not a value; a shorter array is how an item is omitted",
                    )
                out.append(item(element, cx))
            finally:
                cx.pop()
        return out

    return check


def enumeration(variants: tuple[str, ...]) -> Check[str]:
    def check(value: JsonValue, cx: Cx) -> str:
        if not isinstance(value, str):
            raise cx.violation(WRONG_TYPE, f"expected string, found {type_name(value)}")
        if value not in variants:
            raise cx.violation(UNKNOWN_VARIANT, "not a permitted variant")
        return value

    return check


def ordered(low_name: str, low: int, high_name: str, high: int, cx: Cx) -> None:
    """The ``ordered(low <= high)`` cross-field check."""
    if low > high:
        raise schema_violation(
            INCONSISTENT, cx.child(high_name), f"{low_name} must not exceed {high_name}"
        )


def exactly_one(members: tuple[tuple[str, bool], ...], cx: Cx) -> None:
    """The ``exactly_one(a, b, ...)`` cross-field check: a closed sum.

    Every listed member is optional and exactly one is present. None is a
    missing field at the struct; two or more are inconsistent at the second
    present member, in declaration order -- where ``dwk-proto`` reports them.
    """
    present = [name for name, here in members if here]
    if not present:
        raise cx.violation(MISSING_FIELD, "exactly one alternative is required, and none was given")
    if len(present) > 1:
        raise schema_violation(
            INCONSISTENT,
            cx.child(present[1]),
            f"exactly one alternative is permitted; {len(present)} were given",
        )


def paired(
    left_name: str,
    left: str,
    right_name: str,
    right: str,
    allowed: Mapping[str, tuple[str, ...]],
    cx: Cx,
) -> None:
    """The ``paired(left -> right)`` cross-field check.

    Two closed enums whose combination is also closed. A pair the table does not
    list is refused here rather than carried inwards, which is what makes "this
    reason cannot arise from that operation" a property of the wire instead of a
    convention two implementations are each trusted to keep.
    """
    if right not in allowed.get(left, ()):
        raise schema_violation(
            INCONSISTENT,
            cx.child(right_name),
            f"{left_name} {left} cannot produce {right_name} {right}",
        )


# ---- identifiers and timestamps --------------------------------------------


def decode_uuid7(body: str) -> int | None:
    if len(body) != 26:
        return None
    value = 0
    for i, ch in enumerate(body):
        digit = _CROCKFORD.find(ch)
        if digit < 0 or (i == 0 and digit > 7):
            return None
        value = value * 32 + digit
    if (value >> 76) & 0xF != 7 or (value >> 62) & 0b11 != 0b10:
        return None
    return value


def valid_identifier(value: str, prefix: str | None) -> bool:
    head, sep, body = value.partition("_")
    if not sep:
        return False
    if prefix is None:
        if not (2 <= len(head) <= 8 and head.isascii() and head.isalpha() and head.islower()):
            return False
    elif head != prefix:
        return False
    return decode_uuid7(body) is not None


def valid_timestamp(value: str) -> bool:
    if len(value) != 24:
        return False
    for i, ch in enumerate(value):
        expected = {4: "-", 7: "-", 10: "T", 13: ":", 16: ":", 19: ".", 23: "Z"}.get(i)
        if expected is not None:
            if ch != expected:
                return False
        elif ch not in "0123456789":
            return False
    year, month, day = int(value[0:4]), int(value[5:7]), int(value[8:10])
    hour, minute, second = int(value[11:13]), int(value[14:16]), int(value[17:19])
    leap = year % 4 == 0 and (year % 100 != 0 or year % 400 == 0)
    if month in (1, 3, 5, 7, 8, 10, 12):
        days = 31
    elif month in (4, 6, 9, 11):
        days = 30
    elif month == 2:
        days = 29 if leap else 28
    else:
        return False
    return 1 <= day <= days and hour < 24 and minute < 60 and second < 60
