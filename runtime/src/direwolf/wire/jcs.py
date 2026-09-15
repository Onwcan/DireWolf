"""RFC 8785 JSON Canonicalization Scheme, mirroring ``dwk-proto``'s ``jcs``.

* Object members sorted by the UTF-16 code units of their keys.
* Strings: only ``"``, ``\\`` and U+0000..U+001F escaped, with the short forms
  for backspace, tab, newline, form feed and carriage return and lowercase
  four-digit hex otherwise. No Unicode normalisation.
* Numbers: ECMAScript ``Number::toString``, including the round-half-to-even
  tie-break RFC 8785 mandates (Appendix B's "round to even" sample).
* No whitespace; UTF-8 output.

Checked against RFC 8785's own samples and the V8 corpus in
``tests/protocol/vectors/numbers.json``, the same data the Rust crate is checked
against.
"""

from __future__ import annotations

import math
from decimal import Decimal
from typing import Final

from direwolf.wire.errors import MAX_SAFE_INTEGER
from direwolf.wire.strict_json import JsonValue

_BACKSLASH: Final = chr(92)


def _escape_table() -> dict[int, str]:
    table: dict[int, str] = {}
    for code in range(0x20):
        table[code] = f"{_BACKSLASH}u{code:04x}"
    table[0x08] = _BACKSLASH + "b"
    table[0x09] = _BACKSLASH + "t"
    table[0x0A] = _BACKSLASH + "n"
    table[0x0C] = _BACKSLASH + "f"
    table[0x0D] = _BACKSLASH + "r"
    table[ord('"')] = _BACKSLASH + '"'
    table[ord(_BACKSLASH)] = _BACKSLASH + _BACKSLASH
    return table


_ESCAPES: Final = _escape_table()


def canonicalize(value: JsonValue) -> bytes:
    """The canonical UTF-8 bytes of ``value``."""
    parts: list[str] = []
    _write(parts, value)
    return "".join(parts).encode("utf-8")


def _write(parts: list[str], value: JsonValue) -> None:
    if value is None:
        parts.append("null")
    elif value is True:
        parts.append("true")
    elif value is False:
        parts.append("false")
    elif isinstance(value, int):
        if abs(value) <= MAX_SAFE_INTEGER:
            parts.append(str(value))
        else:
            parts.append(format_es(float(value)))
    elif isinstance(value, float):
        parts.append(format_es(value))
    elif isinstance(value, str):
        parts.append(_string(value))
    elif isinstance(value, list):
        parts.append("[")
        for i, item in enumerate(value):
            if i:
                parts.append(",")
            _write(parts, item)
        parts.append("]")
    elif isinstance(value, dict):
        parts.append("{")
        for i, key in enumerate(sorted(value, key=_utf16_key)):
            if i:
                parts.append(",")
            parts.append(_string(key))
            parts.append(":")
            _write(parts, value[key])
        parts.append("}")
    else:
        raise TypeError(f"not a JSON value: {type(value).__name__}")


def _utf16_key(key: str) -> bytes:
    # Big-endian UTF-16 bytes compare exactly as UTF-16 code units do.
    return key.encode("utf-16-be", "surrogatepass")


def _string(s: str) -> str:
    try:
        s.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("RFC 8785 forbids lone surrogates") from exc
    return '"' + s.translate(_ESCAPES) + '"'


def format_es(x: float) -> str:
    """ECMAScript ``String(x)`` for a finite double."""
    if not math.isfinite(x):
        raise ValueError("NaN and Infinity are not JSON")
    if x == 0:
        return "0"
    magnitude = abs(x)
    digits, n = _digits(repr(magnitude))
    # Round-half-to-even at the shortest precision; used when it round-trips.
    tie_even = format(magnitude, f".{len(digits) - 1}e")
    if float(tie_even) == magnitude:
        digits, n = _digits(tie_even)
    k = len(digits)
    sign = "-" if x < 0 else ""
    if k <= n <= 21:
        return sign + digits + "0" * (n - k)
    if 0 < n <= 21:
        return sign + digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return sign + "0." + "0" * (-n) + digits
    exponent = n - 1
    mantissa = digits[0] + ("." + digits[1:] if k > 1 else "")
    return f"{sign}{mantissa}e{'-' if exponent < 0 else '+'}{abs(exponent)}"


def _digits(text: str) -> tuple[str, int]:
    """Significant digits (no trailing zeros) and decimal-point position ``n``,
    such that the value is ``0.d1d2...dk * 10**n``."""
    _, digit_tuple, exponent = Decimal(text).as_tuple()
    digits = "".join(str(d) for d in digit_tuple).lstrip("0") or "0"
    if not isinstance(exponent, int):
        raise ValueError("not a finite decimal")
    stripped = digits.rstrip("0") or "0"
    exponent += len(digits) - len(stripped)
    return stripped, len(stripped) + exponent
