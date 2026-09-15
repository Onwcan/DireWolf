"""DWKP framing: 4-byte big-endian body length, 1 content-type byte, body.

Mirrors ``dwk-proto``'s ``frame`` module: the length counts the body only; a
zero length and a length above 1 MiB are rejected from the header, before any
body byte is kept; content type ``0x01`` is JSON and every other value is
reserved. A framing error poisons the decoder, because after one there is no
trustworthy next boundary.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import Final

from direwolf.wire.errors import (
    CONTENT_TYPE_UNSUPPORTED,
    FRAME_EMPTY,
    FRAME_TOO_LARGE,
    FRAME_TRUNCATED,
    MAX_FRAME_BODY,
    ProtocolError,
)

HEADER_LEN: Final = 5
CONTENT_TYPE_JSON: Final = 0x01


@dataclass(frozen=True, slots=True)
class Frame:
    """One complete frame."""

    content_type: int
    body: bytes


def encode(body: bytes, content_type: int = CONTENT_TYPE_JSON) -> bytes:
    """Frame a body."""
    if not body:
        raise ProtocolError(FRAME_EMPTY, "refusing to encode an empty body")
    if len(body) > MAX_FRAME_BODY:
        raise ProtocolError(FRAME_TOO_LARGE, f"body of {len(body)} bytes exceeds the limit")
    if content_type != CONTENT_TYPE_JSON:
        raise ProtocolError(CONTENT_TYPE_UNSUPPORTED, f"content type {content_type:#04x}")
    return struct.pack(">IB", len(body), content_type) + body


class FrameDecoder:
    """Incremental, bounded frame decoder."""

    def __init__(self) -> None:
        self._header = bytearray()
        self._pending: tuple[int, int] | None = None
        self._body = bytearray()
        self._poisoned: ProtocolError | None = None

    def feed(self, data: bytes) -> tuple[int, Frame | None]:
        """Consume up to the end of the current frame. Returns (consumed, frame)."""
        if self._poisoned is not None:
            raise self._poisoned
        consumed = 0
        if self._pending is None:
            take = min(HEADER_LEN - len(self._header), len(data))
            self._header += data[:take]
            consumed = take
            if len(self._header) < HEADER_LEN:
                return consumed, None
            try:
                self._pending = _parse_header(bytes(self._header))
            except ProtocolError as err:
                self._poisoned = err
                raise
        content_type, length = self._pending
        take = min(length - len(self._body), len(data) - consumed)
        self._body += data[consumed : consumed + take]
        consumed += take
        if len(self._body) < length:
            return consumed, None
        frame = Frame(content_type, bytes(self._body))
        self._header.clear()
        self._body.clear()
        self._pending = None
        return consumed, frame

    def finish(self) -> None:
        """Signal end of stream. A partial frame is an error."""
        if self._poisoned is not None:
            raise self._poisoned
        if self._header or self._pending is not None:
            raise ProtocolError(FRAME_TRUNCATED, "stream ended part-way through a frame")


def _parse_header(header: bytes) -> tuple[int, int]:
    length, content_type = struct.unpack(">IB", header)
    if length == 0:
        raise ProtocolError(FRAME_EMPTY, "frame declares an empty body")
    if length > MAX_FRAME_BODY:
        raise ProtocolError(FRAME_TOO_LARGE, f"frame declares {length} body bytes")
    if content_type != CONTENT_TYPE_JSON:
        raise ProtocolError(CONTENT_TYPE_UNSUPPORTED, f"content-type byte {content_type:#04x}")
    return content_type, length


def decode_all(data: bytes) -> list[Frame]:
    """Decode every frame in a complete byte string."""
    decoder = FrameDecoder()
    frames: list[Frame] = []
    rest = data
    while rest:
        used, frame = decoder.feed(rest)
        if frame is not None:
            frames.append(frame)
        rest = rest[used:]
        if used == 0:
            break
    decoder.finish()
    return frames
