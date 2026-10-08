#!/usr/bin/env python3
"""A deterministic local HTTPS origin for the net.http evidence (ADR-0050 §16).

Standard library only. One TLS listener on 127.0.0.1, presenting the
certificate it is given; one request per connection (the broker always sends
``Connection: close``); the response chosen by the request's path. It never
contacts anything, never follows anything, and never prints a credential:
what it records of an ``Authorization`` header is its SHA-256.

    origin.py --cert origin.pem --key origin.key

prints ``ORIGIN-READY {"port": N}`` once listening, then one
``ORIGIN-REQUEST {...}`` line per request: the method, the target, the header
names in order, the SHA-256 of the ``Authorization`` value (or null), and the
body's length. Paths:

    /ok                    200, ``ok``
    /echo-auth             200, the Authorization value as the body and an ETag
    /echo-auth?where=W     the Authorization value echoed one way (D11's evidence):
                           ``body``, ``kept`` (an ETag), ``dropped`` (an X-Echo
                           header off the keep-list), ``location`` (a 302 to
                           ``/ok?t=<token>``), ``chunked`` (the body split across
                           three chunks), ``malformed`` (both framings),
                           ``truncated`` (a body cut short), ``straddle&at=N``
                           and ``beyond&at=N`` (N filler bytes first)
    /redirect?status=S&to=U  S, ``Location: U`` (U percent-decoded)
    /loop                  302 to itself
    /chain?n=K             302 to /chain?n=K+1, without end
    /big?n=N               200, N bytes
    /cookie                200 with two Set-Cookie headers
    /gzip                  200, Content-Encoding: gzip
    /bad-status            a status line with a four-digit code
    /both-framings         Content-Length and chunked together
    /bad-chunk             a chunk size that is not hexadecimal
    /header-bomb           200 with 150 headers
    /close-delimited       200 with neither length nor chunking
    /switch                101 Switching Protocols
    /never                 reads the request and answers nothing

Everything else is 404. The evidence that drives it is
``crates/dwkd-authority/tests/net_http_evidence.rs``.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import socket
import ssl
import sys
import threading
import time
import urllib.parse

MAX_HEAD = 64 * 1024


def read_request(conn: ssl.SSLSocket) -> tuple[str, str, list[tuple[str, str]], bytes] | None:
    """One request: its method, target, headers and body, or None."""
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(4096)
        if not chunk:
            return None
        data += chunk
        if len(data) > MAX_HEAD:
            return None
    head, _, rest = data.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    method, target, _version = lines[0].split(" ", 2)
    headers = []
    for line in lines[1:]:
        name, _, value = line.partition(":")
        headers.append((name.strip().lower(), value.strip()))
    length = next((int(v) for n, v in headers if n == "content-length"), 0)
    body = rest
    while len(body) < length:
        chunk = conn.recv(4096)
        if not chunk:
            break
        body += chunk
    return method, target, headers, body[:length]


def respond(status: str, headers: list[tuple[str, str]], body: bytes) -> bytes:
    head = f"HTTP/1.1 {status}\r\n"
    for name, value in headers:
        head += f"{name}: {value}\r\n"
    return head.encode("latin-1") + b"\r\n" + body


def plain(status: str, body: bytes, extra: list[tuple[str, str]] | None = None) -> bytes:
    headers = [("Content-Type", "text/plain"), ("Content-Length", str(len(body)))]
    return respond(status, headers + (extra or []), body)


def chunked(parts: list[bytes]) -> bytes:
    """`parts` as chunks, then the last chunk."""
    return b"".join(f"{len(p):x}\r\n".encode() + p + b"\r\n" for p in parts if p) + b"0\r\n\r\n"


def echo(authorization: str, args: dict[str, str]) -> bytes:
    """The credential, sent back the way `where` names."""
    value = authorization.encode("latin-1")
    token = authorization.split(" ", 1)[-1]
    where = args.get("where")
    at = int(args.get("at", "0"))
    if where is None:
        return plain("200 OK", value, [("ETag", authorization)])
    if where == "body":
        return plain("200 OK", value)
    if where == "kept":
        return plain("200 OK", b"ok", [("ETag", authorization)])
    if where == "dropped":
        return plain("200 OK", b"ok", [("X-Echo", authorization)])
    if where == "location":
        return respond("302 Found", [("Location", f"/ok?t={token}"), ("Content-Length", "0")], b"")
    if where == "chunked":
        third = max(len(value) // 3, 1)
        return respond(
            "200 OK",
            [("Transfer-Encoding", "chunked")],
            chunked([value[:third], value[third : 2 * third], value[2 * third :]]),
        )
    if where == "malformed":
        framings = [("Content-Length", str(len(value))), ("Transfer-Encoding", "chunked")]
        return respond("200 OK", [("ETag", authorization), *framings], chunked([value]))
    if where == "truncated":
        promised = ("Content-Length", str(len(value) + 100))
        return respond("200 OK", [("ETag", authorization), promised], value)
    if where in ("straddle", "beyond"):
        return plain("200 OK", b"a" * at + value + b"b" * 100)
    return plain("404 Not Found", b"")


def answer(target: str, headers: list[tuple[str, str]]) -> bytes | None:
    """The bytes for `target`; None to answer nothing."""
    path, _, query = target.partition("?")
    args = dict(urllib.parse.parse_qsl(query))
    authorization = next((v for n, v in headers if n == "authorization"), None)
    if path == "/ok":
        return plain("200 OK", b"ok")
    if path == "/echo-auth":
        return echo(authorization or "none", args)
    if path == "/redirect":
        status = int(args.get("status", "302"))
        location = args.get("to", "/ok")
        return respond(f"{status} Redirect", [("Location", location), ("Content-Length", "0")], b"")
    if path == "/loop":
        return respond("302 Found", [("Location", "/loop"), ("Content-Length", "0")], b"")
    if path == "/chain":
        step = int(args.get("n", "0")) + 1
        return respond(
            "302 Found", [("Location", f"/chain?n={step}"), ("Content-Length", "0")], b""
        )
    if path == "/big":
        return plain("200 OK", b"a" * int(args.get("n", "1024")))
    if path == "/cookie":
        return plain("200 OK", b"ok", [("Set-Cookie", "a=1"), ("Set-Cookie", "b=2")])
    if path == "/gzip":
        return plain("200 OK", b"\x1f\x8b", [("Content-Encoding", "gzip")])
    if path == "/bad-status":
        return b"HTTP/1.1 2000 Nonsense\r\nContent-Length: 0\r\n\r\n"
    if path == "/both-framings":
        return respond(
            "200 OK",
            [("Content-Length", "2"), ("Transfer-Encoding", "chunked")],
            b"2\r\nok\r\n0\r\n\r\n",
        )
    if path == "/bad-chunk":
        return respond("200 OK", [("Transfer-Encoding", "chunked")], b"zz\r\nok\r\n0\r\n\r\n")
    if path == "/header-bomb":
        return respond(
            "200 OK",
            [(f"X-Bomb-{n}", "x") for n in range(150)] + [("Content-Length", "0")],
            b"",
        )
    if path == "/close-delimited":
        return respond("200 OK", [("Content-Type", "text/plain")], b"until the end")
    if path == "/switch":
        return respond("101 Switching Protocols", [("Upgrade", "h2c")], b"")
    if path == "/never":
        return None
    return plain("404 Not Found", b"")


def serve_one(conn: ssl.SSLSocket, lock: threading.Lock) -> None:
    try:
        # The handshake here, not in the accept loop: a client that refuses
        # the certificate, or never finishes, holds only its own thread.
        conn.do_handshake()
        request = read_request(conn)
        if request is None:
            return
        method, target, headers, body = request
        authorization = next((v for n, v in headers if n == "authorization"), None)
        record = {
            "method": method,
            "target": target,
            "headers": [n for n, _ in headers],
            "authorization_sha256": (
                hashlib.sha256(authorization.encode("latin-1")).hexdigest()
                if authorization is not None
                else None
            ),
            "body_bytes": len(body),
        }
        with lock:
            print("ORIGIN-REQUEST " + json.dumps(record, sort_keys=True), flush=True)
        reply = answer(target, headers)
        if reply is None:
            time.sleep(60)
            return
        conn.sendall(reply)
    except (OSError, ValueError):
        return
    finally:
        with contextlib.suppress(OSError):
            conn.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--cert", required=True)
    parser.add_argument("--key", required=True)
    args = parser.parse_args()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(args.cert, args.key)
    context.set_alpn_protocols(["http/1.1"])
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(64)
    print("ORIGIN-READY " + json.dumps({"port": listener.getsockname()[1]}), flush=True)
    lock = threading.Lock()
    while True:
        raw, _ = listener.accept()
        raw.settimeout(30)
        try:
            conn = context.wrap_socket(raw, server_side=True, do_handshake_on_connect=False)
        except (OSError, ssl.SSLError):
            raw.close()
            continue
        threading.Thread(target=serve_one, args=(conn, lock), daemon=True).start()


if __name__ == "__main__":
    sys.exit(main())
