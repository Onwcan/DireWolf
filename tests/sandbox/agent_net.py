"""The network half of the M5d.5 agent-shaped workload (ADR-0052 §§11, 17).

It runs INSIDE a measured `PROXY_ONLY` environment, as the workload's uid
10001, started by the `workload-agent-net` fixture or as a workload of its own
through the image's Python. The evidence harness
(`crates/dwkd-authority/tests/sandbox_agent.rs`) copies it, with the run's test
trust anchor, into the workspace: an agent's own code and its own trust, never
the broker's. The broker terminates no TLS and trusts nothing new; this client
verifies the origin's certificate itself, against the anchor it is given.

    agent_net.py fetch <url> <cafile>
        a stock client: `urllib`, which honours the environment's proxy
        variables, verifying the origin against `cafile`
    agent_net.py fetch-via <proxy-url|none> <url> <cafile>
        the same, after the workload rewrote its own proxy variables: every
        one pointed at `proxy-url`, or every one removed (`none`)
    agent_net.py tls <host> <port> <sni> <cafile> <path>
        CONNECT host:port to wherever HTTPS_PROXY points, then TLS naming
        `sni` (`-`: none), verified against `cafile`, then GET `path`
    agent_net.py raw <hex>
        send exactly these bytes to the proxy; report its answer
    agent_net.py tunnels <host> <port> <n>
        open `n` tunnels at once and hold them; report how many the proxy
        established and how many it refused
    agent_net.py download <host> <port> <n> <cafile>
        GET /big?n=<n> through a tunnel; report how many bytes arrived and
        how the connection ended

Each mode prints exactly one JSON object on standard output: what it tried,
what came back, and -- for a refusal -- where it was refused: `proxy` (the
broker's CONNECT proxy answered so, with its `X-DireWolf-Egress` decision),
`tunnel-closed` (the proxy accepted the CONNECT, then closed the tunnel
before anything reached an origin -- its server-name check), `tls-client`
(this process's own certificate verification, which is the workload's, not
DireWolf's) or `network` (the kernel: an errno, with no proxy in the path).
It asserts nothing; the harness does. It prints no certificate, key or
response body: lengths, and a SHA-256 of what it received.

Standard library only: it runs on the image's Python, with nothing installed.
"""

from __future__ import annotations

import contextlib
import errno
import hashlib
import json
import os
import socket
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable

WAIT_S = 10.0
MAX_HEAD = 8192
# Every name a tool reads a proxy from (`dwk_sandbox_profile::PROXY_VARIABLE_NAMES`).
PROXY_NAMES = (
    "HTTP_PROXY",
    "HTTPS_PROXY",
    "ALL_PROXY",
    "NO_PROXY",
    "FTP_PROXY",
    "RSYNC_PROXY",
    "http_proxy",
    "https_proxy",
    "all_proxy",
    "no_proxy",
    "ftp_proxy",
    "rsync_proxy",
)


def _say(report: dict[str, object]) -> int:
    print(json.dumps(report, sort_keys=True), flush=True)
    return 0


def _errno_name(exc: OSError) -> str:
    return errno.errorcode.get(exc.errno or 0, f"errno-{exc.errno}")


def _proxy() -> tuple[str, int] | None:
    """Where HTTPS_PROXY points, as the environment gave it; None if unset."""
    value = os.environ.get("HTTPS_PROXY") or os.environ.get("https_proxy")
    if not value:
        return None
    parsed = urllib.parse.urlsplit(value)
    if parsed.scheme != "http" or parsed.hostname is None or parsed.port is None:
        return None
    return parsed.hostname, parsed.port


def _head(sock: socket.socket) -> bytes:
    """Read up to the blank line ending a response head, bounded."""
    data = b""
    while b"\r\n\r\n" not in data and len(data) < MAX_HEAD:
        chunk = sock.recv(1)
        if not chunk:
            break
        data += chunk
    return data


def _connect(host: str, port: int, request: bytes | None = None) -> tuple[socket.socket, str, str]:
    """A CONNECT through the proxy: the socket, the status line and the
    proxy's decision header ('-' when it sent none)."""
    proxy = _proxy()
    if proxy is None:
        raise LookupError("no-proxy-variable")
    sock = socket.create_connection(proxy, timeout=WAIT_S)
    if request is None:
        request = f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n".encode()
    sock.sendall(request)
    head = _head(sock).decode("latin-1")
    lines = head.split("\r\n")
    status = lines[0] if lines else ""
    decision = "-"
    for line in lines[1:]:
        name, _, value = line.partition(":")
        if name.strip().lower() == "x-direwolf-egress":
            decision = value.strip()
    return sock, status, decision


def _tls_context(cafile: str) -> ssl.SSLContext:
    """Verification on, the default way, against this run's anchor only."""
    context = ssl.create_default_context(cafile=cafile)
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    return context


def _response(stream: ssl.SSLSocket) -> tuple[int, int, str, str]:
    """Read a whole response: status, body length, body SHA-256, ending."""
    data = b""
    ending = "eof"
    started = time.monotonic()
    while True:
        try:
            chunk = stream.recv(65536)
        except ssl.SSLError as exc:
            ending = f"tls-{exc.reason or 'error'}"
            break
        except OSError as exc:
            ending = _errno_name(exc)
            break
        if not chunk:
            break
        data += chunk
        if time.monotonic() - started > 3 * WAIT_S:
            ending = "still-open"
            break
    head, _, body = data.partition(b"\r\n\r\n")
    words = head.split(b" ", 2)
    status = int(words[1]) if len(words) > 1 and words[1].isdigit() else 0
    return status, len(body), hashlib.sha256(body).hexdigest(), ending


def _refused_by_tls(exc: ssl.SSLError) -> dict[str, object]:
    if isinstance(exc, ssl.SSLCertVerificationError):
        return {
            "refused_by": "tls-client",
            "error": "certificate-verify-failed",
            "verify": exc.verify_message,
        }
    # The peer closed the handshake: the proxy closes a tunnel whose server
    # name is not its CONNECT host, before it dials anything.
    return {"refused_by": "tunnel-closed", "error": f"tls-{exc.reason or 'error'}"}


def fetch(url: str, cafile: str) -> int:
    """A stock client honouring the proxy variables, verifying the origin."""
    report: dict[str, object] = {
        "mode": "fetch",
        "url": url,
        "proxy": os.environ.get("HTTPS_PROXY"),
    }
    opener = urllib.request.build_opener(
        urllib.request.ProxyHandler(),
        urllib.request.HTTPSHandler(context=_tls_context(cafile)),
    )
    try:
        # The URL is the harness's own `https://` origin; nothing else is
        # opened (S310 guards file: and custom schemes).
        with opener.open(url, timeout=WAIT_S) as answer:
            body = answer.read()
            report.update(
                status=answer.status,
                bytes=len(body),
                sha256=hashlib.sha256(body).hexdigest(),
                verified=True,
            )
    except urllib.error.HTTPError as exc:
        report.update(status=exc.code, verified=True)
    except urllib.error.URLError as exc:
        reason = exc.reason
        if isinstance(reason, ssl.SSLError):
            report.update(_refused_by_tls(reason))
        elif isinstance(reason, socket.gaierror):
            # No resolver answers in the environment: the name was never
            # turned into an address, so nothing was dialled.
            report.update(refused_by="network", error="name-not-resolved")
        elif isinstance(reason, OSError) and str(reason).startswith("Tunnel connection failed"):
            report.update(refused_by="proxy", error=str(reason))
        elif isinstance(reason, OSError) and reason.errno is not None:
            report.update(refused_by="network", error=_errno_name(reason))
        else:
            report.update(refused_by="network", error=str(reason))
    except ssl.SSLError as exc:
        report.update(_refused_by_tls(exc))
    except OSError as exc:
        report.update(refused_by="network", error=_errno_name(exc))
    return _say(report)


def fetch_via(proxy: str, url: str, cafile: str) -> int:
    """`fetch`, after the workload rewrote its own proxy variables -- what a
    hostile or confused tool can do inside the environment."""
    for name in PROXY_NAMES:
        os.environ.pop(name, None)
    if proxy != "none":
        for name in ("HTTPS_PROXY", "https_proxy", "HTTP_PROXY", "http_proxy"):
            os.environ[name] = proxy
    return fetch(url, cafile)


def tls(host: str, port: str, sni: str, cafile: str, path: str) -> int:
    """CONNECT, then TLS naming `sni`, verified, then one GET."""
    report: dict[str, object] = {"mode": "tls", "host": host, "port": int(port), "sni": sni}
    try:
        sock, status, decision = _connect(host, int(port))
    except LookupError as exc:
        return _say({**report, "refused_by": "network", "error": str(exc)})
    except OSError as exc:
        return _say({**report, "refused_by": "network", "error": _errno_name(exc)})
    report.update(connect=status, decision=decision)
    if not status.startswith("HTTP/1.1 200"):
        sock.close()
        return _say({**report, "refused_by": "proxy"})
    context = _tls_context(cafile)
    if sni == "-":
        context.check_hostname = False
    try:
        with context.wrap_socket(sock, server_hostname=None if sni == "-" else sni) as stream:
            stream.sendall(
                f"GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
            )
            code, length, digest, ending = _response(stream)
            report.update(status=code, bytes=length, sha256=digest, ending=ending, verified=True)
    except ssl.SSLError as exc:
        report.update(_refused_by_tls(exc))
    except OSError as exc:
        report.update(refused_by="tunnel-closed", error=_errno_name(exc))
    return _say(report)


def raw(hex_request: str) -> int:
    """Exactly these bytes to the proxy, and what it answered."""
    request = bytes.fromhex(hex_request)
    report: dict[str, object] = {"mode": "raw", "sent": len(request)}
    try:
        sock, status, decision = _connect("", 0, request)
    except LookupError as exc:
        return _say({**report, "refused_by": "network", "error": str(exc)})
    except OSError as exc:
        return _say({**report, "refused_by": "network", "error": _errno_name(exc)})
    sock.close()
    report.update(connect=status, decision=decision)
    if not status.startswith("HTTP/1.1 200"):
        report.update(refused_by="proxy")
    return _say(report)


def tunnels(host: str, port: str, count: str) -> int:
    """`count` tunnels at once, each held open: how many the proxy took."""
    held: list[socket.socket] = []
    decisions: dict[str, int] = {}
    established = refused = 0
    for _ in range(int(count)):
        try:
            sock, status, decision = _connect(host, int(port))
        except OSError as exc:
            name = _errno_name(exc)
            decisions[name] = decisions.get(name, 0) + 1
            refused += 1
            continue
        if status.startswith("HTTP/1.1 200"):
            established += 1
            held.append(sock)
        else:
            refused += 1
            decisions[decision] = decisions.get(decision, 0) + 1
            sock.close()
    for sock in held:
        with contextlib.suppress(OSError):
            sock.close()
    return _say(
        {
            "mode": "tunnels",
            "asked": int(count),
            "established": established,
            "refused": refused,
            "decisions": decisions,
        }
    )


def download(host: str, port: str, count: str, cafile: str) -> int:
    """GET /big?n=<count> through one tunnel: how much arrived, and how."""
    report: dict[str, object] = {"mode": "download", "asked": int(count)}
    try:
        sock, status, decision = _connect(host, int(port))
    except LookupError as exc:
        return _say({**report, "refused_by": "network", "error": str(exc)})
    except OSError as exc:
        return _say({**report, "refused_by": "network", "error": _errno_name(exc)})
    report.update(connect=status, decision=decision)
    if not status.startswith("HTTP/1.1 200"):
        sock.close()
        return _say({**report, "refused_by": "proxy"})
    try:
        with _tls_context(cafile).wrap_socket(sock, server_hostname=host) as stream:
            stream.sendall(
                f"GET /big?n={count} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode()
            )
            code, length, _digest, ending = _response(stream)
            report.update(status=code, bytes=length, ending=ending)
    except ssl.SSLError as exc:
        report.update(_refused_by_tls(exc))
    except OSError as exc:
        report.update(refused_by="tunnel-closed", error=_errno_name(exc))
    return _say(report)


MODES: dict[str, tuple[Callable[..., int], int]] = {
    "fetch": (fetch, 2),
    "fetch-via": (fetch_via, 3),
    "tls": (tls, 5),
    "raw": (raw, 1),
    "tunnels": (tunnels, 3),
    "download": (download, 4),
}


def main(argv: list[str]) -> int:
    if len(argv) < 2 or argv[1] not in MODES:
        print(__doc__, file=sys.stderr)
        return 2
    run, arity = MODES[argv[1]]
    if len(argv) != 2 + arity:
        print(f"{argv[1]} takes {arity} arguments", file=sys.stderr)
        return 2
    return run(*argv[2:])


if __name__ == "__main__":
    sys.exit(main(sys.argv))
