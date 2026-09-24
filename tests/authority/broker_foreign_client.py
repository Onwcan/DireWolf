"""A process running as ANOTHER operating-system user, against the broker
channel and the authority (M4b, ADR-0043).

Run by `crates/dwkd-authority/tests/broker_foreign.rs` through
`sudo -n -u $DW_PEER_AS` (the hostile runtime) or `sudo -n -u $DW_BROKER_AS`
(the broker's own identity). Standard library only: the second user may not be
able to reach this checkout's virtualenv. Prints exactly one JSON line; the
harness asserts on it.

Modes:

  hello <socket>                      connect and wait for anything at all
  authorise <socket> <frame-hex>      send a well-formed authorisation with a
                                      descriptor of a file this user can open
  flood <socket> <count>              connect and close, repeatedly
  read-path <path>                    open a path for reading
  probe-authority <state-dir> <kernel-socket> <handshake-hex>
                                      everything the broker identity must not
                                      be able to do to the authority

This is a test harness, never product code: the authority switches no users
and starts no processes (TX010).
"""

from __future__ import annotations

import contextlib
import errno
import json
import os
import socket
import sys
from collections.abc import Callable
from pathlib import Path


def _errno_name(exc: OSError) -> str:
    return errno.errorcode.get(exc.errno or 0, str(exc.errno))


def _read_all(sock: socket.socket, wait: float) -> tuple[int, bool]:
    """Bytes received and whether the peer closed, within `wait` seconds."""
    sock.settimeout(wait)
    received = 0
    try:
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                return received, True
            received += len(chunk)
    except TimeoutError:
        return received, False
    except OSError as exc:
        if exc.errno in (errno.ECONNRESET, errno.EPIPE):
            return received, True
        raise


def _connect(path: str) -> socket.socket:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(path)
    return sock


def hello(path: str) -> dict[str, object]:
    sock = _connect(path)
    received, eof = _read_all(sock, 3.0)
    sock.close()
    return {"connected": True, "received": received, "eof": eof}


def authorise(path: str, frame_hex: str) -> dict[str, object]:
    frame = bytes.fromhex(frame_hex)
    sock = _connect(path)
    own = os.open(__file__, os.O_RDONLY)
    sent = True
    try:
        socket.send_fds(sock, [frame], [own])
    except OSError:
        sent = False
    finally:
        os.close(own)
    received, eof = _read_all(sock, 3.0)
    sock.close()
    return {"connected": True, "sent": sent, "received": received, "eof": eof}


def flood(path: str, count: int) -> dict[str, object]:
    received = 0
    for _ in range(count):
        try:
            sock = _connect(path)
        except OSError:
            continue
        got, _ = _read_all(sock, 0.2)
        received += got
        sock.close()
    return {"attempts": count, "received": received}


def read_path(path: str) -> dict[str, object]:
    try:
        with Path(path).open("rb") as handle:
            data = handle.read(64)
    except OSError as exc:
        return {"refused": True, "errno": _errno_name(exc)}
    return {"refused": False, "bytes": len(data)}


def probe_authority(state_dir: str, kernel_socket: str, handshake_hex: str) -> dict[str, object]:
    state = Path(state_dir)
    attempts: list[dict[str, object]] = []

    def attempt(name: str, action: Callable[[], object]) -> None:
        try:
            action()
        except OSError as exc:
            attempts.append({"attempt": name, "refused": True, "errno": _errno_name(exc)})
            return
        attempts.append({"attempt": name, "refused": False})

    def read(name: str) -> None:
        with (state / name).open("rb") as handle:
            handle.read(1)

    def append_audit() -> None:
        with (state / "audit.log").open("ab") as handle:
            handle.write(b"{}\n")

    def create_in_state() -> None:
        fd = os.open(state / "planted", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)

    attempt("list the state directory", lambda: list(state.iterdir()))
    attempt("read kernel.db", lambda: read("kernel.db"))
    attempt("read audit.log", lambda: read("audit.log"))
    attempt("append to audit.log", append_audit)
    attempt("create a file in the state directory", create_in_state)

    # DWKP: the broker identity is no allowed peer. The socket is reachable
    # (its directory is traverse-only); the peer gate answers nothing.
    sock = _connect(kernel_socket)
    with contextlib.suppress(OSError):
        sock.sendall(bytes.fromhex(handshake_hex))
    received, eof = _read_all(sock, 3.0)
    sock.close()
    return {"attempts": attempts, "dwkp_received": received, "dwkp_eof": eof}


def main(argv: list[str]) -> int:
    mode = argv[1]
    if mode == "hello":
        report = hello(argv[2])
    elif mode == "authorise":
        report = authorise(argv[2], argv[3])
    elif mode == "flood":
        report = flood(argv[2], int(argv[3]))
    elif mode == "read-path":
        report = read_path(argv[2])
    elif mode == "probe-authority":
        report = probe_authority(argv[2], argv[3], argv[4])
    else:
        print(json.dumps({"error": f"unknown mode {mode}"}))
        return 2
    report["euid"] = os.geteuid()
    report["pid"] = os.getpid()
    print(json.dumps(report))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
