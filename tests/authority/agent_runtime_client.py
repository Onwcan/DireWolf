"""The untrusted DWKP runtime client, as its OWN operating-system user (M5d.5).

The three-identity half of the M5d.5 agent evidence (ADR-0052 §13): the
harness (`crates/dwkd-authority/tests/sandbox_agent.rs`) starts the released
`dwkd-authority serve` as its own user (identity A) and the released broker as
`DW_BROKER_AS` (identity B), then runs this script through `sudo -n -u
$DW_PEER_AS` (identity C, the runtime). The harness switches users, never the
authority (TX010).

Modes:

    relay <socket>        connect to the authority's socket and copy bytes both
                          ways between it and this process's standard streams,
                          until either side ends: the harness speaks DWKP
                          through it, so the kernel reports THIS process's uid
                          to the authority as the peer -- C's, not A's
    whoami                this process's uid, gid and supplementary groups
    read <path>           open a path for reading, and read one byte
    write <path>          open an existing path for appending
    create <dir>          create a new file in a directory, and remove it again
    list <dir>            list a directory
    connect <socket>      connect to a Unix socket, send nothing, and wait for
                          anything at all
    inspect <pid>         read another process's environment, open its memory,
                          list its descriptors and signal it with 0

Every mode but `relay` prints exactly one JSON object on standard output.
`relay` prints its identity as one `RELAY {...}` line on standard error first,
then nothing of its own. It asserts nothing; the harness does.

Standard library only: it runs wherever the runtime's user can run `python3`,
with no environment of its own.
"""

from __future__ import annotations

import contextlib
import errno
import json
import os
import select
import socket
import sys
from collections.abc import Callable
from pathlib import Path

WAIT_S = 3.0


def _errno_name(exc: OSError) -> str:
    return errno.errorcode.get(exc.errno or 0, str(exc.errno))


def _identity() -> dict[str, object]:
    return {
        "uid": os.getuid(),
        "euid": os.geteuid(),
        "gid": os.getgid(),
        "egid": os.getegid(),
        "groups": sorted(os.getgroups()),
        "pid": os.getpid(),
    }


def _attempt(action: Callable[[], object]) -> dict[str, object]:
    try:
        action()
    except OSError as exc:
        return {"refused": True, "errno": _errno_name(exc)}
    return {"refused": False}


def relay(path: str) -> int:
    """Copy bytes between the authority's socket and the standard streams."""
    report = _identity()
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.connect(path)
    except OSError as exc:
        report.update(connected=False, errno=_errno_name(exc))
        print("RELAY " + json.dumps(report, sort_keys=True), file=sys.stderr, flush=True)
        return 1
    report.update(connected=True)
    print("RELAY " + json.dumps(report, sort_keys=True), file=sys.stderr, flush=True)
    stdin = sys.stdin.buffer.fileno()
    stdout = sys.stdout.buffer.fileno()
    inputs = [stdin, sock.fileno()]
    while inputs:
        ready, _, _ = select.select(inputs, [], [])
        for fd in ready:
            if fd == stdin:
                chunk = os.read(stdin, 65536)
                if chunk:
                    sock.sendall(chunk)
                else:
                    with contextlib.suppress(OSError):
                        sock.shutdown(socket.SHUT_WR)
                    inputs.remove(stdin)
            else:
                try:
                    chunk = sock.recv(65536)
                except OSError:
                    chunk = b""
                if not chunk:
                    return 0
                view = memoryview(chunk)
                while view:
                    written = os.write(stdout, view)
                    view = view[written:]
    return 0


def read(path: str) -> dict[str, object]:
    def attempt() -> None:
        with Path(path).open("rb") as handle:
            handle.read(1)

    return {"path": path, **_attempt(attempt)}


def write(path: str) -> dict[str, object]:
    def attempt() -> None:
        fd = os.open(path, os.O_WRONLY | os.O_APPEND)
        os.close(fd)

    return {"path": path, **_attempt(attempt)}


def create(directory: str) -> dict[str, object]:
    target = Path(directory) / f"planted-by-{os.getuid()}"

    def attempt() -> None:
        fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        os.close(fd)
        target.unlink()

    return {"path": directory, **_attempt(attempt)}


def listing(directory: str) -> dict[str, object]:
    return {"path": directory, **_attempt(lambda: list(Path(directory).iterdir()))}


def connect(path: str) -> dict[str, object]:
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        sock.connect(path)
    except OSError as exc:
        sock.close()
        return {"path": path, "connected": False, "errno": _errno_name(exc), "received": 0}
    received = 0
    eof = False
    sock.settimeout(WAIT_S)
    try:
        while True:
            ready, _, _ = select.select([sock], [], [], WAIT_S)
            if not ready:
                break
            chunk = sock.recv(65536)
            if not chunk:
                eof = True
                break
            received += len(chunk)
    except OSError:
        eof = True
    finally:
        sock.close()
    return {"path": path, "connected": True, "received": received, "eof": eof}


def inspect(pid: str) -> dict[str, object]:
    proc = Path("/proc") / pid

    def environ() -> None:
        with (proc / "environ").open("rb") as handle:
            handle.read(1)

    def memory() -> None:
        with (proc / "mem").open("rb") as handle:
            handle.read(1)

    return {
        "pid": int(pid),
        "environ": _attempt(environ),
        "mem": _attempt(memory),
        "fds": _attempt(lambda: list((proc / "fd").iterdir())),
        # Signal 0: delivery is checked, nothing is sent.
        "signal": _attempt(lambda: os.kill(int(pid), 0)),
    }


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(__doc__, file=sys.stderr)
        return 2
    mode, args = argv[1], argv[2:]
    if mode == "relay" and len(args) == 1:
        return relay(args[0])
    one: dict[str, Callable[[str], dict[str, object]]] = {
        "read": read,
        "write": write,
        "create": create,
        "list": listing,
        "connect": connect,
        "inspect": inspect,
    }
    if mode == "whoami" and not args:
        report = _identity()
    elif mode in one and len(args) == 1:
        report = {**_identity(), **one[mode](args[0])}
    else:
        print(__doc__, file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True), flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
