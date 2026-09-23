"""A DWKP client run as ANOTHER operating-system user than the authority.

The cross-uid half of the M3e evidence (ADR-0041). The Rust harness
(`crates/dwkd-authority/tests/transport_foreign.rs`) starts the real
`dwkd-authority serve`, then runs this script through `sudo -n -u
$DW_PEER_AS` -- the harness switches users, never the authority. Whatever this
process sends, the kernel reports ITS uid to the server, and the server must
refuse it before reading a byte.

Cases:

    hello <socket> <hex-frame>          send one well-formed handshake frame
    garbage <socket>                    send a malformed frame
    flood <socket> <n> <hex-frame>      connect n times, each sending the frame
    impersonate <socket>                try to remove, replace or shadow the socket

It prints one JSON object on stdout: what it is (uid, euid, pid) and what it
observed. It asserts nothing; the harness does, against the audit log.

Standard library only: it must run wherever the second user can run `python3`,
with no environment of its own.
"""

from __future__ import annotations

import errno
import json
import os
import socket
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path

TIMEOUT_S = 10.0
BAD_FRAME = b"\x00\x00\x00\x05\x01{bad}"


def _identity() -> dict[str, int]:
    return {"uid": os.getuid(), "euid": os.geteuid(), "pid": os.getpid()}


def _exchange(path: str, frame: bytes) -> dict[str, object]:
    """Connect, send `frame`, read until the server closes."""
    result: dict[str, object] = {"connected": False, "received": 0, "eof": False, "error": None}
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(TIMEOUT_S)
    try:
        client.connect(path)
        result["connected"] = True
        try:
            client.sendall(frame)
        except OSError as exc:
            # The server may already have closed an unlisted peer's socket.
            result["error"] = errno.errorcode.get(exc.errno or 0, str(exc.errno))
        received = 0
        while True:
            try:
                chunk = client.recv(65536)
            except ConnectionResetError:
                result["eof"] = True
                break
            if not chunk:
                result["eof"] = True
                break
            received += len(chunk)
        result["received"] = received
    except TimeoutError:
        result["error"] = "timeout"
    except OSError as exc:
        result["error"] = errno.errorcode.get(exc.errno or 0, str(exc.errno))
    finally:
        client.close()
    return result


def _attempts(path: Path) -> list[tuple[str, Callable[[], None]]]:
    ipc = path.parent

    def unlink_socket() -> None:
        path.unlink()

    def rename_over_socket() -> None:
        fd, name = tempfile.mkstemp(dir=ipc.parent if os.access(ipc.parent, os.W_OK) else None)
        os.close(fd)
        try:
            Path(name).rename(path)
        finally:
            if Path(name).exists():
                Path(name).unlink()

    def bind_beside() -> None:
        impostor = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            impostor.bind(str(ipc / "kernel.sock.impostor"))
        finally:
            impostor.close()

    def bind_at_the_name() -> None:
        impostor = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        try:
            impostor.bind(str(path))
        finally:
            impostor.close()

    def rename_ipc_directory() -> None:
        ipc.rename(ipc.with_name(ipc.name + ".moved"))

    def symlink_in_ipc_directory() -> None:
        (ipc / "shadow.sock").symlink_to("elsewhere.sock")

    def chmod_ipc_directory() -> None:
        # The permissive mode is the attack being attempted, not a choice.
        ipc.chmod(0o777)

    return [
        ("unlink the socket", unlink_socket),
        ("rename a file over the socket", rename_over_socket),
        ("bind a socket beside it", bind_beside),
        ("bind a socket at its name", bind_at_the_name),
        ("rename the IPC directory", rename_ipc_directory),
        ("create a symlink in the IPC directory", symlink_in_ipc_directory),
        ("chmod the IPC directory", chmod_ipc_directory),
    ]


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print(__doc__, file=sys.stderr)
        return 2
    case, path = argv[1], argv[2]
    report: dict[str, object] = {"case": case, **_identity()}
    if case == "hello" and len(argv) == 4:
        report.update(_exchange(path, bytes.fromhex(argv[3])))
    elif case == "garbage":
        report.update(_exchange(path, BAD_FRAME))
    elif case == "flood" and len(argv) == 5:
        count = int(argv[3])
        frame = bytes.fromhex(argv[4])
        results = [_exchange(path, frame) for _ in range(count)]
        report["attempts"] = count
        report["connected"] = sum(1 for r in results if r["connected"])
        report["received"] = sum(int(str(r["received"])) for r in results)
    elif case == "impersonate":
        outcomes = []
        for name, attempt in _attempts(Path(path)):
            try:
                attempt()
            except OSError as exc:
                code = errno.errorcode.get(exc.errno or 0, str(exc.errno))
                outcomes.append({"attempt": name, "refused": True, "errno": code})
            else:
                outcomes.append({"attempt": name, "refused": False, "errno": None})
        report["attempts"] = outcomes
    else:
        print(__doc__, file=sys.stderr)
        return 2
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
