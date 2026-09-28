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
  create-path <path>                  create a new file by path, and remove it
                                      again: whether this user can change
                                      names in that directory by itself (M4c)
  rename-path <from> <to>             rename a name, and rename it back
  remove-path <path>                  remove a name
  probe-authority <state-dir> <kernel-socket> <handshake-hex>
                                      everything the broker identity must not
                                      be able to do to the authority
  launch <socket> <frame-hex> <exe> <cwd>
                                      send a process_start authorisation with
                                      two descriptors this user can open (M4d)
  run-helper <broker-binary>          run the launch helper directly, its
                                      stderr not the broker's control channel
  keyring-search <description>        look for a `user` key by description in
                                      this user's own kernel keyring (M4e): a
                                      secret the authority's uid holds is not
                                      in another uid's keyring

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


def launch(path: str, frame_hex: str, exe: str, cwd: str) -> dict[str, object]:
    frame = bytes.fromhex(frame_hex)
    try:
        sock = _connect(path)
    except OSError as exc:
        return {"connected": False, "errno": _errno_name(exc)}
    fds = [os.open(exe, os.O_RDONLY), os.open(cwd, os.O_RDONLY | os.O_DIRECTORY)]
    sent = True
    try:
        socket.send_fds(sock, [frame], fds)
    except OSError:
        sent = False
    finally:
        for fd in fds:
            os.close(fd)
    received, eof = _read_all(sock, 3.0)
    sock.close()
    return {"connected": True, "sent": sent, "received": received, "eof": eof}


def run_helper(binary: str) -> dict[str, object]:
    import subprocess

    done = subprocess.run(
        [binary, "exec-helper"],
        capture_output=True,
        timeout=10,
        check=False,
        env={},
    )
    return {
        "exit": done.returncode,
        "stdout": len(done.stdout),
        "stderr": len(done.stderr),
    }


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


def create_path(path: str) -> dict[str, object]:
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except OSError as exc:
        return {"refused": True, "errno": _errno_name(exc)}
    os.close(fd)
    Path(path).unlink()
    return {"refused": False}


def rename_path(source: str, destination: str) -> dict[str, object]:
    try:
        Path(source).rename(destination)
    except OSError as exc:
        return {"refused": True, "errno": _errno_name(exc)}
    Path(destination).rename(source)
    return {"refused": False}


def remove_path(path: str) -> dict[str, object]:
    try:
        Path(path).unlink()
    except OSError as exc:
        return {"refused": True, "errno": _errno_name(exc)}
    return {"refused": False}


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


def keyring_search(description: str) -> dict[str, object]:
    """`keyctl(KEYCTL_SEARCH, KEY_SPEC_USER_KEYRING, "user", description)`."""
    import ctypes

    numbers = {"x86_64": 250, "aarch64": 219}
    machine = os.uname().machine
    if machine not in numbers:
        return {"found": False, "errno": "UNSUPPORTED_ARCH"}
    libc = ctypes.CDLL(None, use_errno=True)
    keyctl_search, key_spec_user_keyring = 10, -4
    result = libc.syscall(
        numbers[machine],
        keyctl_search,
        key_spec_user_keyring,
        b"user",
        description.encode(),
        0,
    )
    if result >= 0:
        return {"found": True, "errno": None}
    err = ctypes.get_errno()
    return {"found": False, "errno": errno.errorcode.get(err, str(err))}


def keyring_read(serial: str) -> dict[str, object]:
    """`keyctl(KEYCTL_READ, serial, buffer, len)` on another uid's key, by its
    serial. Reports only whether anything was read and why not: the buffer is
    discarded unprinted, and its contents never reach the report."""
    import ctypes

    numbers = {"x86_64": 250, "aarch64": 219}
    machine = os.uname().machine
    if machine not in numbers:
        return {"read": False, "errno": "UNSUPPORTED_ARCH"}
    libc = ctypes.CDLL(None, use_errno=True)
    keyctl_read = 11
    buffer = ctypes.create_string_buffer(64)
    result = libc.syscall(numbers[machine], keyctl_read, int(serial), buffer, 64)
    ctypes.memset(buffer, 0, 64)
    if result >= 0:
        return {"read": True, "errno": None}
    err = ctypes.get_errno()
    return {"read": False, "errno": errno.errorcode.get(err, str(err))}


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
    elif mode == "create-path":
        report = create_path(argv[2])
    elif mode == "rename-path":
        report = rename_path(argv[2], argv[3])
    elif mode == "remove-path":
        report = remove_path(argv[2])
    elif mode == "probe-authority":
        report = probe_authority(argv[2], argv[3], argv[4])
    elif mode == "launch":
        report = launch(argv[2], argv[3], argv[4], argv[5])
    elif mode == "run-helper":
        report = run_helper(argv[2])
    elif mode == "keyring-search":
        report = keyring_search(argv[2])
    elif mode == "keyring-read":
        report = keyring_read(argv[2])
    else:
        print(json.dumps({"error": f"unknown mode {mode}"}))
        return 2
    report["euid"] = os.geteuid()
    report["pid"] = os.getpid()
    print(json.dumps(report))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
