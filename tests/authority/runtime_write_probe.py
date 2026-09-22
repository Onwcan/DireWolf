"""Attempt, as the runtime's operating-system identity, every write that would
let the runtime change the authority state that constrains it.

Run as a user OTHER than the one that owns the state directory. Every attempt
must fail; one that succeeds is a deployment in which the process-and-privilege
boundary of ADR-0000 does not hold for `kernel.db` or `audit.log`, whatever the
mode bits say.

This is deployment verification, outside the authority's decision path: the
authority never calls it, and it never calls sudo. `scripts/dw.py
authority-write-probe` runs it under a second identity when one is available,
and reports NOT EXERCISED -- never a pass -- when it is not.

Exit codes: 0 every write refused; 1 at least one write succeeded; 3 the probe
is running as the state's owner, so it proves nothing.

Standard library only: the probe must run wherever the runtime user can run
`python3`, with no environment of its own.
"""

from __future__ import annotations

import errno
import os
import sys
import tempfile
from collections.abc import Callable
from pathlib import Path


def _attempts(state: Path) -> list[tuple[str, Callable[[], None]]]:
    db = state / "kernel.db"
    wal = state / "kernel.db-wal"
    audit = state / "audit.log"

    def open_for_write(path: Path) -> None:
        with path.open("r+b") as handle:
            handle.write(b"")

    def create_in_directory() -> None:
        with (state / "planted").open("xb") as handle:
            handle.write(b"x")

    def rename_over_db() -> None:
        # A file this user CAN create (in the system temp directory) renamed
        # over kernel.db: the directory, not the file, is what decides this.
        fd, name = tempfile.mkstemp()
        os.close(fd)
        planted = Path(name)
        try:
            planted.rename(db)
        finally:
            if planted.exists():
                planted.unlink()

    def truncate_audit() -> None:
        os.truncate(audit, 0)

    def append_audit() -> None:
        with audit.open("ab") as handle:
            handle.write(b"{}\n")

    def unlink_db() -> None:
        db.unlink()

    def chmod_directory() -> None:
        # The permissive mode is the attack being attempted, not a choice.
        state.chmod(0o777)

    return [
        ("open kernel.db for writing", lambda: open_for_write(db)),
        ("open kernel.db-wal for writing", lambda: open_for_write(wal)),
        ("create a file in the state directory", create_in_directory),
        ("rename a file over kernel.db", rename_over_db),
        ("truncate audit.log", truncate_audit),
        ("append to audit.log", append_audit),
        ("delete kernel.db", unlink_db),
        ("chmod the state directory", chmod_directory),
    ]


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: runtime_write_probe.py <authority-state-dir>", file=sys.stderr)
        return 2
    state = Path(argv[1])
    uid = os.getuid()
    try:
        owner = state.stat().st_uid
    except PermissionError:
        # Cannot even stat it: the parent is closed to this user too. Every
        # attempt below will be refused for that reason, which is still a
        # refusal -- but say so, because it is a stronger layout than 0700.
        owner = -1
    if owner == uid:
        print(f"NOT EXERCISED: running as uid {uid}, the owner of {state}")
        return 3
    print(f"runtime-user write probe: uid {uid} against {state} (owner uid {owner})")
    succeeded = 0
    inconclusive = 0
    for name, attempt in _attempts(state):
        try:
            attempt()
        except OSError as exc:
            if exc.errno == errno.EXDEV:
                # Refused because the temp file was on another filesystem, not
                # because of the state directory's permissions.
                inconclusive += 1
                print(f"  UNPROVEN  {name:<40} cross-device rename; not a permission test")
            else:
                print(f"  refused   {name:<40} {type(exc).__name__}: {exc.strerror}")
        else:
            succeeded += 1
            print(f"  SUCCEEDED {name}")
    if succeeded:
        print(f"FAIL: {succeeded} write(s) succeeded as uid {uid}")
        return 1
    if inconclusive:
        print(f"NOT EXERCISED: {inconclusive} attempt(s) could not test the permission")
        return 3
    print("PASS: every write was refused")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
