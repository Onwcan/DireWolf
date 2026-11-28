"""Drive the trusted approver client on a pseudo-terminal (M6.3, ADR-0081).

A TEST DRIVER. The evidence harness runs it as the approver uid through
`sudo -n -u $DW_APPROVER_AS`: it starts the released `direwolf` on a terminal
of its own, waits for the client's prompt, types one line -- as a person at
that terminal would -- and reports what the client printed and how it ended.
It ships nowhere, and the client it drives is unchanged: it still refuses a
non-terminal input, still shows the request first, still decides nothing on
any line but `approve <code>` or `deny`.

    approver_tty_driver.py <client> <line> <client arguments>...

It prints one JSON object: the client's exit status, whether the line was
typed (only once the prompt appeared), and the client's output.

Standard library only.
"""

from __future__ import annotations

import json
import os
import pty
import select
import sys
import time

DEADLINE_S = 60.0


def main(argv: list[str]) -> int:
    if len(argv) < 4:
        print(__doc__, file=sys.stderr)
        return 2
    client, line, arguments = argv[1], argv[2], argv[3:]
    pid, fd = pty.fork()
    if pid == 0:
        os.execv(client, [client, *arguments])  # noqa: S606 - the client under test, no shell
    output = b""
    typed = False
    deadline = time.monotonic() + DEADLINE_S
    while time.monotonic() < deadline:
        ready, _, _ = select.select([fd], [], [], 0.5)
        if not ready:
            continue
        try:
            chunk = os.read(fd, 65536)
        except OSError:
            break
        if not chunk:
            break
        output += chunk
        if not typed and output.rstrip().endswith(b">"):
            os.write(fd, line.encode() + b"\n")
            typed = True
    _, status = os.waitpid(pid, 0)
    report = {
        "exit": os.waitstatus_to_exitcode(status),
        "typed": typed,
        "output": output.decode("utf-8", "replace"),
    }
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
