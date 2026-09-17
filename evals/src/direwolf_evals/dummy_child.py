"""A deterministic child process for the fault-injection harness.

Deliberately boring: it announces named checkpoints, waits when told to, and
ends in whichever way the script asks for. It models *a process that can be
interrupted*, which is what the harness needs to be proved against — not a
kernel, not an authority process, not anything that will later grow semantics.

The script is a comma-separated list of steps, passed as one argument:

    checkpoint:NAME   print "CHECKPOINT NAME" and continue
    pause:NAME        print "CHECKPOINT NAME" and block until a line arrives
    emit:TEXT         print "OUT TEXT"
    warn:TEXT         print "ERR TEXT" on stderr
    sleep:SECONDS     sleep (bounded)
    crash             exit(70), the conventional "software error"
    hang              sleep until killed, so timeout handling can be tested
    deaf              ignore SIGTERM, then hang: the kill fallback needs a
                      child that will not go quietly (POSIX; on Windows
                      terminate() is TerminateProcess and cannot be ignored)
    exit:CODE         exit with CODE

Steps are parsed, never evaluated; unknown steps are an error.
"""

from __future__ import annotations

import signal
import sys
import time
from typing import Final

__all__ = ["main"]

MAX_SLEEP_S: Final = 30.0
CRASH_CODE: Final = 70


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) != 1:
        print("usage: python -m direwolf_evals.dummy_child <script>", file=sys.stderr)
        return 2
    for step in args[0].split(","):
        step = step.strip()
        if not step:
            continue
        verb, _, argument = step.partition(":")
        if verb == "checkpoint":
            _say(f"CHECKPOINT {argument}")
        elif verb == "pause":
            _say(f"CHECKPOINT {argument}")
            if sys.stdin.readline() == "":
                _say("STDIN CLOSED")
                return 1
            _say(f"RESUMED {argument}")
        elif verb == "emit":
            _say(f"OUT {argument}")
        elif verb == "warn":
            print(f"ERR {argument}", file=sys.stderr, flush=True)
        elif verb == "sleep":
            time.sleep(min(float(argument), MAX_SLEEP_S))
        elif verb == "crash":
            _say("CRASHING")
            return CRASH_CODE
        elif verb == "deaf":
            if hasattr(signal, "SIGTERM"):
                signal.signal(signal.SIGTERM, signal.SIG_IGN)
            _say("CHECKPOINT deaf")
            while True:
                time.sleep(0.05)
        elif verb == "hang":
            while True:
                time.sleep(0.05)
        elif verb == "exit":
            return int(argument)
        else:
            print(f"unknown step {verb!r}", file=sys.stderr)
            return 2
    return 0


def _say(line: str) -> None:
    print(line, flush=True)


if __name__ == "__main__":  # pragma: no cover - exercised as a subprocess
    raise SystemExit(main())
