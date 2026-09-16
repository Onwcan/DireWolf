"""Fault injection: start a process, catch it at a named point, break it there.

Phase 0 asks for the ability to pause a named process at a named state
(`docs/EVALS.md`). M2.5 builds the mechanism and proves it against the dummy
child in :mod:`direwolf_evals.dummy_child`, because the processes it will
really instrument — the authority daemon, the broker — do not exist yet.

The shape is deliberately one-directional:

    real process  --(checkpoint events on stdout)-->  harness  --> eval

The harness *observes and interrupts*. It never implements what the process
does, so M3 can emit checkpoints from the real daemon without this module
learning any authority semantics.

Platform support is reported, not pretended:

* **checkpoint, resume, terminate, kill, timeout** — everywhere.
* **pause/unpause of a running process** — POSIX only (``SIGSTOP``/``SIGCONT``).
  On Windows :meth:`Child.pause` raises :class:`UnsupportedOnPlatformError`; an eval
  that needs it is skipped with that reason rather than reported as passing.

Nothing here runs a shell, and no argument comes from a fixture: the child is
always this package's own module, invoked with ``sys.executable``.
"""

from __future__ import annotations

import contextlib
import os
import queue
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from types import TracebackType
from typing import Final

__all__ = ["Child", "ChildTimeoutError", "UnsupportedOnPlatformError", "spawn"]

MAX_CAPTURED_LINES: Final = 2000
POSIX: Final = os.name == "posix"


class ChildTimeoutError(Exception):
    """A checkpoint or an exit did not arrive inside its budget."""


class UnsupportedOnPlatformError(Exception):
    """The platform cannot do this. Say so; do not emulate it badly."""


@dataclass(slots=True)
class Child:
    """A running dummy process, watched line by line."""

    process: subprocess.Popen[str]
    script: str
    _events: queue.Queue[tuple[str, str]] = field(default_factory=queue.Queue)
    _stdout: list[str] = field(default_factory=list)
    _stderr: list[str] = field(default_factory=list)
    _threads: list[threading.Thread] = field(default_factory=list)
    _paused: bool = False

    # -- lifecycle ---------------------------------------------------------

    def __enter__(self) -> Child:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        """Always leave the host as we found it: no orphan, no stuck pipe."""
        if self._paused:
            with contextlib.suppress(OSError, ValueError):
                self.unpause()
        if self.process.poll() is None:
            self.terminate()
            with contextlib.suppress(OSError, ValueError):
                self.process.wait(timeout=5)
            if self.process.poll() is None:
                self.kill()
        with contextlib.suppress(OSError, ValueError):
            if self.process.stdin is not None:
                self.process.stdin.close()
        for thread in self._threads:
            thread.join(timeout=2)

    # -- observation -------------------------------------------------------

    def wait_for_checkpoint(self, name: str, timeout: float = 10.0) -> None:
        """Block until the child announces ``name``."""
        deadline = time.monotonic() + timeout
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ChildTimeoutError(
                    f"checkpoint {name!r} did not arrive in {timeout}s; saw {self.checkpoints()}"
                )
            try:
                stream, line = self._events.get(timeout=min(remaining, 0.25))
            except queue.Empty:
                if self.process.poll() is not None and self._events.empty():
                    raise ChildTimeoutError(
                        f"the child exited ({self.process.returncode}) before {name!r}"
                    ) from None
                continue
            self._record(stream, line)
            if stream == "stdout" and line.strip() == f"CHECKPOINT {name}":
                return

    def checkpoints(self) -> list[str]:
        self.drain()
        return [line.split(" ", 1)[1] for line in self._stdout if line.startswith("CHECKPOINT ")]

    def drain(self) -> None:
        """Absorb whatever has arrived without waiting for more."""
        while True:
            try:
                stream, line = self._events.get_nowait()
            except queue.Empty:
                return
            self._record(stream, line)

    @property
    def stdout(self) -> list[str]:
        self.drain()
        return list(self._stdout)

    @property
    def stderr(self) -> list[str]:
        self.drain()
        return list(self._stderr)

    # -- interruption ------------------------------------------------------

    def resume(self) -> None:
        """Release a child blocked at a ``pause:`` step."""
        if self.process.stdin is None:
            raise RuntimeError("the child has no stdin")
        self.process.stdin.write("RESUME\n")
        self.process.stdin.flush()

    def pause(self) -> None:
        """Stop the process where it stands (POSIX only)."""
        if not POSIX:
            raise UnsupportedOnPlatformError(
                "pausing a running process needs SIGSTOP; Windows has no equivalent "
                "that does not change what is being measured"
            )
        self.process.send_signal(signal.SIGSTOP)
        self._paused = True

    def unpause(self) -> None:
        if not POSIX:
            raise UnsupportedOnPlatformError("SIGCONT is POSIX-only")
        self.process.send_signal(signal.SIGCONT)
        self._paused = False

    def terminate(self) -> None:
        with contextlib.suppress(OSError, ValueError):
            self.process.terminate()

    def kill(self) -> None:
        with contextlib.suppress(OSError, ValueError):
            self.process.kill()

    def wait(self, timeout: float = 10.0) -> int:
        try:
            code = self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as exc:
            raise ChildTimeoutError(f"the child did not exit in {timeout}s") from exc
        self.drain()
        return code

    # -- internals ---------------------------------------------------------

    def _record(self, stream: str, line: str) -> None:
        target = self._stdout if stream == "stdout" else self._stderr
        if len(target) < MAX_CAPTURED_LINES:
            target.append(line.rstrip("\n"))


def spawn(script: str, *, env: dict[str, str] | None = None) -> Child:
    """Start the dummy child with ``script`` (see :mod:`~.dummy_child`)."""
    process = subprocess.Popen(
        [sys.executable, "-m", "direwolf_evals.dummy_child", script],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        bufsize=1,
        env=env,
    )
    child = Child(process=process, script=script)
    for name, stream in (("stdout", process.stdout), ("stderr", process.stderr)):
        thread = threading.Thread(
            target=_pump,
            args=(name, stream, child._events),
            daemon=True,
        )
        thread.start()
        child._threads.append(thread)
    return child


def _pump(name: str, stream: object, events: queue.Queue[tuple[str, str]]) -> None:
    if stream is None:
        return
    for line in stream:  # type: ignore[attr-defined]
        events.put((name, line))
