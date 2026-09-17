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

:meth:`Child.close` returns only once the child has been **reaped** — not merely
signalled. On POSIX a killed process stays in the table as a zombie until its
parent waits for it, so ``kill()`` without a following ``wait()`` leaks one per
eval. The sequence is terminate, bounded wait, kill, bounded wait, and only then
close the pipes and join the reader threads. If even that does not collect the
child, :class:`CleanupError` is raised: an uncollected process is reported, not
swallowed.
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

__all__ = [
    "Child",
    "ChildTimeoutError",
    "CleanupError",
    "UnsupportedOnPlatformError",
    "spawn",
]

MAX_CAPTURED_LINES: Final = 2000
POSIX: Final = os.name == "posix"
TERMINATE_GRACE_S: Final = 5.0
"""How long a child gets to exit on its own after SIGTERM."""
KILL_GRACE_S: Final = 5.0
"""How long to wait for the kernel to deliver an uncatchable kill. Bounded so
a wedged host cannot hang the suite; exceeding it is reported, not ignored."""
THREAD_JOIN_S: Final = 5.0

# Read once, because these names exist only on POSIX. Guarding the *use* of
# signal.SIGSTOP with `if POSIX` does not stop a type checker on Windows from
# reporting the attribute as missing, and `make typecheck` has to work on
# every platform a contributor develops on.
_SIGSTOP: Final[int] = getattr(signal, "SIGSTOP", 0)
_SIGCONT: Final[int] = getattr(signal, "SIGCONT", 0)


class ChildTimeoutError(Exception):
    """A checkpoint or an exit did not arrive inside its budget."""


class UnsupportedOnPlatformError(Exception):
    """The platform cannot do this. Say so; do not emulate it badly."""


class CleanupError(Exception):
    """A child could not be collected. Reported, never quietly accepted:
    a fault-injection harness that leaks processes corrupts every later
    measurement on the machine."""


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
    _closed: bool = False

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
        """Leave the host as we found it: no orphan, no zombie, no open pipe.

        Idempotent, and safe at every stage of a child's life — already exited,
        exits on SIGTERM, ignores SIGTERM, crashed, or never fully started.

        Killing is not collecting. On POSIX the child stays in the process table
        until the parent waits for it, so every branch here ends in a bounded
        ``wait``. Only exceptions that are understood are suppressed: an already
        dead process (``OSError``/``ProcessLookupError``) and an already closed
        pipe (``ValueError``). Anything else propagates.
        """
        if self._closed:
            return
        self._closed = True

        if self._paused:
            # A stopped process never sees SIGTERM. Let it run before asking it
            # to stop, or the terminate below would wait out its whole budget.
            with contextlib.suppress(OSError, ValueError):
                self.unpause()

        if self.process.poll() is None:
            self.terminate()
            self._reap(TERMINATE_GRACE_S)
        if self.process.poll() is None:
            self.kill()
            self._reap(KILL_GRACE_S)

        # The reader threads end at EOF, which the exit above guarantees. Join
        # them before closing the pipes, so a thread is never reading a file
        # object that is being closed underneath it.
        for thread in self._threads:
            thread.join(timeout=THREAD_JOIN_S)
        for pipe in (self.process.stdin, self.process.stdout, self.process.stderr):
            if pipe is not None:
                with contextlib.suppress(OSError, ValueError):
                    pipe.close()
        self.drain()

        if self.process.poll() is None:
            raise CleanupError(
                f"pid {self.process.pid} survived SIGTERM and SIGKILL and was not collected "
                f"within {TERMINATE_GRACE_S + KILL_GRACE_S}s; it is still on this host"
            )

    def _reap(self, timeout: float) -> None:
        """Wait for the child and collect its exit status. Never busy-waits:
        ``Popen.wait`` blocks in ``waitpid``/``WaitForSingleObject``."""
        with contextlib.suppress(subprocess.TimeoutExpired, OSError, ValueError):
            self.process.wait(timeout=timeout)

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
        self.process.send_signal(_SIGSTOP)
        self._paused = True

    def unpause(self) -> None:
        if not POSIX:
            raise UnsupportedOnPlatformError("SIGCONT is POSIX-only")
        self.process.send_signal(_SIGCONT)
        self._paused = False

    def terminate(self) -> None:
        """Ask the child to stop. Suppressed: the child already exited
        (``ProcessLookupError``) or the handle is gone (``ValueError``)."""
        with contextlib.suppress(OSError, ValueError):
            self.process.terminate()

    def kill(self) -> None:
        """Stop the child without its cooperation. Same suppressions, same
        reason — and, as everywhere here, a kill is followed by a wait."""
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
