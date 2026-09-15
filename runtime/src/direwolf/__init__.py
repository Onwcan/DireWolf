"""DireWolf cognition runtime.

The process that reasons is not the process that is trusted.  This package runs
the agent loop: it ingests model output, tool results, retrieved memory and
external content, and it decides what it would *like* to happen.  It holds no
credentials, no network route, no filesystem handles and no ability to execute
anything.  Every side effect is a request to ``dwkd-authority`` over DWKP,
which decides independently.

Nothing in that description is implemented yet.  At milestone M1 this package
is a foundation: it imports, it reports its version, and it participates in the
lint, type and test pipelines.  See ``docs/ROADMAP.md``.
"""

from __future__ import annotations

from direwolf._version import __version__

__all__ = ["__version__"]
