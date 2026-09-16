"""The evaluation unit, and the vocabulary every other module shares.

An eval is data: a name, a runner to invoke, a fixture to feed it, a seed, and
what its score means. It is never code in a configuration file — fixtures and
suite files are parsed, never executed (`docs/EVALS.md`, and
[ADR-0031](../../../docs/adr/0031-repository-layout-and-boundary-enforcement.md)
on why static rules beat clever ones).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final

__all__ = [
    "DEFAULT_TIMEOUT_S",
    "Eval",
    "Outcome",
    "Status",
    "Suite",
]

DEFAULT_TIMEOUT_S: Final = 30.0


class Status(StrEnum):
    """The outcome of one eval run.

    ``PENDING`` and ``SKIP`` are deliberately not ``PASS``: a property that
    cannot be measured yet is not a property that holds. The gate counts them
    separately and the summary prints them separately, so a dashboard cannot
    turn "not executable yet" into green.
    """

    PASS = "pass"  # noqa: S105 - an outcome, not a credential
    FAIL = "fail"
    SKIP = "skip"
    PENDING = "pending"
    ERROR = "error"

    @property
    def is_success(self) -> bool:
        return self is Status.PASS


@dataclass(frozen=True, slots=True)
class Outcome:
    """What a runner returns: a decision, numbers, and why."""

    status: Status
    metrics: dict[str, float] = field(default_factory=dict)
    reason: str = ""
    artifacts: dict[str, str] = field(default_factory=dict)
    """Small named strings (a failing input, a diff). Bounded by the runner."""


@dataclass(frozen=True, slots=True)
class Eval:
    """One measurable claim."""

    id: str
    """``<suite>/<name>``. Stable across commits: results are compared by it."""
    suite: str
    name: str
    description: str
    runner: str
    """Key into the runner registry. Never an import path from a file."""
    scorer: str
    fixture: str | None
    seed: int
    timeout_s: float
    runs: int
    """How many times to run it. Deterministic evals use 1."""
    requires: tuple[str, ...]
    """Milestones this eval needs, e.g. ``("M3",)``. Unmet means PENDING."""
    pending_reason: str | None
    tags: tuple[str, ...]
    gate: bool
    """Part of the deterministic per-pull-request subset."""

    @property
    def is_pending(self) -> bool:
        return self.pending_reason is not None


@dataclass(frozen=True, slots=True)
class Suite:
    """A group of evals that share a scoring meaning."""

    id: str
    title: str
    description: str
    score_meaning: str
    """What this suite's score *is*. Required: a number nobody can read is not
    a measurement, and averaging unlike properties hides regressions."""
    requires: tuple[str, ...]
    gate: bool
    source: str
    """Repository-relative path of the suite file, for diagnostics."""
    evals: tuple[Eval, ...]
