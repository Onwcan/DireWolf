"""The evaluation unit, and the vocabulary every other module shares.

An eval is data: a name, a runner to invoke, a fixture to feed it, a seed, and
what its score means. It is never code in a configuration file — fixtures and
suite files are parsed, never executed (`docs/EVALS.md`, and
[ADR-0031](../../../docs/adr/0031-repository-layout-and-boundary-enforcement.md)
on why static rules beat clever ones).
"""

from __future__ import annotations

from collections.abc import Sequence
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
    runner: str | None
    """Key into the runner registry. Never an import path from a file.

    ``None`` is allowed only while a required milestone is missing: an eval that
    cannot run yet has nothing honest to name. Once the milestone arrives, an
    absent or unknown runner is a configuration ERROR, never a quiet PENDING."""
    scorer: str
    fixture: str | None
    seed: int
    timeout_s: float
    runs: int
    """How many times to run it. Deterministic evals use 1."""
    requires: tuple[str, ...]
    """Milestones this eval needs, e.g. ``("M3",)``.

    **This, and only this, decides whether the eval is pending.** An eval is
    PENDING exactly when one of these is not in
    :data:`direwolf_evals.runner.AVAILABLE_MILESTONES`."""
    pending_reason: str | None
    """Human detail for *why* the milestone is missing — the clause after the
    colon in "requires M3: there is no authority process to lie to."

    It is documentation, not a switch. It never makes an eval pending and it
    never keeps one pending: an eval whose requirements are all available runs,
    whatever this says. The machine-readable half of the reason is generated
    from :attr:`requires`, so moving a property from M3 to M9 changes the
    recorded reason even if nobody edits this sentence."""
    tags: tuple[str, ...]
    gate: bool
    """Part of the deterministic per-pull-request subset."""
    platforms: tuple[str, ...] = ()
    """Where the property can be measured at all (``linux``, ``macos``,
    ``windows``); empty for everywhere. On any other platform the eval is
    *not exercised* -- SKIP, never a pass. See :mod:`direwolf_evals.preconditions`."""
    needs: tuple[str, ...] = ()
    """What the machine must provide (``second-identity``). Unmet, the eval is
    *not exercised*. See :mod:`direwolf_evals.preconditions`."""

    def pending_reason_for(self, missing: Sequence[str]) -> str:
        """The exact reason recorded when ``missing`` milestones block this eval.

        Deterministic, and derived from ``requires`` rather than from prose, so
        that a baseline can detect a property being deferred to a different
        milestone. ``missing`` is expected sorted.
        """
        requirement = f"requires {', '.join(missing)}"
        if not self.pending_reason:
            return f"{requirement}, which this build does not have"
        return f"{requirement}: {self.pending_reason}"


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
