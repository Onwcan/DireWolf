"""Scoring: what a number means, per suite, and never one number overall.

There is no "DireWolf score". Each suite states its measure in its own file
(``score = ...``), because a rejection rate, a determinism rate and a checkpoint
count are different properties, and an average of them would let a security
regression be paid for by an unrelated improvement.

A scorer turns one outcome into one number in [0, 1]. The gate acts on the
status; the score is what a baseline threshold and a trend are computed from.
"""

from __future__ import annotations

from collections.abc import Callable

from direwolf_evals.model import Outcome, Status

__all__ = ["SCORERS", "score_outcome"]


def _binary(outcome: Outcome) -> float | None:
    """1.0 for a pass, 0.0 for a fail, nothing for anything else."""
    if outcome.status is Status.PASS:
        return 1.0
    if outcome.status is Status.FAIL:
        return 0.0
    return None


def _rate(key: str) -> Callable[[Outcome], float | None]:
    def scorer(outcome: Outcome) -> float | None:
        if outcome.status in (Status.PENDING, Status.SKIP):
            return None
        value = outcome.metrics.get(key)
        return None if value is None else float(value)

    return scorer


SCORERS: dict[str, Callable[[Outcome], float | None]] = {
    "binary": _binary,
    "rejection_rate": _rate("rejection_rate"),
    "determinism_rate": _rate("determinism_rate"),
    "stability_rate": _rate("stability_rate"),
}


def score_outcome(scorer: str, outcome: Outcome) -> float | None:
    if scorer not in SCORERS:
        raise KeyError(f"unknown scorer {scorer!r}; add it to direwolf_evals.scoring.SCORERS")
    return SCORERS[scorer](outcome)
