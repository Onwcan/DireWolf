"""Scoring: what a number means, per suite, and never one number overall.

There is no "DireWolf score". Each suite states its measure in its own file
(``score = ...``), because a rejection rate, a determinism rate and a checkpoint
count are different properties, and an average of them would let a security
regression be paid for by an unrelated improvement.

A scorer turns one outcome into one number in [0, 1]. The gate acts on the
status; the score is what a baseline threshold and a trend are computed from.

Two invariants are enforced here rather than assumed:

* **The registry is closed.** ``scorer`` in a suite file must name one of
  :data:`SCORERS`. Discovery checks it before anything runs, so a typo is a
  configuration error with a list of the valid names, not a ``KeyError`` that
  reaches the top of the process. Nothing imports a scorer by name from data.
* **A score is a finite number in [0, 1].** ``NaN`` is not a score: it compares
  false against every threshold, so a baseline test like ``score <
  min_score`` silently passes. ``inf`` is not a score either, and neither
  survives standards-compliant JSON. A scorer that produces one raises
  :class:`ScoringError`, which the runner turns into an ERROR for that eval.

Metrics are *not* constrained to [0, 1] — a count or a duration is a legitimate
metric. They must still be finite; :mod:`direwolf_evals.results` enforces that.
"""

from __future__ import annotations

import math
from collections.abc import Callable

from direwolf_evals.model import Outcome, Status

__all__ = ["SCORERS", "ScoringError", "check_score", "is_scorer", "score_outcome", "scorer_names"]


class ScoringError(Exception):
    """A scorer was asked for a number it cannot honestly produce.

    Either the scorer is not in the registry, or the value it computed is not a
    finite number in [0, 1]. Both are contained by the runner and reported as an
    ERROR for the affected eval; neither ends the process.
    """


def check_score(score: float | None, *, source: str) -> float | None:
    """Return ``score`` if it is a usable score, else raise.

    ``None`` means "this scorer does not apply here" and is allowed. Anything
    else must be a finite number in [0, 1]. ``bool`` is rejected because a score
    of ``True`` is a category error that would silently compare as 1.0.
    """
    if score is None:
        return None
    if isinstance(score, bool) or not isinstance(score, (int, float)):
        raise ScoringError(f"{source} produced {score!r}, which is not a number")
    value = float(score)
    if not math.isfinite(value):
        raise ScoringError(
            f"{source} produced {value!r}; a score must be finite, because a "
            f"non-finite value compares false against every baseline threshold"
        )
    if not 0.0 <= value <= 1.0:
        raise ScoringError(f"{source} produced {value!r}; a score must be within [0.0, 1.0]")
    return value


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
        if value is None:
            return None
        return check_score(value, source=f"metric {key!r}")

    return scorer


SCORERS: dict[str, Callable[[Outcome], float | None]] = {
    "binary": _binary,
    "rejection_rate": _rate("rejection_rate"),
    "determinism_rate": _rate("determinism_rate"),
    "stability_rate": _rate("stability_rate"),
}


def scorer_names() -> list[str]:
    """Every scorer a suite file may name, for an error message worth reading."""
    return sorted(SCORERS)


def is_scorer(name: str) -> bool:
    return name in SCORERS


def score_outcome(scorer: str, outcome: Outcome) -> float | None:
    """Score one outcome, or raise :class:`ScoringError`.

    Never raises ``KeyError``: an unknown scorer is a configuration fault with a
    message, and the caller contains it.
    """
    implementation = SCORERS.get(scorer)
    if implementation is None:
        raise ScoringError(
            f"unknown scorer {scorer!r}; valid scorers are {scorer_names()}. "
            f"Add it to direwolf_evals.scoring.SCORERS — a suite file can never "
            f"name code that is not in that table."
        )
    try:
        value = implementation(outcome)
    except ScoringError:
        raise
    except Exception as exc:  # a scorer is code; contain it rather than die
        raise ScoringError(f"scorer {scorer!r} failed: {type(exc).__name__}: {exc}") from exc
    return check_score(value, source=f"scorer {scorer!r}")
