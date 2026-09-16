"""The two statistics M2.5 actually needs, and nothing else.

Every number reported states what was measured, over how many runs, and by
which method. A statistic without those three is decoration.

Deterministic evals run once and need no interval. The interval exists for the
evals that will not be deterministic — model-driven ones from M7 — so that the
result format does not have to change when they arrive.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Final

__all__ = ["Interval", "PassRate", "wilson_interval"]

Z_95: Final = 1.959963984540054
"""Two-sided 95% normal quantile."""


@dataclass(frozen=True, slots=True)
class Interval:
    low: float
    high: float
    confidence: float
    method: str


@dataclass(frozen=True, slots=True)
class PassRate:
    """A binary rate over ``n`` runs, with the interval and its method named."""

    successes: int
    n: int
    rate: float
    interval: Interval

    def describe(self) -> str:
        return (
            f"{self.successes}/{self.n} passed "
            f"({self.rate:.3f}, {self.interval.confidence:.0%} "
            f"{self.interval.method} [{self.interval.low:.3f}, {self.interval.high:.3f}])"
        )


def wilson_interval(successes: int, n: int, z: float = Z_95) -> PassRate:
    """Wilson score interval for a binomial proportion.

    Chosen over the normal approximation because the rates that matter here sit
    at the ends: 0/20 failures and 20/20 passes are exactly where the textbook
    interval degenerates to zero width and says something false. Wilson stays
    sane there, and is four lines of arithmetic.
    """
    if n <= 0:
        raise ValueError("a rate over zero runs is not a measurement")
    if not 0 <= successes <= n:
        raise ValueError(f"{successes} successes in {n} runs is impossible")
    p = successes / n
    denominator = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denominator
    margin = (z / denominator) * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return PassRate(
        successes=successes,
        n=n,
        rate=p,
        interval=Interval(
            low=max(0.0, centre - margin),
            high=min(1.0, centre + margin),
            confidence=0.95,
            method="Wilson score interval",
        ),
    )
