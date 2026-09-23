"""Baselines: what the suite is expected to do, written down on purpose.

A baseline is **not** "whatever passed last time". It is a reviewed file stating
the expected status of each eval and the threshold each score must meet, so that
a regression is a diff a human approved or a build that goes red — never a
number that quietly moved.

Nothing here writes a baseline during a gate run. `make eval-baseline` writes
one; a reviewer reads the diff.

A baseline field that is written but never compared is decoration, so
``pending_reason`` is compared. When the baseline says an eval is PENDING it
also says *why*, and that sentence carries the milestone the property is waiting
for. Deferring a security property from M3 to M9 changes it, and a changed
reason is a regression a reviewer has to approve — otherwise "still pending"
would cover a property quietly sliding four milestones into the future.

The comparison is exact, on the whitespace-stripped string. Reasons are
generated deterministically from the eval's ``requires`` plus a fixed sentence
in the suite file, so they are stable; fuzzy matching would hide exactly the
drift this exists to catch.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

from direwolf_evals.model import Status
from direwolf_evals.results import Result

__all__ = ["Baseline", "BaselineError", "Comparison", "compare", "render", "write"]

BASELINE_VERSION: Final = 1


class BaselineError(Exception):
    """The baseline file is missing or not the shape this version reads."""


@dataclass(frozen=True, slots=True)
class Expectation:
    status: Status
    min_score: float | None
    pending_reason: str | None
    """The reason the baseline recorded for a PENDING eval. Compared exactly."""


@dataclass(frozen=True, slots=True)
class Baseline:
    evals: dict[str, Expectation]

    @staticmethod
    def load(path: Path) -> Baseline:
        try:
            raw: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise BaselineError(f"{path}: {exc}") from exc
        if raw.get("baseline_version") != BASELINE_VERSION:
            raise BaselineError(
                f"{path}: baseline_version {raw.get('baseline_version')!r} is not "
                f"{BASELINE_VERSION}; regenerate it deliberately"
            )
        evals = {}
        for eval_id, entry in sorted(raw.get("evals", {}).items()):
            try:
                status = Status(entry["status"])
            except (KeyError, ValueError) as exc:
                raise BaselineError(f"{path}: {eval_id}: bad status: {exc}") from exc
            evals[eval_id] = Expectation(
                status=status,
                min_score=_threshold(path, eval_id, entry.get("min_score")),
                pending_reason=_reason(path, eval_id, entry.get("pending_reason")),
            )
        return Baseline(evals)


def _threshold(path: Path, eval_id: str, value: Any) -> float | None:
    """A threshold that is not a finite number in [0, 1] is not a threshold.

    ``NaN`` is the dangerous one: ``score < float("nan")`` is False for every
    score, so a NaN threshold accepts everything while looking like a bound.
    """
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise BaselineError(f"{path}: {eval_id}: min_score {value!r} is not a number")
    number = float(value)
    if not math.isfinite(number):
        raise BaselineError(
            f"{path}: {eval_id}: min_score {number!r} is not finite; a non-finite "
            f"threshold compares false against every score and bounds nothing"
        )
    if not 0.0 <= number <= 1.0:
        raise BaselineError(f"{path}: {eval_id}: min_score {number!r} is outside [0.0, 1.0]")
    return number


def _reason(path: Path, eval_id: str, value: Any) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str):
        raise BaselineError(f"{path}: {eval_id}: pending_reason {value!r} is not a string")
    return value.strip()


@dataclass(frozen=True, slots=True)
class Comparison:
    """What changed against the baseline, in the words a reviewer needs."""

    regressions: list[str]
    missing: list[str]
    unexpected: list[str]
    improvements: list[str]
    not_exercised: list[str] = field(default_factory=list)
    """Evals expected to pass that this machine could not exercise, by their
    own declared preconditions. Never a pass; listed so nobody reads the
    green as covering them. Only a lenient comparison produces these."""

    @property
    def ok(self) -> bool:
        """Only regressions and missing evals fail. An eval that got *better*
        than its baseline is reported, not punished — but it does not silently
        become the new baseline either."""
        return not self.regressions and not self.missing


def compare(
    baseline: Baseline,
    results: list[Result],
    known_ids: set[str] | None = None,
    unexercised: frozenset[str] = frozenset(),
) -> Comparison:
    """Compare one run against the recorded expectations.

    ``known_ids`` is every eval that exists, which is not the same as every
    eval that ran: the gate runs a subset on purpose. An eval in the baseline
    that no longer exists anywhere is a deletion, and deleting an eval must not
    be a way to make the gate green. An eval that exists but was out of scope
    for this run is simply not compared.

    ``unexercised`` names evals this machine cannot exercise by their declared
    preconditions (``direwolf_evals.preconditions``). A SKIP from one of them,
    where the baseline expects more, is listed as *not exercised* instead of
    as a regression. Pass nothing -- the default -- for the strict gate CI runs,
    where not exercising a gating property is a failure.
    """
    by_id: dict[str, list[Result]] = {}
    for result in results:
        by_id.setdefault(result.eval_id, []).append(result)

    regressions: list[str] = []
    improvements: list[str] = []
    not_exercised: list[str] = []
    absent = set(baseline.evals) - set(by_id)
    missing = sorted(absent if known_ids is None else absent - known_ids)
    unexpected = sorted(set(by_id) - set(baseline.evals))

    for eval_id, expectation in sorted(baseline.evals.items()):
        runs = by_id.get(eval_id)
        if runs is None:
            continue
        worst = _worst(runs)
        if worst is Status.SKIP and eval_id in unexercised and worst is not expectation.status:
            not_exercised.append(f"{eval_id}{_why(runs)}")
            continue
        if worst is not expectation.status:
            message = f"{eval_id}: expected {expectation.status}, got {worst}{_why(runs)}"
            if _rank(worst) > _rank(expectation.status):
                regressions.append(message)
            else:
                improvements.append(message)
            continue
        if expectation.status is Status.PENDING:
            drift = _reason_drift(eval_id, expectation.pending_reason, runs)
            if drift:
                regressions.append(drift)
        if expectation.min_score is not None:
            scores = [r.score for r in runs if r.score is not None]
            score = min(scores) if scores else None
            if score is None:
                regressions.append(f"{eval_id}: expected a score, got none")
            elif not math.isfinite(score):
                # Result construction already refuses this. Belt and braces: a
                # non-finite score must never reach the `<` below, where it
                # would read as "not below the threshold" and quietly pass.
                regressions.append(f"{eval_id}: score {score!r} is not a finite number")
            elif score < expectation.min_score:
                regressions.append(
                    f"{eval_id}: score {score:.4f} is below the baseline "
                    f"threshold {expectation.min_score:.4f}"
                )

    for eval_id in unexpected:
        worst = _worst(by_id[eval_id])
        note = f"{eval_id}: not in the baseline (status {worst})"
        if worst in (Status.FAIL, Status.ERROR):
            regressions.append(note)
        else:
            improvements.append(note)

    return Comparison(
        regressions=regressions,
        missing=[f"{e}: in the baseline but no longer exists" for e in missing],
        unexpected=[f"{e}: not in the baseline" for e in unexpected],
        improvements=improvements,
        not_exercised=not_exercised,
    )


def _reason_drift(eval_id: str, expected: str | None, runs: list[Result]) -> str | None:
    """Compare the recorded pending reason with the one this run produced.

    Exact, on the stripped string. The reason names the milestone the property
    is waiting for, so a change here is a security property moving in time —
    worth a reviewer's attention even though the status is still PENDING.
    """
    actual = sorted({r.reason.strip() for r in runs if r.reason.strip()})
    found = actual[0] if actual else None
    if expected is None:
        if found is None:
            return None
        return (
            f"{eval_id}: still pending, but the baseline records no reason and this run "
            f"gave {found!r}; record it deliberately"
        )
    if found is None:
        return f"{eval_id}: expected pending reason {expected!r}, got none"
    if found != expected:
        return f"{eval_id}: pending reason changed from {expected!r} to {found!r}"
    return None


def write(path: Path, results: list[Result]) -> None:
    """Record the current run as the baseline. A deliberate, reviewed act."""
    evals: dict[str, dict[str, Any]] = {}
    for result in sorted(results, key=lambda r: r.eval_id):
        status = _worst([r for r in results if r.eval_id == result.eval_id])
        entry: dict[str, Any] = {"status": str(status)}
        scores = [r.score for r in results if r.eval_id == result.eval_id and r.score is not None]
        if scores:
            entry["min_score"] = min(scores)
        if status is Status.PENDING:
            # Deterministic across the runs of a multi-run eval: the sorted set,
            # not whichever result the loop happened to end on.
            reasons = sorted(
                {r.reason.strip() for r in results if r.eval_id == result.eval_id and r.reason}
            )
            if reasons:
                entry["pending_reason"] = reasons[0]
        evals[result.eval_id] = entry
    document = {
        "baseline_version": BASELINE_VERSION,
        "note": (
            "Expected outcomes, reviewed by a human. `make eval-check` fails on a "
            "regression against this file. Never regenerated automatically in CI."
        ),
        "evals": dict(sorted(evals.items())),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(document, ensure_ascii=True, indent=1, sort_keys=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )


def render(comparison: Comparison) -> str:
    lines: list[str] = []
    for title, entries in (
        ("regressions", comparison.regressions),
        ("missing from this run", comparison.missing),
        ("changed for the better, baseline not updated", comparison.improvements),
        (
            "NOT EXERCISED on this machine (not a pass; CI's gate requires them)",
            comparison.not_exercised,
        ),
    ):
        if entries:
            lines.append(f"{title}:")
            lines.extend(f"  {entry}" for entry in entries)
    return "\n".join(lines)


_ORDER: Final = {
    Status.PASS: 0,
    Status.SKIP: 1,
    Status.PENDING: 2,
    Status.FAIL: 3,
    Status.ERROR: 4,
}


def _rank(status: Status) -> int:
    return _ORDER[status]


def _worst(results: list[Result]) -> Status:
    return max((r.status for r in results), key=_rank)


def _why(results: list[Result]) -> str:
    reasons = sorted({r.reason for r in results if r.reason})
    return f" ({reasons[0]})" if reasons else ""
