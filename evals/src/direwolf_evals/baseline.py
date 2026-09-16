"""Baselines: what the suite is expected to do, written down on purpose.

A baseline is **not** "whatever passed last time". It is a reviewed file stating
the expected status of each eval and the threshold each score must meet, so that
a regression is a diff a human approved or a build that goes red — never a
number that quietly moved.

Nothing here writes a baseline during a gate run. `make eval-baseline` writes
one; a reviewer reads the diff.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
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
            evals[eval_id] = Expectation(
                status=Status(entry["status"]),
                min_score=entry.get("min_score"),
                pending_reason=entry.get("pending_reason"),
            )
        return Baseline(evals)


@dataclass(frozen=True, slots=True)
class Comparison:
    """What changed against the baseline, in the words a reviewer needs."""

    regressions: list[str]
    missing: list[str]
    unexpected: list[str]
    improvements: list[str]

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
) -> Comparison:
    """Compare one run against the recorded expectations.

    ``known_ids`` is every eval that exists, which is not the same as every
    eval that ran: the gate runs a subset on purpose. An eval in the baseline
    that no longer exists anywhere is a deletion, and deleting an eval must not
    be a way to make the gate green. An eval that exists but was out of scope
    for this run is simply not compared.
    """
    by_id: dict[str, list[Result]] = {}
    for result in results:
        by_id.setdefault(result.eval_id, []).append(result)

    regressions: list[str] = []
    improvements: list[str] = []
    absent = set(baseline.evals) - set(by_id)
    missing = sorted(absent if known_ids is None else absent - known_ids)
    unexpected = sorted(set(by_id) - set(baseline.evals))

    for eval_id, expectation in sorted(baseline.evals.items()):
        runs = by_id.get(eval_id)
        if runs is None:
            continue
        worst = _worst(runs)
        if worst is not expectation.status:
            message = f"{eval_id}: expected {expectation.status}, got {worst}{_why(runs)}"
            if _rank(worst) > _rank(expectation.status):
                regressions.append(message)
            else:
                improvements.append(message)
            continue
        if expectation.min_score is not None:
            scores = [r.score for r in runs if r.score is not None]
            score = min(scores) if scores else None
            if score is None:
                regressions.append(f"{eval_id}: expected a score, got none")
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
    )


def write(path: Path, results: list[Result]) -> None:
    """Record the current run as the baseline. A deliberate, reviewed act."""
    evals: dict[str, dict[str, Any]] = {}
    for result in sorted(results, key=lambda r: r.eval_id):
        status = _worst([r for r in results if r.eval_id == result.eval_id])
        entry: dict[str, Any] = {"status": str(status)}
        scores = [r.score for r in results if r.eval_id == result.eval_id and r.score is not None]
        if scores:
            entry["min_score"] = min(scores)
        if result.reason and status is Status.PENDING:
            entry["pending_reason"] = result.reason
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
