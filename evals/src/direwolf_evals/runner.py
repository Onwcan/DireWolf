"""Executing evals: the same inputs produce the same results, every time.

Order is by identifier, never by filesystem traversal. Seeds are recorded on
every result, and a randomised eval is reproducible from its identifier and its
seed alone — the summary prints the command that does it.

Requirements are checked before anything runs: an eval that needs a milestone
this build does not have is PENDING, and PENDING is not a pass.
"""

from __future__ import annotations

import time
from collections.abc import Sequence
from pathlib import Path
from typing import Final

from direwolf_evals.discovery import discover
from direwolf_evals.fixtures import FixtureError, load_fixture
from direwolf_evals.model import Eval, Outcome, Status, Suite
from direwolf_evals.results import Result, RunReport
from direwolf_evals.runners import Context, resolve
from direwolf_evals.scoring import score_outcome

__all__ = ["AVAILABLE_MILESTONES", "collect", "run_eval", "run_suites"]

AVAILABLE_MILESTONES: Final[frozenset[str]] = frozenset({"M1", "M2", "M2.5"})
"""What this build has. An eval requiring anything else is pending.

Extending this set is how a future milestone turns its suites on: add "M3"
here in the commit that makes M3 real, and every suite that has been waiting
starts running and must pass.
"""


def collect(
    evals_root: Path,
    *,
    suites: Sequence[str] = (),
    gate_only: bool = False,
) -> list[tuple[Suite, Eval]]:
    """Every eval to run, ordered by identifier."""
    selected: list[tuple[Suite, Eval]] = []
    for suite in discover(evals_root):
        if suites and suite.id not in suites:
            continue
        for evaluation in suite.evals:
            if gate_only and not evaluation.gate:
                continue
            selected.append((suite, evaluation))
    return sorted(selected, key=lambda pair: pair[1].id)


def run_eval(
    suite: Suite,
    evaluation: Eval,
    *,
    repo_root: Path,
    evals_root: Path,
    seed_override: int | None = None,
) -> list[Result]:
    """Run one eval ``runs`` times, or report why it did not run."""
    seed = evaluation.seed if seed_override is None else seed_override
    missing = sorted(set(evaluation.requires) - AVAILABLE_MILESTONES)
    fixture_digest = None
    fixture_name = evaluation.fixture

    if evaluation.is_pending or missing:
        reason = evaluation.pending_reason or (
            f"requires {', '.join(missing)}, which this build does not have"
        )
        return [
            _result(suite, evaluation, Status.PENDING, None, 0.0, seed, 0, reason, {}, {}, None)
        ]

    # A declared fixture is resolved before anything runs, even when the runner
    # would not have read it: otherwise a typo in a fixture path is invisible,
    # and an eval can pass while measuring nothing it claimed to measure.
    if fixture_name is not None:
        try:
            fixture_digest = _digest(repo_root, evals_root, fixture_name)
        except FixtureError as exc:
            return [
                _result(
                    suite,
                    evaluation,
                    Status.ERROR,
                    None,
                    0.0,
                    seed,
                    0,
                    f"fixture: {exc}",
                    {},
                    {},
                    None,
                )
            ]

    results: list[Result] = []
    for index in range(max(1, evaluation.runs)):
        started = time.perf_counter()
        try:
            runner = resolve(evaluation.runner)
            context = Context(
                evaluation=evaluation,
                repo_root=repo_root,
                evals_root=evals_root,
                seed=seed,
                run_index=index,
            )
            outcome = runner(context)
        except FixtureError as exc:
            outcome = Outcome(Status.ERROR, {}, f"fixture: {exc}")
        except (KeyError, ValueError, OSError, RuntimeError) as exc:
            outcome = Outcome(Status.ERROR, {}, f"{type(exc).__name__}: {exc}")
        duration_ms = (time.perf_counter() - started) * 1000
        score = (
            score_outcome(evaluation.scorer, outcome) if outcome.status != Status.ERROR else None
        )
        results.append(
            _result(
                suite,
                evaluation,
                outcome.status,
                score,
                duration_ms,
                seed,
                index,
                outcome.reason,
                outcome.metrics,
                outcome.artifacts,
                fixture_digest,
            )
        )
    return results


def run_suites(
    repo_root: Path,
    evals_root: Path,
    *,
    suites: Sequence[str] = (),
    gate_only: bool = False,
    seed_override: int | None = None,
) -> RunReport:
    """Run a selection and collect every result."""
    report = RunReport()
    for suite, evaluation in collect(evals_root, suites=suites, gate_only=gate_only):
        for result in run_eval(
            suite,
            evaluation,
            repo_root=repo_root,
            evals_root=evals_root,
            seed_override=seed_override,
        ):
            report.add(result)
    return report


def _digest(repo_root: Path, evals_root: Path, fixture: str) -> str:
    """Resolve a fixture path against the two roots a suite may name.

    Protocol vectors live in the repository (``tests/protocol/...``); eval
    fixtures live under ``evals/fixtures``. A path that resolves in neither is
    an error, not a silently absent digest.
    """
    errors = []
    for root in (repo_root, evals_root / "fixtures"):
        try:
            return load_fixture(root, fixture).digest
        except FixtureError as exc:
            errors.append(str(exc))
    raise FixtureError(f"{fixture!r} was not found: {'; '.join(errors)}")


def _result(
    suite: Suite,
    evaluation: Eval,
    status: Status,
    score: float | None,
    duration_ms: float,
    seed: int,
    run_index: int,
    reason: str,
    metrics: dict[str, float],
    artifacts: dict[str, str],
    fixture_digest: str | None,
) -> Result:
    return Result(
        eval_id=evaluation.id,
        suite=suite.id,
        status=status,
        score=score,
        runs=max(1, evaluation.runs),
        run_index=run_index,
        duration_ms=duration_ms,
        seed=seed,
        reason=reason,
        metrics=dict(metrics),
        artifacts=dict(artifacts),
        fixture=evaluation.fixture,
        fixture_digest=fixture_digest,
        requires=evaluation.requires,
    )
