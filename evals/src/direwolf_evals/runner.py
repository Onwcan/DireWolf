"""Executing evals: the same inputs produce the same results, every time.

Order is by identifier, never by filesystem traversal. Seeds are recorded on
every result, and a randomised eval is reproducible from its identifier and its
seed alone — the summary prints the command that does it.

Requirements are checked before anything runs: an eval that needs a milestone
this build does not have is PENDING, and PENDING is not a pass.

**Milestone availability is the only thing that makes an eval pending.** The
``pending_reason`` in a suite file is the human half of the sentence, not a
switch: an eval whose requirements are all available runs, whatever that field
says. The day ``"M3"`` joins :data:`AVAILABLE_MILESTONES`, every suite that was
waiting for it starts executing, and one that has no runner yet reports ERROR
rather than staying quietly dormant — a security property that cannot run once
its milestone exists is a configuration defect, not a pending property.
"""

from __future__ import annotations

import math
import time
from collections.abc import Sequence
from pathlib import Path
from typing import Final

from direwolf_evals.discovery import discover
from direwolf_evals.fixtures import FixtureError, load_fixture
from direwolf_evals.model import Eval, Outcome, Status, Suite
from direwolf_evals.results import Result, RunReport
from direwolf_evals.runners import Context, resolve
from direwolf_evals.scoring import ScoringError, score_outcome

__all__ = ["AVAILABLE_MILESTONES", "collect", "run_eval", "run_suites"]

MAX_REASON_CHARS: Final = 1000
"""An error detail is diagnostics, not a channel. Bounded, like everything else
that reaches a result file."""

AVAILABLE_MILESTONES: Final[frozenset[str]] = frozenset({"M1", "M2", "M2.5"})
"""What this build has. An eval requiring anything else is pending.

Extending this set is how a future milestone turns its suites on: add "M3"
here in the commit that makes M3 real, and every suite that has been waiting
starts running and must pass. Nothing else gates them — in particular a
``pending_reason`` left in a suite file does not keep an eval dormant, and an
eval with no runner reports ERROR once its milestone is here.
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

    # Requirements, and nothing else, decide pendingness. `pending_reason` only
    # supplies the detail after the colon; it can neither create this state nor
    # survive it. See Eval.pending_reason_for.
    if missing:
        return [
            _result(
                suite,
                evaluation,
                Status.PENDING,
                None,
                0.0,
                seed,
                0,
                evaluation.pending_reason_for(missing),
                {},
                {},
                None,
            )
        ]

    # Requirements are met, so this eval is expected to run. A missing runner is
    # a configuration defect from here on, and is reported loudly: the failure
    # this guards against is a security property going dormant on the very
    # commit that made it measurable.
    if evaluation.runner is None:
        return [
            _result(
                suite,
                evaluation,
                Status.ERROR,
                None,
                0.0,
                seed,
                0,
                (
                    f"no runner: every milestone it requires "
                    f"({', '.join(evaluation.requires) or 'none'}) is available, so this eval "
                    f"must run. Give it a runner from direwolf_evals.runners.RUNNERS."
                ),
                {},
                {},
                None,
            )
        ]
    runner_name = evaluation.runner

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
            runner = resolve(runner_name)
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
        except Exception as exc:
            # A runner is code, and code raises things nobody enumerated. The
            # blast radius of any of them is this eval, never the process: every
            # other eval still runs and still reaches the results file.
            outcome = Outcome(Status.ERROR, {}, _bounded(f"{type(exc).__name__}: {exc}"))
        duration_ms = (time.perf_counter() - started) * 1000
        outcome, score = _score(evaluation, outcome)
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


def _score(evaluation: Eval, outcome: Outcome) -> tuple[Outcome, float | None]:
    """Score an outcome, or turn a scoring fault into an ERROR for this eval.

    Scoring used to happen outside the runner's containment, so an unknown
    scorer — or a metric that was ``NaN`` — reached the top of the process and
    ended the whole run. Now it is inside: the eval errors, and the rest of the
    suite is unaffected.

    Metrics are checked here too. They are *not* confined to [0, 1] (a count or
    a duration is a legitimate metric) but they must be finite, because a
    results file is machine truth and there is no standards-compliant JSON for
    ``NaN`` or ``Infinity``.
    """
    if outcome.status is Status.ERROR:
        return outcome, None
    for key in sorted(outcome.metrics):
        value = outcome.metrics[key]
        if isinstance(value, bool) or not isinstance(value, (int, float)):
            return _error(outcome, f"metric {key!r} is {value!r}, which is not a number"), None
        if not math.isfinite(float(value)):
            return _error(outcome, f"metric {key!r} is {float(value)!r}, which is not finite"), None
    try:
        return outcome, score_outcome(evaluation.scorer, outcome)
    except ScoringError as exc:
        return _error(outcome, str(exc)), None


def _error(outcome: Outcome, reason: str) -> Outcome:
    """Keep the runner's own reason and say what invalidated it. Metrics are
    dropped, because the metrics are what could not be trusted."""
    prefix = f"{outcome.reason} | " if outcome.reason else ""
    return Outcome(Status.ERROR, {}, _bounded(f"{prefix}{reason}"), dict(outcome.artifacts))


def _bounded(reason: str) -> str:
    if len(reason) <= MAX_REASON_CHARS:
        return reason
    return reason[: MAX_REASON_CHARS - 1] + "…"


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
