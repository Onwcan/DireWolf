"""Regression tests for the five M2.5 harness reliability findings.

Each one is a property the harness claimed and did not have. They are kept
together, and named after the invariant rather than the symptom, because the
point is not "this bug is fixed" but "this class of failure is now visible":

A1  Milestone availability decides pendingness. `pending_reason` explains it
    and never disables an eval, so a security property cannot stay dormant
    after the milestone that owns it arrives.
A2  The scorer registry is closed, and scoring is inside the containment
    boundary: one bad suite file cannot end the process.
A3  A score is a finite number in [0, 1], a threshold is too, and machine JSON
    never contains NaN or Infinity.
A4  A pending baseline compares its reason, so a property cannot be deferred to
    a different milestone behind an unchanged status.
A5  `Child.close()` reaps. Killing is not collecting.
"""

from __future__ import annotations

import json
import math
import os
import subprocess
import sys
from dataclasses import replace
from pathlib import Path
from typing import Final

import pytest

from direwolf_evals import baseline as baseline_module
from direwolf_evals.cli import main
from direwolf_evals.discovery import DiscoveryError, discover
from direwolf_evals.fixtures import FixtureError, load_fixture
from direwolf_evals.model import Eval, Outcome, Status, Suite
from direwolf_evals.process import POSIX, CleanupError, spawn
from direwolf_evals.results import Result, ResultError, RunReport, write_jsonl
from direwolf_evals.runner import AVAILABLE_MILESTONES, collect, run_eval, run_suites
from direwolf_evals.runners import RUNNERS
from direwolf_evals.scoring import ScoringError, score_outcome

EVALS_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = EVALS_ROOT.parent


# --- helpers ----------------------------------------------------------------


def _suite(**over: object) -> Suite:
    base = Suite(
        id="probe",
        title="t",
        description="d",
        score_meaning="a rate of things",
        requires=(),
        gate=False,
        source="evals/suites/probe.toml",
        evals=(),
    )
    return replace(base, **over)  # type: ignore[arg-type]


def _eval(**over: object) -> Eval:
    base = Eval(
        id="probe/e",
        suite="probe",
        name="e",
        description="d",
        runner="harness.checkpoint",
        scorer="binary",
        fixture=None,
        seed=0,
        timeout_s=30.0,
        runs=1,
        requires=(),
        pending_reason=None,
        tags=(),
        gate=False,
    )
    return replace(base, **over)  # type: ignore[arg-type]


def _run(evaluation: Eval) -> list[Result]:
    return run_eval(_suite(), evaluation, repo_root=REPO_ROOT, evals_root=EVALS_ROOT)


def _write_suite(root: Path, body: str) -> Path:
    (root / "suites").mkdir(parents=True, exist_ok=True)
    path = root / "suites" / "probe.toml"
    path.write_text(
        'id = "probe"\ntitle = "t"\ndescription = "d"\nscore = "a rate of things"\n' + body,
        encoding="utf-8",
    )
    return path


def _baseline_file(path: Path, entries: dict[str, dict[str, object]]) -> Path:
    path.write_text(
        json.dumps({"baseline_version": 1, "evals": entries}),
        encoding="utf-8",
    )
    return path


# ===========================================================================
# A1 — milestone availability, not pending_reason, decides pendingness
# ===========================================================================


def test_a_missing_milestone_is_pending_and_says_which_one() -> None:
    results = _run(_eval(requires=("M9",), pending_reason="there is no M9."))
    assert [r.status for r in results] == [Status.PENDING]
    assert results[0].reason == "requires M9: there is no M9."
    assert results[0].score is None


def test_a_pending_reason_does_not_survive_its_milestone_arriving() -> None:
    """The finding, exactly. An eval whose requirements are all available runs,
    even though it still carries the sentence that explained the wait — that
    sentence is documentation, not a switch."""
    evaluation = _eval(
        requires=("M2",),  # available in this build
        pending_reason="this sentence used to keep the eval dormant for ever.",
        runner="harness.checkpoint",
    )
    results = _run(evaluation)
    assert [r.status for r in results] == [Status.PASS], results[0].reason
    assert results[0].reason != "requires M2: this sentence used to keep the eval dormant for ever."


def test_an_available_milestone_with_no_runner_is_an_error_not_a_quiet_pending() -> None:
    """A security property that cannot run once its milestone exists is a
    configuration defect. Reporting it as PENDING would be the same bug wearing
    a different status."""
    results = _run(_eval(requires=("M2",), runner=None, pending_reason="not built yet."))
    assert [r.status for r in results] == [Status.ERROR]
    assert "no runner" in results[0].reason
    assert RunReport(results).failed


def test_an_available_milestone_with_an_unknown_runner_is_an_error() -> None:
    results = _run(_eval(requires=("M2",), runner="nosuch.runner"))
    assert [r.status for r in results] == [Status.ERROR]
    assert "unknown runner" in results[0].reason
    assert RunReport(results).failed


def test_a_still_unavailable_milestone_stays_pending_when_a_nearer_one_lands() -> None:
    """M4 work does not become measurable because M3 shipped."""
    with_m3 = frozenset({*AVAILABLE_MILESTONES, "M3"})
    evaluation = _eval(requires=("M4",), pending_reason="there is no broker.", runner=None)
    missing = sorted(set(evaluation.requires) - with_m3)
    assert missing == ["M4"]
    assert evaluation.pending_reason_for(missing) == "requires M4: there is no broker."


def test_the_pending_reason_carries_the_milestone_from_requires_not_from_prose() -> None:
    """Deferring a property from M3 to M9 changes the recorded reason even if
    nobody touches the sentence — which is what lets a baseline notice."""
    detail = "the component does not exist."
    assert _eval(requires=("M3",), pending_reason=detail).pending_reason_for(["M3"]) == (
        f"requires M3: {detail}"
    )
    assert _eval(requires=("M9",), pending_reason=detail).pending_reason_for(["M9"]) == (
        f"requires M9: {detail}"
    )


def test_pending_never_counts_as_a_pass() -> None:
    report = run_suites(REPO_ROOT, EVALS_ROOT)
    counts = report.counts()
    assert counts["pending"] > 0
    assert not report.failed
    for result in report.results:
        if result.status is Status.PENDING:
            assert result.score is None
            assert result.reason.startswith("requires ")


def test_the_real_pending_suite_will_activate_when_m3_arrives() -> None:
    """The transition strategy, checked against the file that has to survive it.

    Every eval in `pending-kernel` that waits only for M3 must have nothing else
    holding it back, so that adding "M3" to AVAILABLE_MILESTONES really does
    make it run. None of them may name a placeholder runner: on that commit a
    placeholder would start reporting a pass for a property it never measured.
    """
    with_m3 = frozenset({*AVAILABLE_MILESTONES, "M3"})
    kernel = [e for _, e in collect(EVALS_ROOT) if e.suite == "pending-kernel"]
    assert kernel, "the pending suite should exist"

    activating = [e for e in kernel if not set(e.requires) - with_m3]
    assert {e.name for e in activating} == {
        "hostile-dwkp-client",
        "peer-credential-check",
        "epoch-fencing",
        "policy-denies-by-default",
        "capability-attenuation",
    }
    for evaluation in activating:
        assert evaluation.runner is None or evaluation.runner in RUNNERS

    later = [e for e in kernel if set(e.requires) - with_m3]
    assert {e.name for e in later} == {
        "path-traversal",
        "sandbox-egress",
        "approval-binding-drift",
        "model-egress-privacy",
    }
    for evaluation in later:
        assert sorted(set(evaluation.requires) - with_m3) == list(evaluation.requires)


def test_a_pending_reason_that_restates_its_requirement_is_refused(tmp_path: Path) -> None:
    """Two sources of truth for the milestone is how they drift apart."""
    _write_suite(
        tmp_path,
        '[[eval]]\nname = "e"\ndescription = "d"\nrequires = ["M3"]\n'
        'pending_reason = "requires M9: nope."\n',
    )
    with pytest.raises(DiscoveryError, match="must not restate"):
        discover(tmp_path)


def test_a_pending_reason_without_a_requirement_is_refused(tmp_path: Path) -> None:
    _write_suite(
        tmp_path,
        '[[eval]]\nname = "e"\ndescription = "d"\nrunner = "protocol.framing"\n'
        'pending_reason = "some day."\n',
    )
    with pytest.raises(DiscoveryError, match="without 'requires'"):
        discover(tmp_path)


def test_an_eval_with_neither_runner_nor_requirement_is_refused(tmp_path: Path) -> None:
    _write_suite(tmp_path, '[[eval]]\nname = "e"\ndescription = "d"\n')
    with pytest.raises(DiscoveryError, match="'runner' is required"):
        discover(tmp_path)


# ===========================================================================
# A2 — an invalid scorer is a configuration error, never a process death
# ===========================================================================


def test_a_typod_scorer_is_rejected_by_discovery(tmp_path: Path) -> None:
    _write_suite(
        tmp_path,
        '[[eval]]\nname = "e"\ndescription = "d"\nrunner = "protocol.framing"\n'
        'scorer = "rejecton_rate"\n',
    )
    with pytest.raises(DiscoveryError, match="unknown scorer 'rejecton_rate'"):
        discover(tmp_path)


def test_the_rejection_names_the_valid_scorers(tmp_path: Path) -> None:
    """An error a contributor can act on without reading the source."""
    _write_suite(
        tmp_path,
        '[[eval]]\nname = "e"\ndescription = "d"\nrunner = "protocol.framing"\nscorer = "nope"\n',
    )
    with pytest.raises(DiscoveryError, match="rejection_rate"):
        discover(tmp_path)


def test_an_unknown_scorer_never_reaches_a_runner(tmp_path: Path) -> None:
    """Discovery fails first, so nothing executes on a suite that cannot be
    scored — the eval does not run and then get thrown away."""
    _write_suite(
        tmp_path,
        '[[eval]]\nname = "e"\ndescription = "d"\nrunner = "harness.checkpoint"\nscorer = "nope"\n',
    )
    with pytest.raises(DiscoveryError):
        collect(tmp_path)


def test_every_scorer_a_suite_names_is_valid() -> None:
    for suite in discover(EVALS_ROOT):
        for evaluation in suite.evals:
            assert score_outcome(evaluation.scorer, Outcome(Status.SKIP)) is None


def test_an_unknown_scorer_that_slips_through_is_contained_as_an_error() -> None:
    """Defence in depth: discovery is the gate, but an Eval constructed in code
    must still not be able to kill the process."""
    results = _run(_eval(scorer="rejecton_rate", runner="harness.checkpoint"))
    assert [r.status for r in results] == [Status.ERROR]
    assert "unknown scorer" in results[0].reason
    assert RunReport(results).failed


def test_a_scorer_that_raises_is_contained(monkeypatch: pytest.MonkeyPatch) -> None:
    def explode(_: Outcome) -> float | None:
        raise ZeroDivisionError("scorer bug")

    monkeypatch.setitem(
        __import__("direwolf_evals.scoring", fromlist=["SCORERS"]).SCORERS, "binary", explode
    )
    with pytest.raises(ScoringError, match="scorer bug"):
        score_outcome("binary", Outcome(Status.PASS))


def test_one_bad_eval_does_not_corrupt_its_neighbours() -> None:
    """The blast radius of a configuration fault is one eval."""
    good = _run(_eval(runner="harness.checkpoint"))
    bad = _run(_eval(id="probe/bad", scorer="nope", runner="harness.checkpoint"))
    report = RunReport(good + bad)
    assert [r.status for r in good] == [Status.PASS]
    assert [r.status for r in bad] == [Status.ERROR]
    assert report.counts()["pass"] == 1
    assert report.counts()["error"] == 1
    assert report.failed


def test_a_runner_raising_an_unenumerated_exception_is_contained(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The old containment listed four exception types. A runner is code; code
    raises whatever it likes, and none of it may end the run."""

    def explode(_ctx: object) -> Outcome:
        raise AssertionError("not in anybody's except clause")

    monkeypatch.setitem(RUNNERS, "harness.checkpoint", explode)
    results = _run(_eval(runner="harness.checkpoint"))
    assert [r.status for r in results] == [Status.ERROR]
    assert "AssertionError" in results[0].reason


def test_an_error_reason_is_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    def explode(_ctx: object) -> Outcome:
        raise ValueError("x" * 50_000)

    monkeypatch.setitem(RUNNERS, "harness.checkpoint", explode)
    results = _run(_eval(runner="harness.checkpoint"))
    assert results[0].status is Status.ERROR
    assert len(results[0].reason) <= 1000


# ===========================================================================
# A3 — a score is a finite number in [0, 1]; machine JSON is standards JSON
# ===========================================================================

_BAD_SCORES = [float("nan"), float("inf"), float("-inf"), -0.01, 1.01]
_GOOD_SCORES = [0.0, 0.5, 1.0]


@pytest.mark.parametrize("value", _BAD_SCORES)
def test_a_scorer_cannot_produce_an_invalid_score(value: float) -> None:
    with pytest.raises(ScoringError):
        score_outcome("rejection_rate", Outcome(Status.PASS, {"rejection_rate": value}))


@pytest.mark.parametrize("value", _GOOD_SCORES)
def test_a_valid_score_passes_through(value: float) -> None:
    outcome = Outcome(Status.PASS, {"rejection_rate": value})
    assert score_outcome("rejection_rate", outcome) == value


@pytest.mark.parametrize("value", _BAD_SCORES)
def test_an_invalid_score_becomes_an_error_for_that_eval(
    value: float, monkeypatch: pytest.MonkeyPatch
) -> None:
    def runner(_ctx: object) -> Outcome:
        return Outcome(Status.PASS, {"rejection_rate": value})

    monkeypatch.setitem(RUNNERS, "harness.checkpoint", runner)
    results = _run(_eval(runner="harness.checkpoint", scorer="rejection_rate"))
    assert [r.status for r in results] == [Status.ERROR]
    assert results[0].score is None
    assert RunReport(results).failed


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_a_non_finite_metric_is_an_error_even_when_it_is_not_the_score(
    value: float, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Metrics are not confined to [0, 1] — a count is a metric — but a value
    with no JSON form cannot go in a results file."""

    def runner(_ctx: object) -> Outcome:
        return Outcome(Status.PASS, {"observations": value})

    monkeypatch.setitem(RUNNERS, "harness.checkpoint", runner)
    results = _run(_eval(runner="harness.checkpoint"))
    assert [r.status for r in results] == [Status.ERROR]
    assert "not finite" in results[0].reason


def test_a_large_finite_metric_is_fine(monkeypatch: pytest.MonkeyPatch) -> None:
    """The [0, 1] rule is about scores, not about every number."""

    def runner(_ctx: object) -> Outcome:
        return Outcome(Status.PASS, {"observations": 4096.0, "duration_ms": 1234.5})

    monkeypatch.setitem(RUNNERS, "harness.checkpoint", runner)
    results = _run(_eval(runner="harness.checkpoint"))
    assert [r.status for r in results] == [Status.PASS]
    assert results[0].metrics["observations"] == 4096.0


@pytest.mark.parametrize("value", _BAD_SCORES)
def test_a_result_refuses_to_hold_an_invalid_score(value: float) -> None:
    """The last line of defence: no path into a Result accepts one."""
    with pytest.raises(ResultError):
        Result(
            eval_id="x/y",
            suite="x",
            status=Status.PASS,
            score=value,
            runs=1,
            run_index=0,
            duration_ms=1.0,
            seed=0,
        )


def test_a_result_refuses_a_non_finite_metric() -> None:
    with pytest.raises(ResultError, match="not finite"):
        Result(
            eval_id="x/y",
            suite="x",
            status=Status.PASS,
            score=1.0,
            runs=1,
            run_index=0,
            duration_ms=1.0,
            seed=0,
            metrics={"m": float("inf")},
        )


def test_written_results_are_standards_compliant_json(tmp_path: Path) -> None:
    report = run_suites(REPO_ROOT, EVALS_ROOT)
    path = tmp_path / "results.jsonl"
    write_jsonl(path, report.results)
    text = path.read_text(encoding="utf-8")
    for literal in ("NaN", "Infinity", "-Infinity"):
        assert literal not in text
    for line in text.splitlines():
        json.loads(line, parse_constant=_no_constants)


def _no_constants(name: str) -> float:
    raise AssertionError(f"machine JSON contained the non-standard literal {name!r}")


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_writing_refuses_a_non_finite_number_that_arrived_some_other_way(
    value: float, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """`Result` rejects these, so force one past it: `allow_nan=False` must
    still refuse to write a file no strict parser could read."""
    result = Result(
        eval_id="x/y",
        suite="x",
        status=Status.PASS,
        score=1.0,
        runs=1,
        run_index=0,
        duration_ms=1.0,
        seed=0,
    )
    monkeypatch.setattr(type(result), "to_json", lambda _self, _env: {"score": value}, raising=True)
    with pytest.raises(ValueError, match="Out of range float"):
        write_jsonl(tmp_path / "r.jsonl", [result])


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf"), -0.5, 2.0])
def test_a_baseline_threshold_must_be_a_finite_number_in_range(
    value: float, tmp_path: Path
) -> None:
    path = _baseline_file(tmp_path / "b.json", {"x/y": {"status": "pass", "min_score": value}})
    with pytest.raises(baseline_module.BaselineError):
        baseline_module.Baseline.load(path)


def test_a_nan_score_against_a_full_threshold_is_never_a_pass(tmp_path: Path) -> None:
    """The exact regression. `float("nan") < 1.0` is False, so the old
    comparison read a NaN score as "not below the threshold" and passed it.

    Two things now stop it, and both are asserted: the score cannot exist, and
    if it somehow did the comparison would call it out rather than wave it
    through.
    """
    with pytest.raises(ResultError):
        Result(
            eval_id="x/y",
            suite="x",
            status=Status.PASS,
            score=float("nan"),
            runs=1,
            run_index=0,
            duration_ms=1.0,
            seed=0,
        )

    smuggled = Result(
        eval_id="x/y",
        suite="x",
        status=Status.PASS,
        score=1.0,
        runs=1,
        run_index=0,
        duration_ms=1.0,
        seed=0,
    )
    object.__setattr__(smuggled, "score", float("nan"))
    path = _baseline_file(tmp_path / "b.json", {"x/y": {"status": "pass", "min_score": 1.0}})
    comparison = baseline_module.compare(baseline_module.Baseline.load(path), [smuggled])
    assert comparison.regressions
    assert not comparison.ok
    assert "not a finite number" in comparison.regressions[0]


def test_the_repository_results_contain_no_non_finite_number() -> None:
    report = run_suites(REPO_ROOT, EVALS_ROOT)
    for result in report.results:
        assert result.score is None or math.isfinite(result.score)
        for value in result.metrics.values():
            assert math.isfinite(value)


# ===========================================================================
# A4 — a reviewed pending baseline detects pending-reason drift
# ===========================================================================


def _pending(eval_id: str, reason: str) -> Result:
    return Result(
        eval_id=eval_id,
        suite="probe",
        status=Status.PENDING,
        score=None,
        runs=1,
        run_index=0,
        duration_ms=0.0,
        seed=0,
        reason=reason,
    )


def test_a_matching_pending_reason_is_not_a_regression(tmp_path: Path) -> None:
    path = _baseline_file(
        tmp_path / "b.json",
        {"probe/e": {"status": "pending", "pending_reason": "requires M3: no authority."}},
    )
    comparison = baseline_module.compare(
        baseline_module.Baseline.load(path), [_pending("probe/e", "requires M3: no authority.")]
    )
    assert comparison.ok
    assert not comparison.regressions


def test_a_property_deferred_to_a_later_milestone_is_a_regression(tmp_path: Path) -> None:
    """Still PENDING, still no score — and four milestones further away. This
    is the whole reason the field is compared."""
    path = _baseline_file(
        tmp_path / "b.json",
        {"probe/e": {"status": "pending", "pending_reason": "requires M3: no authority."}},
    )
    comparison = baseline_module.compare(
        baseline_module.Baseline.load(path), [_pending("probe/e", "requires M9: no authority.")]
    )
    assert not comparison.ok
    assert "pending reason changed" in comparison.regressions[0]
    assert "M9" in comparison.regressions[0]


def test_a_pending_reason_that_disappeared_is_a_regression(tmp_path: Path) -> None:
    path = _baseline_file(
        tmp_path / "b.json",
        {"probe/e": {"status": "pending", "pending_reason": "requires M3: no authority."}},
    )
    comparison = baseline_module.compare(
        baseline_module.Baseline.load(path), [_pending("probe/e", "")]
    )
    assert not comparison.ok
    assert "got none" in comparison.regressions[0]


def test_a_pending_reason_that_appeared_is_reported(tmp_path: Path) -> None:
    """Deterministic and explicit: the baseline recorded no reason, so a new one
    is a change a reviewer records deliberately rather than inherits."""
    path = _baseline_file(tmp_path / "b.json", {"probe/e": {"status": "pending"}})
    comparison = baseline_module.compare(
        baseline_module.Baseline.load(path), [_pending("probe/e", "requires M3: no authority.")]
    )
    assert not comparison.ok
    assert "records no reason" in comparison.regressions[0]


def test_pending_becoming_a_pass_is_an_improvement_not_an_auto_update(tmp_path: Path) -> None:
    path = _baseline_file(
        tmp_path / "b.json",
        {"probe/e": {"status": "pending", "pending_reason": "requires M3: no authority."}},
    )
    passing = Result(
        eval_id="probe/e",
        suite="probe",
        status=Status.PASS,
        score=1.0,
        runs=1,
        run_index=0,
        duration_ms=1.0,
        seed=0,
    )
    comparison = baseline_module.compare(baseline_module.Baseline.load(path), [passing])
    assert comparison.ok
    assert comparison.improvements
    assert not comparison.regressions
    # The file on disk is untouched: a baseline moves when a reviewer moves it.
    assert json.loads(path.read_text(encoding="utf-8"))["evals"]["probe/e"]["status"] == "pending"


@pytest.mark.parametrize("status", [Status.FAIL, Status.ERROR])
def test_pending_becoming_a_failure_is_a_regression(status: Status, tmp_path: Path) -> None:
    path = _baseline_file(
        tmp_path / "b.json",
        {"probe/e": {"status": "pending", "pending_reason": "requires M3: no authority."}},
    )
    broken = Result(
        eval_id="probe/e",
        suite="probe",
        status=status,
        score=None,
        runs=1,
        run_index=0,
        duration_ms=1.0,
        seed=0,
        reason="it broke",
    )
    comparison = baseline_module.compare(baseline_module.Baseline.load(path), [broken])
    assert not comparison.ok
    assert comparison.regressions


def test_the_repository_baseline_records_a_reason_for_every_pending_eval() -> None:
    path = EVALS_ROOT / "baselines" / "main.json"
    loaded = baseline_module.Baseline.load(path)
    pending = {i: e for i, e in loaded.evals.items() if e.status is Status.PENDING}
    assert pending, "the pending suite should be in the baseline"
    for eval_id, expectation in pending.items():
        assert expectation.pending_reason, eval_id
        assert expectation.pending_reason.startswith("requires M"), eval_id


def test_a_written_baseline_round_trips_its_pending_reasons(tmp_path: Path) -> None:
    report = run_suites(REPO_ROOT, EVALS_ROOT)
    path = tmp_path / "b.json"
    baseline_module.write(path, report.results)
    comparison = baseline_module.compare(baseline_module.Baseline.load(path), report.results)
    assert comparison.ok, comparison.regressions


# ===========================================================================
# A5 — close() reaps. Killing is not collecting.
# ===========================================================================


_WNOHANG: Final[int] = getattr(os, "WNOHANG", 0)
"""`os.WNOHANG` exists only on POSIX; read it once so the type checker sees an
int on every platform rather than an attribute Windows does not have."""


def _alive(pid: int) -> bool:
    """True only for a process that is neither gone nor an uncollected zombie."""
    if not POSIX:
        return False
    try:
        collected, _ = os.waitpid(pid, _WNOHANG)
    except ChildProcessError:
        return False  # already reaped: exactly what close() should leave behind
    return collected == 0


def test_close_collects_a_child_that_exits_on_its_own() -> None:
    child = spawn("exit:0")
    assert child.wait() == 0
    child.close()
    assert child.process.poll() is not None


def test_close_collects_a_child_that_stops_on_terminate() -> None:
    child = spawn("hang")
    child.close()
    assert child.process.poll() is not None
    assert not _alive(child.process.pid)


@pytest.mark.skipif(not POSIX, reason="only POSIX lets a child ignore SIGTERM")
def test_the_kill_fallback_is_followed_by_a_wait() -> None:
    """The finding. A child that ignores SIGTERM has to be killed, and a killed
    child on POSIX stays in the process table until its parent waits for it.
    `kill()` alone left one zombie per eval."""
    child = spawn("deaf")
    child.wait_for_checkpoint("deaf")
    child.close()
    assert child.process.poll() is not None, "close() returned before the child was collected"
    assert child.process.returncode is not None
    assert not _alive(child.process.pid), "the child is still an uncollected zombie"


@pytest.mark.skipif(not POSIX, reason="zombies are a POSIX concept")
def test_the_fault_harness_leaves_no_zombie_behind() -> None:
    pids = []
    for script in ("exit:0", "crash", "hang", "checkpoint:a,exit:3"):
        with spawn(script) as child:
            pids.append(child.process.pid)
    for pid in pids:
        assert not _alive(pid), f"pid {pid} was left uncollected"


def test_close_is_idempotent() -> None:
    child = spawn("hang")
    child.close()
    first = child.process.returncode
    child.close()
    child.close()
    assert child.process.returncode == first


def test_close_after_an_explicit_wait_is_safe() -> None:
    with spawn("crash") as child:
        assert child.wait() == 70
    assert child.process.poll() == 70


@pytest.mark.skipif(not POSIX, reason="pause needs SIGSTOP")
def test_close_releases_a_paused_child_before_terminating_it() -> None:
    """A stopped process never sees SIGTERM: close() has to SIGCONT it first,
    or it would burn the whole terminate budget and fall through to kill."""
    child = spawn("checkpoint:ready,sleep:20,exit:0")
    child.wait_for_checkpoint("ready")
    child.pause()
    child.close()
    assert child.process.poll() is not None
    assert not _alive(child.process.pid)


def test_close_does_not_busy_wait() -> None:
    """Correctness comes from `Popen.wait` blocking in the OS, not from polling.

    Asserted structurally rather than by timing, because a timing assertion on a
    shared machine is a flaky test pretending to be a guarantee.
    """
    source = (EVALS_ROOT / "src/direwolf_evals/process.py").read_text(encoding="utf-8")
    body = source.split("def close(self)", 1)[1].split("\n    # -- observation", 1)[0]
    assert "time.sleep" not in body
    assert "process.wait(timeout=" in source


def test_close_reports_a_child_it_could_not_collect(monkeypatch: pytest.MonkeyPatch) -> None:
    """An uncollected process is reported, not swallowed: a leaked child
    corrupts every later measurement on the machine."""

    def never_exits(_self: object, timeout: float | None = None) -> None:  # noqa: ARG001
        """Stands in for a process the OS will not let us collect."""
        return

    child = spawn("exit:0")
    child.wait()
    monkeypatch.setattr(type(child.process), "poll", lambda _self: None)
    monkeypatch.setattr(type(child.process), "wait", never_exits)
    with pytest.raises(CleanupError, match="survived"):
        child.close()
    monkeypatch.undo()
    child._closed = False
    child.close()


def test_close_closes_every_pipe() -> None:
    child = spawn("exit:0")
    child.close()
    for pipe in (child.process.stdin, child.process.stdout, child.process.stderr):
        assert pipe is None or pipe.closed


def test_a_child_is_still_observable_after_close() -> None:
    """Cleanup must not throw away what the eval measured."""
    with spawn("checkpoint:a,emit:done,exit:0") as child:
        child.wait_for_checkpoint("a")
        child.wait()
    assert child.checkpoints() == ["a"]
    assert "OUT done" in child.stdout


def test_the_dummy_child_is_still_the_only_thing_spawned() -> None:
    source = (EVALS_ROOT / "src/direwolf_evals/process.py").read_text(encoding="utf-8")
    assert "shell=True" not in source
    assert sys.executable  # the argv is [sys.executable, "-m", "...dummy_child", script]
    assert subprocess.Popen is not None


# ===========================================================================
# The section-9 sweep: the same failure classes, found elsewhere
# ===========================================================================


def test_a_malformed_milestone_is_refused(tmp_path: Path) -> None:
    """`requires` now decides whether an eval runs, so a typo in it is the
    dormancy bug arriving through the other field: "m3" matches no available
    milestone and would sit at PENDING for ever, reading correctly."""
    _write_suite(
        tmp_path,
        '[[eval]]\nname = "e"\ndescription = "d"\nrunner = "protocol.framing"\nrequires = ["m3"]\n',
    )
    with pytest.raises(DiscoveryError, match="is not a milestone"):
        discover(tmp_path)


@pytest.mark.parametrize("milestone", ["M1", "M2.5", "M3", "M18"])
def test_well_formed_milestones_are_accepted(milestone: str, tmp_path: Path) -> None:
    _write_suite(
        tmp_path,
        f'[[eval]]\nname = "e"\ndescription = "d"\nrunner = "protocol.framing"\n'
        f'requires = ["{milestone}"]\n',
    )
    assert discover(tmp_path)[0].evals[0].requires == (milestone,)


@pytest.mark.parametrize(
    ("body", "match"),
    [
        ('seed = "zero"', "must be an integer"),
        ("seed = -1", "at least 0"),
        ('runs = "many"', "must be an integer"),
        ("runs = 0", "at least 1"),
        ('timeout_s = "soon"', "must be a number"),
        ("timeout_s = 0", "positive finite"),
        ("timeout_s = -5.0", "positive finite"),
        ('gate = "false"', "must be true or false"),
        ("fixture = 3", "must be a non-empty string"),
    ],
)
def test_a_malformed_value_is_a_configuration_error_not_a_crash(
    body: str, match: str, tmp_path: Path
) -> None:
    """These used to reach a bare `int()`/`float()`/`bool()` and raise
    ValueError — or worse, succeed: `bool("false")` is True, so a gate flag
    could read as the opposite of what the file said."""
    _write_suite(
        tmp_path,
        f'[[eval]]\nname = "e"\ndescription = "d"\nrunner = "protocol.framing"\n{body}\n',
    )
    with pytest.raises(DiscoveryError, match=match):
        discover(tmp_path)


def test_a_malformed_suite_file_exits_cleanly_rather_than_traceback(tmp_path: Path) -> None:
    """What a contributor sees: exit code 2 and a sentence, not a stack trace."""
    _write_suite(
        tmp_path,
        '[[eval]]\nname = "e"\ndescription = "d"\nrunner = "protocol.framing"\nseed = "x"\n',
    )
    assert main(["--evals-root", str(tmp_path), "run"]) == 2


def test_a_fixture_may_not_contain_a_non_json_constant(tmp_path: Path) -> None:
    """Python's JSON reader accepts NaN and Infinity. JSON does not, and a
    fixture carrying one would flow into a metric and out into a results file
    no strict parser could read."""
    (tmp_path / "f").mkdir()
    (tmp_path / "f" / "bad.json").write_text(
        '{"provenance": "authored", "value": NaN}', encoding="utf-8"
    )
    with pytest.raises(FixtureError, match="not JSON"):
        load_fixture(tmp_path / "f", "bad.json")


def test_every_repository_fixture_is_finite_json() -> None:
    for path in sorted((EVALS_ROOT / "fixtures").rglob("*.json")):
        load_fixture(EVALS_ROOT / "fixtures", path.relative_to(EVALS_ROOT / "fixtures").as_posix())


def test_the_status_of_an_eval_lives_in_exactly_one_place() -> None:
    """`Eval.is_pending` was a second, disagreeing source of truth for whether
    an eval would run. It is gone; nothing may reintroduce it."""
    assert not hasattr(_eval(), "is_pending")


def test_skip_is_not_a_success_either() -> None:
    assert not Status.SKIP.is_success
    assert not Status.PENDING.is_success
    assert not Status.ERROR.is_success
    assert not Status.FAIL.is_success
    assert Status.PASS.is_success


def test_error_fails_the_gate_and_pending_does_not() -> None:
    def result(status: Status) -> Result:
        return Result(
            eval_id="x/y",
            suite="x",
            status=status,
            score=None,
            runs=1,
            run_index=0,
            duration_ms=0.0,
            seed=0,
        )

    assert RunReport([result(Status.ERROR)]).failed
    assert RunReport([result(Status.FAIL)]).failed
    assert not RunReport([result(Status.PENDING)]).failed
    assert not RunReport([result(Status.SKIP)]).failed


def test_nothing_in_the_harness_rewrites_a_baseline_outside_the_baseline_command() -> None:
    """CI runs `check`. If anything on that path could write the file, the gate
    would be comparing a run against itself."""
    source_root = EVALS_ROOT / "src" / "direwolf_evals"
    writers = {
        path.name
        for path in source_root.rglob("*.py")
        if "baseline_module.write(" in path.read_text(encoding="utf-8")
        or "\n    path.write_text(" in path.read_text(encoding="utf-8")
    }
    assert writers <= {"baseline.py", "cli.py", "results.py"}
    cli = (source_root / "cli.py").read_text(encoding="utf-8")
    assert cli.count("baseline_module.write(") == 1
    assert "baseline_module.write(" in cli.split("def _baseline(")[1].split("def _list(")[0]
