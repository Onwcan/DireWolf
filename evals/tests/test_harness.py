"""Tests of the measuring equipment.

The important one is :func:`test_a_known_bad_result_fails_the_gate`. An
evaluation framework that has never rejected anything is decorative, and the
only honest way to show that it rejects is to feed it something that must fail
— inside a test, never as a fixture left failing in CI.
"""

from __future__ import annotations

import json
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from direwolf_evals import baseline as baseline_module
from direwolf_evals.cli import main
from direwolf_evals.discovery import DiscoveryError, discover, suite_paths
from direwolf_evals.fixtures import FixtureError, load_fixture
from direwolf_evals.model import Outcome, Status
from direwolf_evals.results import RESULT_VERSION, Result, RunReport, read_jsonl, write_jsonl
from direwolf_evals.runner import AVAILABLE_MILESTONES, collect, run_eval, run_suites
from direwolf_evals.runners import RUNNERS
from direwolf_evals.scoring import score_outcome
from direwolf_evals.statistics import wilson_interval

EVALS_ROOT = Path(__file__).resolve().parents[1]
# Every suite but the M3 authority suite, which builds and launches the real
# authority: these tests check the harness, and `make eval` measures the product.
FAST_SUITES = ("harness-selftest", "pending-kernel", "protocol-compat", "protocol-security")
REPO_ROOT = EVALS_ROOT.parent


# --- discovery is deterministic --------------------------------------------


def test_discovery_is_deterministic() -> None:
    """Same tree, same suites, same order, same ids — on every machine."""
    first = discover(EVALS_ROOT)
    second = discover(EVALS_ROOT)
    assert [s.id for s in first] == [s.id for s in second]
    assert [s.id for s in first] == sorted(s.id for s in first)
    for suite in first:
        assert [e.id for e in suite.evals] == sorted(e.id for e in suite.evals)


def test_every_eval_id_is_unique_and_prefixed_by_its_suite() -> None:
    ids = [e.id for suite in discover(EVALS_ROOT) for e in suite.evals]
    assert len(ids) == len(set(ids))
    for suite in discover(EVALS_ROOT):
        for evaluation in suite.evals:
            assert evaluation.id == f"{suite.id}/{evaluation.name}"


def test_every_runner_named_by_a_suite_exists() -> None:
    """A typo in a suite file must fail loudly, not skip quietly.

    An eval may name no runner at all, but only while it is waiting for a
    milestone: see `test_an_eval_with_no_runner_must_be_waiting_for_something`.
    """
    for suite in discover(EVALS_ROOT):
        for evaluation in suite.evals:
            if evaluation.runner is None:
                continue
            assert evaluation.runner in RUNNERS, f"{evaluation.id}: {evaluation.runner}"


def test_an_eval_with_no_runner_must_be_waiting_for_something() -> None:
    """The only excuse for having no runner is a milestone that does not exist."""
    for suite in discover(EVALS_ROOT):
        for evaluation in suite.evals:
            if evaluation.runner is None:
                assert evaluation.requires, evaluation.id


def test_every_suite_says_what_its_score_means() -> None:
    for suite in discover(EVALS_ROOT):
        assert len(suite.score_meaning.split()) >= 3, suite.id


def test_an_unknown_key_in_a_suite_file_is_an_error(tmp_path: Path) -> None:
    (tmp_path / "suites").mkdir()
    (tmp_path / "suites" / "x.toml").write_text(
        'id = "x"\ntitle = "t"\ndescription = "d"\nscore = "a rate of things"\nwat = 1\n',
        encoding="utf-8",
    )
    with pytest.raises(DiscoveryError, match="unknown keys"):
        discover(tmp_path)


def test_a_pending_eval_must_say_what_is_missing(tmp_path: Path) -> None:
    (tmp_path / "suites").mkdir()
    (tmp_path / "suites" / "x.toml").write_text(
        'id = "x"\ntitle = "t"\ndescription = "d"\nscore = "a rate of things"\n'
        '[[eval]]\nname = "e"\ndescription = "d"\nrunner = "protocol.framing"\n'
        'pending_reason = "  "\n',
        encoding="utf-8",
    )
    with pytest.raises(DiscoveryError, match="pending_reason"):
        discover(tmp_path)


def test_suite_files_are_data_not_code() -> None:
    """No suite may smuggle an import path or a shell command into a runner."""
    for path in suite_paths(EVALS_ROOT):
        text = path.read_text(encoding="utf-8")
        for forbidden in ("import ", "lambda", "os.system", "subprocess", "eval("):
            assert forbidden not in text, f"{path.name} contains {forbidden!r}"


# --- pending is not a pass -------------------------------------------------


def test_pending_evals_are_pending_not_passing() -> None:
    report = run_suites(REPO_ROOT, EVALS_ROOT, suites=FAST_SUITES)
    pending = [r for r in report.results if r.status is Status.PENDING]
    assert pending, "the pending suite should be discovered"
    for result in pending:
        assert result.score is None, f"{result.eval_id} has a score while pending"
        assert result.reason, f"{result.eval_id} does not say what is missing"
    assert not report.failed, "pending must not fail the run either"


def test_an_eval_requiring_a_future_milestone_is_pending() -> None:
    """The mechanism that turns suites on: a milestone this build lacks."""
    assert "M4" not in AVAILABLE_MILESTONES
    suite, evaluation = next((s, e) for s, e in collect(EVALS_ROOT) if "M4" in e.requires)
    results = run_eval(suite, evaluation, repo_root=REPO_ROOT, evals_root=EVALS_ROOT)
    assert [r.status for r in results] == [Status.PENDING]


def test_the_counts_keep_pending_apart_from_passing() -> None:
    report = run_suites(REPO_ROOT, EVALS_ROOT, suites=FAST_SUITES)
    counts = report.counts()
    assert counts["pending"] > 0
    assert (
        counts["pass"] + counts["pending"] + counts["skip"]
        == len(report.results) - counts["fail"] - counts["error"]
    )


# --- the gate rejects a known-bad result -----------------------------------


def test_a_known_bad_result_fails_the_gate(tmp_path: Path) -> None:
    """The acceptance criterion for M2.5: we proved the framework rejects a
    known regression, rather than asserting that it would."""
    good = Result(
        eval_id="protocol-security/framing",
        suite="protocol-security",
        status=Status.PASS,
        score=1.0,
        runs=1,
        run_index=0,
        duration_ms=1.0,
        seed=0,
    )
    baseline_path = tmp_path / "baseline.json"
    baseline_module.write(baseline_path, [good])

    regressed = Result(
        eval_id="protocol-security/framing",
        suite="protocol-security",
        status=Status.FAIL,
        score=0.5,
        runs=1,
        run_index=0,
        duration_ms=1.0,
        seed=0,
        reason="a hostile frame was accepted",
    )
    comparison = baseline_module.compare(baseline_module.Baseline.load(baseline_path), [regressed])
    assert not comparison.ok
    assert any("expected pass, got fail" in line for line in comparison.regressions)

    report = RunReport([regressed])
    assert report.failed


def test_a_score_below_the_baseline_threshold_is_a_regression(tmp_path: Path) -> None:
    """Status alone is not enough: a rejection rate that slips must fail even
    while the eval still reports a pass."""
    baseline_path = tmp_path / "baseline.json"
    baseline_path.write_text(
        json.dumps(
            {
                "baseline_version": 1,
                "evals": {
                    "protocol-security/invalid-vectors": {"status": "pass", "min_score": 1.0}
                },
            }
        ),
        encoding="utf-8",
    )
    slipped = Result(
        eval_id="protocol-security/invalid-vectors",
        suite="protocol-security",
        status=Status.PASS,
        score=0.97,
        runs=1,
        run_index=0,
        duration_ms=1.0,
        seed=0,
    )
    comparison = baseline_module.compare(baseline_module.Baseline.load(baseline_path), [slipped])
    assert not comparison.ok
    assert "below the baseline threshold" in comparison.regressions[0]


def test_a_missing_eval_is_a_regression(tmp_path: Path) -> None:
    """Deleting an eval must not be a way to make the gate green."""
    baseline_path = tmp_path / "baseline.json"
    baseline_module.write(
        baseline_path,
        [
            Result(
                eval_id="protocol-security/framing",
                suite="protocol-security",
                status=Status.PASS,
                score=1.0,
                runs=1,
                run_index=0,
                duration_ms=1.0,
                seed=0,
            )
        ],
    )
    comparison = baseline_module.compare(
        baseline_module.Baseline.load(baseline_path), [], known_ids=set()
    )
    assert not comparison.ok
    assert comparison.missing


def test_the_repository_baseline_matches_a_real_run() -> None:
    """The committed baseline describes this repository, not an aspiration."""
    report = run_suites(REPO_ROOT, EVALS_ROOT, suites=FAST_SUITES)
    known = {evaluation.id for _, evaluation in collect(EVALS_ROOT)}
    comparison = baseline_module.compare(
        baseline_module.Baseline.load(EVALS_ROOT / "baselines" / "main.json"),
        report.results,
        known,
    )
    assert comparison.ok, baseline_module.render(comparison)


def test_the_gate_command_passes_and_writes_results(tmp_path: Path) -> None:
    out = tmp_path / "results.jsonl"
    code = main(["--evals-root", str(EVALS_ROOT), "check", "--out", str(out)])
    assert code == 0
    records = list(read_jsonl(out))
    assert records
    assert {r["result_version"] for r in records} == {RESULT_VERSION}


def test_a_runner_that_raises_is_an_error_and_fails_the_gate() -> None:
    """An eval that blows up is not a pass and not a skip. It is an error, and
    the gate must go red: a harness that swallowed exceptions would report a
    broken measurement as a working one."""
    suite, _ = collect(EVALS_ROOT)[0]
    broken = replace(suite.evals[0], id="x/broken", runner="nosuch.runner")
    results = run_eval(suite, broken, repo_root=REPO_ROOT, evals_root=EVALS_ROOT)
    assert [r.status for r in results] == [Status.ERROR]
    assert results[0].score is None
    assert "unknown runner" in results[0].reason
    assert RunReport(results).failed


def test_a_missing_fixture_is_an_error_naming_the_fixture() -> None:
    suite, _ = collect(EVALS_ROOT)[0]
    broken = replace(suite.evals[0], id="x/missing", fixture="does/not/exist.json")
    results = run_eval(suite, broken, repo_root=REPO_ROOT, evals_root=EVALS_ROOT)
    assert results[0].status is Status.ERROR
    assert "does/not/exist.json" in results[0].reason


def test_two_runs_agree_on_everything_except_timing() -> None:
    """Determinism, stated as the property a result diff between commits rests
    on: the same tree gives the same ids, statuses, scores, seeds and metrics."""

    def snapshot() -> list[tuple[str, Status, float | None, int, dict[str, float]]]:
        report = run_suites(REPO_ROOT, EVALS_ROOT, suites=FAST_SUITES)
        return [(r.eval_id, r.status, r.score, r.seed, r.metrics) for r in report.ordered]

    assert snapshot() == snapshot()


# --- results -----------------------------------------------------------------


def test_results_are_ordered_and_bounded(tmp_path: Path) -> None:
    out = tmp_path / "r.jsonl"
    write_jsonl(
        out,
        [
            Result("b/x", "b", Status.PASS, 1.0, 1, 0, 1.0, 7, artifacts={"big": "x" * 5000}),
            Result("a/x", "a", Status.PASS, 1.0, 1, 0, 1.0, 7),
        ],
    )
    records = list(read_jsonl(out))
    assert [r["eval_id"] for r in records] == ["a/x", "b/x"]
    assert len(records[1]["artifacts"]["big"]) == 2000
    assert records[0]["environment"]["python"] == ".".join(str(p) for p in sys.version_info[:3])


def test_a_failing_run_reports_how_to_reproduce_it() -> None:
    from direwolf_evals.report import render

    report = RunReport(
        [
            Result(
                "suite/eval",
                "suite",
                Status.FAIL,
                0.0,
                1,
                0,
                1.0,
                4242,
                reason="it did not hold",
            )
        ]
    )
    rendered = render(report)
    assert "--eval suite/eval --seed 4242" in rendered
    assert "it did not hold" in rendered


# --- statistics --------------------------------------------------------------


def test_wilson_interval_is_not_degenerate_at_the_extremes() -> None:
    """The reason for choosing it: the normal approximation says [1, 1] here,
    which claims certainty from twenty observations."""
    perfect = wilson_interval(20, 20)
    assert perfect.rate == 1.0
    assert perfect.interval.low < 1.0
    assert perfect.interval.high == 1.0
    none = wilson_interval(0, 20)
    assert none.interval.low == 0.0
    assert none.interval.high > 0.0
    assert "Wilson" in perfect.interval.method


def test_a_rate_over_zero_runs_is_refused() -> None:
    with pytest.raises(ValueError, match="not a measurement"):
        wilson_interval(0, 0)


def test_scores_are_absent_for_statuses_that_have_no_score() -> None:
    for status in (Status.PENDING, Status.SKIP):
        assert score_outcome("binary", Outcome(status)) is None
        assert score_outcome("rejection_rate", Outcome(status, {"rejection_rate": 1.0})) is None


# --- fixtures are data -------------------------------------------------------


def test_a_fixture_cannot_escape_the_fixture_root(tmp_path: Path) -> None:
    (tmp_path / "inside.json").write_text('{"provenance": {"class": "authored"}}', encoding="utf-8")
    assert load_fixture(tmp_path, "inside.json").provenance == "authored"
    with pytest.raises(FixtureError, match="escapes"):
        load_fixture(tmp_path, "../outside.json")


def test_a_fixture_without_provenance_is_refused(tmp_path: Path) -> None:
    (tmp_path / "x.json").write_text('{"cases": []}', encoding="utf-8")
    with pytest.raises(FixtureError, match="provenance"):
        load_fixture(tmp_path, "x.json")


def test_an_external_corpus_fixture_must_record_its_licence(tmp_path: Path) -> None:
    (tmp_path / "x.json").write_text(
        '{"provenance": {"class": "external-corpus", "source": "s", "modification": "none"}}',
        encoding="utf-8",
    )
    with pytest.raises(FixtureError, match="licence"):
        load_fixture(tmp_path, "x.json")


def test_every_repository_fixture_declares_a_known_provenance() -> None:
    for path in sorted((EVALS_ROOT / "fixtures").rglob("*.json")):
        relative = path.relative_to(EVALS_ROOT / "fixtures").as_posix()
        assert load_fixture(EVALS_ROOT / "fixtures", relative).provenance
