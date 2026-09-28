"""`direwolf_evals check --suite`: a gate scoped to named suites.

CI's authority-boundary job proves M3's cross-uid property with the
`authority-security` suite; it must not become a second M4 aggregate (the
dedicated `evals` job runs the full gate). These tests pin what a scoped gate
may and may not do: run only its suites, compare them with the reviewed
baseline, stay strict under `--require-exercised`, refuse an unknown or empty
selection, still catch an eval deleted from the repository -- and leave the
unscoped gate exactly as it was.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from direwolf_evals import baseline as baseline_module
from direwolf_evals import cli
from direwolf_evals.model import Status
from direwolf_evals.results import Result, RunReport
from direwolf_evals.runner import collect

EVALS_ROOT = Path(__file__).resolve().parents[1]
BASELINE = EVALS_ROOT / "baselines" / "main.json"
AUTHORITY = "authority-security"
PEER_EVAL = f"{AUTHORITY}/peer-credential-check"


def _result(eval_id: str, status: Status, reason: str = "") -> Result:
    return Result(
        eval_id=eval_id,
        suite=eval_id.split("/")[0],
        status=status,
        score=1.0 if status is Status.PASS else None,
        runs=1,
        run_index=0,
        duration_ms=0.0,
        seed=0,
        reason=reason,
    )


def _as_expected(suites: set[str], skipped: str | None = None) -> RunReport:
    """A run of `suites` meeting every baseline expectation, except that
    `skipped` was not exercised."""
    report = RunReport()
    for eval_id, expectation in sorted(baseline_module.Baseline.load(BASELINE).evals.items()):
        if eval_id.split("/")[0] not in suites:
            continue
        if eval_id == skipped:
            report.add(_result(eval_id, Status.SKIP, "not exercised: needs a second identity"))
            continue
        result = _result(eval_id, expectation.status, expectation.pending_reason or "")
        report.add(replace(result, score=expectation.min_score or result.score))
    return report


def _every_suite() -> set[str]:
    return {eval_id.split("/")[0] for eval_id in baseline_module.Baseline.load(BASELINE).evals}


class _Recorder:
    """A stand-in for `run_suites` that remembers how it was called."""

    def __init__(self, report: RunReport) -> None:
        self.report = report
        self.calls: list[dict[str, object]] = []

    def __call__(self, *_: object, **kwargs: object) -> RunReport:
        self.calls.append(kwargs)
        return self.report


def _check(argv: list[str], tmp_path: Path) -> int:
    return cli.main(["check", "--out", str(tmp_path / "results.jsonl"), *argv])


def test_a_scoped_gate_runs_only_its_suite_and_leaves_the_rest_of_the_baseline_out_of_scope(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    recorder = _Recorder(_as_expected({AUTHORITY}))
    monkeypatch.setattr(cli, "run_suites", recorder)
    assert _check(["--suite", AUTHORITY, "--require-exercised"], tmp_path) == 0
    assert [call["suites"] for call in recorder.calls] == [[AUTHORITY]]
    out = capsys.readouterr().out
    # The M4 suites' baseline entries were not run and are not "missing".
    assert "missing" not in out
    assert f"gate ok for {AUTHORITY}" in out


def test_a_scoped_gate_is_still_strict(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "run_suites", _Recorder(_as_expected({AUTHORITY}, PEER_EVAL)))
    assert _check(["--suite", AUTHORITY, "--require-exercised"], tmp_path) == 1
    captured = capsys.readouterr()
    assert f"{PEER_EVAL}: expected pass, got skip" in captured.out
    assert "the gate failed" in captured.err


def test_a_scoped_gate_still_compares_its_results_with_the_baseline(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    report = RunReport()
    for result in _as_expected({AUTHORITY}).results:
        failed = result.eval_id == PEER_EVAL
        report.add(replace(result, status=Status.FAIL, score=None) if failed else result)
    monkeypatch.setattr(cli, "run_suites", _Recorder(report))
    assert _check(["--suite", AUTHORITY, "--require-exercised"], tmp_path) == 1
    assert f"{PEER_EVAL}: expected pass, got fail" in capsys.readouterr().out


def test_an_unknown_suite_fails_loudly_and_runs_nothing(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    recorder = _Recorder(RunReport())
    monkeypatch.setattr(cli, "run_suites", recorder)
    assert _check(["--suite", "authority-securty", "--require-exercised"], tmp_path) == 2
    assert recorder.calls == []
    assert "no suite with id authority-securty" in capsys.readouterr().err


def test_a_selection_that_runs_nothing_is_never_green(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(cli, "run_suites", _Recorder(RunReport()))
    assert _check(["--suite", AUTHORITY, "--require-exercised"], tmp_path) == 2
    assert "ran no eval" in capsys.readouterr().err


@pytest.mark.parametrize("scoped", [True, False], ids=["scoped", "full"])
def test_an_eval_deleted_from_the_repository_is_still_missing(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    scoped: bool,
) -> None:
    """Deleting an eval must not be a way to make any gate green."""
    deleted = "m4-security/secret-boundary"
    report = _as_expected({AUTHORITY} if scoped else _every_suite())
    report = RunReport([r for r in report.results if r.eval_id != deleted])
    monkeypatch.setattr(cli, "run_suites", _Recorder(report))
    real_collect = collect
    monkeypatch.setattr(
        cli,
        "collect",
        lambda root, **kw: [(s, e) for s, e in real_collect(root, **kw) if e.id != deleted],
    )
    argv = ["--suite", AUTHORITY] if scoped else []
    assert _check([*argv, "--require-exercised"], tmp_path) == 1
    assert f"{deleted}: in the baseline but no longer exists" in capsys.readouterr().out


def test_the_unscoped_gate_is_unchanged(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    recorder = _Recorder(_as_expected(_every_suite()))
    monkeypatch.setattr(cli, "run_suites", recorder)
    assert _check(["--require-exercised"], tmp_path) == 0
    assert [call["suites"] for call in recorder.calls] == [[]]
    assert [call["gate_only"] for call in recorder.calls] == [True]
    out = capsys.readouterr().out
    assert "direwolf_evals: gate ok (" in out, "no scope in the unscoped gate's summary"
