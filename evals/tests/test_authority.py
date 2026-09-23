"""M3 in the harness: preconditions, the strict gate, and runners that cannot
pass without the product.

The real-process properties themselves are measured by ``make eval`` against
the built binary; these tests check that the harness can neither turn "not
exercised" into a pass nor accept evidence that no real server produced.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from dataclasses import replace
from pathlib import Path

import pytest

from direwolf_evals import baseline as baseline_module
from direwolf_evals import cli, preconditions
from direwolf_evals.discovery import DiscoveryError, discover
from direwolf_evals.model import Eval, Status, Suite
from direwolf_evals.results import Result, RunReport
from direwolf_evals.runner import collect, not_exercised, run_eval
from direwolf_evals.runners import authority

EVALS_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = EVALS_ROOT.parent


def _authority(name: str) -> tuple[Suite, Eval]:
    return next((s, e) for s, e in collect(EVALS_ROOT) if e.id == f"authority-security/{name}")


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


# --- preconditions ---------------------------------------------------------


def test_a_platform_bound_eval_is_not_exercised_elsewhere_and_never_passes() -> None:
    suite, evaluation = _authority("hostile-dwkp-client")
    elsewhere = sorted(preconditions.PLATFORMS - {preconditions.current_platform()})[0]
    moved = replace(evaluation, platforms=(elsewhere,))
    results = run_eval(suite, moved, repo_root=REPO_ROOT, evals_root=EVALS_ROOT)
    assert [r.status for r in results] == [Status.SKIP]
    assert results[0].reason.startswith("not exercised: runs on")
    assert results[0].score is None


def test_a_missing_second_identity_is_not_exercised(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(preconditions.PEER_ENV, raising=False)
    preconditions.second_identity.cache_clear()
    try:
        suite, evaluation = _authority("peer-credential-check")
        linux_only = replace(evaluation, platforms=())
        results = run_eval(suite, linux_only, repo_root=REPO_ROOT, evals_root=EVALS_ROOT)
        assert [r.status for r in results] == [Status.SKIP]
        assert "second operating-system identity" in results[0].reason
    finally:
        preconditions.second_identity.cache_clear()


class _Switched:
    """What `sudo -n -u <user> id -u` returned, for the probe below."""

    def __init__(self, returncode: int, stdout: str) -> None:
        self.returncode = returncode
        self.stdout = stdout


@pytest.mark.parametrize(
    ("switched", "own_uid", "expected"),
    [
        (_Switched(0, "65534\n"), 1001, "nobody"),  # a second, ordinary identity
        (_Switched(0, "1001\n"), 1001, None),  # the same uid under another name
        (_Switched(0, "0\n"), 1001, None),  # root: outside the threat model
        (_Switched(1, ""), 1001, None),  # sudo could not switch
        (_Switched(0, "nobody\n"), 1001, None),  # not a number: not evidence
    ],
    ids=["second-uid", "same-uid", "root", "sudo-refused", "unreadable"],
)
def test_a_second_identity_is_proven_by_its_numeric_uid(
    monkeypatch: pytest.MonkeyPatch,
    switched: _Switched,
    own_uid: int,
    expected: str | None,
) -> None:
    """A name is not a second identity; a process reporting a uid that is
    neither ours nor root's is. Anything else leaves the eval not exercised,
    which the strict gate fails."""
    monkeypatch.setenv(preconditions.PEER_ENV, "nobody")
    monkeypatch.setattr(preconditions, "current_platform", lambda: "linux")
    monkeypatch.setattr(shutil, "which", lambda _: "/usr/bin/sudo")
    monkeypatch.setattr(os, "geteuid", lambda: own_uid, raising=False)
    calls: list[list[str]] = []

    def fake_run(command: list[str], **_: object) -> _Switched:
        calls.append(command)
        return switched

    monkeypatch.setattr(subprocess, "run", fake_run)
    preconditions.second_identity.cache_clear()
    try:
        assert preconditions.second_identity() == expected
        assert calls == [["sudo", "-n", "-u", "nobody", "id", "-u"]]
    finally:
        preconditions.second_identity.cache_clear()


def test_an_unknown_platform_or_need_is_a_configuration_error(tmp_path: Path) -> None:
    (tmp_path / "suites").mkdir()
    for key, value in (("platforms", '["Linux"]'), ("needs", '["second_identity"]')):
        (tmp_path / "suites" / "bad.toml").write_text(
            'id = "bad"\ntitle = "t"\ndescription = "d"\nscore = "s"\n'
            f'[[eval]]\nname = "e"\ndescription = "d"\nrunner = "harness.crash"\n{key} = {value}\n',
            encoding="utf-8",
        )
        with pytest.raises(DiscoveryError, match=f"unknown {key}"):
            discover(tmp_path)


# --- the strict gate ---------------------------------------------------------


def _baseline(tmp_path: Path, eval_id: str) -> baseline_module.Baseline:
    path = tmp_path / "baseline.json"
    baseline_module.write(path, [_result(eval_id, Status.PASS)])
    return baseline_module.Baseline.load(path)


def test_the_strict_gate_fails_a_gating_eval_it_could_not_exercise(tmp_path: Path) -> None:
    eval_id = "authority-security/peer-credential-check"
    skipped = [_result(eval_id, Status.SKIP, "not exercised: needs a second identity")]
    strict = baseline_module.compare(_baseline(tmp_path, eval_id), skipped, {eval_id})
    assert not strict.ok
    assert strict.regressions


def test_a_lenient_gate_lists_what_it_could_not_exercise_and_never_passes_it(
    tmp_path: Path,
) -> None:
    eval_id = "authority-security/peer-credential-check"
    skipped = [_result(eval_id, Status.SKIP, "not exercised: needs a second identity")]
    lenient = baseline_module.compare(
        _baseline(tmp_path, eval_id), skipped, {eval_id}, frozenset({eval_id})
    )
    assert lenient.ok
    assert lenient.not_exercised and eval_id in lenient.not_exercised[0]
    assert "NOT EXERCISED" in baseline_module.render(lenient)
    # Leniency is only for a SKIP: a failure is a failure wherever it runs.
    failed = [_result(eval_id, Status.FAIL, "a foreign uid was served")]
    assert not baseline_module.compare(
        _baseline(tmp_path, eval_id), failed, {eval_id}, frozenset({eval_id})
    ).ok


PEER_EVAL = "authority-security/peer-credential-check"


def _as_the_baseline_expects(skipped: str) -> RunReport:
    """A run that meets every expectation in the real baseline, except that
    `skipped` was not exercised on this machine."""
    report = RunReport()
    expected = baseline_module.Baseline.load(EVALS_ROOT / "baselines" / "main.json").evals
    for eval_id, expectation in sorted(expected.items()):
        if eval_id == skipped:
            report.add(_result(eval_id, Status.SKIP, "not exercised: needs a second identity"))
            continue
        result = _result(eval_id, expectation.status, expectation.pending_reason or "")
        report.add(replace(result, score=expectation.min_score or result.score))
    return report


def test_the_baseline_expects_the_peer_eval_to_pass_and_that_is_not_a_pass() -> None:
    """The baseline states what the accepted build must produce, not what
    happened: "pass" for the cross-uid eval, which a one-user machine cannot
    run. The observed status is what the gate compares."""
    expected = baseline_module.Baseline.load(EVALS_ROOT / "baselines" / "main.json").evals
    assert expected[PEER_EVAL].status is Status.PASS
    report = _as_the_baseline_expects(PEER_EVAL)
    assert report.counts()["skip"] == 1
    assert [r.status for r in report.results if r.eval_id == PEER_EVAL] == [Status.SKIP]


@pytest.mark.parametrize("strict", [True, False], ids=["strict", "lenient"])
def test_the_gate_command_never_turns_a_skip_into_a_pass(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
    strict: bool,
) -> None:
    """End to end through `direwolf_evals check`, against the real baseline,
    which expects PASS: the peer eval SKIPPED fails the strict gate (CI's),
    and the lenient gate (a workstation's) reports it NOT EXERCISED -- counted
    as skipped, never as passed."""
    monkeypatch.setattr(cli, "run_suites", lambda *_, **__: _as_the_baseline_expects(PEER_EVAL))
    monkeypatch.setattr(cli, "not_exercised", lambda _: frozenset({PEER_EVAL}))
    argv = ["check", "--out", str(tmp_path / "results.jsonl")]
    if strict:
        argv.append("--require-exercised")
    status = cli.main(argv)
    out = capsys.readouterr()
    if strict:
        assert status == 1
        assert f"{PEER_EVAL}: expected pass, got skip" in out.out
        assert "the gate failed" in out.err
    else:
        assert status == 0
        assert "NOT EXERCISED on this machine" in out.out
        counts = _as_the_baseline_expects(PEER_EVAL).counts()
        assert (
            f"gate ok ({counts['pass']} passed, {counts['pending']} pending, "
            f"{counts['skip']} skipped, 1 not exercised here)"
        ) in out.out
        assert counts["pass"] == sum(
            1
            for r in _as_the_baseline_expects(PEER_EVAL).results
            if r.status is Status.PASS and r.eval_id != PEER_EVAL
        ), "the skipped eval is not among the passes"


def test_what_this_machine_cannot_exercise_is_computed_from_declarations() -> None:
    cannot = not_exercised(EVALS_ROOT)
    if preconditions.current_platform() != "linux":
        assert "authority-security/hostile-dwkp-client" in cannot
    assert "authority-security/capability-attenuation" not in cannot
    assert "authority-security/policy-denies-by-default" not in cannot


# --- evidence ----------------------------------------------------------------


def _line(case: str, layer: str = "decoder", server: str | None = None) -> str:
    server_field = f',"server":"{server}"' if server is not None else ""
    return (
        f'DWKP-EVIDENCE {{"suite":"hostile","case":"{case}","layer":"{layer}",'
        f'"contained":true,"audited":true{server_field}}}'
    )


def test_evidence_interleaved_after_a_test_name_is_still_read() -> None:
    """libtest, with `--nocapture` and parallel tests, may print "test x ... "
    just before a case's line; losing that case would read as a missing case."""
    parsed = authority.parse_evidence("test linux::cases ... " + _line("interleaved"))
    assert [e.case for e in parsed] == ["interleaved"]


def test_evidence_with_an_unknown_layer_is_unreadable_not_ignored() -> None:
    with pytest.raises(ValueError, match="unknown containment layer"):
        authority.parse_evidence(_line("x", layer="somewhere"))


def test_a_runner_cannot_pass_without_a_real_server_binary(tmp_path: Path) -> None:
    every = "\n".join(_line(case) for case in sorted(authority.HOSTILE_CASES))
    no_server = authority._transport(
        authority._Cargo(0, every), authority.HOSTILE_CASES, {"hostile"}
    )
    assert no_server.status is Status.FAIL
    assert "named the server" in no_server.reason

    impostor = tmp_path / "not-the-authority"
    impostor.write_text("", encoding="utf-8")
    faked = "\n".join(_line(c, server=str(impostor)) for c in sorted(authority.HOSTILE_CASES))
    judged = authority._transport(authority._Cargo(0, faked), authority.HOSTILE_CASES, {"hostile"})
    assert judged.status is Status.FAIL
    assert "not the built binary" in judged.reason


def test_a_case_that_stopped_running_is_a_failure_not_a_smaller_denominator(
    tmp_path: Path,
) -> None:
    server = tmp_path / "dwkd-authority"
    server.write_text("", encoding="utf-8")
    cases = sorted(authority.HOSTILE_CASES)
    partial = "\n".join(_line(c, server=str(server)) for c in cases[1:])
    judged = authority._transport(
        authority._Cargo(0, partial), authority.HOSTILE_CASES, {"hostile"}
    )
    assert judged.status is Status.FAIL
    assert cases[0] in judged.reason


def test_an_uncontained_case_fails_the_eval(tmp_path: Path) -> None:
    server = tmp_path / "dwkd-authority"
    server.write_text("", encoding="utf-8")
    lines = [_line(c, server=str(server)) for c in sorted(authority.HOSTILE_CASES)]
    lines[0] = lines[0].replace('"contained":true', '"contained":false')
    judged = authority._transport(
        authority._Cargo(0, "\n".join(lines)), authority.HOSTILE_CASES, {"hostile"}
    )
    assert judged.status is Status.FAIL
    assert "NOT CONTAINED" in judged.reason


# --- the product ---------------------------------------------------------------


@pytest.mark.slow
@pytest.mark.skipif(
    not sys.platform.startswith("linux") or shutil.which("cargo") is None,
    reason="the DWKP server exists only on Linux, and this builds it",
)
def test_the_hostile_client_eval_measures_the_real_binary() -> None:
    """Against the product: the runner launches the real authority through the
    Rust real-process suites, and every expected case comes back contained."""
    suite, evaluation = _authority("hostile-dwkp-client")
    results = run_eval(suite, evaluation, repo_root=REPO_ROOT, evals_root=EVALS_ROOT)
    assert [r.status for r in results] == [Status.PASS], results[0].reason
    metrics = results[0].metrics
    assert metrics["cases"] == len(authority.HOSTILE_CASES)
    assert metrics["server_binaries"] >= 1
    assert metrics["layer_decoder"] > 0 and metrics["layer_state_fence"] > 0
    assert results[0].score == 1.0
