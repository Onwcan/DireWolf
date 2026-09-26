"""M4 in the harness: the milestone is available, every M4 eval has a real
runner, and the gate fails on each regression the runners exist to catch.

The properties themselves are measured by the runners against the real
resolver, broker, daemons and keyring (``make eval``); these tests hand the
judging functions evidence with one thing wrong, and hand the gate a failing
result, and require a failure every time.
"""

from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path

from direwolf_evals import baseline as baseline_module
from direwolf_evals.inventory import INVENTORY
from direwolf_evals.model import Eval, Status, Suite
from direwolf_evals.results import Result
from direwolf_evals.runner import AVAILABLE_MILESTONES, collect, run_eval
from direwolf_evals.runners import RUNNERS, m4

EVALS_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = EVALS_ROOT.parent
M4_EVALS = ("path-traversal", "exec-mediation", "secret-boundary")


def _m4(name: str) -> tuple[Suite, Eval]:
    return next((s, e) for s, e in collect(EVALS_ROOT) if e.id == f"m4-security/{name}")


def _line(prefix: str, **fields: object) -> str:
    return f"test x ... {prefix}{json.dumps(fields)}"


def _secret_output(drop: tuple[str, str] | None = None) -> str:
    return "\n".join(
        _line("SECRET-EVIDENCE ", suite=suite, case=case, outcome="ok", count=1)
        for suite, case in sorted(m4.SECRET_CASES)
        if (suite, case) != drop
    )


def _exec_output(drop: tuple[str, str] | None = None) -> str:
    return "\n".join(
        _line("PROC-EVIDENCE ", suite=suite, case=case, outcome="ok", count=1)
        for suite, case in sorted(m4.EXEC_CASES)
        if (suite, case) != drop
    )


def _traversal_output(race_outcome: str = "escaped-0-unexpected-0-raced-100") -> str:
    lines = [
        _line(
            "FS-EVIDENCE ", category=category, case=f"{category}-case", outcome="contained", count=1
        )
        for category in m4.TRAVERSAL_CATEGORIES
    ]
    lines += [
        _line("FS-EVIDENCE ", category="toctou", case=race, outcome=race_outcome, count=100)
        for race in m4.TRAVERSAL_RACES
    ]
    lines += [
        _line(
            "BROKER-EVIDENCE ", suite="broker-state", case=case, outcome="read-the-checked-object"
        )
        for case in sorted(m4.BROKERED_CASES)
    ]
    return "\n".join(lines)


# --- the milestone and its runners ------------------------------------------


def test_m4_is_available_and_every_m4_eval_has_a_registered_runner() -> None:
    assert "M4" in AVAILABLE_MILESTONES
    assert "M5" not in AVAILABLE_MILESTONES, "M5 is not implemented"
    for name in M4_EVALS:
        _, evaluation = _m4(name)
        assert evaluation.requires == ("M4",) or "M4" in evaluation.requires
        assert evaluation.runner in RUNNERS, f"{evaluation.id} has no real runner"
        assert evaluation.gate, f"{evaluation.id} must gate"
    # No M4 property is left pending anywhere.
    pending = [e.id for _, e in collect(EVALS_ROOT) if "M4" in e.requires and e.runner is None]
    assert pending == []


def test_the_inventory_measures_every_m4_property_in_the_m4_suite() -> None:
    m4_properties = [p for p in INVENTORY if p.milestone == "M4"]
    assert len(m4_properties) == 3
    assert {p.suite for p in m4_properties} == {"m4-security"}


def test_an_m4_eval_without_a_runner_is_an_error_not_a_pass() -> None:
    suite, evaluation = _m4("secret-boundary")
    orphan = replace(evaluation, runner=None)
    results = run_eval(suite, orphan, repo_root=REPO_ROOT, evals_root=EVALS_ROOT)
    assert [r.status for r in results] == [Status.ERROR]
    assert "no runner" in results[0].reason


def test_a_bad_m4_result_fails_the_gate_against_the_reviewed_baseline() -> None:
    reviewed = baseline_module.Baseline.load(EVALS_ROOT / "baselines" / "main.json")
    for name in M4_EVALS:
        eval_id = f"m4-security/{name}"
        failing = Result(
            eval_id=eval_id,
            suite="m4-security",
            status=Status.FAIL,
            score=0.5,
            runs=1,
            run_index=0,
            duration_ms=0.0,
            seed=0,
            reason="a planted regression",
        )
        comparison = baseline_module.compare(reviewed, [failing], known_ids={eval_id})
        assert not comparison.ok, f"{eval_id}: a failing result must fail the gate"
        assert comparison.regressions


# --- each regression the runners exist to catch -------------------------------


def test_the_judges_pass_complete_evidence() -> None:
    assert m4.judge_secret(_secret_output(), corpus_passed=True).status is Status.PASS
    assert m4.judge_exec(_exec_output()).status is Status.PASS
    assert m4.judge_traversal(_traversal_output()).status is Status.PASS


def test_a_secret_boundary_regression_fails() -> None:
    # The runtime's address space was not shown clean.
    outcome = m4.judge_secret(
        _secret_output(drop=("authority-secret", "runtime-address-space")), corpus_passed=True
    )
    assert outcome.status is Status.FAIL
    assert "runtime-address-space" in outcome.reason
    # A value field appeared in the public protocol.
    assert m4.judge_secret(_secret_output(), corpus_passed=False).status is Status.FAIL
    # A case that says it was not exercised is not evidence.
    not_exercised = _secret_output().replace(
        '"case": "mode-a-one-shot", "outcome": "ok"',
        '"case": "mode-a-one-shot", "outcome": "not-exercised: no keyring"',
    )
    assert m4.judge_secret(not_exercised, corpus_passed=True).status is Status.FAIL


def test_a_traversal_regression_fails() -> None:
    escaped = m4.judge_traversal(_traversal_output("escaped-1-unexpected-0-raced-100"))
    assert escaped.status is Status.FAIL
    assert escaped.metrics["escapes"] == float(len(m4.TRAVERSAL_RACES))
    missing_category = "\n".join(
        line for line in _traversal_output().splitlines() if '"category": "symlink"' not in line
    )
    assert m4.judge_traversal(missing_category).status is Status.FAIL


def test_an_exec_mediation_regression_fails() -> None:
    outcome = m4.judge_exec(_exec_output(drop=("broker-process", "env-built-from-nothing")))
    assert outcome.status is Status.FAIL
    assert "env-built-from-nothing" in outcome.reason


def test_an_unreadable_evidence_line_is_an_error() -> None:
    assert m4.judge_secret("SECRET-EVIDENCE {not json", corpus_passed=True).status is Status.ERROR
