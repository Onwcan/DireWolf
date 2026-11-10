"""M5e.6's gate in the harness: the `m5e-gate` eval exists, is pending until
`M5e` is available, runs only in CI's `m5e-gate` job, and fails on everything
short of a complete inventory and a READY acceptance verdict.

The gate itself is `scripts/dw.py m5e-gate-check`, judged against synthetic
bundles by `tests/architecture/test_ci_m5e_gate.py`. These tests hand the
runner's judging function each verdict the task can print and require a
failure for every one but the last.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from direwolf_evals.baseline import Baseline
from direwolf_evals.model import Status
from direwolf_evals.preconditions import NEEDS, NOT_EXERCISED, m5e_gate_job, unmet
from direwolf_evals.runner import AVAILABLE_MILESTONES, collect, run_eval
from direwolf_evals.runners import RUNNERS, m5e

EVALS_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = EVALS_ROOT.parent
EVAL_ID = "m5e-gate/integrated-m5-gate"
BASELINE = EVALS_ROOT / "baselines" / "main.json"

INVENTORY = (
    "\x1b[32mM5 gate: inventory verdict: COMPLETE: 13 bundles of run 1 attempt 1 at "
    "0123456789ab, each from its job on a GitHub-hosted runner, judged again\x1b[0m"
)
READY = "\x1b[32mM5e acceptance verdict: READY\x1b[0m"
NOT_READY = (
    "\x1b[1mM5e acceptance verdict: NOT READY\x1b[0m (2 blocker(s); enforced by the "
    "m5e-gate eval once M5e is available)\n  - ADR-0054 is Proposed, not Accepted"
)


def test_m5e_and_m5_are_not_available() -> None:
    assert "M5e" not in AVAILABLE_MILESTONES
    assert "M5" not in AVAILABLE_MILESTONES


def test_the_gate_eval_is_pending_with_a_real_runner_and_its_own_job() -> None:
    [(suite, evaluation)] = [(s, e) for s, e in collect(EVALS_ROOT) if e.id == EVAL_ID]
    assert suite.gate is False and evaluation.gate is False
    assert evaluation.requires == ("M5e",)
    assert evaluation.runner == "m5e.gate" and RUNNERS["m5e.gate"] is m5e.gate
    assert evaluation.needs == ("m5e-gate-job",) and "m5e-gate-job" in NEEDS
    [result] = run_eval(suite, evaluation, repo_root=REPO_ROOT, evals_root=EVALS_ROOT)
    assert result.status is Status.PENDING
    assert result.reason.startswith("requires M5e: ")
    expected = Baseline.load(BASELINE).evals[EVAL_ID]
    assert expected.status is Status.PENDING
    assert expected.pending_reason == result.reason


def test_the_gate_job_is_the_only_place_it_is_exercised(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("GITHUB_ACTIONS", "RUNNER_ENVIRONMENT", "GITHUB_JOB"):
        monkeypatch.delenv(name, raising=False)
    assert not m5e_gate_job()
    reason = unmet(("linux",), ("m5e-gate-job",))
    assert reason is not None and reason.startswith(NOT_EXERCISED)
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("RUNNER_ENVIRONMENT", "github-hosted")
    monkeypatch.setenv("GITHUB_JOB", "evals")
    assert not m5e_gate_job()
    monkeypatch.setenv("GITHUB_JOB", "m5e-gate")
    assert m5e_gate_job()
    monkeypatch.setenv("RUNNER_ENVIRONMENT", "self-hosted")
    assert not m5e_gate_job()


def test_a_complete_inventory_and_a_ready_verdict_pass() -> None:
    outcome = m5e.judge_gate(f"{INVENTORY}\n{READY}\n", 0)
    assert outcome.status is Status.PASS, outcome.reason
    assert outcome.metrics == {"inventory_complete": 1.0, "acceptance_ready": 1.0}


@pytest.mark.parametrize(
    ("output", "code", "said"),
    [
        (f"{INVENTORY}\n{NOT_READY}\n", 0, "not READY"),
        (f"{READY}\n", 0, "no complete inventory verdict"),
        (f"{INVENTORY}\n{READY}\n", 1, "the gate task failed (exit 1)"),
        ("dw: NOT EXERCISED: the M5 gate judges only the bundles of a run\n", 1, "exit 1"),
        (f"{INVENTORY}\nM5e acceptance verdict: READY, almost\n", 0, "not READY"),
        (f"{INVENTORY}\n{READY}\n{NOT_READY}\n", 0, "not READY"),
        ("", 0, "no complete inventory verdict"),
    ],
)
def test_anything_short_of_ready_fails(output: str, code: int, said: str) -> None:
    outcome = m5e.judge_gate(output, code)
    assert outcome.status is Status.FAIL
    assert said in outcome.reason
