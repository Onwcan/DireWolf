"""M5e.6's gate in the harness: the `m5e-gate` eval runs since `M5e` joined the
available milestones (2026-11-11), only in CI's `m5e-gate` job, and fails on
everything short of a complete inventory and a READY acceptance verdict; and
`pending-kernel/sandbox-egress`, M5's own, reads the same gate's judgement of
the egress and agent evidence.

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


def test_m5e_and_m5_are_available() -> None:
    assert "M5e" in AVAILABLE_MILESTONES
    assert "M5" in AVAILABLE_MILESTONES


def test_the_gate_eval_runs_with_a_real_runner_in_its_own_job_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("GITHUB_JOB", raising=False)
    [(suite, evaluation)] = [(s, e) for s, e in collect(EVALS_ROOT) if e.id == EVAL_ID]
    assert suite.gate is False and evaluation.gate is False
    assert evaluation.requires == ("M5e",)
    assert evaluation.runner == "m5e.gate" and RUNNERS["m5e.gate"] is m5e.gate
    assert evaluation.needs == ("m5e-gate-job",) and "m5e-gate-job" in NEEDS
    # Off its job it is NOT EXERCISED, never a pass and never pending.
    [result] = run_eval(suite, evaluation, repo_root=REPO_ROOT, evals_root=EVALS_ROOT)
    assert result.status is Status.SKIP
    assert result.reason.startswith(NOT_EXERCISED)
    expected = Baseline.load(BASELINE).evals[EVAL_ID]
    assert expected.status is Status.PASS
    assert expected.min_score == 1.0


EGRESS_ID = "pending-kernel/sandbox-egress"
JUDGED = (
    "  sandbox-egress-evidence: 123 case(s) judged again\n"
    "  sandbox-agent-evidence: 31 case(s) judged again\n"
)
AGENT_ONLY = "  sandbox-agent-evidence: 31 case(s) judged again\n"
EGRESS_ONLY = "  sandbox-egress-evidence: 123 case(s) judged again\n"


def test_m5s_egress_property_reads_the_gate_in_the_same_job() -> None:
    [(_, evaluation)] = [(s, e) for s, e in collect(EVALS_ROOT) if e.id == EGRESS_ID]
    assert evaluation.requires == ("M5",)
    assert evaluation.runner == "m5e.egress" and RUNNERS["m5e.egress"] is m5e.egress
    assert evaluation.needs == ("m5e-gate-job",)
    expected = Baseline.load(BASELINE).evals[EGRESS_ID]
    assert expected.status is Status.PASS and expected.min_score == 1.0


def test_the_egress_eval_passes_on_the_gates_judgement_of_both_tasks() -> None:
    outcome = m5e.judge_egress(f"{INVENTORY}\n{JUDGED}", 0)
    assert outcome.status is Status.PASS, outcome.reason
    assert outcome.metrics == {"inventory_complete": 1.0, "egress_cases_judged": 154.0}


@pytest.mark.parametrize(
    ("output", "code", "said"),
    [
        (f"{INVENTORY}\n{JUDGED}", 1, "the gate task failed (exit 1)"),
        (JUDGED, 0, "no complete inventory verdict"),
        (f"{INVENTORY}\n{AGENT_ONLY}", 0, "sandbox-egress"),
        (f"{INVENTORY}\n{EGRESS_ONLY}", 0, "sandbox-agent"),
        (f"{INVENTORY}\n" + JUDGED.replace("123", "0"), 0, "no case of sandbox-egress"),
        (
            f"{INVENTORY}\n" + JUDGED.replace("  sandbox-egress", "sandbox-egress"),
            0,
            "sandbox-egress",
        ),
    ],
)
def test_the_egress_eval_fails_without_both_tasks_judged_again(
    output: str, code: int, said: str
) -> None:
    outcome = m5e.judge_egress(output, code)
    assert outcome.status is Status.FAIL
    assert said in outcome.reason


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
