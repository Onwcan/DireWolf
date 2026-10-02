"""M5a in the harness: the sub-milestone is available and M5 is not, the M5a
eval has a real runner, and the gate fails on each regression the runner
exists to catch.

The property itself is measured by the runner against a real OCI runtime, the
released broker and the real authority (``make eval``, which runs
``make sandbox-foundation-evidence``); these tests hand the judging function
evidence with one thing wrong, and require a failure every time.
"""

from __future__ import annotations

import json
from pathlib import Path

from direwolf_evals.inventory import INVENTORY
from direwolf_evals.model import Status
from direwolf_evals.preconditions import NEEDS
from direwolf_evals.runner import AVAILABLE_MILESTONES, collect
from direwolf_evals.runners import RUNNERS, m5a

EVALS_ROOT = Path(__file__).resolve().parents[1]
EVAL_ID = "m5a-sandbox-foundation/oci-strict-measured-assurance"


def _line(**fields: object) -> str:
    return f"test x ... SANDBOX-EVIDENCE {json.dumps(fields)}"


def _output(drop: tuple[str, str] | None = None, weakened: str = "detected-14-of-14") -> str:
    lines = [
        _line(suite=suite, case=case, outcome="ok")
        for suite, case in sorted(m5a.M5A_CASES)
        if (suite, case) != drop and case != "weakened-count"
    ]
    if drop != ("sandbox-broker", "weakened-count"):
        lines.append(_line(suite="sandbox-broker", case="weakened-count", outcome=weakened))
    return "\n".join(lines)


def test_m5a_is_available_and_m5_is_not() -> None:
    assert "M5a" in AVAILABLE_MILESTONES
    assert "M5" not in AVAILABLE_MILESTONES, "M5 is in progress, not complete"
    # Every eval waiting for the whole of M5 is still pending: it names no
    # runner and is not turned on by the slice.
    for _, evaluation in collect(EVALS_ROOT):
        if "M5" in evaluation.requires:
            assert evaluation.runner is None, evaluation.id


def test_the_m5a_eval_gates_with_a_real_runner_and_a_real_runtime() -> None:
    _, evaluation = next((s, e) for s, e in collect(EVALS_ROOT) if e.id == EVAL_ID)
    assert evaluation.requires == ("M5a",)
    assert evaluation.gate
    assert evaluation.runner in RUNNERS
    assert "oci-runtime" in evaluation.needs
    assert "oci-runtime" in NEEDS
    assert evaluation.platforms == ("linux",)


def test_the_inventory_measures_the_m5a_property_in_its_own_suite() -> None:
    properties = [p for p in INVENTORY if p.milestone == "M5a"]
    assert [p.suite for p in properties] == ["m5a-sandbox-foundation"]
    # PROXY_ONLY egress is M5's, and still pending.
    assert any(p.milestone == "M5" and p.suite is None for p in INVENTORY)


def test_complete_evidence_passes() -> None:
    outcome = m5a.judge_sandbox(_output(), 0)
    assert outcome.status is Status.PASS, outcome.reason
    assert outcome.metrics["rejection_rate"] == 1.0


def test_every_missing_case_fails() -> None:
    for case in sorted(m5a.M5A_CASES):
        outcome = m5a.judge_sandbox(_output(drop=case), 0)
        assert outcome.status is Status.FAIL, case
        assert outcome.metrics["rejection_rate"] < 1.0 or case[1] == "weakened-count", case


def test_an_undetected_weakening_fails() -> None:
    outcome = m5a.judge_sandbox(_output(weakened="detected-13-of-14"), 0)
    assert outcome.status is Status.FAIL
    assert outcome.metrics["rejection_rate"] == 0.0


def test_a_failed_or_unexercised_task_fails_whatever_it_printed() -> None:
    outcome = m5a.judge_sandbox(_output(), 1)
    assert outcome.status is Status.FAIL
    assert outcome.metrics["rejection_rate"] == 0.0
    not_exercised = "\n".join(
        _line(suite=s, case=c, outcome="not-exercised: no runtime") for s, c in m5a.M5A_CASES
    )
    assert m5a.judge_sandbox(not_exercised, 0).status is Status.FAIL


def test_unreadable_evidence_is_an_error() -> None:
    outcome = m5a.judge_sandbox("x SANDBOX-EVIDENCE {not json", 0)
    assert outcome.status is Status.ERROR
