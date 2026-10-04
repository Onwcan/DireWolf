"""M5b in the harness: the slice is available and M5 is not, the M5b eval
has a real runner, and the gate fails on each regression the runner exists to
catch.

The property itself is measured by the runner against a real OCI runtime, the
released broker, the real relay and the real authority (``make eval``, which
runs ``make sandbox-egress-evidence``); these tests hand the judging function
evidence with one thing wrong, and require a failure every time.
"""

from __future__ import annotations

import json
from pathlib import Path

from direwolf_evals.inventory import INVENTORY
from direwolf_evals.model import Status
from direwolf_evals.preconditions import NEEDS
from direwolf_evals.runner import AVAILABLE_MILESTONES, collect
from direwolf_evals.runners import RUNNERS, m5b

EVALS_ROOT = Path(__file__).resolve().parents[1]
EVAL_ID = "m5b-sandbox-egress/proxy-only-egress"


def _line(**fields: object) -> str:
    return f"test x ... SANDBOX-EVIDENCE {json.dumps(fields)}"


def _outcome_for(case: str) -> str:
    if case == "weakened-topology-count":
        return "detected-9-of-9"
    if (("sandbox-egress", case)) in m5b.BYPASS_CASES:
        return "errno=101 name=ENETUNREACH mechanism=topology-no-route"
    return "ok"


def _output(
    drop: tuple[str, str] | None = None,
    weakened: str = "detected-9-of-9",
    bypass: str | None = None,
) -> str:
    lines = []
    for suite, case in sorted(m5b.M5B_CASES):
        if (suite, case) == drop:
            continue
        outcome = _outcome_for(case)
        if case == "weakened-topology-count":
            outcome = weakened
        if case == bypass:
            outcome = "connected"
        lines.append(_line(suite=suite, case=case, outcome=outcome))
    return "\n".join(lines)


def test_m5b_is_available_and_m5_is_not() -> None:
    assert "M5b" in AVAILABLE_MILESTONES
    assert "M5" not in AVAILABLE_MILESTONES, "M5 is in progress, not complete"
    for _, evaluation in collect(EVALS_ROOT):
        if "M5" in evaluation.requires:
            assert evaluation.runner is None, evaluation.id


def test_the_m5b_eval_gates_with_a_real_runner_and_a_real_runtime() -> None:
    _, evaluation = next((s, e) for s, e in collect(EVALS_ROOT) if e.id == EVAL_ID)
    assert evaluation.requires == ("M5b",)
    assert evaluation.gate
    assert evaluation.runner in RUNNERS
    assert "oci-runtime" in evaluation.needs
    assert "oci-runtime" in NEEDS
    assert evaluation.platforms == ("linux",)


def test_the_inventory_measures_the_m5b_property_in_its_own_suite() -> None:
    properties = [p for p in INVENTORY if p.milestone == "M5b"]
    assert [p.suite for p in properties] == ["m5b-sandbox-egress"]
    # The end-to-end workload property is the whole of M5's, still pending.
    assert any(p.milestone == "M5" and p.suite is None for p in INVENTORY)


def test_complete_evidence_passes() -> None:
    outcome = m5b.judge_egress(_output(), 0)
    assert outcome.status is Status.PASS, outcome.reason
    assert outcome.metrics["rejection_rate"] == 1.0


def test_every_missing_case_fails() -> None:
    for case in sorted(m5b.M5B_CASES):
        outcome = m5b.judge_egress(_output(drop=case), 0)
        assert outcome.status is Status.FAIL, case


def test_an_undetected_weakening_fails() -> None:
    outcome = m5b.judge_egress(_output(weakened="detected-7-of-8"), 0)
    assert outcome.status is Status.FAIL
    assert outcome.metrics["rejection_rate"] == 0.0


def test_a_bypass_with_no_refusing_mechanism_fails() -> None:
    for _, case in sorted(m5b.BYPASS_CASES):
        outcome = m5b.judge_egress(_output(bypass=case), 0)
        assert outcome.status is Status.FAIL, case
        assert outcome.metrics["rejection_rate"] == 0.0, case


def test_a_failed_or_unexercised_task_fails_whatever_it_printed() -> None:
    outcome = m5b.judge_egress(_output(), 1)
    assert outcome.status is Status.FAIL
    assert outcome.metrics["rejection_rate"] == 0.0
    not_exercised = "\n".join(
        _line(suite=s, case=c, outcome="not-exercised: no runtime") for s, c in m5b.M5B_CASES
    )
    assert m5b.judge_egress(not_exercised, 0).status is Status.FAIL


def test_unreadable_evidence_is_an_error() -> None:
    outcome = m5b.judge_egress("x SANDBOX-EVIDENCE {not json", 0)
    assert outcome.status is Status.ERROR
