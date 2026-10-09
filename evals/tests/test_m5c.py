"""M5c in the harness: the slice is available and M5 is not, the M5c eval
has a real runner, and the gate fails on each regression the runner exists to
catch.

The property itself is measured by the runner against the released broker,
local HTTPS origins and the authority's library (``make eval``, which runs
``make net-http-evidence``); these tests hand the judging function evidence
with one thing wrong, and require a failure every time.
"""

from __future__ import annotations

import json
from pathlib import Path

from direwolf_evals.inventory import INVENTORY
from direwolf_evals.model import Status
from direwolf_evals.runner import AVAILABLE_MILESTONES, collect
from direwolf_evals.runners import RUNNERS, m5c

EVALS_ROOT = Path(__file__).resolve().parents[1]
EVAL_ID = "m5c-net-http/kernel-performed-net-http"


def _line(**fields: object) -> str:
    return f"test x ... NET-EVIDENCE {json.dumps(fields)}"


def _outcome_for(suite: str, case: str) -> str:
    if suite == "net-http" and case.startswith(("ssrf-", "dns-resolution-")):
        return "ADDRESS_BLOCKED"
    if case == "credential-cross-origin-redirect":
        return "never-attached"
    if (suite, case) == m5c.ECHO_RESIDUE:
        return "absent-the-exchange-worker-is-gone"
    return "ok"


def _output(drop: tuple[str, str] | None = None, change: tuple[str, str, str] | None = None) -> str:
    lines = []
    for suite, case in sorted(m5c.M5C_CASES):
        if (suite, case) == drop:
            continue
        outcome = _outcome_for(suite, case)
        if change is not None and (suite, case) == change[:2]:
            outcome = change[2]
        lines.append(_line(suite=suite, case=case, outcome=outcome))
    return "\n".join(lines)


def test_m5c_is_available_and_m5_is_not() -> None:
    assert "M5c" in AVAILABLE_MILESTONES
    assert "M5" not in AVAILABLE_MILESTONES, "M5 is in progress, not complete"


def test_the_m5c_eval_gates_with_a_real_runner() -> None:
    _, evaluation = next((s, e) for s, e in collect(EVALS_ROOT) if e.id == EVAL_ID)
    assert evaluation.requires == ("M5c",)
    assert evaluation.gate
    assert evaluation.runner in RUNNERS
    assert evaluation.platforms == ("linux",)


def test_the_inventory_measures_the_m5c_property_in_its_own_suite() -> None:
    properties = [p for p in INVENTORY if p.milestone == "M5c"]
    assert [p.suite for p in properties] == ["m5c-net-http"]


def test_the_runner_requires_every_suite_and_more_than_a_hundred_cases() -> None:
    suites = {suite for suite, _ in m5c.M5C_CASES}
    assert suites == {
        "broker-http",
        "authority-net-pipeline",
        "authority-net-credential",
        "net-http",
    }
    assert len(m5c.M5C_CASES) > 100


def test_complete_evidence_passes() -> None:
    outcome = m5c.judge_net_http(_output(), 0)
    assert outcome.status is Status.PASS, outcome.reason
    assert outcome.metrics["rejection_rate"] == 1.0


def test_every_missing_case_fails() -> None:
    for case in sorted(m5c.M5C_CASES):
        outcome = m5c.judge_net_http(_output(drop=case), 0)
        assert outcome.status is Status.FAIL, case


def test_an_answered_ssrf_case_fails() -> None:
    ssrf = sorted(c for c in m5c.M5C_CASES if c[0] == "net-http" and c[1].startswith("ssrf-"))
    assert ssrf
    for suite, case in ssrf:
        outcome = m5c.judge_net_http(_output(change=(suite, case, "200-ok")), 0)
        assert outcome.status is Status.FAIL, case
        assert outcome.metrics["rejection_rate"] == 0.0, case


def test_a_credential_across_origins_fails() -> None:
    for suite, case in sorted(
        c for c in m5c.M5C_CASES if c[1] == "credential-cross-origin-redirect"
    ):
        outcome = m5c.judge_net_http(_output(change=(suite, case, "attached")), 0)
        assert outcome.status is Status.FAIL, suite


def test_any_broker_residue_fails() -> None:
    # The exchange worker (D11) leaves the long-lived broker nothing to hold:
    # a residue reported present -- even the old documented limitation -- fails.
    for present in ("PRESENT", "PRESENT-documented-limitation-response-library-buffers", "absent"):
        outcome = m5c.judge_net_http(_output(change=(*m5c.ECHO_RESIDUE, present)), 0)
        assert outcome.status is Status.FAIL, present


def test_a_failed_or_unexercised_task_fails_whatever_it_printed() -> None:
    outcome = m5c.judge_net_http(_output(), 1)
    assert outcome.status is Status.FAIL
    assert outcome.metrics["rejection_rate"] == 0.0
    not_exercised = "\n".join(
        _line(suite=s, case=c, outcome="not-exercised: no openssl") for s, c in m5c.M5C_CASES
    )
    assert m5c.judge_net_http(not_exercised, 0).status is Status.FAIL


def test_unreadable_evidence_is_an_error() -> None:
    outcome = m5c.judge_net_http("x NET-EVIDENCE {not json", 0)
    assert outcome.status is Status.ERROR
