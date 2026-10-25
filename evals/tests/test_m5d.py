"""M5d in the harness: the slice is available and M5 is not, the M5d eval has
a real runner gated on a real runtime, and the gate fails on each regression
the runner exists to catch.

The property itself is measured by the runner against a real OCI runtime, the
released broker, the real authority and a real DWKP client (``make eval``,
which runs ``make sandbox-release-evidence``); these tests hand the judging
function evidence with one thing wrong -- a case missing, falsified, measured
at another level, unexercised, unattributed, or a task that failed -- and
require a failure every time.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from direwolf_evals.baseline import Baseline
from direwolf_evals.inventory import INVENTORY
from direwolf_evals.model import Status
from direwolf_evals.preconditions import NEEDS
from direwolf_evals.runner import AVAILABLE_MILESTONES, collect
from direwolf_evals.runners import RUNNERS, m5d

EVALS_ROOT = Path(__file__).resolve().parents[1]
EVAL_ID = "m5d-sandbox-exec/sandboxed-exec-and-release-teardown"
BASELINE = EVALS_ROOT / "baselines" / "main.json"


def _outcome(expected: str) -> str:
    """An outcome that agrees with `expected`."""
    if expected.startswith("re:"):
        return "CLOSED=1,TARGET_NOT_GRANTED=2"
    return expected


def _line(suite: str, case: str, outcome: str, level: str, enforcement: str = "guard") -> str:
    record = {
        "suite": suite,
        "case": case,
        "outcome": outcome,
        "level": level,
        "enforcement": enforcement,
    }
    return f"test x ... SANDBOX-EVIDENCE {json.dumps(record)}"


def _output(**override: tuple[str, str, str, str] | None) -> str:
    """Every expected case, as the task prints it; `override` replaces the
    line of `suite/case` with (suite, case, outcome, level) -- or drops it."""
    lines = []
    for (suite, case), (level, expected) in sorted(m5d.EXPECTED.items()):
        key = f"{suite}/{case}"
        if key in override:
            replaced = override[key]
            if replaced is None:
                continue
            lines.append(_line(*replaced))
            continue
        lines.append(_line(suite, case, _outcome(expected), level))
    return "\n".join(lines)


def test_m5d_is_available_and_m5_is_not() -> None:
    assert "M5d" in AVAILABLE_MILESTONES
    assert "M5" not in AVAILABLE_MILESTONES, "M5 is M5e's to complete"
    for _, evaluation in collect(EVALS_ROOT):
        if "M5" in evaluation.requires:
            assert evaluation.runner is None, evaluation.id


def test_the_complete_m5_egress_property_stays_pending() -> None:
    _, evaluation = next(
        (s, e) for s, e in collect(EVALS_ROOT) if e.id == "pending-kernel/sandbox-egress"
    )
    assert evaluation.requires == ("M5",)
    assert evaluation.runner is None
    assert Baseline.load(BASELINE).evals[evaluation.id].status is Status.PENDING


def test_the_m5d_eval_gates_with_a_real_runner_and_a_real_runtime() -> None:
    _, evaluation = next((s, e) for s, e in collect(EVALS_ROOT) if e.id == EVAL_ID)
    assert evaluation.requires == ("M5d",)
    assert evaluation.gate
    assert RUNNERS[evaluation.runner or ""] is m5d.sandbox_exec
    assert "oci-runtime" in evaluation.needs
    assert "oci-runtime" in NEEDS
    assert evaluation.platforms == ("linux",)
    expected = Baseline.load(BASELINE).evals[EVAL_ID]
    assert expected.status is Status.PASS
    assert expected.min_score == 1.0


def test_the_inventory_measures_the_m5d_property_in_its_own_suite() -> None:
    properties = [p for p in INVENTORY if p.milestone == "M5d"]
    assert [p.suite for p in properties] == ["m5d-sandbox-exec"]
    assert any(p.milestone == "M5" and p.suite is None for p in INVENTORY)


def test_complete_evidence_passes() -> None:
    outcome = m5d.judge_sandbox_exec(_output(), 0)
    assert outcome.status is Status.PASS, outcome.reason
    assert outcome.metrics["rejection_rate"] == 1.0
    assert outcome.metrics["cases"] == float(len(m5d.M5D_CASES))


@pytest.mark.parametrize("key", sorted(f"{s}/{c}" for s, c in m5d.M5D_CASES))
def test_every_missing_case_fails(key: str) -> None:
    outcome = m5d.judge_sandbox_exec(_output(**{key: None}), 0)
    assert outcome.status is Status.FAIL, key
    assert key in outcome.reason
    assert outcome.metrics["rejection_rate"] == 0.0


@pytest.mark.parametrize(
    ("case", "falsified"),
    [
        # A teardown that did not happen.
        ("release-over-dwkp-destroys-the-environment", "container-kept"),
        ("release-ends-in-flight-workload-and-descendants", "container-kept"),
        # A false destruction success.
        ("release-broker-lost-destruction-pending", "DESTROYED"),
        # A replay after the release or a crash.
        ("release-in-flight-workload-never-rerun", "ran"),
        ("release-crash-u-never-rerun", "ran-again"),
        # A refusal accepted: a stale epoch or another holder ends it.
        ("release-stale-epoch-refused-nothing-destroyed", "ACK"),
        ("release-other-holder-refused-nothing-destroyed", "container-removed"),
        # A released run that can still execute.
        ("released-run-launch-refused-over-dwkp", "residue-pass"),
        # Something foreign destroyed.
        ("release-spares-foreign-containers", "decoy-removed"),
        ("release-spares-another-runs-environment", "container-removed"),
        # A PROXY_ONLY destruction that recorded no refused tunnel.
        ("release-destruction-records-the-egress-by-disposition", "CLOSED=1"),
    ],
)
def test_an_outcome_contradicting_the_expected_fails(case: str, falsified: str) -> None:
    level, _ = m5d.EXPECTED[("sandbox-release", case)]
    key = f"sandbox-release/{case}"
    outcome = m5d.judge_sandbox_exec(
        _output(**{key: ("sandbox-release", case, falsified, level)}), 0
    )
    assert outcome.status is Status.FAIL, case
    assert "contradicting" in outcome.reason
    assert outcome.metrics["rejection_rate"] == 0.0


def test_a_fake_brokers_line_is_never_a_real_containers_end() -> None:
    for case in (
        "release-over-dwkp-destroys-the-environment",
        "release-ends-in-flight-workload-and-descendants",
        "release-crash-k-completed-at-restart",
    ):
        level, expected = m5d.EXPECTED[("sandbox-release", case)]
        key = f"sandbox-release/{case}"
        for other in {"fake-broker", "real-oci", "dwkp-end-to-end"} - {level}:
            outcome = m5d.judge_sandbox_exec(
                _output(**{key: ("sandbox-release", case, expected, other)}), 0
            )
            assert outcome.status is Status.FAIL, (case, other)
            assert "wrong level" in outcome.reason


def test_an_unexercised_case_is_never_counted() -> None:
    key = "sandbox-release/release-in-flight-workload-settled-unknown"
    outcome = m5d.judge_sandbox_exec(
        _output(
            **{
                key: (
                    "sandbox-release",
                    "release-in-flight-workload-settled-unknown",
                    "not-exercised: no runtime",
                    "real-oci",
                )
            }
        ),
        0,
    )
    assert outcome.status is Status.FAIL
    assert key in outcome.reason


def test_a_case_naming_no_enforcement_fails() -> None:
    case = "release-audited"
    level, expected = m5d.EXPECTED[("sandbox-release", case)]
    output = _output().replace(
        _line("sandbox-release", case, expected, level),
        _line("sandbox-release", case, expected, level, enforcement=""),
    )
    outcome = m5d.judge_sandbox_exec(output, 0)
    assert outcome.status is Status.FAIL
    assert "no enforcement" in outcome.reason


def test_a_failed_or_unexercised_task_fails_whatever_it_printed() -> None:
    outcome = m5d.judge_sandbox_exec(_output(), 1)
    assert outcome.status is Status.FAIL
    assert outcome.metrics["rejection_rate"] == 0.0
    not_exercised = "\n".join(
        _line(s, c, "not-exercised: no runtime", level)
        for (s, c), (level, _) in m5d.EXPECTED.items()
    )
    assert m5d.judge_sandbox_exec(not_exercised, 0).status is Status.FAIL
    assert m5d.judge_sandbox_exec("", 0).status is Status.FAIL


def test_unreadable_evidence_is_an_error() -> None:
    outcome = m5d.judge_sandbox_exec("x SANDBOX-EVIDENCE {not json", 0)
    assert outcome.status is Status.ERROR
