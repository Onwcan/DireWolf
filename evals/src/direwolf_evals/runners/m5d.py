"""M5d runner: production sandboxed process execution, measured as the product.

Like every runner since M3, this reimplements nothing. It runs the real
evidence task -- `scripts/dw.py sandbox-release-evidence`: the real authority
against the route tests' fake broker for its state machine, then the released
broker, a real OCI runtime, the real authority over a real DWKP client and the
released `serve --sandbox-config` -- and judges the evidence lines each passing
case prints after its assertions held (ADR-0052 §§8, 17).

Every case the runner expects is listed here with the level it must be
measured at and the outcome it must report. A case that silently stopped
running is a FAIL naming it, never a smaller denominator; a case measured at
another level -- a fake broker's line offered for a real container's end, an
in-process call offered for a DWKP client's -- is a FAIL; an outcome that
contradicts the expected one (a refusal accepted, an environment kept, a
replay) is a FAIL; the task's own failure -- including NOT EXERCISED, a
container left behind or one removed that predated it -- is a FAIL.

What the required hosted jobs measure is theirs, and is never counted here:
M5d.1-M5d.2's whole workload evidence (`sandbox-workload`), secret modes B and
C (`sandbox-secret`), the operator-provisioned workspace and its quota
(`sandbox-workspace`), and the agent's three host identities (`sandbox-agent`).

The judging function takes the task's output and nothing else, so the meta
tests can hand it a regression and watch the gate fail.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from typing import TYPE_CHECKING, Any, Final

from direwolf_evals.model import Outcome, Status

if TYPE_CHECKING:  # pragma: no cover - import cycle only matters to type checkers
    from direwolf_evals.runners import Context

__all__ = ["EXPECTED", "M5D_CASES", "judge_sandbox_exec", "sandbox_exec"]

MAX_ARTIFACT: Final = 1500
PREFIX: Final = "SANDBOX-EVIDENCE "

FAKE: Final = "fake-broker"
E2E: Final = "dwkp-end-to-end"
REAL: Final = "real-oci"

_UNIT: Final = "authority-release"
_RELEASE: Final = "sandbox-release"

# The authority's state machine against the fake broker (labelled so): what
# it decides, records and refuses -- never a container's end.
_UNIT_EXPECTED: Final[dict[str, str]] = {
    "release-destroys-the-runs-environment": "DESTROYED",
    "release-intent-durable-before-the-broker": "DESTROYING-and-RELEASED-at-the-order",
    "release-names-only-its-environment": "exact-environment-run-container",
    "release-audited-in-order": "run.released-then-destroy_intent-then-destroyed",
    "release-spares-another-runs-environment": "READY-and-ran",
    "release-repeated-no-second-effect": "ACK-nothing-destroyed",
    "released-run-launch-refused-nothing-prepared": "UNKNOWN_RUN",
    "released-runs-key-never-runs-again": "IDEMPOTENCY_KEY_REUSED",
    "release-keeps-the-runs-ledger": "charged-never-refunded",
    "release-without-an-environment-destroys-nothing": "ACK-nothing-destroyed",
    "release-without-a-sandbox-unchanged": "ACK-broker-asked-nothing",
    "release-stale-epoch-refused-nothing-destroyed": "STALE_EPOCH",
    "release-other-holder-refused-nothing-destroyed": "STALE_EPOCH",
    "release-of-a-run-not-held-destroys-nothing": "ACK-nothing-destroyed",
    "release-ends-an-in-flight-workloads-environment": "DESTROYED-while-LAUNCHING",
    "release-in-flight-workload-settled-unknown": "OUTCOME_UNKNOWN",
    "release-in-flight-workload-never-rerun": "IDEMPOTENCY_KEY_REUSED",
    "release-during-preparation-environment-destroyed": "RUN_ENDED",
    "release-during-preparation-nothing-ran": "ENVIRONMENT_UNAVAILABLE",
    "release-broker-unreachable-destruction-pending": "DESTROYING",
    "release-broker-unreachable-completed-at-restart": "DESTROYED",
    "release-answer-lost-destruction-pending": "DESTROYING",
    "release-answer-lost-completed-at-restart": "DESTROYED",
    "release-pending-destruction-completed-by-the-next-preparation": "DESTROYED",
    "release-completes-its-runs-pending-destruction": "DESTROYED",
    **{f"release-crash-{w}-environment-destroyed-at-restart": "DESTROYED" for w in "ukl"},
    **{f"release-crash-{w}-never-rerun": "IDEMPOTENCY_KEY_REUSED" for w in "ukl"},
}

# Real containers: the level each case is measured at, and what it reports.
_REAL_EXPECTED: Final[dict[str, tuple[str, str]]] = {
    "sandboxed-exec-in-a-measured-environment-never-the-host": (E2E, "CONTAINER_ISOLATION"),
    "sandboxed-exec-names-the-pinned-image-and-executable": (E2E, "image-and-sha256-pinned"),
    "sandboxed-exec-runs-as-the-environment-user": (E2E, "uid-10001"),
    "release-stale-epoch-refused-nothing-destroyed": (E2E, "STALE_EPOCH"),
    "release-other-holder-refused-nothing-destroyed": (E2E, "STALE_EPOCH"),
    "release-of-a-run-not-held-destroys-nothing": (E2E, "ACK-container-kept"),
    "release-over-dwkp-destroys-the-environment": (E2E, "container-removed"),
    "release-audited": (E2E, "destroy_intent-RELEASED-then-destroyed"),
    "release-spares-another-runs-environment": (E2E, "container-kept"),
    "release-spares-foreign-containers": (E2E, "unlabelled-and-another-stores-kept"),
    "release-other-run-still-runs": (E2E, "residue-pass"),
    "release-repeated-over-dwkp-no-second-effect": (E2E, "ACK-nothing-destroyed"),
    "released-run-launch-refused-over-dwkp": (E2E, "UNKNOWN_RUN"),
    "release-without-an-environment-over-dwkp": (E2E, "ACK-nothing-destroyed"),
    "release-in-flight-agent-and-descendants-running": (REAL, "plan-workers-and-daemon-as-10001"),
    "release-ends-in-flight-workload-and-descendants": (
        REAL,
        "container-removed-with-every-process",
    ),
    "release-in-flight-workload-settled-unknown": (REAL, "OUTCOME_UNKNOWN"),
    "release-in-flight-workload-never-rerun": (REAL, "IDEMPOTENCY_KEY_REUSED"),
    **{f"release-crash-{w}-completed-at-restart": (REAL, "container-removed") for w in "ukl"},
    **{f"release-crash-{w}-never-rerun": (REAL, "nothing-recorded-or-run") for w in "ukl"},
    "release-broker-lost-destruction-pending": (REAL, "DESTROYING-container-kept"),
    "release-broker-lost-completed-at-restart": (REAL, "container-removed"),
    "release-removes-the-proxy-only-environment-relay-and-setup": (E2E, "every-role-removed"),
    # The dispositions themselves vary; a refused tunnel must be among them.
    "release-destruction-records-the-egress-by-disposition": (
        E2E,
        r"re:(^|.*,)TARGET_NOT_GRANTED=[1-9][0-9]*(,.*|$)",
    ),
    "release-spares-another-runs-proxy-only-environment": (
        E2E,
        "relay-kept-and-reaching-its-origin",
    ),
}

# Every expected (suite, case): its level and its outcome -- an exact string,
# or `re:` and a pattern the whole outcome must match.
EXPECTED: Final[dict[tuple[str, str], tuple[str, str]]] = {
    **{(_UNIT, case): (FAKE, outcome) for case, outcome in _UNIT_EXPECTED.items()},
    **{(_RELEASE, case): expected for case, expected in _REAL_EXPECTED.items()},
}
M5D_CASES: Final = frozenset(EXPECTED)


def _records(output: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line in output.splitlines():
        at = line.find(PREFIX)
        if at < 0:
            continue
        raw: Any = json.loads(line[at + len(PREFIX) :])
        if not isinstance(raw, dict):
            raise ValueError(f"an evidence line is not an object: {line[:200]}")
        records.append(raw)
    return records


def _agrees(expected: str, outcome: str) -> bool:
    if expected.startswith("re:"):
        return re.fullmatch(expected[3:], outcome) is not None
    return outcome == expected


def judge_sandbox_exec(output: str, code: int) -> Outcome:
    """Every expected case reported at its level with its expected outcome and
    what enforced it, and the evidence task itself passed."""
    try:
        records = _records(output)
    except (ValueError, json.JSONDecodeError) as exc:
        return Outcome(Status.ERROR, {}, f"unreadable evidence: {exc}")
    seen: dict[tuple[str, str], dict[str, Any]] = {}
    for record in records:
        key = (str(record.get("suite")), str(record.get("case")))
        outcome = str(record.get("outcome", ""))
        if key in EXPECTED and not outcome.lower().startswith("not-exercised"):
            seen.setdefault(key, record)
    missing = sorted(f"{s}/{c}" for s, c in M5D_CASES - set(seen))
    wrong_level = sorted(
        f"{s}/{c} at {record.get('level')!r}"
        for (s, c), record in seen.items()
        if record.get("level") != EXPECTED[(s, c)][0]
    )
    contradicted = sorted(
        f"{s}/{c} reported {record.get('outcome')!r}"
        for (s, c), record in seen.items()
        if not _agrees(EXPECTED[(s, c)][1], str(record.get("outcome")))
    )
    unattributed = sorted(
        f"{s}/{c}" for (s, c), record in seen.items() if not record.get("enforcement")
    )
    sound = code == 0 and not (missing or wrong_level or contradicted or unattributed)
    found = sum(
        1
        for key, record in seen.items()
        if record.get("level") == EXPECTED[key][0]
        and _agrees(EXPECTED[key][1], str(record.get("outcome")))
    )
    metrics = {
        "cases": float(found),
        "expected_cases": float(len(M5D_CASES)),
        "real_cases": float(sum(1 for s, _ in seen if s == _RELEASE)),
        "contradicted": float(len(contradicted)),
        "wrong_level": float(len(wrong_level)),
        "rejection_rate": (found / len(M5D_CASES)) if sound else 0.0,
    }
    problems = []
    if code != 0:
        problems.append(f"the evidence task failed (exit {code})")
    if missing:
        problems.append(f"missing cases: {', '.join(missing)}")
    if wrong_level:
        problems.append(f"measured at the wrong level: {', '.join(wrong_level)}")
    if contradicted:
        problems.append(f"outcomes contradicting the expected: {', '.join(contradicted)}")
    if unattributed:
        problems.append(f"cases naming no enforcement: {', '.join(unattributed)}")
    if problems:
        return Outcome(
            Status.FAIL,
            metrics,
            "; ".join(problems)[:MAX_ARTIFACT],
            {"output": output[-MAX_ARTIFACT:]},
        )
    return Outcome(Status.PASS, metrics)


def sandbox_exec(ctx: Context) -> Outcome:
    """ADR-0052 §§8, 17: a sandboxed launch runs where the authority decided,
    as the environment's user, the pinned bytes; a run's release ends its
    environment -- durably first, exactly its own, an in-flight workload and
    its descendants with it, crashes and a lost broker reconciled, nothing
    replayed, nothing foreign touched -- the real evidence task."""
    completed = subprocess.run(
        [sys.executable, "scripts/dw.py", "sandbox-release-evidence"],
        cwd=str(ctx.repo_root),
        env=dict(os.environ),
        capture_output=True,
        text=True,
        errors="replace",
        timeout=ctx.evaluation.timeout_s,
        check=False,
    )
    return judge_sandbox_exec(completed.stdout + completed.stderr, completed.returncode)
