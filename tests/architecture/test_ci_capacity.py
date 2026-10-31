"""CI cannot lose M5e.2's live-environment capacity evidence, or run it anywhere unsafe.

R8 at the cap (ADR-0056 §6, the owner's Option B) prepares every live
environment the authority allows, all of the one sandbox uid, and holds all
but one at their own task bound while the last is prepared, measured and
served. That is thousands of sleeping tasks of one uid, so it runs only on a
disposable GitHub-hosted runner, in a job of its own, after the runner's
capacity is checked. The wiring is security-relevant twice over: a job the
aggregate does not require, or a condition that skips it, would be a green CI
that never filled the cap; and a flag set anywhere else, or a task that started
work before checking where it is, could fill a host that is not disposable.

These tests hold both, reading the workflow as text (no YAML parser is a
dependency) and the task through `scripts/dw.py`. The capacity itself is
evidenced only by the hosted job.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CI = REPO_ROOT / ".github" / "workflows" / "ci.yml"

sys.path.insert(0, str(REPO_ROOT / "scripts"))
import dw  # noqa: E402  - imported after the path is extended

JOB = "sandbox-capacity"
AGGREGATE_JOB = "ci"
COMMAND = "make sandbox-capacity-evidence"
FLAG = "DW_CAPACITY_EVIDENCE"


def _uncommented(line: str) -> str:
    if line.lstrip().startswith("#"):
        return ""
    return re.split(r"\s+#", line, maxsplit=1)[0]


def _jobs() -> dict[str, list[str]]:
    lines = CI.read_text(encoding="utf-8").splitlines()
    jobs: dict[str, list[str]] = {}
    current: str | None = None
    for line in lines[lines.index("jobs:") + 1 :]:
        match = re.fullmatch(r"  ([a-z][a-z0-9-]*):\s*", line)
        if match:
            current = match.group(1)
            jobs[current] = []
        elif line and not line[0].isspace() and not line.startswith("#"):
            break
        elif current is not None:
            jobs[current].append(line)
    return jobs


def _steps(job: list[str]) -> list[list[str]]:
    steps: list[list[str]] = []
    current: list[str] | None = None
    for line in job:
        if line.startswith("      - "):
            current = [line]
            steps.append(current)
        elif current is not None and (line.startswith("        ") or not line.strip()):
            current.append(line)
        else:
            current = None
    return steps


def _run(step: list[str]) -> str:
    for line in step:
        match = re.match(r"\s*(?:- )?run:\s*(.*)$", _uncommented(line))
        if match:
            return match.group(1).strip()
    return ""


def _env(step: list[str]) -> dict[str, str]:
    env: dict[str, str] = {}
    for line in step:
        match = re.fullmatch(r"\s{10}([A-Z][A-Z0-9_]*):\s*(.*?)\s*", _uncommented(line))
        if match:
            env[match.group(1)] = match.group(2).strip("\"'")
    return env


def test_the_capacity_job_exists_is_unconditional_and_required() -> None:
    job = _jobs().get(JOB)
    assert job is not None, f"no `{JOB}` job: R8 at the cap is evidenced nowhere"
    text = "\n".join(_uncommented(line) for line in job)
    assert re.search(r"^    runs-on:\s*ubuntu-latest\s*$", text, re.MULTILINE), "Linux only"
    for forbidden in ("strategy:", "matrix", "continue-on-error", "if:"):
        assert forbidden not in text, f"`{forbidden}` in {JOB}"
    needs = next(
        (
            [n.strip() for n in m.group(1).split(",")]
            for line in _jobs()[AGGREGATE_JOB]
            if (m := re.match(r"\s+needs:\s*\[([^\]]*)\]", line))
        ),
        [],
    )
    assert JOB in needs, f"the aggregate `{AGGREGATE_JOB}` job does not require {JOB}"
    # R8's two-environment case is the workload job's, which stays required.
    assert "sandbox-workload" in needs


def test_the_capacity_job_runs_its_task_with_its_flag_and_nothing_else_has_it() -> None:
    jobs = _jobs()
    found = [s for s in _steps(jobs[JOB]) if _run(s) == COMMAND]
    assert len(found) == 1, f"{JOB} must run `{COMMAND}` exactly once"
    assert _env(found[0]) == {FLAG: "1"}
    for name, job in jobs.items():
        if name == JOB:
            continue
        for step in _steps(job):
            assert FLAG not in _env(step), f"{name} sets {FLAG}: only {JOB} fills the cap"
            assert "sandbox-capacity-evidence" not in _run(step), name


@pytest.mark.parametrize(
    ("environ", "said"),
    [
        ({}, "DW_CAPACITY_EVIDENCE=1 is not set"),
        ({FLAG: "0", "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}, "not set"),
        ({FLAG: "1"}, "not a disposable GitHub-hosted runner"),
        ({FLAG: "1", "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "self-hosted"}, "not a"),
    ],
    ids=["no-flag", "flag-off", "off-actions", "self-hosted"],
)
def test_the_task_refuses_before_anything_runs_off_a_disposable_runner(
    monkeypatch: pytest.MonkeyPatch, environ: dict[str, str], said: str
) -> None:
    def nothing(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("the task started work before it checked where it is")

    monkeypatch.setattr(dw, "_workload_setup", nothing)
    monkeypatch.setattr(dw, "run", nothing)
    monkeypatch.setattr(dw, "run_captured", nothing)
    monkeypatch.setattr(sys, "platform", "linux")
    for name in (FLAG, "GITHUB_ACTIONS", "RUNNER_ENVIRONMENT"):
        monkeypatch.delenv(name, raising=False)
    for name, value in environ.items():
        monkeypatch.setenv(name, value)
    with pytest.raises(dw.TaskError, match="NOT EXERCISED") as refused:
        dw.task_sandbox_capacity_evidence()
    assert said in str(refused.value)


def test_a_hosted_runner_with_the_flag_is_not_refused() -> None:
    hosted = {FLAG: "1", "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}
    assert dw.capacity_refusal(hosted) is None
    # The restart's flag is not this job's, nor this job's the restart's.
    assert dw.capacity_refusal({**hosted, FLAG: "", "DW_RUNTIME_RESTART": "1"}) is not None
    assert dw.restart_refusal({**hosted, FLAG: "1"}) is not None


def _line(suite: str, case: str) -> str:
    contract = dw.attribution(suite, case)
    assert contract is not None, f"{suite}/{case} is unattributed"
    level, mechanisms = contract
    record = {"suite": suite, "case": case, "outcome": "ok", "level": level}
    record["enforcement"] = sorted(mechanisms)[0]
    return f"x {dw.SANDBOX_EVIDENCE_PREFIX}{json.dumps(record)}"


def test_the_capacity_task_requires_its_cases_through_the_attributed_gate() -> None:
    levels = {
        contract[0] for s, c in dw.CAPACITY_CASES if (contract := dw.attribution(s, c)) is not None
    }
    assert levels == {"real-oci"}
    complete = "\n".join(_line(s, c) for s, c in dw.CAPACITY_CASES)
    assert len(dw.require_attributed_evidence(complete, dw.CAPACITY_CASES)) == 4
    for dropped in range(len(dw.CAPACITY_CASES)):
        lines = complete.splitlines()
        del lines[dropped]
        with pytest.raises(dw.TaskError, match="NOT EXERCISED"):
            dw.require_attributed_evidence("\n".join(lines), dw.CAPACITY_CASES)
