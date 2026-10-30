"""CI cannot lose M5e.2's runtime-restart evidence, or run it anywhere unsafe.

R11 (the owner's OD-E8) restarts the container runtime under a running
authority. That needs root on the host and stops every container it holds, so
it runs only on a disposable GitHub-hosted runner, in a job of its own. The
wiring is therefore security-relevant twice over: a job the aggregate does not
require, or a condition that skips it, would be a green CI that never
restarted anything; and a flag set anywhere else, or a task that started work
before checking where it is, could restart a daemon that is not disposable.

These tests hold both, reading the workflow as text (no YAML parser is a
dependency) and the task through `scripts/dw.py`. The restart itself is
evidenced only by the hosted job.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CI = REPO_ROOT / ".github" / "workflows" / "ci.yml"
SUITE = REPO_ROOT / "crates" / "dwkd-authority" / "tests" / "sandbox_workload.rs"

sys.path.insert(0, str(REPO_ROOT / "scripts"))
import dw  # noqa: E402  - imported after the path is extended

JOB = "sandbox-restart"
AGGREGATE_JOB = "ci"
COMMAND = "make sandbox-restart-evidence"
FLAG = "DW_RUNTIME_RESTART"


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


def test_the_restart_job_exists_is_unconditional_and_required() -> None:
    job = _jobs().get(JOB)
    assert job is not None, f"no `{JOB}` job: the runtime restart is evidenced nowhere"
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


def test_the_restart_job_runs_its_task_with_its_flag_and_nothing_else_has_it() -> None:
    jobs = _jobs()
    found = [s for s in _steps(jobs[JOB]) if _run(s) == COMMAND]
    assert len(found) == 1, f"{JOB} must run `{COMMAND}` exactly once"
    assert _env(found[0]) == {FLAG: "1"}
    for name, job in jobs.items():
        if name == JOB:
            continue
        for step in _steps(job):
            assert FLAG not in _env(step), f"{name} sets {FLAG}: only {JOB} restarts a runtime"
            assert "sandbox-restart-evidence" not in _run(step), name
            assert "systemctl restart docker" not in _run(step), name


def test_the_restart_test_is_ignored_selected_by_name_and_guarded_first() -> None:
    source = SUITE.read_text(encoding="utf-8")
    for name in dw.RESTART_TESTS:
        function = name.rsplit("::", 1)[-1]
        found = re.search(r'#\[ignore = "([^"]*)"\]\s*fn ' + re.escape(function) + r"\(\)", source)
        assert found is not None, f"{function} is not an #[ignore]d test"
        assert "hosted only" in found.group(1), found.group(1)
    module = source[source.index("    mod restart {") : source.index("    mod release {")]
    guard = module.index("fn disposable_runner")
    for check in (FLAG, "GITHUB_ACTIONS", "RUNNER_ENVIRONMENT", "Docker Desktop", "is-active"):
        assert check in module[guard : module.index("fn restart_runtime")], check
    body = module[module.index("fn the_runtime_restarts") :]
    assert body.index("disposable_runner(") < body.index("Lab::new("), (
        "the test checks where it is before it makes anything"
    )


@pytest.mark.parametrize(
    ("environ", "said"),
    [
        ({}, "DW_RUNTIME_RESTART=1 is not set"),
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
        dw.task_sandbox_restart_evidence()
    assert said in str(refused.value)


def test_a_hosted_runner_with_the_flag_is_not_refused() -> None:
    hosted = {FLAG: "1", "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}
    assert dw.restart_refusal(hosted) is None
