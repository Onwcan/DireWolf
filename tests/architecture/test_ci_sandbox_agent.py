"""CI cannot turn missing M5d.5 agent evidence into a green check.

M5d.5's three-identity half (ADR-0052 §13; docs/M5D5_IMPLEMENTATION_HANDOFF.md
C01, C02) cannot be measured on a one-user workstation: it needs three host
users, the workspace group 10001 and a bounded workspace, which only a
disposable hosted runner provisions. So the wiring that carries it is itself
security-relevant: a job the aggregate does not require, a skipped or
conditional job, an identity that is really the runner's own, a case the
suite prints that the task never asks for -- or one the task asks for that
the suite never prints -- would each be a green CI that proved nothing.

These tests assert that structure, reading the workflow as text (as
`test_ci_authority_gate.py` does: no YAML parser is a dependency), and the
task's accounting directly, through `scripts/dw.py`.
"""

from __future__ import annotations

import re
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CI = REPO_ROOT / ".github" / "workflows" / "ci.yml"
SUITE = REPO_ROOT / "crates" / "dwkd-authority" / "tests" / "sandbox_agent.rs"

sys.path.insert(0, str(REPO_ROOT / "scripts"))
import dw  # noqa: E402  - imported after the path is extended

JOB = "sandbox-agent"
AGGREGATE_JOB = "ci"
COMMAND = (
    'sudo --non-interactive --preserve-env --user "$USER" env "PATH=$PATH" '
    "make sandbox-agent-evidence"
)


def _uncommented(line: str) -> str:
    if line.lstrip().startswith("#"):
        return ""
    return re.split(r"\s+#", line, maxsplit=1)[0]


def _jobs() -> dict[str, list[str]]:
    """Each job's lines, keyed by its id (two-space indented under `jobs:`)."""
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


def _run(step: list[str]) -> str | None:
    for line in step:
        match = re.match(r"\s*(?:- )?run:\s*(.*)$", _uncommented(line))
        if match:
            return match.group(1).strip()
    return None


def _env(step: list[str]) -> dict[str, str]:
    env: dict[str, str] = {}
    for line in step:
        match = re.fullmatch(r"\s{10}([A-Z][A-Z0-9_]*):\s*(.*?)\s*", _uncommented(line))
        if match:
            env[match.group(1)] = match.group(2).strip("\"'")
    return env


def _needs() -> list[str]:
    for line in _jobs()[AGGREGATE_JOB]:
        match = re.match(r"\s+needs:\s*\[([^\]]*)\]", line)
        if match:
            return [n.strip() for n in match.group(1).split(",") if n.strip()]
    raise AssertionError("the aggregate job declares no `needs`")


def _evidence_step() -> list[str]:
    found = [s for s in _steps(_jobs()[JOB]) if _run(s) == COMMAND]
    assert len(found) == 1, f"{JOB} must run `{COMMAND}` exactly once; found {len(found)}"
    return found[0]


def test_the_agent_job_exists_on_linux_and_is_unconditional() -> None:
    job = _jobs().get(JOB)
    assert job is not None, f"no `{JOB}` job: M5d.5 is measured nowhere"
    text = "\n".join(_uncommented(line) for line in job)
    assert re.search(r"^    runs-on:\s*ubuntu-latest\s*$", text, re.MULTILINE), "Linux only"
    assert re.search(
        r"^    name:\s*sandbox agent \(make sandbox-agent-evidence\)\s*$", text, re.MULTILINE
    ), "the required check keeps its name"
    for forbidden in ("strategy:", "matrix", "continue-on-error", "secrets."):
        assert forbidden not in text, f"`{forbidden}` in {JOB}"
    assert not re.search(r"^    if:", text, re.MULTILINE), f"{JOB} has a condition"
    # The evidence step itself is unconditional; only the cleanup runs always.
    assert not any(re.match(r"\s+if:", _uncommented(line)) for line in _evidence_step())


def test_the_aggregate_requires_the_agent_job_and_every_job_once() -> None:
    needs = _needs()
    assert JOB in needs, f"the aggregate `ci` job does not require `{JOB}`"
    assert len(needs) == len(set(needs)), f"a job is required twice: {needs}"
    jobs = set(_jobs()) - {AGGREGATE_JOB}
    assert set(needs) == jobs, f"jobs the aggregate does not require: {sorted(jobs - set(needs))}"


def test_the_agent_job_runs_three_distinct_ordinary_identities() -> None:
    env = _env(_evidence_step())
    assert env.get("DW_AGENT_PRIVILEGED") == "1", "the three-identity half must run in CI"
    users = [env.get(name) for name in ("DW_BROKER_AS", "DW_PEER_AS", "DW_AGENT_OUTSIDER")]
    for user in users:
        assert user, "an identity is not configured"
        assert user not in ("root", "0", "$USER", "runner"), (
            f"{user!r} is not an ordinary other user: root is outside the threat model and "
            "the runner's own account is the authority's"
        )
    assert len(set(users)) == 3, f"one identity in two roles: {users}"
    steps = _steps(_jobs()[JOB])
    setup = "\n".join(line for step in steps[: steps.index(_evidence_step())] for line in step)
    for user in users[:2]:
        assert f"useradd --system --no-create-home --shell /usr/sbin/nologin {user}" in setup
    # The broker's user alone has the runtime's socket; the runtime's has
    # neither it nor the workspace group.
    grants = re.findall(r"usermod --append --groups (\S+) (\S+)", setup)
    assert ("dwworkspace,docker", users[0]) in grants, grants
    assert all(user != users[1] for _, user in grants), f"the runtime is given a group: {grants}"
    assert all("docker" not in groups or user == users[0] for groups, user in grants), grants
    assert "groupadd --gid 10001 dwworkspace" in setup
    cleanup = [s for s in steps if "userdel" in "\n".join(s)]
    assert cleanup, "the identities the job created are not removed"
    assert any("if: always()" in line for line in cleanup[0]), "cleanup must always run"


def test_the_identity_tests_are_ignored_by_default_and_selected_by_name() -> None:
    source = SUITE.read_text(encoding="utf-8")
    for name in (*dw.AGENT_TESTS, *dw.AGENT_IDENTITY_TESTS):
        module, function = name.split("::")
        assert module == "linux"
        assert re.search(r"#\[ignore = [^\]]*\]\s*fn " + re.escape(function) + r"\(\)", source), (
            f"{function} is not an #[ignore]d test in {SUITE.name}"
        )


def test_the_task_names_exactly_the_cases_the_suite_prints() -> None:
    """A renamed case would otherwise fail only in CI; an extra one would be
    printed and never required."""
    source = SUITE.read_text(encoding="utf-8")
    printed = set(re.findall(r'"((?:a|i)\d\d-[a-z0-9-]+|audit-[a-z0-9-]+)"', source))
    required = {case for _, case in (*dw.AGENT_CASES, *dw.AGENT_IDENTITY_CASES)}
    assert printed == required, (
        f"printed, never required: {sorted(printed - required)}; "
        f"required, never printed: {sorted(required - printed)}"
    )
    assert not set(dw.AGENT_CASES) & set(dw.AGENT_IDENTITY_CASES)


def _line(suite: str, case: str, outcome: str = "ok", level: str = "dwkp-end-to-end") -> str:
    return (
        f'SANDBOX-EVIDENCE {{"suite":"{suite}","case":"{case}","outcome":"{outcome}",'
        f'"level":"{level}","enforcement":"connect-proxy:grant"}}'
    )


def test_agent_evidence_requires_every_case_with_its_level_and_enforcement() -> None:
    cases = dw.AGENT_CASES
    complete = "\n".join(_line(suite, case) for suite, case in cases)
    dw.require_agent_evidence(complete, cases)
    suite, case = cases[3]
    with pytest.raises(dw.TaskError, match=re.escape(f"{suite}/{case}")):
        dw.require_agent_evidence(
            "\n".join(line for line in complete.splitlines() if f'"{case}"' not in line), cases
        )
    with pytest.raises(dw.TaskError, match=re.escape(f"{suite}/{case}")):
        dw.require_agent_evidence(
            complete.replace(_line(suite, case), _line(suite, case, "not-exercised: no runtime")),
            cases,
        )
    with pytest.raises(dw.TaskError, match="level or enforcement"):
        dw.require_agent_evidence(
            complete.replace(_line(suite, case), _line(suite, case, level="unit")), cases
        )


def test_without_the_identities_the_task_is_not_exercised_after_the_rest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The one-identity half passing is never the three-identity half."""
    monkeypatch.delenv("DW_AGENT_PRIVILEGED", raising=False)
    assert not dw.agent_privileged()
    monkeypatch.setenv("DW_AGENT_PRIVILEGED", "yes")
    assert not dw.agent_privileged(), "only exactly 1 provisions a host"
    monkeypatch.setenv("DW_AGENT_PRIVILEGED", "1")
    monkeypatch.delenv("DW_BROKER_AS", raising=False)
    with pytest.raises(dw.TaskError, match="NOT EXERCISED: DW_AGENT_PRIVILEGED=1 but"):
        dw._sandbox_agent_evidence(require_privileged=True)


# --- the task's cleanup (hosted run 40024819700) ------------------------------
#
# A failed suite must be the failure reported: cleanup that meets a workspace
# the run never provisioned must not raise in its place, and what cleanup does
# find -- a leaked or a lost container, a mount -- is reported beside the
# suite's failure, or as the failure of a run whose suites passed.

PRE_EXISTING = "pre-existing"
IMAGE = "sha256:" + "a" * 64


def _stub_runner(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    suite: Callable[[tuple[str, ...]], str],
    listed: str,
) -> list[str]:
    """`_sandbox_agent_evidence` with no runtime, build or host: the runtime
    lists `listed` after the evidence (`PRE_EXISTING` before it), the suites
    do what `suite` does, and the workspace base is never made. Returns the
    commands the task ran."""
    ran: list[str] = []
    monkeypatch.delenv("DW_AGENT_PRIVILEGED", raising=False)
    monkeypatch.setattr(
        dw,
        "_agent_setup",
        lambda: (tmp_path / "docker", "/run/docker.sock", {}, {PRE_EXISTING}, [IMAGE]),
    )
    monkeypatch.setattr(dw, "run", lambda *command: ran.append(" ".join(command)))
    monkeypatch.setattr(dw, "_agent_suite", suite)
    monkeypatch.setattr(dw, "_agent_workspace_base", lambda: tmp_path / "never-provisioned")
    monkeypatch.setattr(dw, "_mounted_under", lambda _base: [])
    monkeypatch.setattr(dw, "_socket_dirs_left", list)

    def docker(_client: Path, _socket: str, *args: str, **_options: bool) -> str:
        ran.append("docker " + " ".join(args))
        return listed if args[:2] == ("container", "ls") else ""

    monkeypatch.setattr(dw, "_docker", docker)
    return ran


def _failed_suite(tests: tuple[str, ...]) -> str:
    raise dw.TaskError(f"the sandbox_agent suite did not run all of its {len(tests)} tests")


def test_a_failed_suite_is_reported_even_when_nothing_was_provisioned(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    ran = _stub_runner(monkeypatch, tmp_path, _failed_suite, PRE_EXISTING)
    with pytest.raises(dw.TaskError, match="did not run all of its 3 tests"):
        dw._sandbox_agent_evidence(require_privileged=True)
    assert f"docker image rm --force {IMAGE}" in ran, "the cleanup still ran"
    assert not (tmp_path / "never-provisioned").exists()
    assert "cleanup also failed" not in capsys.readouterr().err


def test_what_cleanup_finds_is_reported_beside_the_suites_failure(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    _stub_runner(monkeypatch, tmp_path, _failed_suite, f"{PRE_EXISTING}\nleaked")
    with pytest.raises(dw.TaskError, match="did not run all of its 3 tests"):
        dw._sandbox_agent_evidence(require_privileged=True)
    assert (
        "cleanup also failed: the evidence left 1 container(s) behind: ['leaked']"
        in capsys.readouterr().err
    )


def test_cleanup_fails_a_run_whose_suites_passed(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    complete = "\n".join(_line(suite, case) for suite, case in dw.AGENT_CASES)
    _stub_runner(monkeypatch, tmp_path, lambda _tests: complete, "")
    with pytest.raises(
        dw.TaskError, match=re.escape("cleanup failed: 1 container(s) that predate")
    ):
        dw._sandbox_agent_evidence(require_privileged=False)


def test_unprovisioning_is_clean_when_nothing_was_provisioned_and_strict_when_it_was(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    base = tmp_path / "never-provisioned"
    monkeypatch.setattr(dw, "_mounted_under", lambda _base: [])
    dw._unprovision_workspaces(base)
    assert not base.exists()
    # A mount that will not come off is still a failure, never ignored.
    monkeypatch.setattr(dw, "_mounted_under", lambda under: [str(under / "tmpfs")])
    # Every `umount` "succeeds" and changes nothing.
    monkeypatch.setattr(
        subprocess,
        "run",
        lambda *args, **_options: subprocess.CompletedProcess(args, 0, "", ""),
    )
    with pytest.raises(dw.TaskError, match="still mounted"):
        dw._unprovision_workspaces(base)
