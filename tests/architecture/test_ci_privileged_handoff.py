"""CI cannot lose a privileged evidence job's configuration at the identity switch.

Three hosted jobs -- filesystem operations, the sandbox workspace and the
sandbox agent -- run their evidence as a fresh session of the runner's own
user, so that the groups the job just created are in force. Until CI #106
(run 40954372045) the step's `DW_*` configuration crossed that switch only
through a bare `sudo --preserve-env`. On the Ubuntu 26.04 image `sudo` is
sudo-rs, whose `env_reset` cannot be disabled (sudoers-rs(5)), and the bare
flag carried nothing: all three tasks saw no configuration and reported their
hosted-only halves NOT EXERCISED -- correctly failing -- while the tests that
pinned the command text stayed green.

So the handoff is held two ways here. As text: each job runs
`scripts/ci_handoff.py` naming exactly the variables its step sets and the
groups the switch exists for, the aggregate requires it, nothing makes it
conditional, and no bare `--preserve-env` is left; each kind of mutation of
that text fails. And executed: the job's own command runs under a stub `sudo`
that resets the environment as sudo-rs documents, and a stub `make` records
what reached it -- exactly the step's values, in the runner's own session.
The CI #106 command, under the same stub, is shown to lose every value.
"""

from __future__ import annotations

import json
import os
import re
import shlex
import stat
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CI = REPO_ROOT / ".github" / "workflows" / "ci.yml"
HANDOFF = REPO_ROOT / "scripts" / "ci_handoff.py"
AGGREGATE_JOB = "ci"

# Each job that switches identity: its evidence task, the configuration that
# must reach it, and the groups the switch exists to bring into force.
JOBS: dict[str, tuple[str, tuple[str, ...], tuple[str, ...]]] = {
    "filesystem-operations": (
        "filesystem-operations-evidence",
        ("DW_BROKER_AS", "DW_PEER_AS", "DW_WRITE_GROUP"),
        ("dwwrite",),
    ),
    "sandbox-workspace": (
        "sandbox-workspace-evidence",
        ("DW_WORKSPACE_PRIVILEGED", "DW_WORKSPACE_PEER"),
        ("dwworkspace",),
    ),
    "sandbox-agent": (
        "sandbox-agent-evidence",
        ("DW_AGENT_PRIVILEGED", "DW_BROKER_AS", "DW_PEER_AS", "DW_AGENT_OUTSIDER"),
        ("dwworkspace",),
    ),
}
# The host-provisioning flags these jobs carry, and no other job may.
PRIVILEGED = {
    "DW_WORKSPACE_PRIVILEGED": "sandbox-workspace",
    "DW_AGENT_PRIVILEGED": "sandbox-agent",
}
# The command CI #106 ran, which the stub shows losing every value.
CI106 = 'sudo --non-interactive --preserve-env --user "$USER" env "PATH=$PATH" make {task}'

POSIX = pytest.mark.skipif(os.name != "posix", reason="the identity switch is POSIX's")


def _uncommented(line: str) -> str:
    if line.lstrip().startswith("#"):
        return ""
    return re.split(r"\s+#", line, maxsplit=1)[0]


def _jobs(text: str) -> dict[str, list[str]]:
    """Each job's lines, keyed by its id (two-space indented under `jobs:`)."""
    lines = text.splitlines()
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


def _needs(text: str) -> list[str]:
    for line in _jobs(text).get(AGGREGATE_JOB, []):
        match = re.match(r"\s+needs:\s*\[([^\]]*)\]", line)
        if match:
            return [n.strip() for n in match.group(1).split(",") if n.strip()]
    return []


def _handoff(task: str, names: tuple[str, ...], groups: tuple[str, ...]) -> list[str]:
    return [
        "python3",
        "scripts/ci_handoff.py",
        *(word for name in names for word in ("--pass", name)),
        *(word for group in groups for word in ("--group", group)),
        "--",
        "make",
        task,
    ]


def contract_errors(text: str) -> list[str]:
    """Everything wrong with the workflow's handoff, as text: empty when the
    three jobs hand over exactly their configuration and nothing is lost."""
    errors: list[str] = []
    if "--preserve-env" in "\n".join(_uncommented(line) for line in text.splitlines()):
        errors.append("a bare --preserve-env is back: under sudo-rs it carries nothing")
    jobs = _jobs(text)
    needs = _needs(text)
    for name, (task, required, groups) in JOBS.items():
        job = jobs.get(name)
        if job is None:
            errors.append(f"{name}: no such job")
            continue
        body = "\n".join(_uncommented(line) for line in job)
        for forbidden in ("continue-on-error", "strategy:", "matrix"):
            if forbidden in body:
                errors.append(f"{name}: `{forbidden}`")
        # The job itself, and any step but an always-run clean-up, is
        # unconditional.
        if re.search(r"^    if:", body, re.MULTILINE):
            errors.append(f"{name}: the job is conditional")
        for step in _steps(job):
            text_ = "\n".join(_uncommented(line) for line in step)
            condition = re.search(r"^\s+if:\s*(.*?)\s*$", text_, re.MULTILINE)
            if condition and (condition.group(1) != "always()" or "make " in _run(step)):
                errors.append(f"{name}: a step is conditional ({condition.group(1)})")
        if name not in needs:
            errors.append(f"{name}: the aggregate `{AGGREGATE_JOB}` job does not require it")
        steps = [s for s in _steps(job) if f"make {task}" in _run(s)]
        if len(steps) != 1:
            errors.append(f"{name}: runs `make {task}` {len(steps)} times, not once")
            continue
        command = shlex.split(_run(steps[0]))
        if command != _handoff(task, required, groups):
            errors.append(f"{name}: `{_run(steps[0])}` is not the handoff of {list(required)}")
        env = _env(steps[0])
        unset = [n for n in required if not env.get(n)]
        if unset:
            errors.append(f"{name}: the step does not set {unset}")
        extra = sorted(n for n in env if n.startswith("DW_") and n not in required)
        if extra:
            errors.append(f"{name}: the step sets {extra}, which nothing hands over")
        for flag in (n for n in required if n.endswith("_PRIVILEGED")):
            if env.get(flag) != "1":
                errors.append(f'{name}: {flag} is {env.get(flag)!r}, not "1"')
    for name, job in jobs.items():
        for step in _steps(job):
            run = _run(step)
            if "sudo" in run and "make " in run:
                errors.append(f"{name}: `{run}` runs make through sudo without the handoff")
            for flag, owner in PRIVILEGED.items():
                if flag in _env(step) and name != owner:
                    errors.append(f"{name}: sets {flag}, which provisions the host ({owner} only)")
    return errors


# --- the handoff as text -------------------------------------------------------


def test_the_three_jobs_hand_over_exactly_their_configuration() -> None:
    assert contract_errors(CI.read_text(encoding="utf-8")) == []


def _replace(old: str, new: str) -> Callable[[str], str]:
    def mutate(text: str) -> str:
        assert text.count(old) == 1, f"the mutation's target is not in the workflow once: {old!r}"
        return text.replace(old, new)

    return mutate


@pytest.mark.parametrize(
    ("mutate", "said"),
    [
        (_replace("--pass DW_AGENT_OUTSIDER ", ""), "sandbox-agent: `python3"),
        (_replace("          DW_WRITE_GROUP: dwwrite\n", ""), "does not set ['DW_WRITE_GROUP']"),
        (_replace("--pass DW_WORKSPACE_PEER ", ""), "sandbox-workspace: `python3"),
        (
            _replace(
                "python3 scripts/ci_handoff.py --pass DW_WORKSPACE_PRIVILEGED "
                "--pass DW_WORKSPACE_PEER --group dwworkspace -- make sandbox-workspace-evidence",
                CI106.format(task="sandbox-workspace-evidence"),
            ),
            "a bare --preserve-env is back",
        ),
        (_replace("--group dwwrite ", ""), "filesystem-operations: `python3"),
        (_replace(", sandbox-agent,", ","), "sandbox-agent: the aggregate"),
        (
            _replace(
                "    name: sandbox workspace (make sandbox-workspace-evidence)\n",
                "    name: sandbox workspace (make sandbox-workspace-evidence)\n"
                "    continue-on-error: true\n",
            ),
            "sandbox-workspace: `continue-on-error`",
        ),
        (
            _replace(
                '          DW_AGENT_PRIVILEGED: "1"\n', '          DW_AGENT_PRIVILEGED: "0"\n'
            ),
            "DW_AGENT_PRIVILEGED is '0'",
        ),
        (
            _replace("-- make sandbox-workspace-evidence", "-- make sandbox-workload-evidence"),
            "sandbox-workspace: runs `make sandbox-workspace-evidence` 0 times",
        ),
        (
            _replace(
                "      - run: make sandbox-foundation-evidence\n",
                "      - run: make sandbox-foundation-evidence\n"
                "        env:\n"
                '          DW_AGENT_PRIVILEGED: "1"\n',
            ),
            "sandbox-foundation: sets DW_AGENT_PRIVILEGED",
        ),
    ],
    ids=[
        "agent-variable-not-passed",
        "filesystem-variable-not-set",
        "workspace-variable-not-passed",
        "bare-preserve-env-restored",
        "group-not-required",
        "aggregate-drops-the-job",
        "continue-on-error",
        "privileged-flag-off",
        "another-task",
        "privileged-flag-elsewhere",
    ],
)
def test_each_lost_handoff_fails_the_contract(mutate: Callable[[str], str], said: str) -> None:
    errors = contract_errors(mutate(CI.read_text(encoding="utf-8")))
    assert any(said in error for error in errors), errors


# --- the handoff executed --------------------------------------------------------


def _executable(path: Path, body: str) -> Path:
    path.write_text(f"#!{sys.executable}\n{body}", encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR)
    return path


def _stubs(tmp_path: Path, *, leak: bool = False) -> tuple[Path, Path]:
    """A `sudo` that resets the environment as sudo-rs documents -- HOME,
    LOGNAME, USER, SHELL and a default PATH, and nothing of the caller's --
    or, with `leak`, keeps all of it (a `--preserve-env` that worked); and a
    `make` that records what reached it."""
    bindir = tmp_path / "bin"
    bindir.mkdir()
    record = tmp_path / "make.json"
    _executable(
        bindir / "sudo",
        "import os, sys\n"
        "args = sys.argv[1:]\n"
        "user = None\n"
        "while args and args[0].startswith('-'):\n"
        "    arg = args.pop(0)\n"
        "    if arg == '--user':\n"
        "        user = args.pop(0)\n"
        "    elif arg not in ('--non-interactive', '--preserve-env'):\n"
        "        sys.exit(f'stub sudo: {arg}?')\n"
        "if user is None:\n"
        "    sys.exit('stub sudo: no --user')\n"
        f"if {leak!r}:\n"
        "    env = dict(os.environ)\n"
        "else:\n"
        "    kept = ('HOME', 'LOGNAME', 'USER', 'SHELL')\n"
        "    env = {k: os.environ[k] for k in kept if k in os.environ}\n"
        "    env['PATH'] = '/usr/bin:/bin'\n"
        "os.execvpe(args[0], args, env)\n",
    )
    _executable(
        bindir / "make",
        "import json, os, sys\n"
        "dw = {k: v for k, v in os.environ.items() if k.startswith('DW_')}\n"
        f"with open({str(record)!r}, 'w') as out:\n"
        "    json.dump({'argv': sys.argv[1:], 'uid': os.getuid(), 'dw': dw}, out)\n",
    )
    return bindir, record


def _job_command(job: str) -> tuple[list[str], dict[str, str]]:
    """The job's own command and its step's environment -- with the groups
    the runner would have, which this host does not, replaced by this user's
    own primary group, which the stub's session holds."""
    import grp  # POSIX only, as every test that gets here

    task = JOBS[job][0]
    [step] = [s for s in _steps(_jobs(CI.read_text(encoding="utf-8"))[job]) if task in _run(s)]
    argv = shlex.split(_run(step))
    own = grp.getgrgid(os.getgid()).gr_name
    argv = [own if i and argv[i - 1] == "--group" else word for i, word in enumerate(argv)]
    return [sys.executable, *argv[1:]], _env(step)


def _environment(bindir: Path, step: dict[str, str], **more: str) -> dict[str, str]:
    base = {k: os.environ[k] for k in ("HOME", "LOGNAME", "USER", "SHELL") if k in os.environ}
    return {
        **base,
        "PATH": f"{bindir}{os.pathsep}{os.environ.get('PATH', '')}",
        "RUNNER_ENVIRONMENT": "github-hosted",
        **step,
        **more,
    }


@POSIX
@pytest.mark.parametrize("job", sorted(JOBS))
def test_every_value_reaches_the_evidence_in_the_runners_own_session(
    job: str, tmp_path: Path
) -> None:
    bindir, record = _stubs(tmp_path)
    argv, step = _job_command(job)
    done = subprocess.run(
        argv,
        cwd=REPO_ROOT,
        env=_environment(bindir, step),
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    reached = json.loads(record.read_text(encoding="utf-8"))
    assert reached["argv"] == [JOBS[job][0]]
    assert reached["uid"] == os.getuid() != 0
    assert reached["dw"] == {name: step[name] for name in JOBS[job][1]}
    assert "handoff before:" in done.stdout and "handoff after:" in done.stdout
    assert f"handoff after: uid={os.getuid()} " in done.stdout


@POSIX
@pytest.mark.parametrize("job", sorted(JOBS))
def test_the_ci106_command_loses_every_value_under_env_reset(job: str, tmp_path: Path) -> None:
    """The mechanism of CI #106, reproduced: the bare `--preserve-env` under
    an environment reset delivers `make` none of the step's configuration."""
    bindir, record = _stubs(tmp_path)
    _, step = _job_command(job)
    command = CI106.format(task=JOBS[job][0])
    done = subprocess.run(
        ["/bin/sh", "-c", command],
        cwd=REPO_ROOT,
        env=_environment(bindir, step),
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 0, done.stderr
    assert json.loads(record.read_text(encoding="utf-8"))["dw"] == {}


@POSIX
def test_configuration_nobody_handed_over_stops_the_run(tmp_path: Path) -> None:
    """A `sudo` that keeps the whole environment would let a stray value
    through unnoticed; the far side refuses it, and `make` never starts."""
    bindir, record = _stubs(tmp_path, leak=True)
    argv, step = _job_command("sandbox-agent")
    done = subprocess.run(
        argv,
        cwd=REPO_ROOT,
        env=_environment(bindir, step, DW_WORKSPACE_PRIVILEGED="1"),
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 2, done.stdout
    assert "configuration nobody handed over arrived: DW_WORKSPACE_PRIVILEGED" in done.stderr
    assert not record.exists()


@POSIX
@pytest.mark.parametrize(
    ("unset", "more", "said"),
    [
        ("DW_PEER_AS", {}, "DW_PEER_AS is unset before the identity switch"),
        (None, {"DW_BROKER_AS": "dw broker;id"}, "is not an identity, a group or a flag"),
        (None, {"RUNNER_ENVIRONMENT": "self-hosted"}, "only a disposable GitHub-hosted runner"),
    ],
    ids=["unset", "unsafe-value", "privileged-off-a-hosted-runner"],
)
def test_a_missing_or_unsafe_prerequisite_stops_the_run_before_the_switch(
    unset: str | None, more: dict[str, str], said: str, tmp_path: Path
) -> None:
    bindir, record = _stubs(tmp_path)
    argv, step = _job_command("sandbox-agent")
    if unset is not None:
        del step[unset]
    done = subprocess.run(
        argv,
        cwd=REPO_ROOT,
        env=_environment(bindir, step, **more),
        capture_output=True,
        text=True,
        check=False,
    )
    assert done.returncode == 2
    assert said in done.stderr
    assert not record.exists()


# --- the far side's checks, one at a time ------------------------------------------


@POSIX
def test_the_far_side_refuses_another_uid_root_a_lost_or_changed_value_and_a_missing_group() -> (
    None
):
    sys.path.insert(0, str(HANDOFF.parent))
    import ci_handoff

    values = {"DW_BROKER_AS": "dwbroker", "DW_PEER_AS": "dwruntime"}
    names = list(values)
    sealed = ci_handoff.digest(values)
    groups = {"dwworkspace": 10001}
    ok = ci_handoff.after(values, names, sealed, (1001, 1001), 1001, [1001, 10001], groups)
    assert ok == values
    cases = [
        ((values, sealed, (1002, 1002), 1001, [10001]), "not the runner's uid 1001"),
        ((values, sealed, (1001, 0), 1001, [10001]), "running as uid 1001/0"),
        ((values, sealed, (0, 0), 0, [10001]), "would run as root"),
        (({"DW_BROKER_AS": "dwbroker"}, sealed, (1001, 1001), 1001, [10001]), "lost across"),
        (
            ({**values, "DW_PEER_AS": "nobody"}, sealed, (1001, 1001), 1001, [10001]),
            "not the values that left",
        ),
        ((values, sealed, (1001, 1001), 1001, [1001]), "does not hold: dwworkspace (gid 10001)"),
    ]
    for (environ, expected, ids, want, gids), said in cases:
        with pytest.raises(ci_handoff.HandoffError, match=re.escape(said)):
            ci_handoff.after(environ, names, expected, ids, want, gids, groups)
    with pytest.raises(ci_handoff.HandoffError, match="never as root"):
        ci_handoff.before(values, names, [], 0)
    with pytest.raises(ci_handoff.HandoffError, match="only DW_"):
        ci_handoff.before({"HOME": "/root"}, ["HOME"], [], 1001)
