"""CI cannot turn missing M3 authority evidence into a green check.

The cross-uid property of ADR-0041 -- a real second operating-system user is
refused by the uid the kernel reports -- cannot be measured on a one-user
workstation. It is measured in CI, and only there. So the wiring that carries
it is itself security-relevant: a skipped job counted as green, an
`#[ignore]`d test that no job selects, a strict gate that a lost environment
line turns lenient, or a second "identity" that is really the runner's own uid
would each be a green CI that proved nothing.

These tests assert that structure, and only that structure: which jobs exist,
what they run and with which identity, what the aggregate check requires, and
that nothing around the evidence may fail quietly. Like `test_dev_surface.py`
they read the workflow as text -- no YAML parser is a dependency -- through a
deliberately small reader of this repository's own layout. The behaviour
behind the `make` targets is tested directly, through `scripts/dw.py`.

M4a's canonical filesystem evidence (ADR-0042) is held to the same structure:
its own unconditional Linux job, required by the aggregate, and a task that
fails on a missing category, a race campaign that escaped or did not report,
or a case left unexercised that an ordinary runner can exercise.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CI = REPO_ROOT / ".github" / "workflows" / "ci.yml"
FOREIGN_SUITE = REPO_ROOT / "crates" / "dwkd-authority" / "tests" / "transport_foreign.rs"

sys.path.insert(0, str(REPO_ROOT / "scripts"))
import dw  # noqa: E402  - imported after the path is extended

LINUX = sys.platform.startswith("linux")

# The jobs that carry the M3 authority evidence, and the aggregate that gates.
EVIDENCE_JOB = "authority-transport"
EVAL_JOB = "evals"
AGGREGATE_JOB = "ci"
# M4a's canonical filesystem evidence, and the tests that print it.
FILESYSTEM_JOB = "filesystem-canonicalization"
RESOLVER_TESTS = (
    REPO_ROOT / "crates" / "dwkd-authority" / "src" / "resource" / "fs" / "linux" / "tests.rs",
    REPO_ROOT / "crates" / "dwkd-authority" / "tests" / "resource_workspace.rs",
)


# --- a small reader for this workflow's layout -----------------------------


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


def _step_running(job: str, command: str) -> list[str]:
    found = [s for s in _steps(_jobs()[job]) if _run(s) == command]
    assert len(found) == 1, f"job {job} must run `{command}` exactly once; found {len(found)}"
    return found[0]


def _needs() -> list[str]:
    for line in _jobs()[AGGREGATE_JOB]:
        match = re.match(r"\s+needs:\s*\[([^\]]*)\]", line)
        if match:
            return [n.strip() for n in match.group(1).split(",") if n.strip()]
    raise AssertionError("the aggregate job declares no `needs`")


def _second_identity(value: str | None) -> None:
    assert value, "no second identity is configured"
    assert value not in ("root", "0", "$USER", "runner"), (
        f"{value!r} is not an ordinary second user; root is outside the threat model and "
        f"the runner's own account is one identity, not two"
    )


# --- the evidence job ----------------------------------------------------


def test_the_authority_evidence_job_exists_on_linux_and_is_unconditional() -> None:
    job = _jobs().get(EVIDENCE_JOB)
    assert job is not None, f"no `{EVIDENCE_JOB}` job: the cross-uid property is measured nowhere"
    text = "\n".join(_uncommented(line) for line in job)
    assert re.search(r"^    runs-on:\s*ubuntu-latest\s*$", text, re.MULTILINE), "Linux only"
    for forbidden in ("strategy:", "matrix", "continue-on-error"):
        assert forbidden not in text, f"`{forbidden}` in {EVIDENCE_JOB}"
    assert not re.search(r"^\s+if:", text, re.MULTILINE), (
        f"{EVIDENCE_JOB} has a condition: the evidence must run on every push and pull request"
    )


def test_the_evidence_job_runs_the_cross_uid_suite_as_a_real_second_user() -> None:
    step = _step_running(EVIDENCE_JOB, "make authority-transport-evidence")
    _second_identity(_env(step).get("DW_PEER_AS"))
    probe = _step_running(EVIDENCE_JOB, "make authority-write-probe")
    _second_identity(_env(probe).get("DW_PROBE_AS"))


def test_the_evidence_job_runs_the_eval_gate_strictly_with_the_second_user() -> None:
    step = _step_running(EVIDENCE_JOB, "make eval-check")
    env = _env(step)
    assert env.get("DW_EVAL_REQUIRE_EXERCISED") == "1"
    _second_identity(env.get("DW_PEER_AS"))


def test_the_eval_job_is_strict_too() -> None:
    job = "\n".join(_uncommented(line) for line in _jobs()[EVAL_JOB])
    assert re.search(r"^    runs-on:\s*ubuntu-latest\s*$", job, re.MULTILINE)
    env = _env(_step_running(EVAL_JOB, "make eval-check"))
    assert env.get("DW_EVAL_REQUIRE_EXERCISED") == "1"
    _second_identity(env.get("DW_PEER_AS"))


def test_nothing_around_the_evidence_may_fail_quietly() -> None:
    """No `continue-on-error`, no shell escape hatch, and no step condition --
    except the evals job's upload of its results when it has already failed,
    which cannot change the job's outcome."""
    for name in (EVIDENCE_JOB, EVAL_JOB, FILESYSTEM_JOB, AGGREGATE_JOB):
        text = "\n".join(_uncommented(line) for line in _jobs()[name])
        for hatch in ("continue-on-error", "|| true", "|| :", "set +e", "exit 0"):
            assert hatch not in text, f"`{hatch}` in job {name}"
        for step in _steps(_jobs()[name]):
            body = "\n".join(_uncommented(line) for line in step)
            condition = re.search(r"^\s+if:\s*(.*)$", body, re.MULTILINE)
            if condition is None:
                continue
            assert condition.group(1).strip() == "failure()", f"{name}: {condition.group(0)}"
            assert "actions/upload-artifact@" in body, (
                f"{name}: only a results upload may be conditional"
            )


# --- the aggregate ---------------------------------------------------------


def test_every_job_is_required_by_the_aggregate_check() -> None:
    """No orphan job: a security job the aggregate does not need is advisory."""
    jobs = set(_jobs()) - {AGGREGATE_JOB}
    needs = set(_needs())
    assert EVIDENCE_JOB in needs and EVAL_JOB in needs and FILESYSTEM_JOB in needs
    assert jobs == needs, f"not required: {sorted(jobs - needs)}; unknown: {sorted(needs - jobs)}"


def test_the_aggregate_counts_only_success() -> None:
    """`skipped` is not success: a skipped evidence job proved nothing."""
    text = "\n".join(_uncommented(line) for line in _jobs()[AGGREGATE_JOB])
    assert re.search(r"^    if:\s*always\(\)\s*$", text, re.MULTILINE), (
        "the aggregate must run when a job it needs failed, and fail"
    )
    assert '!= "success"' in text, "the aggregate must require success, not merely no failure"
    assert "failure\\|cancelled" not in text, "matching failures only lets `skipped` through"
    assert "NEEDS: ${{ toJSON(needs) }}" in text


# --- the task behind `make authority-transport-evidence` -------------------


def test_the_foreign_tests_are_ignored_by_default_and_selected_by_name() -> None:
    """`cargo test` may skip them; the evidence task may not. Every name the
    task selects is an `#[ignore]`d test that exists."""
    source = FOREIGN_SUITE.read_text(encoding="utf-8")
    assert len(dw.FOREIGN_TESTS) == 2
    for name in dw.FOREIGN_TESTS:
        module, function = name.split("::")
        assert module == "linux"
        assert re.search(r"#\[ignore = [^\]]*\]\s*fn " + re.escape(function) + r"\(\)", source), (
            f"{function} is not an #[ignore]d test in {FOREIGN_SUITE.name}"
        )


def test_the_task_and_the_eval_expect_the_same_foreign_cases() -> None:
    from direwolf_evals.runners import authority

    assert set(dw.FOREIGN_CASES) == set(authority.PEER_CASES)


@pytest.mark.parametrize(
    ("environ", "strict"),
    [
        ({}, False),
        ({"DW_EVAL_REQUIRE_EXERCISED": "0"}, False),
        ({"DW_EVAL_REQUIRE_EXERCISED": "1"}, True),
        ({"DW_EVAL_REQUIRE_EXERCISED": "true"}, True),  # a typo is strict, not lenient
        ({"GITHUB_ACTIONS": "true"}, True),  # CI is strict even if the line is lost
        ({"GITHUB_ACTIONS": "true", "DW_EVAL_REQUIRE_EXERCISED": "0"}, True),
    ],
)
def test_the_eval_gate_fails_closed(environ: dict[str, str], strict: bool) -> None:
    assert dw.eval_gate_is_strict(environ) is strict


def _libtest(passed: int, cases: tuple[str, ...]) -> str:
    lines = ["running 2 tests"]
    lines += [
        f'test linux::x ... DWKP-EVIDENCE {{"suite":"peer","case":"{c}","layer":"peer-gate",'
        f'"contained":true,"audited":true,"server":"/t/dwkd-authority"}}'
        for c in cases
    ]
    lines.append(
        f"test result: ok. {passed} passed; 0 failed; 0 ignored; 0 measured; "
        f"{2 - passed} filtered out; finished in 1.00s"
    )
    return "\n".join(lines)


def test_a_cross_uid_run_that_selected_nothing_is_not_evidence() -> None:
    with pytest.raises(dw.TaskError, match="did not run both"):
        dw.require_foreign_evidence(_libtest(0, ()))
    with pytest.raises(dw.TaskError, match="did not run both"):
        dw.require_foreign_evidence(_libtest(1, dw.FOREIGN_CASES))
    with pytest.raises(dw.TaskError, match="did not report: foreign-uid-flood"):
        dw.require_foreign_evidence(
            _libtest(2, tuple(c for c in dw.FOREIGN_CASES if c != "foreign-uid-flood"))
        )
    uncontained = _libtest(2, dw.FOREIGN_CASES).replace(
        '"case":"foreign-uid-impersonation","layer":"peer-gate","contained":true',
        '"case":"foreign-uid-impersonation","layer":"peer-gate","contained":false',
    )
    with pytest.raises(dw.TaskError, match="foreign-uid-impersonation"):
        dw.require_foreign_evidence(uncontained)
    dw.require_foreign_evidence(_libtest(2, dw.FOREIGN_CASES))


class _Recorder:
    def __init__(self) -> None:
        self.commands: list[tuple[str, ...]] = []

    def run(self, *command: str, **_: object) -> None:
        self.commands.append(command)

    def captured(self, *command: str) -> str:
        self.commands.append(command)
        return _libtest(2, dw.FOREIGN_CASES)

    def uvrun(self, module: str, *args: str) -> None:
        self.commands.append(("uv", module, *args))


@pytest.mark.skipif(not LINUX, reason="the task runs only where the server does")
def test_the_evidence_task_proves_the_identity_first_and_selects_the_ignored_tests(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorder = _Recorder()
    proven_after: list[int] = []

    def second_identity(variable: str) -> tuple[str, int, int]:
        assert variable == "DW_PEER_AS"
        proven_after.append(len(recorder.commands))
        return "nobody", 1001, 65534

    monkeypatch.setenv("DW_PEER_AS", "nobody")
    monkeypatch.setattr(dw, "run", recorder.run)
    monkeypatch.setattr(dw, "run_captured", recorder.captured)
    monkeypatch.setattr(dw, "uvrun", recorder.uvrun)
    monkeypatch.setattr(dw, "second_identity", second_identity)
    dw.task_authority_transport_evidence()
    assert proven_after == [0], "the second identity is proven before anything runs"
    foreign = [c for c in recorder.commands if "transport_foreign" in c]
    assert len(foreign) == 1
    for flag in ("--ignored", "--exact", *dw.FOREIGN_TESTS):
        assert flag in foreign[0], f"the cross-uid run lacks {flag}"


@pytest.mark.skipif(not LINUX, reason="the task runs only where the server does")
def test_the_evidence_task_without_a_second_user_is_not_exercised(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorder = _Recorder()
    monkeypatch.delenv("DW_PEER_AS", raising=False)
    monkeypatch.setattr(dw, "run", recorder.run)
    monkeypatch.setattr(dw, "run_captured", recorder.captured)
    monkeypatch.setattr(dw, "uvrun", recorder.uvrun)
    with pytest.raises(dw.TaskError, match="NOT EXERCISED"):
        dw.task_authority_transport_evidence()
    assert not [c for c in recorder.commands if "transport_foreign" in c]


class _Switched:
    def __init__(self, returncode: int, stdout: str) -> None:
        self.returncode = returncode
        self.stdout = stdout
        self.stderr = "" if returncode == 0 else "sudo: a password is required"


@pytest.mark.skipif(not LINUX, reason="a second identity is a Linux precondition")
@pytest.mark.parametrize(
    ("switched", "message"),
    [
        (_Switched(0, "1001\n"), "one identity, not two"),
        (_Switched(0, "0\n"), "outside the threat model"),
        (_Switched(1, ""), "NOT EXERCISED"),
        (_Switched(0, "nobody\n"), "NOT EXERCISED"),
    ],
    ids=["same-uid", "root", "sudo-refused", "unreadable"],
)
def test_a_second_identity_must_be_a_different_ordinary_uid(
    monkeypatch: pytest.MonkeyPatch, switched: _Switched, message: str
) -> None:
    monkeypatch.setenv("DW_PEER_AS", "nobody")
    monkeypatch.setattr(shutil, "which", lambda _: "/usr/bin/sudo")
    monkeypatch.setattr(os, "geteuid", lambda: 1001)
    monkeypatch.setattr(subprocess, "run", lambda *_, **__: switched)
    with pytest.raises(dw.TaskError, match=message):
        dw.second_identity("DW_PEER_AS")


@pytest.mark.skipif(not LINUX, reason="a second identity is a Linux precondition")
def test_a_second_identity_is_accepted_by_its_numbers(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("DW_PEER_AS", "nobody")
    monkeypatch.setattr(shutil, "which", lambda _: "/usr/bin/sudo")
    monkeypatch.setattr(os, "geteuid", lambda: 1001)
    monkeypatch.setattr(subprocess, "run", lambda *_, **__: _Switched(0, "65534\n"))
    assert dw.second_identity("DW_PEER_AS") == ("nobody", 1001, 65534)


# --- M4a: the canonical filesystem evidence --------------------------------


def test_the_filesystem_evidence_job_exists_on_linux_and_is_unconditional() -> None:
    job = _jobs().get(FILESYSTEM_JOB)
    assert job is not None, f"no `{FILESYSTEM_JOB}` job: the resolver is measured nowhere"
    text = "\n".join(_uncommented(line) for line in job)
    assert re.search(r"^    runs-on:\s*ubuntu-latest\s*$", text, re.MULTILINE), "Linux only"
    for forbidden in ("strategy:", "matrix", "continue-on-error"):
        assert forbidden not in text, f"`{forbidden}` in {FILESYSTEM_JOB}"
    assert not re.search(r"^\s+if:", text, re.MULTILINE), f"{FILESYSTEM_JOB} has a condition"
    _step_running(FILESYSTEM_JOB, "make filesystem-canonicalization-evidence")


def _fs_line(category: str, case: str, outcome: str, count: int = 1) -> str:
    return (
        f'FS-EVIDENCE {{"category":"{category}","case":"{case}",'
        f'"outcome":"{outcome}","count":{count}}}'
    )


def _fs_complete() -> list[str]:
    lines = [
        _fs_line(category, "a-case", "resolved")
        for category in dw.FS_EVIDENCE_CATEGORIES
        if category != "toctou"
    ]
    lines += [
        _fs_line("toctou", case, "escaped-0-unexpected-0-resolved-9-refused-1-swaps-500", 10)
        for case in dw.FS_TOCTOU_CASES
    ]
    return lines


def test_complete_filesystem_evidence_passes_and_lists_what_was_not_exercised(
    capsys: pytest.CaptureFixture[str],
) -> None:
    environmental = _fs_line("unicode", "casefold-filesystem", "not-exercised:needs-casefold", 0)
    dw.require_filesystem_evidence("\n".join([*_fs_complete(), environmental]))
    out = capsys.readouterr().out
    assert "NOT EXERCISED  unicode/casefold-filesystem" in out
    assert "complete" in out


def _without(text: str) -> Callable[[list[str]], list[str]]:
    return lambda lines: [line for line in lines if text not in line]


def _replacing(old: str, new: str) -> Callable[[list[str]], list[str]]:
    return lambda lines: [line.replace(old, new) for line in lines]


def _adding(extra: str) -> Callable[[list[str]], list[str]]:
    return lambda lines: [*lines, extra]


def _only_unexercised(category: str) -> Callable[[list[str]], list[str]]:
    marker = f'"category":"{category}"'
    return lambda lines: [
        line.replace('"resolved"', '"not-exercised:no-procfs"') if marker in line else line
        for line in lines
    ]


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (_without('"category":"symlink"'), "category `symlink` has no exercised case"),
        (_without("leaf-replaced"), "race campaign `leaf-replaced` did not report"),
        (_replacing("escaped-0-", "escaped-1-"), "`root-path-exchange`: escaped-1"),
        (_replacing("unexpected-0-", "unexpected-2-"), "unexpected-2"),
        (
            _adding(_fs_line("toctou", "extra", "not-exercised:no-renameat2-exchange", 0)),
            "toctou/extra was not exercised",
        ),
        (_only_unexercised("magic-link"), "category `magic-link` has no exercised case"),
        (_adding("FS-EVIDENCE {not json"), "unreadable evidence line"),
        (_adding('FS-EVIDENCE {"category":"x","count":"1"}'), "malformed evidence line"),
        (lambda _: [], "category `normal` has no exercised case"),
    ],
    ids=[
        "missing-category",
        "missing-race",
        "escape",
        "unexpected-object",
        "race-not-exercised",
        "category-only-unexercised",
        "unreadable",
        "malformed",
        "nothing",
    ],
)
def test_incomplete_filesystem_evidence_fails(
    mutate: Callable[[list[str]], list[str]],
    message: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    with pytest.raises(dw.TaskError, match=re.escape(message)):
        dw.require_filesystem_evidence("\n".join(mutate(_fs_complete())))
    capsys.readouterr()


def test_the_task_names_what_the_resolver_tests_print() -> None:
    """The contract between `dw.py` and the Rust tests, checked on the source:
    every race campaign and environmental case the task knows by name, and
    every category it requires, is one a test prints. A renamed case would
    otherwise fail only in CI, or -- for an environmental one -- never."""
    source = "\n".join(path.read_text(encoding="utf-8") for path in RESOLVER_TESTS)
    for case in (*dw.FS_TOCTOU_CASES, *dw.FS_ENVIRONMENTAL):
        assert f'"{case}"' in source, f"no resolver test prints `{case}`"
    for category in dw.FS_EVIDENCE_CATEGORIES:
        emitted = f'evidence("{category}"' in source or f'"{category}",' in source
        emitted = emitted or f'\\"category\\":\\"{category}\\"' in source
        assert emitted, f"no resolver test emits category `{category}`"


def test_the_filesystem_task_off_linux_is_not_exercised_and_runs_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recorder = _Recorder()
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(dw, "run", recorder.run)
    monkeypatch.setattr(dw, "run_captured", recorder.captured)
    monkeypatch.setattr(dw, "uvrun", recorder.uvrun)
    with pytest.raises(dw.TaskError, match="NOT EXERCISED"):
        dw.task_filesystem_canonicalization_evidence()
    assert recorder.commands == []


def test_the_filesystem_task_checks_what_both_suites_printed(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The resolver's lib tests and the state suite are captured and checked
    together; `state` comes only from the second, so losing it fails."""
    complete = "\n".join(line for line in _fs_complete() if '"state"' not in line)
    state = _fs_line("state", "run-resolves", "resolved")
    outputs = iter([complete, state])
    commands: list[tuple[str, ...]] = []

    def captured(*command: str) -> str:
        commands.append(command)
        return next(outputs)

    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(dw, "run_captured", captured)
    monkeypatch.setattr(dw, "uvrun", lambda *_: None)
    dw.task_filesystem_canonicalization_evidence()
    assert [c for c in commands if "resource::fs::" in c], commands
    assert [c for c in commands if "resource_workspace" in c], commands
    outputs = iter([complete, ""])
    with pytest.raises(dw.TaskError, match="category `state` has no exercised case"):
        dw.task_filesystem_canonicalization_evidence()
    capsys.readouterr()
