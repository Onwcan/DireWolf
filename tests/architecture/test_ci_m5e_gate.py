"""M5e.6's first slice (G1): every M5 evidence task keeps what it judged, and
its job seals and uploads it for the gate, or the gate has nothing to judge.

The M5 gate (M5E6_PREPARATION_HANDOFF.md §§5-6) re-judges each M5 evidence
task's own output in the run that produced it. G1 is what it will read:

* each task of the gate (`dw.M5E_GATE_TASKS`) is one job of `ci.yml` that runs
  it, and no job runs it that the table does not name;
* each such job, right after its evidence step, runs `make m5e-evidence-bundle`
  and uploads `target/m5e-evidence/` with the one pinned upload action,
  `if-no-files-found: error`, kept 7 days -- neither step under an `if:`, so a
  failed task's job never uploads, and an upload that finds nothing fails;
* what a task keeps is exactly what `require_attributed_evidence` judged and
  passed -- its table, prefix and text -- with its cleanup census, written by
  the task runner after the task returned (`save_judged_evidence`), never on
  failure;
* the bundle is sealed only on a disposable GitHub-hosted runner, in the task's
  own job, over exactly one task's record, each file at its digest and nothing
  beside it, with the run's id, attempt and commit.

Each holds with a negative control. Nothing here runs a container or the gate:
the bundles themselves are the hosted jobs' alone.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CI = REPO_ROOT / ".github" / "workflows" / "ci.yml"
sys.path.insert(0, str(REPO_ROOT / "scripts"))
import dw  # noqa: E402  - imported after the path is extended

UPLOAD = "actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9"
BUNDLE = "make m5e-evidence-bundle"
SHA = "0123456789abcdef0123456789abcdef01234567"


# --- the workflow ---------------------------------------------------------------


def _jobs(text: str) -> dict[str, list[str]]:
    lines = text.splitlines()
    jobs: dict[str, list[str]] = {}
    current: str | None = None
    for line in lines[lines.index("jobs:") + 1 :]:
        match = re.fullmatch(r"  ([a-z][a-z0-9-]*):\s*", line)
        if match:
            current = match.group(1)
            jobs[current] = []
        elif current is not None:
            jobs[current].append(line)
    return jobs


def _steps(job: list[str]) -> list[list[str]]:
    """The job's steps, each its lines, comments dropped."""
    steps: list[list[str]] = []
    for line in job:
        if line.lstrip().startswith("#") or not line.strip():
            continue
        if re.match(r"      - ", line):
            steps.append([line])
        elif steps and line.startswith("        "):
            steps[-1].append(line)
    return steps


def _gate_problems(text: str, table: dict[str, str]) -> list[str]:
    """Every way the workflow fails to keep the gate's evidence."""
    problems: list[str] = []
    jobs = _jobs(text)
    for task, job in table.items():
        if job not in jobs:
            problems.append(f"{task}: no job {job!r}")
            continue
        steps = _steps(jobs[job])
        runs = [i for i, step in enumerate(steps) if f"make {task}" in step[0]]
        if len(runs) != 1:
            problems.append(f"{job}: runs {task} {len(runs)} times, not once")
            continue
        at = runs[0]
        bundle = steps[at + 1] if len(steps) > at + 1 else [""]
        upload = steps[at + 2] if len(steps) > at + 2 else [""]
        if bundle[0].strip() != f"- run: {BUNDLE}" or len(bundle) != 1:
            problems.append(f"{job}: the step after its evidence is not `{BUNDLE}` alone")
        head = upload[0].strip()
        if not head.startswith(f"- uses: {UPLOAD}"):
            problems.append(f"{job}: the bundle is not uploaded by the pinned upload action")
        body = {line.strip().split(":", 1)[0]: line.strip() for line in upload[1:]}
        wanted = {
            "name": f"name: m5e-evidence-{job}",
            "path": "path: target/m5e-evidence/",
            "if-no-files-found": "if-no-files-found: error",
            "retention-days": "retention-days: 7",
        }
        for key, line in wanted.items():
            if body.get(key) != line:
                problems.append(f"{job}: the upload's {key} is not `{line}`")
        if any(line.strip().startswith("if:") for line in [*bundle, *upload]):
            problems.append(f"{job}: the bundle or its upload runs under an `if:`")
    for job, lines in jobs.items():
        bundles = sum(1 for step in _steps(lines) if step[0].strip() == f"- run: {BUNDLE}")
        if bundles and job not in table.values():
            problems.append(f"{job}: seals a bundle but runs no task of the gate")
        for task in table:
            if job != table[task] and any(f"make {task}" in step[0] for step in _steps(lines)):
                problems.append(f"{job}: runs {task}, which the gate keeps from {table[task]!r}")
    return problems


def test_every_task_of_the_gate_keeps_and_uploads_its_evidence() -> None:
    assert len(dw.M5E_GATE_TASKS) == 9
    assert set(dw.M5E_GATE_TASKS) <= set(dw.TASKS)
    assert "m5e-evidence-bundle" in dw.TASKS
    assert _gate_problems(CI.read_text(encoding="utf-8"), dw.M5E_GATE_TASKS) == []


def _mutated(old: str, new: str) -> str:
    text = CI.read_text(encoding="utf-8")
    assert text.count(old) >= 1, f"the mutation's target is not in the workflow: {old!r}"
    return text.replace(old, new, 1)


@pytest.mark.parametrize(
    ("change", "said"),
    [
        ("bundle-dropped", "is not `make m5e-evidence-bundle` alone"),
        ("upload-unpinned", "not uploaded by the pinned upload action"),
        ("upload-always", "under an `if:`"),
        ("upload-tolerates-nothing", "if-no-files-found"),
        ("upload-kept-longer", "retention-days"),
        ("upload-renamed", "name"),
        ("table-names-another-job", "no job"),
    ],
)
def test_a_gate_job_that_keeps_less_fails(change: str, said: str) -> None:
    table = dict(dw.M5E_GATE_TASKS)
    upload = (
        f"      - uses: {UPLOAD} # v7.0.2\n"
        "        with:\n"
        "          name: m5e-evidence-sandbox-foundation\n"
    )
    if change == "bundle-dropped":
        text = _mutated(f"      - run: {BUNDLE}\n", "")
    elif change == "upload-unpinned":
        text = _mutated(upload, upload.replace(UPLOAD, "actions/upload-artifact@v7"))
    elif change == "upload-always":
        text = _mutated(
            upload, upload.replace("        with:\n", "        if: always()\n        with:\n")
        )
    elif change == "upload-tolerates-nothing":
        text = _mutated("if-no-files-found: error", "if-no-files-found: warn")
    elif change == "upload-kept-longer":
        kept = "          if-no-files-found: error\n          retention-days: "
        text = _mutated(f"{kept}7\n", f"{kept}90\n")
    elif change == "upload-renamed":
        text = _mutated("name: m5e-evidence-sandbox-foundation", "name: evidence")
    elif change == "table-names-another-job":
        text = CI.read_text(encoding="utf-8")
        table["sandbox-foundation-evidence"] = "sandbox-founding"
    else:
        raise AssertionError(change)
    problems = _gate_problems(text, table)
    assert any(said in problem for problem in problems), (change, problems)


# --- what a task keeps --------------------------------------------------------------


def _line(suite: str, case: str) -> str:
    record = {"suite": suite, "case": case, "outcome": "x", "level": "l", "enforcement": "e"}
    return dw.SANDBOX_EVIDENCE_PREFIX + json.dumps(record)


def test_only_a_judgement_that_passed_is_kept(monkeypatch: pytest.MonkeyPatch) -> None:
    """`require_attributed_evidence` keeps its table, prefix and text only
    after it passed; one that fails keeps nothing."""
    monkeypatch.setattr(dw, "_JUDGED", [])
    with pytest.raises(dw.TaskError):
        dw.require_attributed_evidence("no evidence at all", dw.RESTART_CASES)
    assert dw._JUDGED == []
    source = dw.require_attributed_evidence.__code__
    assert "_JUDGED" in source.co_names and "_table_name" in source.co_names
    assert dw._table_name(dw.RESTART_CASES) == "RESTART_CASES"
    assert dw._table_name((("suite", "case"),)) is None


def test_the_task_runner_keeps_a_gate_task_only_after_it_passed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kept: list[str] = []
    monkeypatch.setattr(dw, "save_judged_evidence", lambda task: kept.append(task))

    def fails() -> None:
        raise dw.TaskError("the evidence failed")

    monkeypatch.setitem(dw.TASKS, "sandbox-restart-evidence", fails)
    assert dw.main(["sandbox-restart-evidence"]) == 1
    assert kept == [], "a failed task keeps nothing"
    monkeypatch.setitem(dw.TASKS, "sandbox-restart-evidence", lambda: None)
    assert dw.main(["sandbox-restart-evidence"]) == 0
    assert kept == ["sandbox-restart-evidence"]
    monkeypatch.setitem(dw.TASKS, "lint", lambda: None)
    assert dw.main(["lint"]) == 0
    assert kept == ["sandbox-restart-evidence"], "a task outside the gate keeps nothing"


def _kept(tmp_path: Path, task: str = "sandbox-restart-evidence") -> Path:
    judged = [("RESTART_CASES", dw.SANDBOX_EVIDENCE_PREFIX, "line one\nline two\n")]
    cleanup = ["cleanup: no evidence container remains; 0 pre-existing kept"]
    return dw.save_judged_evidence(task, tmp_path, judged, cleanup)


HOSTED = {
    "GITHUB_ACTIONS": "true",
    "RUNNER_ENVIRONMENT": "github-hosted",
    "GITHUB_JOB": "sandbox-restart",
    "GITHUB_RUN_ID": "42612635209",
    "GITHUB_RUN_ATTEMPT": "1",
    "GITHUB_SHA": SHA,
    "GITHUB_REF": "refs/heads/main",
    "RUNNER_OS": "Linux",
    "ImageOS": "ubuntu26",
    "ImageVersion": "20261101.186.1",
}


def test_a_kept_record_seals_into_a_bundle(tmp_path: Path) -> None:
    directory = _kept(tmp_path)
    kept = json.loads((directory / "judged.json").read_text(encoding="utf-8"))
    data = (directory / "judged-0.txt").read_bytes()
    assert kept["judged"][0]["sha256"] == hashlib.sha256(data).hexdigest()
    record = dw.m5e_bundle_record(HOSTED, tmp_path)
    assert record["task"] == "sandbox-restart-evidence" and record["job"] == "sandbox-restart"
    assert (record["run_id"], record["run_attempt"], record["sha"]) == ("42612635209", "1", SHA)
    assert record["runner"] == {
        "environment": "github-hosted",
        "os": "Linux",
        "image": "ubuntu26",
        "image_version": "20261101.186.1",
    }
    assert record["exit"] == 0 and record["judged"] == kept["judged"]


@pytest.mark.parametrize(
    ("change", "said"),
    [
        ("not-hosted", "NOT EXERCISED"),
        ("self-hosted", "NOT EXERCISED"),
        ("another-job", "sealed by the 'sandbox-restart' job"),
        ("two-tasks", "must hold one task's kept evidence"),
        ("nothing-kept", "nothing kept"),
        ("byte-changed", "is not the output the task judged"),
        ("file-beside", "files beside"),
        ("repeated-key", "unreadable"),
        ("unknown-table", "is not a case table"),
        ("no-census", "kept no cleanup census"),
        ("no-commit", "the run's commit"),
        ("no-attempt", "id or attempt"),
    ],
)
def test_a_bundle_that_proves_less_is_refused(tmp_path: Path, change: str, said: str) -> None:
    environ = dict(HOSTED)
    root = tmp_path / "kept"
    directory = _kept(root)
    record_path = directory / "judged.json"
    if change == "not-hosted":
        environ.pop("GITHUB_ACTIONS")
    elif change == "self-hosted":
        environ["RUNNER_ENVIRONMENT"] = "self-hosted"
    elif change == "another-job":
        environ["GITHUB_JOB"] = "sandbox-egress"
    elif change == "two-tasks":
        _kept(root, "sandbox-capacity-evidence")
    elif change == "nothing-kept":
        root = tmp_path / "absent"
    elif change == "byte-changed":
        (directory / "judged-0.txt").write_bytes(b"line one\nline 2wo\n")
    elif change == "file-beside":
        (directory / "extra.txt").write_text("x", encoding="utf-8")
    elif change == "repeated-key":
        text = record_path.read_text(encoding="utf-8")
        record_path.write_text(
            text.replace('"task":', '"task": "x",\n  "task":', 1), encoding="utf-8"
        )
    elif change == "unknown-table":
        kept = json.loads(record_path.read_text(encoding="utf-8"))
        kept["judged"][0]["table"] = "NO_SUCH_CASES"
        record_path.write_text(json.dumps(kept), encoding="utf-8")
    elif change == "no-census":
        kept = json.loads(record_path.read_text(encoding="utf-8"))
        kept["cleanup"] = []
        record_path.write_text(json.dumps(kept), encoding="utf-8")
    elif change == "no-commit":
        environ["GITHUB_SHA"] = "main"
    elif change == "no-attempt":
        environ.pop("GITHUB_RUN_ATTEMPT")
    else:
        raise AssertionError(change)
    with pytest.raises(dw.TaskError, match=re.escape(said)):
        dw.m5e_bundle_record(environ, root)


def test_nothing_is_kept_that_proves_nothing(tmp_path: Path) -> None:
    cleanup = ["cleanup: no evidence container remains; 0 pre-existing kept"]
    judged = [("RESTART_CASES", dw.SANDBOX_EVIDENCE_PREFIX, "x")]
    with pytest.raises(dw.TaskError, match="not a task of the M5 gate"):
        dw.save_judged_evidence("lint", tmp_path, judged, cleanup)
    with pytest.raises(dw.TaskError, match="judged no evidence"):
        dw.save_judged_evidence("sandbox-restart-evidence", tmp_path, [], cleanup)
    with pytest.raises(dw.TaskError, match="no cleanup census"):
        dw.save_judged_evidence("sandbox-restart-evidence", tmp_path, judged, [])
    with pytest.raises(dw.TaskError, match="no name"):
        dw.save_judged_evidence("sandbox-restart-evidence", tmp_path, [(None, "p", "x")], cleanup)


def test_every_task_of_the_gate_reports_its_census_for_the_gate() -> None:
    """Each task of the gate reports its census through `report_cleanup`, so
    the gate reads the line the task printed."""
    import inspect

    for task in dw.M5E_GATE_TASKS:
        source = inspect.getsource(dw.TASKS[task])
        if task == "sandbox-workspace-evidence":
            source = inspect.getsource(dw._sandbox_workspace_evidence)
        assert "report_cleanup(" in source, task
        assert "{GREEN}cleanup:" not in source, task
