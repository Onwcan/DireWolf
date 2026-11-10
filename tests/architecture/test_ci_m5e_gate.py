"""M5e.6, the M5 gate: every M5 evidence task keeps what it judged, its job
seals and uploads it, and the `m5e-gate` job judges every bundle again.

The M5 gate (M5E6_PREPARATION_HANDOFF.md §§5-6) re-judges each M5 evidence
task's own output in the run that produced it:

* each task of the gate (`dw.M5E_GATE_TASKS`) is one job of `ci.yml` that runs
  it, and no job runs it that the table does not name (G1, and G1b for the four
  tasks that judge their own output: agent, release, net.http and the M5 eval
  suites);
* each such job, right after its last run of the task, runs `make
  m5e-evidence-bundle` and uploads `target/m5e-evidence/<task>/` -- its own
  task's directory and nothing else -- with the one pinned upload action,
  `if-no-files-found: error`, kept 7 days, neither step under an `if:`;
* what a task keeps is exactly what its judge passed -- the judge, its table,
  prefix and text -- with its cleanup census, written by the task runner after
  the task returned (`save_judged_evidence`), never on failure, and whatever an
  earlier process or a restored cache left is forgotten before the task runs;
* the bundle is sealed only on a disposable GitHub-hosted runner, for the task
  its job runs, each file at its digest and nothing beside it;
* the `m5e-gate` job (G2) needs every job of the gate, is required by `ci`,
  downloads only this run's bundles with the one pinned download action, and
  `make m5e-gate-check` judges every bundle again: this run, this commit, a
  GitHub-hosted runner, the expected judgements, the whole inventory less the
  tables not yet required, a clean census; then the M5e acceptance verdict,
  NOT READY until M5e.5 is accepted;
* the `m5e-gate` eval (G3) runs in that job and is pending until `M5e` is
  available.

Each holds with a negative control. Nothing here runs a container: the
bundles themselves are the hosted jobs' alone, and the gate's unit tests judge
synthetic bundles built here.
"""

from __future__ import annotations

import ast
import hashlib
import inspect
import json
import re
import shutil
import sys
import textwrap
import tomllib
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CI = REPO_ROOT / ".github" / "workflows" / "ci.yml"
sys.path.insert(0, str(REPO_ROOT / "scripts"))
import dw  # noqa: E402  - imported after the path is extended

UPLOAD = "actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9"
DOWNLOAD = "actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333"
CHECKOUT = "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1"
BUNDLE = "make m5e-evidence-bundle"
GATE = "make m5e-gate-check"
GATE_EVAL = (
    "uv run --frozen python -m direwolf_evals check --all --suite m5e-gate --require-exercised"
)
SHA = "0123456789abcdef0123456789abcdef01234567"
CENSUS = "cleanup: no evidence container remains; 0 pre-existing kept"


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


def _runs(step: list[str], task: str) -> bool:
    return any(re.search(rf"\bmake {re.escape(task)}(\s|$)", line) for line in step)


def _gate_problems(text: str, table: dict[str, str]) -> list[str]:
    """Every way the workflow fails to keep the gate's evidence."""
    problems: list[str] = []
    jobs = _jobs(text)
    for task, job in table.items():
        if job not in jobs:
            problems.append(f"{task}: no job {job!r}")
            continue
        steps = _steps(jobs[job])
        runs = [i for i, step in enumerate(steps) if _runs(step, task)]
        if not runs:
            problems.append(f"{job}: never runs {task}")
            continue
        at = runs[-1]
        bundle = steps[at + 1] if len(steps) > at + 1 else [""]
        upload = steps[at + 2] if len(steps) > at + 2 else [""]
        if bundle[0].strip() != f"- run: {BUNDLE}" or len(bundle) != 1:
            problems.append(f"{job}: the step after its last evidence run is not `{BUNDLE}` alone")
        head = upload[0].strip()
        if not head.startswith(f"- uses: {UPLOAD}"):
            problems.append(f"{job}: the bundle is not uploaded by the pinned upload action")
        body = {line.strip().split(":", 1)[0]: line.strip() for line in upload[1:]}
        wanted = {
            "name": f"name: m5e-evidence-{job}",
            "path": f"path: target/m5e-evidence/{task}/",
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
        if bundles > 1:
            problems.append(f"{job}: seals {bundles} bundles")
        for task in table:
            if job != table[task] and any(_runs(step, task) for step in _steps(lines)):
                problems.append(f"{job}: runs {task}, which the gate keeps from {table[task]!r}")
    return problems


def test_every_task_of_the_gate_keeps_and_uploads_its_evidence() -> None:
    assert len(dw.M5E_GATE_TASKS) == 13
    assert set(dw.M5E_GATE_TASKS) <= set(dw.TASKS)
    assert len(set(dw.M5E_GATE_TASKS.values())) == 13
    assert "m5e-evidence-bundle" in dw.TASKS and "m5e-gate-check" in dw.TASKS
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
        ("upload-everything-kept", "path"),
        ("bundle-before-the-last-run", "after its last evidence run"),
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
    elif change == "upload-everything-kept":
        text = _mutated(
            "path: target/m5e-evidence/sandbox-foundation-evidence/", "path: target/m5e-evidence/"
        )
    elif change == "bundle-before-the-last-run":
        # A run of the task after the upload: what was uploaded is not what
        # the job's last run judged, and that run's task runner forgets it.
        uploaded = (
            "          name: m5e-evidence-net-http\n"
            "          path: target/m5e-evidence/net-http-evidence/\n"
            "          if-no-files-found: error\n"
            "          retention-days: 7\n"
        )
        text = _mutated(uploaded, uploaded + "      - run: make net-http-evidence\n")
    elif change == "table-names-another-job":
        text = CI.read_text(encoding="utf-8")
        table["sandbox-foundation-evidence"] = "sandbox-founding"
    else:
        raise AssertionError(change)
    problems = _gate_problems(text, table)
    assert any(said in problem for problem in problems), (change, problems)


def _gate_job_problems(text: str, table: dict[str, str]) -> list[str]:
    """Every way the `m5e-gate` job fails to be the required, unconditional
    gate over this run's bundles."""
    problems: list[str] = []
    jobs = _jobs(text)
    job = jobs.get(dw.M5E_GATE_JOB)
    if job is None:
        return [f"no job {dw.M5E_GATE_JOB!r}"]
    head = [line for line in job if not line.startswith("      ") and line.strip()]
    head = [line for line in head if not line.lstrip().startswith("#")]
    for hatch in ("if:", "continue-on-error", "strategy:", "matrix:", "services:"):
        if any(line.strip().startswith(hatch) for line in head):
            problems.append(f"the gate job has `{hatch}`")
    needs = next((line for line in head if line.strip().startswith("needs:")), "")
    named = re.findall(r"[a-z][a-z0-9-]*", needs.split(":", 1)[1]) if needs else []
    if sorted(named) != sorted(table.values()):
        problems.append(f"the gate job needs {sorted(named)}, not every job of the gate")
    aggregate = next((line for line in jobs.get("ci", []) if line.strip().startswith("needs:")), "")
    if dw.M5E_GATE_JOB not in re.findall(r"[a-z][a-z0-9-]*", aggregate):
        problems.append("the `ci` job does not need the gate job")
    steps = _steps(job)
    firsts = [step[0].strip() for step in steps]
    expected = [
        f"- uses: {CHECKOUT} # v5.0.1",
        "- uses: ./.github/actions/setup",
        f"- uses: {DOWNLOAD} # v8.0.2",
        f"- run: {GATE}",
        f"- run: {GATE_EVAL}",
    ]
    if firsts != expected:
        problems.append(f"the gate job's steps are {firsts}, not {expected}")
    for step in steps:
        if any(line.strip().startswith(("if:", "continue-on-error")) for line in step):
            problems.append(f"a gate step runs under a condition: {step[0].strip()}")
    download = next((step for step in steps if DOWNLOAD in step[0]), None)
    if download is not None:
        inputs = {
            line.strip().split(":", 1)[0]: line.strip().split(":", 1)[1].strip()
            for line in download[2:]
        }
        if inputs != {"pattern": "m5e-evidence-*", "path": "target/m5e-gate/"}:
            problems.append(f"the download takes {inputs}, not only this run's bundles")
    for other, lines in jobs.items():
        if other != dw.M5E_GATE_JOB and any("download-artifact" in line for line in lines):
            problems.append(f"{other}: downloads artifacts, which only the gate job does")
    return problems


def test_the_gate_job_is_required_and_reads_only_this_runs_bundles() -> None:
    assert _gate_job_problems(CI.read_text(encoding="utf-8"), dw.M5E_GATE_TASKS) == []


@pytest.mark.parametrize(
    ("change", "said"),
    [
        ("not-required", "the `ci` job does not need the gate job"),
        ("conditional", "has `if:`"),
        ("may-fail", "has `continue-on-error`"),
        ("a-job-not-needed", "not every job of the gate"),
        ("another-run", "not only this run's bundles"),
        ("a-token", "not only this run's bundles"),
        ("unpinned", "the gate job's steps are"),
        ("no-eval", "the gate job's steps are"),
        ("step-conditional", "a gate step runs under a condition"),
        ("table-has-another-task", "not every job of the gate"),
    ],
)
def test_a_gate_job_that_judges_less_fails(change: str, said: str) -> None:
    table = dict(dw.M5E_GATE_TASKS)
    needs = "    needs: [sandbox-foundation, sandbox-egress,"
    download = f"      - uses: {DOWNLOAD} # v8.0.2\n        with:\n"
    if change == "not-required":
        text = _mutated("net-http, m5e-gate, supply-chain", "net-http, supply-chain")
    elif change == "conditional":
        text = _mutated(needs, "    if: github.event_name == 'push'\n" + needs)
    elif change == "may-fail":
        text = _mutated(needs, "    continue-on-error: true\n" + needs)
    elif change == "a-job-not-needed":
        text = _mutated(needs, "    needs: [sandbox-egress,")
    elif change == "another-run":
        text = _mutated(download, download + "          run-id: 42800717936\n")
    elif change == "a-token":
        text = _mutated(download, download + "          github-token: ${{ github.token }}\n")
    elif change == "unpinned":
        text = _mutated(download, download.replace(DOWNLOAD, "actions/download-artifact@v8"))
    elif change == "no-eval":
        text = _mutated(f"      - run: {GATE_EVAL}\n", "")
    elif change == "step-conditional":
        text = _mutated(f"      - run: {GATE}\n", f"      - run: {GATE}\n        if: success()\n")
    elif change == "table-has-another-task":
        text = CI.read_text(encoding="utf-8")
        table["d11-hardening-evidence"] = "d11-hardening"
    else:
        raise AssertionError(change)
    problems = _gate_job_problems(text, table)
    assert any(said in problem for problem in problems), (change, problems)


def test_the_gate_eval_is_pending_and_runs_only_in_the_gate_job() -> None:
    suite = tomllib.loads((REPO_ROOT / "evals" / "suites" / "m5e-gate.toml").read_text("utf-8"))
    assert suite["requires"] == ["M5e"] and suite["gate"] is False
    [evaluation] = suite["eval"]
    assert evaluation["runner"] == "m5e.gate"
    assert evaluation["needs"] == ["m5e-gate-job"]
    baseline = json.loads((REPO_ROOT / "evals" / "baselines" / "main.json").read_text("utf-8"))
    assert baseline["evals"]["m5e-gate/integrated-m5-gate"]["status"] == "pending"


# --- what each task must have judged ------------------------------------------------

_SOURCES: dict[str, tuple[Callable[..., object], ...]] = {
    "sandbox-workspace-evidence": (dw._sandbox_workspace_evidence,),
    "sandbox-agent-evidence": (dw._sandbox_agent_evidence,),
    "sandbox-release-evidence": (
        dw.task_sandbox_release_evidence,
        dw._release_unit_half,
        dw._release_workload_half,
        dw._release_agent_half,
    ),
}
_JUDGES = {
    "require_attributed_evidence": "attributed",
    "require_agent_evidence": "agent",
    "require_release_evidence": "release",
    "require_net_evidence": "net-http",
    "require_m5_eval_results": "eval",
}


def _source(task: str) -> str:
    functions = _SOURCES.get(task, (dw.TASKS[task],))
    return "\n".join(textwrap.dedent(inspect.getsource(fn)) for fn in functions)


def _judgement_tables(source: str) -> tuple[set[tuple[str, str]], list[str]]:
    """Every (judge, table) `source` judges against, and each call whose case
    table is not a module-level table of `dw` named at the call: a table built
    at the call (`A + B`) has no name to keep it by, and its task would fail
    after all of its checks passed."""
    made: set[tuple[str, str]] = set()
    unnamed: list[str] = []
    for node in ast.walk(ast.parse(source)):
        if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)):
            continue
        judge = _JUDGES.get(node.func.id)
        if judge is None:
            continue
        table = node.args[1] if len(node.args) > 1 else None
        if isinstance(table, ast.Name) and dw._case_table(table.id) is not None:
            made.add((judge, table.id))
        else:
            unnamed.append(ast.unparse(table) if table is not None else "no table")
    return made, unnamed


def test_every_task_of_the_gate_judges_what_the_gate_expects() -> None:
    assert set(dw.M5E_GATE_JUDGEMENTS) == set(dw.M5E_GATE_TASKS)
    for task, expected in dw.M5E_GATE_JUDGEMENTS.items():
        assert len(set(expected)) == len(expected), task
        made, unnamed = _judgement_tables(_source(task))
        assert unnamed == [], f"{task} judges against a table with no name: {unnamed}"
        assert set(expected) <= made, f"{task} never makes {sorted(set(expected) - made)}"
    # The negative controls: the call that failed hosted run 42619476453, and
    # a name that is no case table.
    built = "def f():\n    require_attributed_evidence(out, WORKSPACE_CASES + EXTRA_CASES)\n"
    assert _judgement_tables(built) == (set(), ["WORKSPACE_CASES + EXTRA_CASES"])
    assert _judgement_tables("def f():\n    require_net_evidence(out, TELEMETRY_FIELDS)\n") == (
        set(),
        ["TELEMETRY_FIELDS"],
    )


def test_the_gate_covers_the_whole_inventory_less_what_is_not_yet_required() -> None:
    judged: set[tuple[str, str]] = set()
    for expected in dw.M5E_GATE_JUDGEMENTS.values():
        for judge, table in expected:
            cases = dw._case_table(table)
            assert cases is not None, table
            if judge == "attributed":
                judged.update(cases)
    later: set[tuple[str, str]] = set()
    for table in dw.M5E_NOT_YET_REQUIRED:
        later.update(dw._case_table(table) or ())
    assert later and not judged & later
    assert judged | later == set(dw.ATTRIBUTED_CASES)
    assert dw.M5E_NOT_YET_REQUIRED == ("HYGIENE_CASES",)
    assert "sandbox-hygiene-evidence" not in dw.M5E_GATE_TASKS


def test_the_eval_verdicts_kept_are_the_m5_suites_evals() -> None:
    listed: set[tuple[str, str]] = set()
    for path in sorted((REPO_ROOT / "evals" / "suites").glob("m5[a-d]-*.toml")):
        suite = tomllib.loads(path.read_text(encoding="utf-8"))
        assert suite["gate"] is True, path.name
        listed.update((suite["id"], evaluation["name"]) for evaluation in suite["eval"])
    assert listed == set(dw.M5_EVAL_CASES)


def test_every_task_of_the_gate_reports_its_census_for_the_gate() -> None:
    """Each task of the gate that makes containers reports its census through
    `report_cleanup`, so the gate reads the line the task printed."""
    assert set(dw.M5E_CENSUS_FREE) == {"net-http-evidence", "eval-check"}
    for task in dw.M5E_GATE_TASKS:
        source = _source(task)
        if task in dw.M5E_CENSUS_FREE:
            assert "report_cleanup(" not in source, task
            continue
        assert "report_cleanup(" in source, task
        assert "{GREEN}cleanup:" not in source, task


# --- what a task keeps --------------------------------------------------------------


def _line(suite: str, case: str, prefix: str = dw.SANDBOX_EVIDENCE_PREFIX, **more: str) -> str:
    """An evidence line that satisfies its judge: the case's own level and a
    mechanism `ATTRIBUTION` gives it."""
    record: dict[str, object] = {"suite": suite, "case": case, "outcome": "ok"}
    contract = dw.attribution(suite, case)
    if contract is not None:
        level, mechanisms = contract
        record.update(level=level, enforcement=sorted(mechanisms)[0])
    record.update(more)
    return prefix + json.dumps(record)


def _restart_output(drop: int | None = None, **more: str) -> str:
    return "\n".join(
        _line(suite, case, **(more if i == 0 else {}))
        for i, (suite, case) in enumerate(dw.RESTART_CASES)
        if i != drop
    )


def test_only_a_judgement_that_passed_is_kept(monkeypatch: pytest.MonkeyPatch) -> None:
    """Each judge keeps its table, prefix and text only after it passed; one
    that fails keeps nothing."""
    monkeypatch.setattr(dw, "_JUDGED", [])
    with pytest.raises(dw.TaskError):
        dw.require_attributed_evidence("no evidence at all", dw.RESTART_CASES)
    with pytest.raises(dw.TaskError):
        dw.require_net_evidence("no evidence at all", dw.NET_HTTP_CASES)
    assert dw._JUDGED == []
    dw.require_attributed_evidence(_restart_output(), dw.RESTART_CASES)
    assert [entry[:3] for entry in dw._JUDGED] == [
        ("attributed", "RESTART_CASES", dw.SANDBOX_EVIDENCE_PREFIX)
    ]
    for judge in _JUDGES:
        assert "keep_judged" in getattr(dw, judge).__code__.co_names, judge
    assert dw._table_name(dw.RESTART_CASES) == "RESTART_CASES"
    assert dw._table_name((("suite", "case"),)) is None


def test_the_task_runner_keeps_a_gate_task_only_after_it_passed(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    kept: list[str] = []
    forgotten: list[str] = []
    monkeypatch.setattr(dw, "save_judged_evidence", lambda task: kept.append(task))
    monkeypatch.setattr(dw, "forget_kept", lambda task: forgotten.append(task))

    def fails() -> None:
        raise dw.TaskError("the evidence failed")

    monkeypatch.setitem(dw.TASKS, "sandbox-restart-evidence", fails)
    assert dw.main(["sandbox-restart-evidence"]) == 1
    assert kept == [] and forgotten == ["sandbox-restart-evidence"], "a failed task keeps nothing"
    monkeypatch.setitem(dw.TASKS, "sandbox-restart-evidence", lambda: None)
    assert dw.main(["sandbox-restart-evidence"]) == 0
    assert kept == ["sandbox-restart-evidence"]
    monkeypatch.setitem(dw.TASKS, "lint", lambda: None)
    assert dw.main(["lint"]) == 0
    assert kept == ["sandbox-restart-evidence"], "a task outside the gate keeps nothing"


def test_a_lenient_eval_gate_keeps_nothing() -> None:
    assert dw.m5e_keeps("eval-check", {"GITHUB_ACTIONS": "true"})
    assert dw.m5e_keeps("eval-check", {"DW_EVAL_REQUIRE_EXERCISED": "1"})
    assert not dw.m5e_keeps("eval-check", {})
    assert dw.m5e_keeps("net-http-evidence", {})
    assert not dw.m5e_keeps("lint", {"GITHUB_ACTIONS": "true"})


def test_what_an_earlier_process_kept_is_forgotten(tmp_path: Path) -> None:
    stale = tmp_path / "sandbox-restart-evidence"
    stale.mkdir()
    (stale / "judged.json").write_text("{}", encoding="utf-8")
    (tmp_path / "sandbox-capacity-evidence").mkdir()
    dw.forget_kept("sandbox-restart-evidence", tmp_path)
    assert not stale.exists() and (tmp_path / "sandbox-capacity-evidence").is_dir()
    dw.forget_kept("sandbox-restart-evidence", tmp_path)


def _kept(
    tmp_path: Path,
    task: str = "sandbox-restart-evidence",
    judged: Sequence[tuple[str, str | None, str, str]] | None = None,
    cleanup: list[str] | None = None,
) -> Path:
    if judged is None:
        judged = [("attributed", "RESTART_CASES", dw.SANDBOX_EVIDENCE_PREFIX, _restart_output())]
    return dw.save_judged_evidence(task, tmp_path, judged, [CENSUS] if cleanup is None else cleanup)


HOSTED = {
    "GITHUB_ACTIONS": "true",
    "RUNNER_ENVIRONMENT": "github-hosted",
    "GITHUB_JOB": "sandbox-restart",
    "GITHUB_RUN_ID": "42800717936",
    "GITHUB_RUN_ATTEMPT": "1",
    "GITHUB_SHA": SHA,
    "GITHUB_REF": "refs/heads/main",
    "RUNNER_OS": "Linux",
    "ImageOS": "ubuntu24",
    "ImageVersion": "20261101.186.1",
}


def test_a_kept_record_seals_into_a_bundle(tmp_path: Path) -> None:
    directory = _kept(tmp_path)
    _kept(tmp_path, "sandbox-capacity-evidence")  # another task's: never sealed here
    kept = json.loads((directory / "judged.json").read_text(encoding="utf-8"))
    data = (directory / "judged-0.txt").read_bytes()
    assert kept["judged"][0]["sha256"] == hashlib.sha256(data).hexdigest()
    assert kept["judged"][0]["judge"] == "attributed"
    record = dw.m5e_bundle_record(HOSTED, tmp_path)
    assert record["task"] == "sandbox-restart-evidence" and record["job"] == "sandbox-restart"
    assert (record["run_id"], record["run_attempt"], record["sha"]) == ("42800717936", "1", SHA)
    assert record["runner"] == {
        "environment": "github-hosted",
        "os": "Linux",
        "image": "ubuntu24",
        "image_version": "20261101.186.1",
    }
    assert record["exit"] == 0 and record["judged"] == kept["judged"]
    assert record["version"] == 2 and record["cleanup"] == [CENSUS]


def test_a_task_that_makes_no_container_keeps_no_census(tmp_path: Path) -> None:
    output = "\n".join(
        _line(suite, case, dw.NET_EVIDENCE_PREFIX) for suite, case in dw.NET_HTTP_CASES
    )
    judged = [("net-http", "NET_HTTP_CASES", dw.NET_EVIDENCE_PREFIX, output)]
    _kept(tmp_path, "net-http-evidence", judged, [])
    record = dw.m5e_bundle_record({**HOSTED, "GITHUB_JOB": "net-http"}, tmp_path)
    assert record["cleanup"] == [] and record["task"] == "net-http-evidence"


@pytest.mark.parametrize(
    ("change", "said"),
    [
        ("not-hosted", "NOT EXERCISED"),
        ("self-hosted", "NOT EXERCISED"),
        ("a-job-of-no-task", "runs no task of the M5 gate"),
        ("another-tasks-job", "nothing kept under"),
        ("nothing-kept", "nothing kept"),
        ("byte-changed", "is not the output the task judged"),
        ("file-beside", "files beside"),
        ("repeated-key", "unreadable"),
        ("unknown-table", "is not a case table"),
        ("not-a-case-table", "is not a case table"),
        ("unknown-judge", "is no judge of the M5 gate"),
        ("judge-prefix-changed", "line prefix"),
        ("no-census", "kept no cleanup census"),
        ("dirty-census", "not its clean cleanup lines"),
        ("older-version", "at this schema and version"),
        ("oversized", "over"),
        ("no-commit", "the run's commit"),
        ("no-attempt", "id or attempt"),
    ],
)
def test_a_bundle_that_proves_less_is_refused(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str, said: str
) -> None:
    environ = dict(HOSTED)
    root = tmp_path / "kept"
    directory = _kept(root)
    record_path = directory / "judged.json"
    kept = json.loads(record_path.read_text(encoding="utf-8"))

    def rewrite() -> None:
        record_path.write_text(json.dumps(kept), encoding="utf-8")

    if change == "not-hosted":
        environ.pop("GITHUB_ACTIONS")
    elif change == "self-hosted":
        environ["RUNNER_ENVIRONMENT"] = "self-hosted"
    elif change == "a-job-of-no-task":
        environ["GITHUB_JOB"] = "lint"
    elif change == "another-tasks-job":
        environ["GITHUB_JOB"] = "sandbox-egress"
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
        kept["judged"][0]["table"] = "NO_SUCH_CASES"
        rewrite()
    elif change == "not-a-case-table":
        kept["judged"][0]["table"] = "TELEMETRY_FIELDS"
        rewrite()
    elif change == "unknown-judge":
        kept["judged"][0]["judge"] = "trusted"
        rewrite()
    elif change == "judge-prefix-changed":
        kept["judged"][0]["judge"] = "net-http"
        rewrite()
    elif change == "no-census":
        kept["cleanup"] = []
        rewrite()
    elif change == "dirty-census":
        kept["cleanup"] = ["cleanup: the evidence left 1 container(s) behind"]
        rewrite()
    elif change == "older-version":
        kept["version"] = 1
        rewrite()
    elif change == "oversized":
        monkeypatch.setattr(dw, "M5E_GATE_MAX_FILE", 64)
    elif change == "no-commit":
        environ["GITHUB_SHA"] = "main"
    elif change == "no-attempt":
        environ.pop("GITHUB_RUN_ATTEMPT")
    else:
        raise AssertionError(change)
    with pytest.raises(dw.TaskError, match=re.escape(said)):
        dw.m5e_bundle_record(environ, root)


def test_nothing_is_kept_that_proves_nothing(tmp_path: Path) -> None:
    judged = [("attributed", "RESTART_CASES", dw.SANDBOX_EVIDENCE_PREFIX, "x")]
    with pytest.raises(dw.TaskError, match="not a task of the M5 gate"):
        dw.save_judged_evidence("lint", tmp_path, judged, [CENSUS])
    with pytest.raises(dw.TaskError, match="judged no evidence"):
        dw.save_judged_evidence("sandbox-restart-evidence", tmp_path, [], [CENSUS])
    with pytest.raises(dw.TaskError, match="no cleanup census"):
        dw.save_judged_evidence("sandbox-restart-evidence", tmp_path, judged, [])
    with pytest.raises(dw.TaskError, match="no name"):
        dw.save_judged_evidence(
            "sandbox-restart-evidence", tmp_path, [("attributed", None, "p", "x")], [CENSUS]
        )
    with pytest.raises(dw.TaskError, match="no judge"):
        dw.save_judged_evidence(
            "sandbox-restart-evidence", tmp_path, [("trusted", "RESTART_CASES", "p", "x")], [CENSUS]
        )


# --- the M5 eval suites' own verdicts --------------------------------------------------


def _result(suite: str, name: str, **more: object) -> str:
    record: dict[str, object] = {
        "result_version": 1,
        "eval_id": f"{suite}/{name}",
        "suite": suite,
        "status": "pass",
        "score": 1.0,
        "runs": 1,
        "run_index": 0,
    }
    record.update(more)
    return json.dumps(record, sort_keys=True)


def _results(**changes: Mapping[str, object]) -> str:
    lines = [_result("protocol-security", "hostile-vectors", status="fail", score=0.0)]
    for suite, name in dw.M5_EVAL_CASES:
        lines.append(_result(suite, name, **changes.get(suite, {})))
    return "\n".join(lines) + "\n"


def test_the_m5_eval_verdicts_pass_only_when_each_passed(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(dw, "_JUDGED", [])
    records = dw.require_m5_eval_results(_results(), dw.M5_EVAL_CASES)
    assert len(records) == 4
    assert [entry[:3] for entry in dw._JUDGED] == [("eval", "M5_EVAL_CASES", "")]


@pytest.mark.parametrize(
    ("text", "said"),
    [
        (_results(**{"m5c-net-http": {"status": "fail", "score": 0.0}}), "not a pass at 1.0"),
        (_results(**{"m5a-sandbox-foundation": {"score": 0.5}}), "not a pass at 1.0"),
        (_results(**{"m5b-sandbox-egress": {"score": True}}), "not a pass at 1.0"),
        (_results(**{"m5d-sandbox-exec": {"status": "pending", "score": None}}), "not a pass"),
        (_results(**{"m5d-sandbox-exec": {"result_version": 2}}), "a result of version 2"),
        (_results(**{"m5a-sandbox-foundation": {"runs": 2}}), "not each reported once"),
        (_results(**{"m5a-sandbox-foundation": {"runs": []}}), "not each reported once"),
        (_results(**{"m5b-sandbox-egress": {"run_index": True}}), "not each reported once"),
        (
            _results() + _result("m5c-net-http", "kernel-performed-net-http") + "\n",
            "not each reported once",
        ),
        (_results() + _result("m5c-net-http", "a-new-eval") + "\n", "the gate does not list"),
        (
            "\n".join(_results().splitlines()[:-1]) + "\n",
            "m5d-sandbox-exec/sandboxed-exec-and-release-teardown: no result",
        ),
        (_results() + "{not json\n", "unreadable eval result"),
        (_results() + '{"suite": "a", "suite": "b"}\n', "unreadable eval result"),
    ],
)
def test_an_m5_eval_verdict_that_is_not_a_pass_fails(text: str, said: str) -> None:
    with pytest.raises(dw.TaskError, match=re.escape(said)):
        dw.require_m5_eval_results(text, dw.M5_EVAL_CASES)


# --- the gate ----------------------------------------------------------------------

GATE_ENV = {**HOSTED, "GITHUB_JOB": "m5e-gate", "GITHUB_RUN_ATTEMPT": "2"}


@pytest.fixture
def small_gate(monkeypatch: pytest.MonkeyPatch) -> None:
    """A gate of two tasks -- one attributed, one self-judging and census-free
    -- over an inventory of the restart cases alone, so its bundles can be
    built here from lines each judge passes."""
    monkeypatch.setattr(
        dw,
        "M5E_GATE_TASKS",
        {"sandbox-restart-evidence": "sandbox-restart", "net-http-evidence": "net-http"},
    )
    monkeypatch.setattr(
        dw,
        "M5E_GATE_JUDGEMENTS",
        {
            "sandbox-restart-evidence": (("attributed", "RESTART_CASES"),),
            "net-http-evidence": (("net-http", "NET_HTTP_CASES"),),
        },
    )
    monkeypatch.setattr(dw, "ATTRIBUTED_CASES", frozenset(dw.RESTART_CASES))
    monkeypatch.setattr(dw, "M5E_NOT_YET_REQUIRED", ())


def _bundles(root: Path, attempt: str = "1", restart: str | None = None) -> Path:
    """This run's two bundles, as the download action lays them out."""
    for task, job in dw.M5E_GATE_TASKS.items():
        kept = root.parent / "kept" / job
        if task == "net-http-evidence":
            output = "\n".join(
                _line(suite, case, dw.NET_EVIDENCE_PREFIX) for suite, case in dw.NET_HTTP_CASES
            )
            judged = [("net-http", "NET_HTTP_CASES", dw.NET_EVIDENCE_PREFIX, output)]
            directory = _kept(kept, task, judged, [])
        else:
            judged = [
                (
                    "attributed",
                    "RESTART_CASES",
                    dw.SANDBOX_EVIDENCE_PREFIX,
                    _restart_output() if restart is None else restart,
                )
            ]
            directory = _kept(kept, task, judged)
        record = dw.m5e_bundle_record(
            {**HOSTED, "GITHUB_JOB": job, "GITHUB_RUN_ATTEMPT": attempt}, kept
        )
        (directory / "bundle.json").write_text(json.dumps(record), encoding="utf-8")
        shutil.copytree(directory, root / f"m5e-evidence-{job}")
    return root


@pytest.mark.usefixtures("small_gate")
def test_the_gate_judges_every_bundle_of_this_run_again(tmp_path: Path) -> None:
    root = _bundles(tmp_path / "gate", attempt="2")
    lines, blockers = dw.m5e_gate_verdict(GATE_ENV, root, REPO_ROOT)
    assert lines[0].startswith(dw._INVENTORY_VERDICT)
    assert "attributed inventory: 7 of 7 cases" in lines[1]
    assert "  net-http-evidence: 179 case(s) judged again" in lines
    assert blockers  # today: M5e.5 is not accepted
    # An earlier attempt of the same run is this run: its job passed and was
    # not run again.
    root = _bundles(tmp_path / "earlier", attempt="1")
    dw.m5e_gate_verdict(GATE_ENV, root, REPO_ROOT)


def _rewrite(path: Path, change: Callable[[dict[str, object]], None]) -> None:
    record = json.loads(path.read_text(encoding="utf-8"))
    change(record)
    path.write_text(json.dumps(record), encoding="utf-8")


def _self_hosted(record: dict[str, object]) -> None:
    runner = record["runner"]
    assert isinstance(runner, dict)
    runner["environment"] = "self-hosted"


@pytest.mark.usefixtures("small_gate")
@pytest.mark.parametrize(
    ("change", "said"),
    [
        ("not-hosted", "NOT EXERCISED"),
        ("another-job", "runs in the 'm5e-gate' job"),
        ("nothing-downloaded", "nothing was downloaded"),
        ("a-bundle-missing", "missing bundle(s)"),
        ("a-bundle-extra", "no task of the gate uploads"),
        ("another-run", "not this run's"),
        ("another-commit", "not this run's"),
        ("a-later-attempt", "not this run's"),
        ("self-hosted", "not a GitHub-hosted one"),
        ("another-tasks-bundle", "at this schema and version"),
        ("task-failed", "exit is not 0"),
        ("bundle-disagrees", "disagree"),
        ("byte-changed", "is not the output the task judged"),
        ("a-case-not-reported", "NOT EXERCISED: 1 required case"),
        ("a-level-downgraded", "at level"),
        ("an-enforcement-swapped", "is not what this case exercises"),
        ("not-exercised", "NOT EXERCISED"),
        ("a-judgement-missing", "not exactly"),
        ("a-census-missing", "kept no cleanup census"),
        ("the-inventory-grew", "attributed case(s) no bundle judged"),
        ("oversized", "over"),
    ],
)
def test_a_gate_over_less_than_this_runs_evidence_fails(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, change: str, said: str
) -> None:
    environ = dict(GATE_ENV)
    restart: str | None = None
    if change == "a-case-not-reported":
        restart = _restart_output(drop=3)
    elif change == "a-level-downgraded":
        restart = _restart_output(level="unit")
    elif change == "an-enforcement-swapped":
        restart = _restart_output(enforcement="authority-idempotency")
    elif change == "not-exercised":
        restart = _restart_output(outcome="not-exercised")
    root = _bundles(tmp_path / "gate", restart=restart)
    restart_dir = root / "m5e-evidence-sandbox-restart"
    bundle = restart_dir / "bundle.json"
    if change == "not-hosted":
        environ["RUNNER_ENVIRONMENT"] = "self-hosted"
    elif change == "another-job":
        environ["GITHUB_JOB"] = "sandbox-restart"
    elif change == "nothing-downloaded":
        root = tmp_path / "absent"
    elif change == "a-bundle-missing":
        shutil.rmtree(root / "m5e-evidence-net-http")
    elif change == "a-bundle-extra":
        shutil.copytree(restart_dir, root / "m5e-evidence-d11-hardening")
    elif change == "another-run":
        _rewrite(bundle, lambda r: r.update(run_id="42619476453"))
    elif change == "another-commit":
        _rewrite(bundle, lambda r: r.update(sha="f" * 40))
    elif change == "a-later-attempt":
        _rewrite(bundle, lambda r: r.update(run_attempt="3"))
    elif change == "self-hosted":
        _rewrite(bundle, _self_hosted)
    elif change == "another-tasks-bundle":
        _rewrite(bundle, lambda r: r.update(task="sandbox-capacity-evidence"))
    elif change == "task-failed":
        _rewrite(bundle, lambda r: r.update(exit=1))
    elif change == "bundle-disagrees":
        _rewrite(bundle, lambda r: r.update(cleanup=["cleanup: no network remains"]))
    elif change == "byte-changed":
        (restart_dir / "judged-0.txt").write_text("forged", encoding="utf-8")
    elif change == "a-judgement-missing":
        monkeypatch.setitem(
            dw.M5E_GATE_JUDGEMENTS,
            "sandbox-restart-evidence",
            (("attributed", "RESTART_CASES"), ("attributed", "CAPACITY_CASES")),
        )
    elif change == "a-census-missing":
        for path in (bundle, restart_dir / "judged.json"):
            _rewrite(path, lambda r: r.update(cleanup=[]))
    elif change == "the-inventory-grew":
        monkeypatch.setattr(dw, "ATTRIBUTED_CASES", frozenset({*dw.RESTART_CASES, ("x", "y")}))
    elif change == "oversized":
        monkeypatch.setattr(dw, "M5E_GATE_MAX_FILE", 256)
    elif change not in {
        "a-case-not-reported",
        "a-level-downgraded",
        "an-enforcement-swapped",
        "not-exercised",
    }:
        raise AssertionError(change)
    with pytest.raises(dw.TaskError, match=re.escape(said)):
        dw.m5e_gate_verdict(environ, root, REPO_ROOT)


# --- the M5e acceptance verdict ------------------------------------------------------


def test_the_acceptance_verdict_is_not_ready_today() -> None:
    blockers = dw.m5e_acceptance_blockers(REPO_ROOT)
    assert blockers == [
        "M5e.5's evidence is not yet required: HYGIENE_CASES (M5e.5's acceptance change)",
        "ADR-0054 is Proposed, not Accepted",
        "ADR-0055 is Proposed, not Accepted",
        "the plan records no M5e.5's acceptance",
    ]


def _repo(tmp_path: Path, statuses: dict[str, str], records: str) -> Path:
    adr = tmp_path / "docs" / "adr"
    adr.mkdir(parents=True)
    for number, status in statuses.items():
        (adr / f"{number}-record.md").write_text(
            f"# ADR-{number}\n\n**Status:** {status} · **Date:** 2026-11-10\n", encoding="utf-8"
        )
    (tmp_path / "docs" / "M5E_ASSURANCE_PLAN.md").write_text(records, encoding="utf-8")
    return tmp_path


ALL_RECORDS = (
    "**M5e.2's closure (2026-11-09).** x\n"
    "**M5e.4's acceptance (2026-11-09).** x\n"
    "**M5e.5's acceptance (2026-11-20).** x\n"
)
ACCEPTED = {
    "0054": "Accepted",
    "0055": "Accepted",
    "0057": "**Superseded by ADR-0058**",
    "0058": "Accepted",
    "0059": "Accepted",
}


def test_the_acceptance_verdict_is_ready_only_with_every_acceptance(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(dw, "M5E_NOT_YET_REQUIRED", ())
    monkeypatch.setitem(dw.M5E_GATE_TASKS, "sandbox-hygiene-evidence", "sandbox-hygiene")
    assert dw.m5e_acceptance_blockers(_repo(tmp_path / "ready", ACCEPTED, ALL_RECORDS)) == []
    proposed = _repo(tmp_path / "proposed", {**ACCEPTED, "0055": "Proposed"}, ALL_RECORDS)
    assert dw.m5e_acceptance_blockers(proposed) == ["ADR-0055 is Proposed, not Accepted"]
    standing = _repo(tmp_path / "standing", {**ACCEPTED, "0057": "Proposed"}, ALL_RECORDS)
    assert dw.m5e_acceptance_blockers(standing) == ["ADR-0057 is Proposed, not Superseded"]
    unrecorded = _repo(tmp_path / "unrecorded", ACCEPTED, ALL_RECORDS.splitlines()[0])
    assert dw.m5e_acceptance_blockers(unrecorded) == [
        "the plan records no M5e.4's acceptance",
        "the plan records no M5e.5's acceptance",
    ]
    monkeypatch.setattr(dw, "M5E_NOT_YET_REQUIRED", ("HYGIENE_CASES",))
    assert dw.m5e_acceptance_blockers(_repo(tmp_path / "later", ACCEPTED, ALL_RECORDS)) == [
        "M5e.5's evidence is not yet required: HYGIENE_CASES (M5e.5's acceptance change)"
    ]
