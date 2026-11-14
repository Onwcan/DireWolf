"""F-07: every coverage-guided target runs, on its own budget, and nothing but
this run's record of a whole libFuzzer run is a pass.

Three things are held here.

**Inventory.** `scripts/dw.py` FUZZ_TARGETS, `fuzz/fuzz_targets/*.rs`,
`fuzz/Cargo.toml` and the Fuzz workflow's matrix name the same targets, and
each can be selected alone. A target added to one and forgotten in another
fails here, rather than silently dropping out of the weekly campaign.

**Budgets.** Each trigger's budget is fixed or bounded, and the time limits
nest: the runner's own limits expire before the `make fuzz` step's, and the
step's before the job's, so an overrun is recorded rather than inferred.

**Outcomes.** The runner and the report are driven here with stand-in child
processes in place of cargo and libFuzzer -- real processes, so the
streaming, the watchdog and the kill are the real code -- and with records in
every state a run can leave: a crash fails, a time limit is TIMEOUT, a
cancellation is CANCELLED, a missing or stale record is never a pass, and
output without libFuzzer's coverage counters (the stable smoke harness's,
say) is NOT EXERCISED.

The workflow assertions are text assertions, as in test_dev_surface.py: no
YAML parser is a dependency here.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import sys
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "fuzz.yml"
FUZZ_TARGET_SOURCES = REPO_ROOT / "fuzz" / "fuzz_targets"
FUZZ_MANIFEST = REPO_ROOT / "fuzz" / "Cargo.toml"

sys.path.insert(0, str(REPO_ROOT / "scripts"))
import dw  # noqa: E402  - imported after the path is extended

SHA = "0123456789abcdef0123456789abcdef01234567"


# --- the workflow, read as text ---------------------------------------------


def _workflow() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def _job(text: str, name: str) -> str:
    """One job's block: from `  <name>:` up to the next job."""
    match = re.search(rf"^  {name}:\n((?:(?:    .*)?\n)*)", text, re.MULTILINE)
    assert match is not None, f"the Fuzz workflow has no job {name!r}"
    return match.group(1)


def _step(block: str, name: str) -> str:
    """One step of a job: from `- name: <name>` up to the next step."""
    match = re.search(
        rf"^      - name: {re.escape(name)}\n((?:(?:        .*)?\n)*)", block, re.MULTILINE
    )
    assert match is not None, f"no step {name!r}"
    return match.group(1)


def matrix_targets(text: str) -> list[str]:
    """The coverage-guided job's matrix, in order."""
    match = re.search(
        r"^        target:\n((?:          (?:- \S+|#.*)\n)+)", _job(text, "libfuzzer"), re.MULTILINE
    )
    if match is None:
        return []
    return re.findall(r"^          - (\S+)$", match.group(1), re.MULTILINE)


def _sources() -> list[str]:
    return sorted(p.stem for p in FUZZ_TARGET_SOURCES.glob("*.rs"))


def _bins() -> list[str]:
    text = FUZZ_MANIFEST.read_text(encoding="utf-8")
    return re.findall(r'^\[\[bin\]\]\nname = "([^"]+)"', text, re.MULTILINE)


def inventory_problems(workflow: str, sources: list[str], bins: list[str]) -> list[str]:
    """Every way the four inventories, and target selection, disagree."""
    declared = list(dw.FUZZ_TARGETS)
    problems = []
    for where, found in (
        ("the Fuzz workflow's matrix", matrix_targets(workflow)),
        ("fuzz/fuzz_targets/", sources),
        ("fuzz/Cargo.toml", bins),
    ):
        for target in sorted(set(declared) - set(found)):
            problems.append(f"{target} is in FUZZ_TARGETS but not in {where}")
        for target in sorted(set(found) - set(declared)):
            problems.append(f"{target} is in {where} but not in FUZZ_TARGETS")
        if len(found) != len(set(found)):
            problems.append(f"{where} names a target twice")
    for target in declared:
        try:
            alone = dw.fuzz_selected_targets({"DW_FUZZ_TARGET": target})
        except dw.TaskError:
            alone = ()
        if alone != (target,):
            problems.append(f"{target} cannot be selected alone")
    return problems


# --- stand-ins for cargo and libFuzzer --------------------------------------


def _child(lines: list[str], code: int = 0, sleep: float = 0.0, touch: str = "") -> list[str]:
    """A real child process that prints `lines`, optionally writes `touch`,
    optionally sleeps, and exits `code`."""
    script = (
        "import sys, time\n"
        f"lines = {json.dumps(lines)}\n"
        "for line in lines:\n"
        "    print(line, flush=True)\n"
        f"if {touch!r}:\n"
        f"    open({touch!r}, 'wb').write(b'crashing input')\n"
        f"time.sleep({sleep})\n"
        f"sys.exit({code})\n"
    )
    return [sys.executable, "-c", script]


def _libfuzzer_lines(seconds: int) -> list[str]:
    """What a clean libFuzzer run prints, in its own format."""
    return [
        "INFO: Running with entropic power schedule (0xFF, 100).",
        "INFO: Seed: 1234",
        "INFO: Loaded 1 modules   (5120 inline 8-bit counters): 5120 [0x55d0, 0x55e0),",
        "INFO: Loaded 1 PC tables (5120 PCs): 5120 [0x55f0,0x5600),",
        "#256\tINITED cov: 812 ft: 1490 corp: 210/38Kb exec/s: 0 rss: 48Mb",
        "#65536\tpulse  cov: 845 ft: 1702 corp: 236/41Kb lim: 1310 exec/s: 21845 rss: 61Mb",
        f"Done 131072 runs in {seconds} second(s)",
    ]


@pytest.fixture(autouse=True)
def _local(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Iterator[None]:
    """A local run against a scratch fuzz/ directory, whatever CI sets."""
    for name in (
        "DW_FUZZ_TARGET",
        "DW_FUZZ_SECONDS",
        "DW_FUZZ_STEP_OUTCOME",
        "DW_FUZZ_REQUESTED",
        "GITHUB_ACTIONS",
        "GITHUB_EVENT_NAME",
        "GITHUB_OUTPUT",
        "GITHUB_RUN_ATTEMPT",
        "GITHUB_RUN_ID",
        "GITHUB_STEP_SUMMARY",
    ):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("GITHUB_SHA", SHA)
    monkeypatch.setattr(dw, "FUZZ_DIR", tmp_path / "fuzz")
    monkeypatch.setattr(shutil, "which", lambda name: f"/stand-in/{name}")
    monkeypatch.setattr(
        dw,
        "_fuzz_tool_versions",
        lambda: {
            "toolchain": dw.FUZZ_NIGHTLY,
            "rustc": "rustc 1.100.0-nightly (stand-in)",
            "cargo_fuzz": f"cargo-fuzz {dw.CARGO_FUZZ_VERSION}",
        },
    )
    yield


@pytest.fixture
def journal(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Where the stand-in builds note which target they built."""
    path = tmp_path / "built.txt"
    monkeypatch.setattr(
        dw,
        "_fuzz_build_argv",
        lambda target: [
            sys.executable,
            "-c",
            f"open({str(path)!r}, 'a').write({target!r} + '\\n')",
        ],
    )
    return path


def _record(tmp_path: Path, target: str) -> dict[str, object]:
    loaded = json.loads((tmp_path / "fuzz" / "evidence" / f"{target}.json").read_text("utf-8"))
    assert isinstance(loaded, dict)
    return loaded


# --- 1, 11: inventory --------------------------------------------------------


def test_every_target_has_its_own_job_and_every_inventory_agrees() -> None:
    assert len(dw.FUZZ_TARGETS) == 8
    assert matrix_targets(_workflow()) == list(dw.FUZZ_TARGETS)
    assert inventory_problems(_workflow(), _sources(), _bins()) == []


def test_a_target_missing_anywhere_fails_the_inventory() -> None:
    dropped = _workflow().replace("          - policy_evaluate\n", "")
    assert "policy_evaluate is in FUZZ_TARGETS but not in the Fuzz workflow's matrix" in (
        inventory_problems(dropped, _sources(), _bins())
    )
    added = [*_sources(), "new_decoder"]
    assert "new_decoder is in fuzz/fuzz_targets/ but not in FUZZ_TARGETS" in (
        inventory_problems(_workflow(), added, _bins())
    )
    unbuilt = [b for b in _bins() if b != "url_parse"]
    assert "url_parse is in FUZZ_TARGETS but not in fuzz/Cargo.toml" in (
        inventory_problems(_workflow(), _sources(), unbuilt)
    )
    twice = _workflow().replace("          - url_parse\n", "          - url_parse\n" * 2)
    assert "the Fuzz workflow's matrix names a target twice" in (
        inventory_problems(twice, _sources(), _bins())
    )


def test_the_matrix_runs_every_target_independently() -> None:
    block = _job(_workflow(), "libfuzzer")
    assert "fail-fast: false" in block
    assert "DW_FUZZ_TARGET: ${{ matrix.target }}" in _step(block, "make fuzz")
    assert "name: coverage-guided ${{ matrix.target }} (make fuzz)" in _workflow()


# --- 2, 3: selection ---------------------------------------------------------


def test_the_default_is_every_target() -> None:
    assert dw.fuzz_selected_targets({}) == dw.FUZZ_TARGETS


@pytest.mark.parametrize(
    "name",
    [
        "nope",
        "",
        "frame_decoder,dwkp_decode",
        "frame_decoder dwkp_decode",
        " frame_decoder",
        "frame_decoder\n",
        "FRAME_DECODER",
        "../fuzz_targets/frame_decoder",
        "frame_decoder; id",
        "$(id)",
    ],
)
def test_an_unknown_target_is_refused_before_anything_runs(name: str) -> None:
    with pytest.raises(dw.TaskError, match="not a coverage-guided target"):
        dw.fuzz_selected_targets({"DW_FUZZ_TARGET": name})


def test_an_unknown_target_fails_make_fuzz_and_runs_nothing(
    monkeypatch: pytest.MonkeyPatch, journal: Path, tmp_path: Path
) -> None:
    monkeypatch.setenv("DW_FUZZ_TARGET", "fuzz_everything")
    with pytest.raises(dw.TaskError):
        dw.task_fuzz()
    assert not journal.exists()
    assert not (tmp_path / "fuzz").exists()


# --- 4, 5: one target runs alone, from its own surface's seeds ---------------


def test_a_selected_target_runs_alone_for_its_budget(
    monkeypatch: pytest.MonkeyPatch, journal: Path, tmp_path: Path
) -> None:
    monkeypatch.setenv("DW_FUZZ_TARGET", "url_parse")
    monkeypatch.setenv("DW_FUZZ_SECONDS", "7")
    runs: list[tuple[str, int]] = []

    def run_argv(target: str, seconds: int) -> list[str]:
        runs.append((target, seconds))
        return _child(_libfuzzer_lines(seconds))

    monkeypatch.setattr(dw, "_fuzz_run_argv", run_argv)
    dw.task_fuzz()
    assert journal.read_text("utf-8") == "url_parse\n"
    assert runs == [("url_parse", 7)]
    evidence = sorted(p.name for p in (tmp_path / "fuzz" / "evidence").iterdir())
    assert evidence == ["url_parse.json"]
    record = _record(tmp_path, "url_parse")
    assert record["status"] == "PASS"
    assert record["engine"] == "libfuzzer"
    assert record["coverage_guided"] is True
    assert record["requested_seconds"] == 7
    assert record["commit"] == SHA
    assert record["trigger"] == "local"
    assert record["cargo_fuzz"] == f"cargo-fuzz {dw.CARGO_FUZZ_VERSION}"
    assert record["toolchain"] == dw.FUZZ_NIGHTLY
    assert record["libfuzzer"] == {
        "coverage_counters": 5120,
        "initial_coverage": 812,
        "final_coverage": 845,
        "runs": 131072,
        "reported_seconds": 7,
    }
    assert sorted(p.name for p in (tmp_path / "fuzz" / "corpus").iterdir()) == ["url_parse"]


def test_the_run_command_is_libfuzzer_with_its_budget_and_input_limit() -> None:
    argv = dw._fuzz_run_argv("policy_loader", 900)
    assert argv == [
        "cargo",
        f"+{dw.FUZZ_NIGHTLY}",
        "fuzz",
        "run",
        "policy_loader",
        "--",
        "-max_total_time=900",
        f"-timeout={dw.FUZZ_INPUT_TIMEOUT}",
    ]
    assert dw._fuzz_build_argv("policy_loader") == [
        "cargo",
        f"+{dw.FUZZ_NIGHTLY}",
        "fuzz",
        "build",
        "policy_loader",
    ]


@pytest.mark.usefixtures("journal")
def test_each_target_is_seeded_from_its_own_surface(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    for target in dw.PROTO_FUZZ_TARGETS:
        assert dw.fuzz_seeds_for(target) == dw._fuzz_seeds()
    for target in dw.POLICY_FUZZ_TARGETS:
        assert dw.fuzz_seeds_for(target) == dw._policy_fuzz_seeds()
    with pytest.raises(dw.TaskError):
        dw.fuzz_seeds_for("not_a_target")
    monkeypatch.setattr(dw, "_fuzz_run_argv", lambda _target, _seconds: _child([], 0))
    for target in ("policy_loader", "frame_decoder"):
        monkeypatch.setenv("DW_FUZZ_TARGET", target)
        with pytest.raises(dw.TaskError):  # the stand-in printed nothing: NOT EXERCISED
            dw.task_fuzz()
        corpus = {p.read_bytes() for p in (tmp_path / "fuzz" / "corpus" / target).iterdir()}
        assert corpus == set(dw.fuzz_seeds_for(target))
    assert set(dw.fuzz_seeds_for("policy_loader")).isdisjoint(dw.fuzz_seeds_for("frame_decoder"))


# --- 6, 7: budgets and time limits -------------------------------------------


@pytest.mark.parametrize(
    # The last: Arabic-Indic "30", which str.isdigit() would have let through.
    "value",
    ["", "0", "-1", "abc", "1e3", " 30", "30 ", "30s", "3601", "99999999", "٣٠"],
)
def test_an_invalid_budget_is_refused(value: str) -> None:
    with pytest.raises(dw.TaskError, match="whole number of seconds from 1 to 3600"):
        dw.fuzz_seconds({"DW_FUZZ_SECONDS": value})
    with pytest.raises(dw.TaskError, match="whole number of seconds from 1 to 3600"):
        dw.fuzz_plan("workflow_dispatch", value)


def test_the_budgets_by_trigger() -> None:
    assert dw.fuzz_seconds({}) == dw.FUZZ_LOCAL_SECONDS == 60
    assert dw.fuzz_seconds({"DW_FUZZ_SECONDS": "1"}) == 1
    assert dw.fuzz_seconds({"DW_FUZZ_SECONDS": "3600"}) == 3600
    assert dw.fuzz_plan("pull_request", "")["seconds"] == 30
    assert dw.fuzz_plan("schedule", "")["seconds"] == 900
    # The budgets of the fixed triggers are not the caller's to change.
    assert dw.fuzz_plan("schedule", "5")["seconds"] == 900
    assert dw.fuzz_plan("workflow_dispatch", "1200")["seconds"] == 1200
    for event in ("push", "pull_request_target", "", "workflow_run"):
        with pytest.raises(dw.TaskError, match="no budget for the trigger"):
            dw.fuzz_plan(event, "900")


@pytest.mark.parametrize(
    ("event", "requested"),
    [
        ("pull_request", ""),
        ("schedule", ""),
        ("workflow_dispatch", "1"),
        ("workflow_dispatch", "3600"),
    ],
)
def test_the_time_limits_nest_inside_one_another(event: str, requested: str) -> None:
    plan = dw.fuzz_plan(event, requested)
    seconds = plan["seconds"]
    watchdog = seconds + dw.FUZZ_INPUT_TIMEOUT + dw.FUZZ_RUN_GRACE
    # The runner stops libFuzzer, and records TIMEOUT, before the step's limit.
    assert plan["step_timeout_minutes"] * 60 >= dw.FUZZ_BUILD_LIMIT + watchdog + dw.FUZZ_STEP_MARGIN
    # The step's limit leaves the job time to report and keep the evidence.
    assert plan["job_timeout_minutes"] >= plan["step_timeout_minutes"] + 10
    # libFuzzer gets its whole budget before the runner's limit.
    assert watchdog > seconds
    # GitHub-hosted jobs stop at six hours whatever the workflow says.
    assert plan["job_timeout_minutes"] <= 360


def test_the_workflow_takes_its_limits_from_the_plan() -> None:
    text = _workflow()
    plan = _job(text, "plan")
    assert "run: make fuzz-plan" in plan
    assert "DW_FUZZ_REQUESTED: ${{ inputs.seconds }}" in plan
    for output in ("seconds", "step_timeout_minutes", "job_timeout_minutes"):
        assert f"{output}: ${{{{ steps.plan.outputs.{output} }}}}" in plan
    block = _job(text, "libfuzzer")
    assert "needs: plan" in block
    assert "timeout-minutes: ${{ fromJSON(needs.plan.outputs.job_timeout_minutes) }}" in block
    fuzz = _step(block, "make fuzz")
    assert "timeout-minutes: ${{ fromJSON(needs.plan.outputs.step_timeout_minutes) }}" in fuzz
    assert "DW_FUZZ_SECONDS: ${{ needs.plan.outputs.seconds }}" in fuzz
    # Nothing in the coverage-guided job spells a budget of its own.
    assert re.search(r"DW_FUZZ_SECONDS: .*'\d+'", block) is None
    # The manual input's default is a budget the plan accepts.
    default = re.search(r"seconds:\n(?:        .*\n)*?        default: \"(\d+)\"", text)
    assert default is not None
    assert dw.fuzz_plan("workflow_dispatch", default.group(1))["seconds"] == int(default.group(1))
    assert f"1 to {dw.FUZZ_MAX_SECONDS}" in text


def test_fuzz_plan_hands_the_workflow_its_outputs(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    output = tmp_path / "output"
    summary = tmp_path / "summary"
    monkeypatch.setenv("GITHUB_EVENT_NAME", "schedule")
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    dw.task_fuzz_plan()
    plan = dw.fuzz_plan("schedule", "")
    assert output.read_text("utf-8").splitlines() == [f"{k}={v}" for k, v in plan.items()]
    assert "900 s of libFuzzer per target" in summary.read_text("utf-8")
    monkeypatch.setenv("GITHUB_EVENT_NAME", "workflow_dispatch")
    monkeypatch.setenv("DW_FUZZ_REQUESTED", "86400")
    with pytest.raises(dw.TaskError):
        dw.task_fuzz_plan()


# --- 8, 9, 10: failures, time limits and cancellations ----------------------


@pytest.mark.usefixtures("journal")
def test_a_crashing_target_fails_and_keeps_its_reproducer(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    crash = tmp_path / "fuzz" / "artifacts" / "dwkp_decode" / "crash-5eed"
    crash.parent.mkdir(parents=True)
    lines = [
        *_libfuzzer_lines(900)[:5],
        "thread '<unnamed>' panicked at crates/dwk-proto/src/frame.rs:10:5:",
        "==4242== ERROR: libFuzzer: deadly signal",
        f"artifact_prefix='{crash.parent}/'; Test unit written to {crash}",
    ]
    monkeypatch.setattr(dw, "_fuzz_run_argv", lambda _t, _s: _child(lines, 77, touch=str(crash)))
    monkeypatch.setenv("DW_FUZZ_TARGET", "dwkp_decode")
    with pytest.raises(dw.TaskError, match="dwkp_decode FAIL"):
        dw.task_fuzz()
    record = _record(tmp_path, "dwkp_decode")
    assert record["status"] == "FAIL"
    assert str(record["detail"]).startswith("CRASH: libFuzzer: deadly signal")
    assert record["exit_code"] == 77
    assert record["crash"] == {
        "artifact": dw._fuzz_sanitised(str(crash)),
        "readable": True,
        "bytes": len(b"crashing input"),
        "sha256": hashlib.sha256(b"crashing input").hexdigest(),
    }
    monkeypatch.setenv("DW_FUZZ_STEP_OUTCOME", "failure")
    with pytest.raises(dw.TaskError, match="dwkp_decode FAIL"):
        dw.task_fuzz_report()


def test_one_failing_target_does_not_stop_or_hide_the_others(
    monkeypatch: pytest.MonkeyPatch, journal: Path, tmp_path: Path
) -> None:
    monkeypatch.setenv("DW_FUZZ_SECONDS", "3")

    def run_argv(target: str, seconds: int) -> list[str]:
        if target == "canonical_roundtrip":
            lines = [*_libfuzzer_lines(seconds)[:5], "==7== ERROR: AddressSanitizer: SEGV"]
            return _child(lines, 1)
        return _child(_libfuzzer_lines(seconds))

    monkeypatch.setattr(dw, "_fuzz_run_argv", run_argv)
    with pytest.raises(dw.TaskError, match="1 of 8") as raised:
        dw.task_fuzz()
    assert "canonical_roundtrip FAIL" in str(raised.value)
    assert journal.read_text("utf-8").split() == list(dw.FUZZ_TARGETS)
    statuses = {t: _record(tmp_path, t)["status"] for t in dw.FUZZ_TARGETS}
    assert statuses == {t: "FAIL" if t == "canonical_roundtrip" else "PASS" for t in statuses}
    assert str(_record(tmp_path, "canonical_roundtrip")["detail"]).startswith("SANITIZER:")


@pytest.mark.usefixtures("journal")
def test_a_run_past_its_limit_is_stopped_and_recorded_as_a_timeout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(dw, "FUZZ_INPUT_TIMEOUT", 0)
    monkeypatch.setattr(dw, "FUZZ_RUN_GRACE", 1)
    monkeypatch.setenv("DW_FUZZ_TARGET", "envelope_version")
    monkeypatch.setenv("DW_FUZZ_SECONDS", "1")
    hung = _libfuzzer_lines(1)[:5]
    monkeypatch.setattr(dw, "_fuzz_run_argv", lambda _t, _s: _child(hung, 0, sleep=60))
    started = time.monotonic()
    with pytest.raises(dw.TaskError, match="envelope_version TIMEOUT"):
        dw.task_fuzz()
    assert time.monotonic() - started < 30, "the runner waited for the hung child"
    record = _record(tmp_path, "envelope_version")
    assert record["status"] == "TIMEOUT"
    assert record["exit_code"] is None
    assert dw.fuzz_verdict("envelope_version", record, "failure", {})[0] == "TIMEOUT"


def test_a_run_shorter_than_its_budget_is_not_a_pass() -> None:
    log = dw.LibFuzzerLog()
    for line in _libfuzzer_lines(3):
        log.feed(line)
    assert dw.classify_libfuzzer(0, log, 3)[0] == "PASS"
    status, detail = dw.classify_libfuzzer(0, log, 900)
    assert (status, detail) == ("FAIL", "libFuzzer stopped after 3 s of 900 s")
    unfinished = dw.LibFuzzerLog()
    for line in _libfuzzer_lines(900)[:-1]:
        unfinished.feed(line)
    assert dw.classify_libfuzzer(0, unfinished, 900)[0] == "FAIL"


@pytest.mark.parametrize(
    ("kind", "line"),
    [
        ("INPUT TIMEOUT", "==1== ERROR: libFuzzer: timeout after 61 seconds"),
        ("OUT OF MEMORY", "==1== ERROR: libFuzzer: out-of-memory (used: 2100Mb; exceeds: 2048Mb)"),
        ("LEAK", "==1==ERROR: LeakSanitizer: detected memory leaks"),
        ("SANITIZER", "==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x6"),
        ("CRASH", "==1== ERROR: libFuzzer: deadly signal"),
    ],
)
def test_every_kind_of_finding_fails(kind: str, line: str) -> None:
    log = dw.LibFuzzerLog()
    for each in [*_libfuzzer_lines(900)[:5], line]:
        log.feed(each)
    status, detail = dw.classify_libfuzzer(1, log, 900)
    assert status == "FAIL"
    assert detail.startswith(f"{kind}:")


def _running(target: str, phase: str = "fuzz") -> dict[str, object]:
    return {
        "schema": dw.FUZZ_EVIDENCE_SCHEMA,
        "engine": "libfuzzer",
        "target": target,
        "commit": SHA,
        "status": "RUNNING",
        "phase": phase,
        "requested_seconds": 900,
    }


def test_a_run_stopped_by_the_step_time_limit_is_a_timeout() -> None:
    status, detail = dw.fuzz_verdict("frame_decoder", _running("frame_decoder"), "failure", {})
    assert status == "TIMEOUT"
    assert "budget is not evidenced" in detail


def test_a_cancelled_run_is_never_completed() -> None:
    for outcome in ("cancelled", ""):
        status, _ = dw.fuzz_verdict("frame_decoder", _running("frame_decoder"), outcome, {})
        assert status == "CANCELLED"
    status, _ = dw.fuzz_verdict(
        "frame_decoder", _running("frame_decoder", "build"), "cancelled", {}
    )
    assert status == "CANCELLED"
    assert dw.fuzz_verdict("frame_decoder", None, "cancelled", {})[0] == "CANCELLED"
    assert dw.fuzz_verdict("frame_decoder", _running("frame_decoder"), "success", {})[0] == "FAIL"


def test_no_record_is_not_exercised(monkeypatch: pytest.MonkeyPatch) -> None:
    for outcome in ("failure", "skipped", "success", ""):
        assert dw.fuzz_verdict("url_parse", None, outcome, {})[0] == "NOT EXERCISED"
    monkeypatch.setenv("DW_FUZZ_TARGET", "url_parse")
    monkeypatch.setenv("DW_FUZZ_STEP_OUTCOME", "skipped")
    with pytest.raises(dw.TaskError, match="url_parse NOT EXERCISED"):
        dw.task_fuzz_report()


def test_every_verdict_is_one_of_the_five() -> None:
    passed = {
        **_running("url_parse"),
        "status": "PASS",
        "coverage_guided": True,
        "libfuzzer": {"reported_seconds": 900},
    }
    records: list[dict[str, object] | None] = [
        None,
        _running("url_parse"),
        passed,
        {**passed, "status": "FAIL"},
        {**passed, "status": "TIMEOUT"},
        {**passed, "status": "NOT EXERCISED"},
        {**passed, "status": "UNHEARD-OF"},
    ]
    for record in records:
        for outcome in ("success", "failure", "cancelled", "skipped", ""):
            status, _ = dw.fuzz_verdict("url_parse", record, outcome, {})
            assert status in dw.FUZZ_VERDICTS


# --- 12: the stable harness is never coverage-guided evidence ----------------


def test_output_without_coverage_counters_is_not_exercised() -> None:
    smoke = dw.LibFuzzerLog()
    for line in (
        "running 6 tests",
        "fuzz frame_decoder: 600 s, 1843200 iterations, 0 failures",
        "test fuzz_frame_decoder ... ok",
        "test result: ok. 6 passed; 0 failed; 0 ignored",
        "Done 1843200 runs in 600 second(s)",
    ):
        smoke.feed(line)
    assert not smoke.coverage_guided
    assert dw.classify_libfuzzer(0, smoke, 600)[0] == "NOT EXERCISED"


def test_a_record_of_another_engine_or_without_libfuzzers_report_is_not_a_pass() -> None:
    passed = {
        **_running("policy_loader"),
        "status": "PASS",
        "coverage_guided": True,
        "libfuzzer": {"reported_seconds": 900},
    }
    assert dw.fuzz_verdict("policy_loader", passed, "success", {})[0] == "PASS"
    smoke = {**passed, "engine": "stable-mutation"}
    assert dw.fuzz_verdict("policy_loader", smoke, "success", {})[0] == "NOT EXERCISED"
    for forged in (
        {**passed, "coverage_guided": False},
        {**passed, "libfuzzer": {"reported_seconds": 30}},
        {**passed, "libfuzzer": {}},
        {key: value for key, value in passed.items() if key != "libfuzzer"},
    ):
        assert dw.fuzz_verdict("policy_loader", forged, "success", {})[0] == "FAIL"


def test_without_cargo_fuzz_nothing_falls_back_to_the_smoke_harness(
    monkeypatch: pytest.MonkeyPatch, journal: Path, tmp_path: Path
) -> None:
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    ran: list[tuple[str, ...]] = []
    monkeypatch.setattr(dw, "run", lambda *command, **_options: ran.append(command))
    monkeypatch.setenv("DW_FUZZ_TARGET", "policy_evaluate")
    with pytest.raises(dw.TaskError, match="NOT EXERCISED"):
        dw.task_fuzz()
    assert ran == [] and not journal.exists()
    assert _record(tmp_path, "policy_evaluate")["status"] == "NOT EXERCISED"
    monkeypatch.setenv("DW_FUZZ_STEP_OUTCOME", "failure")
    with pytest.raises(dw.TaskError, match="policy_evaluate NOT EXERCISED"):
        dw.task_fuzz_report()


def test_the_workflow_keeps_the_two_engines_apart() -> None:
    text = _workflow()
    smoke = _job(text, "smoke")
    assert "run: make fuzz-smoke" in smoke
    assert "DW_FUZZ_" not in smoke and "fuzz/evidence" not in smoke
    libfuzzer = _job(text, "libfuzzer")
    assert "fuzz-smoke" not in libfuzzer and "DWK_FUZZ_SECONDS" not in libfuzzer
    assert re.search(r"^        run: make fuzz$", libfuzzer, re.MULTILINE)
    gate = _job(text, "fuzz")
    assert "stable mutation smoke, NOT coverage-guided" in gate


# --- 13: triggers ------------------------------------------------------------


def test_pull_requests_touching_a_fuzzed_surface_trigger_the_workflow() -> None:
    match = re.search(
        r"^  pull_request:\n(?:    #.*\n)*    paths:\n((?:      - .*\n)+)",
        _workflow(),
        re.MULTILINE,
    )
    assert match is not None
    paths = re.findall(r'^      - "([^"]+)"$', match.group(1), re.MULTILINE)
    for required in (
        "crates/dwk-proto/**",  # the protocol parser and canonicaliser, and its target bodies
        "crates/dwkd-authority/src/policy/**",  # the policy loader and evaluator
        "crates/dwkd-authority/src/capability/**",  # what policy evaluation reads
        "crates/dwkd-authority/tests/fuzz_targets/**",  # the policy target bodies
        "policy/**",  # the policy seeds
        "tests/protocol/vectors/**",  # the protocol seeds
        "fuzz/**",  # the cargo-fuzz targets and their lockfile
        "scripts/dw.py",  # the fuzz runner
        "Makefile",
        ".github/workflows/fuzz.yml",
        ".github/actions/setup/**",
    ):
        assert required in paths, f"a change to {required} does not trigger the Fuzz workflow"
    assert not [p for p in paths if p.startswith("docs") or p.endswith(".md")]
    on = _workflow().split("\npermissions:", 1)[0]
    assert re.search(r"^  schedule:\n", on, re.MULTILINE)
    assert re.search(r"^  workflow_dispatch:\n", on, re.MULTILINE)
    assert "pull_request_target" not in on


def test_only_a_pull_requests_run_is_cancelled_by_a_newer_one() -> None:
    text = _workflow()
    assert "cancel-in-progress: ${{ github.event_name == 'pull_request' }}" in text
    assert "group: fuzz-${{ github.event_name }}-${{ github.ref }}" in text


# --- 14: pins ----------------------------------------------------------------


def test_every_coverage_guided_job_installs_the_runners_pins() -> None:
    block = _job(_workflow(), "libfuzzer")
    install = _step(block, "Install the pinned nightly and cargo-fuzz")
    assert f"rustup toolchain install {dw.FUZZ_NIGHTLY} --profile minimal" in install
    assert f"cargo install cargo-fuzz --version {dw.CARGO_FUZZ_VERSION} --locked" in install
    assert _workflow().count("cargo install cargo-fuzz") == 1
    assert dw._fuzz_build_argv("x")[1] == dw._fuzz_run_argv("x", 1)[1] == f"+{dw.FUZZ_NIGHTLY}"


# --- 15: failure evidence is kept, and never read as success -----------------


def test_the_evidence_is_kept_whatever_happened() -> None:
    block = _job(_workflow(), "libfuzzer")
    report = _step(block, "make fuzz-report")
    assert "if: always()" in report
    assert "DW_FUZZ_STEP_OUTCOME: ${{ steps.fuzz.outcome }}" in report
    assert "DW_FUZZ_SECONDS: ${{ needs.plan.outputs.seconds }}" in report
    assert "run: make fuzz-report" in report
    kept = _step(block, "Keep this target's evidence record")
    assert "if: always()" in kept
    assert "path: fuzz/evidence/${{ matrix.target }}.json" in kept
    assert "retention-days: 7" in kept
    reproducer = _step(block, "Keep the reproducer of a failing target")
    assert "if: failure()" in reproducer
    assert "path: fuzz/artifacts/${{ matrix.target }}/" in reproducer
    assert "retention-days: 7" in reproducer
    gate = _job(_workflow(), "fuzz")
    assert "needs: [smoke, plan, libfuzzer]" in gate
    assert "if: always()" in gate
    assert "only 'success' counts" in gate


def test_a_record_from_another_run_is_never_this_runs_evidence() -> None:
    passed = {
        **_running("frame_decoder"),
        "status": "PASS",
        "coverage_guided": True,
        "libfuzzer": {"reported_seconds": 900},
        "run_id": "111",
        "run_attempt": "1",
    }
    this_run = {"GITHUB_RUN_ID": "111", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_SHA": SHA}
    assert dw.fuzz_verdict("frame_decoder", passed, "success", this_run)[0] == "PASS"
    for other in (
        {**this_run, "GITHUB_RUN_ID": "112"},
        {**this_run, "GITHUB_RUN_ATTEMPT": "2"},
        {**this_run, "GITHUB_SHA": "f" * 40},
    ):
        assert dw.fuzz_verdict("frame_decoder", passed, "success", other)[0] == "NOT EXERCISED"
    assert dw.fuzz_verdict("dwkp_decode", passed, "success", this_run)[0] == "NOT EXERCISED"
    planned = {**this_run, "DW_FUZZ_SECONDS": "30"}
    assert dw.fuzz_verdict("frame_decoder", passed, "success", planned)[0] == "FAIL"


def test_a_new_run_removes_the_last_runs_record_first(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    stale = tmp_path / "fuzz" / "evidence" / "location_resolve.json"
    stale.parent.mkdir(parents=True)
    stale.write_text(json.dumps({"target": "location_resolve", "status": "PASS"}), "utf-8")
    monkeypatch.setenv("DW_FUZZ_TARGET", "location_resolve")
    monkeypatch.setattr(dw, "_fuzz_build_argv", lambda _t: _child([], 101))
    with pytest.raises(dw.TaskError, match="location_resolve NOT EXERCISED"):
        dw.task_fuzz()
    record = _record(tmp_path, "location_resolve")
    assert record["status"] == "NOT EXERCISED"
    assert record["detail"] == "the build failed (exit 101); libFuzzer never ran"


def test_the_report_annotates_and_summarises_each_target(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    summary = tmp_path / "summary.md"
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary))
    monkeypatch.setenv("DW_FUZZ_TARGET", "frame_decoder")
    monkeypatch.setenv("DW_FUZZ_STEP_OUTCOME", "failure")
    dw._write_fuzz_record(_running("frame_decoder"))
    with pytest.raises(dw.TaskError, match="frame_decoder TIMEOUT"):
        dw.task_fuzz_report()
    out = capsys.readouterr().out
    assert "::error title=fuzz frame_decoder::TIMEOUT: " in out
    text = summary.read_text("utf-8")
    assert "not coverage-guided and is not counted here" in text
    assert "| frame_decoder | **TIMEOUT** | 900 |" in text
