"""M6.2.1 (ADR-0080, accepted 2026-11-27): the approval registry's real-process crash
evidence -- its children, its supervisor, its judging and its separation
from every release artifact -- agrees with the code.

The judging functions are tested here on every platform; the supervisor
itself, with a stand-in child that misbehaves in each way a real child could,
on Linux, where it runs.
"""

from __future__ import annotations

import json
import re
import stat
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CRATE = REPO_ROOT / "crates" / "dwkd-authority"
SRC = CRATE / "src"
STATE = SRC / "state"

sys.path.insert(0, str(REPO_ROOT / "scripts"))

import dw  # noqa: E402  - imported after the path is extended

LINUX_ONLY = pytest.mark.skipif(
    not sys.platform.startswith("linux"), reason="the supervisor runs its children on Linux"
)


def _read(path: Path) -> str:
    return path.read_bytes().decode("utf-8")


def _kebab(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "-", name).lower()


# --- the children: test-only, Linux-only, outside the state layer ----------


def test_the_crash_children_are_compiled_into_linux_unit_test_builds_only() -> None:
    lib = _read(SRC / "lib.rs")
    assert lib.count("\nmod crash_child;\n") == 1
    assert '\n#[cfg(all(test, target_os = "linux"))]\nmod crash_child;\n' in lib
    assert "\n#[cfg(test)]\nmod scratch;\n" in lib
    child = _read(SRC / "crash_child.rs")
    # It reads its assignment and writes its handshake; it starts, signals and
    # waits for no process (TX010), and holds no unsafe code or libc call.
    for forbidden in ("Command", "process::", "kill(", "unsafe", "libc", "signal::", "nix::"):
        assert forbidden not in child, forbidden
    assert "std::thread::park()" in child
    # The assignment's variables mean something to this file alone.
    holders = sorted(
        str(path.relative_to(SRC)).replace("\\", "/")
        for path in SRC.rglob("*.rs")
        if "DW_M621_" in _read(path)
    )
    assert holders == ["crash_child.rs"], holders
    scratch = _read(SRC / "scratch.rs")
    assert '    #[cfg(all(test, target_os = "linux"))]\n    pub(crate) const fn kept(' in scratch
    # The children are ignored tests of the Linux route tests' module.
    route = _read(STATE / "workload_route.rs")
    assert (
        '#[cfg(all(test, target_os = "linux"))]\n#[path = "workload_route_tests.rs"]\nmod tests;'
        in (route)
    )
    fixture = _read(STATE / "workload_route_tests.rs")
    assert '#[path = "approval_route_tests.rs"]\nmod approval;' in fixture
    tests = _read(STATE / "approval_route_tests.rs")
    for name in ("m6_2_1_crash_child", "m6_2_1_recovery_child"):
        at = tests.index(f"\nfn {name}() {{")
        head = tests[:at].splitlines()
        assert head[-2] == "#[test]", name
        assert head[-1].startswith('#[ignore = "a real-process '), name
    # The authority declares no Cargo feature: none can switch a seam on.
    assert "[features]" not in _read(CRATE / "Cargo.toml")
    # The pre-M6 host-launch test approval answers no in every other build.
    process = _read(STATE / "process.rs")
    approved = process[process.index("\nfn approved() -> bool {") :]
    approved = approved[: approved.index("\n}\n")]
    assert "#[cfg(not(test))]\n    {\n        false\n    }" in approved
    assert '#[cfg(all(test, target_os = "linux"))]\npub(crate) fn with_test_approval<' in process
    assert "#[cfg(test)]\nthread_local! {\n    static TEST_APPROVAL:" in process


def test_the_crash_tables_agree_between_the_children_and_the_supervisor() -> None:
    letters = dict(re.findall(r"Self::(\w+) => '(.)',", _read(STATE / "crash.rs")))
    tests = _read(STATE / "approval_route_tests.rs")
    size = re.search(r"const CRASH_CASES: \[CrashCase; (\d+)\] = \[", tests)
    assert size is not None
    rows = re.findall(
        r'crash_case\(\s*"([a-z0-9-]+)",\s*Scenario::(\w+),\s*(None|AT_USE|AT_REQUEST),'
        r"\s*CrashPoint::(\w+),\s*(true|false),?\s*\)",
        tests,
    )
    rust = [
        (name, _kebab(scenario), letters[point], durable == "true")
        for name, scenario, _, point, durable in rows
    ]
    assert len(rust) == int(size.group(1))
    assert rust == list(dw.APPROVAL_CRASH_CASES)
    assert len({case[0] for case in rust}) == len(rust)


def test_the_matrix_covers_every_window_it_claims() -> None:
    by: dict[str, set[str]] = {}
    for name, scenario, point, durable in dw.APPROVAL_CRASH_CASES:
        by.setdefault(scenario, set()).add(point)
        assert name.startswith(scenario + "-"), name
        assert durable == (point not in "AwBxyzH"), name
    assert by["spend"] == set("AwBCDEFGqtrs")
    assert by["migration"] == set("yzHI")
    assert by["request"] >= set("xBC")
    for scenario in (
        "grant",
        "deny",
        "ended-run-decision",
        "revoke",
        "expiry",
        "endpoint-grant",
        "endpoint-deny",
    ):
        assert {"B", "C"} <= by[scenario], scenario
    assert set(by) == {
        "spend",
        "request",
        "grant",
        "deny",
        "ended-run-decision",
        "revoke",
        "expiry",
        "migration",
        # M6.3 (ADR-0081): the approver endpoint's decision.
        "endpoint-grant",
        "endpoint-deny",
    }


def test_the_migration_crosses_its_points_in_order_inside_one_transaction() -> None:
    state = _read(STATE / "mod.rs")
    body = state[state.index("fn migrate_store(") :]
    body = body[: body.index("\n}\n")]
    order = [
        body.index("stop_migration(hook, CrashPoint::MigrationBeforeTransaction)?;"),
        body.index(".transaction_with_behavior(TransactionBehavior::Immediate)"),
        body.index("schema::migrate(&tx"),
        body.index("stop_migration(hook, CrashPoint::MigrationAfterSchema)?;"),
        body.index("audit::append"),
        body.index("stop_migration(hook, CrashPoint::MigrationBeforeCommit)?;"),
        body.index("tx.commit()"),
        body.index("stop_migration(hook, CrashPoint::MigrationAfterCommit)"),
    ]
    assert order == sorted(order)
    # A stop fails the start closed; no point is crossed by a plain start.
    helper = state[state.index("fn stop_migration(") :]
    helper = helper[: helper.index("\n}\n")]
    assert "Some(HookAction::Stop) => Err(StartError::Migration(" in helper
    crash = _read(STATE / "crash.rs")
    assert "pub const MIGRATION: [Self; 4]" in crash
    all_points = crash[crash.index("pub const ALL:") :]
    all_points = all_points[: all_points.index("];")]
    assert "Migration" not in all_points


# --- locating the executable -------------------------------------------------


def _artifact(
    name: str = "dwkd_authority",
    kind: str = "lib",
    test: bool = True,
    executable: str | None = "/t/debug/deps/dwkd_authority-0123",
) -> str:
    return json.dumps(
        {
            "reason": "compiler-artifact",
            "target": {"name": name, "kind": [kind]},
            "profile": {"test": test},
            "executable": executable,
        }
    )


def test_the_unit_test_executable_is_selected_from_cargo_messages_only() -> None:
    found = dw.select_unit_test_executable(
        [
            "garbage",
            "{not json",
            json.dumps({"reason": "build-finished", "success": True}),
            _artifact(name="dwk_proto"),
            _artifact(kind="bin", executable="/t/debug/deps/dwkd_authority-bin"),
            _artifact(test=False, executable=None),
            _artifact(),
        ]
    )
    assert found == Path("/t/debug/deps/dwkd_authority-0123")
    for lines in (
        [],
        [_artifact(test=False)],
        [_artifact(executable=None)],
        [_artifact(kind="bin")],
        [_artifact(name="dwkd_authority_other")],
        [_artifact(), _artifact(executable="/t/other")],
    ):
        with pytest.raises(dw.TaskError, match="expected one library unit-test executable"):
            dw.select_unit_test_executable(lines)


def test_the_children_must_be_listed_each_once() -> None:
    both = f"{dw.APPROVAL_CRASH_CHILD}: test\n{dw.APPROVAL_RECOVERY_CHILD}: test\n"
    dw.require_crash_children("noise\n" + both + "2 tests, 0 benchmarks\n")
    for listing in ("", f"{dw.APPROVAL_CRASH_CHILD}: test\n", both + both, "0 tests\n"):
        with pytest.raises(dw.TaskError, match="NOT EXERCISED"):
            dw.require_crash_children(listing)


# --- judging a crash child ---------------------------------------------------

CASE = dw.APPROVAL_CRASH_CASES[3]  # spend-after-commit, C, durable
NAME, LETTER = CASE[0], CASE[2]


def test_a_crash_counts_only_at_its_window_and_by_the_supervisors_kill() -> None:
    dw.judge_crash_child(CASE, f"{NAME} {LETTER}\n", -dw.APPROVAL_CRASH_SIGKILL, False)
    for ready, code, timed_out, why in (
        (None, None, True, "never reached its window"),
        (None, 0, False, "before its window"),  # an early exit, or zero tests
        (None, 101, False, "before its window"),  # a panic
        (None, -6, False, "before its window"),  # an abort
        (f"{NAME} B\n", -9, False, "another window"),
        (f"spend-before-transaction {LETTER}\n", -9, False, "another window"),
        ("", -9, False, "another window"),
        (f"{NAME} {LETTER}\n", 0, False, "not the supervisor's SIGKILL"),
        (f"{NAME} {LETTER}\n", -15, False, "not the supervisor's SIGKILL"),
        (f"{NAME} {LETTER}\n", -6, False, "not the supervisor's SIGKILL"),
        (f"{NAME} {LETTER}\n", 101, False, "not the supervisor's SIGKILL"),
        (f"{NAME} {LETTER}\n", None, False, "not the supervisor's SIGKILL"),
    ):
        with pytest.raises(dw.TaskError, match=why):
            dw.judge_crash_child(CASE, ready, code, timed_out)


# --- judging a recovery child -------------------------------------------------


def _recovery_output(
    record: dict[str, object], *, lines: int = 1, summary: str | None = None
) -> str:
    evidence = "\n".join(f"{dw.APPROVAL_CRASH_PREFIX}{json.dumps(record)}" for _ in range(lines))
    return (
        "running 1 test\n"
        f"{evidence}\n"
        f"{summary or 'test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured'}\n"
    )


def test_the_expectations_follow_the_case() -> None:
    spend = dw.approval_crash_expected(CASE)
    assert (spend["requests"], spend["approvals"], spend["uses"], spend["intents"]) == (1, 1, 1, 1)
    assert spend["version"] == 15 and spend["fenced"] == "refused" and spend["durable"] is True
    undone = dw.approval_crash_expected(dw.APPROVAL_CRASH_CASES[2])  # use before commit
    assert (undone["uses"], undone["intents"]) == (0, 0)
    by_name = {case[0]: case for case in dw.APPROVAL_CRASH_CASES}
    before = dw.approval_crash_expected(by_name["migration-before-commit"])
    after = dw.approval_crash_expected(by_name["migration-after-commit"])
    assert (before["version"], after["version"]) == (14, 15)
    assert before["fenced"] == after["fenced"] == "migrated"
    expiry = dw.approval_crash_expected(by_name["expiry-after-commit"])
    assert (expiry["requests"], expiry["approvals"]) == (2, 1)


def test_a_recovery_counts_only_with_one_test_and_its_exact_line() -> None:
    expected = dw.approval_crash_expected(CASE)
    record = dw.judge_crash_recovery(CASE, 0, _recovery_output(expected))
    assert record == expected
    wrong_fields = [
        ("requests", 2),
        ("approvals", 0),
        ("uses", 0),
        ("intents", 2),
        ("version", 14),
        ("durable", False),
        ("audit", "unverified"),
        ("fenced", "migrated"),
        ("suite", "authority-approval-registry"),
        ("case", "spend-after-start"),
        ("point", "B"),
        ("count", 2),
    ]
    for key, value in wrong_fields:
        with pytest.raises(dw.TaskError, match=f"found {key}="):
            dw.judge_crash_recovery(CASE, 0, _recovery_output({**expected, key: value}))
    missing = {k: v for k, v in expected.items() if k != "uses"}
    with pytest.raises(dw.TaskError, match="found uses=None"):
        dw.judge_crash_recovery(CASE, 0, _recovery_output(missing))
    for code, output, why in (
        (101, _recovery_output(expected), "recovery child failed"),
        (None, _recovery_output(expected), "recovery child failed"),
        (
            0,
            _recovery_output(expected, summary="test result: ok. 0 passed; 0 failed"),
            "ran no test",
        ),
        (0, _recovery_output(expected) + "test result: ok. 1 passed; 0 failed\n", "ran no test"),
        (0, "test result: ok. 1 passed; 0 failed\n", "expected one recovery evidence line"),
        (0, _recovery_output(expected, lines=2), "expected one recovery evidence line"),
        (
            0,
            f"{dw.APPROVAL_CRASH_PREFIX}{{not json\ntest result: ok. 1 passed; 0 failed\n",
            "unreadable",
        ),
        (0, f"{dw.APPROVAL_CRASH_PREFIX}[1]\ntest result: ok. 1 passed; 0 failed\n", "unreadable"),
    ):
        with pytest.raises(dw.TaskError, match=why):
            dw.judge_crash_recovery(CASE, code, output)


# --- the supervisor, against a stand-in child --------------------------------

STAND_IN = r"""
import json, os, signal, sys, time
mode = os.environ.get("M621_STAND_IN_MODE", "")
argv = sys.argv[1:]
if "--ignored" not in argv or "--exact" not in argv:
    sys.exit(3)
if "DW_M621_CRASH_CASE" in os.environ:
    if argv[-1] != os.environ["M621_STAND_IN_CRASH"] or "DW_M621_RECOVER_CASE" in os.environ:
        sys.exit(3)
    if mode == "early-exit":
        sys.exit(0)
    if mode == "panic":
        sys.exit(101)
    if mode == "abort":
        os.abort()
    if mode == "hang":
        time.sleep(600)
    ready = os.environ["DW_M621_READY"]
    letter = "Z" if mode == "wrong-window" else os.environ["M621_STAND_IN_LETTER"]
    with open(ready + ".partial", "w") as f:
        f.write(os.environ["DW_M621_CRASH_CASE"] + " " + letter + "\n")
    os.rename(ready + ".partial", ready)
    while True:
        signal.pause()
elif "DW_M621_RECOVER_CASE" in os.environ:
    if argv[-1] != os.environ["M621_STAND_IN_RECOVERY"] or "DW_M621_CRASH_CASE" in os.environ:
        sys.exit(3)
    if mode == "recovery-fails":
        print("test result: FAILED. 0 passed; 1 failed")
        sys.exit(101)
    if mode == "zero-tests":
        print("test result: ok. 0 passed; 0 failed; 0 ignored")
        sys.exit(0)
    record = json.loads(os.environ["M621_STAND_IN_RECORD"])
    if mode == "wrong-count":
        record["uses"] = 7
    print("APPROVAL-CRASH-EVIDENCE " + json.dumps(record))
    print("test result: ok. 1 passed; 0 failed; 0 ignored")
else:
    sys.exit(4)
"""


@pytest.fixture
def stand_in(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    script = tmp_path / "stand_in.py"
    script.write_text(STAND_IN, encoding="utf-8")
    executable = tmp_path / "dwkd_authority-stand-in"
    executable.write_text(f'#!/bin/sh\nexec "{sys.executable}" "{script}" "$@"\n', encoding="utf-8")
    executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
    monkeypatch.setenv("M621_STAND_IN_CRASH", dw.APPROVAL_CRASH_CHILD)
    monkeypatch.setenv("M621_STAND_IN_RECOVERY", dw.APPROVAL_RECOVERY_CHILD)
    monkeypatch.setenv("M621_STAND_IN_LETTER", LETTER)
    monkeypatch.setenv("M621_STAND_IN_RECORD", json.dumps(dw.approval_crash_expected(CASE)))
    # A variable of the supervisor's own from the outer environment is never
    # passed through.
    monkeypatch.setenv("DW_M621_RECOVER_CASE", "inherited")
    return executable


@LINUX_ONLY
def test_the_supervisor_kills_its_child_at_the_window_and_recovers(
    stand_in: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("M621_STAND_IN_MODE", "")
    record = dw.run_approval_crash_case(stand_in, CASE, tmp_path / "cases")
    assert record["handshake"] == f"{NAME} {LETTER}"
    assert record["termination"] == f"SIGKILL ({dw.APPROVAL_CRASH_SIGKILL})"
    assert record["category"] == "real-process"
    work = tmp_path / "cases" / NAME
    assert stat.S_IMODE(work.stat().st_mode) == 0o700
    assert (work / "recovery-child.log").is_file()


@LINUX_ONLY
@pytest.mark.parametrize(
    ("mode", "why"),
    [
        ("early-exit", "before its window"),
        ("panic", "before its window"),
        ("abort", "before its window"),
        ("wrong-window", "another window"),
        ("hang", "never reached its window"),
        ("recovery-fails", "recovery child failed"),
        ("zero-tests", "ran no test"),
        ("wrong-count", "found uses=7"),
    ],
)
def test_the_supervisor_refuses_every_other_ending(
    stand_in: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, mode: str, why: str
) -> None:
    monkeypatch.setenv("M621_STAND_IN_MODE", mode)
    monkeypatch.setattr(dw, "APPROVAL_CRASH_READY_LIMIT", 2.0)
    with pytest.raises(dw.TaskError, match=why):
        dw.run_approval_crash_case(stand_in, CASE, tmp_path / "cases")


def test_the_supervisor_ends_only_its_own_child() -> None:
    source = _read(REPO_ROOT / "scripts" / "dw.py")
    body = source[source.index("def run_approval_crash_case(") :]
    body = body[: body.index("\ndef ")]
    assert "os.kill(child.pid, APPROVAL_CRASH_SIGKILL)" in body
    for broad in ("killpg", "pkill", "killall", "shell=True", "os.system"):
        assert broad not in body, broad
    assert body.count("preexec_fn=_no_core_dump") == 2
    assert "start_new_session=True" in body
    core = source[source.index("def _no_core_dump(") :]
    core = core[: core.index("\ndef ")]
    assert "resource.setrlimit(resource.RLIMIT_CORE, (0, 0))" in core


# --- the separation scan ------------------------------------------------------


def _release(
    rlib: bytes = b"..." + dw.APPROVAL_RELEASE_SYMBOL_CONTROL,
    daemon: bytes = b"..."
    + dw.APPROVAL_RELEASE_LITERAL_CONTROL
    + b"."
    + dw.APPROVER_RELEASE_LITERAL_CONTROL,
    client: bytes = b"clean." + dw.APPROVER_RELEASE_LITERAL_CONTROL,
) -> list[tuple[str, bytes]]:
    # M6.3 (ADR-0081): both the daemon and the trusted client must speak
    # the approver protocol for the scan to count.
    return [("direwolf", client), ("dwkd-authority", daemon), ("libdwkd_authority.rlib", rlib)]


def test_the_separation_scan_needs_its_controls_and_finds_a_seam() -> None:
    seams = dw.approval_test_seams()
    control = b"\0".join(seams)
    assert len(dw.judge_seam_separation(control, _release())) == 3
    # A bare name -- what the release metadata keeps of an item a `cfg`
    # removed -- is not a trace of its code.
    named = b"\x12with_test_approval\x0bcrash_child"
    assert len(dw.judge_seam_separation(control, _release(rlib=_release()[2][1] + named))) == 3
    for absent in (b"16attach_approvers", b"DW_M621_CRASH_CASE"):
        with pytest.raises(dw.TaskError, match="the scan is blind"):
            dw.judge_seam_separation(control.replace(absent, b""), _release())
    with pytest.raises(dw.TaskError, match="no release artifact"):
        dw.judge_seam_separation(control, [])
    # A stripped or wrong library, or a daemon without the registry: blind.
    with pytest.raises(dw.TaskError, match="no release library shows a compiled symbol"):
        dw.judge_seam_separation(control, _release(rlib=b"stripped"))
    with pytest.raises(dw.TaskError, match="no registry literal"):
        dw.judge_seam_separation(control, _release(daemon=b"other"))
    # M6.3: a client or a daemon that does not speak the approver protocol
    # is the wrong file, or a stripped one: blind.
    with pytest.raises(dw.TaskError, match="direwolf does not speak the approver protocol"):
        dw.judge_seam_separation(control, _release(client=b"clean"))
    with pytest.raises(dw.TaskError, match="dwkd-authority does not speak"):
        dw.judge_seam_separation(
            control, _release(daemon=b"..." + dw.APPROVAL_RELEASE_LITERAL_CONTROL)
        )
    for seam in seams:
        with pytest.raises(dw.TaskError, match="holds test-only seams"):
            dw.judge_seam_separation(control, [*_release(), ("dwkd-broker", b"." + seam + b".")])
    assert b"16attach_approvers" in seams
    assert b"17approver_endpoint" in seams, "M6.3's in-process endpoint for the route tests"
    assert b"18with_test_approval" in seams
    assert b"13TEST_APPROVAL" in seams
    assert b"DW_M621_CRASH_CASE" in seams


# --- tasks, CI and the evidence categories -------------------------------------


def test_the_tasks_run_in_ci_and_the_makefile() -> None:
    assert dw.TASKS["approval-registry-crash-evidence"] is dw.task_approval_registry_crash_evidence
    assert dw.TASKS["approval-registry-separation"] is dw.task_approval_registry_separation
    makefile = _read(REPO_ROOT / "Makefile")
    for target in ("approval-registry-crash-evidence", "approval-registry-separation"):
        assert f"\n{target}: ## M6.2.1" in makefile, target
        assert f"\t@$(DW) {target}\n" in makefile, target
    ci = _read(REPO_ROOT / ".github" / "workflows" / "ci.yml")
    job = ci[ci.index("\n  authority-transport:\n") :]
    job = job[: job.index("\n\n  #")]
    evidence = job.index("      - run: make approval-registry-evidence\n")
    assert job.index("      - run: make approval-registry-crash-evidence\n") > evidence
    build = ci[ci.index("\n  build:\n") :]
    build = build[: build.index("\n\n  #")]
    release = build.index("      - run: cargo build --workspace --release\n")
    # The job's last step: the slice ends before its newline.
    assert build.endswith("\n      - run: make approval-registry-separation")
    assert build.index("      - run: make approval-registry-separation") > release
    assert "build" in ci[ci.index("\n  ci:\n") :]


def test_every_evidence_case_has_one_category_and_none_claims_a_real_process() -> None:
    categories = dw.APPROVAL_EVIDENCE_CATEGORIES
    assert sorted(categories) == sorted(dw.APPROVAL_EVIDENCE_CASES)
    assert set(categories.values()) <= {
        "end-to-end",
        "end-to-end-drift",
        "component",
        "structural",
        "fail-closed",
        "in-process-hook",
    }
    assert len(dw.APPROVAL_EVIDENCE_CASES) == 34


def test_the_record_stage_never_runs_a_test_a_source_edit_alone_fails() -> None:
    nodes = dw.APPROVAL_REGISTRY_RECORD_TESTS
    assert len(nodes) == len(set(nodes)) == 4
    for node in nodes:
        path, name = node.split("::")
        assert f"\ndef {name}(" in _read(REPO_ROOT / path), node
    joined = "\n".join(nodes)
    assert "mutation_table" not in joined
    assert "spend_guard_has_a_mutant" not in joined
    assert "migration_crosses_its_points" not in joined
