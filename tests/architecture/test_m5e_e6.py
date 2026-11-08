"""R3's E6 cannot pass unless every hard rule was weakened, caught and refused.

ADR-0057's E6, which the owner's R-B requires (M5E_ASSURANCE_PLAN.md §§3a,
3b; issue #19), is a real `PROXY_ONLY` environment the released broker
prepared with exactly one hard rule weakened -- by a test-only runtime that
does not do what the plan asks (ADR-0058) -- measured from both vantages and
refused by the production decision. It runs only on a disposable
GitHub-hosted runner, so its wiring and its gate are held here:

* the required `sandbox-proxy-weakened` job runs the task once, with its flag,
  which no other job sets; the task refuses before it builds anything
  anywhere else; the test is ignored, hosted only, checks its flag before it
  makes anything, and runs the one case that touches the host only where
  that host is disposable;
* the test's rows and the task's are one account, and together they cover
  every one of ADR-0057 §1a's fifteen rows, each with the invariants §1a
  names and from the vantage it names;
* the gate refuses every way an E6 line could mislead -- a weakening kept,
  refused by too little or too much, from another vantage, with the topology
  or the rest unreported, a row not exercised, the count short -- and the
  raw observations are checked again from their bytes: a digest, a missing or
  extra file, a record that does not show the weakening, a create changed
  beyond its row, a report that is not the probe's, an inside verdict the
  broker did not answer, a refusal the broker never made, a topology never
  built; and the offline review of a hosted log refuses a tampered one.

The synthetic data below tests the gate only; it is never evidence. Only the
hosted job, on a real runtime, produces E6.
"""

from __future__ import annotations

import base64
import hashlib
import inspect
import json
import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CI = REPO_ROOT / ".github" / "workflows" / "ci.yml"
SUITE = REPO_ROOT / "crates" / "dwkd-broker" / "tests" / "sandbox_egress.rs"
RESIDUAL = REPO_ROOT / "docs" / "adr" / "0057-m5e-proxy-only-real-container-evidence-residual.md"

sys.path.insert(0, str(REPO_ROOT / "scripts"))
import dw  # noqa: E402  - imported after the path is extended

JOB = "sandbox-proxy-weakened"
AGGREGATE_JOB = "ci"
COMMAND = "make sandbox-proxy-weakened-evidence"
FLAG = "DW_E6_EVIDENCE"
TEST = "every_hard_rule_weakened_in_a_real_proxy_only_environment_is_refused"


# --- the workflow, read as text ------------------------------------------------


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


def test_the_e6_job_exists_is_unconditional_and_required() -> None:
    job = _jobs().get(JOB)
    assert job is not None, f"no `{JOB}` job: E6 is evidenced nowhere"
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


def test_the_e6_job_runs_its_task_with_its_flag_and_nothing_else_has_it() -> None:
    jobs = _jobs()
    found = [s for s in _steps(jobs[JOB]) if _run(s) == COMMAND]
    assert len(found) == 1, f"{JOB} must run `{COMMAND}` exactly once"
    assert _env(found[0]) == {FLAG: "1"}
    for name, job in jobs.items():
        if name == JOB:
            continue
        for step in _steps(job):
            assert FLAG not in _env(step), f"{name} sets {FLAG}: only {JOB} weakens a runtime"
            assert "sandbox-proxy-weakened" not in _run(step), name


@pytest.mark.parametrize(
    ("environ", "said"),
    [
        ({}, "DW_E6_EVIDENCE=1 is not set"),
        ({FLAG: "0", "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}, "not set"),
        ({FLAG: "1"}, "not a disposable GitHub-hosted runner"),
        ({FLAG: "1", "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "self-hosted"}, "not a"),
    ],
    ids=["no-flag", "flag-off", "off-actions", "self-hosted"],
)
def test_the_task_refuses_before_anything_runs_off_a_disposable_runner(
    monkeypatch: pytest.MonkeyPatch, environ: dict[str, str], said: str
) -> None:
    for name in (FLAG, "GITHUB_ACTIONS", "RUNNER_ENVIRONMENT"):
        monkeypatch.delenv(name, raising=False)
    for name, value in environ.items():
        monkeypatch.setenv(name, value)
    monkeypatch.setattr(sys, "platform", "linux")
    built: list[str] = []
    monkeypatch.setattr(dw, "_proxy_only_images", lambda *_: built.append("images"))
    monkeypatch.setattr(dw, "_trusted_client", lambda *_: built.append("client"))
    with pytest.raises(dw.TaskError, match=f"NOT EXERCISED: .*{re.escape(said)}"):
        dw.task_sandbox_proxy_weakened_evidence()
    assert not built, "the task built something before it knew where it was"
    assert (
        dw.e6_refusal({FLAG: "1", "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"})
        is None
    )


def test_the_task_checks_where_it_is_then_its_census_then_its_lines_then_their_bytes() -> None:
    source = inspect.getsource(dw.task_sandbox_proxy_weakened_evidence)
    order = [
        "e6_refusal(os.environ)",
        "_trusted_client(",
        "_runtime_state(client, socket)",
        "_proxy_only_images(",
        "run_captured(",
        "    finally:\n",
        "the evidence left {len(left)} container(s)",
        "that predate the evidence are",
        "require_attributed_evidence(output, E6_CASES)",
        "e6_check_raw(output, raw, lines, tag)",
        "_e6_publish(files, provenance, census)",
    ]
    at = [source.index(marker) for marker in order]
    assert at == sorted(at), dict(zip(order, at, strict=True))
    assert 'if "Docker Desktop" in system' in source


def test_the_test_is_ignored_hosted_only_and_guarded_before_it_makes_anything() -> None:
    source = SUITE.read_text(encoding="utf-8")
    module = source[source.index("    mod e6 {") :]
    found = re.search(r'#\[ignore = "([^"]*)"\]\s*fn ' + TEST + r"\(\)", module)
    assert found is not None, f"{TEST} is not an #[ignore]d test"
    assert "hosted only" in found.group(1), found.group(1)
    body = module[module.index(f"fn {TEST}()") :]
    flag = body.index(FLAG)
    assert flag < body.index("Evidence::load()") < body.index("Broker::evidence("), (
        "the test checks its flag before it makes anything"
    )
    assert body.index("disposable_runner(") < body.index("the_control(")
    loop = body[body.index("for row in ROWS") :]
    assert (
        loop.index("row.host_side_effect")
        < loop.index("Err(why) = &runner")
        < loop.index("refused(&lab")
    ), "the case that touches the host runs only where the host is disposable"
    guard = module[module.index("fn disposable_runner(") : module.index("fn host_loopback(")]
    for check in ("GITHUB_ACTIONS", "RUNNER_ENVIRONMENT", "Docker Desktop"):
        assert check in guard, check
    # Selected by the E6 task alone: the egress task never runs it.
    assert not [t for t in dw.EGRESS_BROKER_TESTS if t.endswith(TEST)]
    assert (f"linux::e6::{TEST}",) == dw.E6_TESTS


# --- the rows: one account, every one of ADR-0057 §1a's -----------------------


def _snake(name: str) -> str:
    return re.sub(r"(?<!^)(?=[A-Z])", "_", name).upper()


def _rust_rows() -> dict[str, tuple[str, tuple[str, ...], tuple[str, ...], bool]]:
    source = SUITE.read_text(encoding="utf-8")
    block = source[source.index("const ROWS: &[Row] = &[") :]
    block = block[: block.index("\n        ];")]
    rows = {}
    for found in re.finditer(r"Row \{(.*?)\n            \}", block, re.DOTALL):
        body = found.group(1)
        case = re.search(r'case: "([^"]+)"', body)
        row = re.search(r'row: "([^"]+)"', body)
        changed = re.search(r"changed: &\[(.*?)\]", body, re.DOTALL)
        caught = re.search(r"caught: &\[(.*?)\]", body, re.DOTALL)
        side = re.search(r"host_side_effect: (true|false)", body)
        assert case and row and changed and caught and side, body
        rows[case.group(1)] = (
            row.group(1),
            tuple(_snake(i) for i in re.findall(r"I::(\w+)", caught.group(1))),
            tuple(re.findall(r'"([^"]+)"', changed.group(1))),
            side.group(1) == "true",
        )
    return rows


def test_the_tests_rows_and_the_tasks_are_one_account() -> None:
    rust = _rust_rows()
    assert list(rust) == list(dw.E6_ROWS), "the same cases, in the same order"
    for case, (row, caught, changed, side) in rust.items():
        assert dw.E6_ROWS[case] == (row, caught, changed), case
        assert side == (case == dw.E6_HOST_SIDE_EFFECT), case
    assert list(rust)[-1] == dw.E6_HOST_SIDE_EFFECT, "the host's network runs last"


# ADR-0057 §1a's rows, by their first column, and the E6 row each is.
SECTION_1A = {
    "Read-only root": "read-only-root",
    "Non-root user": "non-root-user",
    "Not privileged": "not-privileged",
    "No runtime socket": "no-runtime-socket",
    "Capabilities dropped": "capabilities-dropped",
    "`no-new-privileges`": "no-new-privileges",
    "The pinned seccomp profile, not unconfined": "seccomp-not-unconfined",
    "The pinned seccomp profile, not the runtime's default": "seccomp-not-runtime-default",
    "Private PID namespace": "private-pid-namespace",
    "Private IPC namespace": "private-ipc-namespace",
    "Private UTS namespace": "private-uts-namespace",
    "Isolated network": "isolated-network",
    "Image pinned by digest": "digest-pinned-image",
    "No devices": "no-additional-devices",
    "Resource limits, the 8 192 task backstop included": "resource-limits",
}


def test_every_row_of_adr_0057_1a_is_covered_from_its_vantage() -> None:
    text = RESIDUAL.read_text(encoding="utf-8")
    section = text[text.index("### 1a. By hard rule") : text.index("### 2. What is proven")]
    rows = [
        line
        for line in section.splitlines()
        if line.startswith("| ") and not line.startswith("| Hard rule ")
    ]
    assert len(rows) == 15, len(rows)
    previous: list[str] = []
    for line in rows:
        title, invariants = (cell.strip() for cell in line.split("|")[1:3])
        named = re.findall(r"`((?:HOST|CONTAINER)_[A-Z_]+)`", invariants) or previous
        previous = named
        both = "(both)" in invariants
        assert both or "(host only)" in invariants, line
        slug = SECTION_1A[title]
        cases = [case for case, (row, _, _) in dw.E6_ROWS.items() if row == slug]
        assert cases, f"no E6 case for §1a's {title!r}"
        caught = {i for case in cases for i in dw.E6_ROWS[case][1]}
        assert set(named) <= caught, (title, sorted(set(named) - caught))
        inside = any(i.startswith("CONTAINER_") for i in caught)
        assert inside == both, (title, "the vantage §1a names")
    assert set(SECTION_1A.values()) == set(dw.E6_ROW_NAMES)
    assert len(dw.E6_ROW_NAMES) == 15


# --- the gate: what a line says ---------------------------------------------------


TOPOLOGY = "+".join(f"{name}=PASS" for name in dw.E6_TOPOLOGY)
ROW = "e6-weakened-privileged-refused"


def _line(case: str, outcome: str, enforcement: str | None = None) -> dict[str, object]:
    level, mechanisms = dw.attribution(dw.E6_SUITE, case) or ("", frozenset())
    return {
        "suite": dw.E6_SUITE,
        "case": case,
        "outcome": outcome,
        "level": level,
        "enforcement": enforcement or sorted(mechanisms)[0],
    }


def _good(case: str) -> str:
    if case == dw.E6_CONTROL:
        return (
            f"kept:every-required-invariant-pass;topology:{TOPOLOGY};"
            "forwarded-unchanged;destroyed:removed"
        )
    if case == dw.E6_COUNT:
        n, rows = len(dw.E6_ROWS), len(dw.E6_ROW_NAMES)
        return f"refused-{n}-of-{n}-cases;rows-{rows}-of-{rows}"
    _, caught, changed = dw.E6_ROWS[case]
    added = "169.254.7.1/32" if case == dw.E6_HOST_SIDE_EFFECT else "not-applicable"
    return (
        f"refused:{'+'.join(caught)};also:CONTAINER_RAW_SOCKETS_REFUSED=UNOBSERVABLE;"
        f"topology:{TOPOLOGY};weakened:{'+'.join(changed)};host-loopback-added:{added}"
    )


def _output(lines: list[dict[str, object]]) -> str:
    return "\n".join(f"{dw.SANDBOX_EVIDENCE_PREFIX}{json.dumps(line)}" for line in lines)


def _complete() -> list[dict[str, object]]:
    return [_line(case, _good(case)) for _, case in dw.E6_CASES]


def test_a_complete_e6_output_passes() -> None:
    assert len(dw.require_attributed_evidence(_output(_complete()), dw.E6_CASES)) == 18


@pytest.mark.parametrize(
    ("case", "outcome", "enforcement", "said"),
    [
        (ROW, f"kept:every-required-invariant-pass;topology:{TOPOLOGY}", None, "must be refused"),
        (
            ROW,
            f"refused:HOST_NOT_PRIVILEGED;also:none;topology:{TOPOLOGY};weakened:"
            "HostConfig.Privileged;host-loopback-added:not-applicable",
            None,
            "must be exactly",
        ),
        (
            "e6-weakened-host-ipc-refused",
            _good("e6-weakened-host-ipc-refused"),
            "measured-both",
            "enforcement 'measured-both' is not what this case exercises",
        ),
        (ROW, _good(ROW).replace(f";topology:{TOPOLOGY}", ""), None, "topology's four"),
        (ROW, _good(ROW).replace("=UNOBSERVABLE", "=PASS"), None, "what else did not pass"),
        (
            ROW,
            _good(ROW).replace("also:CONTAINER_RAW_SOCKETS_REFUSED", "also:HOST_NOT_PRIVILEGED"),
            None,
            "what else did not pass",
        ),
        (
            ROW,
            _good(ROW).replace("HostConfig.Privileged", "HostConfig.CapAdd"),
            None,
            "the weakening must be",
        ),
        (
            dw.E6_HOST_SIDE_EFFECT,
            _good(dw.E6_HOST_SIDE_EFFECT).replace("169.254.7.1/32", "unobservable"),
            None,
            "loopback gained is not observed",
        ),
        (ROW, _good(ROW).replace("not-applicable", "none"), None, "touches no host"),
        (
            dw.E6_CONTROL,
            _good(dw.E6_CONTROL).replace("HOST_RELAY_DIGEST=PASS", "HOST_RELAY_DIGEST=FAIL"),
            None,
            "topology must pass whole",
        ),
        (dw.E6_CONTROL, f"refused:HOST_NOT_PRIVILEGED;topology:{TOPOLOGY}", None, "must be kept"),
        (dw.E6_COUNT, "refused-15-of-16-cases;rows-15-of-15", None, "every case refused"),
    ],
    ids=[
        "kept",
        "refused-by-too-little",
        "wrong-vantage",
        "topology-unreported",
        "a-pass-in-also",
        "also-names-a-caught-one",
        "another-field",
        "host-residue-unobserved",
        "residue-where-no-host",
        "control-topology-failed",
        "control-refused",
        "count-short",
    ],
)
def test_an_e6_line_that_misleads_fails(
    case: str, outcome: str, enforcement: str | None, said: str
) -> None:
    lines = _complete()
    at = next(i for i, line in enumerate(lines) if line["case"] == case)
    lines[at] = _line(case, outcome, enforcement)
    with pytest.raises(dw.TaskError, match=re.escape(said)):
        dw.require_attributed_evidence(_output(lines), dw.E6_CASES)


def test_a_row_not_exercised_or_missing_fails_e6_whole() -> None:
    lines = _complete()
    at = next(i for i, line in enumerate(lines) if line["case"] == dw.E6_HOST_SIDE_EFFECT)
    unexercised = [
        *lines[:at],
        _line(dw.E6_HOST_SIDE_EFFECT, "not-exercised: here"),
        *lines[at + 1 :],
    ]
    with pytest.raises(dw.TaskError, match="NOT EXERCISED: 1 required case"):
        dw.require_attributed_evidence(_output(unexercised), dw.E6_CASES)
    with pytest.raises(dw.TaskError, match="NOT EXERCISED: 1 required case"):
        dw.require_attributed_evidence(_output(lines[:at] + lines[at + 1 :]), dw.E6_CASES)


# --- the raw observations, checked again from their bytes -----------------------------


PRIVILEGED = (
    "HOST_NOT_PRIVILEGED",
    "CONTAINER_CAPABILITIES_EMPTY",
    "CONTAINER_DEVICES_MINIMAL",
    "CONTAINER_PROC_RESTRICTED",
)


def _plan() -> dict[str, object]:
    return {
        "User": "10001:10001",
        "Image": "sha256:aa",
        "Labels": {"io.direwolf.role": "environment", "io.direwolf.environment": "e1"},
        "HostConfig": {"Privileged": False, "SecurityOpt": ["no-new-privileges=true"]},
    }


def _frames(stdout: bytes) -> bytes:
    return bytes([1, 0, 0, 0]) + len(stdout).to_bytes(4, "big") + stdout


def _case_files(row: bool) -> dict[str, bytes]:
    sent = _plan()
    received = json.loads(json.dumps(sent))
    if row:
        received["HostConfig"]["Privileged"] = True
    record = {"Id": "c", "Config": {"User": "10001:10001"}, "HostConfig": received["HostConfig"]}
    fail = set(PRIVILEGED) if row else set()
    kept = "false" if row else "true"
    inside = [
        "CONTAINER_CAPABILITIES_EMPTY",
        "CONTAINER_DEVICES_MINIMAL",
        "CONTAINER_PROXY_REACHABLE",
    ]
    report = json.dumps(
        {"checks": [{"invariant": i, "verdict": "FAIL" if i in fail else "PASS"} for i in inside]}
    ).encode()
    verdicts = {i: ("FAIL" if i in fail else "PASS") for i in (*PRIVILEGED, *dw.E6_TOPOLOGY)}
    measurement = f"retained={kept}\n" + "".join(f"{k} {v}\n" for k, v in verdicts.items())
    requests = "".join(
        f"POST /containers/create 201 role={role}\n" for role in ("environment", "setup", "relay")
    )
    return {
        "create-sent.json": json.dumps(sent).encode(),
        "create-received.json": json.dumps(received).encode(),
        "record.json": json.dumps(record).encode(),
        "probe-stream.bin": _frames(report),
        "probe-report.json": report,
        "measurement.txt": measurement.encode(),
        "requests.txt": requests.encode(),
        "broker-events.txt": (
            f"environment_prepared declared=CONTAINER_ISOLATION retained={kept}\n"
        ).encode(),
    }


@pytest.fixture
def one_row(monkeypatch: pytest.MonkeyPatch) -> None:
    """E6 cut down to the control and one row, for synthetic observations."""
    monkeypatch.setattr(dw, "E6_ROWS", {ROW: dw.E6_ROWS[ROW]})
    monkeypatch.setattr(dw, "E6_ROW_NAMES", ("not-privileged",))
    monkeypatch.setattr(
        dw, "E6_CASES", tuple((dw.E6_SUITE, c) for c in (dw.E6_CONTROL, ROW, dw.E6_COUNT))
    )


def _lab(tmp_path: Path, change: str = "") -> tuple[str, Path, list[dict[str, object]]]:
    raw = tmp_path / "raw"
    printed: list[str] = []
    for case, row in ((dw.E6_CONTROL, False), (ROW, True)):
        files = _case_files(row)
        if case == ROW and change == "record-not-weakened":
            files["record.json"] = json.dumps({"HostConfig": {"Privileged": False}}).encode()
        if case == ROW and change == "another-field-received":
            received = json.loads(files["create-received.json"])
            received["User"] = "0:0"
            files["create-received.json"] = json.dumps(received).encode()
        if case == ROW and change == "another-plan":
            sent, received = (
                json.loads(files[n]) for n in ("create-sent.json", "create-received.json")
            )
            sent["Image"] = received["Image"] = "sha256:bb"
            files["create-sent.json"] = json.dumps(sent).encode()
            files["create-received.json"] = json.dumps(received).encode()
        if case == ROW and change == "report-not-the-stream":
            files["probe-report.json"] = files["probe-report.json"].replace(b"FAIL", b"PASS", 1)
        if case == ROW and change == "inside-verdict-not-answered":
            files["measurement.txt"] = files["measurement.txt"].replace(
                b"CONTAINER_CAPABILITIES_EMPTY FAIL", b"CONTAINER_CAPABILITIES_EMPTY PASS"
            )
        if case == ROW and change == "kept":
            files["measurement.txt"] = files["measurement.txt"].replace(
                b"retained=false", b"retained=true"
            )
        if case == ROW and change == "no-relay":
            files["requests.txt"] = files["requests.txt"].replace(b"role=relay", b"role=other")
        if case == dw.E6_CONTROL and change == "control-changed":
            files["create-received.json"] = files["create-received.json"].replace(b" ", b"")
        (raw / case).mkdir(parents=True)
        for name, data in files.items():
            (raw / case / name).write_bytes(data)
            digest = hashlib.sha256(data).hexdigest()
            printed.append(
                dw.E6_RAW_PREFIX
                + json.dumps({"case": case, "file": name, "sha256": digest, "bytes": len(data)})
            )
    if change == "digest":
        (raw / ROW / "record.json").write_bytes(b'{"HostConfig":{"Privileged":true}} ')
    if change == "extra-file":
        (raw / ROW / "notes.txt").write_bytes(b"x")
    if change == "missing-file":
        (raw / ROW / "probe-report.json").unlink()
    topology = (
        TOPOLOGY.replace("HOST_RELAY_DIGEST=PASS", "HOST_RELAY_DIGEST=FAIL")
        if (change == "topology-not-the-answer")
        else TOPOLOGY
    )
    lines = [
        _line(dw.E6_CONTROL, _good(dw.E6_CONTROL)),
        _line(
            ROW,
            f"refused:{'+'.join(PRIVILEGED)};also:none;topology:{topology};"
            "weakened:HostConfig.Privileged;host-loopback-added:not-applicable",
        ),
        _line(dw.E6_COUNT, "refused-1-of-1-cases;rows-1-of-1"),
    ]
    return "\n".join([*printed, _output(lines)]), raw, lines


@pytest.mark.usefixtures("one_row")
def test_complete_raw_observations_pass(tmp_path: Path) -> None:
    output, raw, lines = _lab(tmp_path)
    assert dw.require_attributed_evidence(output, dw.E6_CASES) == lines
    files = dw.e6_check_raw(output, raw, lines, "tag")
    assert len(files) == 2 * len(dw.E6_RAW_FILES)


@pytest.mark.usefixtures("one_row")
@pytest.mark.parametrize(
    ("change", "said"),
    [
        ("digest", "is not what the test printed"),
        ("extra-file", "raw files"),
        ("missing-file", "raw files"),
        ("record-not-weakened", "does not show the weakening"),
        ("another-field-received", "the daemon received"),
        ("another-plan", "the client asked for another plan"),
        ("report-not-the-stream", "is not its stream's stdout"),
        ("inside-verdict-not-answered", "is not the broker's inside verdict"),
        ("kept", "did not refuse it"),
        ("no-relay", "relay was never created"),
        ("topology-not-the-answer", "the line's topology is not the broker's answer"),
        ("control-changed", "forwarded byte for byte"),
    ],
)
def test_raw_observations_that_do_not_hold_fail(tmp_path: Path, change: str, said: str) -> None:
    output, raw, lines = _lab(tmp_path, change)
    with pytest.raises(dw.TaskError, match=re.escape(said)):
        dw.e6_check_raw(output, raw, lines, "tag")


@pytest.mark.usefixtures("one_row")
def test_the_offline_review_verifies_a_published_log_and_refuses_a_tampered_one(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    output, raw, lines = _lab(tmp_path)
    files = dw.e6_check_raw(output, raw, lines, "tag")
    capsys.readouterr()
    digest = dw._e6_publish(files, {"images": {"mutable-tag": "tag"}}, "census")
    log = output + "\n" + capsys.readouterr().out
    assert dw.e6_review(log) == digest
    published = [line for line in log.splitlines() if line.startswith(dw.E6_FILE_PREFIX)]
    record = json.loads(published[0][len(dw.E6_FILE_PREFIX) :])
    record["base64"] = base64.b64encode(b"tampered").decode()
    tampered = log.replace(published[0], dw.E6_FILE_PREFIX + json.dumps(record))
    with pytest.raises(dw.TaskError, match="is not its digest"):
        dw.e6_review(tampered)
    manifest = next(line for line in log.splitlines() if line.startswith(dw.E6_MANIFEST_PREFIX))
    with pytest.raises(dw.TaskError, match="the manifest is not its digest"):
        dw.e6_review(log.replace(manifest, manifest.replace('"census"', '"Census"', 1)))
    with pytest.raises(dw.TaskError, match="0 manifests"):
        dw.e6_review(log.replace(manifest, ""))
