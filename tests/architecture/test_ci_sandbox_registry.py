"""CI cannot lose M5e.4's registry evidence, weaken it, or run it anywhere unsafe.

`make sandbox-registry-evidence` downloads the pinned registry tools -- a
CPython build, pip, Node.js and the npm it bundles -- builds an image of them
and runs pip and npm against M5e.3's fixture registries. Package-manager tools
run only on a disposable GitHub-hosted runner (owner direction 3), so the job
is the only place the evidence runs, and the wiring is security-relevant:

* a job the aggregate does not require, a condition that skips it, or a flag
  set anywhere else would be a green CI that never ran pip -- or a developer's
  host that downloads and runs registry tools;
* a pin that floats, a checksum not checked before use, or a version read
  wrong would be an image of unknown provenance;
* a dropped case, a line at the wrong level or naming the wrong mechanism, or
  an outcome that hides what it shows -- a source distribution's build called
  anything but today's gap, a refusal that installed something -- would be a
  green check that proves less than it says;
* and a suite that starts before it checks where it is, or leaves a container
  or a network behind, would break the census every evidence task keeps.

These tests hold each, reading the workflow as text (no YAML parser is a
dependency), the task through `scripts/dw.py` and the suite as source, with a
negative control for each way. The registry evidence itself is the hosted
job's alone: nothing here downloads, builds or runs a registry tool.
"""

from __future__ import annotations

import hashlib
import inspect
import io
import json
import re
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
CI = REPO_ROOT / ".github" / "workflows" / "ci.yml"
SUITE_SOURCE = REPO_ROOT / "crates" / "dwkd-authority" / "tests" / "sandbox_registry.rs"
WORKLOAD_SOURCE = REPO_ROOT / "crates" / "dwkd-broker" / "tests" / "sandbox_workload.rs"
DIGEST_SOURCE = REPO_ROOT / "crates" / "dwkd-broker" / "src" / "sandbox" / "digest.rs"

sys.path.insert(0, str(REPO_ROOT / "scripts"))
import dw  # noqa: E402  - imported after the path is extended

JOB = "sandbox-registry"
AGGREGATE_JOB = "ci"
COMMAND = "make sandbox-registry-evidence"
FLAG = "DW_REGISTRY_EVIDENCE"
HOSTED = {FLAG: "1", "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"}


# --- the workflow --------------------------------------------------------------


def _uncommented(line: str) -> str:
    if line.lstrip().startswith("#"):
        return ""
    return re.split(r"\s+#", line, maxsplit=1)[0]


def _jobs(text: str | None = None) -> dict[str, list[str]]:
    lines = (CI.read_text(encoding="utf-8") if text is None else text).splitlines()
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


def _needs(jobs: dict[str, list[str]]) -> list[str]:
    return next(
        (
            [n.strip() for n in m.group(1).split(",")]
            for line in jobs[AGGREGATE_JOB]
            if (m := re.match(r"\s+needs:\s*\[([^\]]*)\]", line))
        ),
        [],
    )


def _workflow_problems(text: str) -> list[str]:
    """Every way the workflow `text` would let the registry evidence go
    missing, be skipped, or run its flag anywhere but its job."""
    jobs = _jobs(text)
    job = jobs.get(JOB)
    if job is None:
        return [f"no `{JOB}` job"]
    problems: list[str] = []
    body = "\n".join(_uncommented(line) for line in job)
    if not re.search(r"^    runs-on:\s*ubuntu-latest\s*$", body, re.MULTILINE):
        problems.append("not ubuntu-latest")
    for forbidden in ("strategy:", "matrix", "continue-on-error", "if:", "secrets."):
        if forbidden in body:
            problems.append(f"`{forbidden}` in {JOB}")
    if _needs(jobs).count(JOB) != 1:
        problems.append(f"`{AGGREGATE_JOB}` does not require {JOB} exactly once")
    found = [s for s in _steps(job) if _run(s) == COMMAND]
    if len(found) != 1:
        problems.append(f"{JOB} does not run `{COMMAND}` exactly once")
    elif _env(found[0]) != {FLAG: "1"}:
        problems.append(f"{JOB}'s step does not set exactly {FLAG}=1")
    for name, other in jobs.items():
        if name == JOB:
            continue
        for step in _steps(other):
            if FLAG in _env(step) or "sandbox-registry-evidence" in _run(step):
                problems.append(f"{name} sets {FLAG} or runs the registry evidence")
    return problems


def test_the_registry_job_exists_is_unconditional_required_and_alone_with_its_flag() -> None:
    assert _workflow_problems(CI.read_text(encoding="utf-8")) == []
    # The aggregate requires every job, this one included, once.
    jobs = _jobs()
    needs = _needs(jobs)
    assert sorted(needs) == sorted(name for name in jobs if name != AGGREGATE_JOB)


@pytest.mark.parametrize(
    ("weaken", "said"),
    [
        (lambda t: t.replace("  sandbox-registry:\n", "  sandbox-registry-x:\n", 1), "no `"),
        (
            # The aggregate's own list: the M5 gate's job needs this job too.
            lambda t: t.replace(", sandbox-registry, sandbox-hygiene,", ", sandbox-hygiene,", 1),
            "exactly once",
        ),
        (
            lambda t: t.replace(
                f"      - run: {COMMAND}\n", f"      - run: {COMMAND}\n        if: false\n", 1
            ),
            "`if:`",
        ),
        (
            lambda t: t.replace(
                f"      - run: {COMMAND}\n",
                f"      - run: {COMMAND}\n        continue-on-error: true\n",
                1,
            ),
            "continue-on-error",
        ),
        (lambda t: t.replace(f'{FLAG}: "1"', f'{FLAG}: "0"', 1), f"exactly {FLAG}=1"),
        (lambda t: t.replace(f"      - run: {COMMAND}\n", "      - run: make test\n", 1), "once"),
        (
            lambda t: t.replace(
                "      - run: make sandbox-capacity-evidence\n        env:\n",
                "      - run: make sandbox-capacity-evidence\n        env:\n"
                f'          {FLAG}: "1"\n',
                1,
            ),
            "sandbox-capacity sets",
        ),
    ],
    ids=[
        "renamed",
        "not-required",
        "skipped",
        "allowed-to-fail",
        "flag-off",
        "other-command",
        "flag-elsewhere",
    ],
)
def test_a_weakened_workflow_fails(weaken: object, said: str) -> None:
    text = CI.read_text(encoding="utf-8")
    weakened = weaken(text)  # type: ignore[operator]
    assert weakened != text, "the negative control changed nothing"
    problems = _workflow_problems(weakened)
    assert any(said in problem for problem in problems), problems


# --- the task's refusal --------------------------------------------------------


@pytest.mark.parametrize(
    ("environ", "said"),
    [
        ({}, "DW_REGISTRY_EVIDENCE=1 is not set"),
        ({**HOSTED, FLAG: "0"}, "not set"),
        ({FLAG: "1"}, "not a disposable GitHub-hosted runner"),
        ({**HOSTED, "RUNNER_ENVIRONMENT": "self-hosted"}, "not a disposable"),
        ({**HOSTED, "GITHUB_ACTIONS": "false"}, "not a disposable"),
    ],
    ids=["no-flag", "flag-off", "off-actions", "self-hosted", "not-actions"],
)
def test_the_task_refuses_before_anything_is_fetched_or_built(
    monkeypatch: pytest.MonkeyPatch, environ: dict[str, str], said: str
) -> None:
    def nothing(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("the task started work before it checked where it is")

    for name in ("load_registry_pins", "_registry_setup", "_fetch_verified", "run", "run_captured"):
        monkeypatch.setattr(dw, name, nothing)
    monkeypatch.setattr(sys, "platform", "linux")
    for name in (FLAG, "GITHUB_ACTIONS", "RUNNER_ENVIRONMENT"):
        monkeypatch.delenv(name, raising=False)
    for name, value in environ.items():
        monkeypatch.setenv(name, value)
    with pytest.raises(dw.TaskError, match="NOT EXERCISED") as refused:
        dw.task_sandbox_registry_evidence()
    assert said in str(refused.value)


def test_only_a_hosted_runner_with_this_flag_is_not_refused() -> None:
    assert dw.registry_refusal(HOSTED) is None
    # Another job's flag is not this one's, nor this one's another's.
    assert dw.registry_refusal({**HOSTED, FLAG: "", "DW_CAPACITY_EVIDENCE": "1"}) is not None
    assert dw.capacity_refusal(HOSTED) is not None
    assert dw.restart_refusal(HOSTED) is not None


def test_the_task_checks_where_it_is_first_and_cleans_up_after() -> None:
    source = inspect.getsource(dw.task_sandbox_registry_evidence)
    first_work = min(
        source.index(call)
        for call in ("load_registry_pins(", "_registry_setup(", "run(", "run_captured(")
    )
    assert source.index("registry_refusal(os.environ)") < first_work
    # The census: containers and networks before and after whatever happened
    # (`finally`), images removed, any problem failing the task before a line
    # is counted; then the attributed gate, once.
    for needed in (
        '"container", "ls", "--all"',
        '"network", "ls"',
        '"image", "rm", "--force"',
        "finally:",
        "problems = registry_census_problems(before, after, networks, networks_after)",
        'raise TaskError("cleanup failed: "',
        "require_attributed_evidence(output, REGISTRY_CASES)",
    ):
        assert needed in source, needed
    assert source.index("finally:") < source.index("registry_census_problems(")
    assert source.index('raise TaskError("cleanup failed: "') < source.index(
        "require_attributed_evidence("
    )
    setup = inspect.getsource(dw._registry_setup)
    assert setup.index('"container", "ls"') < setup.index("_registry_tools_image(")
    assert setup.index('"network", "ls"') < setup.index("_registry_tools_image(")


@pytest.mark.parametrize(
    ("after", "networks_after", "said"),
    [
        ({"old", "made"}, {"bridge"}, "the evidence left 1 container(s): ['made']"),
        (set(), {"bridge"}, "1 container(s) that predate the evidence are gone: ['old']"),
        ({"old"}, {"bridge", "made"}, "the runtime's networks changed: made ['made']"),
        ({"old"}, set(), "lost ['bridge']"),
    ],
    ids=["container-left", "container-lost", "network-made", "network-lost"],
)
def test_the_census_fails_on_anything_left_or_lost(
    after: set[str], networks_after: set[str], said: str
) -> None:
    assert dw.registry_census_problems({"old"}, {"old"}, {"bridge"}, {"bridge"}) == []
    problems = dw.registry_census_problems({"old"}, after, {"bridge"}, networks_after)
    assert any(said in problem for problem in problems), problems


# --- the suite -------------------------------------------------------------------


def _test_body(name: str) -> tuple[str, str]:
    text = SUITE_SOURCE.read_text(encoding="utf-8")
    found = re.search(r'#\[ignore = "([^"]*)"\]\n( *)fn ' + name + r"\(\) \{", text)
    assert found is not None, f"{name} is not an #[ignore]d test of the registry suite"
    end = text.index(f"\n{found.group(2)}}}\n", found.end())
    return found.group(1), text[found.end() : end]


def test_the_suite_is_hosted_only_checks_first_and_prints_every_required_case() -> None:
    text = SUITE_SOURCE.read_text(encoding="utf-8")
    printed: list[str] = []
    for test in dw.REGISTRY_TESTS:
        reason, body = _test_body(test.removeprefix("linux::"))
        assert "hosted only" in reason, reason
        assert body.lstrip().startswith("let lab = Lab::new("), "the lab is the test's first act"
        printed += re.findall(r'evidence\(\s*"(registry-[a-z0-9-]+)"', body)
    assert sorted(printed) == sorted(case for _, case in dw.REGISTRY_CASES)
    assert len(printed) == len(set(printed)), "a case is printed twice"
    lab = text[text.index("    impl Lab {") :]
    new = lab[lab.index("fn new(") :]
    # Where it is is checked before any pin is read or anything is started.
    assert new.index("hosted();") < new.index("Pins::load()") < new.index("Broker::start(")
    guard = text[text.index("fn hosted()") : text.index("fn var(")]
    for check in (FLAG, "GITHUB_ACTIONS", "RUNNER_ENVIRONMENT", "NOT EXERCISED"):
        assert check in guard, check
    # Every line at the suite's one level, through the canonical emitter.
    assert 'const LEVEL: &str = "dwkp-end-to-end";' in text
    assert "to_canonical_string" in text
    # A fresh environment for every pip case: each run released, and its
    # environment, relay and setup containers gone when it is.
    pip_body = _test_body("pip_as_it_is_today_reaches_only_the_granted_fixture_registry")[1]
    assert pip_body.count("lab.peer(") == pip_body.count("lab.release(") == 13
    assert '["environment", "relay", "setup"]' in text


def test_npm_is_held_to_its_refusal_before_preparation() -> None:
    _reason, body = _test_body("npm_is_refused_before_anything_is_prepared")
    for needed in (
        "ToolDeniedV5",
        '"OBLIGATION_UNENFORCEABLE"',
        "rule_id.as_str(), RULE",
        "environment_id.is_none()",
        '"install"',
        '"ci"',
        "FROM environment WHERE run_id",
        "FROM workload WHERE run_id",
        '"environment.intent_recorded"',
        "requests().is_empty()",
        "npm/node_modules",
    ):
        assert needed in body, needed
    text = SUITE_SOURCE.read_text(encoding="utf-8")
    # The operator's rule carries the shipped packs' obligation, which is
    # what refuses npm: never a rule written to refuse it.
    rule = text[text.index('id = "{RULE}"') :]
    rule = rule[: rule.index("[[rule]]")]
    assert 'obligations = ["workspace_exec_hygiene"' in rule
    assert "{npm}@{npm_sha}" in rule and 'effect = "ALLOW"' in rule
    assert "argv_safe" not in rule


# --- the contract ------------------------------------------------------------------


def _line(suite: str, case: str, **change: object) -> str:
    contract = dw.attribution(suite, case)
    assert contract is not None, f"{suite}/{case} is unattributed"
    level, mechanisms = contract
    record: dict[str, object] = {
        "suite": suite,
        "case": case,
        "outcome": f"{dw.REGISTRY_OUTCOMES[case]};synthetic",
        "level": level,
        "enforcement": sorted(mechanisms)[0],
    }
    record.update(change)
    return f"x {dw.SANDBOX_EVIDENCE_PREFIX}{json.dumps(record)}"


def _complete(**change_at: dict[str, object]) -> str:
    return "\n".join(_line(s, c, **change_at.get(c, {})) for s, c in dw.REGISTRY_CASES)


def test_every_case_is_end_to_end_attributed_and_shows_its_outcome() -> None:
    assert len(dw.REGISTRY_CASES) == 20
    assert set(dw.REGISTRY_OUTCOMES) == {case for _, case in dw.REGISTRY_CASES}
    levels = {dw.attribution(s, c)[0] for s, c in dw.REGISTRY_CASES}  # type: ignore[index]
    assert levels == {"dwkp-end-to-end"}
    records = dw.require_attributed_evidence(_complete(), dw.REGISTRY_CASES)
    assert len(records) == 20
    # Named apart from the cases ADR-0054 §8 and ADR-0055 §9 propose.
    assert all(case.startswith("registry-") for _, case in dw.REGISTRY_CASES)
    # The pip cases the handoff names, and npm's.
    for case in (
        "registry-pip-granted-index-installs",
        "registry-pip-dependency-from-granted-index",
        "registry-pip-ungranted-index-refused",
        "registry-pip-file-on-ungranted-host-refused",
        "registry-pip-redirect-to-ungranted-host-refused",
        "registry-pip-direct-route-refused",
        "registry-pip-untrusted-issuer-refused",
        "registry-pip-sdist-never-built",
        "registry-pip-pth-not-run-by-install",
        "registry-npm-install-refused-before-preparation",
        "registry-npm-ci-refused-before-preparation",
        "registry-census-clean",
    ):
        assert (dw.REGISTRY_SUITE, case) in dw.REGISTRY_CASES, case


@pytest.mark.parametrize("dropped", range(20))
def test_a_dropped_case_fails(dropped: int) -> None:
    lines = _complete().splitlines()
    suite, case = dw.REGISTRY_CASES[dropped]
    del lines[dropped]
    with pytest.raises(
        dw.TaskError, match=re.escape(f"NOT EXERCISED: 1 required case(s): {suite}/{case}")
    ):
        dw.require_attributed_evidence("\n".join(lines), dw.REGISTRY_CASES)


@pytest.mark.parametrize(
    ("case", "change", "said"),
    [
        # A wrong level: a container's or a unit's line offered as end-to-end.
        ("registry-pip-granted-index-installs", {"level": "real-oci"}, "at level 'real-oci'"),
        ("registry-npm-ci-refused-before-preparation", {"level": "fake-broker"}, "at level"),
        # A missing or wrong attribution.
        ("registry-pip-ungranted-index-refused", {"enforcement": ""}, "names no enforcement"),
        ("registry-census-clean", {"enforcement": None}, "names no enforcement"),
        (
            "registry-pip-ungranted-index-refused",
            {"enforcement": "relay-and-connect-proxy-grant"},
            "is not what this case exercises",
        ),
        (
            "registry-pip-untrusted-issuer-refused",
            {"enforcement": "connect-proxy:grant"},
            "is not what this case exercises",
        ),
        (
            "registry-pip-sdist-never-built",
            {"enforcement": "workload-effects-measured"},
            "is not what this case exercises",
        ),
        # An outcome that does not show what the case claims.
        (
            "registry-pip-sdist-never-built",
            {"outcome": "refused:nothing-installed"},
            "must begin 'not-built:backend-marker-absent'",
        ),
        (
            "registry-pip-ungranted-index-refused",
            {"outcome": "installed:3-files-as-the-fixture"},
            "must begin 'refused:nothing-installed'",
        ),
        (
            "registry-pip-granted-index-installs",
            {"outcome": "ok"},
            "must begin 'installed:'",
        ),
        (
            "registry-pip-pth-not-run-by-install",
            {"outcome": "not-run:pth-marker-present"},
            "must begin 'not-run:pth-marker-absent'",
        ),
        (
            "registry-npm-install-refused-before-preparation",
            {"outcome": "refused:NO_MATCHING_RULE"},
            "must begin 'refused:OBLIGATION_UNENFORCEABLE'",
        ),
    ],
    ids=[
        "level-oci",
        "level-fake",
        "enforcement-empty",
        "enforcement-missing",
        "enforcement-not-the-grant",
        "tls-called-the-proxy",
        "sdist-called-measured",
        "sdist-gap-hidden",
        "refusal-installed",
        "install-shows-nothing",
        "pth-ran",
        "npm-refused-by-another-rule",
    ],
)
def test_a_line_that_says_more_than_it_shows_fails(
    case: str, change: dict[str, object], said: str
) -> None:
    named = f"{dw.REGISTRY_SUITE}/{case}"
    lines = []
    for suite, required in dw.REGISTRY_CASES:
        line = _line(suite, required)
        if required == case:
            record = json.loads(line.split(dw.SANDBOX_EVIDENCE_PREFIX, 1)[1])
            for key, value in change.items():
                if value is None:
                    record.pop(key, None)
                else:
                    record[key] = value
            line = f"x {dw.SANDBOX_EVIDENCE_PREFIX}{json.dumps(record)}"
        lines.append(line)
    with pytest.raises(dw.TaskError) as refused:
        dw.require_attributed_evidence("\n".join(lines), dw.REGISTRY_CASES)
    assert named in str(refused.value) and said in str(refused.value), str(refused.value)


# --- the pins and the verified download ------------------------------------------


PINS_TEXT = (REPO_ROOT / "tests" / "sandbox" / "registry_tools.toml").read_text(encoding="utf-8")
INTERPRETER_DIGEST_LINE = next(
    line + "\n" for line in PINS_TEXT.splitlines() if line.startswith("executable_sha256 = ")
)


def test_the_committed_pins_are_exact_and_checked() -> None:
    pins = dw.load_registry_pins()
    assert set(pins) == {"python", "pip", "node"}
    assert pins["python"]["version"].startswith("3.12.")
    for tool, pin in pins.items():
        assert re.fullmatch(r"[0-9a-f]{64}", pin["sha256"]), tool
        assert pin["url"].startswith(f"https://{dw.REGISTRY_TOOL_HOSTS[tool][0]}/"), tool
    assert re.fullmatch(r"\d+\.\d+\.\d+", pins["node"]["npm_version"])


def test_the_pinned_interpreter_fits_the_bound_the_broker_really_has() -> None:
    """Hosted run 42112947252: the interpreter of the build first pinned was
    68 023 040 bytes, past the 64 MiB the broker copies out of a container
    and hashes, so every launch was refused EXECUTABLE_CHANGED, its bytes
    unchanged. The bound stands: the pin is held below it, against the
    broker's own constant, here and in `make test`, not on the next run."""
    source = DIGEST_SOURCE.read_text(encoding="utf-8")
    found = re.search(r"const MAX_PROBE_BYTES: usize = (\d+) << (\d+);", source)
    assert found is not None, "the broker's bound is not where this test reads it"
    bound = int(found.group(1)) << int(found.group(2))
    assert bound == dw.EXECUTABLE_COPY_BOUND == 64 << 20
    overhead = re.search(
        r"const MAX_ARCHIVE_BYTES: usize = MAX_PROBE_BYTES \+ \((\d+) << (\d+)\);", source
    )
    assert overhead is not None
    archive_bound = bound + (int(overhead.group(1)) << int(overhead.group(2)))
    pins = dw.load_registry_pins()
    assert int(pins["python"]["executable_bytes"]) <= bound
    # Never the unstripped build again.
    assert "install_only_stripped" in pins["python"]["url"]
    # The real-runtime fixture past the bound is past the whole copy too, and
    # is the size that run measured: it reproduces the cut, not a header's.
    assert dw.SANDBOX_FIXTURE_PAST_BOUND_BYTES == 68_023_040 > archive_bound


def test_a_padded_copy_is_the_exact_size_and_the_same_program(tmp_path: Path) -> None:
    source = tmp_path / "source"
    source.write_bytes(b"\x7fELF the fixture")
    target = tmp_path / "padded" / "copy"
    digest = dw._padded(source, target, 4096)
    data = target.read_bytes()
    assert len(data) == 4096 and data.startswith(source.read_bytes())
    assert not data[len(source.read_bytes()) :].strip(b"\0")
    assert digest == hashlib.sha256(data).hexdigest()
    with pytest.raises(dw.TaskError, match="do not fit"):
        dw._padded(source, target, 4)


def test_the_broker_evidence_stands_on_both_sides_of_the_bound() -> None:
    """The bound is shown on a real runtime, through its own tar stream, in
    the evidence every commit runs: a file exactly at it runs, and a correctly
    pinned file past it is refused, runs nothing, and says why."""
    text = WORKLOAD_SOURCE.read_text(encoding="utf-8")
    start = text.index("fn only_the_pinned_bytes_run()")
    body = text[start : text.index("// ---- where it runs", start)]
    for needed in (
        "FIXTURE_AT_BOUND",
        "FIXTURE_PAST_BOUND",
        "DW_SANDBOX_FIXTURE_AT_BOUND_SHA256",
        "DW_SANDBOX_FIXTURE_PAST_BOUND_SHA256",
        "verdict=FAIL cause=past-the-copy-bound",
        "verdict=FAIL cause=not-the-pinned-file",
        "verdict=UNOBSERVABLE cause=copy-failed",
    ):
        assert needed in body, needed
    required = {case for suite, case in dw.WORKLOAD_CASES if suite == "sandbox-workload"}
    for case in (
        "workload-executable-at-the-copy-bound-runs",
        "workload-executable-past-the-copy-bound-refused",
    ):
        assert case in required and f'"{case}"' in body, case
        assert dw.attribution("sandbox-workload", case) == (
            "real-oci",
            frozenset({"executable-digest-pin"}),
        )
    setup = inspect.getsource(dw._workload_setup)
    for needed in ("EXECUTABLE_COPY_BOUND", "SANDBOX_FIXTURE_PAST_BOUND_BYTES", "_padded("):
        assert needed in setup, needed


@pytest.mark.parametrize(
    ("before", "after", "said"),
    [
        ("executable_bytes = 31009064", "executable_bytes = 68023040", "past the broker's bound"),
        ("executable_bytes = 31009064", "executable_bytes = 67108865", "past the broker's bound"),
        ("executable_bytes = 31009064", "executable_bytes = true", "is a byte count"),
        ("executable_bytes = 31009064", 'executable_bytes = "31009064"', "is a byte count"),
        ("executable_bytes = 31009064\n", "", "is a byte count"),
        ('executable_sha256 = "eaaa', 'executable_sha256 = "EAAA', "64 lowercase hex"),
        (INTERPRETER_DIGEST_LINE, "", "64 lowercase hex"),
        ("format = 1", "format = 2", "`format` must be 1"),
        ('version = "3.12.15"', 'version = "3.12"', "exact N.N.N"),
        ('version = "26.2.2"', 'version = "latest"', "exact N.N.N"),
        ('npm_version = "11.19.1"', 'npm_version = "11"', "exact N.N.N"),
        ("https://files.pythonhosted.org/", "http://files.pythonhosted.org/", "url is https://"),
        ("https://nodejs.org/", "https://nodejs.org.example/", "url is https://"),
        ("https://nodejs.org/", "https://nodejs.org:8443/", "url is https://"),
        ("node-v24.22.1-linux-x64.tar.xz", "node-v24.22.0-linux-x64.tar.xz", "does not name"),
        ('sha256 = "fd7f', 'sha256 = "FD7F', "64 lowercase hex"),
        ("[pip]", "[pipx]", "the pins are exactly"),
        ('npm_version = "11.19.1"\n', "", "holds exactly"),
        ('version = "26.2.2"\n', 'version = "26.2.2"\nextra = "x"\n', "holds exactly"),
    ],
    ids=[
        "interpreter-of-the-failed-run",
        "interpreter-a-byte-past-the-bound",
        "interpreter-size-a-boolean",
        "interpreter-size-a-string",
        "interpreter-size-unpinned",
        "interpreter-digest-uppercase",
        "interpreter-digest-unpinned",
        "format",
        "inexact-python",
        "floating-pip",
        "inexact-npm",
        "plain-http",
        "foreign-host",
        "port",
        "url-of-another-version",
        "uppercase-digest",
        "unknown-tool",
        "npm-unpinned",
        "extra-key",
    ],
)
def test_a_floating_or_malformed_pin_fails_closed(
    tmp_path: Path, before: str, after: str, said: str
) -> None:
    assert before in PINS_TEXT, before
    path = tmp_path / "registry_tools.toml"
    path.write_text(PINS_TEXT.replace(before, after, 1), encoding="utf-8")
    with pytest.raises(dw.TaskError, match=re.escape(said)):
        dw.load_registry_pins(path)


class _Response(io.BytesIO):
    def __init__(self, data: bytes, url: str) -> None:
        super().__init__(data)
        self._url = url

    def geturl(self) -> str:
        return self._url


class _Opener:
    def __init__(self, data: bytes, final: str | None = None) -> None:
        self.data, self.final = data, final

    def open(self, request: urllib.request.Request, timeout: int) -> _Response:
        assert timeout > 0
        return _Response(self.data, self.final or request.full_url)


URL = "https://files.pythonhosted.org/packages/x/pip-26.2.2-py3-none-any.whl"


def test_a_download_is_kept_only_when_its_digest_is_the_pin(tmp_path: Path) -> None:
    data = b"pinned bytes"
    got = dw._fetch_verified(
        "pip", URL, hashlib.sha256(data).hexdigest(), tmp_path, opener=_Opener(data)
    )
    assert got.read_bytes() == data and got.name == "pip-26.2.2-py3-none-any.whl"
    assert sorted(p.name for p in tmp_path.iterdir()) == [got.name]


@pytest.mark.parametrize(
    ("data", "final", "said"),
    [
        (b"other bytes", None, "not the pinned"),
        (b"pinned bytes", "https://evil.example/pip.whl", "answered from"),
        (b"pinned bytes", "http://files.pythonhosted.org/pip.whl", "answered from"),
    ],
    ids=["digest-mismatch", "foreign-final-host", "downgraded"],
)
def test_a_download_that_is_not_the_pin_fails_closed_and_leaves_nothing(
    tmp_path: Path, data: bytes, final: str | None, said: str
) -> None:
    pinned = hashlib.sha256(b"pinned bytes").hexdigest()
    with pytest.raises(dw.TaskError, match=said):
        dw._fetch_verified("pip", URL, pinned, tmp_path, opener=_Opener(data, final))
    assert list(tmp_path.iterdir()) == []


def test_an_oversized_or_misplaced_download_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(dw, "REGISTRY_ARCHIVE_LIMIT", 4)
    with pytest.raises(dw.TaskError, match="over 4 bytes"):
        dw._fetch_verified("pip", URL, "0" * 64, tmp_path, opener=_Opener(b"12345"))
    assert list(tmp_path.iterdir()) == []
    for misplaced in (URL, URL.replace("https://", "http://")):
        with pytest.raises(dw.TaskError, match="is not https on"):
            tool = "node" if misplaced == URL else "pip"
            dw._fetch_verified(tool, misplaced, "0" * 64, tmp_path, opener=_Opener(b""))
    assert list(tmp_path.iterdir()) == []


def test_a_redirect_is_followed_only_over_https_to_the_tools_own_hosts() -> None:
    handler = dw._registry_redirects("python")()
    request = urllib.request.Request("https://github.com/x")
    allowed = "https://release-assets.githubusercontent.com/asset"
    assert handler.redirect_request(request, None, 302, "Found", {}, allowed) is not None
    for refused in ("http://release-assets.githubusercontent.com/a", "https://evil.example/a"):
        with pytest.raises(dw.TaskError, match="is refused"):
            handler.redirect_request(request, None, 302, "Found", {}, refused)


def _fill(archive: tarfile.TarFile, entries: dict[str, bytes]) -> None:
    for name, data in entries.items():
        info = tarfile.TarInfo(name)
        info.size = len(data)
        info.mode = 0o755
        archive.addfile(info, io.BytesIO(data))


def _tar(entries: dict[str, bytes], *, xz: bool = False) -> bytes:
    buffer = io.BytesIO()
    if xz:
        with tarfile.open(fileobj=buffer, mode="w:xz") as archive:
            _fill(archive, entries)
    else:
        with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
            _fill(archive, entries)
    return buffer.getvalue()


def test_an_archive_member_outside_its_top_or_escaping_is_refused(tmp_path: Path) -> None:
    for name in ("other/file", "../escape", "/abs"):
        archive = tmp_path / "a.tar.gz"
        archive.write_bytes(_tar({"python/ok": b"x", name: b"y"}))
        with pytest.raises(dw.TaskError):
            dw._extract_tar(archive, tmp_path / "out", "python")
    wheel = tmp_path / "w.whl"
    with zipfile.ZipFile(wheel, "w") as zipped:
        zipped.writestr("../escape.py", b"")
    with pytest.raises(dw.TaskError, match="refused member"):
        dw._unzip_wheel(wheel, tmp_path / "site")


# --- the image: built from the pins, each version read back, fail closed -----------


FAKE_INTERPRETER = b"\x7fELF python"


def _fake_tools(tmp_path: Path, pins: dict[str, dict[str, str]]) -> dict[str, Path]:
    minor = ".".join(pins["python"]["version"].split(".")[:2])
    python = _tar(
        {
            f"python/bin/python{minor}": FAKE_INTERPRETER,
            f"python/lib/python{minor}/site-packages/pip/__init__.py": b"bundled",
            f"python/lib/python{minor}/site-packages/pip-0.1.dist-info/METADATA": b"old",
        }
    )
    top = f"node-v{pins['node']['version']}-linux-x64"
    node = _tar(
        {
            f"{top}/bin/node": b"\x7fELF node",
            f"{top}/lib/node_modules/npm/package.json": b'{"version": "x"}',
            f"{top}/lib/node_modules/npm/lib/cli.js": b"module.exports = () => {}",
        },
        xz=True,
    )
    wheel = io.BytesIO()
    with zipfile.ZipFile(wheel, "w") as archive:
        archive.writestr("pip/__init__.py", b'__version__ = "pinned"\n')
        archive.writestr(f"pip-{pins['pip']['version']}.dist-info/METADATA", b"pinned")
    files = {"python": python, "node": node, "pip": wheel.getvalue()}
    out: dict[str, Path] = {}
    for tool, data in files.items():
        path = tmp_path / f"{tool}.archive"
        path.write_bytes(data)
        out[tool] = path
    return out


def _build(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    reported: dict[str, str],
    calls: list[list[str]] | None = None,
    interpreter: dict[str, str] | None = None,
) -> tuple[str, dict[str, str], Path, list[list[str]]]:
    pins = dw.load_registry_pins()
    # The fake archive's own interpreter, unless a test pins another.
    pins["python"]["executable_bytes"] = str(len(FAKE_INTERPRETER))
    pins["python"]["executable_sha256"] = hashlib.sha256(FAKE_INTERPRETER).hexdigest()
    pins["python"].update(interpreter or {})
    (tmp_path / "archives").mkdir()
    archives = _fake_tools(tmp_path / "archives", pins)
    fetched: list[Path] = []

    def fetch(tool: str, _url: str, _sha256: str, into: Path, **_k: object) -> Path:
        fetched.append(into)
        return archives[tool]

    monkeypatch.setattr(dw, "_fetch_verified", fetch)
    monkeypatch.setattr(dw, "_ldd_closure", lambda _binaries: set())
    calls = [] if calls is None else calls
    context = tmp_path / "context"

    def docker(_client: Path, _socket: str, *args: str, **_kwargs: object) -> str:
        calls.append(list(args))
        if args[0] == "image":
            return ""
        if args[0] == "build":
            # Only the Dockerfile and the image's tree reach the runtime:
            # the downloaded archives are kept beside the context.
            assert args[-1] == str(context)
            assert sorted(p.name for p in context.iterdir()) == ["Dockerfile", "rootfs"]
            assert fetched and all(not into.is_relative_to(context) for into in fetched)
            Path(args[args.index("--iidfile") + 1]).write_text("sha256:" + "a" * 64)
            return ""
        argv = " ".join(args)
        for tool, needle in (
            ("node", "--version"),
            ("npm", "package.json"),
            ("pip", "pip.__version__"),
            ("python", "sys.version"),
        ):
            if needle in argv:
                return ("v" if tool == "node" else "") + reported[tool] + "\n"
        raise AssertionError(argv)

    monkeypatch.setattr(dw, "_docker", docker)
    probe, relay = tmp_path / "probe", tmp_path / "relay"
    probe.write_bytes(b"probe")
    relay.write_bytes(b"relay")
    image, variables = dw._registry_tools_image(
        Path("docker"), "/run/docker.sock", context, (probe, relay), "linux/amd64", pins
    )
    return image, variables, context / "rootfs", calls


def _pinned() -> dict[str, str]:
    pins = dw.load_registry_pins()
    return {
        "python": pins["python"]["version"],
        "pip": pins["pip"]["version"],
        "node": pins["node"]["version"],
        "npm": pins["node"]["npm_version"],
    }


def test_the_image_holds_the_pinned_tools_and_reads_each_version_back(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    image, variables, rootfs, calls = _build(tmp_path, monkeypatch, _pinned())
    assert image == "sha256:" + "a" * 64
    assert not [c for c in calls if c[0] == "image"], "an image that passed was removed"
    build = next(c for c in calls if c[0] == "build")
    assert build[build.index("--network") + 1] == "none" and "--pull=false" in build
    runs = [c for c in calls if c[0] == "run"]
    assert len(runs) == 4
    for run in runs:
        for word in ("--rm", "--read-only", "--cap-drop"):
            assert word in run, run
        assert run[run.index("--network") + 1] == "none"
        assert run[run.index("--user") + 1] == "10001:10001"
    site = next(rootfs.glob("opt/direwolf/python/lib/python3.*/site-packages"))
    assert (site / "pip" / "__init__.py").read_text() == '__version__ = "pinned"\n'
    assert not list(site.glob("pip-0.1.dist-info")), "the bundled pip was kept"
    npm = rootfs / "opt" / "direwolf" / "node" / "bin" / "npm"
    assert npm.read_text(encoding="utf-8") == dw.REGISTRY_NPM_LAUNCHER
    assert variables["DW_REGISTRY_NPM_SHA256"] == hashlib.sha256(npm.read_bytes()).hexdigest()
    assert variables["DW_REGISTRY_NPM"] == dw.REGISTRY_NPM_PATH
    assert variables["DW_REGISTRY_PYTHON"].startswith(dw.REGISTRY_PYTHON_HOME + "/bin/python3.")
    # What the broker is told to expect is the bytes the image holds.
    python = next(rootfs.glob("opt/direwolf/python/bin/python3.*"))
    assert variables["DW_REGISTRY_PYTHON_SHA256"] == hashlib.sha256(python.read_bytes()).hexdigest()
    assert not (rootfs / "etc").exists(), "the image carries a configuration or a trust store"


@pytest.mark.parametrize(
    "interpreter",
    [
        {"executable_bytes": "68023040"},
        {"executable_sha256": "0" * 64},
    ],
    ids=["another-size", "other-bytes"],
)
def test_an_interpreter_that_is_not_the_pinned_one_is_refused_before_the_build(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, interpreter: dict[str, str]
) -> None:
    calls: list[list[str]] = []
    with pytest.raises(dw.TaskError, match=r"the interpreter is .* not the pinned"):
        _build(tmp_path, monkeypatch, _pinned(), calls, interpreter)
    assert calls == [], "nothing is built from an interpreter that is not the pinned one"


@pytest.mark.parametrize("tool", ["python", "pip", "node", "npm"])
def test_a_tool_that_reports_another_version_fails_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, tool: str
) -> None:
    reported = {**_pinned(), tool: "0.0.1"}
    calls: list[list[str]] = []
    with pytest.raises(dw.TaskError, match=rf"the image's {tool} reports '0\.0\.1'"):
        _build(tmp_path, monkeypatch, reported, calls)
    # Refused, and the image that failed its check is not left behind.
    assert calls[-1] == ["image", "rm", "--force", "sha256:" + "a" * 64], calls[-1]


# --- the proxy's count ----------------------------------------------------------

# Every case that reads what the proxy refused, by the rule it must keep: a
# workload that reaches only what it was granted, or no proxy at all, caused
# none; a refused one caused at least one. Hosted run 42296614431 failed the
# granted install on the probe's own question (`beyond_the_probe`).
# F-17's standing control (ADR-0061, Proposed) is one more of the first: its
# registry is granted, so the ceiling refuses none of its tunnels, and the
# policy's refusals are counted apart (`policy_refusals`).
EXACTLY_NONE = 7
AT_LEAST_ONE = 3
ACCOUNTING_TEST = "a_probes_own_question_is_never_counted_as_a_workloads_refusal"


def _accounting_problems(text: str) -> list[str]:
    """Every way the suite `text` could count its environments' own probe
    question as a workload's refusal again, or lose what holds that."""
    problems: list[str] = []
    try:
        helper = text[text.index("    fn beyond_the_probe(") :]
        helper = helper[: helper.index("\n    }\n")]
    except ValueError:
        return ["no beyond_the_probe"]
    if "checked_sub(probe_questions)" not in helper:
        problems.append("beyond_the_probe does not take the probe's questions away, or errs")
    outside = text.replace(helper, "")
    raw = [
        m.start()
        for m in re.finditer(r"(?<![\w:])counted\(", outside)
        if outside[max(0, m.start() - 3) : m.start()] != "fn "
    ]
    if raw:
        problems.append(f"{len(raw)} raw count(s) of a disposition outside beyond_the_probe")
    # A policy refusal is never the probe's (its question is the ceiling's), so
    # it is counted apart -- and only it.
    if "    fn policy_refusals(" in text:
        policy = text[text.index("    fn policy_refusals(") :]
        policy = policy[: policy.index("\n    }\n")]
        if re.findall(r'"[A-Z_]+="', policy) != ['"POLICY_DENIED="']:
            problems.append("policy_refusals counts a disposition other than POLICY_DENIED")
    if not re.search(r"#\[test\]\n    fn " + ACCOUNTING_TEST + r"\(\)", text):
        problems.append(f"{ACCOUNTING_TEST} is gone, or is not run everywhere")
    if "Ok(0)" not in text[text.find(ACCOUNTING_TEST) :][:2400]:
        problems.append("the accounting test no longer holds the hosted failure's numbers")
    questions = text[text.find("fn probe_questions(") :][:1600]
    for needed in (
        '"environment.ready"',
        '1 + u64::try_from(of("environment.measured")',
        "PROBE_INVARIANT",
    ):
        if needed not in questions:
            problems.append(f"probe_questions does not read {needed}")
    try:
        start = text.index("    fn pip_as_it_is_today_reaches_only_the_granted_fixture_registry(")
        pip = text[start : text.index("    // ---- npm, refused", start)]
    except ValueError:
        return [*problems, "no pip test"]
    none = len(re.findall(r"lab\.refused_by_proxy\([^)]*\),\s*0,", pip))
    if none != EXACTLY_NONE:
        problems.append(f"{none} cases hold the proxy to no refusal, not {EXACTLY_NONE}")
    some = len(re.findall(r"let refusals = lab\.refused_by_proxy\(", pip))
    if some != AT_LEAST_ONE or pip.count("refusals >= 1") != AT_LEAST_ONE:
        problems.append(f"{some} refused cases read the workload's own refusals")
    return problems


def test_no_case_counts_the_probes_own_question_as_a_workloads_refusal() -> None:
    assert _accounting_problems(SUITE_SOURCE.read_text(encoding="utf-8")) == []


@pytest.mark.parametrize(
    ("mutate", "said"),
    [
        # The hosted failure's own shape: the raw count, held to zero.
        (
            lambda t: t.replace(
                "lab.refused_by_proxy(&destroyed, &ran.environment),\n            0,",
                'counted(&texts(&destroyed, "egress_dispositions"), "TARGET_NOT_GRANTED"),\n'
                "            0,",
                1,
            ),
            "raw count",
        ),
        # The false pass it hid: a refused case satisfied by the probe alone.
        (
            lambda t: t.replace(
                "let refusals = lab.refused_by_proxy(&destroyed, &ran.environment);",
                'let refusals = counted(&texts(&destroyed, "egress_dispositions"), '
                '"TARGET_NOT_GRANTED");',
                1,
            ),
            "raw count",
        ),
        (
            lambda t: t.replace("checked_sub(probe_questions)", "checked_sub(0)", 1),
            "take the probe",
        ),
        (
            lambda t: t.replace(
                f"#[test]\n    fn {ACCOUNTING_TEST}(",
                f'#[test]\n    #[ignore = "later"]\n    fn {ACCOUNTING_TEST}(',
                1,
            ),
            "run everywhere",
        ),
        (lambda t: t.replace("1 + u64::try_from(", "u64::try_from(", 1), "measured"),
        (
            lambda t: t.replace(
                "lab.refused_by_proxy(&destroyed, &ran.environment),\n            0,",
                "lab.refused_by_proxy(&destroyed, &ran.environment),\n            1,",
                1,
            ),
            "no refusal",
        ),
        (lambda t: t.replace("refusals >= 1", "refusals >= 0", 1), "refused cases"),
    ],
    ids=[
        "granted-raw-count",
        "refused-raw-count",
        "probe-not-taken-away",
        "accounting-test-ignored",
        "re-measurement-forgotten",
        "granted-case-tolerates-a-refusal",
        "refused-case-tolerates-none",
    ],
)
def test_counting_the_probe_as_the_workloads_is_caught(mutate: object, said: str) -> None:
    text = SUITE_SOURCE.read_text(encoding="utf-8")
    mutated = mutate(text)  # type: ignore[operator]
    assert mutated != text, "the mutation did not apply"
    problems = _accounting_problems(mutated)
    assert any(said in problem for problem in problems), problems
