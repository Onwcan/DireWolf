"""CI cannot turn missing M5d.6 release evidence into a green check.

A run's release ending its environment (ADR-0052 §8) is measured by `make
sandbox-release-evidence`: the authority's state machine against a fake
broker, then real containers over a real DWKP client. So the wiring that
carries it is itself security-relevant: a job the aggregate does not require,
a conditional or skipped job, a case the suites print that the task never
asks for -- or one the task asks for that nothing prints -- a fake broker's
line accepted for a real container's end, or an eval that expects other
cases than the task requires, would each be a green CI that proved nothing.

These tests assert that structure, reading the workflow as text (as the
other CI tests do: no YAML parser is a dependency), the suites' sources, and
the task's and the eval runner's accounting directly.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

from direwolf_evals.runners import m5d

REPO_ROOT = Path(__file__).resolve().parents[2]
CI = REPO_ROOT / ".github" / "workflows" / "ci.yml"
MAKEFILE = REPO_ROOT / "Makefile"
TESTS = REPO_ROOT / "crates" / "dwkd-authority" / "tests"
UNIT = REPO_ROOT / "crates" / "dwkd-authority" / "src" / "state" / "release_route_tests.rs"

sys.path.insert(0, str(REPO_ROOT / "scripts"))
import dw  # noqa: E402  - imported after the path is extended

JOB = "sandbox-release"
AGGREGATE_JOB = "ci"
COMMAND = "make sandbox-release-evidence"


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


def _needs() -> list[str]:
    for line in _jobs()[AGGREGATE_JOB]:
        match = re.match(r"\s+needs:\s*\[([^\]]*)\]", line)
        if match:
            return [n.strip() for n in match.group(1).split(",") if n.strip()]
    raise AssertionError("the aggregate job declares no `needs`")


def test_the_release_job_exists_on_linux_and_is_unconditional() -> None:
    job = _jobs().get(JOB)
    assert job is not None, f"no `{JOB}` job: M5d.6 is measured nowhere"
    text = "\n".join(_uncommented(line) for line in job)
    assert re.search(r"^    runs-on:\s*ubuntu-latest\s*$", text, re.MULTILINE), "Linux only"
    assert re.search(
        r"^    name:\s*sandbox release \(make sandbox-release-evidence\)\s*$", text, re.MULTILINE
    ), "the required check keeps its name"
    for forbidden in ("strategy:", "matrix", "continue-on-error", "secrets.", "if:", "sudo"):
        assert forbidden not in text, f"`{forbidden}` in {JOB}"
    runs = re.findall(r"^\s+- run:\s*(.+?)\s*$", text, re.MULTILINE)
    assert runs == [COMMAND], f"{JOB} must run exactly `{COMMAND}`: {runs}"


def test_the_aggregate_requires_the_release_job_and_every_job_once() -> None:
    needs = _needs()
    assert JOB in needs, f"the aggregate `ci` job does not require `{JOB}`"
    assert len(needs) == len(set(needs)), f"a job is required twice: {needs}"
    jobs = set(_jobs()) - {AGGREGATE_JOB}
    assert set(needs) == jobs, f"jobs the aggregate does not require: {sorted(jobs - set(needs))}"
    # The jobs M5d.6 must not have made optional stay required.
    for earlier in ("sandbox-workload", "sandbox-secret", "sandbox-workspace", "sandbox-agent"):
        assert earlier in needs, earlier


def test_the_commands_are_one_interface() -> None:
    makefile = MAKEFILE.read_text(encoding="utf-8")
    for task in ("sandbox-release-evidence", "sandbox-release-mutations"):
        assert task in dw.TASKS, task
        assert re.search(rf"^{task}:\s*##", makefile, re.MULTILINE), f"no `make {task}`"
        assert re.search(rf"^\t@\$\(DW\) {task}$", makefile, re.MULTILINE), task


def test_the_real_tests_are_ignored_by_default_and_selected_by_name() -> None:
    for name, source in (
        *((name, TESTS / "sandbox_workload.rs") for name in dw.RELEASE_WORKLOAD_TESTS),
        *((name, TESTS / "sandbox_agent.rs") for name in dw.RELEASE_AGENT_TESTS),
    ):
        function = name.split("::")[-1]
        text = source.read_text(encoding="utf-8")
        assert re.search(r"#\[ignore = [^\]]*\]\s*fn " + re.escape(function) + r"\(\)", text), (
            f"{function} is not an #[ignore]d test in {source.name}"
        )
    unit = UNIT.read_text(encoding="utf-8")
    assert len(re.findall(r"#\[test\]\s*fn ", unit)) == dw.RELEASE_UNIT_TESTS


def _printed(source: Path, suite_marker: str) -> set[str]:
    """Every case name a release suite's source can print: the literal first
    argument of its `evidence(...)` calls, and the crash windows' expansion."""
    text = source.read_text(encoding="utf-8")
    start = text.index(suite_marker)
    names = set(re.findall(r"evidence\(\s*(?:RELEASE_SUITE,\s*)?\"([a-z0-9-]+)\"", text[start:]))
    for template in re.findall(
        r"evidence\(\s*&format!\(\s*\"(release-crash-\{\}-[a-z-]+)\"", text[start:]
    ):
        names |= {template.replace("{}", letter) for letter in "ukl"}
    for template in re.findall(r"&format!\(\"(release-\{case\}-[a-z-]+)\"\)", text[start:]):
        names |= {
            template.replace("{case}", case) for case in ("broker-unreachable", "answer-lost")
        }
    return names


def test_the_task_names_exactly_the_cases_the_suites_print() -> None:
    """A renamed case would otherwise fail only in CI; an extra one would be
    printed and never required."""
    unit = _printed(UNIT, "fn a_release_destroys")
    assert unit == {case for _, case in dw.RELEASE_UNIT_CASES}, (
        f"unit, printed only: {sorted(unit - {c for _, c in dw.RELEASE_UNIT_CASES})}; "
        f"required only: {sorted({c for _, c in dw.RELEASE_UNIT_CASES} - unit)}"
    )
    real = _printed(TESTS / "sandbox_workload.rs", "mod release {") | _printed(
        TESTS / "sandbox_agent.rs", "const RELEASE_SUITE"
    )
    assert real == {case for _, case in dw.RELEASE_CASES}, (
        f"real, printed only: {sorted(real - {c for _, c in dw.RELEASE_CASES})}; "
        f"required only: {sorted({c for _, c in dw.RELEASE_CASES} - real)}"
    )


def test_the_eval_expects_exactly_what_the_task_requires_at_its_level() -> None:
    """The gated eval and the task are two halves of one gate: a case one
    stops counting is a gap."""
    assert set(m5d.M5D_CASES) == set(dw.RELEASE_UNIT_CASES) | set(dw.RELEASE_CASES)
    for (suite, case), (level, _outcome) in m5d.EXPECTED.items():
        assert level in dw.RELEASE_LEVELS[suite], (suite, case, level)


def _line(suite: str, case: str, level: str, enforcement: str = "guard") -> str:
    return (
        f'SANDBOX-EVIDENCE {{"suite":"{suite}","case":"{case}","outcome":"ok",'
        f'"level":"{level}","enforcement":"{enforcement}"}}'
    )


def test_release_evidence_requires_every_case_at_its_level_with_its_enforcement() -> None:
    cases = dw.RELEASE_CASES
    complete = "\n".join(_line(suite, case, "real-oci") for suite, case in cases)
    dw.require_release_evidence(complete, cases)
    suite, case = cases[4]
    with pytest.raises(dw.TaskError, match=re.escape(f"{suite}/{case}")):
        dw.require_release_evidence(
            "\n".join(line for line in complete.splitlines() if f'"{case}"' not in line), cases
        )
    with pytest.raises(dw.TaskError, match="wrong level"):
        dw.require_release_evidence(
            complete.replace(_line(suite, case, "real-oci"), _line(suite, case, "fake-broker")),
            cases,
        )
    with pytest.raises(dw.TaskError, match="enforcement"):
        dw.require_release_evidence(
            complete.replace(_line(suite, case, "real-oci"), _line(suite, case, "real-oci", "")),
            cases,
        )
    unit = dw.RELEASE_UNIT_CASES
    fake = "\n".join(_line(s, c, "fake-broker") for s, c in unit)
    dw.require_release_evidence(fake, unit)
    with pytest.raises(dw.TaskError, match="wrong level"):
        dw.require_release_evidence(fake.replace("fake-broker", "real-oci", 1), unit)


def test_every_release_mutant_targets_exactly_one_place() -> None:
    """A stale target would stop the campaign part of the way."""
    assert len(dw.RELEASE_MUTATIONS) >= 7
    for what, rel, old, new in dw.RELEASE_MUTATIONS:
        assert old != new, what
        assert (REPO_ROOT / rel).read_text(encoding="utf-8").count(old) == 1, what
