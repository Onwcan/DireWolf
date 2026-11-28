"""M6.3 (ADR-0081, Proposed): the approver endpoint's operations and the
trusted approver client agree with their record.

The approver set is attached at start and nowhere else; the endpoint's
in-process test helper is test-only; the client has no option that approves
without asking; the evidence tasks refuse whatever is not evidence -- an
unreadable line, a case reported twice or at another level, a suite that ran
no test; each mutant's anchor is in its file exactly once; CI runs the
evidence with its identities; and ADR-0081 is Proposed, indexed and counted.
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SERVER = REPO_ROOT / "crates" / "dwkd-authority" / "src" / "server"
STATE = REPO_ROOT / "crates" / "dwkd-authority" / "src" / "state"
CLIENT = REPO_ROOT / "crates" / "direwolf-cli" / "src" / "approve"
ADR = (
    REPO_ROOT
    / "docs"
    / "adr"
    / "0081-the-approver-endpoints-operations-and-the-trusted-approver-client.md"
)

sys.path.insert(0, str(REPO_ROOT / "scripts"))

import dw  # noqa: E402  - imported after the path is extended


def _read(path: Path) -> str:
    return path.read_bytes().decode("utf-8")


def _production(source: str) -> str:
    """A Rust module's code before its tests, its comment lines dropped."""
    end = source.find("#[cfg(test)]")
    code = source if end < 0 else source[:end]
    return "\n".join(line for line in code.splitlines() if not line.lstrip().startswith("//"))


# --- the record tests the mutation review runs ------------------------------


def test_the_endpoints_test_helper_is_test_only() -> None:
    """The in-process approver endpoint for the route tests is compiled into
    Linux test builds alone: it serves an authority whose approvers a test
    attached."""
    server = _read(SERVER / "mod.rs")
    at = server.index("pub(crate) mod testing {")
    before = server[:at].rstrip().splitlines()[-1].strip()
    assert before == '#[cfg(all(test, target_os = "linux"))]', before
    assert server.count("pub(crate) mod testing {") == 1


def test_the_start_up_attaches_the_set_before_the_endpoint_accepts() -> None:
    """`serve`'s start-up attaches the operator's set once, refusing a second,
    and the endpoint is made from the same set -- all before the endpoint's
    accept loop starts."""
    server = _read(SERVER / "mod.rs")
    attach = server[server.index("fn attach_operator_approvers(") :]
    attach = attach[: attach.index("\n}\n")]
    assert "if !authority.attach_approver_set(&set) {" in attach
    assert "approver::ApproverPolicy::from_set(&set)" in attach
    start = server[server.index("fn start(\n") :]
    start = start[: start.index("\n}\n")]
    assert start.index("Authority::start(") < start.index("attach_operator_approvers(")
    run = server[server.index("fn run(config: &ServeConfig)") :]
    run = run[: run.index("\n}\n")]
    assert run.index("start(config)?") < run.index("approver::accept(")


# --- the client --------------------------------------------------------------


def test_the_client_has_no_option_that_approves_without_asking() -> None:
    code = _production(_read(CLIENT / "mod.rs"))
    for option in ("--yes", "--approve-all", "--skip-confirmation", "--remember", '"-y"'):
        assert option not in code, option
    assert "std::env::var" not in code, "no environment-controlled default"
    assert "is_terminal()" in code
    assert 'if line == format!("approve {code}") {' in code
    # It never builds a binding or spells the binding's schema (TX067).
    assert "ApprovalBinding" not in code
    render = _production(_read(CLIENT / "render.rs"))
    assert "7. UNTRUSTED: FROM THE AGENT -- NOT PART OF THIS DECISION" in render


# --- the evidence parsers ----------------------------------------------------


def _line(case: str, level: str = "component", **extra: object) -> str:
    fields = {
        "suite": dw.APPROVER_OPERATIONS_SUITE,
        "case": case,
        "outcome": "ok",
        "level": level,
        "count": 1,
    }
    fields.update(extra)

    return dw.APPROVER_OPERATIONS_PREFIX + json.dumps(fields)


def _all_lines() -> list[str]:
    return [_line(case, level) for case, level in dw.APPROVER_OPERATIONS_CASES.items()]


def _parse(lines: list[str]) -> list[dict[str, object]]:
    return dw.require_approver_cases(
        "\n".join(lines),
        prefix=dw.APPROVER_OPERATIONS_PREFIX,
        suite=dw.APPROVER_OPERATIONS_SUITE,
        cases=dw.APPROVER_OPERATIONS_CASES,
    )


def test_every_registry_case_is_required_once_at_its_level() -> None:
    assert len(_parse(_all_lines())) == len(dw.APPROVER_OPERATIONS_CASES)
    first = next(iter(dw.APPROVER_OPERATIONS_CASES))
    end_to_end = next(c for c, lv in dw.APPROVER_OPERATIONS_CASES.items() if lv != "component")
    for name, lines, message in (
        ("missing", _all_lines()[1:], "NOT EXERCISED"),
        ("twice", [*_all_lines(), _line(first)], "reported twice"),
        ("unknown", [*_all_lines(), _line("nothing-of-the-kind")], "no inventory"),
        ("unreadable", [*_all_lines(), dw.APPROVER_OPERATIONS_PREFIX + "{"], "unreadable"),
        (
            "another suite",
            [*_all_lines(), _line(first, suite="authority-approval-registry")],
            "another suite",
        ),
        (
            "component labelled end-to-end",
            [
                _line(c, "end-to-end-fake-broker") if c == first else _line(c, lv)
                for c, lv in dw.APPROVER_OPERATIONS_CASES.items()
            ],
            "not 'component'",
        ),
        (
            "end-to-end labelled component",
            [
                _line(c, "component") if c == end_to_end else _line(c, lv)
                for c, lv in dw.APPROVER_OPERATIONS_CASES.items()
            ],
            "not 'end-to-end-fake-broker'",
        ),
        (
            "no outcome",
            [_line(c, lv, outcome="") for c, lv in dw.APPROVER_OPERATIONS_CASES.items()],
            "no outcome",
        ),
    ):
        with pytest.raises(dw.TaskError, match=message):
            _parse(lines)
        assert name


def test_a_production_case_is_never_a_fake_brokers() -> None:
    """The production inventory is real OCI alone: a line at any other level
    is refused."""
    assert set(dw.APPROVER_PRODUCTION_CASES.values()) == {"real-oci-production"}

    lines = [
        "APPROVER-EVIDENCE "
        + json.dumps(
            {
                "suite": "approver-production",
                "case": case,
                "outcome": "ok",
                "level": "end-to-end-fake-broker",
            }
        )
        for case in dw.APPROVER_PRODUCTION_CASES
    ]
    with pytest.raises(dw.TaskError, match="not 'real-oci-production'"):
        dw.require_approver_cases(
            "\n".join(lines),
            prefix="APPROVER-EVIDENCE ",
            suite="approver-production",
            cases=dw.APPROVER_PRODUCTION_CASES,
        )


def test_a_suite_must_run_exactly_its_tests() -> None:
    ok = "test result: ok. 8 passed; 0 failed; 0 ignored; 0 measured; 5 filtered out"
    dw.require_suite_count(ok, "p", 8)
    # The other binaries a filter matched nothing in do not count.
    dw.require_suite_count(
        "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out\n" + ok,
        "p",
        8,
    )
    for bad in (
        "",
        "test result: ok. 0 passed; 0 failed; 0 ignored; 0 measured; 9 filtered out",
        "test result: ok. 7 passed; 0 failed; 0 ignored; 0 measured",
        "test result: ok. 8 passed; 0 failed; 1 ignored; 0 measured",
        "test result: FAILED. 7 passed; 1 failed; 0 ignored",
        ok + "\n" + ok,
    ):
        with pytest.raises(dw.TaskError):
            dw.require_suite_count(bad, "p", 8)


def _evidence_calls(path: Path, function: str) -> dict[str, str]:
    """`function("case", "outcome", "level")` calls: case to level."""
    text = _read(path)
    calls = re.findall(function + r'\(\s*"([a-z0-9-]+)",\s*"[^"]*",\s*"([a-z-]+)",?\s*\)', text)
    return dict(calls)


def test_the_inventories_are_the_tests_own_lines() -> None:
    route = _evidence_calls(STATE / "approver_route_tests.rs", "approver_evidence")
    assert route == dw.APPROVER_OPERATIONS_CASES
    workload = _read(REPO_ROOT / "crates" / "dwkd-authority" / "tests" / "sandbox_workload.rs")
    production = set(re.findall(r'approver_evidence\(\s*"([a-z0-9-]+)"', workload))
    assert production == set(dw.APPROVER_PRODUCTION_CASES)
    transport = _read(REPO_ROOT / "crates" / "dwkd-authority" / "tests" / "transport_approver.rs")
    named = set(re.findall(r'operations_evidence\("([a-z0-9-]+)"\)', transport))
    generated = {
        f"cross-uid-{who}-cannot-{name}"
        for who in ("runtime", "other")
        for name in ("list", "show", "decide")
    }
    assert named | generated == set(dw.APPROVER_OPERATIONS_IDENTITY_CASES)


# --- the mutation tables -----------------------------------------------------


@pytest.mark.parametrize(
    ("table", "label"),
    [
        (dw.APPROVER_OPERATIONS_MUTATIONS, "M6.3"),
        (dw.APPROVER_MUTATIONS, "F-18"),
    ],
)
def test_each_mutants_anchor_is_in_its_file_once(
    table: tuple[tuple[str, str, str, str], ...], label: str
) -> None:
    names = [name for name, *_ in table]
    assert len(names) == len(set(names)), label
    for name, path, anchor, mutant in table:
        text = _read(REPO_ROOT / path)
        assert text.count(anchor) == 1, f"{label} {name}: {text.count(anchor)} matches"
        assert mutant != anchor, name


def test_the_equivalents_say_why() -> None:
    labels = {name.split(":")[0] for name, _ in dw.APPROVER_OPERATIONS_EQUIVALENT}
    assert labels == {"E1", "E2"}
    for _, why in dw.APPROVER_OPERATIONS_EQUIVALENT:
        assert len(why) > 80, why


# --- CI and the record -------------------------------------------------------


def test_ci_runs_the_m6_3_evidence_with_its_identities() -> None:
    ci = _read(REPO_ROOT / ".github" / "workflows" / "ci.yml")
    boundary = ci[ci.index("  authority-transport:") : ci.index("  filesystem-canonicalization:")]
    assert "useradd --system --no-create-home --shell /usr/sbin/nologin dwother" in boundary
    step = boundary[boundary.index("- run: make approver-operations-evidence") :]
    step = (
        step[: step.index("- run: make authority-write-probe")]
        if "authority-write-probe" in step
        else step
    )
    for variable in ("DW_PEER_AS: nobody", "DW_APPROVER_AS: dwapprover", "DW_OTHER_AS: dwother"):
        assert variable in step, variable
    workload = ci[ci.index("  sandbox-workload:") : ci.index("  # M5d.3 (ADR-0052 §7)")]
    bundle = workload.index("name: m5e-evidence-sandbox-workload")
    production = workload.index("- run: make approver-production-evidence")
    assert bundle < production, "the production approval runs after the M5 bundle is sealed"
    assert "DW_APPROVER_AS: dwapprover" in workload[production:]
    makefile = _read(REPO_ROOT / "Makefile")
    for target in (
        "approver-operations-evidence",
        "approver-production-evidence",
        "approver-operations-mutations",
    ):
        assert f"\n{target}: ##" in makefile, target
        assert target in dw.TASKS, target


def test_adr_0081_is_proposed_indexed_and_counted() -> None:
    text = _read(ADR)
    assert text.startswith("# ADR-0081:")
    assert re.search(r"^\*\*Status:\*\* Proposed · ", text, re.M)
    assert "nothing here is accepted" in text
    for decision in ("OD-1", "OD-2", "OD-3", "OD-4", "OD-5", "OD-6", "OD-7", "OD-8"):
        assert f"**{decision}**" in text, decision
    index = _read(REPO_ROOT / "docs" / "adr" / "README.md")
    row = next(line for line in index.splitlines() if "[0081]" in line)
    assert "(**Proposed**" in row
    assert "accepted.sha256" not in row
    manifest = _read(REPO_ROOT / "docs" / "adr" / "accepted.sha256")
    assert "0081-" not in manifest, "a Proposed record has no digest"
    readme = _read(REPO_ROOT / "README.md")
    assert "82 architecture decision records (0000\u20130081)" in readme
