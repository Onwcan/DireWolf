"""M5e.1: every line of the sandbox evidence says what it is and what enforced it.

The owner's OD-E1 decided that a contained attempt is *attributed* -- each case
names the existing mechanism that enforced or observed it -- not individually
audited (SANDBOX.md §6). `scripts/dw.py` holds that as a contract
(`ATTRIBUTION`): for every case the foundation, egress, workload, secret and
workspace tasks require, the level its line must say and the mechanisms it may
name. `require_attributed_evidence` refuses any line that does not.

So what is checked here is the contract and the gate, not containment:

* the contract names every required case once, uses every rule, and uses a
  documented vocabulary; a case only a provisioned host runs is
  `privileged-oci` and nothing else is; a fake broker's line is never a
  container's;
* each of the five tasks gates its lines through the attributed validator;
* the Rust emitters print what the contract says -- every literal case's
  level and mechanism read from the source, so a drift fails here, without a
  runtime;
* the gate refuses each way a line can mislead: a missing, unexercised,
  duplicated or unknown case, a missing or wrong level, an empty, unknown or
  wrong enforcement, unreadable JSON, telemetry offered as more.

The synthetic lines below test the gate only. They are never evidence of
containment: only the real tasks, on a real runtime, are.
"""

from __future__ import annotations

import fnmatch
import inspect
import json
import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SANDBOX = REPO_ROOT / "docs" / "SANDBOX.md"

sys.path.insert(0, str(REPO_ROOT / "scripts"))
import dw  # noqa: E402  - imported after the path is extended

# Each task, the tables it requires and the prefix its lines carry.
TASKS = {
    "task_sandbox_foundation_evidence": ((dw.SANDBOX_CASES, dw.SANDBOX_EVIDENCE_PREFIX),),
    "task_sandbox_egress_evidence": ((dw.EGRESS_CASES, dw.SANDBOX_EVIDENCE_PREFIX),),
    "task_sandbox_workload_evidence": ((dw.WORKLOAD_CASES, dw.SANDBOX_EVIDENCE_PREFIX),),
    "task_sandbox_secret_evidence": (
        (dw.SECRET_SANDBOX_UNIT_CASES, dw.SECRET_EVIDENCE_PREFIX),
        (dw.SECRET_SANDBOX_CASES, dw.SANDBOX_EVIDENCE_PREFIX),
    ),
    "_sandbox_workspace_evidence": (
        (dw.WORKSPACE_UNIT_CASES, dw.WORKSPACE_EVIDENCE_PREFIX),
        (dw.WORKSPACE_CASES, dw.SANDBOX_EVIDENCE_PREFIX),
        (dw.WORKSPACE_CASES + dw.WORKSPACE_PRIVILEGED_CASES, dw.SANDBOX_EVIDENCE_PREFIX),
    ),
}

# Which suite each emitter prints, and whether a call names its level (an
# explicit level argument) or the region has one level for every line. The
# release module is the release evidence's, attributed since M5d.6.
CONST = {"OCI": "real-oci", "E2E": "dwkp-end-to-end", "PRIV": "privileged-oci"}
EMITTERS = (
    ("crates/dwkd-broker/tests/sandbox_foundation.rs", "evidence", "sandbox-broker", None, None),
    ("crates/dwkd-broker/tests/sandbox_egress.rs", "evidence", "sandbox-egress", None, None),
    (
        "crates/dwkd-broker/tests/sandbox_workload.rs",
        "evidence",
        "sandbox-workload",
        None,
        "    mod workspace {",
    ),
    (
        "crates/dwkd-broker/tests/sandbox_workload.rs",
        "evidence",
        "sandbox-workspace",
        "    mod workspace {",
        None,
    ),
    ("crates/dwkd-broker/tests/sandbox_secret.rs", "evidence", "sandbox-secret", None, None),
    (
        "crates/dwkd-authority/tests/sandbox_workload.rs",
        "evidence",
        "sandbox-authority-workload",
        None,
        "    mod workspace {",
    ),
    (
        "crates/dwkd-authority/tests/sandbox_workload.rs",
        "evidence",
        "sandbox-authority-workspace",
        "    mod workspace {",
        "    mod release {",
    ),
    (
        "crates/dwkd-authority/tests/sandbox_secret.rs",
        "evidence",
        "sandbox-authority-secret",
        None,
        None,
    ),
    (
        "crates/dwkd-authority/tests/sandbox_lifecycle.rs",
        "evidence",
        "sandbox-authority",
        None,
        None,
    ),
    (
        "crates/dwkd-authority/tests/sandbox_lifecycle.rs",
        "egress_evidence",
        "sandbox-authority-egress",
        None,
        None,
    ),
    (
        "crates/dwkd-authority/src/state/workload_secret_tests.rs",
        "secret_evidence",
        "authority-workload-secret",
        None,
        None,
    ),
    (
        "crates/dwkd-authority/src/state/workspace_route_tests.rs",
        "evidence",
        "authority-route",
        None,
        None,
    ),
    (
        "crates/dwkd-broker/src/exchange/workspace_tests.rs",
        "evidence",
        "broker-exchange",
        None,
        None,
    ),
)
_STRING = re.compile(r'"((?:[^"\\]|\\.)*)"')
_ARGUMENT = re.compile(r'\s*(?:"([^"]*)"|([A-Z][A-Z0-9_]*)|(.+?))\s*$', re.DOTALL)


def _calls(text: str, helper: str) -> list[tuple[int, list[str]]]:
    """Every call of `helper` in `text`: its line and its top-level arguments."""
    found = []
    for match in re.finditer(rf"(?<![\w:.]){helper}\(", text):
        if text[max(0, match.start() - 3) : match.start()] == "fn ":
            continue
        args: list[str] = []
        depth, at, start = 1, match.end(), match.end()
        while depth:
            char = text[at]
            if char == '"':
                literal = _STRING.match(text, at)
                assert literal is not None
                at = literal.end()
                continue
            if char in "([{":
                depth += 1
            elif char in ")]}":
                depth -= 1
            if (char == "," and depth == 1) or depth == 0:
                args.append(text[start:at].strip())
                start = at + 1
            at += 1
        found.append((text.count("\n", 0, match.start()) + 1, [a for a in args if a]))
    return found


def _region(rel: str, start: str | None, end: str | None) -> str:
    text = (REPO_ROOT / rel).read_text(encoding="utf-8")
    return text[text.index(start) if start else 0 : text.index(end) if end else len(text)]


def _fixed_level(rel: str) -> str | None:
    """The one level a file prints every line of a fixed-level region at."""
    text = (REPO_ROOT / rel).read_text(encoding="utf-8")
    found = re.search(r'const LEVEL: &str = "([a-z-]+)";', text) or re.search(
        r'\("level", "([a-z-]+)"\)', text
    )
    return found.group(1) if found else None


def _contract(suite: str, case: str) -> tuple[str, frozenset[str]]:
    got = dw.attribution(suite, case)
    assert got is not None, f"{suite}/{case} is unattributed"
    return got


def _record(suite: str, case: str) -> dict[str, object]:
    """A synthetic line the contract accepts for `(suite, case)`."""
    level, mechanisms = _contract(suite, case)
    record: dict[str, object] = {
        "suite": suite,
        "case": case,
        "outcome": "ok",
        "level": level,
        "enforcement": sorted(mechanisms)[0],
    }
    if "telemetry" in mechanisms:
        record.update(outcome="measured", **dict.fromkeys(dw.TELEMETRY_FIELDS, 7))
    return record


def _output(records: list[dict[str, object]], prefix: str = dw.SANDBOX_EVIDENCE_PREFIX) -> str:
    return "\n".join(f"test x ... {prefix}{json.dumps(r)}" for r in records)


def _complete(cases: tuple[tuple[str, str], ...]) -> list[dict[str, object]]:
    return [_record(suite, case) for suite, case in cases]


# --- the contract -----------------------------------------------------------


def test_every_required_case_is_attributed_and_every_rule_is_used() -> None:
    inventory = set(dw.ATTRIBUTED_CASES)
    tables = (
        dw.SANDBOX_CASES,
        dw.EGRESS_CASES,
        dw.WORKLOAD_CASES,
        dw.SECRET_SANDBOX_UNIT_CASES,
        dw.SECRET_SANDBOX_CASES,
        dw.WORKSPACE_UNIT_CASES,
        dw.WORKSPACE_CASES,
        dw.WORKSPACE_PRIVILEGED_CASES,
    )
    assert inventory == {key for table in tables for key in table}
    for table in tables:
        assert len(table) == len(set(table)), "a case is required twice"
    unattributed = sorted(f"{s}/{c}" for s, c in inventory if dw.attribution(s, c) is None)
    assert not unattributed, unattributed
    assert {suite for suite, _ in inventory} == set(dw.ATTRIBUTION)
    for suite, rules in dw.ATTRIBUTION.items():
        cases = [case for s, case in inventory if s == suite]
        for at, (pattern, _level, _mechanisms) in enumerate(rules):
            first = [
                case
                for case in cases
                if fnmatch.fnmatchcase(case, pattern)
                and not any(fnmatch.fnmatchcase(case, p) for p, _, _ in rules[:at])
            ]
            assert first, f"{suite}: the rule `{pattern}` attributes no required case"
    # The inventory M5e.1 attributes, by count: a smaller one is a lost case.
    assert len(inventory) == 497


def test_the_vocabulary_is_closed_used_and_documented() -> None:
    used: set[str] = set()
    for rules in dw.ATTRIBUTION.values():
        for _pattern, level, mechanisms in rules:
            assert level in dw.ATTRIBUTION_LEVELS, level
            named = {mechanisms} if isinstance(mechanisms, str) else set(mechanisms)
            assert named <= dw.ATTRIBUTION_MECHANISMS, named - dw.ATTRIBUTION_MECHANISMS
            used |= named
    assert used == dw.ATTRIBUTION_MECHANISMS, f"never used: {dw.ATTRIBUTION_MECHANISMS - used}"
    text = SANDBOX.read_text(encoding="utf-8")
    section = text[text.index("### 6a.") :]
    undocumented = sorted(
        word
        for word in dw.ATTRIBUTION_LEVELS | dw.ATTRIBUTION_MECHANISMS
        if f"`{word}`" not in section
    )
    assert not undocumented, f"SANDBOX.md §6a does not say what these mean: {undocumented}"


def test_each_suite_is_only_at_the_levels_it_can_reach() -> None:
    """A fake broker's line is never a container's; a broker suite has no DWKP
    client; a case only a provisioned host runs is `privileged-oci`, and no
    other case is."""
    reachable = {
        "broker-exchange": {"in-process"},
        "authority-route": {"fake-broker"},
        "authority-workload-secret": {"fake-broker"},
        "sandbox-broker": {"real-oci"},
        "sandbox-egress": {"real-oci"},
        "sandbox-workload": {"real-oci"},
        "sandbox-secret": {"real-oci"},
        "sandbox-workspace": {"real-oci", "privileged-oci"},
        "sandbox-authority": {"real-oci"},
        "sandbox-authority-egress": {"real-oci"},
        "sandbox-authority-workload": {"real-oci", "dwkp-end-to-end"},
        "sandbox-authority-secret": {"real-oci", "dwkp-end-to-end"},
        "sandbox-authority-workspace": {"real-oci", "dwkp-end-to-end", "privileged-oci"},
    }
    assert set(reachable) == set(dw.ATTRIBUTION)
    privileged = set(dw.WORKSPACE_PRIVILEGED_CASES)
    for suite, case in dw.ATTRIBUTED_CASES:
        level, _ = _contract(suite, case)
        assert level in reachable[suite], (suite, case, level)
        assert (level == "privileged-oci") == ((suite, case) in privileged), (suite, case, level)
    # Telemetry is the latency's alone.
    telemetry = [(s, c) for s, c in dw.ATTRIBUTED_CASES if "telemetry" in _contract(s, c)[1]]
    assert telemetry == [("sandbox-broker", "latency")]


def test_each_task_gates_its_lines_through_the_attributed_validator() -> None:
    for name, halves in TASKS.items():
        source = inspect.getsource(getattr(dw, name))
        assert "require_sandbox_evidence(" not in source, f"{name} still takes unattributed lines"
        calls = re.findall(r"require_attributed_evidence\(\s*([^\n]*)", source)
        assert len(calls) == len(halves), (name, calls)
    workspace = inspect.getsource(dw._sandbox_workspace_evidence)
    # Without a provisioned host the privileged half is NOT EXERCISED, which
    # fails the task, never a pass.
    assert 'raise TaskError(\n        f"NOT EXERCISED:' in workspace


# --- the emitters ------------------------------------------------------------


def test_every_emitter_prints_canonical_attributed_lines() -> None:
    for rel in sorted({rel for rel, *_ in EMITTERS}):
        text = (REPO_ROOT / rel).read_text(encoding="utf-8")
        assert "to_canonical_string" in text, f"{rel}: lines not written as canonical JSON"
        # No line spelt by hand outside the release's own module.
        hand = text[: text.index("    mod release {")] if "mod release {" in text else text
        assert '-EVIDENCE {{\\"suite' not in hand, f"{rel}: a line spelt by hand"
        assert re.search(r"fn \w*evidence\w*\([^)]*enforcement: &str", text), rel


def test_every_literal_case_prints_what_the_contract_says() -> None:
    """The contract and the source are two entries of one account: a case's
    level or mechanism changed in either alone fails here, before a runtime."""
    checked = 0
    for rel, helper, suite, start, end in EMITTERS:
        fixed = _fixed_level(rel)
        for line, args in _calls(_region(rel, start, end), helper):
            assert len(args) in (3, 4), (rel, line, args)
            case = _ARGUMENT.match(args[0])
            assert case is not None
            if case.group(1) is None:
                # A computed case: its mechanism is what the test observed,
                # and the run's gate holds it to the contract.
                continue
            level, mechanisms = _contract(suite, case.group(1))
            mechanism = _ARGUMENT.match(args[-1])
            assert mechanism is not None
            if mechanism.group(1) is not None:
                assert mechanism.group(1) in mechanisms, (rel, line, suite, case.group(1))
            if len(args) == 4:
                named = _ARGUMENT.match(args[2])
                said = CONST.get((named.group(2) if named else None) or "")
            else:
                said = fixed
            assert said == level, (rel, line, suite, case.group(1), said, level)
            checked += 1
    assert checked >= 330, checked


# --- the gate ------------------------------------------------------------------


@pytest.mark.parametrize(
    ("cases", "prefix"),
    [
        (dw.SANDBOX_CASES, dw.SANDBOX_EVIDENCE_PREFIX),
        (dw.EGRESS_CASES, dw.SANDBOX_EVIDENCE_PREFIX),
        (dw.WORKLOAD_CASES, dw.SANDBOX_EVIDENCE_PREFIX),
        (dw.SECRET_SANDBOX_UNIT_CASES, dw.SECRET_EVIDENCE_PREFIX),
        (dw.SECRET_SANDBOX_CASES, dw.SANDBOX_EVIDENCE_PREFIX),
        (dw.WORKSPACE_UNIT_CASES, dw.WORKSPACE_EVIDENCE_PREFIX),
        (dw.WORKSPACE_CASES, dw.SANDBOX_EVIDENCE_PREFIX),
        (dw.WORKSPACE_CASES + dw.WORKSPACE_PRIVILEGED_CASES, dw.SANDBOX_EVIDENCE_PREFIX),
    ],
)
def test_a_complete_attributed_output_passes(
    cases: tuple[tuple[str, str], ...], prefix: str
) -> None:
    records = dw.require_attributed_evidence(_output(_complete(cases), prefix), cases, prefix)
    assert [(r["suite"], r["case"]) for r in records] == list(cases)


def _refused(
    records: list[dict[str, object]],
    match: str,
    cases: tuple[tuple[str, str], ...] = dw.WORKLOAD_CASES,
) -> None:
    with pytest.raises(dw.TaskError, match=match):
        dw.require_attributed_evidence(_output(records), cases)


def _with(records: list[dict[str, object]], at: int, **change: object) -> list[dict[str, object]]:
    changed = [dict(r) for r in records]
    for key, value in change.items():
        if value is None:
            changed[at].pop(key, None)
        else:
            changed[at][key] = value
    return changed


SUITE, CASE = dw.WORKLOAD_CASES[10]
NAMED = re.escape(f"{SUITE}/{CASE}")


def test_a_missing_case_fails_naming_it() -> None:
    complete = _complete(dw.WORKLOAD_CASES)
    _refused(complete[:10] + complete[11:], rf"NOT EXERCISED: 1 required case\(s\): {NAMED}")


def test_a_line_without_its_level_fails() -> None:
    _refused(_with(_complete(dw.WORKLOAD_CASES), 10, level=None), rf"{NAMED}: at level None")


def test_an_empty_or_missing_enforcement_fails() -> None:
    complete = _complete(dw.WORKLOAD_CASES)
    _refused(_with(complete, 10, enforcement=""), rf"{NAMED}: names no enforcement")
    _refused(_with(complete, 10, enforcement=None), rf"{NAMED}: names no enforcement")


def test_a_wrong_level_fails() -> None:
    _refused(
        _with(_complete(dw.WORKLOAD_CASES), 10, level="dwkp-end-to-end"),
        rf"{NAMED}: at level 'dwkp-end-to-end', which must be 'real-oci'",
    )


def test_a_fake_brokers_line_promoted_to_a_real_one_fails() -> None:
    unit = dw.SECRET_SANDBOX_UNIT_CASES
    promoted = _with(_complete(unit), 0, level="real-oci")
    suite, case = unit[0]
    with pytest.raises(dw.TaskError, match=re.escape(f"{suite}/{case}: at level 'real-oci'")):
        dw.require_attributed_evidence(
            _output(promoted, dw.SECRET_EVIDENCE_PREFIX), unit, dw.SECRET_EVIDENCE_PREFIX
        )


def test_a_privileged_case_is_never_stood_in_for_by_one_that_ran_here() -> None:
    cases = dw.WORKSPACE_CASES + dw.WORKSPACE_PRIVILEGED_CASES
    complete = _complete(cases)
    at = len(dw.WORKSPACE_CASES)
    suite, case = cases[at]
    with pytest.raises(dw.TaskError, match=re.escape(f"{suite}/{case}: at level 'real-oci'")):
        dw.require_attributed_evidence(_output(_with(complete, at, level="real-oci")), cases)
    # Nor does an unprivileged case claim a provisioned host.
    suite, case = cases[0]
    with pytest.raises(dw.TaskError, match=re.escape(f"{suite}/{case}: at level")):
        dw.require_attributed_evidence(_output(_with(complete, 0, level="privileged-oci")), cases)
    # And a privileged half that never ran is NOT EXERCISED, not a pass.
    with pytest.raises(dw.TaskError, match="NOT EXERCISED: 27 required case"):
        dw.require_attributed_evidence(_output(complete[:at]), cases)


def test_unreadable_json_fails() -> None:
    text = _output(_complete(dw.WORKLOAD_CASES)) + f"\n{dw.SANDBOX_EVIDENCE_PREFIX}{{not json"
    with pytest.raises(dw.TaskError, match="unreadable evidence line"):
        dw.require_attributed_evidence(text, dw.WORKLOAD_CASES)
    with pytest.raises(dw.TaskError, match="malformed evidence line"):
        dw.require_attributed_evidence(f"{dw.SANDBOX_EVIDENCE_PREFIX}[1, 2]", dw.WORKLOAD_CASES)


def test_not_exercised_fails_naming_the_case() -> None:
    for outcome in ("not-exercised: no runtime", "NOT EXERCISED: no runtime"):
        _refused(
            _with(_complete(dw.WORKLOAD_CASES), 10, outcome=outcome),
            rf"NOT EXERCISED: 1 required case\(s\): {NAMED}",
        )


def test_a_duplicate_never_conceals_a_missing_case() -> None:
    complete = _complete(dw.WORKLOAD_CASES)
    concealed = [*complete[:10], complete[9], *complete[11:]]
    assert len(concealed) == len(complete)
    _refused(concealed, re.escape(f"{complete[9]['suite']}/{complete[9]['case']}: reported twice"))


def test_a_line_without_its_suite_or_case_or_of_another_suite_fails() -> None:
    complete = _complete(dw.WORKLOAD_CASES)
    _refused(_with(complete, 10, suite=None), "evidence without its suite or case")
    _refused(_with(complete, 10, case=""), "evidence without its suite or case")
    _refused(
        _with(complete, 10, suite="sandbox-wrkload"),
        re.escape(f"sandbox-wrkload/{CASE}: a suite this task does not run"),
    )


def test_a_case_the_inventory_does_not_hold_fails() -> None:
    _refused(
        _with(_complete(dw.WORKLOAD_CASES), 10, case="workload-renamed"),
        re.escape(f"{SUITE}/workload-renamed: a case no task requires"),
    )


def test_an_unknown_or_unearned_mechanism_fails() -> None:
    complete = _complete(dw.WORKLOAD_CASES)
    _refused(
        _with(complete, 10, enforcement="audit-event-per-attempt"),
        rf"{NAMED}: enforcement 'audit-event-per-attempt' is no known mechanism",
    )
    # A real mechanism -- but not what this case exercises.
    _refused(
        _with(complete, 10, enforcement="connect-proxy:grant"),
        rf"{NAMED}: enforcement 'connect-proxy:grant' is not what this case exercises",
    )


def test_a_line_without_an_outcome_fails() -> None:
    _refused(_with(_complete(dw.WORKLOAD_CASES), 10, outcome=None), rf"{NAMED}: no outcome")


def test_telemetry_cannot_pass_as_more() -> None:
    complete = _complete(dw.SANDBOX_CASES)
    at = dw.SANDBOX_CASES.index(("sandbox-broker", "latency"))
    for change in ({"outcome": "pass"}, {"rounds": None}, {"prepare_ms_p95": -1}):
        with pytest.raises(dw.TaskError, match="sandbox-broker/latency: telemetry"):
            dw.require_attributed_evidence(_output(_with(complete, at, **change)), dw.SANDBOX_CASES)
    # And no containment case may name telemetry.
    with pytest.raises(dw.TaskError, match="is not what this case exercises"):
        dw.require_attributed_evidence(
            _output(_with(complete, 0, enforcement="telemetry")), dw.SANDBOX_CASES
        )


def test_zero_cases_fail() -> None:
    with pytest.raises(dw.TaskError, match="zero cases required"):
        dw.require_attributed_evidence("", ())
    with pytest.raises(dw.TaskError, match=f"NOT EXERCISED: {len(dw.WORKLOAD_CASES)} required"):
        dw.require_attributed_evidence("no evidence at all", dw.WORKLOAD_CASES)


def test_the_agent_and_release_contracts_are_their_own_and_unchanged() -> None:
    """M5e.1 adds a gate; it takes nothing from the two that predate it."""
    agent = inspect.getsource(dw.require_agent_evidence)
    release = inspect.getsource(dw.require_release_evidence)
    assert "AGENT_EVIDENCE_LEVELS" in agent and "enforcement" in agent
    assert "RELEASE_LEVELS" in release and "enforcement" in release
    assert (
        frozenset(
            ("dwkp-end-to-end", "measured-oci", "real-process-refusal", "hosted-three-identity")
        )
        == dw.AGENT_EVIDENCE_LEVELS
    )
    assert {
        "authority-release": frozenset({"fake-broker"}),
        "sandbox-release": frozenset({"dwkp-end-to-end", "real-oci"}),
    } == dw.RELEASE_LEVELS
    assert not set(dw.ATTRIBUTION) & {"sandbox-agent", "sandbox-agent-identity"}
    assert not set(dw.ATTRIBUTION) & set(dw.RELEASE_LEVELS)
