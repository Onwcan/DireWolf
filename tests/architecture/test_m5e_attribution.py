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
  wrong enforcement, unreadable JSON, telemetry offered as more;
* an outcome that does not show what its line claims (ADR-0057, the
  owner's R-B): a weakening the production decision kept or never refused, an
  in-process judgement naming the inside vantage, a real weakening that says
  nothing caught it, or a detection whose invariants are of another vantage
  than its enforcement says;
* and a real-runtime suite that reads an inspection's failure -- which a
  runtime the client could not ask also answers -- as a container gone: every
  suite's `exists` asks one shared listing (`runtime_support`), the
  evidence's side of finding F-ABSENT.

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
    "task_sandbox_foundation_evidence": (
        (dw.BROKER_ASSURANCE_CASES, dw.ASSURANCE_EVIDENCE_PREFIX),
        (dw.SANDBOX_CASES, dw.SANDBOX_EVIDENCE_PREFIX),
    ),
    "task_sandbox_egress_evidence": (
        (dw.EGRESS_CASES, dw.SANDBOX_EVIDENCE_PREFIX),
        (dw.CAPTURED_ASSURANCE_CASES, dw.ASSURANCE_EVIDENCE_PREFIX),
    ),
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
    "task_sandbox_restart_evidence": ((dw.RESTART_CASES, dw.SANDBOX_EVIDENCE_PREFIX),),
    "task_sandbox_capacity_evidence": ((dw.CAPACITY_CASES, dw.SANDBOX_EVIDENCE_PREFIX),),
    "task_sandbox_proxy_weakened_evidence": ((dw.E6_CASES, dw.SANDBOX_EVIDENCE_PREFIX),),
    "task_sandbox_registry_evidence": ((dw.REGISTRY_CASES, dw.SANDBOX_EVIDENCE_PREFIX),),
    "task_sandbox_hygiene_evidence": ((dw.HYGIENE_CASES, dw.SANDBOX_EVIDENCE_PREFIX),),
}

# Which suite each emitter prints, and whether a call names its level (an
# explicit level argument) or the region has one level for every line. The
# release module is the release evidence's, attributed since M5d.6.
CONST = {"OCI": "real-oci", "E2E": "dwkp-end-to-end", "PRIV": "privileged-oci"}
EMITTERS = (
    ("crates/dwkd-broker/tests/sandbox_foundation.rs", "evidence", "sandbox-broker", None, None),
    ("crates/dwkd-broker/tests/sandbox_egress.rs", "evidence", "sandbox-egress", None, None),
    (
        "crates/dwkd-broker/tests/sandbox_egress.rs",
        "evidence_in",
        "sandbox-proxy-weakened",
        "    mod e6 {",
        None,
    ),
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
        "    mod closure {",
    ),
    (
        "crates/dwkd-broker/tests/sandbox_workload.rs",
        "evidence",
        "sandbox-closure",
        "    mod closure {",
        None,
    ),
    (
        "crates/dwkd-broker/src/sandbox/inspect_tests.rs",
        "assurance_evidence",
        "broker-assurance",
        None,
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
        "    mod restart {",
    ),
    (
        "crates/dwkd-authority/tests/sandbox_workload.rs",
        "evidence",
        "sandbox-restart",
        "    mod restart {",
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
    (
        "crates/dwkd-authority/tests/sandbox_registry.rs",
        "evidence",
        "sandbox-registry",
        None,
        None,
    ),
    (
        "crates/dwkd-authority/tests/sandbox_hygiene.rs",
        "evidence",
        "sandbox-hygiene",
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


# One real invariant of each vantage, for a synthetic line's outcome.
HOST_INVARIANT, INSIDE_INVARIANT = "HOST_NOT_PRIVILEGED", "CONTAINER_CAPABILITIES_EMPTY"


def _outcome(suite: str, case: str, enforcement: str) -> str:
    """An outcome the gate accepts: kept, refused by a host invariant, or
    detected by invariants of the enforcement's vantage; `ok` otherwise."""
    if suite == "broker-assurance":
        return dw.ASSURANCE_KEPT if case.endswith("-kept") else f"refused:{HOST_INVARIANT}"
    if (
        suite in dw.DETECTION_SUITES
        and case.startswith("weakened-")
        and not case.endswith("-count")
    ):
        named = {"measured-host": HOST_INVARIANT, "measured-inside": INSIDE_INVARIANT}.get(
            enforcement, f"{HOST_INVARIANT}+{INSIDE_INVARIANT}"
        )
        return f"detected:{named};measured-in-7ms"
    if suite == dw.REGISTRY_SUITE:
        return f"{dw.REGISTRY_OUTCOMES[case]};synthetic"
    if suite == dw.E6_SUITE:
        return _e6_outcome(case)
    return "ok"


def _e6_outcome(case: str) -> str:
    """An E6 outcome the gate accepts: the control kept, each row refused by
    exactly its invariants, the count complete."""
    topology = "+".join(f"{name}=PASS" for name in dw.E6_TOPOLOGY)
    if case == dw.E6_CONTROL:
        return (
            f"kept:every-required-invariant-pass;topology:{topology};"
            "forwarded-unchanged;destroyed:removed"
        )
    if case == dw.E6_COUNT:
        n, rows = len(dw.E6_ROWS), len(dw.E6_ROW_NAMES)
        return f"refused-{n}-of-{n}-cases;rows-{rows}-of-{rows}"
    _, caught, changed = dw.E6_ROWS[case]
    added = "none" if case == dw.E6_HOST_NETWORK else "not-applicable"
    return (
        f"refused:{'+'.join(caught)};also:none;topology:{topology};"
        f"weakened:{'+'.join(changed)};host-loopback-added:{added}"
    )


def _record(suite: str, case: str) -> dict[str, object]:
    """A synthetic line the contract accepts for `(suite, case)`."""
    level, mechanisms = _contract(suite, case)
    enforcement = sorted(mechanisms)[0]
    record: dict[str, object] = {
        "suite": suite,
        "case": case,
        "outcome": _outcome(suite, case, enforcement),
        "level": level,
        "enforcement": enforcement,
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
        dw.BROKER_ASSURANCE_CASES,
        dw.CAPTURED_ASSURANCE_CASES,
        dw.SANDBOX_CASES,
        dw.EGRESS_CASES,
        dw.WORKLOAD_CASES,
        dw.SECRET_SANDBOX_UNIT_CASES,
        dw.SECRET_SANDBOX_CASES,
        dw.WORKSPACE_UNIT_CASES,
        dw.WORKSPACE_CASES,
        dw.WORKSPACE_PRIVILEGED_CASES,
        dw.RESTART_CASES,
        dw.CAPACITY_CASES,
        dw.E6_CASES,
        dw.REGISTRY_CASES,
        dw.HYGIENE_CASES,
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
    # The inventory attributed, by count: M5e.1's 497 and M5e.2's 65 (20 in
    # process, and 19 in process over a real runtime's PROXY_ONLY record; on
    # a real runtime, 4 cross-run, the host UTS namespace and R8's 10
    # neighbour cases, 5 at the broker and 5 through the authority; on the
    # hosted runner, 7 of the runtime's restart and 4 at the live-environment
    # cap); and M5e.4's 19 registry cases, hosted only, and 2 at the broker's
    # executable-copy bound on a real runtime; and M5e.5's 44, hosted only and
    # manual: ADR-0054 §8's 22, ADR-0055 §9's 21, and the interpreter's way
    # around pip's profile (D4); and R3's E6 (ADR-0058), 18 on the hosted
    # runner: the control, ADR-0057 §1a's 15 rows in 16 cases, and their
    # count. A smaller one is a lost case.
    assert len(dw.BROKER_ASSURANCE_CASES) == 20
    assert len(dw.CAPTURED_ASSURANCE_CASES) == 19
    closure = [c for s, c in dw.WORKLOAD_CASES if s == "sandbox-closure"]
    assert len(closure) == 9
    assert len([c for c in closure if c.startswith("neighbour-")]) == 5
    authority_neighbour = [
        c
        for s, c in dw.WORKLOAD_CASES
        if s == "sandbox-authority-workload" and c.startswith("neighbour-")
    ]
    assert len(authority_neighbour) == 5
    assert ("sandbox-broker", "weakened-host-uts") in dw.SANDBOX_CASES
    assert len(dw.RESTART_CASES) == 7
    assert len(dw.CAPACITY_CASES) == 4
    assert len(dw.REGISTRY_CASES) == 19
    assert len(dw.HYGIENE_NPM_CASES) == 22
    assert len(dw.HYGIENE_PIP_CASES) == 21
    assert len(dw.HYGIENE_CASES) == 44
    assert len(dw.E6_CASES) == 18
    assert len(inventory) == 645


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
        "broker-assurance": {"in-process"},
        "sandbox-closure": {"real-oci"},
        "sandbox-restart": {"privileged-oci"},
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
        "sandbox-registry": {"dwkp-end-to-end"},
        "sandbox-hygiene": {"dwkp-end-to-end"},
        "sandbox-proxy-weakened": {"real-oci"},
    }
    assert set(reachable) == set(dw.ATTRIBUTION)
    # The provisioned workspace's cases, and the runtime's restart (which
    # needs the hosted runner's root): privileged, and nothing else is.
    privileged = set(dw.WORKSPACE_PRIVILEGED_CASES) | set(dw.RESTART_CASES)
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
        (dw.BROKER_ASSURANCE_CASES, dw.ASSURANCE_EVIDENCE_PREFIX),
        (dw.SANDBOX_CASES, dw.SANDBOX_EVIDENCE_PREFIX),
        (dw.EGRESS_CASES, dw.SANDBOX_EVIDENCE_PREFIX),
        (dw.WORKLOAD_CASES, dw.SANDBOX_EVIDENCE_PREFIX),
        (dw.SECRET_SANDBOX_UNIT_CASES, dw.SECRET_EVIDENCE_PREFIX),
        (dw.SECRET_SANDBOX_CASES, dw.SANDBOX_EVIDENCE_PREFIX),
        (dw.WORKSPACE_UNIT_CASES, dw.WORKSPACE_EVIDENCE_PREFIX),
        (dw.WORKSPACE_CASES, dw.SANDBOX_EVIDENCE_PREFIX),
        (dw.WORKSPACE_CASES + dw.WORKSPACE_PRIVILEGED_CASES, dw.SANDBOX_EVIDENCE_PREFIX),
        (dw.RESTART_CASES, dw.SANDBOX_EVIDENCE_PREFIX),
        (dw.CAPACITY_CASES, dw.SANDBOX_EVIDENCE_PREFIX),
        (dw.E6_CASES, dw.SANDBOX_EVIDENCE_PREFIX),
        (dw.REGISTRY_CASES, dw.SANDBOX_EVIDENCE_PREFIX),
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


# --- M5e.2's inventories ---------------------------------------------------------


def test_the_in_process_assurance_is_never_a_containers_and_never_partial() -> None:
    """R2 and R3 are judged in process: a line offered as an environment's
    measurement, a case missing or NOT EXERCISED, or one attributed to
    anything but the host judgement fails the foundation task."""
    cases = dw.BROKER_ASSURANCE_CASES
    prefix = dw.ASSURANCE_EVIDENCE_PREFIX
    complete = _complete(cases)
    uts = cases.index(("broker-assurance", "proxy-only-weakened-host-uts-refused"))
    named = re.escape("broker-assurance/proxy-only-weakened-host-uts-refused")
    for change, match in (
        ({"level": "real-oci"}, rf"{named}: at level 'real-oci'"),
        ({"enforcement": "capabilities-and-seccomp"}, rf"{named}: enforcement"),
        ({"outcome": "not-exercised: no broker"}, rf"NOT EXERCISED: 1 required case\(s\): {named}"),
    ):
        with pytest.raises(dw.TaskError, match=match):
            dw.require_attributed_evidence(
                _output(_with(complete, uts, **change), prefix), cases, prefix
            )
    with pytest.raises(dw.TaskError, match=rf"NOT EXERCISED: 1 required case\(s\): {named}"):
        dw.require_attributed_evidence(
            _output(complete[:uts] + complete[uts + 1 :], prefix), cases, prefix
        )
    # The same lines under the container evidence's prefix are not read.
    with pytest.raises(dw.TaskError, match=f"NOT EXERCISED: {len(cases)} required"):
        dw.require_attributed_evidence(_output(complete), cases, prefix)


def test_the_captured_record_cases_stay_in_process_and_complete() -> None:
    """R3 over a real runtime's own PROXY_ONLY record: the runtime never ran a
    weakened record, so every line is `in-process` -- a line offered as a real
    container's, a case missing or NOT EXERCISED fails the egress task -- and
    every PROXY_ONLY hard rule of the in-process table is broken in it, with
    the task backstop's old value besides."""
    cases = dw.CAPTURED_ASSURANCE_CASES
    prefix = dw.ASSURANCE_EVIDENCE_PREFIX
    proxy_only = {c for _, c in dw.BROKER_ASSURANCE_CASES if c.startswith("proxy-only-")}
    assert {c.removeprefix("captured-") for _, c in cases} == proxy_only | {
        "proxy-only-weakened-task-backstop-at-256-refused"
    }
    complete = _complete(cases)
    assert {r["level"] for r in complete} == {"in-process"}
    at = cases.index(("broker-assurance", "captured-proxy-only-weakened-privileged-refused"))
    named = re.escape("broker-assurance/captured-proxy-only-weakened-privileged-refused")
    for change, match in (
        ({"level": "real-oci"}, rf"{named}: at level 'real-oci'"),
        ({"level": "privileged-oci"}, rf"{named}: at level 'privileged-oci'"),
        ({"outcome": "not-exercised: nothing captured"}, "NOT EXERCISED: 1 required case"),
    ):
        with pytest.raises(dw.TaskError, match=match):
            dw.require_attributed_evidence(
                _output(_with(complete, at, **change), prefix), cases, prefix
            )
    with pytest.raises(dw.TaskError, match=rf"NOT EXERCISED: 1 required case\(s\): {named}"):
        dw.require_attributed_evidence(
            _output(complete[:at] + complete[at + 1 :], prefix), cases, prefix
        )
    egress = inspect.getsource(dw.task_sandbox_egress_evidence)
    assert "DW_CAPTURED_RECORD_DIR" in egress
    # One directory, the same for the task and the broker's test -- which
    # names it from its own crate, never from a variable (TX042).
    assert dw.CAPTURED_RECORD_DIR == REPO_ROOT / "target" / "m5e-captured-proxy-only"
    judged = (REPO_ROOT / "crates/dwkd-broker/src/sandbox/inspect_tests.rs").read_text("utf-8")
    assert '"/../../target/m5e-captured-proxy-only"' in judged
    assert 'env!("CARGO_MANIFEST_DIR")' in judged
    assert egress.index('require_attributed_evidence("\\n".join(outputs)') < egress.index(
        "CAPTURED_ASSURANCE_TEST"
    ), "the record is judged only after the real environment's own evidence passed"


U4 = (
    "proxy-only-weakened-seccomp-default-profile-refused",
    "proxy-only-weakened-swap-limit-lifted-refused",
    "proxy-only-weakened-pids-and-swap-limits-lifted-refused",
)


@pytest.mark.parametrize("case", U4)
def test_u4_is_required_in_process_over_both_records_and_never_as_a_container(
    case: str,
) -> None:
    """ADR-0057 §3, U4: the runtime's default seccomp profile and the swap
    limit -- alone, and with the pids limit as the real NO_NETWORK case
    lifts both -- are judged under PROXY_ONLY over the hand-written record
    and over a real runtime's own, and required by name in both tasks. Each
    is `in-process`: offered as a real container's, missing, NOT EXERCISED
    or reported twice in place of another, it fails its task. The real
    NO_NETWORK cases they mirror stay required at their own level."""
    prefix = dw.ASSURANCE_EVIDENCE_PREFIX
    source = (REPO_ROOT / "crates/dwkd-broker/src/sandbox/inspect_tests.rs").read_text("utf-8")
    assert f'"{case}"' in source, "the broker's test emits it"
    for cases, name in (
        (dw.BROKER_ASSURANCE_CASES, case),
        (dw.CAPTURED_ASSURANCE_CASES, f"captured-{case}"),
    ):
        at = cases.index(("broker-assurance", name))
        named = re.escape(f"broker-assurance/{name}")
        complete = _complete(cases)
        assert complete[at]["level"] == "in-process"
        for change, match in (
            ({"level": "real-oci"}, rf"{named}: at level 'real-oci'"),
            ({"level": "privileged-oci"}, rf"{named}: at level 'privileged-oci'"),
            (
                {"outcome": "not-exercised: no record"},
                rf"NOT EXERCISED: 1 required case\(s\): {named}",
            ),
        ):
            with pytest.raises(dw.TaskError, match=match):
                dw.require_attributed_evidence(
                    _output(_with(complete, at, **change), prefix), cases, prefix
                )
        missing = complete[:at] + complete[at + 1 :]
        with pytest.raises(dw.TaskError, match=rf"NOT EXERCISED: 1 required case\(s\): {named}"):
            dw.require_attributed_evidence(_output(missing, prefix), cases, prefix)
        # Another case's line twice does not stand in for this one.
        other = missing[0 if at else 1]
        with pytest.raises(dw.TaskError, match="reported twice"):
            dw.require_attributed_evidence(_output([*missing, other], prefix), cases, prefix)
    for real in ("weakened-seccomp-default-profile", "weakened-resource-limits-dropped"):
        assert ("sandbox-broker", real) in dw.SANDBOX_CASES
        contract = dw.attribution("sandbox-broker", real)
        assert contract is not None
        assert contract[0] == "real-oci"


# --- what a line says it showed (R17; ADR-0057, the owner's R-B) ----------------


def _shown_refused(
    cases: tuple[tuple[str, str], ...], case: str, outcome: str, match: str, prefix: str
) -> None:
    at = cases.index(next(key for key in cases if key[1] == case))
    named = re.escape(f"{cases[at][0]}/{case}")
    changed = _with(_complete(cases), at, outcome=outcome)
    with pytest.raises(dw.TaskError, match=rf"{named}: {match}"):
        dw.require_attributed_evidence(_output(changed, prefix), cases, prefix)


@pytest.mark.parametrize(
    ("cases", "prefix"),
    [
        (dw.BROKER_ASSURANCE_CASES, dw.ASSURANCE_EVIDENCE_PREFIX),
        (dw.CAPTURED_ASSURANCE_CASES, dw.ASSURANCE_EVIDENCE_PREFIX),
    ],
)
def test_a_weakening_the_production_decision_did_not_refuse_fails(
    cases: tuple[tuple[str, str], ...], prefix: str
) -> None:
    """R3's judgement shows the production decision's refusal by the
    invariants that failed: a weakened record whose line says it was kept,
    passed, or refused by nothing that is an invariant fails its task -- and
    so does a conforming record reported anything but kept."""
    weakened = next(c for _, c in cases if c.endswith("-weakened-privileged-refused"))
    for outcome in (
        dw.ASSURANCE_KEPT,
        "kept",
        "pass",
        "refused",
        "refused:",
        "refused:host_not_privileged",
        f"refused:{HOST_INVARIANT}+",
        f"detected:{HOST_INVARIANT}",
    ):
        _shown_refused(
            cases, weakened, outcome, "the production decision's refusal is not shown", prefix
        )
    conforming = next(c for _, c in cases if c.endswith("-conforming-kept"))
    for outcome in (f"refused:{HOST_INVARIANT}", "kept", "pass"):
        _shown_refused(cases, conforming, outcome, "a conforming record's line must say", prefix)


@pytest.mark.parametrize("cases", [dw.BROKER_ASSURANCE_CASES, dw.CAPTURED_ASSURANCE_CASES])
def test_an_in_process_judgement_never_claims_the_inside_vantage(
    cases: tuple[tuple[str, str], ...],
) -> None:
    """The judgement reads the runtime's record -- the host's vantage alone. A
    line naming an invariant only the probe inside measures claims a
    measurement no in-process case makes, the step E6 needs a real container
    for (ADR-0057 §3, U2)."""
    weakened = next(c for _, c in cases if c.endswith("-weakened-privileged-refused"))
    for outcome in (
        f"refused:{HOST_INVARIANT}+{INSIDE_INVARIANT}",
        f"refused:{INSIDE_INVARIANT}",
    ):
        _shown_refused(
            cases,
            weakened,
            outcome,
            "a judgement of the runtime's record names the inside vantage",
            dw.ASSURANCE_EVIDENCE_PREFIX,
        )


def test_a_real_weakening_names_what_caught_it_from_the_vantage_it_claims() -> None:
    """E2 and E3 -- a real runtime's weakened topologies and `NO_NETWORK`
    profiles -- each say what caught them: a weakening that names nothing
    caught, a detection naming no invariant, or invariants of another vantage
    than the line's enforcement claims, fails its task. So no line can say
    `measured-both` for a weakening only one vantage saw."""
    prefix = dw.SANDBOX_EVIDENCE_PREFIX
    both = f"detected:{HOST_INVARIANT}+{INSIDE_INVARIANT};measured-in-7ms"
    for cases, case, outcome, match in (
        (dw.SANDBOX_CASES, "weakened-privileged", "clean", "a weakening's line must say"),
        (dw.SANDBOX_CASES, "weakened-privileged", "pass", "a weakening's line must say"),
        (dw.SANDBOX_CASES, "weakened-privileged", "detected:", "a detection that names no"),
        (dw.SANDBOX_CASES, "weakened-privileged", "detected:yes", "a detection that names no"),
        (
            dw.SANDBOX_CASES,
            "weakened-privileged",
            f"detected:{HOST_INVARIANT};measured-in-7ms",
            "its invariants were measured-host, not measured-both",
        ),
        (
            dw.SANDBOX_CASES,
            "weakened-privileged",
            f"detected:{INSIDE_INVARIANT}",
            "its invariants were measured-inside, not measured-both",
        ),
        (
            dw.SANDBOX_CASES,
            "weakened-host-ipc",
            both,
            "its invariants were measured-both, not measured-host",
        ),
        (dw.EGRESS_CASES, "weakened-bridge-network", "pass", "a weakening's line must say"),
        (
            dw.EGRESS_CASES,
            "weakened-bridge-network",
            f"detected:{HOST_INVARIANT}",
            "its invariants were measured-host, not measured-both",
        ),
        (dw.EGRESS_CASES, "weakened-relay-tampered", "never-started", "a weakening's line"),
        (
            dw.EGRESS_CASES,
            "drift-extra-peer-listening",
            f"detected:{HOST_INVARIANT}",
            "its invariants were measured-host, not measured-inside",
        ),
    ):
        _shown_refused(cases, case, outcome, match, prefix)
    # What the suites print is accepted: each weakening's own invariants, its
    # measurement time after them, and the counts that name no invariant.
    complete = _complete(dw.SANDBOX_CASES)
    for case, outcome in (
        (
            "weakened-runtime-socket-mounted",
            "detected:HOST_NO_RUNTIME_SOCKET+HOST_MOUNTS_EXACT+CONTAINER_NO_RUNTIME_SOCKET;"
            "measured-in-412ms",
        ),
        ("weakened-host-uts", "detected:HOST_UTS_NAMESPACE_PRIVATE;measured-in-97ms"),
        ("weakened-count", "detected-15-of-15"),
        ("drift-pids-limit-raised", "detected-host-and-inside"),
    ):
        at = dw.SANDBOX_CASES.index(("sandbox-broker", case))
        complete = _with(complete, at, outcome=outcome)
    dw.require_attributed_evidence(_output(complete, prefix), dw.SANDBOX_CASES, prefix)


def _invariant_lists(text: str, cases: list[str]) -> dict[str, list[str]]:
    """Each case's expected invariants as its table spells them: the first
    `&[I::…]` after the case's literal, as `HOST_…`/`CONTAINER_…` names."""
    found = {}
    for case in cases:
        start = text.index(f'"{case}"')
        listed = re.search(r"&\[\s*((?:(?:I|SandboxInvariant)::\w+,?\s*)+)\]", text[start:])
        assert listed is not None, case
        found[case] = [
            re.sub(r"(?<!^)(?=[A-Z])", "_", name).upper()
            for name in re.findall(r"::(\w+)", listed.group(1))
        ]
    return found


def test_each_weakenings_invariants_are_of_the_vantage_its_contract_gives() -> None:
    """The source and the contract agree on vantage before any runtime: each
    real `NO_NETWORK` weakening's expected invariants (E3) are of the vantage
    `ATTRIBUTION` gives its case, and every in-process judgement under either
    topology (E4, E5) expects host invariants only."""
    foundation = (REPO_ROOT / "crates/dwkd-broker/tests/sandbox_foundation.rs").read_text("utf-8")
    body = foundation[foundation.index("fn every_weakened_profile_is_detected") :]
    body = body[: body.index("\n    }\n")]
    weakenings = [
        c for _, c in dw.SANDBOX_CASES if c.startswith("weakened-") and not c.endswith("-count")
    ]
    assert len(weakenings) == 15, weakenings
    for case, named in _invariant_lists(body, weakenings).items():
        measured = dw._VANTAGE[
            (
                any(n.startswith("HOST_") for n in named),
                any(n.startswith("CONTAINER_") for n in named),
            )
        ]
        assert _contract("sandbox-broker", case)[1] == {measured}, (case, named, measured)
    judged = (REPO_ROOT / "crates/dwkd-broker/src/sandbox/inspect_tests.rs").read_text("utf-8")
    table = judged[judged.index("fn hard_rule_weakenings") :]
    table = table[: table.index("\n}\n")]
    refused = [
        c for _, c in dw.BROKER_ASSURANCE_CASES if c.endswith("-refused") and f'"{c}"' in table
    ]
    assert len(refused) == len(dw.BROKER_ASSURANCE_CASES) - 3, refused
    expected = _invariant_lists(table, refused)
    assert all(n.startswith("HOST_") for named in expected.values() for n in named), expected
    # The two the table does not hold -- U4's limits lifted, the backstop at
    # 256 -- name the host's resource limits alone.
    assert judged.count("&[SandboxInvariant::HostResourceLimits]") >= 3


def test_the_closure_cases_are_a_real_runtimes_and_each_its_own() -> None:
    """R9 runs on a real runtime: a line claiming less, or attributed to
    another case's mechanism, fails the workload task."""
    cases = dw.WORKLOAD_CASES
    complete = _complete(cases)
    at = cases.index(("sandbox-closure", "cross-run-processes-not-visible"))
    named = re.escape("sandbox-closure/cross-run-processes-not-visible")
    _refused(_with(complete, at, level="in-process"), rf"{named}: at level 'in-process'")
    _refused(
        _with(complete, at, enforcement="exact-label-ownership"),
        rf"{named}: enforcement 'exact-label-ownership' is not what this case exercises",
    )
    _refused(complete[:at] + complete[at + 1 :], rf"NOT EXERCISED: 1 required case\(s\): {named}")
    # Every M5e.2 case is one the plan's matrix cites, and so one a task
    # requires by name.
    plan = (REPO_ROOT / "docs" / "M5E_ASSURANCE_PLAN.md").read_text(encoding="utf-8")
    uncited = sorted(
        case
        for suite, case in (
            *dw.BROKER_ASSURANCE_CASES,
            *dw.CAPTURED_ASSURANCE_CASES,
            *cases,
            *dw.CAPACITY_CASES,
        )
        if (suite in ("broker-assurance", "sandbox-closure") or case.startswith("neighbour-"))
        and f"`{case}`" not in plan
    )
    assert not uncited, f"the plan's matrix does not cite: {uncited}"


BROKER_WORKLOAD = REPO_ROOT / "crates" / "dwkd-broker" / "tests" / "sandbox_workload.rs"
AUTHORITY_WORKLOAD = REPO_ROOT / "crates" / "dwkd-authority" / "tests" / "sandbox_workload.rs"
NEIGHBOUR = "a_neighbour_at_its_task_bound_leaves_another_environment_and_the_broker_serving"
AUTHORITY_NEIGHBOUR = "a_run_at_its_task_bound_leaves_another_runs_process_exec_served"


def _test_body(path: Path, name: str) -> tuple[str, str]:
    """`name`'s `#[ignore]` reason and its body, from its file."""
    text = path.read_text(encoding="utf-8")
    found = re.search(r'#\[ignore = "([^"]*)"\]\n( *)fn ' + name + r"\(\) \{", text)
    assert found is not None, f"{name} is not an #[ignore]d test in {path.name}"
    end = text.index(f"\n{found.group(2)}}}\n", found.end())
    return found.group(1), text[found.end() : end]


def test_the_neighbour_tests_are_required_evidence_since_adr_0056() -> None:
    """R8 restored (ADR-0056, the owner's Option B): finding F-R8's reproducer
    is a required test of the workload evidence, at the broker and through
    the authority, every case it prints required by name -- none can be
    dropped, and a run that leaves one out is NOT EXERCISED, which fails."""
    assert dw.WORKLOAD_BROKER_TESTS.count(f"linux::closure::{NEIGHBOUR}") == 1
    assert dw.WORKLOAD_AUTHORITY_TESTS.count(f"linux::{AUTHORITY_NEIGHBOUR}") == 1
    for path, name, suite in (
        (BROKER_WORKLOAD, NEIGHBOUR, "sandbox-closure"),
        (AUTHORITY_WORKLOAD, AUTHORITY_NEIGHBOUR, "sandbox-authority-workload"),
    ):
        reason, body = _test_body(path, name)
        assert reason == "needs a real OCI runtime: make sandbox-workload-evidence", reason
        printed = re.findall(r'evidence\(\s*"(neighbour-[a-z0-9-]+)"', body)
        required = sorted(c for s, c in dw.WORKLOAD_CASES if s == suite and c.startswith("neigh"))
        assert sorted(printed) == required, (name, printed)
        # The pressure is asserted from the fixture's own count and the
        # runtime's, never reduced: at least PIDS_LIMIT - 8, the cgroup full.
        assert "workload-hold-tasks" in body and "4096" in body, name
        assert "+ 8 >= " in body and "PIDS_LIMIT" in body, name
        assert "finding F-R8" in body, f"{name} no longer says the coupling it finds"
    complete = _complete(dw.WORKLOAD_CASES)
    for at, (suite, case) in enumerate(dw.WORKLOAD_CASES):
        if case.startswith("neighbour-"):
            named = re.escape(f"{suite}/{case}")
            _refused(
                complete[:at] + complete[at + 1 :],
                rf"NOT EXERCISED: 1 required case\(s\): {named}",
            )
            _refused(
                _with(complete, at, outcome="not-exercised: no runtime"),
                rf"NOT EXERCISED: 1 required case\(s\): {named}",
            )


def test_the_capacity_test_is_hosted_only_guarded_first_and_required() -> None:
    """R8 at the cap fills every live environment the authority allows: it is
    selected by name by the hosted capacity task alone, checks where it is
    before it makes anything, and prints every case that task requires."""
    assert len(dw.CAPACITY_TESTS) == 1
    name = dw.CAPACITY_TESTS[0].rsplit("::", 1)[-1]
    selected = (*dw.WORKLOAD_BROKER_TESTS, *dw.WORKLOAD_AUTHORITY_TESTS, *dw.RESTART_TESTS)
    assert not [test for test in selected if test.endswith(name)]
    reason, body = _test_body(BROKER_WORKLOAD, name)
    assert "hosted only" in reason, reason
    assert body.index("capacity_runner(") < body.index("Broker::start("), (
        "the test checks where it is before it makes anything"
    )
    printed = re.findall(r'evidence\(\s*"(capacity-[a-z0-9-]+)"', body)
    assert sorted(printed) == sorted(c for _, c in dw.CAPACITY_CASES)
    text = BROKER_WORKLOAD.read_text(encoding="utf-8")
    guard = text[text.index("fn capacity_runner(") : text.index(f"fn {name}(")]
    for check in (
        "DW_CAPACITY_EVIDENCE",
        "GITHUB_ACTIONS",
        "RUNNER_ENVIRONMENT",
        "Docker Desktop",
        "MemAvailable",
        "threads-max",
        "pid_max",
        "SANDBOX_UID",
    ):
        assert check in guard, check


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


SUPPORT = tuple(
    REPO_ROOT / "crates" / crate / "tests" / "runtime_support" / "mod.rs"
    for crate in ("dwkd-broker", "dwkd-authority")
)


def test_a_suite_believes_a_container_gone_only_from_a_listing_the_runtime_answered() -> None:
    """The evidence's side of F-ABSENT: the runtime's client fails an
    inspection alike for a container the runtime does not hold and for a
    runtime it could not ask, so no suite reads an inspection's failure as an
    absence. Every real-runtime suite's `exists` asks the one shared listing,
    which fails its test when the client failed -- its own unit tests hold
    that, the negative control among them -- and both crates hold that
    listing byte for byte."""
    broker, authority = (path.read_bytes() for path in SUPPORT)
    assert broker == authority, "the crates' runtime_support copies differ"
    shared = broker.decode("utf-8")
    assert re.search(
        r'"container",\s*"ls",\s*"--all",\s*"--no-trunc",\s*"--quiet",\s*"--filter"', shared
    )
    assert "out.status.success()" in shared
    delegates = 0
    for path in sorted((REPO_ROOT / "crates").glob("*/tests/*.rs")):
        source = path.read_text(encoding="utf-8")
        name = path.relative_to(REPO_ROOT)
        # Existence by an inspection's exit status, however the call is laid out.
        assert not re.search(r'"inspect",\s*"--format",\s*"\{\{\.Id\}\}"', source), name
        for found in re.finditer(
            r"fn exists\(&self, (\w+): &str\) -> bool \{\n(.*?)\n\s*\}\n", source, re.S
        ):
            wanted = f"super::runtime_support::exists(|args| self.docker(args), {found.group(1)})"
            assert found.group(2).strip() == wanted, name
            delegates += 1
    # A pattern that matches nothing would pass vacuously.
    assert delegates == 8, delegates
