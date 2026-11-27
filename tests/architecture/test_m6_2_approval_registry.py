"""M6.2 (ADR-0080): the approval registry's record, its mutation review, its
evidence inventory and its seams agree with the code."""

from __future__ import annotations

import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
STATE = REPO_ROOT / "crates" / "dwkd-authority" / "src" / "state"
REGISTRY = STATE / "approvals.rs"
ADR = (
    REPO_ROOT
    / "docs"
    / "adr"
    / "0080-the-approval-registry-durable-requests-and-atomic-consumption.md"
)

sys.path.insert(0, str(REPO_ROOT / "scripts"))

import dw  # noqa: E402  - imported after the path is extended


def _read(path: Path) -> str:
    return path.read_bytes().decode("utf-8")


def test_the_record_is_proposed_and_names_its_schema() -> None:
    adr = _read(ADR)
    assert adr.startswith("# ADR-0080:")
    assert "**Status:** Proposed" in adr
    schema = _read(STATE / "schema.rs")
    assert "pub(super) const CURRENT_VERSION: i64 = 15;" in schema
    for table in ("approval_clock", "approval_request", "approval", "approval_use"):
        assert f"CREATE TABLE {table} (" in schema, table
        assert f"`{table}`" in adr, table


def test_the_mutation_table_matches_the_source_once_per_mutant() -> None:
    names = [m[0] for m in dw.APPROVAL_REGISTRY_MUTATIONS]
    # A01-A49 are M6.2's; A50-A54 M6.2.1's.
    assert [n.split(":")[0] for n in names] == [f"A{n:02d}" for n in range(1, 55)]
    files = {
        "crates/dwkd-authority/src/state/approvals.rs",
        "crates/dwkd-authority/src/state/workload.rs",
        "crates/dwkd-authority/src/state/schema.rs",
        "crates/dwkd-authority/src/state/mod.rs",
        "crates/dwkd-authority/src/lib.rs",
    }
    for what, rel, old, new in dw.APPROVAL_REGISTRY_MUTATIONS:
        assert rel in files, what
        assert _read(REPO_ROOT / rel).count(old) == 1, what
        assert old != new, what
    assert dw.TASKS["approval-registry-mutations"] is dw.task_approval_registry_mutations
    assert dw.TASKS["approval-registry-evidence"] is dw.task_approval_registry_evidence
    assert [s.name for s in dw._approval_registry_stages()] == [
        "approval-registry",
        "approval-registry-record",
        "approval-registry-crash",
    ]
    makefile = _read(REPO_ROOT / "Makefile")
    assert "\napproval-registry-mutations: ## M6.2" in makefile
    assert "\t@$(DW) approval-registry-mutations\n" in makefile
    assert "\napproval-registry-evidence: ## M6.2" in makefile
    assert "\t@$(DW) approval-registry-evidence\n" in makefile
    assert [e[0].split(":")[0] for e in dw.APPROVAL_REGISTRY_EQUIVALENT] == ["E1", "E2", "E3"]


def test_every_spend_guard_has_a_mutant() -> None:
    """Each conjunct of the spend-time check, mutated on its own."""
    registry = _read(REGISTRY)
    body = registry[registry.index("fn passes(") :]
    body = body[: body.index("\n}\n")]
    guards = [
        line.strip().removeprefix("&& ")
        for line in body.splitlines()[1:]
        if line.strip() and not line.strip().startswith("//")
    ]
    olds = "".join(old for _, _, old, _ in dw.APPROVAL_REGISTRY_MUTATIONS)
    assert len(guards) == 10, guards
    for guard in guards:
        assert guard in olds, guard


def test_every_evidence_case_is_printed_by_exactly_one_test() -> None:
    route = _read(STATE / "approval_route_tests.rs")
    secret = _read(STATE / "workload_secret_tests.rs")
    printed = re.findall(r'approval_evidence\(\s*"([a-z0-9-]+)"', route)
    in_secret = re.findall(r'\("case", "([a-z0-9-]+)"\)', secret)
    assert in_secret == ["a2-credential-launch-not-requested"]
    printed += in_secret
    assert sorted(printed) == sorted(dw.APPROVAL_EVIDENCE_CASES)
    assert len(set(printed)) == len(printed)
    tests = re.findall(r"\n#\[test\]\nfn (m6_2_\w+)\(", route)
    assert len(tests) == len(re.findall(r'approval_evidence\(\s*"', route)), tests


def test_the_seams_have_no_production_caller() -> None:
    """The approver set is attached in test builds only; the decision and the
    revocation say in their code that M6.3 is their first caller."""
    registry = _read(REGISTRY)
    at = registry.index("pub(crate) fn attach_approvers(")
    before = registry[:at].rstrip().splitlines()[-1].strip()
    assert before == '#[cfg(all(test, target_os = "linux"))]', before
    for seam, reason in (
        ("pub(crate) fn decide_approval(", "M6.3's approver operations are its first production"),
        ("pub(crate) fn revoke_approval(", "M6.3's operator revocation is its first production"),
    ):
        at = registry.index(seam)
        attributes = registry[registry.rindex("    #[cfg_attr(", 0, at) : at]
        assert 'not(all(test, target_os = "linux"))' in attributes, seam
        assert "dead_code" in attributes, seam
        assert reason in attributes, seam
    # The approver endpoint still holds no operation (TX065, unchanged).
    approver = _read(REPO_ROOT / "crates" / "dwkd-authority" / "src" / "server" / "approver.rs")
    assert "decide_approval" not in approver
    assert "revoke_approval" not in approver


def test_a_use_is_spent_after_its_intent_in_the_intents_transaction() -> None:
    route = _read(STATE / "workload.rs")
    body = route[route.index("fn intent_recorded(") :]
    body = body[: body.index("\n}\n")]
    assert body.index("AuditEvent::WorkloadIntentRecorded") < body.index("approvals::consume(")
    begin = route[route.index("pub(super) fn begin(") :]
    begin = begin[: begin.index("\n}\n")]
    # The intent is recorded, then the use, then the secret's intent: one
    # transaction, before the broker hears of it.
    assert begin.index("record_intent(") < begin.index("intent_recorded(")
    assert begin.index("intent_recorded(") < begin.index("secret_intent(")
    assert "broker" not in begin.lower()


def test_the_authority_evidence_job_requires_the_registry_evidence() -> None:
    ci = _read(REPO_ROOT / ".github" / "workflows" / "ci.yml")
    job = ci[ci.index("\n  authority-transport:\n") :]
    job = job[: job.index("\n\n  #")]
    assert "      - run: make approval-registry-evidence\n" in job
    assert "authority-transport" in ci[ci.index("\n  ci:\n") :]


def _evidence_line(
    case: str, *, suite: str = "authority-approval-registry", outcome: str = "x"
) -> str:
    return (
        f'APPROVAL-EVIDENCE {{"suite":"{suite}","case":"{case}","outcome":"{outcome}","count":1}}'
    )


def test_the_evidence_requires_every_case_once_with_an_outcome() -> None:
    every = "\n".join(_evidence_line(case) for case in dw.APPROVAL_EVIDENCE_CASES)
    records = dw.require_approval_evidence("noise\n" + every + "\ntest result: ok.")
    assert [r["case"] for r in records] == list(dw.APPROVAL_EVIDENCE_CASES)
    first, *rest = dw.APPROVAL_EVIDENCE_CASES
    without_first = "\n".join(_evidence_line(case) for case in rest)
    for output, why in (
        ("", "NOT EXERCISED"),
        ("test result: ok. 0 passed", "NOT EXERCISED"),
        (without_first, "NOT EXERCISED"),
        (every + "\n" + _evidence_line(first), "reported twice"),
        (every + "\n" + _evidence_line("not-a-case"), "no inventory"),
        (
            every.replace(_evidence_line(first), _evidence_line(first, suite="other")),
            "another suite",
        ),
        (every.replace(_evidence_line(first), _evidence_line(first, outcome="")), "no outcome"),
        (every + "\nAPPROVAL-EVIDENCE {not json", "unreadable"),
    ):
        try:
            dw.require_approval_evidence(output)
        except dw.TaskError as error:
            assert why in str(error), (why, str(error))
        else:
            raise AssertionError(f"accepted: {why}")
