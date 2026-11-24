"""C3 (Phase 2.5): hosted evidence for Phase 1's remediations.

What these tests hold:

* the evidence matrix (`docs/c3-evidence-matrix.json`) gives every finding
  (F-19, F-17, F-01, F-18) and every invariant of ADR-0061 (EG-1..EG-14) and
  ADR-0062 (T-1..T-12) an evidence contract, and every row names a real
  producer at its real level: an attributed case at the level its attribution
  states, a three-identity case from the three-identity table, a unit test
  that exists, a mutation campaign the C3 gate knows;
* the mutation harness (`dw.mutation_review`) counts a mutant KILLED only
  when a named test failed or an evidence task refused -- never a build
  error, a command that failed with no failing test, a selection that ran no
  test, a timeout or a NOT EXERCISED -- runs nothing when the unmutated
  baseline fails, restores every file, and keeps a record that says so;
* the C3 gate (`dw.c3_gate_verdict`) accepts only THIS run's records, every
  shard of every campaign, each inventory exactly its table, every mutant
  killed, and two distinct, ordinary uids for the cross-uid cases;
* the hand-dispatched workflow matches the campaigns, and the required CI and
  its M5 gate are untouched; ADR-0060..0063 stay Proposed.

Everything here is synthetic: records built here, fake stages, no cargo.
"""

from __future__ import annotations

import copy
import hashlib
import json
import re
import shutil
import sys
from collections.abc import Callable
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))
import dw  # noqa: E402  - imported after the path is extended

MATRIX_PATH = REPO_ROOT / "docs" / "c3-evidence-matrix.json"
REPORT = REPO_ROOT / "docs" / "C3_HOSTED_EVIDENCE.md"
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "c3-evidence.yml"
CI = REPO_ROOT / ".github" / "workflows" / "ci.yml"
RUN_ID = "43700000001"
SHA = "0123456789abcdef0123456789abcdef01234567"
OTHER_SHA = "fedcba9876543210fedcba9876543210fedcba98"
HOSTED = {
    "GITHUB_ACTIONS": "true",
    "RUNNER_ENVIRONMENT": "github-hosted",
    "GITHUB_RUN_ID": RUN_ID,
    "GITHUB_RUN_ATTEMPT": "1",
    "GITHUB_SHA": SHA,
    "GITHUB_REF": "refs/heads/main",
    "RUNNER_OS": "Linux",
    "ImageOS": "ubuntu26",
    "ImageVersion": "20261101.186.1",
}
GATE_ENV = {**HOSTED, "GITHUB_JOB": dw.C3_GATE_JOB}
FINDINGS = {"F-19": "0060", "F-17": "0061", "F-01": "0062", "F-18": "0063"}


def _matrix() -> dict[str, object]:
    loaded = json.loads(MATRIX_PATH.read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def _rows(matrix: dict[str, object]) -> list[dict[str, object]]:
    rows = matrix["rows"]
    assert isinstance(rows, list)
    return rows


def _d(value: object) -> dict[str, object]:
    assert isinstance(value, dict)
    return value


def _l(value: object) -> list[object]:
    assert isinstance(value, list)
    return value


# --- the matrix ------------------------------------------------------------------------


def matrix_problems(matrix: dict[str, object]) -> list[str]:
    """Every way a matrix row fails to name a real producer at its real level."""
    problems: list[str] = []
    statuses = set(_l(matrix["statuses"]))
    if statuses != {"VERIFIED", "FAILED", "NOT EXERCISED", "NOT VERIFIED", "BLOCKED"}:
        problems.append(f"statuses {sorted(map(str, statuses))}")
    tables = {
        campaign: {m[0] for m in dw._c3_table(campaign)}
        for campaign, spec in dw.C3_CAMPAIGNS.items()
        if spec[3] is not None
    }
    ids: set[str] = set()
    for row in _rows(matrix):
        rid = str(row.get("id"))
        if rid in ids:
            problems.append(f"{rid}: listed twice")
        ids.add(rid)
        finding, adr = row.get("finding"), row.get("adr")
        if FINDINGS.get(str(finding)) != adr:
            problems.append(f"{rid}: {finding} is not ADR-{adr}'s finding")
        status = row.get("status")
        if status not in statuses:
            problems.append(f"{rid}: status {status!r}")
        evidence = _d(row.get("evidence"))
        kind, level = evidence.get("kind"), row.get("level")
        if kind == "attributed-case":
            key = (str(evidence["suite"]), str(evidence["case"]))
            contract = dw.attribution(*key)
            if key not in dw.ATTRIBUTED_CASES or contract is None:
                problems.append(f"{rid}: {key} is no attributed case")
            elif contract[0] != level:
                problems.append(f"{rid}: {key} is {contract[0]}, not {level}")
        elif kind == "agent-cases":
            for case in _l(evidence["cases"]):
                if (str(evidence["suite"]), case) not in dw.AGENT_IDENTITY_CASES:
                    problems.append(f"{rid}: {case} is no three-identity agent case")
            if level != "hosted-three-identity" or row.get("identities") != 3:
                problems.append(f"{rid}: a three-identity case at {level}")
        elif kind == "eval":
            suite = (REPO_ROOT / "evals" / "suites" / "authority-security.toml").read_text(
                encoding="utf-8"
            )
            name = str(evidence["eval_id"]).removeprefix("authority-security/")
            if f'name = "{name}"' not in suite or _l(evidence["cases"]) != list(dw.FOREIGN_CASES):
                problems.append(f"{rid}: not the peer-credential eval over FOREIGN_CASES")
            if row.get("identities") != 2:
                problems.append(f"{rid}: a cross-uid eval is two identities")
        elif kind == "unit":
            source = (REPO_ROOT / str(evidence["file"])).read_text(encoding="utf-8")
            for test in _l(evidence["tests"]):
                if not re.search(rf"\bfn {re.escape(str(test))}\(", source):
                    problems.append(f"{rid}: no test {test} in {evidence['file']}")
        elif kind == "mutation-campaign":
            if evidence["campaign"] not in dw.C3_CAMPAIGNS:
                problems.append(f"{rid}: no campaign {evidence['campaign']}")
            # A campaign is VERIFIED by the C3 workflow's own run and its passed
            # gate -- never by a local run, another workflow or the matrix alone.
            cited = row.get("run")
            if status == "VERIFIED" and not (
                isinstance(cited, dict)
                and cited.get("workflow") == ".github/workflows/c3-evidence.yml"
                and "C3 gate: COMPLETE" in str(row.get("provenance"))
            ):
                problems.append(f"{rid}: a campaign is VERIFIED only by a passed C3 gate")
        elif kind == "inventory":
            if not (REPO_ROOT / str(evidence["pinned"])).is_file():
                problems.append(f"{rid}: no pinned inventory {evidence['pinned']}")
        elif kind == "workflow":
            if not (REPO_ROOT / str(evidence["workflow"])).is_file():
                problems.append(f"{rid}: no workflow {evidence['workflow']}")
        elif kind == "jobs":
            ci = CI.read_text(encoding="utf-8")
            for job in _l(evidence["jobs"]):
                # A matrix job's name carries its platform; ci.yml does not.
                name = re.sub(r" \((ubuntu|windows|macos)-latest\)$", "", str(job))
                if f"name: {name}\n" not in ci:
                    problems.append(f"{rid}: no CI job {job}")
        elif kind == "boundary-rules":
            rules = (REPO_ROOT / "architecture.toml").read_text(encoding="utf-8")
            for rule in _l(evidence["rules"]):
                if f'id = "{rule}-' not in rules:
                    problems.append(f"{rid}: no boundary rule {rule}")
        else:
            problems.append(f"{rid}: an unknown kind of evidence {kind!r}")
        for control in _l(row.get("mutation_control")):
            campaign, _, mutant = str(control).partition(": ")
            if mutant not in tables.get(campaign, set()):
                problems.append(f"{rid}: no mutant {control!r}")
        run = row.get("run")
        if status == "VERIFIED":
            if not isinstance(run, dict) or not re.fullmatch(
                r"[0-9a-f]{40}", str(run.get("commit"))
            ):
                problems.append(f"{rid}: VERIFIED with no hosted run and commit")
            if not row.get("observed") or not row.get("provenance"):
                problems.append(f"{rid}: VERIFIED with nothing observed")
            if kind == "attributed-case" and not _d(row.get("artifact")).get("digest"):
                problems.append(f"{rid}: VERIFIED with no artifact digest")
        elif not row.get("gap"):
            problems.append(f"{rid}: {status} with no gap named")
    return problems


def test_the_matrix_names_a_real_producer_for_every_row() -> None:
    assert matrix_problems(_matrix()) == []


def test_every_finding_and_invariant_has_an_evidence_contract() -> None:
    rows = _rows(_matrix())
    for finding in FINDINGS:
        assert [r for r in rows if r["finding"] == finding], finding
    invariants = " ".join(str(r["invariant"]) for r in rows)
    for n in range(1, 15):
        assert re.search(rf"\bEG-{n}\b", invariants), f"EG-{n}"
    for n in range(1, 13):
        assert re.search(rf"\bT-{n}\b", invariants), f"T-{n}"
    # Every case Phase 1 added to the attributed inventory is a row: F-19's
    # two, F-17's twenty-one and F-01's seven.
    pinned = {
        name: {
            tuple(line.split()[:2])
            for line in (REPO_ROOT / "tests" / "architecture" / name)
            .read_text(encoding="utf-8")
            .splitlines()
            if line.strip() and not line.startswith("#")
        }
        for name in (
            "m5e_cases_before_f17.txt",
            "m5e_cases_before_f01.txt",
            "m5e_cases_before_f18.txt",
        )
    }
    added = (pinned["m5e_cases_before_f01.txt"] - pinned["m5e_cases_before_f17.txt"]) | (
        pinned["m5e_cases_before_f18.txt"] - pinned["m5e_cases_before_f01.txt"]
    )
    listed = {
        (str(_d(r["evidence"])["suite"]), str(_d(r["evidence"])["case"]))
        for r in rows
        if _d(r["evidence"])["kind"] == "attributed-case"
    }
    assert len(added) == 28 and added <= listed
    assert ("sandbox-authority-egress", "grant-constrained-https-not-destinations") in listed
    assert ("sandbox-authority-egress", "constrained-grant-name-not-granted") in listed


def test_every_campaign_and_mutant_is_represented() -> None:
    rows = _rows(_matrix())
    campaigns = [
        str(_d(r["evidence"])["campaign"])
        for r in rows
        if _d(r["evidence"])["kind"] == "mutation-campaign"
    ]
    assert sorted(campaigns) == sorted(dw.C3_CAMPAIGNS)
    tables = {
        "AGENT_MUTATIONS",
        "EGRESS_POLICY_MUTATIONS",
        "TAINT_MUTATIONS",
        "OWNERSHIP_MUTATIONS",
    }
    assert {spec[3] for spec in dw.C3_CAMPAIGNS.values()} - {None} == tables
    # The gate's shards cover each table exactly once.
    for campaign, (_, _, _, table, shards) in dw.C3_CAMPAIGNS.items():
        if table is None:
            continue
        names = [m[0] for m in dw._c3_table(campaign)]
        covered = [
            m[0]
            for k in range(1, shards + 1)
            for i, m in enumerate(dw._c3_table(campaign))
            if i % shards == k - 1
        ]
        assert sorted(covered) == sorted(names) and len(set(names)) == len(names)
    assert ("a constrained network.https grant becomes a proxy destination") in {
        m[0] for m in dw.AGENT_MUTATIONS
    }


@pytest.mark.parametrize(
    ("change", "said"),
    [
        # In-process evidence is not real-OCI evidence.
        (
            lambda row: row["evidence"].update(suite="sandbox-workload-unit", case="x"),
            "is no attributed case",
        ),
        (lambda row: row.update(level="in-process"), "is real-oci, not in-process"),
        # A three-identity property is not a one-identity case.
        (
            lambda row: row.update(
                evidence={
                    "kind": "agent-cases",
                    "suite": "sandbox-agent",
                    "cases": ["a01-granted-https-reached"],
                },
                level="hosted-three-identity",
                identities=3,
            ),
            "is no three-identity agent case",
        ),
        (lambda row: row.update(status="PASSED"), "status 'PASSED'"),
        (lambda row: row.update(run=None), "VERIFIED with no hosted run"),
        (lambda row: row.update(finding="F-18"), "is not ADR-0060's finding"),
        (lambda row: row.update(mutation_control=["agent-mutations: no such mutant"]), "no mutant"),
        (lambda row: row.update(status="NOT VERIFIED", gap=""), "with no gap named"),
    ],
)
def test_a_row_that_misstates_its_producer_is_found(
    change: Callable[[dict[str, object]], None], said: str
) -> None:
    matrix = copy.deepcopy(_matrix())
    row = next(r for r in _rows(matrix) if r["id"] == "F-19-1")
    change(row)
    assert any(said in problem for problem in matrix_problems(matrix)), matrix_problems(matrix)


@pytest.mark.parametrize(
    "change",
    [
        # Another workflow's run, however green, is not the C3 gate's.
        lambda row: row.update(run={**row["run"], "workflow": ".github/workflows/ci.yml"}),
        # A run that names no passed gate.
        lambda row: row.update(provenance="the developer's machine: 12 of 12 killed"),
        lambda row: row.update(run=None),
    ],
)
def test_a_campaign_is_verified_only_by_the_c3_gates_own_run(
    change: Callable[[dict[str, object]], None],
) -> None:
    matrix = copy.deepcopy(_matrix())
    row = next(r for r in _rows(matrix) if r["id"] == "F-19-5")
    assert row["status"] == "VERIFIED"
    change(row)
    assert any("only by a passed C3 gate" in p for p in matrix_problems(matrix))


def test_no_adr_of_phase_1_is_accepted_without_the_owners_record() -> None:
    """ADR acceptance is the owner's separate decision: a status change here
    must come with the matrix and the report saying so, never alone."""
    matrix = _matrix()
    # ADR-0063 (F-18) was accepted on 2026-11-24; the other three stay
    # Proposed. Every status is pinned: a change needs this, the matrix and
    # the report together.
    statuses = {"0060": "Proposed", "0061": "Proposed", "0062": "Proposed", "0063": "Accepted"}
    assert matrix["adr_status"] == statuses
    for number, status in statuses.items():
        assert dw.adr_status(REPO_ROOT, number) == status, number
    acceptance = {
        "F-01": "PENDING (Proposed)",
        "F-17": "PENDING (Proposed)",
        "F-18": "ACCEPTED 2026-11-24",
        "F-19": "PENDING (Proposed)",
    }
    milestones = _d(matrix["milestones"])
    assert sorted(milestones) == sorted(acceptance)
    for finding, milestone in milestones.items():
        assert _d(milestone)["adr_acceptance"] == acceptance[finding], finding
    report = REPORT.read_text(encoding="utf-8")
    assert "ADR ACCEPTANCE PENDING" in report and "Proposed" in report
    assert "ADR-0063 (F-18) was\naccepted on 2026-11-24" in report


def test_the_report_names_every_row_and_what_is_pending() -> None:
    report = REPORT.read_text(encoding="utf-8")
    for row in _rows(_matrix()):
        assert f"`{row['id']}`" in report, row["id"]
    for marker in (
        "IMPLEMENTATION COMPLETE",
        "HOSTED EVIDENCE VERIFIED",
        "HOSTED EVIDENCE PENDING",
        "ADR ACCEPTANCE PENDING",
        "43640168802",
        "43648487347",
        "c3-evidence.yml",
    ):
        assert marker in report, marker


# --- the mutation harness -----------------------------------------------------------------

TARGET = "src/guard.rs"
GUARD = "    if !allowed { return Err(Refused); }\n"
MUTATION = ("the guard is removed", TARGET, GUARD, "    let _ = allowed;\n")


class Fake:
    """`cargo`, faked: the build and each stage's answer, unmutated and mutated."""

    def __init__(self, root: Path, **answers: dw.SuiteRun) -> None:
        self.root = root
        self.answers = answers
        self.calls: list[tuple[str, ...]] = []

    def __call__(self, *command: str) -> dw.SuiteRun:
        self.calls.append(command)
        mutated = GUARD not in (self.root / TARGET).read_text(encoding="utf-8")
        stage = "build" if "--no-run" in command else command[-1]
        key = f"{stage}_{'mutated' if mutated else 'clean'}"
        default = dw.SuiteRun(0, ("unit::one", "unit::two"), (), 2, 0.1)
        return self.answers.get(key, default)


@pytest.fixture
def harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    # LF, as the repository's sources are (.gitattributes), on every platform.
    (root / TARGET).write_text("fn check() {\n" + GUARD + "}\n", encoding="utf-8", newline="\n")
    monkeypatch.setattr(dw, "ROOT", root)
    stages = (dw.MutationStage("unit", ("cargo", "test", "unit")),)
    monkeypatch.setattr(dw, "_c3_stages", lambda _campaign: stages)
    return root


def _review(root: Path, tests: Fake, **environ: str) -> dict[str, object]:
    return dw.mutation_review(
        "taint-mutations", (MUTATION,), environ=environ, root=root / "records", tests=tests
    )


def _kept(root: Path, shard: str = "1of1") -> dict[str, object]:
    path = root / "records" / f"taint-mutations-{shard}" / "record.json"
    return _d(json.loads(path.read_text(encoding="utf-8")))


def _mutant(root: Path) -> dict[str, object]:
    return _d(_l(_kept(root)["mutants"])[0])


def test_a_mutant_a_named_test_catches_is_killed_and_the_file_restored(harness: Path) -> None:
    before = (harness / TARGET).read_bytes()
    failed = dw.SuiteRun(101, ("unit::one",), ("guard::tests::refuses",), 2, 0.1)
    record = _review(harness, Fake(harness, unit_mutated=failed))
    assert record["result"] == "PASS"
    mutant = _mutant(harness)
    assert (mutant["outcome"], mutant["stage"]) == ("KILLED", "unit")
    assert mutant["failed_tests"] == ["guard::tests::refuses"]
    assert mutant["applied"] is True and mutant["restored"] is True
    assert mutant["before_sha256"] == hashlib.sha256(before).hexdigest() != mutant["mutated_sha256"]
    assert (harness / TARGET).read_bytes() == before
    baseline = _d(_kept(harness)["baseline"])
    assert baseline["result"] == "PASS"
    assert _d(_l(baseline["stages"])[0])["passed"] == ["unit::one", "unit::two"]


@pytest.mark.parametrize(
    ("answers", "outcome"),
    [
        # Every stage passed: the mutant survived.
        ({}, "SURVIVED"),
        # A mutant that does not build is not caught by a test.
        ({"build_mutated": dw.SuiteRun(101, (), (), 0, 1.0)}, "COMPILE_ERROR"),
        # A command that failed with no failing test is not a detection.
        ({"unit_mutated": dw.SuiteRun(101, (), (), 0, 1.0)}, "ERROR"),
        # A selection that ran nothing caught nothing.
        ({"unit_mutated": dw.SuiteRun(0, (), (), 0, 1.0)}, "NO_TESTS"),
        # Stopped at its limit is no verdict.
        ({"unit_mutated": dw.SuiteRun(None, (), (), 0, 2700.0)}, "TIMEOUT"),
        ({"build_mutated": dw.SuiteRun(None, (), (), 0, 2700.0)}, "TIMEOUT"),
    ],
)
def test_only_a_named_failure_kills_and_anything_else_fails_with_its_record(
    harness: Path, answers: dict[str, dw.SuiteRun], outcome: str
) -> None:
    before = (harness / TARGET).read_bytes()
    with pytest.raises(dw.TaskError, match=f"not killed: the guard is removed {outcome}"):
        _review(harness, Fake(harness, **answers))
    record = _kept(harness)
    assert record["result"] == "FAIL" and outcome in str(record["reason"])
    assert _mutant(harness)["outcome"] == outcome
    assert (harness / TARGET).read_bytes() == before


def test_an_evidence_task_kills_by_refusing_and_is_blocked_by_not_exercised(
    harness: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    said: list[str] = []

    def evidence() -> None:
        if GUARD not in (harness / TARGET).read_text(encoding="utf-8") and said:
            raise dw.TaskError(said[0])

    stages = (
        dw.MutationStage("unit", ("cargo", "test", "unit")),
        dw.MutationStage("evidence", evidence=evidence),
    )
    monkeypatch.setattr(dw, "_c3_stages", lambda _campaign: stages)
    said.append("1 sandbox evidence case(s) refused: tunnel carried")
    assert _review(harness, Fake(harness))["result"] == "PASS"
    assert (_mutant(harness)["outcome"], _mutant(harness)["stage"]) == ("KILLED", "evidence")
    said[0] = "NOT EXERCISED: no OCI runtime answers"
    with pytest.raises(dw.TaskError, match="BLOCKED"):
        _review(harness, Fake(harness))
    assert _mutant(harness)["outcome"] == "BLOCKED"


def test_a_baseline_that_fails_judges_no_mutant(harness: Path) -> None:
    for answers in (
        {"build_clean": dw.SuiteRun(101, (), (), 0, 1.0)},
        {"unit_clean": dw.SuiteRun(101, (), ("unit::flaky",), 1, 1.0)},
        # A selection that runs nothing unmutated would never catch anything.
        {"unit_clean": dw.SuiteRun(0, (), (), 0, 1.0)},
    ):
        tests = Fake(harness, **answers)
        with pytest.raises(dw.TaskError, match="BLOCKED: taint-mutations: the unmutated baseline"):
            _review(harness, tests)
        record = _kept(harness)
        assert record["result"] == "BLOCKED" and record["mutants"] == []
        assert GUARD in (harness / TARGET).read_text(encoding="utf-8")


def test_a_mutation_whose_target_moved_runs_nothing(harness: Path) -> None:
    moved = ("the guard is removed", TARGET, "no such line\n", "x\n")
    tests = Fake(harness)
    with pytest.raises(dw.TaskError, match=r"not in src/guard\.rs exactly once"):
        dw.mutation_review("taint-mutations", (moved,), environ={}, root=harness, tests=tests)
    assert tests.calls == [] and not (harness / "taint-mutations-1of1").exists()


def test_a_target_is_found_in_the_bytes_the_mutant_is_made_from(harness: Path) -> None:
    """A CRLF copy of the source holds no LF target: refused before anything
    runs, never applied as a no-op and misreported."""
    crlf = ("fn check() {\n" + GUARD + "}\n").replace("\n", "\r\n").encode("utf-8")
    (harness / TARGET).write_bytes(crlf)
    tests = Fake(harness)
    with pytest.raises(dw.TaskError, match="exactly once"):
        _review(harness, tests)
    assert tests.calls == [] and (harness / TARGET).read_bytes() == crlf


def test_a_shard_judges_its_share_and_a_bad_shard_is_refused(harness: Path) -> None:
    second = ("a second guard", TARGET, "fn check() {\n", "fn check() { let _ = 0;\n")
    failed = dw.SuiteRun(101, (), ("guard::tests::refuses",), 1, 0.1)

    class Both(Fake):
        def __call__(self, *command: str) -> dw.SuiteRun:
            self.calls.append(command)
            text = (self.root / TARGET).read_text(encoding="utf-8")
            clean = GUARD in text and text.startswith("fn check() {\n")
            if "--no-run" in command or clean:
                return dw.SuiteRun(0, ("unit::one",), (), 1, 0.1)
            return failed

    record = dw.mutation_review(
        "taint-mutations",
        (MUTATION, second),
        environ={"DW_MUTATION_SHARD": "2/2"},
        root=harness / "records",
        tests=Both(harness),
    )
    assert record["inventory"] == ["a second guard"] and record["shard"] == "2/2"
    for bad in ("0/2", "3/2", "1", "a/b", "1/100"):
        with pytest.raises(dw.TaskError, match="is not k/n"):
            dw.mutation_review(
                "taint-mutations",
                (MUTATION,),
                environ={"DW_MUTATION_SHARD": bad},
                tests=Fake(harness),
            )


def test_the_record_is_local_unless_the_run_is_hosted(harness: Path) -> None:
    failed = dw.SuiteRun(101, (), ("guard::tests::refuses",), 1, 0.1)
    _review(harness, Fake(harness, unit_mutated=failed))
    provenance = _d(_kept(harness)["provenance"])
    assert provenance["hosted"] is False and provenance["run_id"] is None
    _review(harness, Fake(harness, unit_mutated=failed), **{**HOSTED, "GITHUB_JOB": "mutations"})
    provenance = _d(_kept(harness)["provenance"])
    assert (provenance["hosted"], provenance["run_id"], provenance["sha"]) == (True, RUN_ID, SHA)


def test_the_four_reviews_run_through_the_harness() -> None:
    import inspect

    for task, campaign, table in (
        (dw.task_sandbox_agent_mutations, "agent-mutations", "AGENT_MUTATIONS"),
        (
            dw.task_sandbox_egress_policy_mutations,
            "egress-policy-mutations",
            "EGRESS_POLICY_MUTATIONS",
        ),
        (dw.task_sandbox_taint_mutations, "taint-mutations", "TAINT_MUTATIONS"),
        (dw.task_authority_ownership_mutations, "ownership-mutations", "OWNERSHIP_MUTATIONS"),
    ):
        source = inspect.getsource(task)
        assert f'mutation_review("{campaign}", {table})' in source, task.__name__
        assert dw.TASKS[dw.C3_CAMPAIGNS[campaign][2]] is task
    # The agent review's evidence stage is the one-identity half: its
    # three-identity half is the hosted job's, never a kill here.
    stages = dw._c3_stages("agent-mutations")
    assert [s.name for s in stages][-1] == "agent-evidence-one-identity"
    for campaign in (
        "agent-mutations",
        "egress-policy-mutations",
        "taint-mutations",
        "ownership-mutations",
    ):
        selections = [s for s in dw._c3_stages(campaign) if s.evidence is None]
        assert selections and all(
            s.command[:3] == ("cargo", "test", "--locked") for s in selections
        )


# --- the C3 gate --------------------------------------------------------------------------

FOREIGN_OUTPUT = "\n".join(
    [
        "running 3 tests",
        *(
            f"{dw.EVIDENCE_PREFIX}"
            + json.dumps({"suite": "peer", "case": case, "contained": True, "audited": True})
            for case in dw.FOREIGN_CASES
        ),
        "test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out",
        "",
    ]
)


def _stage_rows(campaign: str) -> list[dict[str, object]]:
    rows: list[dict[str, object]] = []
    for stage in dw._c3_stages(campaign):
        tests = stage.evidence is None
        rows.append(
            {
                "stage": stage.name,
                "kind": "tests" if tests else "evidence",
                "command": list(stage.command),
                "exit": 0,
                "tests_run": 3 if tests else None,
                "passed": ["a::one", "a::two", "a::three"] if tests else [],
                "failed": [],
                "detail": None,
                "seconds": 1.0,
                "ok": True,
            }
        )
    return rows


def _record(
    campaign: str, k: int, n: int, run_id: str = RUN_ID, sha: str = SHA
) -> dict[str, object]:
    finding, adr, task, table, _ = dw.C3_CAMPAIGNS[campaign]
    record: dict[str, object] = {
        "schema": dw.C3_RECORD_SCHEMA,
        "version": dw.C3_RECORD_VERSION,
        "kind": "mutation" if table else "cross-uid",
        "campaign": campaign,
        "finding": finding,
        "adr": adr,
        "task": task,
        "shard": f"{k}/{n}",
        "provenance": {
            "hosted": True,
            "run_id": run_id,
            "run_attempt": "1",
            "sha": sha,
            "ref": "refs/heads/main",
            "job": "mutations",
            "runner": {
                "environment": "github-hosted",
                "os": "Linux",
                "image": "ubuntu26",
                "image_version": "x",
            },
        },
        "started_at": "2026-11-15T00:00:00Z",
        "finished_at": "2026-11-15T01:00:00Z",
        "result": "PASS",
        "reason": None,
    }
    if table is None:
        record.update(
            identities={"user": "nobody", "runner_uid": 1001, "peer_uid": 65534},
            output={
                "file": "output.txt",
                "sha256": hashlib.sha256(FOREIGN_OUTPUT.encode()).hexdigest(),
                "bytes": len(FOREIGN_OUTPUT.encode()),
            },
            cases=list(dw.FOREIGN_CASES),
            hostile={"exit": 0, "tests_run": 9, "passed": [dw.C3_HOSTILE_FD_TEST], "failed": []},
        )
        return record
    names = [m[0] for i, m in enumerate(dw._c3_table(campaign)) if i % n == k - 1]
    first = dw._c3_stages(campaign)[0].name
    record.update(
        inventory=names,
        baseline={"build_exit": 0, "stages": _stage_rows(campaign), "result": "PASS"},
        mutants=[
            {
                "name": name,
                "file": "crates/x.rs",
                "before_sha256": "a" * 64,
                "mutated_sha256": "b" * 64,
                "applied": True,
                "outcome": "KILLED",
                "stage": first,
                "signature": "1 test(s) failed: x::refuses",
                "failed_tests": ["x::refuses"],
                "restored": True,
                "seconds": 60.0,
            }
            for name in names
        ],
    )
    return record


def _gate_root(tmp_path: Path, **records: dict[str, object]) -> Path:
    """This run's every record, as the download action lays them out; any
    `records` given replace the one of their artifact."""
    root = tmp_path / "c3-gate"
    for artifact, (campaign, k, n) in dw.c3_expected_records().items():
        directory = root / artifact
        directory.mkdir(parents=True)
        record = records.get(artifact.replace("-", "_"), _record(campaign, k, n))
        (directory / "record.json").write_text(json.dumps(record), encoding="utf-8")
        if campaign == "cross-uid-ownership":
            (directory / "output.txt").write_text(FOREIGN_OUTPUT, encoding="utf-8", newline="\n")
    return root


def test_the_gate_accepts_every_record_of_this_run(tmp_path: Path) -> None:
    lines = dw.c3_gate_verdict(GATE_ENV, _gate_root(tmp_path))
    assert lines[0].startswith(f"C3 gate: COMPLETE: {len(dw.c3_expected_records())} record(s)")
    assert any("agent-mutations (F-19, ADR-0060" in line for line in lines)
    assert any("cross-uid-ownership (F-18, ADR-0063" in line for line in lines)


AGENT_1 = "c3-evidence-agent-mutations-1of2"
CROSS = "c3-evidence-cross-uid-ownership-1of1"


def _broken(tmp_path: Path, artifact: str, change: Callable[[dict[str, object]], None]) -> str:
    campaign, k, n = dw.c3_expected_records()[artifact]
    record = _record(campaign, k, n)
    change(record)
    root = _gate_root(tmp_path, **{artifact.replace("-", "_"): record})
    with pytest.raises(dw.TaskError) as refused:
        dw.c3_gate_verdict(GATE_ENV, root)
    return str(refused.value)


def _first_mutant(record: dict[str, object]) -> dict[str, object]:
    return _d(_l(record["mutants"])[0])


@pytest.mark.parametrize(
    ("artifact", "change", "said"),
    [
        # A surviving or otherwise unkilled mutant.
        (AGENT_1, lambda r: _first_mutant(r).update(outcome="SURVIVED"), "SURVIVED, not KILLED"),
        (AGENT_1, lambda r: _first_mutant(r).update(outcome="BLOCKED"), "BLOCKED, not KILLED"),
        (AGENT_1, lambda r: _first_mutant(r).update(outcome="COMPILE_ERROR"), "not KILLED"),
        (AGENT_1, lambda r: _first_mutant(r).update(outcome="NO_TESTS"), "not KILLED"),
        # Killed by a test selection with no failing test named.
        (AGENT_1, lambda r: _first_mutant(r).update(failed_tests=[]), "no failing test named"),
        (AGENT_1, lambda r: _first_mutant(r).update(stage="elsewhere"), "killed by no stage"),
        (AGENT_1, lambda r: _first_mutant(r).update(restored=False), "not restored"),
        (
            AGENT_1,
            lambda r: _first_mutant(r).update(mutated_sha256="a" * 64),
            "do not show a change",
        ),
        # A failed campaign keeps its record, and is never a pass.
        (AGENT_1, lambda r: r.update(result="FAIL", reason="1 survived"), "FAIL: 1 survived"),
        (AGENT_1, lambda r: r.update(result="RUNNING"), "RUNNING"),
        # A baseline that ran no test, or failed, proves nothing.
        (
            AGENT_1,
            lambda r: _d(_l(_d(r["baseline"])["stages"])[0]).update(tests_run=0),
            "ran no test",
        ),
        (AGENT_1, lambda r: _d(r["baseline"]).update(result="BLOCKED"), "baseline did not pass"),
        (AGENT_1, lambda r: _l(_d(r["baseline"])["stages"]).pop(), "not the stages"),
        # Case identity drift: the inventory is exactly its table's shard.
        (AGENT_1, lambda r: _l(r["inventory"]).reverse(), "not its table's shard"),
        (
            AGENT_1,
            lambda r: _first_mutant(r).update(name="a renamed guard"),
            "not exactly its inventory",
        ),
        (CROSS, lambda r: r.update(cases=list(dw.FOREIGN_CASES)[:-1]), "its cases are not exactly"),
        # Wrong provenance: another run, commit, a later attempt, not hosted.
        (AGENT_1, lambda r: _d(r["provenance"]).update(run_id="43640168802"), "not this run's"),
        (AGENT_1, lambda r: _d(r["provenance"]).update(sha=OTHER_SHA), "not this run's"),
        (AGENT_1, lambda r: _d(r["provenance"]).update(run_attempt="2"), "not this run's"),
        (AGENT_1, lambda r: _d(r["provenance"]).update(hosted=False), "not from a disposable"),
        (
            AGENT_1,
            lambda r: _d(_d(r["provenance"])["runner"]).update(environment="self-hosted"),
            "runner is not GitHub-hosted",
        ),
        # Corrupt or reshaped records.
        (AGENT_1, lambda r: r.update(extra=True), "does not have exactly"),
        (AGENT_1, lambda r: r.update(version=2), "its record is"),
        (AGENT_1, lambda r: r.update(campaign="taint-mutations"), "its record is"),
        # One identity is not two; root is outside the threat model.
        (CROSS, lambda r: _d(r["identities"]).update(peer_uid=1001), "not two ordinary, distinct"),
        (CROSS, lambda r: _d(r["identities"]).update(peer_uid=0), "not two ordinary, distinct"),
        (
            CROSS,
            lambda r: _d(r["output"]).update(sha256="0" * 64),
            "not the output the record names",
        ),
        (CROSS, lambda r: _d(r["hostile"]).update(passed=[]), "did not pass"),
    ],
)
def test_the_gate_refuses_a_record_that_proves_less(
    tmp_path: Path, artifact: str, change: Callable[[dict[str, object]], None], said: str
) -> None:
    assert said in _broken(tmp_path, artifact, change)


def test_the_gate_refuses_missing_corrupt_and_foreign_records(tmp_path: Path) -> None:
    root = _gate_root(tmp_path / "missing")
    shutil.rmtree(root / AGENT_1)
    with pytest.raises(dw.TaskError, match="missing record"):
        dw.c3_gate_verdict(GATE_ENV, root)
    root = _gate_root(tmp_path / "file")
    (root / CROSS / "output.txt").unlink()
    with pytest.raises(dw.TaskError, match=r"holds \['record.json'\], not exactly"):
        dw.c3_gate_verdict(GATE_ENV, root)
    root = _gate_root(tmp_path / "json")
    (root / AGENT_1 / "record.json").write_text('{"schema": 1, "schema": 2}', encoding="utf-8")
    with pytest.raises(dw.TaskError, match=r"record\.json is unreadable"):
        dw.c3_gate_verdict(GATE_ENV, root)
    root = _gate_root(tmp_path / "extra")
    (root / "c3-evidence-agent-mutations-3of3").mkdir()
    with pytest.raises(dw.TaskError, match="no campaign of C3 makes"):
        dw.c3_gate_verdict(GATE_ENV, root)
    root = _gate_root(tmp_path / "stray")
    (root / AGENT_1 / "notes.txt").write_text("x", encoding="utf-8")
    with pytest.raises(dw.TaskError, match="not exactly"):
        dw.c3_gate_verdict(GATE_ENV, root)


def test_an_archived_run_never_satisfies_the_gate(tmp_path: Path) -> None:
    """Every record of an earlier run -- CI #172's commit, an archive's
    restore -- is refused by a later run's gate, whole."""
    root = tmp_path / "c3-gate"
    for artifact, (campaign, k, n) in dw.c3_expected_records().items():
        (root / artifact).mkdir(parents=True)
        old = _record(campaign, k, n, run_id="43640168802", sha=OTHER_SHA)
        (root / artifact / "record.json").write_text(json.dumps(old), encoding="utf-8")
        if campaign == "cross-uid-ownership":
            (root / artifact / "output.txt").write_text(FOREIGN_OUTPUT, encoding="utf-8")
    with pytest.raises(dw.TaskError) as refused:
        dw.c3_gate_verdict(GATE_ENV, root)
    assert str(refused.value).count("not this run's") == len(dw.c3_expected_records())


def test_the_gate_runs_only_hosted_in_its_own_job(tmp_path: Path) -> None:
    root = _gate_root(tmp_path)
    with pytest.raises(dw.TaskError, match="NOT EXERCISED"):
        dw.c3_gate_verdict({}, root)
    with pytest.raises(dw.TaskError, match="runs in the 'c3-gate' job"):
        dw.c3_gate_verdict({**HOSTED, "GITHUB_JOB": "m5e-gate"}, root)


# --- the workflow, and what it leaves alone -------------------------------------------------


def _workflow() -> str:
    return WORKFLOW.read_text(encoding="utf-8")


def test_the_workflow_runs_exactly_the_campaigns_by_hand_with_read_only_rights() -> None:
    text = _workflow()
    assert re.search(r"^on:\n  workflow_dispatch:\n\n", text, re.M)
    for trigger in ("push:", "pull_request", "schedule:", "workflow_run", "pull_request_target"):
        assert trigger not in text.split("\njobs:")[0].replace("never on a push", ""), trigger
    assert "permissions:\n  contents: read\n" in text and "write" not in text.split("\njobs:")[1]
    assert "secrets." not in text and "run-id:" not in text and "sudo" not in text
    matrix = re.findall(r"- \{ campaign: (\S+), task: (\S+), shard: (\d+), shards: (\d+) \}", text)
    listed = {f"c3-evidence-{c}-{k}of{n}": (c, int(k), int(n)) for c, _t, k, n in matrix}
    expected = {a: v for a, v in dw.c3_expected_records().items() if v[0] != "cross-uid-ownership"}
    assert listed == expected
    for campaign, task, _k, _n in matrix:
        assert dw.C3_CAMPAIGNS[campaign][2] == task
    assert "fail-fast: false" in text
    assert (
        "name: c3-evidence-${{ matrix.campaign }}-${{ matrix.shard }}of${{ matrix.shards }}" in text
    )
    assert (
        "path: target/c3-evidence/${{ matrix.campaign }}-${{ matrix.shard }}of${{ matrix.shards }}/"
        in text
    )
    assert "name: c3-evidence-cross-uid-ownership-1of1" in text and "DW_PEER_AS: nobody" in text
    # Records are kept whatever happened, and the gate judges whatever came.
    assert text.count("if: always()") == 3
    gate = text.split("  c3-gate:\n")[1]
    assert "needs: [mutations, cross-uid]" in gate and "pattern: c3-evidence-*" in gate
    assert "run: make c3-gate-check" in gate and "path: target/c3-gate/" in gate


def test_the_required_ci_and_its_m5_gate_are_unchanged() -> None:
    ci = CI.read_text(encoding="utf-8")
    assert "c3-evidence" not in ci and "c3-gate" not in ci
    needs = re.search(r"\n  ci:\n(?:.*\n)*?    needs: \[([^\]]*)\]", ci)
    assert needs is not None
    required = {name.strip() for name in needs.group(1).split(",")}
    assert {
        "m5e-gate",
        "sandbox-egress",
        "sandbox-agent",
        "sandbox-registry",
        "sandbox-hygiene",
        "authority-transport",
        "evals",
        "test",
        "architecture",
    } <= required
    assert "pattern: m5e-evidence-*" in ci and "run: make m5e-gate-check" in ci
    gate = re.search(r"\n  m5e-gate:\n(?:.*\n)*?    needs: \[([^\]]*)\]", ci)
    assert gate is not None
    assert set(dw.M5E_GATE_TASKS.values()) <= {name.strip() for name in gate.group(1).split(",")}
    assert "evidence_archive" not in _workflow()
