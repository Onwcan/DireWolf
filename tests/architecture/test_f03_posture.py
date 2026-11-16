"""F-03's effective posture stays complete and truthful (ADR-0065, Proposed).

**Every weakening switch has a record.** Each development or evidence
acknowledgement either daemon parses is named by that daemon's effective
posture: a new `--allow-*` switch fails this test until someone says which
control it reduces. The broker's switches are spelled once, as constants its
parser matches on; the authority's are its posture module's constants, and
they must be exactly the switches its parser accepts that weaken something.

**The report and the decision read the same facts.** The broker's per-hop
checks read the host before they consult an acknowledgement, so a hop the
facts would refuse is admitted *and reported*, never admitted unread; the
authority records its posture in `audit.log` once per start, after what it
attaches and before it serves. These orderings are held here, statically;
the unit and process suites hold the behaviour.

**One vocabulary, no score.** Both daemons spell the same five conditions, the
report document defines them, and neither summary carries a count of what
holds.

**Each guard has a mutant.** `make posture-mutations` weakens each guard in
turn with C3's judge, as F-02's review does; its table must match the source
exactly once per mutant. ADR-0065 is Proposed, and stays so here.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
BROKER = REPO_ROOT / "crates" / "dwkd-broker" / "src"
AUTHORITY = REPO_ROOT / "crates" / "dwkd-authority" / "src"
ADR = REPO_ROOT / "docs" / "adr" / "0065-f03-effective-posture-is-reported-and-recorded.md"
REPORT = REPO_ROOT / "docs" / "F03_EFFECTIVE_POSTURE.md"
CONDITIONS = ("ENFORCED", "REDUCED", "UNVERIFIED", "UNSUPPORTED", "NOT_APPLICABLE")

sys.path.insert(0, str(REPO_ROOT / "scripts"))
import dw  # noqa: E402  - imported after the path is extended


def _read(path: Path) -> str:
    return path.read_bytes().decode("utf-8")


def _broker_acknowledgements() -> dict[str, str]:
    """The broker's acknowledgement constants: name -> the flag."""
    found = re.findall(
        r'^pub\(crate\) const ([A-Z_]+): &str = "(--allow-[a-z-]+)";$',
        _read(BROKER / "config.rs"),
        re.MULTILINE,
    )
    return dict(found)


def test_every_broker_acknowledgement_is_parsed_once_and_reduces_a_named_control() -> None:
    config = _read(BROKER / "config.rs")
    acknowledgements = _broker_acknowledgements()
    assert sorted(acknowledgements.values()) == sorted(
        [
            "--allow-shared-authority-uid",
            "--allow-dumpable",
            "--allow-traceable-workers",
            "--allow-swappable-workers",
            "--allow-evidence-topology",
            "--allow-unverified-workspace",
            "--allow-evidence-egress",
            "--allow-evidence-trust",
        ]
    )
    parse = config[config.index("pub(crate) fn parse(") : config.index("#[cfg(test)]")]
    # The parser matches on the constants, and on no flag spelled again.
    assert not re.search(r'^\s*"--allow-[a-z-]+" =>', parse, re.MULTILINE)
    effective = _read(BROKER / "effective.rs") + _read(BROKER / "http" / "mod.rs")
    for name, flag in acknowledgements.items():
        assert re.search(rf"^\s*{name} => ", parse, re.MULTILINE), f"{flag} is not parsed"
        assert f"config::{name}" in effective, f"{flag} reduces no control in the posture"
    # Each is listed in the usage the operator reads.
    usage = _read(BROKER / "main.rs")
    for flag in acknowledgements.values():
        assert flag in usage, flag


def test_every_authority_weakening_switch_is_a_posture_constant() -> None:
    config = _read(AUTHORITY / "server" / "config.rs")
    parsed = set(re.findall(r'^\s*"(--allow-[a-z-]+)" =>', config, re.MULTILINE))
    # `--allow-uid` lists peers; it weakens nothing by itself (a peer with the
    # authority's own uid needs `--allow-authority-uid`).
    weakening = parsed - {"--allow-uid"}
    posture = _read(AUTHORITY / "posture.rs")
    constants = dict(re.findall(r'^pub const ([A-Z_]+): &str = "([^"]+)";$', posture, re.MULTILINE))
    flags = {v for v in constants.values() if v.startswith("--allow-")}
    assert flags == weakening
    assert constants["UNVERIFIED_WORKSPACE_KEY"] == "[workspace] unverified_evidence"
    body = posture[posture.index("pub fn of_authority(") :]
    memory = posture[posture.index("fn memory(") : posture.index("fn broker(")]
    broker = posture[posture.index("fn broker(") : posture.index("pub fn of_authority(")]
    for name in constants:
        assert f"Some({name})" in memory + broker + body, f"{name} reduces no control"


def test_both_daemons_spell_one_vocabulary_and_neither_summary_scores() -> None:
    for path in (BROKER / "effective.rs", AUTHORITY / "posture.rs"):
        text = _read(path)
        spelled = re.findall(r'=> "([A-Z_]+)",', text[text.index("impl Condition") :])
        assert tuple(spelled[: len(CONDITIONS)]) == CONDITIONS, path
        summary = text[text.index('"posture_summary') :]
        summary = summary[: summary.index(")")]
        assert "ENFORCED" not in summary and "%" not in summary, path
        assert "reduced=" in summary and "unverified=" in summary and "unsupported=" in summary
    report = _read(REPORT)
    for condition in CONDITIONS:
        assert f"`{condition}`" in report, condition


def test_the_per_hop_checks_read_the_host_before_any_acknowledgement() -> None:
    http = _read(BROKER / "http" / "mod.rs")
    start = http[http.index("    pub(crate) fn admits_start(") :]
    start = start[: start.index("\n    }\n")]
    assert start.index("(self.startup)(binary)") < start.index(
        "self.traceable == TraceableWorkers::Permitted"
    )
    assert "(self.report)(" in start
    credential = http[http.index("    pub(crate) fn admits_credential(") :]
    credential = credential[: credential.index("\n    }\n")]
    assert credential.index("(self.swap)(pid)") < credential.index(
        "self.swappable == SwappableWorkers::Permitted"
    )
    assert "(self.report)(" in credential
    assert "report: report_acknowledged," in http


def test_the_broker_says_its_posture_before_it_decides_whether_to_serve() -> None:
    main = _read(BROKER / "main.rs")
    deployment = main[main.index("fn deployment(") :]
    deployment = deployment[: deployment.index("\n}\n")]
    assert deployment.index("effective::lines(") < deployment.index("admit(")
    assert "hardening::observed()" in deployment


def test_the_authority_records_its_posture_after_what_it_attaches_and_before_it_serves() -> None:
    server = _read(AUTHORITY / "server" / "mod.rs")
    start = server[server.index("fn start(") :]
    start = start[: start.index("\n}\n")]
    assert start.index("let workspace = sandbox::attach(") < start.index(
        "record_posture(&mut authority, config, authority_uid, workspace)?;"
    )
    # The start's success return; F-18 Phase 3.4 (ADR-0067) adds the approver
    # endpoint's place to the tuple after `report`.
    assert start.index("record_posture(") < start.index("Ok((place, authority, report")
    record = server[server.index("fn record_posture(") :]
    record = record[: record.index("\n}\n")]
    assert "hardening::observed()" in record
    assert ".record_posture(&controls)" in record
    run = server[server.index("fn run(config: &ServeConfig)") :]
    # The socket is bound only after the start -- which recorded the posture.
    assert run.index("start(config)?") < run.index("socket::bind(")
    sandbox = _read(AUTHORITY / "server" / "sandbox.rs")
    assert "Ok(Some(workspace))" in sandbox and "return Ok(None);" in sandbox
    audit = _read(AUTHORITY / "state" / "audit.rs")
    assert 'Self::AuthorityPosture => "authority.posture",' in audit
    assert "        Self::AuthorityPosture,\n    ];" in audit


def test_doctor_names_where_each_daemon_reports_and_never_says_nothing_exists() -> None:
    doctor = _read(REPO_ROOT / "crates" / "direwolf-cli" / "src" / "doctor.rs")
    assert "no security mechanism is implemented" not in doctor
    assert "authority.posture" in doctor and "event=posture" in doctor
    assert "does not verify any security property" in doctor


def test_the_mutation_table_matches_the_source_once_per_mutant() -> None:
    names = [m[0] for m in dw.POSTURE_MUTATIONS]
    assert len(names) == len(set(names))
    labels = [name.split(":")[0] for name in names]
    assert labels == [f"P{i}" for i in range(1, len(names) + 1)]
    for what, rel, old, new in dw.POSTURE_MUTATIONS:
        text = (REPO_ROOT / rel).read_bytes().decode("utf-8")
        assert text.count(old) == 1, what
        assert old != new, what
    # Each daemon's posture, its per-hop checks, its read-back and the
    # authority's record each have at least one mutant.
    files = {m[1] for m in dw.POSTURE_MUTATIONS}
    assert files == {
        "crates/dwkd-broker/src/effective.rs",
        "crates/dwkd-broker/src/posture.rs",
        "crates/dwkd-broker/src/http/mod.rs",
        "crates/dwkd-broker/src/main.rs",
        "crates/dwkd-broker/src/hardening.rs",
        "crates/dwkd-authority/src/posture.rs",
        "crates/dwkd-authority/src/server/mod.rs",
        "crates/dwkd-authority/src/server/hardening.rs",
        "crates/dwkd-authority/src/state/mod.rs",
    }
    assert dw.TASKS["posture-mutations"] is dw.task_posture_mutations
    stages = dw._posture_stages()
    assert [s.name for s in stages] == [
        "broker-unit",
        "authority-unit",
        "authority-process",
        "broker-process",
    ]
    assert all(s.evidence is None for s in stages)
    # Kept apart from C3's closed campaign registry and from F-02's record.
    assert "posture" not in dw.C3_CAMPAIGNS
    assert dw.POSTURE_EVIDENCE_DIR != dw.CONCURRENCY_EVIDENCE_DIR


def test_the_broker_evidence_requires_the_real_broker_posture_case() -> None:
    assert ("private-protocol", "effective-posture") in dw.BROKER_CASES
    protocol = _read(REPO_ROOT / "crates" / "dwkd-broker" / "tests" / "private_protocol.rs")
    assert 'evidence("effective-posture", ' in protocol


def test_adr_0065_is_proposed_and_records_its_evidence() -> None:
    text = _read(ADR)
    assert text.startswith("# ADR-0065:")
    assert re.search(r"^\*\*Status:\*\* Proposed ", text, re.MULTILINE)
    for evidence in (
        "effective_tests.rs",
        "transport_server.rs",
        "private_protocol.rs",
        "posture-mutations",
    ):
        assert evidence in text, evidence


# --- the review's machinery, driven with a stand-in for cargo ----------------

TARGET = "src/posture.rs"
GUARD = "    if acknowledged { return Reduced; }\n"
MUTATION = ("P0: the guard is removed", TARGET, GUARD, "")


class Fake:
    """`cargo`, faked: the build and each stage's answer, unmutated and mutated."""

    def __init__(self, root: Path, **answers: dw.SuiteRun) -> None:
        self.root = root
        self.answers = answers

    def __call__(self, *command: str) -> dw.SuiteRun:
        mutated = GUARD not in (self.root / TARGET).read_text(encoding="utf-8")
        stage = "build" if "--no-run" in command else command[-1]
        key = f"{stage}_{'mutated' if mutated else 'clean'}"
        default = dw.SuiteRun(0, ("unit::one",), (), 1, 0.1)
        return self.answers.get(key, default)


@pytest.fixture
def harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    (root / TARGET).write_text("fn check() {\n" + GUARD + "}\n", encoding="utf-8", newline="\n")
    monkeypatch.setattr(dw, "ROOT", root)
    stages = (dw.MutationStage("unit", ("cargo", "test", "unit")),)
    monkeypatch.setattr(dw, "_posture_stages", lambda: stages)
    return root


def _kept(root: Path) -> dict[str, object]:
    record = json.loads((root / "record" / "record.json").read_text(encoding="utf-8"))
    assert isinstance(record, dict)
    return record


def test_a_named_failure_kills_and_the_file_is_restored(harness: Path) -> None:
    before = (harness / TARGET).read_bytes()
    failed = dw.SuiteRun(101, (), ("effective::tests::reduced",), 1, 0.1)
    record = dw.posture_review(
        (MUTATION,), root=harness / "record", tests=Fake(harness, unit_mutated=failed)
    )
    assert record["result"] == "PASS"
    kept = _kept(harness)
    assert kept["schema"] == "direwolf.f03.mutation-review"
    assert (kept["finding"], kept["adr"], kept["task"]) == ("F-03", "0065", "posture-mutations")
    mutants = kept["mutants"]
    assert isinstance(mutants, list) and len(mutants) == 1
    mutant = mutants[0]
    assert isinstance(mutant, dict)
    assert (mutant["outcome"], mutant["stage"]) == ("KILLED", "unit")
    assert mutant["applied"] is True and mutant["restored"] is True
    assert mutant["before_sha256"] == hashlib.sha256(before).hexdigest()
    assert (harness / TARGET).read_bytes() == before


@pytest.mark.parametrize(
    ("answers", "outcome"),
    [
        ({}, "SURVIVED"),
        ({"build_mutated": dw.SuiteRun(101, (), (), 0, 1.0)}, "COMPILE_ERROR"),
        ({"unit_mutated": dw.SuiteRun(101, (), (), 0, 1.0)}, "ERROR"),
        ({"unit_mutated": dw.SuiteRun(0, (), (), 0, 1.0)}, "NO_TESTS"),
        ({"unit_mutated": dw.SuiteRun(None, (), (), 0, 2700.0)}, "TIMEOUT"),
    ],
)
def test_anything_but_a_named_failure_fails_the_review(
    harness: Path, answers: dict[str, dw.SuiteRun], outcome: str
) -> None:
    before = (harness / TARGET).read_bytes()
    with pytest.raises(dw.TaskError, match=f"F-03 not killed: P0: the guard is removed {outcome}"):
        dw.posture_review((MUTATION,), root=harness / "record", tests=Fake(harness, **answers))
    assert _kept(harness)["result"] == "FAIL"
    assert (harness / TARGET).read_bytes() == before


def test_a_failing_baseline_judges_no_mutant(harness: Path) -> None:
    broken = dw.SuiteRun(101, (), ("effective::tests::reduced",), 1, 0.1)
    with pytest.raises(dw.TaskError, match="BLOCKED: posture-mutations"):
        dw.posture_review(
            (MUTATION,), root=harness / "record", tests=Fake(harness, unit_clean=broken)
        )
    kept = _kept(harness)
    assert kept["result"] == "BLOCKED" and kept["mutants"] == []


def test_a_stale_target_stops_the_review_before_anything_is_built(harness: Path) -> None:
    stale = ("P0: a stale target", TARGET, "    if gone {}\n", "")
    with pytest.raises(dw.TaskError, match="exactly once"):
        dw.posture_review((stale,), root=harness / "record", tests=Fake(harness))
    assert not (harness / "record").exists()
