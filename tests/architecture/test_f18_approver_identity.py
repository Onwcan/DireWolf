"""F-18 Phase 3.4's approver identity boundary stays what it is (ADR-0067, Proposed).

**The approver is never the runtime.** The approver endpoint is a socket of
its own for the uids the operator names; none is a DWKP peer, the broker or
the authority, and no `serve` flag overrides that. It holds no approval
operation before M6: it reads, answers and dispatches nothing (TX065).

**The runtime's endpoint is unchanged.** TX061 and TX063 still cover the whole
server directory with no exemption, every runtime admission is `api`, and
`StandingGrantState` still has one variant.

**It builds where the server does not run.** The endpoint and its start-up
helpers are `#[cfg(unix)]`, as `start` is (CI #184's lesson).

**Each guard has a mutant.** `make approver-identity-mutations` weakens each
in turn with C3's judge; its table must match the source exactly once per
mutant. ADR-0067 is Proposed, and stays so here; so does ADR-0063.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
import tomllib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SERVER = REPO_ROOT / "crates" / "dwkd-authority" / "src" / "server"
ADR = REPO_ROOT / "docs" / "adr" / "0067-f18-approver-endpoint-identity-boundary.md"
ADR_0063 = (
    REPO_ROOT / "docs" / "adr" / "0063-principal-ownership-of-sessions-workspaces-and-profiles.md"
)
REPORT = REPO_ROOT / "docs" / "F18_APPROVER_IDENTITY.md"

sys.path.insert(0, str(REPO_ROOT / "scripts"))

import dw  # noqa: E402  - imported after the path is extended


def _read(path: Path) -> str:
    return path.read_bytes().decode("utf-8")


def _rule(rule_id: str) -> dict[str, object]:
    rules = tomllib.loads(_read(REPO_ROOT / "architecture.toml"))["text_rules"]
    found = [rule for rule in rules if rule["id"] == rule_id]
    assert len(found) == 1, rule_id
    rule = found[0]
    assert isinstance(rule, dict)
    return rule


def test_the_endpoint_and_its_start_helpers_build_only_where_start_does() -> None:
    server = _read(SERVER / "mod.rs")
    for item in ("mod approver;", "type Approver =", "fn approver_place("):
        at = server.index(item)
        before = server[:at].rstrip().splitlines()
        attributes = [line.strip() for line in before[-3:]]
        assert "#[cfg(unix)]" in attributes, f"{item} is not #[cfg(unix)]: {attributes}"


def test_the_runtime_endpoint_rules_still_cover_the_whole_server() -> None:
    for rule_id in (
        "TX061-the-runtime-endpoint-receives-no-descriptor",
        "TX063-the-runtime-endpoint-takes-its-subject-from-the-kernel",
    ):
        rule = _rule(rule_id)
        assert rule["paths"] == ["crates/dwkd-authority/src/server"], rule_id
        assert rule["exempt_paths"] == [], f"{rule_id} gained an exemption"
    tx062 = _rule("TX062-the-runtime-path-selects-no-origin-and-records-no-approval")
    assert tx062["paths"] == ["crates/dwkd-authority/src/state", "crates/dwkd-authority/src/server"]
    assert tx062["exempt_paths"] == []
    tx065 = _rule("TX065-the-approver-endpoint-holds-no-operation-before-m6")
    assert tx065["paths"] == ["crates/dwkd-authority/src/server/approver.rs"]
    assert tx065["exempt_paths"] == []


def test_the_endpoint_holds_no_operation() -> None:
    # TX065's statement, read off the module's code (its comments and its
    # tests aside); the module's own Rust test says the same.
    source = _read(SERVER / "approver.rs")
    code = source[: source.index("#[cfg(test)]")]
    lines = [line for line in code.splitlines() if not line.lstrip().startswith("//")]
    text = "\n".join(lines)
    assert "fn accept(" in text
    for token in (
        "std::io::Read",
        "std::io::Write",
        ".read(",
        ".write",
        "dispatch",
        ".connect(",
        "unix_uid",
        "AuthenticatedSubject",
        "CallerContext",
        "decode",
        "connection::",
    ):
        assert token not in text, f"the approver endpoint spells {token}"


def test_a_standing_grant_has_one_value_and_a_runtime_admission_one_origin() -> None:
    context = _read(REPO_ROOT / "crates" / "dwkd-authority" / "src" / "policy" / "context.rs")
    body = re.search(r"pub enum StandingGrantState \{(.*?)\n\}", context, re.S)
    assert body is not None
    variants = re.findall(r"^\s{4}([A-Z]\w*),", body.group(1), re.M)
    assert variants == ["Unavailable"], variants
    admission = _read(REPO_ROOT / "crates" / "dwkd-authority" / "src" / "state" / "admission.rs")
    assert admission.count("origin: Origin::") == 1
    assert admission.count("        origin: Origin::Api,\n") == 1


def test_no_serve_flag_lets_an_approver_share_an_identity() -> None:
    config = _read(SERVER / "config.rs")
    flags = set(re.findall(r'"(--approver[-a-z]*)"\s*=>', config))
    assert flags == {"--approver-socket", "--approver-uid"}, flags
    start = config.index("pub const SERVE_USAGE")
    usage = config[start : config.index('";', start)]
    usage_flags = set(re.findall(r"^\s+(--[a-z-]+)", usage, re.M))
    assert {"--approver-socket", "--approver-uid"} <= usage_flags
    overrides = {flag for flag in usage_flags if flag.startswith("--allow") and "approv" in flag}
    assert not overrides, overrides
    assert "never a DWKP peer's, the broker's or the authority's" in usage
    assert "no approval operation before M6" in usage


def test_adr_0067_is_proposed_and_adr_0063_is_not_silently_accepted() -> None:
    text = _read(ADR)
    assert text.startswith("# ADR-0067:")
    assert re.search(r"^\*\*Status:\*\* Proposed ", text, re.M)
    for evidence in (
        "transport_approver.rs",
        "approver-identity-mutations",
        "TX065",
        "DW_APPROVER_AS",
        "F18_APPROVER_IDENTITY.md",
    ):
        assert evidence in text, evidence
    assert re.search(r"^\*\*Status:\*\* Proposed ", _read(ADR_0063), re.M)
    index = _read(REPO_ROOT / "docs" / "adr" / "README.md")
    assert "[0067](0067-f18-approver-endpoint-identity-boundary.md)" in index
    report = _read(REPORT)
    for marker in (
        "IMPLEMENTATION PARTIAL",
        "HOSTED EVIDENCE VERIFIED",
        "ARCHITECTURAL ACCEPTANCE PENDING",
        "M6 APPROVAL REGISTRY DEFERRED",
        "F-12 ARTIFACT CAPTURE DEFERRED",
    ):
        assert marker in report, marker
    assert "IMPLEMENTATION COMPLETE" not in report
    # CI #201 ran the three-identity cases; acceptance is still the owner's.
    assert "HOSTED EVIDENCE PENDING" not in report


def test_the_mutation_table_matches_the_source_once_per_mutant() -> None:
    names = [m[0] for m in dw.APPROVER_MUTATIONS]
    assert len(names) == len(set(names))
    labels = [name.split(":")[0] for name in names]
    assert labels == [f"P{i}" for i in range(1, len(names) + 1)]
    for what, rel, old, new in dw.APPROVER_MUTATIONS:
        text = (REPO_ROOT / rel).read_bytes().decode("utf-8")
        assert text.count(old) == 1, what
        assert old != new, what
    assert {m[1] for m in dw.APPROVER_MUTATIONS} == {
        "crates/dwkd-authority/src/server/approver.rs",
        "crates/dwkd-authority/src/server/config.rs",
        "crates/dwkd-authority/src/server/mod.rs",
        "crates/dwkd-authority/src/state/transport.rs",
        "crates/dwkd-authority/src/state/admission.rs",
        "crates/dwkd-authority/src/policy/context.rs",
    }
    assert dw.TASKS["approver-identity-mutations"] is dw.task_approver_identity_mutations
    stages = dw._approver_stages()
    assert [s.name for s in stages] == ["authority-unit", "approver-process"]
    assert all(s.evidence is None for s in stages)
    assert "approver" not in " ".join(dw.C3_CAMPAIGNS)
    assert dw.APPROVER_EVIDENCE_DIR not in (
        dw.CONCURRENCY_EVIDENCE_DIR,
        dw.POSTURE_EVIDENCE_DIR,
        dw.POLICY_ANCHOR_EVIDENCE_DIR,
    )
    makefile = _read(REPO_ROOT / "Makefile")
    assert "\napprover-identity-mutations: ## F-18 Phase 3.4 mutation review" in makefile
    assert "\t@$(DW) approver-identity-mutations\n" in makefile


# --- the review's machinery, driven with a stand-in for cargo ----------------

TARGET = "src/approver.rs"
GUARD = "        self.uids.contains(&uid)\n"
MUTATION = ("P0: the guard is removed", TARGET, GUARD, "        true\n")


class Fake:
    """`cargo`, faked: the build and each stage's answer, unmutated and mutated."""

    def __init__(self, root: Path, **answers: dw.SuiteRun) -> None:
        self.root = root
        self.answers = answers

    def __call__(self, *command: str) -> dw.SuiteRun:
        mutated = GUARD not in (self.root / TARGET).read_text(encoding="utf-8")
        stage = "build" if command[1] == "build" else command[-1]
        key = f"{stage}_{'mutated' if mutated else 'clean'}"
        default = dw.SuiteRun(0, ("unit::one",), (), 1, 0.1)
        return self.answers.get(key, default)


@pytest.fixture
def harness(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    root = tmp_path / "repo"
    (root / "src").mkdir(parents=True)
    (root / TARGET).write_text("fn admits() {\n" + GUARD + "}\n", encoding="utf-8", newline="\n")
    monkeypatch.setattr(dw, "ROOT", root)
    stages = (dw.MutationStage("unit", ("cargo", "test", "unit")),)
    monkeypatch.setattr(dw, "_approver_stages", lambda: stages)
    return root


def _kept(root: Path) -> dict[str, object]:
    record = json.loads((root / "record" / "record.json").read_text(encoding="utf-8"))
    assert isinstance(record, dict)
    return record


def test_a_named_failure_kills_and_the_file_is_restored(harness: Path) -> None:
    before = (harness / TARGET).read_bytes()
    failed = dw.SuiteRun(101, (), ("server::approver::tests::only_a_uid",), 1, 0.1)
    record = dw.approver_review(
        (MUTATION,), root=harness / "record", tests=Fake(harness, unit_mutated=failed)
    )
    assert record["result"] == "PASS"
    kept = _kept(harness)
    assert kept["schema"] == "direwolf.f18-approver.mutation-review"
    assert (kept["finding"], kept["adr"], kept["task"]) == (
        "F-18",
        "0067",
        "approver-identity-mutations",
    )
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
    with pytest.raises(dw.TaskError, match=f"F-18 not killed: P0: the guard is removed {outcome}"):
        dw.approver_review((MUTATION,), root=harness / "record", tests=Fake(harness, **answers))
    assert _kept(harness)["result"] == "FAIL"
    assert (harness / TARGET).read_bytes() == before


def test_a_failing_baseline_judges_no_mutant(harness: Path) -> None:
    broken = dw.SuiteRun(101, (), ("server::approver::tests::only_a_uid",), 1, 0.1)
    with pytest.raises(dw.TaskError, match="BLOCKED: approver-identity-mutations"):
        dw.approver_review(
            (MUTATION,), root=harness / "record", tests=Fake(harness, unit_clean=broken)
        )
    kept = _kept(harness)
    assert kept["result"] == "BLOCKED" and kept["mutants"] == []
