"""F-12's host path anchors stay sound (ADR-0066, Proposed).

**No live decision is made in the one-namespace model.** The policy engine's
`PathAnchors { host: None }` -- every anchor a canonical path in the
candidate's own namespace -- is what its unit tests and benchmark build. A
live context is built in one place, `state/query.rs`, and always in the
logical namespace (`anchors.host = Some(...)`); nothing else in the authority
builds the one-namespace model.

**Placement happens outside the decision's transaction.** Where a host path
lies is found by walking the host, so it is computed beside the targets'
resolution -- with no transaction open -- through the same pinned root, and
handed to the decision as a value. The policy core never looks.

**`~` has no default.** Nothing in the state layer or the server derives a
home from a variable, a subject or the authority's own state: the operator's
`--path-anchor home=` is its only source.

**Each guard has a mutant.** `make policy-anchor-mutations` weakens each
guard in turn with C3's judge; its table must match the source exactly once
per mutant, and the real-process cases it relies on must be required by the
broker evidence. ADR-0066 is Proposed, and stays so here.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
AUTHORITY = REPO_ROOT / "crates" / "dwkd-authority" / "src"
ADR = REPO_ROOT / "docs" / "adr" / "0066-f12-host-path-anchors-are-placed-by-identity.md"
REPORT = REPO_ROOT / "docs" / "F12_POLICY_PACK_USABILITY.md"

sys.path.insert(0, str(REPO_ROOT / "scripts"))
import dw  # noqa: E402  - imported after the path is extended


def _read(path: Path) -> str:
    return path.read_bytes().decode("utf-8")


def _code(text: str) -> str:
    """The text without its comment lines."""
    return "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("//"))


def test_only_the_policy_tests_build_the_one_namespace_model() -> None:
    # Every `PathAnchors { ... }` literal in the authority is the tests'
    # models in `testing.rs`; the strict constructor is `context.rs`'s `Self`.
    # A literal, not a declaration, an impl or a return type.
    literal = re.compile(r"(?<!struct )(?<!for )(?<!impl )(?<!-> )(?<!&)\bPathAnchors \{")
    builders = sorted(
        path.relative_to(AUTHORITY).as_posix()
        for path in AUTHORITY.rglob("*.rs")
        if literal.search(_code(_read(path)))
    )
    assert builders == ["policy/testing.rs"], builders
    # The one-namespace model (`host: None`) is the tests' alone.
    context = _code(_read(AUTHORITY / "policy" / "context.rs"))
    assert not re.search(r"\bhost:\s*None\b", context)
    assert "host: Some(HostPlacements::new())" in context
    testing = _code(_read(AUTHORITY / "policy" / "testing.rs"))
    assert re.search(r"\bhost:\s*None\b", testing)


def test_every_live_context_is_in_the_logical_namespace() -> None:
    query = _code(_read(AUTHORITY / "state" / "query.rs"))
    assert query.count("anchors.host = Some(placed);") == 1
    # `policy_context` is `policy_context_placed` with nothing placed: the
    # strict default, never the one-namespace model.
    assert "policy_context_placed(work, run, active, HostPlacements::new())" in query
    # The filesystem decision is the one made with placements.
    tool = _code(_read(AUTHORITY / "state" / "tool.rs"))
    assert "query::policy_context_placed(work, asked.run.as_str(), active, placed.clone())" in tool


def test_placement_is_computed_beside_the_resolution_and_outside_any_transaction() -> None:
    state = _code(_read(AUTHORITY / "state" / "mod.rs"))
    resolve_call = state.split("fn resolve_call(", 1)[1].split("\n    fn ", 1)[0]
    # One call, through the pinned root `resolve_targets` hands it, and the
    # step that calls it is the one with no transaction open.
    assert resolve_call.count("anchors::place(") == 1
    assert "tool::resolve_targets(&binding, &call, place)" in resolve_call
    place_line = next(line for line in resolve_call.splitlines() if "anchors::place(" in line)
    assert "transact" not in place_line
    # Nowhere else in the state layer places host paths.
    callers = [
        path.relative_to(AUTHORITY).as_posix()
        for path in (AUTHORITY / "state").rglob("*.rs")
        if "anchors::place(" in _code(_read(path))
    ]
    assert callers == ["state/mod.rs"], callers
    # The policy core and the server never reach the host walk.
    for core in (AUTHORITY / "policy", AUTHORITY / "server"):
        for path in core.rglob("*.rs"):
            assert "relation_to(" not in _code(_read(path)), path


def test_the_home_anchor_has_no_source_but_the_operator() -> None:
    anchors = _code(_read(AUTHORITY / "state" / "anchors.rs"))
    with_own = anchors.split("pub fn with_own(", 1)[1].split("\n    }\n", 1)[0]
    # The authority adds its own state and executable directories, never a home.
    assert "all.home" not in with_own
    assert "all.direwolf_home" in with_own and "all.direwolf_install" in with_own
    server = _code(_read(AUTHORITY / "server" / "mod.rs"))
    host_anchors = server.split("fn host_anchors(", 1)[1].split("\n}\n", 1)[0]
    assert "AnchorName::Home => &mut anchors.home" in host_anchors
    assert host_anchors.count("anchors.home") == 1
    # No variable, no subject, no user database.
    for text in (with_own, host_anchors):
        for word in ("std::env", "HOME", "getpwuid", "passwd", "home_dir"):
            assert word not in text, word


def test_the_anchors_build_and_start_off_linux() -> None:
    """CI #184 (ace658b): Windows did not compile -- the server's anchor
    functions called the Unix-only `log` -- and on macOS every in-process
    start failed, the authority's own state directory refused by a check that
    has no resolver there. Neither shows on Linux, where the gates run."""
    server = _read(AUTHORITY / "server" / "mod.rs")
    for function in ("fn host_anchors(", "fn log_anchors(", "fn start(", "fn log("):
        head = server.split(function, 1)[0].rsplit("\n\n", 1)[-1]
        assert "#[cfg(unix)]" in head, f"{function} is not Unix-only like its callers"
    anchors = _code(_read(AUTHORITY / "state" / "anchors.rs"))
    check = anchors.split("pub fn check(", 1)[1].split("\n    }\n", 1)[0]
    # The first thing the check does off Linux is nothing.
    first = check.split("{", 1)[1].strip()
    assert first.startswith('if !cfg!(target_os = "linux") {\n            return Ok(());'), first
    resource = _read(AUTHORITY / "resource" / "fs" / "mod.rs")
    host_end = resource.split("pub(in crate::resource) enum HostEnd {", 1)[0].rsplit("///", 1)[-1]
    assert 'not(target_os = "linux")' in host_end and "dead_code" in host_end


def test_the_mutation_table_matches_the_source_once_per_mutant() -> None:
    names = [m[0] for m in dw.POLICY_ANCHOR_MUTATIONS]
    assert len(names) == len(set(names))
    labels = [name.split(":")[0] for name in names]
    assert labels == [f"A{i}" for i in range(1, len(names) + 1)]
    for what, rel, old, new in dw.POLICY_ANCHOR_MUTATIONS:
        text = (REPO_ROOT / rel).read_bytes().decode("utf-8")
        assert text.count(old) == 1, what
        assert old != new, what
    files = {m[1] for m in dw.POLICY_ANCHOR_MUTATIONS}
    assert files == {
        "crates/dwkd-authority/src/policy/value.rs",
        "crates/dwkd-authority/src/policy/load.rs",
        "crates/dwkd-authority/src/resource/fs/mod.rs",
        "crates/dwkd-authority/src/resource/fs/linux/mod.rs",
        "crates/dwkd-authority/src/state/anchors.rs",
        "crates/dwkd-authority/src/state/tool.rs",
        "crates/dwkd-authority/src/state/query.rs",
        "crates/dwkd-authority/src/state/mod.rs",
        "crates/dwkd-authority/src/state/plan.rs",
        "policy/balanced.toml",
    }
    assert dw.TASKS["policy-anchor-mutations"] is dw.task_policy_anchor_mutations
    stages = dw._policy_anchor_stages()
    assert [s.name for s in stages] == [
        "authority-unit",
        "policy-packs",
        "policy-composition",
        "authority-process",
    ]
    assert all(s.evidence is None for s in stages)
    # Kept apart from C3's closed registry and from F-02's and F-03's records.
    assert "policy-anchor" not in dw.C3_CAMPAIGNS
    assert dw.POLICY_ANCHOR_EVIDENCE_DIR not in (
        dw.CONCURRENCY_EVIDENCE_DIR,
        dw.POSTURE_EVIDENCE_DIR,
    )
    makefile = _read(REPO_ROOT / "Makefile")
    assert "\npolicy-anchor-mutations: ## F-12 mutation review" in makefile
    assert "\t@$(DW) policy-anchor-mutations\n" in makefile


def test_the_broker_evidence_requires_the_shipped_pack_cases() -> None:
    cases = (
        "shipped-pack-denies-unevaluable",
        "shipped-pack-reads-with-a-trusted-home",
        "shipped-pack-refuses-an-overlapping-home",
        "serve-refuses-an-unexaminable-home",
    )
    read = _read(REPO_ROOT / "crates" / "dwkd-authority" / "tests" / "broker_fs_read.rs")
    for case in cases:
        assert ("broker-fs-read", case) in dw.BROKER_CASES, case
        assert f'"{case}"' in read, case


def test_the_shipped_packs_name_host_paths_only_in_denials() -> None:
    # What the loader enforces (ValueError::HostPathOutsideDenial), read off
    # the packs themselves: every `path_under` outside the workspace is in a
    # DENY rule.
    for pack in ("safe", "balanced", "power"):
        text = _read(REPO_ROOT / "policy" / f"{pack}.toml")
        for rule in text.split("[[rule]]")[1:]:
            effect = re.search(r'^effect\s*=\s*"([A-Z_]+)"', rule, re.MULTILINE)
            under = re.search(r"^when\.path_under\s*=\s*(.+?)(?=^\S|\Z)", rule, re.S | re.M)
            if effect is None or under is None:
                continue
            paths = re.findall(r'"([^"]+)"', under.group(1))
            host = [p for p in paths if not p.startswith(("${WORKSPACE}", "/workspace"))]
            if host:
                assert effect.group(1) == "DENY", (pack, host)


def test_adr_0066_is_proposed_and_records_its_evidence() -> None:
    text = _read(ADR)
    assert text.startswith("# ADR-0066:")
    assert re.search(r"^\*\*Status:\*\* Proposed ", text, re.MULTILINE)
    for evidence in (
        "policy_packs.rs",
        "broker_fs_read.rs",
        "linux/tests.rs",
        "policy-anchor-mutations",
    ):
        assert evidence in text, evidence
    report = _read(REPORT)
    assert "ARTIFACT CAPTURE DEFERRED TO M8" in report


# --- the review's machinery, driven with a stand-in for cargo ----------------

TARGET = "src/value.rs"
GUARD = "    None => Err(Unresolved),\n"
MUTATION = ("A0: the guard is removed", TARGET, GUARD, "    None => Ok(false),\n")


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
    (root / TARGET).write_text("fn under() {\n" + GUARD + "}\n", encoding="utf-8", newline="\n")
    monkeypatch.setattr(dw, "ROOT", root)
    stages = (dw.MutationStage("unit", ("cargo", "test", "unit")),)
    monkeypatch.setattr(dw, "_policy_anchor_stages", lambda: stages)
    return root


def _kept(root: Path) -> dict[str, object]:
    record = json.loads((root / "record" / "record.json").read_text(encoding="utf-8"))
    assert isinstance(record, dict)
    return record


def test_a_named_failure_kills_and_the_file_is_restored(harness: Path) -> None:
    before = (harness / TARGET).read_bytes()
    failed = dw.SuiteRun(101, (), ("policy::fixtures::an_unplaced_host_path",), 1, 0.1)
    record = dw.policy_anchor_review(
        (MUTATION,), root=harness / "record", tests=Fake(harness, unit_mutated=failed)
    )
    assert record["result"] == "PASS"
    kept = _kept(harness)
    assert kept["schema"] == "direwolf.f12.mutation-review"
    assert (kept["finding"], kept["adr"], kept["task"]) == (
        "F-12",
        "0066",
        "policy-anchor-mutations",
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
    with pytest.raises(dw.TaskError, match=f"F-12 not killed: A0: the guard is removed {outcome}"):
        dw.policy_anchor_review(
            (MUTATION,), root=harness / "record", tests=Fake(harness, **answers)
        )
    assert _kept(harness)["result"] == "FAIL"
    assert (harness / TARGET).read_bytes() == before


def test_a_failing_baseline_judges_no_mutant(harness: Path) -> None:
    broken = dw.SuiteRun(101, (), ("policy::fixtures::an_unplaced_host_path",), 1, 0.1)
    with pytest.raises(dw.TaskError, match="BLOCKED: policy-anchor-mutations"):
        dw.policy_anchor_review(
            (MUTATION,), root=harness / "record", tests=Fake(harness, unit_clean=broken)
        )
    kept = _kept(harness)
    assert kept["result"] == "BLOCKED" and kept["mutants"] == []
