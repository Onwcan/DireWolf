"""F-02's authority gate stays where ADR-0064 (Proposed) puts it.

**Every broker hand-off in the state layer is accounted for.** An effect the
authority decides reaches the broker only inside an effect section, so an end
of authority -- a revocation's first phase, a lease taken over or released,
a run released -- never commits between an effect's decision and its outcome.
The hand-offs are counted per file and each is named here with what orders it;
a new one fails this test until someone says which kind it is.

**Each guard has a mutant.** `make authority-concurrency-mutations` weakens
the gate's rules and each section in turn; its table must still match the
source exactly once per mutant, or the review stops before it starts. Its
judge is C3's (`_judge_mutant`): a build failure, a stage stopped at its limit
or a selection that ran nothing is never a kill, and every file is restored
byte-identically -- the harness below drives it with a stand-in for cargo.

**The decision is the owner's.** ADR-0064 is Proposed, and stays so here.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
STATE = REPO_ROOT / "crates" / "dwkd-authority" / "src" / "state"
ADR = REPO_ROOT / "docs" / "adr" / "0064-f02-authority-endings-serialised-with-decided-effects.md"

sys.path.insert(0, str(REPO_ROOT / "scripts"))
import dw  # noqa: E402  - imported after the path is extended

# Each file's broker hand-offs (`.perform(`, outside tests), and what orders
# each against an end of authority.
HAND_OFFS = {
    # tool_invoke and process_invoke: inside their effect sections;
    # reclaim_staging: a clean-up that never performs an invocation again.
    "mod.rs": 3,
    # exchange(): inside the hop's effect section (net_hop).
    "net_http/mod.rs": 1,
    # start(): inside the launch's section (`routed` to the start);
    # collect(): a started workload's, which an end of authority destroys.
    "workload_ops.rs": 2,
    # list, prepare, measure, destroy: undone, or themselves a clean-up, and
    # settled against the run's state at their outcome.
    "environment_ops.rs": 4,
}

ENDINGS = ("acquire_lease", "release_lease", "release_run")
EFFECTS = ("tool_invoke", "process_invoke")


def _source(rel: str) -> str:
    return (STATE / rel).read_text(encoding="utf-8")


def _body(text: str, name: str) -> str:
    """The text of `fn name` up to the next function at its indentation."""
    match = re.search(rf"^(?P<indent>[ ]*)pub(?:\(crate\))? fn {name}\(", text, re.MULTILINE)
    assert match is not None, f"no fn {name}"
    indent = match.group("indent")
    rest = text[match.end() :]
    following = re.search(rf"^{indent}(?:pub(?:\([a-z]+\))? )?fn \w", rest, re.MULTILINE)
    return rest if following is None else rest[: following.start()]


def test_every_broker_hand_off_in_the_state_layer_is_accounted_for() -> None:
    found = {}
    for path in sorted(STATE.rglob("*.rs")):
        rel = path.relative_to(STATE).as_posix()
        # The route tests' fakes are brokers, not hand-offs.
        if rel.endswith(("_tests.rs", "/tests.rs")) or rel == "interleave.rs":
            continue
        count = path.read_text(encoding="utf-8").count(".perform(")
        if count:
            found[rel] = count
    assert found == HAND_OFFS


def test_each_end_of_authority_and_each_effect_takes_its_section_before_deciding() -> None:
    state = _source("mod.rs")
    for name in ENDINGS:
        body = _body(state, name)
        assert body.index("gate.ending()?") < body.index("self.transact("), name
        assert body.index("drop(ending)") < body.index("self.end_runs("), name
    revocation = state[state.index("    fn revoke(&mut self, target") :]
    assert revocation.index(".ending()") < revocation.index("ownership::revoke(")
    assert revocation.index("drop(ending)") < revocation.index("finish_revocation(")
    for name in EFFECTS:
        body = _body(state, name)
        assert body.index("gate.effect()?") < body.index("::decide("), name
        assert body.index("drop(effect)") > body.index(".perform(order)"), name
    hop = _source("net_http/mod.rs")
    hop = hop[hop.index("    fn net_hop(") :]
    assert hop.index("gate.effect()?") < hop.index("self.net_intent(")
    assert hop.index("drop(effect)") > hop.index("exchange(shared, chain")
    route = _source("workload_route.rs")
    routed = route[route.index("    fn routed(") :]
    assert routed.index("gate.effect()?") < routed.index("route(work, asked, call, context, false)")
    # After a preparation the route is decided again, in a section of its own
    # taken after the preparation and before that transaction.
    prepared = routed[routed.index("self.environment_prepare(") :]
    assert prepared.index("gate.effect()?") < prepared.index(
        "route(work, asked, call, context, true)"
    )
    launch = route[route.index("    fn sandboxed(") :]
    launch = launch[: launch.index("\n    }\n")]
    # Held to the end of the launch: past the start, never dropped before it.
    assert "let (routed, _effect) = self.routed(" in launch
    assert launch.index("self.routed(") < launch.index("workload_ops::start(")
    assert "drop(_effect)" not in launch


def test_the_mutation_table_matches_the_source_once_per_mutant_and_names_every_guard() -> None:
    names = [m[0] for m in dw.CONCURRENCY_MUTATIONS]
    assert len(names) == len(set(names))
    labels = sorted(name.split(":")[0] for name in names)
    wanted = [f"G{i}" for i in range(1, 6)] + [f"E{i}" for i in range(1, 9)]
    wanted += [f"C{i}" for i in range(1, 8)]
    assert labels == sorted(wanted)
    for what, rel, old, new in dw.CONCURRENCY_MUTATIONS:
        text = (REPO_ROOT / rel).read_bytes().decode("utf-8")
        assert text.count(old) == 1, what
        assert old != new, what
    assert dw.TASKS["authority-concurrency-mutations"] is dw.task_authority_concurrency_mutations
    stages = dw._concurrency_stages()
    assert [s.name for s in stages] == ["authority-unit", "state-concurrency"]
    assert all(s.evidence is None for s in stages)


def test_adr_0064_is_proposed_and_records_its_evidence() -> None:
    text = ADR.read_text(encoding="utf-8")
    assert text.startswith("# ADR-0064:")
    assert re.search(r"^\*\*Status:\*\* Proposed ", text, re.MULTILINE)
    for evidence in (
        "concurrency_route_tests.rs",
        "state_concurrency.rs",
        "authority-concurrency-mutations",
    ):
        assert evidence in text, evidence


# --- the review's machinery, driven with a stand-in for cargo ----------------

TARGET = "src/guard.rs"
GUARD = "    if stale { return Err(Refused); }\n"
MUTATION = ("the guard is removed", TARGET, GUARD, "")


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
    monkeypatch.setattr(dw, "_concurrency_stages", lambda: stages)
    return root


def _review(root: Path, tests: Fake) -> dict[str, object]:
    return dw.concurrency_review((MUTATION,), root=root / "record", tests=tests)


def _kept(root: Path) -> dict[str, object]:
    record = json.loads((root / "record" / "record.json").read_text(encoding="utf-8"))
    assert isinstance(record, dict)
    return record


def test_a_named_failure_kills_and_the_file_is_restored(harness: Path) -> None:
    before = (harness / TARGET).read_bytes()
    failed = dw.SuiteRun(101, (), ("state::gate::tests::refuses",), 1, 0.1)
    record = _review(harness, Fake(harness, unit_mutated=failed))
    assert record["result"] == "PASS"
    kept = _kept(harness)
    assert kept["schema"] == "direwolf.f02.mutation-review" and kept["finding"] == "F-02"
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
    with pytest.raises(dw.TaskError, match=f"not killed: the guard is removed {outcome}"):
        _review(harness, Fake(harness, **answers))
    assert _kept(harness)["result"] == "FAIL"
    assert (harness / TARGET).read_bytes() == before


def test_a_failing_baseline_judges_no_mutant(harness: Path) -> None:
    broken = dw.SuiteRun(101, (), ("state::gate::tests::refuses",), 1, 0.1)
    with pytest.raises(dw.TaskError, match="BLOCKED"):
        _review(harness, Fake(harness, unit_clean=broken))
    kept = _kept(harness)
    assert kept["result"] == "BLOCKED" and kept["mutants"] == []


def test_a_stale_target_stops_the_review_before_anything_is_built(harness: Path) -> None:
    stale = ("a stale target", TARGET, "    if gone {}\n", "")
    with pytest.raises(dw.TaskError, match="exactly once"):
        dw.concurrency_review((stale,), root=harness / "record", tests=Fake(harness))
