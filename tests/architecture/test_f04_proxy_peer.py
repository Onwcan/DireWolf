"""F-04's peer check on the CONNECT proxy stays what it is (ADR-0068, Proposed).

**The relay is admitted by its kernel uid, and only by it.** Every proxy the
broker builds admits `RELAY_UID` alone; the one way to name another uid is
compiled into tests only. The check runs after the closing check and before a
byte is read, a handler slot is held or a thread is started.

**The evidence is required.** `make proxy-peer-evidence` runs the broker's
cases by name and requires each to report; the hosted `sandbox-egress` job
runs it last, with a real second identity, after lifting the AppArmor
restriction on unprivileged namespaces on its disposable runner.

**Each guard has a mutant.** `make proxy-peer-mutations` weakens each in turn
with C3's judge; its table must match the source exactly once per mutant.
ADR-0068 is Proposed, and stays so here.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
PROXY = REPO_ROOT / "crates" / "dwkd-broker" / "src" / "egress" / "proxy.rs"
TESTS = REPO_ROOT / "crates" / "dwkd-broker" / "src" / "egress" / "tests.rs"
ADR = REPO_ROOT / "docs" / "adr" / "0068-f04-connect-proxy-peers-are-authenticated-by-kernel-uid.md"
CI = REPO_ROOT / ".github" / "workflows" / "ci.yml"

sys.path.insert(0, str(REPO_ROOT / "scripts"))

import dw  # noqa: E402  - imported after the path is extended


def _read(path: Path) -> str:
    return path.read_bytes().decode("utf-8")


def _job(name: str) -> list[str]:
    lines = _read(CI).splitlines()
    start = lines.index(f"  {name}:")
    end = next(
        (i for i in range(start + 1, len(lines)) if re.match(r"^  [a-z][a-z0-9-]*:\s*$", lines[i])),
        len(lines),
    )
    return [line for line in lines[start:end] if not line.lstrip().startswith("#")]


def test_every_proxy_the_broker_builds_admits_the_relay_uid_alone() -> None:
    source = _read(PROXY)
    assert source.count("relay: RELAY_UID,") == 2, "new() and without_root()"
    seam = source.index("    pub(crate) fn admitting(")
    assert source[:seam].rstrip().endswith("#[cfg(test)]")
    assert "self.relay = uid;" in source
    decide = source[source.index("pub(crate) fn admits(") :]
    decide = decide[: decide.index("\n}\n")]
    assert "Ok(peer) if peer.uid == relay => Ok(())," in decide
    assert "Err(_) => Err(PeerRefusal::Unidentified)," in decide
    assert ".pid" not in decide and "gid" not in decide
    # The one reader of a peer's credentials (ADR-0049), never rustix's.
    assert "admits(&crate::peer::of(&stream), relay)" in source
    assert "socket_peercred" not in source.replace("`rustix` 1.1.5's", "")


def test_the_process_harness_is_tests_only_and_outside_the_egress_code() -> None:
    """The peer cases start `unshare` and `sudo` and read `DW_PEER_AS` only
    through `peer/harness.rs`: compiled into tests only, named by TX021, and
    outside `egress/`, whose code -- its tests included -- reads no
    environment variable (TX042)."""
    peer = _read(REPO_ROOT / "crates" / "dwkd-broker" / "src" / "peer.rs")
    assert "#[cfg(test)]\npub(crate) mod harness;" in peer
    tests = _read(TESTS)
    for spelled in ("std::process::Command", "std::process::Stdio", "std::env::var"):
        assert spelled not in tests, spelled
    rules = _read(REPO_ROOT / "architecture.toml")
    tx021 = rules[rules.index('id = "TX021-') :]
    tx021 = tx021[: tx021.index("[[text_rules]]")]
    assert '"crates/dwkd-broker/src/peer/harness.rs",' in tx021
    tx042 = rules[rules.index('id = "TX042-') :]
    assert tx042[: tx042.index("suffixes")].count("exempt_paths = []") == 1


def test_the_check_comes_after_closing_and_before_any_slot_byte_or_thread() -> None:
    source = _read(PROXY)
    start = source.index("\nfn accept(")
    body = source[start : start + source[start:].index("\n}\n")]
    order = [
        "context.closing.load(Ordering::SeqCst)",
        "admits(&crate::peer::of(&stream), relay)",
        "refuse(context, refused, refusal);",
        "Handling::take(handlers)",
        ".spawn(",
        "tunnel::serve(&stream, &context)",
    ]
    positions = [body.index(needle) for needle in order]
    assert positions == sorted(positions), order


def test_the_evidence_task_names_tests_that_exist_and_requires_every_case() -> None:
    source = _read(TESTS)
    for name in (*dw.PROXY_PEER_TESTS, *dw.PROXY_PEER_FOREIGN_TESTS):
        module, function = name.rsplit("::", 1)
        assert module == "egress::tests"
        assert re.search(r"#\[test\]\s*(#\[ignore[^\]]*\]\s*)?fn " + function + r"\(\)", source)
    for name in dw.PROXY_PEER_FOREIGN_TESTS:
        function = name.rsplit("::", 1)[1]
        assert re.search(r"#\[ignore = [^\]]*\]\s*fn " + function + r"\(\)", source)
    for case in (*dw.PROXY_PEER_CASES, *dw.PROXY_PEER_FOREIGN_CASES):
        assert f'"{case}"' in source, case
    assert dw.TASKS["proxy-peer-evidence"] is dw.task_proxy_peer_evidence


def _libtest(passed: int, cases: tuple[str, ...]) -> str:
    lines = [f'F04-EVIDENCE {{"case":"{case}","level":"unit","contained":true}}' for case in cases]
    lines.append(f"test result: ok. {passed} passed; 0 failed; 0 ignored; 0 measured")
    return "\n".join(lines)


def test_a_run_that_selected_nothing_or_missed_a_case_is_not_evidence() -> None:
    tests, cases = dw.PROXY_PEER_TESTS, dw.PROXY_PEER_CASES
    with pytest.raises(dw.TaskError, match="did not run every"):
        dw.require_proxy_peer_evidence(_libtest(0, ()), tests, cases, "suite")
    hidden = tuple(c for c in cases if c != "hidden-pid-admitted-by-uid-and-refused-by-uid")
    with pytest.raises(dw.TaskError, match="apparmor_restrict_unprivileged_userns"):
        dw.require_proxy_peer_evidence(_libtest(len(tests), hidden), tests, cases, "suite")
    uncontained = _libtest(len(tests), cases).replace(
        '"admission-before-slot-byte-and-thread","level":"unit","contained":true',
        '"admission-before-slot-byte-and-thread","level":"unit","contained":false',
    )
    with pytest.raises(dw.TaskError, match="admission-before-slot-byte-and-thread"):
        dw.require_proxy_peer_evidence(uncontained, tests, cases, "suite")
    dw.require_proxy_peer_evidence(_libtest(len(tests), cases), tests, cases, "suite")


@pytest.mark.skipif(not sys.platform.startswith("linux"), reason="the task runs on Linux")
def test_the_task_without_a_second_user_is_not_exercised(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commands: list[tuple[str, ...]] = []

    def captured(*command: str) -> str:
        commands.append(command)
        return _libtest(len(dw.PROXY_PEER_TESTS), dw.PROXY_PEER_CASES)

    monkeypatch.delenv("DW_PEER_AS", raising=False)
    monkeypatch.setattr(dw, "run_captured", captured)
    with pytest.raises(dw.TaskError, match="NOT EXERCISED: the cross-uid half"):
        dw.task_proxy_peer_evidence()
    assert len(commands) == 1 and "--ignored" not in commands[0]
    for name in dw.PROXY_PEER_TESTS:
        assert name in commands[0]


def test_the_hosted_egress_job_runs_it_last_with_a_second_user() -> None:
    job = _job("sandbox-egress")
    text = "\n".join(job)
    runs = [line.strip() for line in job if re.match(r"\s+(- )?run: ", line)]
    assert runs.index("- run: make sandbox-egress-evidence") < runs.index(
        "- run: make proxy-peer-evidence"
    )
    assert runs[-1] == "- run: make proxy-peer-evidence", "the F-04 evidence is the job's last"
    tail = text[text.index("- run: make proxy-peer-evidence") :]
    peer = re.search(r"DW_PEER_AS:\s*(\S+)", tail)
    assert peer is not None and peer.group(1) not in ("root", "0", "runner", "$USER")
    sysctl = text.index("sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0")
    assert text.index("- run: make m5e-evidence-bundle") < sysctl
    assert sysctl < text.index("- run: make proxy-peer-evidence")
    for forbidden in ("continue-on-error", "if:"):
        assert forbidden not in text


def test_the_mutation_table_matches_the_source_once_per_mutant() -> None:
    names = [m[0] for m in dw.PROXY_PEER_MUTATIONS]
    assert len(names) == len(set(names))
    assert [n.split(":")[0] for n in names] == [f"K{i}" for i in range(1, len(names) + 1)]
    for what, rel, old, new in dw.PROXY_PEER_MUTATIONS:
        text = (REPO_ROOT / rel).read_bytes().decode("utf-8")
        assert text.count(old) == 1, what
        assert old != new, what
    assert {m[1] for m in dw.PROXY_PEER_MUTATIONS} == {"crates/dwkd-broker/src/egress/proxy.rs"}
    assert dw.TASKS["proxy-peer-mutations"] is dw.task_proxy_peer_mutations
    stages = dw._proxy_peer_stages()
    assert [s.name for s in stages] == ["proxy-decision", "proxy-order", "broker-egress"]
    assert all(s.evidence is None for s in stages)
    assert dw.PROXY_PEER_EVIDENCE_DIR not in (
        dw.APPROVER_EVIDENCE_DIR,
        dw.POLICY_ANCHOR_EVIDENCE_DIR,
        dw.POSTURE_EVIDENCE_DIR,
        dw.CONCURRENCY_EVIDENCE_DIR,
    )
    makefile = _read(REPO_ROOT / "Makefile")
    for target in ("proxy-peer-evidence", "proxy-peer-mutations"):
        assert f"\n{target}: ## F-04" in makefile
        assert f"\t@$(DW) {target}\n" in makefile


def test_adr_0068_is_proposed_and_records_its_evidence() -> None:
    text = _read(ADR)
    assert text.startswith("# ADR-0068:")
    assert re.search(r"^\*\*Status:\*\* Proposed ", text, re.M)
    for evidence in (
        "egress/tests.rs",
        "proxy-peer-evidence",
        "proxy-peer-mutations",
        "DW_PEER_AS",
        "ADR-0048",
        "ADR-0049",
    ):
        assert evidence in text, evidence
    index = _read(REPO_ROOT / "docs" / "adr" / "README.md")
    assert "[0068](0068-f04-connect-proxy-peers-are-authenticated-by-kernel-uid.md)" in index


# --- the review's machinery, driven with a stand-in for cargo ----------------

TARGET = "src/proxy.rs"
GUARD = "        Ok(peer) if peer.uid == relay => Ok(()),\n"
MUTATION = ("K0: the guard is removed", TARGET, GUARD, "        Ok(_) => Ok(()),\n")


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
    monkeypatch.setattr(dw, "_proxy_peer_stages", lambda: stages)
    return root


def _kept(root: Path) -> dict[str, object]:
    record = json.loads((root / "record" / "record.json").read_text(encoding="utf-8"))
    assert isinstance(record, dict)
    return record


def test_a_named_failure_kills_and_the_file_is_restored(harness: Path) -> None:
    before = (harness / TARGET).read_bytes()
    failed = dw.SuiteRun(101, (), ("egress::tests::f04_only_the_relays_uid",), 1, 0.1)
    record = dw.proxy_peer_review(
        (MUTATION,), root=harness / "record", tests=Fake(harness, unit_mutated=failed)
    )
    assert record["result"] == "PASS"
    kept = _kept(harness)
    assert kept["schema"] == "direwolf.f04.mutation-review"
    assert (kept["finding"], kept["adr"], kept["task"]) == ("F-04", "0068", "proxy-peer-mutations")
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
    with pytest.raises(dw.TaskError, match=f"F-04 not killed: K0: the guard is removed {outcome}"):
        dw.proxy_peer_review((MUTATION,), root=harness / "record", tests=Fake(harness, **answers))
    assert _kept(harness)["result"] == "FAIL"
    assert (harness / TARGET).read_bytes() == before


def test_a_failing_baseline_judges_no_mutant(harness: Path) -> None:
    broken = dw.SuiteRun(101, (), ("egress::tests::f04_only_the_relays_uid",), 1, 0.1)
    with pytest.raises(dw.TaskError, match="BLOCKED: proxy-peer-mutations"):
        dw.proxy_peer_review(
            (MUTATION,), root=harness / "record", tests=Fake(harness, unit_clean=broken)
        )
    kept = _kept(harness)
    assert kept["result"] == "BLOCKED" and kept["mutants"] == []
