"""F-05's identity and confinement judgement stays what it is (ADR-0069, Proposed).

**Measured, not assumed.** The probe reads its own kernel -- its uid and gid
maps, its security labels -- in a version-4 report, and the broker judges that
against the runtime's record and the host's kernel. The shared identity map is
never reported as remapping, and a security module counts as enforcing only
where the host's kernel runs it and both vantages name the same enforcing
profile or confined domain. Landlock, which nothing installs, is never
counted.

**Reported, never admitted on.** The judgement is a broker event: no
invariant, no protocol-12 field and no admission decision changes. Carrying it
to the authority is protocol 13's.

**Each guard has a mutant.** `make sandbox-identity-mutations` weakens each in
turn with C3's judge; its table must match the source exactly once per mutant.
ADR-0069 is Proposed, and stays so here.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
IDENTITY = REPO_ROOT / "crates" / "dwkd-broker" / "src" / "sandbox" / "identity.rs"
PROTO = REPO_ROOT / "crates" / "dwk-proto" / "src" / "brokerp" / "sandbox.rs"
PROBE = REPO_ROOT / "crates" / "dwk-sandbox-probe" / "src" / "linux.rs"
OCI = REPO_ROOT / "crates" / "dwkd-broker" / "src" / "sandbox" / "oci.rs"
ADR = (
    REPO_ROOT
    / "docs"
    / "adr"
    / "0069-f05-user-namespace-and-lsm-assurance-are-measured-not-assumed.md"
)

sys.path.insert(0, str(REPO_ROOT / "scripts"))

import dw  # noqa: E402  - imported after the path is extended


def _read(path: Path) -> str:
    return path.read_bytes().decode("utf-8")


def _function(source: str, signature: str) -> str:
    start = source.index(signature)
    return source[start : start + source[start:].index("\n}\n")]


def test_the_probe_reports_its_own_kernel_in_a_version_four_report() -> None:
    proto = _read(PROTO)
    assert "ProbeReportVersion(u16), min = 3, max = 4" in proto
    assert "optional identity: IdentityFacts," in proto
    assert "if (report.version.get() >= 4) != report.identity.is_some() {" in proto
    probe = _read(PROBE)
    assert "ProbeReportVersion::new(4)" in probe
    assert "identity: Some(identity_facts())," in probe
    facts = _function(probe, "fn identity_facts() -> IdentityFacts {")
    for path in (
        "/proc/self/uid_map",
        "/proc/self/gid_map",
        "/proc/self/attr/current",
        "/proc/self/attr/apparmor/current",
    ):
        assert f'"{path}"' in facts, path


def test_the_judgement_is_reported_and_never_an_invariant() -> None:
    """One call site, in the broker's judgement, writing an event; no
    invariant, no verdict and no admission reads it, and protocol 12 is
    unchanged."""
    oci = _read(OCI)
    assert oci.count("super::identity::judge(") == 1
    call = oci[oci.index("crate::event(&super::identity::line(") :]
    call = call[: call.index("));\n") + 4]
    assert "checks.push" not in call and "Verdict" not in call
    users = sorted(
        p.relative_to(REPO_ROOT).as_posix()
        for p in (REPO_ROOT / "crates").rglob("*.rs")
        if "identity::" in _read(p) and "sandbox" in p.as_posix()
    )
    assert users == [
        "crates/dwkd-broker/src/sandbox/identity_tests.rs",
        "crates/dwkd-broker/src/sandbox/inspect.rs",
        "crates/dwkd-broker/src/sandbox/oci.rs",
    ], users
    brokerp = _read(REPO_ROOT / "crates" / "dwk-proto" / "src" / "brokerp.rs")
    assert "pub const PROTOCOL: u16 = 12;" in brokerp
    invariants = _read(PROTO)
    invariants = invariants[invariants.index("\n    SandboxInvariant {\n") :]
    invariants = invariants[: invariants.index("\n    }\n")]
    wire = re.findall(r' = "([A-Z_]+)",', invariants)
    assert len(wire) == 52, "protocol 12's invariants, none added"
    for name in wire:
        for absent in ("APPARMOR", "SELINUX", "LANDLOCK", "LSM", "REMAP", "IDENTITY_MAP"):
            assert absent not in name, name
    assert "**Not** a user" in invariants


def test_only_both_vantages_on_a_running_module_count_as_enforced() -> None:
    source = _read(IDENTITY)
    enforced = [line.strip() for line in source.splitlines() if "Condition::Enforced" in line]
    assert enforced == [
        'judged(Condition::Enforced, "both", name)',
        'judged(Condition::Enforced, "both", domain)',
    ], enforced
    apparmor = _function(source, "fn apparmor(")
    assert apparmor.index("if !host.apparmor {") < apparmor.index("Condition::Enforced")
    assert 'if name == named && name != "unconfined"' in apparmor
    selinux = _function(source, "fn selinux(")
    assert selinux.index("host.selinux_enforcing else") < selinux.index("Condition::Enforced")
    assert selinux.index("label.as_str() != record") < selinux.index("Condition::Enforced")
    assert 'landlock: judged(Condition::NotApplicable, "build", "no-ruleset"),' in source
    userns = _function(source, "fn userns(")
    assert "Condition::Enforced" not in userns and "Condition::Reduced" not in userns


def test_the_mutation_table_matches_the_source_once_per_mutant() -> None:
    names = [m[0] for m in dw.IDENTITY_MUTATIONS]
    assert len(names) == len(set(names))
    assert [n.split(":")[0] for n in names] == [f"N{i}" for i in range(1, len(names) + 1)]
    for what, rel, old, new in dw.IDENTITY_MUTATIONS:
        text = (REPO_ROOT / rel).read_bytes().decode("utf-8")
        assert text.count(old) == 1, what
        assert old != new, what
    assert {m[1] for m in dw.IDENTITY_MUTATIONS} == {"crates/dwkd-broker/src/sandbox/identity.rs"}
    assert dw.TASKS["sandbox-identity-mutations"] is dw.task_sandbox_identity_mutations
    stages = dw._identity_stages()
    assert [s.name for s in stages] == ["broker-identity"]
    assert all(s.evidence is None for s in stages)
    assert dw.IDENTITY_EVIDENCE_DIR not in (
        dw.PROXY_PEER_EVIDENCE_DIR,
        dw.APPROVER_EVIDENCE_DIR,
        dw.POLICY_ANCHOR_EVIDENCE_DIR,
        dw.POSTURE_EVIDENCE_DIR,
        dw.CONCURRENCY_EVIDENCE_DIR,
    )
    makefile = _read(REPO_ROOT / "Makefile")
    assert "\nsandbox-identity-mutations: ## F-05" in makefile
    assert "\t@$(DW) sandbox-identity-mutations\n" in makefile


def test_only_the_judgement_reads_the_hosts_kernel_files() -> None:
    """TX015 exempts the judgement and its tests, for the kernel's own files
    and nothing a workspace names; no other sandbox module joins them."""
    rules = _read(REPO_ROOT / "architecture.toml")
    tx015 = rules[rules.index('id = "TX015-') :]
    tx015 = tx015[: tx015.index("[[text_rules]]")]
    exempt = tx015[: tx015.index("suffixes")]
    for path in ("sandbox/identity.rs", "sandbox/identity_tests.rs"):
        assert f'"crates/dwkd-broker/src/{path}",' in exempt, path
    source = _read(IDENTITY)
    reads = re.findall(r'read\("(/[^"]+)"\)', source)
    assert sorted(reads) == [
        "/sys/fs/selinux/enforce",
        "/sys/kernel/security/lsm",
        "/sys/module/apparmor/parameters/enabled",
    ], reads


def test_the_real_environment_reports_its_identity_from_both_vantages() -> None:
    suite = _read(REPO_ROOT / "crates" / "dwkd-broker" / "tests" / "sandbox_foundation.rs")
    assert "identity_reported(&ev, &broker, &e, &container);" in suite
    assert '" userns=UNSUPPORTED:inside:shared "' in suite
    assert '"{{.AppArmorProfile}}"' in suite
    assert '" landlock=NOT_APPLICABLE:build:no-ruleset"' in suite


def test_the_docs_claim_no_remapping_and_no_landlock() -> None:
    sandbox = _read(REPO_ROOT / "docs" / "SANDBOX.md")
    assert "userns:           remap" not in sandbox
    assert "| User namespace remap | ✅ |" not in sandbox
    assert "| Landlock (host exec) | ✅ 5.13+ |" not in sandbox
    assert "host execution additionally applies Landlock" not in sandbox
    assert "apparmor/selinux: enforced where available\n" not in sandbox
    threat = _read(REPO_ROOT / "docs" / "THREAT_MODEL.md")
    assert "`no-new-privileges`, seccomp, user namespaces, **never mount" not in threat
    for doc in (sandbox, threat):
        assert "0069-f05-user-namespace-and-lsm-assurance-are-measured-not-assumed.md" in doc


def test_adr_0069_is_proposed_and_records_its_evidence() -> None:
    text = _read(ADR)
    assert text.startswith("# ADR-0069:")
    assert re.search(r"^\*\*Status:\*\* Proposed ", text, re.M)
    for evidence in (
        "identity_tests.rs",
        "sandbox-foundation-evidence",
        "sandbox-identity-mutations",
        "ADR-0052",
        "ADR-0056",
        "ADR-0048",
        "ADR-0068",
        "protocol 13",
    ):
        assert evidence in text, evidence
    index = _read(REPO_ROOT / "docs" / "adr" / "README.md")
    assert "[0069](0069-f05-user-namespace-and-lsm-assurance-are-measured-not-assumed.md)" in index


# --- the review's machinery, driven with a stand-in for cargo ----------------

TARGET = "src/identity.rs"
GUARD = '            judged(Condition::Reduced, "both", "complain")\n'
MUTATION = (
    "N0: complain counts as enforced",
    TARGET,
    GUARD,
    '            judged(Condition::Enforced, "both", "complain")\n',
)


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
    (root / TARGET).write_text("fn apparmor() {\n" + GUARD + "}\n", encoding="utf-8", newline="\n")
    monkeypatch.setattr(dw, "ROOT", root)
    stages = (dw.MutationStage("unit", ("cargo", "test", "unit")),)
    monkeypatch.setattr(dw, "_identity_stages", lambda: stages)
    return root


def _kept(root: Path) -> dict[str, object]:
    record = json.loads((root / "record" / "record.json").read_text(encoding="utf-8"))
    assert isinstance(record, dict)
    return record


def test_a_named_failure_kills_and_the_file_is_restored(harness: Path) -> None:
    before = (harness / TARGET).read_bytes()
    failed = dw.SuiteRun(101, (), ("sandbox::identity_tests::apparmor_counts_only",), 1, 0.1)
    record = dw.identity_review(
        (MUTATION,), root=harness / "record", tests=Fake(harness, unit_mutated=failed)
    )
    assert record["result"] == "PASS"
    kept = _kept(harness)
    assert kept["schema"] == "direwolf.f05.mutation-review"
    assert (kept["finding"], kept["adr"], kept["task"]) == (
        "F-05",
        "0069",
        "sandbox-identity-mutations",
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
    with pytest.raises(
        dw.TaskError, match=f"F-05 not killed: N0: complain counts as enforced {outcome}"
    ):
        dw.identity_review((MUTATION,), root=harness / "record", tests=Fake(harness, **answers))
    assert _kept(harness)["result"] == "FAIL"
    assert (harness / TARGET).read_bytes() == before


def test_a_failing_baseline_judges_no_mutant(harness: Path) -> None:
    broken = dw.SuiteRun(101, (), ("sandbox::identity_tests::apparmor_counts_only",), 1, 0.1)
    with pytest.raises(dw.TaskError, match="BLOCKED: sandbox-identity-mutations"):
        dw.identity_review(
            (MUTATION,), root=harness / "record", tests=Fake(harness, unit_clean=broken)
        )
    kept = _kept(harness)
    assert kept["result"] == "BLOCKED" and kept["mutants"] == []


@pytest.mark.skipif(sys.platform.startswith("linux"), reason="the guard is for other hosts")
def test_the_task_off_linux_is_not_exercised() -> None:
    with pytest.raises(dw.TaskError, match="NOT EXERCISED"):
        dw.task_sandbox_identity_mutations()
