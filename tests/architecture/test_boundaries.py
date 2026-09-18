"""Prove that the architecture boundary checks reject known violations.

The acceptance criterion for M1 is not "we configured a checker". It is "we
demonstrated the checker rejects a known violation" -- for every rule, not just
for one.

``tests/architecture/fixtures/violations/`` is a miniature repository that
breaks every rule in ``architecture.toml`` at once. These tests point the *real*
rules at that tree and assert each rule fires. If someone deletes a rule, or
writes one whose paths never match anything, a test here fails.

Scope note: these rules are development hygiene, not containment. See
``tests/architecture/README.md``.
"""

from __future__ import annotations

import tomllib
from pathlib import Path

import pytest

from dwcheck.checks_adr import _accepted_content, _immutable_adrs, check_adr, check_adr_history
from dwcheck.checks_links import check_links
from dwcheck.checks_manifests import (
    check_crates,
    check_lockfile_closure,
    check_python_dependencies,
)
from dwcheck.checks_python import check_python_imports, check_text
from dwcheck.checks_version import check_version
from dwcheck.cli import main
from dwcheck.config import ArchitectureConfig, load

REPO_ROOT = Path(__file__).resolve().parents[2]
RULES = REPO_ROOT / "architecture.toml"
VIOLATIONS = REPO_ROOT / "tests" / "architecture" / "fixtures" / "violations"


def _all_findings(config: ArchitectureConfig) -> list[str]:
    findings = [
        *check_python_imports(config),
        *check_text(config),
        *check_python_dependencies(config),
        *check_crates(config),
        *check_lockfile_closure(config),
        *check_links(config.root, config.docs_exempt_paths),
        *check_adr(config),
        *check_version(config),
    ]
    return [f.rule for f in findings]


@pytest.fixture(scope="module")
def violation_rules() -> list[str]:
    return _all_findings(load(VIOLATIONS, RULES))


def _declared_rule_ids() -> list[str]:
    raw = tomllib.loads(RULES.read_text(encoding="utf-8"))
    ids: list[str] = []
    for section in ("python_rules", "text_rules", "dependency_rules", "crate_rules"):
        for rule in raw.get(section, []):
            ids.append(str(rule["id"]))
    return ids


# --- the repository itself passes -----------------------------------------


def test_the_repository_passes_every_check() -> None:
    assert main(["--root", str(REPO_ROOT), "all"]) == 0


# --- every declared rule is capable of firing ------------------------------


@pytest.mark.parametrize("rule_id", _declared_rule_ids())
def test_each_declared_rule_rejects_its_violation(rule_id: str, violation_rules: list[str]) -> None:
    """A rule that never fires against the fixture is a rule that does nothing.

    If you are adding a rule, add the violation it is meant to catch to
    tests/architecture/fixtures/violations/ in the same commit.
    """
    assert rule_id in violation_rules, (
        f"{rule_id} did not fire against the violation fixture; "
        f"either the rule matches nothing or the fixture does not exercise it"
    )


@pytest.mark.parametrize(
    "rule_id",
    [
        "RS000-workspace",  # a crate directory outside the workspace
        "RS004-authority-dependency-allowlist",  # TCB dependency outside the allowlist
        "RS005-workspace-dependency-inheritance",  # per-crate version pin
        "RS006-authority-dependency-closure",  # a TCB dependency arriving transitively
        "RS007-authority-plane-is-undependable",  # a new crate bridging the two daemons
        "RS008-shared-crate-allowlist",  # a helper crate both daemons link
        "RS009-shared-crate-is-a-leaf",  # the shared wire crate linking in-tree code
        "ADR001-accepted-adr-modified",  # an accepted ADR edited after acceptance
        "ADR002-adr-not-recorded",  # an accepted ADR no digest covers
        "ADR003-recorded-adr-missing",  # a digest for an ADR that is gone
        "DOC001-broken-relative-link",
        "DOC002-missing-adr",
        "VER003-version-drift",
    ],
)
def test_built_in_rules_reject_their_violation(rule_id: str, violation_rules: list[str]) -> None:
    """Rules the checker implements directly rather than reading from config."""
    assert rule_id in violation_rules


# --- the specific violations that matter most ------------------------------


def test_broker_cannot_depend_on_authority(violation_rules: list[str]) -> None:
    """ADR-0018: linking authority into the broker would make policy evaluation,
    capability minting and approval matching reachable from the process that is
    supposed to decide nothing."""
    assert "RS002-broker-cannot-reach-authority-internals" in violation_rules


def test_the_tcb_dependency_claim_covers_the_transitive_closure(
    violation_rules: list[str],
) -> None:
    """ADR-0019's claim is about everything linked into `dwkd-authority`, not
    only what its manifest names. Nobody adds an HTTP stack to a TCB on
    purpose; it arrives through something that looked harmless."""
    assert "RS006-authority-dependency-closure" in violation_rules


def test_authority_cannot_depend_on_the_broker(violation_rules: list[str]) -> None:
    """ADR-0018: the split exists so the broker's dependency tree -- a container
    client, TLS, content parsers -- stays out of the address space holding the
    MAC key and the secrets."""
    assert "RS001-authority-depends-on-nothing-in-tree" in violation_rules


def test_cognition_cannot_reach_for_sockets_or_exec(violation_rules: list[str]) -> None:
    """ADR-0000: there is exactly one path from cognition to effect."""
    assert "PY001-runtime-has-no-ambient-effects" in violation_rules


def test_the_eval_harness_cannot_be_imported_by_product_code(
    violation_rules: list[str],
) -> None:
    """M2.5 adds a test-only execution-environment double and a process-control
    harness. Either one imported from the runtime would be a second path from
    cognition to effect wearing test-infrastructure clothes."""
    assert "PY003-product-code-does-not-import-the-eval-harness" in violation_rules


def test_an_agent_framework_is_rejected_in_both_forms(violation_rules: list[str]) -> None:
    """As an import and as a declared dependency -- docs/ARCHITECTURE.md §2."""
    assert "PY002-no-agent-framework-imports" in violation_rules
    assert "DEP001-no-agent-framework-dependency" in violation_rules


def test_provider_names_outside_the_adapter_package_are_rejected(
    violation_rules: list[str],
) -> None:
    """Goal G3: swapping providers changes configuration, not core code."""
    assert "TX001-provider-names-confined" in violation_rules


def test_a_new_crate_cannot_bridge_the_two_daemons(violation_rules: list[str]) -> None:
    """The named direction rules only cover the crates that exist. The way the
    ADR-0018 boundary would actually be lost is a crate added later to share a
    little code between authority and broker, which breaks no named rule
    because no named rule is about it."""
    assert "RS007-authority-plane-is-undependable" in violation_rules


def test_the_wire_contract_crate_cannot_reach_for_effects(violation_rules: list[str]) -> None:
    """dwk-proto is linked into the TCB from M3 and into both daemons. Decoding
    a message must not be able to open a socket, a file or a process."""
    assert "TX002-proto-has-no-ambient-effects" in violation_rules


def test_the_capability_core_cannot_reach_for_effects(violation_rules: list[str]) -> None:
    """The capability core is a pure function of its arguments: parse, compare,
    narrow. A filesystem read there would be the start of the mistake ADR-0037
    exists to prevent -- deciding authority from a path by looking at the path,
    before M4's canonicaliser exists to do it safely. The fixture does exactly
    that, in four lines."""
    assert "TX003-capability-core-has-no-ambient-effects" in violation_rules


def test_capability_core_findings_skip_the_comment_that_names_the_ban() -> None:
    """As for TX002: the module must be able to document what it must not do."""
    findings = [f for f in check_text(load(VIOLATIONS, RULES)) if f.rule.startswith("TX003")]
    assert [f.line for f in findings] == [4], "the doc comment naming std::fs is not a finding"


def test_a_helper_crate_shared_by_both_daemons_is_rejected(violation_rules: list[str]) -> None:
    """RS007 catches a crate that depends on the daemons. It cannot see a crate
    the daemons depend on -- "a few helpers" linked into both -- which is the
    other way the ADR-0018 split erodes. RS008 allows exactly [crates].shared,
    and RS009 keeps each shared crate a leaf so it cannot carry a bridge in."""
    assert "RS008-shared-crate-allowlist" in violation_rules
    assert "RS009-shared-crate-is-a-leaf" in violation_rules


def test_proto_findings_name_only_what_is_linked() -> None:
    """The fixture's dwk-proto dev-depends on proptest. That must not be an
    RS004 finding: dev-dependencies are never linked into the crate."""
    findings = check_crates(load(VIOLATIONS, RULES))
    proto = [f.message for f in findings if f.path == "crates/dwk-proto/Cargo.toml"]
    assert any("serde_json" in m for m in proto), proto
    assert not any("proptest" in m for m in proto), proto
    text = [f for f in check_text(load(VIOLATIONS, RULES)) if f.rule.startswith("TX002")]
    assert [f.line for f in text] == [4], "the doc comment naming std::net is not a finding"


def test_an_edit_to_an_accepted_adr_is_detected(violation_rules: list[str]) -> None:
    """ADRs are the record of what was decided and why. An appended note changes
    that record; it happened once, during M2, to ADR-0019, and no gate caught
    it. The digest manifest is the tripwire for that; the gate is the history
    anchor, which `tools/dwcheck/tests/test_checks.py` covers, because proving
    it needs a repository with a history rather than a fixture directory."""
    assert "ADR001-accepted-adr-modified" in violation_rules


def test_every_accepted_adr_in_this_repository_matches_its_recorded_digest() -> None:
    """The positive case: this repository's own ADRs are unmodified."""
    assert check_adr(load(REPO_ROOT, RULES)) == []


def test_every_accepted_adr_matches_the_revision_that_accepted_it() -> None:
    """The control, on this repository. Skipped where the history is not there
    to check -- a shallow CI checkout, or an unpacked release -- because a
    weaker anchor reported as a pass is the failure this whole check removes.
    The `architecture` CI job checks out at full depth and passes
    `--require-adr-history`, so the skip cannot hide a regression there."""
    findings = check_adr_history(load(REPO_ROOT, RULES), require_history=True)
    if [f.rule for f in findings] == ["ADR007-adr-history-unavailable"]:
        pytest.skip(findings[0].message)
    assert findings == []


def test_the_history_anchor_actually_covers_this_repositorys_adrs() -> None:
    """A check that anchors nothing passes, which is the shape every other test
    here would still be happy with: repoint `[adr].directory` at an empty path
    and ADR001-ADR007 all go quiet. So assert that history really did produce
    anchors, and that they are ADRs from this repository."""
    config = load(REPO_ROOT, RULES)
    assert config.adr.directory == "docs/adr"
    anchored, where = _accepted_content(REPO_ROOT, "HEAD", config.adr.directory)
    if not where:
        pytest.skip("no ADR history here (shallow checkout or unpacked release)")

    on_disk = {path.name for path in _immutable_adrs(config)}
    assert set(anchored) <= on_disk, sorted(set(anchored) - on_disk)
    assert len(anchored) >= 30, (
        f"only {len(anchored)} accepted ADRs are anchored to a revision; "
        f"{len(on_disk)} are accepted on disk"
    )


def test_the_required_boundary_rules_are_all_declared() -> None:
    """Deleting a rule from architecture.toml would otherwise reduce coverage
    silently: every *declared* rule is tested, so a rule that is gone is a rule
    that is no longer tested, and nothing goes red.

    Removing an entry from this list is a deliberate act with a reviewer. See
    CODEOWNERS.
    """
    required = {
        "PY001-runtime-has-no-ambient-effects",
        "PY002-no-agent-framework-imports",
        "PY003-product-code-does-not-import-the-eval-harness",
        "TX001-provider-names-confined",
        "TX002-proto-has-no-ambient-effects",
        "TX003-capability-core-has-no-ambient-effects",
        "DEP001-no-agent-framework-dependency",
        "DEP002-runtime-has-no-transport-dependency",
        "RS001-authority-depends-on-nothing-in-tree",
        "RS002-broker-cannot-reach-authority-internals",
        "RS003-cli-holds-no-authority",
    }
    missing = required - set(_declared_rule_ids())
    assert not missing, f"boundary rules removed from architecture.toml: {sorted(missing)}"


def test_the_authority_dependency_allowlist_is_still_declared() -> None:
    """An empty allowlist is the claim. A *deleted* allowlist is no claim."""
    config = load(REPO_ROOT, RULES)
    assert config.authority_crates == ("dwkd-authority", "dwk-proto")
    assert "dwkd-authority" in config.crates.undependable
    assert "dwkd-broker" in config.crates.undependable
    assert config.crates.shared == ("dwk-proto",)


# --- the checker's own failure modes ---------------------------------------


def test_checker_exits_nonzero_on_the_violation_fixture() -> None:
    exit_code = main(["--root", str(VIOLATIONS), "--rules", str(RULES), "all"])
    assert exit_code == 1


def test_unreadable_rules_file_is_an_error_not_a_pass(tmp_path: Path) -> None:
    """A checker that treats a missing config as "nothing to check" is worse
    than no checker: it reports success."""
    missing = tmp_path / "nope.toml"
    assert main(["--root", str(REPO_ROOT), "--rules", str(missing), "all"]) == 2


def test_unsupported_schema_version_is_an_error(tmp_path: Path) -> None:
    rules = tmp_path / "architecture.toml"
    rules.write_text("schema_version = 999\n", encoding="utf-8")
    assert main(["--root", str(REPO_ROOT), "--rules", str(rules), "all"]) == 2


def test_the_tcb_destined_closure_is_empty() -> None:
    """ADR-0019, as amended by ADR-0033 and ADR-0034: dwkd-authority links
    nothing third-party, and neither does dwk-proto, which it links from M3.

    RS006 fails on a crate outside the allowlist. This pins the claim from the
    other side: if a linked dependency appears, this test names it, and the
    commit that adds it must also add the ADR that justifies it.
    """
    lock = tomllib.loads((REPO_ROOT / "Cargo.lock").read_text(encoding="utf-8"))
    edges = {
        str(p["name"]): [str(d).split(" ", 1)[0] for d in p.get("dependencies", [])]
        for p in lock.get("package", [])
    }
    manifests = {
        "dwkd-authority": REPO_ROOT / "crates/dwkd-authority/Cargo.toml",
        "dwk-proto": REPO_ROOT / "crates/dwk-proto/Cargo.toml",
    }
    linked: set[str] = set()
    for crate, manifest in manifests.items():
        declared = tomllib.loads(manifest.read_text(encoding="utf-8"))
        for section in ("dependencies", "build-dependencies"):
            stack = list(declared.get(section, {}))
            while stack:
                name = stack.pop()
                if name not in linked:
                    linked.add(name)
                    stack.extend(edges.get(name, []))
        assert crate in edges, f"{crate} is missing from Cargo.lock"
    assert linked == set(), f"the TCB-destined closure is no longer empty: {sorted(linked)}"
