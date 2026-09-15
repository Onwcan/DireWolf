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
        "TX001-provider-names-confined",
        "TX002-proto-has-no-ambient-effects",
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


def test_the_tcb_destined_closure_is_exactly_the_reviewed_set() -> None:
    """ADR-0019 as amended by ADR-0033: dwkd-authority links nothing third-party
    today, and dwk-proto -- which it links from M3 -- links exactly
    unicode-normalization and its two small dependencies.

    RS006 already fails on an unlisted crate. This pins the set from the other
    side, so that *removing* an allowlist entry or silently growing it in the
    same commit is also visible. Update it together with ADR-0033.
    """
    lock = tomllib.loads((REPO_ROOT / "Cargo.lock").read_text(encoding="utf-8"))
    edges = {
        str(p["name"]): [str(d).split(" ", 1)[0] for d in p.get("dependencies", [])]
        for p in lock.get("package", [])
    }
    dev_only = {"proptest", "serde_json"}
    seen: set[str] = set()
    stack = ["dwkd-authority", *(d for d in edges["dwk-proto"] if d not in dev_only)]
    while stack:
        name = stack.pop()
        if name not in seen:
            seen.add(name)
            stack.extend(edges.get(name, []))
    assert sorted(seen) == [
        "dwkd-authority",
        "tinyvec",
        "tinyvec_macros",
        "unicode-normalization",
    ]
    assert edges["dwkd-authority"] == [], "dwkd-authority gains its first dependency at M3"
