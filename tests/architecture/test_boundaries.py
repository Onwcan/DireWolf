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


def test_the_policy_core_cannot_read_the_environment(violation_rules: list[str]) -> None:
    """A policy rule writes `${WORKSPACE}`, which looks like shell and is not:
    it is a closed symbolic anchor resolved from kernel-owned state. If the
    engine could ask the process environment what it means, whoever sets the
    variable would decide which directory every workspace rule governs -- and
    pinning the workspace root by (dev, ino) at admission exists precisely
    because the NAME can be made to lie. The fixture asks the environment."""
    assert "TX004-policy-core-has-no-ambient-effects" in violation_rules


def test_policy_core_findings_skip_the_comment_that_names_the_ban() -> None:
    """As for TX002 and TX003."""
    findings = [f for f in check_text(load(VIOLATIONS, RULES)) if f.rule.startswith("TX004")]
    lines = [f.line for f in findings]
    assert 3 not in lines, "the doc comment naming std::env is not a finding"
    assert lines, "the fixture must produce at least one TX004 finding"


def test_the_pure_cores_cannot_reach_the_store(violation_rules: list[str]) -> None:
    """M3d's storage stays in the state layer. The fixture's policy module
    imports rusqlite and calls into crate::state."""
    assert "TX005-the-pure-cores-never-touch-the-store" in violation_rules
    findings = [f for f in check_text(load(VIOLATIONS, RULES)) if f.rule.startswith("TX005")]
    lines = sorted(f.line for f in findings)
    assert lines == [4, 9], "the import and the call; never the doc comment naming them"


def test_the_state_layer_builds_no_sql_from_values(violation_rules: list[str]) -> None:
    """ADR-0035: every value is a bound parameter. The fixture splices a table
    name into a statement and asks for its own process id."""
    rule = "TX006-state-sql-is-static-and-the-state-layer-has-no-ambient-effects"
    assert rule in violation_rules
    findings = [f for f in check_text(load(VIOLATIONS, RULES)) if f.rule == rule]
    lines = sorted(f.line for f in findings)
    assert lines == [6, 11], "the format! and std::process; never the doc comment"


def test_the_transport_cannot_become_a_second_authority_engine(
    violation_rules: list[str],
) -> None:
    """TX007 (M3e): a TCP fallback, a call into the policy core and a peek at a
    request's epoch are each a finding in the server module -- and the comment
    that names them is not."""
    rule = "TX007-the-transport-is-an-adapter"
    assert rule in violation_rules
    findings = [f for f in check_text(load(VIOLATIONS, RULES)) if f.rule == rule]
    texts = " ".join(f.message for f in findings)
    assert "TcpListener" in texts and "crate::policy" in texts and "epoch" in texts
    assert all("FIXTURE" not in f.message for f in findings), "a comment line was a finding"


def test_rustix_is_named_only_at_the_reviewed_syscall_boundaries(
    violation_rules: list[str],
) -> None:
    """TX008 (narrowed by ADR-0042): rustix outside `server/peer.rs` and
    `resource/fs/linux/` is a finding -- including in `resource/fs/mod.rs`,
    the portable half of the same resolver, one directory up. The fixture's
    `resource/fs/linux/mod.rs` uses rustix and is NOT a finding, which proves
    the exemption names that file rather than silencing the rule; the
    binary's `use rustix as _;` acknowledgement is not a finding either."""
    rule = "TX008-rustix-only-at-reviewed-syscall-boundaries"
    assert rule in violation_rules
    findings = [f for f in check_text(load(VIOLATIONS, RULES)) if f.rule == rule]
    assert findings and all("as _" not in f.message for f in findings)
    assert {f.path for f in findings} == {
        "crates/dwkd-authority/src/stray_peer.rs",
        "crates/dwkd-authority/src/resource/fs/mod.rs",
    }, sorted({f.path for f in findings})


def test_only_the_state_layer_reaches_the_filesystem_resolver(
    violation_rules: list[str],
) -> None:
    """TX011 (M4a): the policy engine calling `resource::fs` -- by path and by
    a brace import -- is a finding. TX004 bans `std::fs` in the policy core;
    this bans the back door through the one module allowed to look."""
    rule = "TX011-only-the-state-layer-reaches-the-resolver"
    assert rule in violation_rules
    findings = [f for f in check_text(load(VIOLATIONS, RULES)) if f.rule == rule]
    assert sorted((f.path, f.line) for f in findings) == [
        ("crates/dwkd-authority/src/policy/resolve.rs", 6),
        ("crates/dwkd-authority/src/policy/resolve.rs", 9),
    ], "the import and the call; never the doc comment naming them"


def test_the_nfc_crate_is_confined_to_the_name_checker(violation_rules: list[str]) -> None:
    """TX012 (M4a): unicode_normalization named in the policy engine is a
    second canonicaliser. The fixture's `use ... as _;` acknowledgement and
    the fixture's `resource/fs/names.rs`, which may name it, are not findings."""
    rule = "TX012-unicode-normalization-is-confined-to-the-name-checker"
    assert rule in violation_rules
    findings = [f for f in check_text(load(VIOLATIONS, RULES)) if f.rule == rule]
    assert [(f.path, f.line) for f in findings] == [
        ("crates/dwkd-authority/src/policy/fold.rs", 6),
    ]


def test_the_wire_contract_links_no_unicode_database(violation_rules: list[str]) -> None:
    """RS016 (M4a): unicode-normalization is on the authority's allowlist, so
    RS004 is silent about it in dwk-proto -- and RS016 is not. ADR-0034 keeps
    the wire contract free of a Unicode database."""
    rule = "RS016-the-wire-contract-links-no-unicode-database"
    assert rule in violation_rules
    findings = [f for f in check_crates(load(VIOLATIONS, RULES)) if f.rule == rule]
    assert [f.path for f in findings] == ["crates/dwk-proto/Cargo.toml"]
    assert "unicode-normalization" in findings[0].message
    rs004 = [
        f.message
        for f in check_crates(load(VIOLATIONS, RULES))
        if f.rule.startswith("RS004") and f.path == "crates/dwk-proto/Cargo.toml"
    ]
    assert not any("unicode-normalization" in m for m in rs004), rs004


def _paths(rule: str) -> set[str]:
    return {f.path for f in check_text(load(VIOLATIONS, RULES)) if f.rule == rule}


def test_a_second_listener_is_rejected(violation_rules: list[str]) -> None:
    """TX009 (refined by ADR-0043): each daemon listens in exactly one place.

    A second authority listener, a second broker listener, a broker TCP
    listener and a CLI helper daemon are each findings; the broker's reviewed
    `listener.rs` is not -- the exemption names that one file, so a sibling is
    not reviewed by sitting beside it."""
    rule = "TX009-one-listener-per-daemon"
    assert rule in violation_rules
    assert _paths(rule) == {
        "crates/dwkd-authority/src/debug_socket.rs",
        "crates/dwkd-broker/src/second_listener.rs",
        "crates/dwkd-broker/src/tcp.rs",
        "crates/direwolf-cli/src/helper.rs",
    }, sorted(_paths(rule))


def test_the_broker_grows_no_authority_and_no_other_input(violation_rules: list[str]) -> None:
    """TX013 (M4b): DWKP dispatch, a store, a key library, `kernel.db`, a
    process and a TCP socket in the broker are each findings -- and the
    broker's reviewed listener is not."""
    rule = "TX013-the-broker-decides-nothing-records-nothing-and-reaches-nothing"
    assert rule in violation_rules
    findings = [f for f in check_text(load(VIOLATIONS, RULES)) if f.rule == rule]
    texts = " ".join(f.message for f in findings)
    for needle in ("dwkp", "rusqlite", "kernel", "Command", "TcpListener"):
        assert needle in texts, needle
    assert {f.path for f in findings} == {
        "crates/dwkd-broker/src/dispatch.rs",
        "crates/dwkd-broker/src/tcp.rs",
    }


def test_only_the_broker_link_hands_out_a_descriptor(violation_rules: list[str]) -> None:
    """TX014 (M4b): releasing a checked descriptor, or naming `SCM_RIGHTS`,
    outside the broker link is a finding; the fixture's `broker/link.rs`,
    which does both, is not."""
    rule = "TX014-only-the-broker-link-hands-out-a-descriptor"
    assert rule in violation_rules
    findings = [f for f in check_text(load(VIOLATIONS, RULES)) if f.rule == rule]
    assert sorted((f.path, f.line) for f in findings) == [
        ("crates/dwkd-authority/src/state/leak.rs", 5),
        ("crates/dwkd-authority/src/state/leak.rs", 8),
    ], "the release and the SCM_RIGHTS name; never the doc comment"


def test_the_broker_opens_nothing_by_path(violation_rules: list[str]) -> None:
    """TX015 (M4b): a path-based open in the broker is a second canonicaliser;
    the listener, which creates its own lock file, is exempt by name."""
    rule = "TX015-the-broker-reads-only-what-it-is-handed"
    assert rule in violation_rules
    assert _paths(rule) == {"crates/dwkd-broker/src/dispatch.rs"}


def test_the_cognition_side_cannot_name_the_private_channel(violation_rules: list[str]) -> None:
    """TX016 (M4b): the runtime or the CLI naming the private protocol's module
    or its message kinds is a finding."""
    rule = "TX016-the-cognition-side-cannot-name-the-private-channel"
    assert rule in violation_rules
    assert _paths(rule) == {
        "crates/direwolf-cli/src/helper.rs",
        "runtime/src/direwolf/broker_reach.py",
    }


def test_a_new_declaration_means_only_what_the_resolver_found(
    violation_rules: list[str],
) -> None:
    """TX017 (M4b): naming the grammar-only reader of stored grants outside the
    one module that re-reads them is a finding; its doc-comment mention is not."""
    rule = "TX017-a-new-declaration-means-only-what-the-resolver-found"
    assert rule in violation_rules
    findings = [f for f in check_text(load(VIOLATIONS, RULES)) if f.rule == rule]
    assert sorted((f.path, f.line) for f in findings) == [
        ("crates/dwkd-authority/src/state/grammar_grant.rs", 5),
    ]


def test_the_authority_starts_no_process(violation_rules: list[str]) -> None:
    """TX010: no `Command`, and no user switching, anywhere in the authority."""
    rule = "TX010-the-authority-executes-nothing"
    assert rule in violation_rules
    findings = [f for f in check_text(load(VIOLATIONS, RULES)) if f.rule == rule]
    assert all("FIXTURE" not in f.message for f in findings)


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
        "TX004-policy-core-has-no-ambient-effects",
        "TX005-the-pure-cores-never-touch-the-store",
        "TX006-state-sql-is-static-and-the-state-layer-has-no-ambient-effects",
        "TX007-the-transport-is-an-adapter",
        "TX008-rustix-only-at-reviewed-syscall-boundaries",
        "TX009-one-listener-per-daemon",
        "TX010-the-authority-executes-nothing",
        "TX011-only-the-state-layer-reaches-the-resolver",
        "TX012-unicode-normalization-is-confined-to-the-name-checker",
        "TX013-the-broker-decides-nothing-records-nothing-and-reaches-nothing",
        "TX014-only-the-broker-link-hands-out-a-descriptor",
        "TX015-the-broker-reads-only-what-it-is-handed",
        "TX016-the-cognition-side-cannot-name-the-private-channel",
        "TX017-a-new-declaration-means-only-what-the-resolver-found",
        "DEP001-no-agent-framework-dependency",
        "DEP002-runtime-has-no-transport-dependency",
        "RS001-authority-depends-on-nothing-in-tree",
        "RS002-broker-cannot-reach-authority-internals",
        "RS003-cli-holds-no-authority",
        "RS016-the-wire-contract-links-no-unicode-database",
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


def _tcb_linked_closure() -> set[str]:
    """Everything third-party reachable from the authority plane, computed from
    the lockfile independently of `dwcheck`.

    Optional edges the workspace does not enable are skipped, using the same
    reviewed list `dwcheck` uses -- see `[[authority.optional_edges]]` in
    architecture.toml for why the lockfile over-approximates. Reading the list
    rather than hard-coding it means a stale entry shows up as a disagreement
    between this and `cargo tree`, not as a silently wrong assertion.

    The two in-tree authority crates are expanded from their OWN manifests'
    normal and build sections, never from their lock entries: a lock entry
    lists dev-dependencies too, and since M3d links `dwk-proto` into the
    authority, following its lock entry would walk into `serde_json` and the
    derive stack, which test `dwk-proto` and are never linked.

    A lockfile does not record dependency kinds, so the result is the runtime
    closure AND the build-only closure together (M3d's `cc` and friends).
    Separating them is the exact gate's job, from the resolved graph.
    """
    rules = tomllib.loads((REPO_ROOT / "architecture.toml").read_text(encoding="utf-8"))
    excluded = {(e["parent"], e["child"]) for e in rules["authority"].get("optional_edges", [])}
    lock = tomllib.loads((REPO_ROOT / "Cargo.lock").read_text(encoding="utf-8"))
    edges = {
        str(p["name"]): [
            str(d).split(" ", 1)[0]
            for d in p.get("dependencies", [])
            if (str(p["name"]), str(d).split(" ", 1)[0]) not in excluded
        ]
        for p in lock.get("package", [])
    }
    manifests = {
        "dwkd-authority": REPO_ROOT / "crates/dwkd-authority/Cargo.toml",
        "dwk-proto": REPO_ROOT / "crates/dwk-proto/Cargo.toml",
    }
    linked: set[str] = set()
    for crate, manifest in manifests.items():
        declared = tomllib.loads(manifest.read_text(encoding="utf-8"))
        # Target-specific tables count: `[target.'cfg(...)'.dependencies]` is
        # how M3e declares rustix, and a closure that skipped them would miss
        # the peer-credential syscall layer entirely -- a fail-open found by
        # this very test when rustix arrived.
        tables = [declared, *declared.get("target", {}).values()]
        for table in tables:
            for section in ("dependencies", "build-dependencies"):
                stack = [name for name in table.get(section, {}) if name not in manifests]
                while stack:
                    name = stack.pop()
                    if name not in linked:
                        linked.add(name)
                        stack.extend(edges.get(name, []))
        assert crate in edges, f"{crate} is missing from Cargo.lock"
    return linked


def test_the_tcb_destined_closure_equals_the_reviewed_allowlist() -> None:
    """ADR-0019, as amended by ADR-0035 and ADR-0038.

    Until M3c this asserted the closure was EMPTY. M3c links a TOML parser, so
    the claim changes shape -- and it changes to "the closure equals the list
    somebody reviewed", not to "the authority may use dependencies".

    RS006 already fails on a crate in the closure and not in the allowlist.
    This pins the other direction: a stale allowlist entry, for a crate no
    longer linked, is also a finding. An allowlist that drifts away from
    reality stops being a review and becomes a list.
    """
    authority = tomllib.loads((REPO_ROOT / "architecture.toml").read_text(encoding="utf-8"))[
        "authority"
    ]
    runtime = set(authority["allowed_third_party"])
    build = set(authority["allowed_build_third_party"])
    assert not runtime & build, "a crate is either linked or build-only, never both"
    allowlist = runtime | build
    assert _tcb_linked_closure() == allowlist, (
        "the authority's linked closure and its reviewed allowlist disagree; "
        "adding to the closure needs a new ADR amending ADR-0019, and removing "
        "from it needs the allowlist entry removed in the same commit"
    )


def test_the_tcb_closure_has_no_proc_macro_and_only_the_reviewed_native_code() -> None:
    """ADR-0035 section 2 promises the policy parser arrives with "no
    serde_derive, no syn, no quote, no proc-macro2". ADR-0038 records that the
    resolver agreed, and M3d keeps it: the storage and hashing crates bring no
    derive macro either.

    Native code is a different sentence now. Until M3c this asserted there was
    NONE, and said M3d's SQLite would arrive "with its own ADR saying so". It
    has (ADR-0039): the bundled amalgamation behind `libsqlite3-sys`, compiled
    by `cc`, and `libc` where `cpufeatures` needs it. M3e adds the syscall layer
    for peer credentials (ADR-0041): `rustix`, and `linux-raw-sys` beneath it --
    Rust, no C, but the layer that talks to the kernel directly. The assertion
    is that the native, syscall and build-executing set is EXACTLY that -- a
    second C library, a second syscall wrapper, or a second tool that runs a
    compiler, is a new decision and fails here until one is recorded.
    `#![forbid(unsafe_code)]` reaches none of it.
    """
    closure = _tcb_linked_closure()
    proc_macro = {"serde", "serde_derive", "syn", "quote", "proc-macro2"}
    gained = sorted(closure & proc_macro)
    assert not gained, f"the authority's closure gained {gained}"
    native_or_compiler = {
        "cc",
        "libc",
        "libsqlite3-sys",
        "openssl-sys",
        "bindgen",
        "cmake",
        "pkg-config",
        "vcpkg",
        "rustix",
        "linux-raw-sys",
    }
    assert closure & native_or_compiler == {
        "cc",
        "libc",
        "libsqlite3-sys",
        "pkg-config",
        "vcpkg",
        "rustix",
        "linux-raw-sys",
    }, sorted(closure & native_or_compiler)
