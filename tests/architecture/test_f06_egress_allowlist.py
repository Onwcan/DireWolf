"""F-06's operator egress allowlist stays what it is (ADR-0071, Proposed).

**Every shipped network rule requires it.** Each ALLOW rule of a shipped pack
that can match a network verb also requires `when.destination_allowlisted =
true`, so without the operator's file no pack reaches any destination.

**The authority alone says it.** The input is set in exactly one place, the
state layer's decision function, for every network decision, from the
operator's file (OF-2, ADR-0073); no wire type of `dwk-proto` carries an
allowlist, so no run can supply or widen one. The file is read only through
the trusted operator reader, under its own flag.

**It is a ceiling** (OF-2). The policy evaluator denies every network action
the input does not place inside, whatever a rule said, attributed to a
reserved rule id and reason no policy file may claim; the evaluator has one
caller, so no decision is made around it.

**Each guard has a mutant.** `make egress-allowlist-mutations` weakens each in
turn; its table must match the source exactly once per mutant.
"""

from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
AUTHORITY = REPO_ROOT / "crates" / "dwkd-authority" / "src"
ADR = (
    REPO_ROOT
    / "docs"
    / "adr"
    / "0071-f06-an-operator-egress-allowlist-every-shipped-network-rule-requires.md"
)
CEILING_ADR = (
    REPO_ROOT
    / "docs"
    / "adr"
    / "0073-f06-of2-the-operators-egress-allowlist-is-a-ceiling-every-policy-is-under.md"
)

sys.path.insert(0, str(REPO_ROOT / "scripts"))

import dw  # noqa: E402  - imported after the path is extended

NETWORK_VERBS = {"network.http", "network.https", "network.tcp"}


def _read(path: Path) -> str:
    return path.read_bytes().decode("utf-8")


def _verbs(rule: dict[str, object]) -> set[str]:
    when = rule.get("when", {})
    assert isinstance(when, dict)
    verb = when.get("verb", [])
    if isinstance(verb, str):
        return {verb}
    assert isinstance(verb, list)
    return {str(v) for v in verb}


def test_every_shipped_network_allow_requires_the_operators_allowlist() -> None:
    allowing: dict[str, list[str]] = {}
    for pack in ("safe", "balanced", "power"):
        document = tomllib.loads(_read(REPO_ROOT / "policy" / f"{pack}.toml"))
        for rule in document["rule"]:
            if rule.get("effect") != "ALLOW" or not (_verbs(rule) & NETWORK_VERBS):
                continue
            when = rule["when"]
            assert when.get("destination_allowlisted") is True, (pack, rule["id"])
            allowing.setdefault(pack, []).append(rule["id"])
    assert allowing == {
        "balanced": ["allow-package-registries"],
        "power": ["allow-https-egress"],
    }, allowing


def test_the_predicate_is_a_network_predicate_the_loader_knows() -> None:
    predicate = _read(AUTHORITY / "policy" / "predicate.rs")
    assert 'Self::DestinationAllowlisted => "destination_allowlisted",' in predicate
    assert "Self::IpIn | Self::DestinationAllowlisted => {" in predicate
    assert "pub const ALL: [Self; 16] = [" in predicate
    load = _read(AUTHORITY / "policy" / "load.rs")
    assert '.optional_bool(table, "destination_allowlisted", &member)?' in load


def test_only_the_authority_sets_it_in_its_one_decision_function() -> None:
    setters = sorted(
        p.relative_to(REPO_ROOT).as_posix()
        for p in AUTHORITY.rglob("*.rs")
        if not p.name.endswith(("tests.rs", "_tests.rs", "fixtures.rs", "testing.rs"))
        and ".with_destination_allowlisted(" in _read(p)
    )
    assert setters == ["crates/dwkd-authority/src/state/query.rs"], setters
    query = _read(AUTHORITY / "state" / "query.rs")
    assert ".admits(action.capability(), action.environment())," in query
    egress = _read(AUTHORITY / "state" / "egress_allowlist.rs")
    assert "Environment::Host => EgressScope::NetHttp," in egress
    assert "Environment::Sandbox => EgressScope::Workload," in egress
    # The builders no longer compute it: one place, one answer.
    for builder in (("net_http", "plan.rs"), ("workload_egress.rs",)):
        text = _read(AUTHORITY.joinpath("state", *builder))
        assert ".covers(" not in text and ".admits(" not in text, builder
    # No wire type carries an allowlist or the input: a run cannot say it.
    for path in (REPO_ROOT / "crates" / "dwk-proto" / "src").rglob("*.rs"):
        text = _read(path)
        assert "destination_allowlisted" not in text, path
        assert "egress_allowlist" not in text.lower(), path


def test_the_ceiling_is_the_evaluators_and_no_file_can_claim_it() -> None:
    evaluator = _read(AUTHORITY / "policy" / "eval.rs")
    assert "    egress_ceiling(by_rules(policy, action, context), action)\n" in evaluator
    public = sorted(re.findall(r"^pub (?:const )?fn (\w+)", evaluator, re.M))
    assert public == ["evaluate", "would_require_approval"], public
    policy = _read(AUTHORITY / "policy" / "mod.rs")
    assert 'pub const EGRESS_CEILING: &\'static str = "operator-egress-ceiling";' in policy
    load = _read(AUTHORITY / "policy" / "load.rs")
    assert ".filter(|id| !id.is_egress_ceiling())" in load
    reason = _read(AUTHORITY / "policy" / "reason.rs")
    assert 'Self::OutsideEgressAllowlist => "OUTSIDE_EGRESS_ALLOWLIST",' in reason
    # The evaluator's one caller is the state layer's decision function:
    # no product path decides a network action around the ceiling.
    callers = sorted(
        p.relative_to(REPO_ROOT).as_posix()
        for p in AUTHORITY.rglob("*.rs")
        if p.parent.name != "policy"
        and not p.name.endswith(("tests.rs", "_tests.rs", "fixtures.rs", "testing.rs"))
        and re.search(r"\bevaluate\(", _read(p))
    )
    assert callers == ["crates/dwkd-authority/src/state/query.rs"], callers


def test_the_file_is_read_only_through_the_trusted_operator_reader() -> None:
    server = _read(AUTHORITY / "server" / "mod.rs")
    reader = server[server.index("fn egress_allowlist(") :]
    reader = reader[: reader.index("\n}\n")]
    assert "crate::secret::backend::read_operator_file(" in reader
    assert '"--egress-allowlist",' in reader
    assert "crate::state::egress_allowlist::MAX_FILE_BYTES" in reader
    config = _read(AUTHORITY / "server" / "config.rs")
    assert '"--egress-allowlist" => once(&mut self.egress_allowlist' in config
    assert '"--egress-allowlist must be an absolute path"' in config
    egress = _read(AUTHORITY / "state" / "egress_allowlist.rs")
    # The parser opens nothing: it takes text.
    assert "std::fs" not in egress and "File::open" not in egress
    assert "pub fn parse(text: &str)" in egress


def test_the_mutation_table_matches_the_source_once_per_mutant() -> None:
    names = [m[0] for m in dw.EGRESS_ALLOWLIST_MUTATIONS]
    assert len(names) == len(set(names)) == 19
    assert [n.split(":")[0] for n in names] == [f"G{i}" for i in range(1, 20)]
    for what, rel, old, new in dw.EGRESS_ALLOWLIST_MUTATIONS:
        text = _read(REPO_ROOT / rel)
        assert text.count(old) == 1, what
        assert old != new, what
    assert dw.TASKS["egress-allowlist-mutations"] is dw.task_egress_allowlist_mutations
    assert [s.name for s in dw._egress_allowlist_stages()] == [
        "authority-units",
        "query",
        "serve",
    ]
    makefile = _read(REPO_ROOT / "Makefile")
    assert "\negress-allowlist-mutations: ## F-06" in makefile
    assert "\t@$(DW) egress-allowlist-mutations\n" in makefile
    assert dw.EGRESS_ALLOWLIST_EVIDENCE_DIR != dw.IDENTITY_EVIDENCE_DIR


def test_the_real_broker_evidence_is_required() -> None:
    cases = {case for suite, case in dw.NET_HTTP_CASES if suite == "net-http"}
    bench = _read(REPO_ROOT / "crates" / "dwkd-authority" / "tests" / "net_http_evidence.rs")
    for case in (
        "egress-allowlist-absent-denies",
        "egress-allowlist-cross-origin-hop-denied",
        "egress-allowlist-exact-allows",
        "egress-allowlist-neighbour-denies",
        "egress-allowlist-other-path-denies",
        "egress-allowlist-other-port-denies",
        "egress-allowlist-private-address-still-blocked",
        "of2-operator-policy-absent-denies",
        "of2-operator-policy-cross-origin-hop-denied",
        "of2-operator-policy-deny-rule-kept",
        "of2-operator-policy-exact-allows",
        "of2-operator-policy-neighbour-denies",
        "of2-operator-policy-other-path-denies",
        "of2-operator-policy-other-port-denies",
    ):
        assert case in cases, case
        assert f'"{case}"' in bench, case


def test_adr_0071_is_proposed_and_the_documents_say_what_is_built() -> None:
    text = _read(ADR)
    assert text.startswith("# ADR-0071:")
    assert re.search(r"^\*\*Status:\*\* Proposed ", text, re.M)
    for said in ("--egress-allowlist", "destination_allowlisted", "OF-1", "OF-2", "R12"):
        assert said in text, said
    index = _read(REPO_ROOT / "docs" / "adr" / "README.md")
    assert f"[0071]({ADR.name})" in index
    doc = _read(REPO_ROOT / "docs" / "F06_EGRESS_ALLOWLIST.md")
    rows = re.findall(r"^\| (\d+) \|", doc, re.M)
    assert rows == [str(n) for n in range(1, 31)], rows
    for path in ("NETWORK_SECURITY.md", "POLICY.md", "SECURITY.md", "THREAT_MODEL.md"):
        assert ADR.name in _read(REPO_ROOT / "docs" / path), path


def test_adr_0073_is_proposed_and_the_documents_say_the_ceiling_is_built() -> None:
    text = _read(CEILING_ADR)
    assert text.startswith("# ADR-0073:")
    assert re.search(r"^\*\*Status:\*\* Proposed ", text, re.M)
    for said in ("operator-egress-ceiling", "OUTSIDE_EGRESS_ALLOWLIST", "OF-2", "restart"):
        assert said in text, said
    index = _read(REPO_ROOT / "docs" / "adr" / "README.md")
    assert f"[0073]({CEILING_ADR.name})" in index
    for path in ("F06_EGRESS_ALLOWLIST.md", "NETWORK_SECURITY.md", "POLICY.md"):
        assert CEILING_ADR.name in _read(REPO_ROOT / "docs" / path), path
