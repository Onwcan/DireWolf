"""F-16's resolver stays what it is (ADR-0074, Proposed).

**The decided name and no other.** The broker's one production resolver asks
the host's resolver for the absolute name -- the decided name and a trailing
dot -- so no search domain is appended and glibc's `/etc/hosts` lookup does
not answer for it; an answer past its bound is refused whole.

**Shown on a real resolver.** The hostile-resolver test runs in user, mount
and network namespaces the harness starts, with no shell.

**Each guard has a mutant.** `make resolver-mutations` weakens each in turn;
its table must match the source exactly once per mutant.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
BROKER = REPO_ROOT / "crates" / "dwkd-broker" / "src"
RESOLVE = BROKER / "egress" / "resolve.rs"
ADR = REPO_ROOT / "docs" / "adr" / "0074-f16-the-broker-resolves-the-decided-name-and-no-other.md"

sys.path.insert(0, str(REPO_ROOT / "scripts"))

import dw  # noqa: E402  - imported after the path is extended


def _read(path: Path) -> str:
    return path.read_bytes().decode("utf-8")


def test_the_broker_asks_for_the_absolute_name_and_bounds_the_answer() -> None:
    resolve = _read(RESOLVE)
    assert 'let absolute = format!("{name}.");' in resolve
    assert "(absolute.as_str(), 0u16)" in resolve
    assert "pub(crate) const MAX_ANSWER_ADDRESSES: usize = 64;" in resolve
    assert "if answer.len() == MAX_ANSWER_ADDRESSES {" in resolve
    # One production resolver: no other product file resolves a name.
    resolvers = sorted(
        p.relative_to(REPO_ROOT).as_posix()
        for p in BROKER.rglob("*.rs")
        if not p.name.endswith(("tests.rs", "_tests.rs", "harness.rs"))
        and "to_socket_addrs" in _read(p)
    )
    assert resolvers == ["crates/dwkd-broker/src/egress/resolve.rs"], resolvers


def test_the_hostile_resolver_runs_in_namespaces_of_its_own() -> None:
    harness = _read(BROKER / "peer" / "harness.rs")
    assert '["--user", "--map-root-user", "--mount", "--net"]' in harness
    assert "pub(crate) fn under_hostile_resolver(" in harness
    assert "pub(crate) fn install_hostile_resolver(" in harness
    assert '"sh"' not in harness and '"-c"' not in harness
    tests = _read(BROKER / "egress" / "tests.rs")
    assert "fn f16_the_resolver_asks_for_the_decided_name_and_no_other()" in tests
    for case in (
        "f16-search-domain-not-appended",
        "f16-hosts-file-not-consulted",
        "f16-nxdomain-fails",
        "f16-answer-past-the-bound-refused",
        "f16-whole-answer-kept",
        "f16-silent-server-times-out",
    ):
        assert case in tests, case


def test_the_mutation_table_matches_the_source_once_per_mutant() -> None:
    names = [m[0] for m in dw.RESOLVER_MUTATIONS]
    assert [n.split(":")[0] for n in names] == ["R1", "R2", "R3"]
    for what, rel, old, new in dw.RESOLVER_MUTATIONS:
        text = _read(REPO_ROOT / rel)
        assert text.count(old) == 1, what
        assert old != new, what
    assert dw.TASKS["resolver-mutations"] is dw.task_resolver_mutations
    assert [s.name for s in dw._resolver_stages()] == ["broker-resolver"]
    makefile = _read(REPO_ROOT / "Makefile")
    assert "\nresolver-mutations: ## F-16" in makefile
    assert "\t@$(DW) resolver-mutations\n" in makefile
    assert dw.RESOLVER_EVIDENCE_DIR != dw.EGRESS_ALLOWLIST_EVIDENCE_DIR


def test_the_hosted_egress_job_requires_the_namespace_tests_to_run() -> None:
    """The hostile resolver prints NOT EXERCISED wherever unprivileged user
    namespaces are restricted -- every hosted job but this one. Here they are
    lifted first, and `make namespace-evidence` requires every case."""
    ci = _read(REPO_ROOT / ".github" / "workflows" / "ci.yml")
    job = ci[ci.index("\n  sandbox-egress:\n") :]
    job = job[: job.index("\n  sandbox-workload:\n")]
    sysctl = job.index("sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0")
    evidence = job.index("      - run: make namespace-evidence\n")
    assert sysctl < evidence < job.index("      - run: make proxy-peer-evidence\n")
    assert dw.TASKS["namespace-evidence"] is dw.task_namespace_evidence
    makefile = _read(REPO_ROOT / "Makefile")
    assert "\nnamespace-evidence: ## " in makefile
    assert "\t@$(DW) namespace-evidence\n" in makefile
    # Every case the hostile-resolver test prints is required by name.
    (f16,) = [m for t, m in dw.NAMESPACE_EVIDENCE if t.startswith("egress::tests::f16_")]
    tests = _read(BROKER / "egress" / "tests.rs")
    for case in dw._F16_CASES:
        assert f'F16-EVIDENCE {{"case":"{case}"' in f16, case
        assert case in tests, case
    for test, markers in dw.NAMESPACE_EVIDENCE:
        module, _, name = test.rpartition("::")
        source = {
            "egress::tests": BROKER / "egress" / "tests.rs",
            "sandbox::identity_tests": BROKER / "sandbox" / "identity_tests.rs",
            "process::tests": BROKER / "process" / "tests.rs",
        }[module]
        assert f"fn {name}()" in _read(source), test
        assert markers, test


def test_a_namespace_test_that_was_not_exercised_fails_the_task() -> None:
    test, markers = dw.NAMESPACE_EVIDENCE[0]
    ran = "test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 300 filtered out\n"
    full = "\n".join(f"{marker}...}}" for marker in markers) + "\n" + ran
    dw.require_namespace_evidence(full, test, markers)
    for broken, why in (
        ("NOT EXERCISED: unprivileged user, mount and network namespaces\n" + ran, "NOT EXERCISED"),
        (ran, "did not report"),
        (full.replace(markers[-1], "F16-EVIDENCE other"), "did not report"),
        (full.replace("1 passed", "0 passed"), "did not run"),
        (full + ran, "did not run"),
    ):
        with pytest.raises(dw.TaskError, match=why):
            dw.require_namespace_evidence(broken, test, markers)


def test_adr_0074_is_proposed_and_claims_no_dnssec() -> None:
    text = _read(ADR)
    assert text.startswith("# ADR-0074:")
    assert re.search(r"^\*\*Status:\*\* Proposed ", text, re.M)
    for said in ("search domain", "/etc/hosts", "No DNSSEC", "MAX_ANSWER_ADDRESSES"):
        assert said in text, said
    index = _read(REPO_ROOT / "docs" / "adr" / "README.md")
    assert f"[0074]({ADR.name})" in index
    assert ADR.name in _read(REPO_ROOT / "docs" / "NETWORK_SECURITY.md")
