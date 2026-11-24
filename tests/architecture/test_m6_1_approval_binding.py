"""M6.1 (ADR-0079, Proposed): the approval binding's record, its mutation
review and its architecture rules agree with the code."""

from __future__ import annotations

import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
BINDING = REPO_ROOT / "crates" / "dwkd-authority" / "src" / "state" / "binding.rs"
ADR = (
    REPO_ROOT
    / "docs"
    / "adr"
    / "0079-the-approval-binding-v1-what-it-binds-and-how-it-is-encoded.md"
)

sys.path.insert(0, str(REPO_ROOT / "scripts"))

import dw  # noqa: E402  - imported after the path is extended

MEMBERS = (
    "schema",
    "verb",
    "resource_identity",
    "canonical_args",
    "workspace",
    "environment_profile",
    "credential_handles",
    "agent",
    "requester",
    "scope",
    "taint_level",
    "privacy_class",
    "obligations",
)


def _read(path: Path) -> str:
    return path.read_bytes().decode("utf-8")


def test_the_mutation_table_matches_the_source_once_per_mutant() -> None:
    text = _read(BINDING)
    names = [m[0] for m in dw.APPROVAL_BINDING_MUTATIONS]
    assert [n.split(":")[0] for n in names] == [f"B{n:02d}" for n in range(1, 44)]
    for what, rel, old, new in dw.APPROVAL_BINDING_MUTATIONS:
        assert rel == "crates/dwkd-authority/src/state/binding.rs", what
        assert text.count(old) == 1, what
        assert old != new, what
    assert dw.TASKS["approval-binding-mutations"] is dw.task_approval_binding_mutations
    assert [s.name for s in dw._approval_binding_stages()] == ["approval-binding"]
    makefile = _read(REPO_ROOT / "Makefile")
    assert "\napproval-binding-mutations: ## M6.1" in makefile
    assert "\t@$(DW) approval-binding-mutations\n" in makefile
    assert [e[0].split(":")[0] for e in dw.APPROVAL_BINDING_EQUIVALENT] == ["E1", "E2"]


def test_every_hashed_member_has_a_mutant_that_drops_it() -> None:
    dropped = {
        old.strip().split(",")[0].strip('("')
        for what, _, old, new in dw.APPROVAL_BINDING_MUTATIONS
        if new == "\n" and what.endswith(" dropped") and old.startswith("\n" + " " * 12 + '("')
    }
    for member in MEMBERS:
        assert member in dropped, member


def test_the_binding_spells_every_member_the_record_names() -> None:
    text = _read(BINDING)
    adr = _read(ADR)
    assert adr.startswith("# ADR-0079:")
    assert "**Status:** Proposed" in adr
    assert 'pub(crate) const SCHEMA: &str = "direwolf.approval.binding.v1";' in text
    for member in MEMBERS:
        assert f'("{member}", ' in text, member
        assert f"`{member}`" in adr, member


def test_the_binding_module_declares_no_caller_before_m6_2() -> None:
    """The production build carries the binding with no caller, said in its
    code -- not hidden behind a call that does nothing."""
    text = _read(BINDING)
    assert "M6.2's request record is its first production caller" in text
    assert "expect(\n        dead_code," in text
