"""F-12's deferred `require_artifact_capture` stays discoverable, and is never
represented as built.

F-12 (ADR-0066, Proposed) left the obligation unenforceable: BALANCED's
`allow-workspace-write` carries it for `fs.write` and `fs.create`, and the
authority refuses both `OBLIGATION_UNENFORCEABLE`. The roadmap tracks the
dependency where the storage milestone is planned (M8) without moving the
full artifact system out of M12, and the owner's choice between them stays
open. These checks keep that true as the roadmap is edited: the note cannot
be dropped, softened into a completed claim, or silently reassign M12's
scope; the pack keeps its obligation; ARTIFACTS.md says the store is not
built.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
ROADMAP = REPO_ROOT / "docs" / "ROADMAP.md"


def _read(path: Path) -> str:
    return path.read_bytes().decode("utf-8")


def _section(title: str) -> str:
    """One `### ` section of the roadmap, up to the next heading of its level
    or above."""
    text = _read(ROADMAP)
    start = text.index(f"\n### {title}")
    end = re.search(r"\n#{2,3} ", text[start + 1 :])
    return text[start : start + 1 + end.start()] if end else text[start:]


def test_m8_tracks_the_capture_obligation_and_its_open_decision() -> None:
    m8 = _section("M8 · Storage, events, run state machine")
    for needed in (
        "F-12",
        "`require_artifact_capture`",
        "`allow-workspace-write`",
        "`fs.write`",
        "`fs.create`",
        "`OBLIGATION_UNENFORCEABLE`",
        "kernel-owned storage, quotas, retention, redaction, provenance, an authorised reader",
        "crash-safe binding to the filesystem effect",
        "M12",
        "owner decision not yet made",
        "option (b) is not approved",
        "Nothing in this milestone's plan implements a capture",
        "F12_POLICY_PACK_USABILITY.md",
        "adr/0066-f12-host-path-anchors-are-placed-by-identity.md",
    ):
        assert needed in m8, needed
    heading = m8.strip().splitlines()[0]
    assert "COMPLETE" not in heading, "M8 is not complete"


def test_m12_keeps_the_full_artifact_system_and_points_at_m8() -> None:
    m12 = _section("M12 · Artifacts")
    assert "CAS with kernel-side creation and quarantine" in m12, "M12's scope was moved"
    assert "the full artifact system stays here" in m12
    assert "`require_artifact_capture`" in m12
    assert "under M8 above" in m12
    assert "`OBLIGATION_UNENFORCEABLE`" in m12


def test_the_pack_keeps_the_obligation_and_no_document_calls_the_store_built() -> None:
    balanced = _read(REPO_ROOT / "policy" / "balanced.toml")
    rule = balanced[balanced.index('id     = "allow-workspace-write"') :]
    rule = rule[: rule.index("[[rule]]")] if "[[rule]]" in rule else rule
    assert 'when.verb       = ["fs.write", "fs.create"]' in rule
    assert 'obligations = ["require_artifact_capture"]' in rule
    artifacts = _read(REPO_ROOT / "docs" / "ARTIFACTS.md")
    assert "**Status: specified, not built.**" in artifacts
    report = _read(REPO_ROOT / "docs" / "F12_POLICY_PACK_USABILITY.md")
    assert "ARTIFACT CAPTURE DEFERRED TO M8" in report
    assert "`RequireArtifactCapture` stays\nunenforceable" in report
