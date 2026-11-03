"""R3 under the owner's R-B: no record or document turns E6 into a pass.

On 2026-11-01 the owner selected R-B on ADR-0057: R3 needs real `PROXY_ONLY`
containers weakened one hard rule at a time, measured from both vantages
(ADR-0057's E6), and the residual that record proposed is not accepted. E6 is
BLOCKED -- not built and not planned while an earlier safety control stands --
and nothing else stands in for it. So:

* ADR-0057 is never Accepted -- accepting it would accept the residual R-B
  refused -- and stays outside the accepted digest; its one exit is
  "Superseded by" an accepted record of E6's evidence (ADR-0057 §8);
* while it is Proposed, its own E6 row and the plan's R3 and E6 rows say E6 is
  NOT EXERCISED or BLOCKED, the ROADMAP's M5e heading says R3 is blocked, no
  status document says M5e.2 is COMPLETE, and its limited claim (§5, not
  approved) is not M5's;
* ADR-0056, accepted, stays in the digest at its accepted bytes;
* the owner's one exception to M5e's order (2026-11-03, the plan's §10) moves
  M5e.3 alone: while ADR-0057 stands, no status document claims a later step,
  M5e or M5 complete, the ROADMAP keeps M5e.4-M5e.6 not started, issue #19
  stays cited, and neither `M5e` nor `M5` is an available milestone;
* the two tasks that carry R3's supporting evidence keep their cleanup and
  ownership census -- nothing the evidence made left behind, nothing that
  predates it gone -- and check it before they count a line.

The evidence R-B does not count as E6 is held at its own level by
`test_m5e_attribution.py`. This module reads documents and source and runs
nothing: it is not evidence of containment, and it builds or plans no
container.
"""

from __future__ import annotations

import inspect
import re
import sys
from pathlib import Path

from dwcheck.checks_adr import _digest, _load_manifest, _status

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))
import dw  # noqa: E402  - imported after the path is extended

ADR_DIR = REPO_ROOT / "docs" / "adr"
RESIDUAL = ADR_DIR / "0057-m5e-proxy-only-real-container-evidence-residual.md"
TASK_LIMIT = ADR_DIR / "0056-m5e-cross-run-task-limit-isolation.md"
MANIFEST = ADR_DIR / "accepted.sha256"
PLAN = REPO_ROOT / "docs" / "M5E_ASSURANCE_PLAN.md"
ROADMAP = REPO_ROOT / "docs" / "ROADMAP.md"
README = REPO_ROOT / "README.md"
# Every document that states where M5e.2 stands.
STATUS_DOCUMENTS = (
    README,
    ROADMAP,
    PLAN,
    RESIDUAL,
    REPO_ROOT / "docs" / "SANDBOX.md",
    REPO_ROOT / "docs" / "SECURITY.md",
    REPO_ROOT / "docs" / "EVALS.md",
    REPO_ROOT / "docs" / "M5E2_FINAL_CLOSURE_REVIEW.md",
    ADR_DIR / "README.md",
    REPO_ROOT / "tests" / "README.md",
)
# "M5e.2 COMPLETE", "**M5e.2 is COMPLETE**", "M5e.2 — COMPLETE": the
# documents' own way of saying a step closed.
_COMPLETE = re.compile(r"M5e\.2\W{0,4}(?:is\W{1,4})?COMPLETE\b")
# The owner's one exception to M5e's order, as the plan's §10 records it.
_SEQUENCING = "**M5e.3's sequencing (2026-11-03).**"
ISSUE_19 = "https://github.com/Onwcan/DireWolf/issues/19"
# A step after M5e.3, M5e itself or M5 said to be closed: "M5e.6 COMPLETE",
# "**M5e — COMPLETE**", "M5 · Sandbox — **COMPLETE**", "**M5 is COMPLETE**".
_GATE_COMPLETE = re.compile(
    r"\bM5(?:e(?:\.[4-6])?)?(?:\W{1,6}Sandbox)?\W{1,6}(?:is\W{1,4})?COMPLETE\b"
)


def _text(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _manifest() -> dict[str, str]:
    """`docs/adr/accepted.sha256`, read as `dwcheck adr` reads it."""
    recorded = _load_manifest(MANIFEST)
    assert len(recorded) >= 50, "the manifest was not read"
    return recorded


def _row(text: str, marker: str) -> str:
    """The one table row of `text` that contains `marker`."""
    rows = [line for line in text.splitlines() if line.startswith("|") and marker in line]
    assert len(rows) == 1, (marker, len(rows))
    return rows[0]


def test_adr_0057_is_never_accepted_and_stays_outside_the_digest() -> None:
    status = _status(_text(RESIDUAL))
    assert status.startswith(("proposed", "superseded")), (
        f"ADR-0057 reads {status!r}: accepting it would accept the residual the owner's "
        "R-B refused; its one exit is 'Superseded by' a record of E6's evidence (§8 there)"
    )
    if status.startswith("proposed"):
        assert "r-b" in status, "the owner's decision is stated on the status line"
    assert RESIDUAL.name not in _manifest()
    # ADR-0056, accepted, at the bytes it was accepted with.
    assert _status(_text(TASK_LIMIT)).startswith("accepted")
    assert _manifest()[TASK_LIMIT.name] == _digest(TASK_LIMIT)


def test_while_adr_0057_stands_e6_is_never_claimed() -> None:
    status = _status(_text(RESIDUAL))
    if status.startswith("superseded"):
        # Closed only by an accepted record, in the digest, that states E6's
        # evidence -- the governance ADR-0057 §8 names.
        number = re.search(r"adr-(\d{4})", status)
        assert number is not None, status
        successors = sorted(ADR_DIR.glob(f"{number.group(1)}-*.md"))
        assert len(successors) == 1, successors
        assert _status(_text(successors[0])).startswith("accepted")
        assert successors[0].name in _manifest()
        return
    e6 = _row(_text(RESIDUAL), "| E6 |")
    assert "NOT EXERCISED" in e6 and "BLOCKED" in e6, e6
    plan = _text(PLAN)
    r3 = _row(plan, "| R3 | `sandbox-egress-evidence`")
    assert "NOT EXERCISED" in r3 and "BLOCKED" in r3, "the plan's R3 row"
    assert "**BLOCKED**" in _row(plan, "(R3, E6)"), "the plan's local-versus-hosted E6 row"
    heading = next(line for line in _text(ROADMAP).splitlines() if line.startswith("#### M5e "))
    assert "IN PROGRESS" in heading and "blocked" in heading.lower(), heading
    claimed = [
        f"{path.relative_to(REPO_ROOT)}: {found.group(0)!r}"
        for path in STATUS_DOCUMENTS
        for found in _COMPLETE.finditer(_text(path))
    ]
    assert not claimed, f"M5e.2 claimed complete while E6 is blocked: {claimed}"


def test_the_residuals_limited_claim_is_not_m5s() -> None:
    """ADR-0057 §5's wording would limit M5's claim only on the owner's
    acceptance and separate approval, neither given: it appears in no
    statement of M5's contract or status."""
    text = _text(RESIDUAL)
    section = text[text.index("### 5. ") : text.index("### 6. ")]
    quoted = " ".join(
        line.removeprefix(">").strip() for line in section.splitlines() if line.startswith(">")
    )
    first = quoted.split(". ")[0]
    assert first.startswith("Weakened-profile closure for `PROXY_ONLY` is shown"), first
    for path in (ROADMAP, README, PLAN, REPO_ROOT / "docs" / "SANDBOX.md"):
        flat = " ".join(_text(path).split())
        assert first not in flat, f"{path.name} states ADR-0057's unapproved limited claim"
    # The test of the pattern itself: it finds the claim it exists to refuse.
    assert _COMPLETE.search("**M5e.2 is COMPLETE**")
    assert _COMPLETE.search("M5e.2 — COMPLETE")
    assert not _COMPLETE.search("M5e.2 IN PROGRESS, R3 E6 BLOCKED")


def test_the_m5e3_sequencing_exception_moves_m5e3_alone() -> None:
    """The owner's exception of 2026-11-03 lets M5e.3's fixture work proceed
    while M5e.2 is open, and changes nothing else. While ADR-0057 stands: the
    plan records it once, among the owner's decisions; no status document
    claims a later step, M5e or M5 complete; the ROADMAP's M5e heading keeps
    M5e.4-M5e.6 not started; the plan's current status line and the ROADMAP's
    "Still to do" cite issue #19; and neither `M5e` nor `M5` is an available
    milestone, so no eval that waits for M5's gate turns on."""
    from direwolf_evals.runner import AVAILABLE_MILESTONES

    if _status(_text(RESIDUAL)).startswith("superseded"):
        return
    plan = _text(PLAN)
    decisions = plan[plan.index("## 10. ") : plan.index("## 11. ")]
    assert plan.count(_SEQUENCING) == 1, "the exception has one record"
    assert _SEQUENCING in decisions, "the exception is recorded among the owner's decisions"
    claimed = [
        f"{path.relative_to(REPO_ROOT)}: {found.group(0)!r}"
        for path in STATUS_DOCUMENTS
        for found in _GATE_COMPLETE.finditer(_text(path))
    ]
    assert not claimed, f"a later step, M5e or M5 claimed complete while E6 is blocked: {claimed}"
    roadmap = _text(ROADMAP)
    section = roadmap[roadmap.index("#### M5e ") : roadmap.index("#### The M5 contract")]
    heading = section.splitlines()[0]
    assert "M5e.4\N{EN DASH}M5e.6 not started" in heading, heading
    todo = section[section.index("\nStill to do: ") :]
    assert ISSUE_19 in todo[: todo.index("\n\n")], "the ROADMAP's 'Still to do' cites issue #19"
    current = [line for line in plan.splitlines() if line.startswith("**Status (")][-1]
    assert ISSUE_19 in current, "the plan's current status line cites issue #19"
    assert not {"M5e", "M5"} & AVAILABLE_MILESTONES, sorted(AVAILABLE_MILESTONES)
    # The test of the pattern itself: it finds the claims it exists to refuse,
    # and none of the steps that may close.
    for claim in (
        "M5e.6 COMPLETE",
        "**M5e — COMPLETE**",
        "M5 \N{MIDDLE DOT} Sandbox — **COMPLETE**",
        "**M5 is COMPLETE**",
    ):
        assert _GATE_COMPLETE.search(claim), claim
    for allowed in ("M5e.1 COMPLETE", "M5e.3 COMPLETE", "M5a — COMPLETE", "M5 is complete only"):
        assert not _GATE_COMPLETE.search(allowed), allowed


def test_the_r3_tasks_check_their_census_before_they_count_a_line() -> None:
    """E1-E4's real runtime runs in the foundation and egress tasks: each
    takes the runtime's census after its suites whatever happened (`finally`),
    fails on a container the evidence left or one that predated it and is
    gone, and only then reads the evidence -- so a passing line never comes
    from a run that left something behind or touched what was not its own."""
    for task in (dw.task_sandbox_foundation_evidence, dw.task_sandbox_egress_evidence):
        source = inspect.getsource(task)
        # The census before the real suites run, again after them whatever
        # happened, and both judged before their lines are read.
        census = "_runtime_state(client, socket)" if "egress" in task.__name__ else "before = set("
        suites = source.index("for package, test, names in (")
        finally_at = source.index("    finally:\n", suites)
        left = source.index("the evidence left {len(left)} container(s)")
        gone = source.index("that predate the evidence are")
        counted = source.index('require_attributed_evidence("\\n".join(outputs)')
        assert source.index(census) < suites < finally_at, task.__name__
        assert finally_at < left < counted, task.__name__
        assert finally_at < gone < counted, task.__name__
        assert re.search(r"if left\b", source) and re.search(r"if removed\b", source)
