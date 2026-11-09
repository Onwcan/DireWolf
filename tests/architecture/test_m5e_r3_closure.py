"""R3 under the owner's R-B: no record or document turns E6 into a pass early.

On 2026-11-01 the owner selected R-B on ADR-0057: R3 needs real `PROXY_ONLY`
containers weakened one hard rule at a time, measured from both vantages
(ADR-0057's E6), and the residual that record proposed is not accepted. E6 was
BLOCKED -- not built and not planned while an earlier safety control stood --
until the owner authorised its implementation on 2026-11-08. It was built
(ADR-0058), its required hosted job passed at `14405ab` after ADR-0059's fix
(run 42525106398), and on 2026-11-09 the owner accepted ADR-0059 and ADR-0058,
ADR-0057 superseded by ADR-0058; nothing else stood in for it. So:

* ADR-0057 is never Accepted -- accepting it would accept the residual R-B
  refused. While it stands (Proposed, R-B on its status line) it stays outside
  the accepted digest; its one exit is "Superseded by" ADR-0058, the accepted
  record of E6's evidence (ADR-0057 §8), which puts it in the digest at its
  bytes, as `dwcheck adr` holds every superseded record -- each with a
  negative control;
* while it is Proposed, its own E6 row and the plan's R3 and E6 rows say E6 is
  NOT EXERCISED -- BLOCKED, or since 2026-11-08 hosted evidence pending -- the
  ROADMAP's M5e heading says R3 is blocked or pending, no status document says
  M5e.2 is COMPLETE or E6 passed, and its limited claim (§5, not approved) is
  not M5's;
* ADR-0058, which states E6's evidence path, stays Proposed and outside the
  digest while ADR-0057 is Proposed -- accepted, it must be ADR-0057's
  successor, ADR-0057 marked "Superseded by" it -- each with a negative
  control;
* ADR-0056, accepted, stays in the digest at its accepted bytes;
* the owner's three exceptions to M5e's order (the plan's §10) move M5e.3
  (2026-11-03), M5e.4 (2026-11-05) and M5e.5's implementation (2026-11-07)
  alone: while ADR-0057 stands, each is recorded once among the owner's
  decisions, M5e.4's saying M5e.5 and M5e.6 were not authorised, M5e.5's that
  neither of its ADRs is accepted, that its evidence joins no required job
  before M5e.4 passes hosted and that M5e.6 is not authorised, and issue #19
  stays cited; and, whether or not ADR-0057 stands -- closing M5e.2 closes
  none of what follows it -- no status document claims M5e.4, M5e.5, M5e.6,
  M5e or M5 complete, or M5e.6 begun, the ROADMAP keeps M5e.6 not started, and
  neither `M5e` nor `M5` is an available milestone -- each held with a
  negative control;
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

import pytest

from dwcheck.checks_adr import _digest, _load_manifest, _status

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))
import dw  # noqa: E402  - imported after the path is extended

ADR_DIR = REPO_ROOT / "docs" / "adr"
RESIDUAL = ADR_DIR / "0057-m5e-proxy-only-real-container-evidence-residual.md"
# E6's evidence path (2026-11-08): the record that supersedes ADR-0057 only on
# the owner's acceptance, after its hosted evidence passes.
E6_PATH = ADR_DIR / "0058-m5e-proxy-only-hard-rules-weakened-in-a-real-environment.md"
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
    E6_PATH,
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
# E6 or R3 said to have passed: "E6 PASSED", "**E6 — VERIFIED**", "R3 is MET".
_E6_PASSED = re.compile(
    r"\b(?:E6|R3)\W{1,6}(?:is\W{1,4})?(?:PASS(?:ED)?|VERIFIED|HOSTED[ -]VERIFIED|MET|SATISFIED)\b"
)
# What E6's row may say while ADR-0057 stands: not yet, blocked or pending.
_NOT_YET = re.compile(r"BLOCKED|HOSTED EVIDENCE PENDING")
# The owner's exceptions to M5e's order, as the plan's §10 records them.
_SEQUENCING = "**M5e.3's sequencing (2026-11-03).**"
_SEQUENCING_M5E4 = "**M5e.4's sequencing (2026-11-05).**"
_SEQUENCING_M5E5 = "**M5e.5's sequencing (2026-11-07).**"
# What M5e.5's record must keep saying: implementation, not acceptance; M5e.4
# first in CI; M5e.6 still waiting; R-B and issue #19.
_M5E5_RECORD_SAYS = (
    "ADR-0054 and ADR-0055 stay Proposed",
    "it accepts neither",
    "joins no job `ci` requires before M5e.4's repair passes hosted",
    "M5e.6 is not authorised",
    "R-B",
)
ISSUE_19 = "https://github.com/Onwcan/DireWolf/issues/19"
# A step after M5e.3, M5e itself or M5 said to be closed: "M5e.6 COMPLETE",
# "**M5e — COMPLETE**", "M5 · Sandbox — **COMPLETE**", "**M5 is COMPLETE**".
_GATE_COMPLETE = re.compile(
    r"\bM5(?:e(?:\.[4-6])?)?(?:\W{1,6}Sandbox)?\W{1,6}(?:is\W{1,4})?COMPLETE\b"
)
# A step no exception covers said to have begun: "M5e.6 is IN PROGRESS",
# "**M5e.6 — STARTED**", "M5e.6 AUTHORISED". M5e.5's implementation is
# authorised (2026-11-07), so it may be IN PROGRESS; never COMPLETE.
_LATER_STARTED = re.compile(
    r"\bM5e\.6\W{1,6}(?:is\W{1,4})?(?:IN PROGRESS|STARTED|BUILT|AUTHORI[SZ]ED)\b"
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


# ADR-0057's two lawful status lines, up to the line's first `·`: standing
# under the owner's R-B, and superseded by ADR-0058.
_STANDING = "**Status:** Proposed — the owner selected **R-B** on 2026-11-01 (§8)"
_SUPERSEDED = (
    "**Status:** **Superseded by "
    "[ADR-0058](0058-m5e-proxy-only-hard-rules-weakened-in-a-real-environment.md)**"
)


def _with_status(text: str, status: str) -> str:
    """`text` with its status, up to the status line's first `·`, replaced."""
    changed, found = re.subn(
        r"^\*\*Status:\*\*[^·\n]*", lambda _: f"{status} ", text, count=1, flags=re.MULTILINE
    )
    assert found == 1, "the record has no status line"
    return changed


def _residual_problems(residual: str, recorded: dict[str, str], digest: str) -> list[str]:
    """ADR-0057 against the accepted digest. Never Accepted. While it stands --
    Proposed, the owner's R-B on its status line -- outside the digest. Once
    superseded, by ADR-0058 and no other record, inside it at `digest`, its
    bytes: `dwcheck adr` holds a superseded record as immutable as an accepted
    one, and `dwcheck adr --record` records it."""
    status = _status(residual)
    problems: list[str] = []
    if status.startswith("proposed"):
        if "r-b" not in status:
            problems.append("the owner's R-B is not stated on ADR-0057's status line")
        if RESIDUAL.name in recorded:
            problems.append("ADR-0057 is in the accepted digest while it stands")
    elif status.startswith("superseded"):
        if "adr-0058" not in status:
            problems.append(f"ADR-0057 is superseded by another record: {status!r}")
        if recorded.get(RESIDUAL.name) != digest:
            problems.append("ADR-0057, superseded, is not in the accepted digest at its bytes")
    else:
        problems.append(
            f"ADR-0057 reads {status!r}: accepting it would accept the residual the owner's "
            "R-B refused; its one exit is 'Superseded by' a record of E6's evidence (§8 there)"
        )
    return problems


def test_adr_0057_is_never_accepted_and_in_the_digest_only_once_superseded() -> None:
    problems = _residual_problems(_text(RESIDUAL), _manifest(), _digest(RESIDUAL))
    assert not problems, problems
    # ADR-0056, accepted, at the bytes it was accepted with.
    assert _status(_text(TASK_LIMIT)).startswith("accepted")
    assert _manifest()[TASK_LIMIT.name] == _digest(TASK_LIMIT)


@pytest.mark.parametrize(
    ("change", "said"),
    [
        ("accepted", "accepting it would accept the residual"),
        ("standing-without-r-b", "the owner's R-B is not stated"),
        ("standing-in-the-digest", "in the accepted digest while it stands"),
        ("superseded-outside-the-digest", "not in the accepted digest at its bytes"),
        ("superseded-at-other-bytes", "not in the accepted digest at its bytes"),
        ("superseded-by-another", "superseded by another record"),
    ],
)
def test_adr_0057_against_the_digest_out_of_turn_fails(change: str, said: str) -> None:
    residual, digest = _text(RESIDUAL), _digest(RESIDUAL)
    standing, superseded = _with_status(residual, _STANDING), _with_status(residual, _SUPERSEDED)
    # The two lawful states, each sound before it is changed.
    assert not _residual_problems(standing, {}, digest)
    assert not _residual_problems(superseded, {RESIDUAL.name: digest}, digest)
    if change == "accepted":
        text, recorded = _with_status(residual, "**Status:** Accepted"), {RESIDUAL.name: digest}
    elif change == "standing-without-r-b":
        text, recorded = _with_status(residual, "**Status:** Proposed"), {}
    elif change == "standing-in-the-digest":
        text, recorded = standing, {RESIDUAL.name: digest}
    elif change == "superseded-outside-the-digest":
        text, recorded = superseded, {}
    elif change == "superseded-at-other-bytes":
        text, recorded = superseded, {RESIDUAL.name: "0" * 64}
    elif change == "superseded-by-another":
        text = _with_status(residual, "**Status:** **Superseded by ADR-0099**")
        recorded = {RESIDUAL.name: digest}
    else:
        raise AssertionError(change)
    problems = _residual_problems(text, recorded, digest)
    assert any(said in problem for problem in problems), (change, problems)


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
    problems = _e6_claim_problems(_text(RESIDUAL), _text(PLAN), _text(ROADMAP), _documents())
    assert not problems, problems


def _e6_claim_problems(
    residual: str, plan: str, roadmap: str, documents: dict[str, str]
) -> list[str]:
    """Every way E6, R3 or M5e.2 would be claimed while ADR-0057 stands."""
    problems: list[str] = []
    e6 = _row(residual, "| E6 |")
    if "NOT EXERCISED" not in e6 or not _NOT_YET.search(e6):
        problems.append(f"ADR-0057's E6 row does not say NOT EXERCISED: {e6[:120]}")
    r3 = _row(plan, "| R3 | `sandbox-egress-evidence`")
    if "NOT EXERCISED" not in r3 or not _NOT_YET.search(r3):
        problems.append("the plan's R3 row does not say E6 is NOT EXERCISED")
    hosted = _row(plan, "(R3, E6)")
    if "**BLOCKED**" not in hosted and "**HOSTED EVIDENCE PENDING**" not in hosted:
        problems.append("the plan's local-versus-hosted E6 row does not say not yet")
    heading = next(line for line in roadmap.splitlines() if line.startswith("#### M5e "))
    if "IN PROGRESS" not in heading or not re.search(r"blocked|pending", heading.lower()):
        problems.append(f"the ROADMAP's M5e heading: {heading[:120]}")
    for name, text in documents.items():
        for found in _COMPLETE.finditer(text):
            problems.append(f"{name}: M5e.2 claimed complete: {found.group(0)!r}")
        for found in _E6_PASSED.finditer(text):
            problems.append(f"{name}: E6 or R3 claimed passed: {found.group(0)!r}")
    return problems


@pytest.mark.parametrize(
    ("change", "said"),
    [
        ("e6-row-passed", "ADR-0057's E6 row"),
        ("r3-row-passed", "the plan's R3 row"),
        ("hosted-row-passed", "local-versus-hosted"),
        ("heading-done", "the ROADMAP's M5e heading"),
        ("e6-claimed", "E6 or R3 claimed passed"),
        ("r3-claimed", "E6 or R3 claimed passed"),
        ("m5e2-claimed", "M5e.2 claimed complete"),
    ],
)
def test_an_e6_claim_while_adr_0057_stands_fails(change: str, said: str) -> None:
    if _status(_text(RESIDUAL)).startswith("superseded"):
        pytest.skip("ADR-0057 superseded: E6 may be claimed")
    residual, plan, roadmap, documents = _text(RESIDUAL), _text(PLAN), _text(ROADMAP), _documents()
    if change == "e6-row-passed":
        row = _row(residual, "| E6 |")
        residual = residual.replace(row, "| E6 | real weakened containers | `e6-*` | PASS |")
    elif change == "r3-row-passed":
        row = _row(plan, "| R3 | `sandbox-egress-evidence`")
        plan = plan.replace(row, "| R3 | `sandbox-egress-evidence`: all | Hosted — PASS | none |")
    elif change == "hosted-row-passed":
        row = _row(plan, "(R3, E6)")
        plan = plan.replace(row, "| real weakened containers (R3, E6) | runs | passed |")
    elif change == "heading-done":
        heading = next(line for line in roadmap.splitlines() if line.startswith("#### M5e "))
        roadmap = roadmap.replace(heading, "#### M5e · the gate — **IN PROGRESS** (R3 done)")
    elif change == "e6-claimed":
        documents["README.md"] += "\n**E6 PASSED** in the hosted run.\n"
    elif change == "r3-claimed":
        documents["docs/ROADMAP.md"] += "\nR3 is SATISFIED.\n"
    elif change == "m5e2-claimed":
        documents["docs/ROADMAP.md"] += "\n**M5e.2 is COMPLETE**\n"
    problems = _e6_claim_problems(residual, plan, roadmap, documents)
    assert any(said in problem for problem in problems), (change, problems)


def test_adr_0058_stays_proposed_until_it_supersedes_adr_0057() -> None:
    """E6's evidence path is a proposal until the owner accepts it after its
    hosted evidence passes; accepted, it is ADR-0057's successor, and nothing
    else may be."""
    problems = _successor_problems(_text(RESIDUAL), _text(E6_PATH), set(_manifest()))
    assert not problems, problems


def _successor_problems(residual: str, path: str, digest: set[str]) -> list[str]:
    problems: list[str] = []
    status, own = _status(residual), _status(path)
    if "adr-0057" not in path.split("\n", 3)[2].lower():
        problems.append("ADR-0058's status line does not name ADR-0057 as what it would supersede")
    if status.startswith("proposed"):
        if not own.startswith("proposed"):
            problems.append(f"ADR-0058 reads {own!r} while ADR-0057 is Proposed")
        if E6_PATH.name in digest:
            problems.append("ADR-0058 is in the accepted digest while ADR-0057 is Proposed")
    elif own.startswith("accepted") and "adr-0058" not in status:
        problems.append(f"ADR-0058 is accepted but ADR-0057 reads {status!r}")
    return problems


@pytest.mark.parametrize(
    ("change", "said"),
    [
        ("accepted-early", "while ADR-0057 is Proposed"),
        ("digested-early", "in the accepted digest"),
        ("superseded-by-another", "ADR-0057 reads"),
        ("names-no-predecessor", "does not name ADR-0057"),
    ],
)
def test_adr_0058_accepted_out_of_turn_fails(change: str, said: str) -> None:
    # Each control starts where the owner's acceptance started -- ADR-0057
    # standing, ADR-0058 Proposed, neither in the digest -- whatever state the
    # tree is in, and makes one change.
    residual = _with_status(_text(RESIDUAL), _STANDING)
    path = _with_status(_text(E6_PATH), "**Status:** Proposed")
    digest = set(_manifest()) - {RESIDUAL.name, E6_PATH.name}
    assert not _successor_problems(residual, path, digest), "the starting state"
    if change == "accepted-early":
        path = _with_status(path, "**Status:** Accepted")
    elif change == "digested-early":
        digest.add(E6_PATH.name)
    elif change == "superseded-by-another":
        path = _with_status(path, "**Status:** Accepted")
        residual = _with_status(residual, "**Status:** Superseded by ADR-0099")
    elif change == "names-no-predecessor":
        lines = path.split("\n")
        lines[2] = lines[2].replace("ADR-0057", "ADR-0000").replace("0057-", "0000-")
        path = "\n".join(lines)
    problems = _successor_problems(residual, path, digest)
    assert any(said in problem for problem in problems), (change, problems)


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


def _record(decisions: str, marker: str) -> str:
    """The record of the plan's §10 that `marker` opens, its bullets
    included: up to the next paragraph that is not a bullet."""
    start = decisions.index(marker)
    ends = [
        at
        for opener in ("\n\n**", "\n\n`", "\n\n## ")
        if (at := decisions.find(opener, start + len(marker))) >= 0
    ]
    return decisions[start : min(ends, default=len(decisions))]


def _sequencing_problems(
    plan: str, roadmap: str, documents: dict[str, str], available: frozenset[str] | set[str]
) -> list[str]:
    """Every way the owner's three sequencing exceptions would be overstated.

    M5e.3's (2026-11-03) let its fixtures proceed while M5e.2 is open; M5e.4's
    (2026-11-05) lets M5e.4 be implemented and evidenced while M5e.2 is open,
    and authorised nothing after it then; M5e.5's (2026-11-07) authorises
    M5e.5's implementation and accepts neither of its ADRs. While ADR-0057
    stands, then: each is recorded once, among the owner's decisions; M5e.4's
    says M5e.5 and M5e.6 are not authorised; M5e.5's keeps `_M5E5_RECORD_SAYS`;
    the plan's current status line and the ROADMAP's "Still to do" cite issue
    #19; and `_later_step_problems` holds."""
    problems = _later_step_problems(roadmap, documents, available)
    if "## 10. " not in plan or "## 11. " not in plan:
        return [*problems, "the plan has no owner's decisions (§10)"]
    decisions = plan[plan.index("## 10. ") : plan.index("## 11. ")]
    for marker in (_SEQUENCING, _SEQUENCING_M5E4, _SEQUENCING_M5E5):
        if plan.count(marker) != 1:
            problems.append(f"{marker} is recorded {plan.count(marker)} times, not once")
        elif marker not in decisions:
            problems.append(f"{marker} is not among the owner's decisions")
    if decisions.count(_SEQUENCING_M5E4) == 1:
        record = " ".join(_record(decisions, _SEQUENCING_M5E4).split())
        for needed in ("M5e.5 and M5e.6 are not authorised", ISSUE_19, "R-B"):
            if needed not in record:
                problems.append(f"M5e.4's record does not say {needed!r}")
    if decisions.count(_SEQUENCING_M5E5) == 1:
        record = " ".join(_record(decisions, _SEQUENCING_M5E5).split())
        for needed in (*_M5E5_RECORD_SAYS, ISSUE_19):
            if needed not in record:
                problems.append(f"M5e.5's record does not say {needed!r}")
    section = _m5e_section(roadmap)
    if section is not None:
        if "\nStill to do: " not in section:
            problems.append("the ROADMAP's M5e section has no 'Still to do'")
        else:
            todo = section[section.index("\nStill to do: ") :]
            if ISSUE_19 not in todo[: todo.find("\n\n") if "\n\n" in todo else len(todo)]:
                problems.append("the ROADMAP's 'Still to do' does not cite issue #19")
    statuses = [line for line in plan.splitlines() if line.startswith("**Status (")]
    if not statuses or ISSUE_19 not in statuses[-1]:
        problems.append("the plan's current status line does not cite issue #19")
    return problems


def _m5e_section(roadmap: str) -> str | None:
    if "#### M5e " not in roadmap or "#### The M5 contract" not in roadmap:
        return None
    return roadmap[roadmap.index("#### M5e ") : roadmap.index("#### The M5 contract")]


def _later_step_problems(
    roadmap: str, documents: dict[str, str], available: frozenset[str] | set[str]
) -> list[str]:
    """What closing M5e.2 does not change, held whether or not ADR-0057 stands:
    no status document claims M5e.4, M5e.5, M5e.6, M5e or M5 complete, or M5e.6
    begun; the ROADMAP's M5e heading keeps M5e.6 not started; and neither `M5e`
    nor `M5` is an available milestone, so no eval that waits for M5's gate
    turns on. Each of those moves only by its own change, on the owner's
    decision (M5E6_PREPARATION_HANDOFF.md §9), which amends this guard."""
    problems: list[str] = []
    for name, text in documents.items():
        for found in _GATE_COMPLETE.finditer(text):
            problems.append(f"{name}: a later step, M5e or M5 claimed complete: {found.group(0)!r}")
        for found in _LATER_STARTED.finditer(text):
            problems.append(f"{name}: a step no exception covers: {found.group(0)!r}")
    section = _m5e_section(roadmap)
    if section is None:
        problems.append("the ROADMAP has no M5e section")
    elif "M5e.6 not started" not in section.splitlines()[0]:
        problems.append(
            f"the ROADMAP's M5e heading does not keep M5e.6 not started: {section.splitlines()[0]}"
        )
    if {"M5e", "M5"} & set(available):
        problems.append(f"M5e or M5 is an available milestone: {sorted(available)}")
    return problems


def _documents() -> dict[str, str]:
    return {str(path.relative_to(REPO_ROOT).as_posix()): _text(path) for path in STATUS_DOCUMENTS}


def test_the_sequencing_exceptions_move_m5e3_and_m5e4_alone() -> None:
    """The owner's two exceptions to M5e's order -- M5e.3's fixtures
    (2026-11-03) and M5e.4's implementation (2026-11-05) -- each move one step
    ahead of M5e.2's close and change nothing else (`_sequencing_problems`).
    Once ADR-0057 is superseded M5e.2 is closed and the exceptions to its order
    bind no more; what follows it is unchanged by its closing
    (`_later_step_problems`)."""
    from direwolf_evals.runner import AVAILABLE_MILESTONES

    if _status(_text(RESIDUAL)).startswith("superseded"):
        problems = _later_step_problems(_text(ROADMAP), _documents(), AVAILABLE_MILESTONES)
    else:
        problems = _sequencing_problems(
            _text(PLAN), _text(ROADMAP), _documents(), AVAILABLE_MILESTONES
        )
    assert not problems, problems
    # The test of the patterns themselves: they find the claims they exist to
    # refuse, and none of what may be said.
    for claim in (
        "M5e.4 COMPLETE",
        "**M5e.4 is COMPLETE**",
        "M5e.6 COMPLETE",
        "**M5e — COMPLETE**",
        "M5 \N{MIDDLE DOT} Sandbox — **COMPLETE**",
        "**M5 is COMPLETE**",
    ):
        assert _GATE_COMPLETE.search(claim), claim
    for allowed in (
        "M5e.1 COMPLETE",
        "M5e.3 COMPLETE",
        "M5a — COMPLETE",
        "M5 is complete only",
        "M5e.4 is IN PROGRESS",
        "M5e.4's implementation is complete, its hosted verification pending",
    ):
        assert not _GATE_COMPLETE.search(allowed), allowed
    for started in ("M5e.6 is IN PROGRESS", "**M5e.6 — STARTED**", "M5e.6 AUTHORISED"):
        assert _LATER_STARTED.search(started), started
    for allowed in (
        "M5e.5 is IN PROGRESS",
        "M5e.5\N{EN DASH}M5e.6 NOT STARTED",
        "M5e.6 NOT STARTED",
        "M5e.5 and M5e.6 are not authorised",
    ):
        assert not _LATER_STARTED.search(allowed), allowed
    for claim in ("M5e.5 COMPLETE", "**M5e.5 is COMPLETE**"):
        assert _GATE_COMPLETE.search(claim), claim


def _weakened(change: str, *, standing: bool = True) -> list[str]:
    """`_sequencing_problems` over the real documents, with `change` made --
    `_later_step_problems` alone once ADR-0057 no longer stands."""
    plan, roadmap, documents = _text(PLAN), _text(ROADMAP), _documents()
    available: set[str] = set()
    m5e4 = _record(plan[plan.index("## 10. ") :], _SEQUENCING_M5E4)
    m5e5 = _record(plan[plan.index("## 10. ") :], _SEQUENCING_M5E5)
    if change == "m5e4-record-missing":
        plan = plan.replace(_SEQUENCING_M5E4, "**A decision.**")
    elif change == "m5e4-record-twice":
        plan = plan.replace("## 11. ", f"{_SEQUENCING_M5E4}\n\n## 11. ", 1)
    elif change == "m5e4-record-outside-the-decisions":
        plan = plan.replace(m5e4, "").replace("## 6. ", f"{m5e4}\n\n## 6. ", 1)
    elif change == "m5e5-authorised-silently":
        silent = re.sub(r"M5e\.5 and M5e\.6 are not\s+authorised", "M5e.5 may follow", m5e4)
        assert silent != m5e4, "the negative control changed nothing"
        plan = plan.replace(m5e4, silent)
    elif change == "m5e6-started":
        documents["docs/ROADMAP.md"] += "\n**M5e.6 is IN PROGRESS.**\n"
    elif change == "m5e5-claimed-complete":
        documents["docs/ROADMAP.md"] += "\n**M5e.5 is COMPLETE**\n"
    elif change == "m5e5-record-missing":
        plan = plan.replace(_SEQUENCING_M5E5, "**A decision.**")
    elif change == "m5e5-accepts-its-adrs":
        accepted = m5e5.replace("it accepts neither", "it accepts both")
        assert accepted != m5e5, "the negative control changed nothing"
        plan = plan.replace(m5e5, accepted)
    elif change == "m5e5-required-before-m5e4":
        early = re.sub(
            r"joins no job `ci` requires before\s+M5e\.4's repair passes hosted",
            "is required",
            m5e5,
        )
        assert early != m5e5, "the negative control changed nothing"
        plan = plan.replace(m5e5, early)
    elif change == "m5e5-authorises-m5e6":
        m5e6 = re.sub(r"M5e\.6 is not\s+authorised", "M5e.6 may follow", m5e5)
        assert m5e6 != m5e5, "the negative control changed nothing"
        plan = plan.replace(m5e5, m5e6)
    elif change == "m5e4-claimed-complete":
        documents["README.md"] += "\n**M5e.4 is COMPLETE**\n"
    elif change == "heading-drops-m5e6":
        # The M5e heading's own words, not the first that read so elsewhere.
        heading = roadmap[roadmap.index("#### M5e ") :].split("\n", 1)[0]
        dropped = heading.replace("M5e.6 not started", "M5e.6 begun")
        assert dropped != heading, "the negative control changed nothing"
        roadmap = roadmap.replace(heading, dropped, 1)
    elif change == "issue-19-dropped":
        roadmap = roadmap.replace(ISSUE_19, "https://example.invalid/elsewhere")
    elif change == "milestone-available":
        available = {"M5e"}
    else:
        raise AssertionError(change)
    if not standing:
        return _later_step_problems(roadmap, documents, available)
    return _sequencing_problems(plan, roadmap, documents, available)


# The controls `_later_step_problems` must refuse, whether or not ADR-0057
# stands; the others are of the exceptions' records, which bind only while it
# does.
_LATER_STEP_CHANGES = frozenset(
    {
        "m5e6-started",
        "m5e4-claimed-complete",
        "m5e5-claimed-complete",
        "heading-drops-m5e6",
        "milestone-available",
    }
)


@pytest.mark.parametrize(
    ("change", "said"),
    [
        ("m5e4-record-missing", "recorded 0 times"),
        ("m5e4-record-twice", "recorded 2 times"),
        ("m5e4-record-outside-the-decisions", "not among the owner's decisions"),
        ("m5e5-authorised-silently", "M5e.5 and M5e.6 are not authorised"),
        ("m5e6-started", "a step no exception covers"),
        ("m5e4-claimed-complete", "claimed complete"),
        ("m5e5-claimed-complete", "claimed complete"),
        ("m5e5-record-missing", "recorded 0 times"),
        ("m5e5-accepts-its-adrs", "it accepts neither"),
        ("m5e5-required-before-m5e4", "joins no job"),
        ("m5e5-authorises-m5e6", "M5e.6 is not authorised"),
        ("heading-drops-m5e6", "M5e.6 not started"),
        ("issue-19-dropped", "issue #19"),
        ("milestone-available", "available milestone"),
    ],
)
def test_an_overstated_sequencing_fails(change: str, said: str) -> None:
    standing = not _status(_text(RESIDUAL)).startswith("superseded")
    if not standing and change not in _LATER_STEP_CHANGES:
        pytest.skip("ADR-0057 superseded: the exceptions' records no longer bind")
    problems = _weakened(change, standing=standing)
    assert any(said in problem for problem in problems), (change, problems)


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
