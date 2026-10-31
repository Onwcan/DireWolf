"""ADR-0056 (finding F-R8): the task backstop stays derived from the live cap.

`RLIMIT_NPROC` is counted by the kernel per host uid, across every
environment, since all of them run as uid 10001. The owner's Option B makes it
a host-wide backstop, `PIDS_LIMIT * MAX_LIVE_ENVIRONMENTS * 2`, so that every
environment the authority allows at its own bound -- and as many again it does
not count -- leaves room for another environment's probe and workload.

The cap is the authority's (`MAX_LIVE_ENVIRONMENTS`, ADR-0052 §2a), and the
authority does not link the profile's crate (ADR-0047 §5), so the profile
keeps its own copy to size the backstop, and its compile-time assertion can
only see that copy. These tests hold what the compiler cannot: the two copies
equal, the formula the source of truth, the assertion present, the authority's
evidence using the profile's `PIDS_LIMIT`, and the neighbour control's target
in place. Raising the cap alone, or writing the backstop as a bare number,
fails here before any runtime.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
PROFILE = REPO_ROOT / "crates" / "dwk-sandbox-profile" / "src" / "lib.rs"
AUTHORITY = REPO_ROOT / "crates" / "dwkd-authority" / "src" / "state" / "workload.rs"
AUTHORITY_EVIDENCE = REPO_ROOT / "crates" / "dwkd-authority" / "tests" / "sandbox_workload.rs"
RELAY_PLAN = REPO_ROOT / "crates" / "dwkd-broker" / "src" / "sandbox" / "relay_plan.rs"

sys.path.insert(0, str(REPO_ROOT / "scripts"))
import dw  # noqa: E402  - imported after the path is extended

FORMULA = "pub const RLIMIT_NPROC: u64 = PIDS_LIMIT * MAX_LIVE_ENVIRONMENTS * 2;"
ASSERTION = "RLIMIT_NPROC >= 2 * MAX_LIVE_ENVIRONMENTS * PIDS_LIMIT"


def _constant(text: str, pattern: str) -> int | None:
    found = re.findall(pattern, text, re.MULTILINE)
    return int(found[0].replace("_", "")) if len(found) == 1 else None


def backstop_errors(profile: str, authority: str, evidence: str) -> list[str]:
    """What is wrong with the backstop's derivation in these three sources."""
    errors: list[str] = []
    pids = _constant(profile, r"^pub const PIDS_LIMIT: u64 = ([0-9_]+);$")
    cap = _constant(profile, r"^pub const MAX_LIVE_ENVIRONMENTS: u64 = ([0-9_]+);$")
    their_cap = _constant(
        authority, r"^pub\(super\) const MAX_LIVE_ENVIRONMENTS: i64 = ([0-9_]+);$"
    )
    their_pids = _constant(evidence, r"^    const PIDS_LIMIT: u64 = ([0-9_]+);$")
    if pids is None:
        errors.append("the profile has no single PIDS_LIMIT")
    if cap is None:
        errors.append("the profile has no single MAX_LIVE_ENVIRONMENTS")
    if their_cap is None:
        errors.append("the authority has no single MAX_LIVE_ENVIRONMENTS")
    if cap is not None and their_cap is not None and cap != their_cap:
        errors.append(
            f"the authority allows {their_cap} live environments, the backstop is sized for {cap}"
        )
    if pids is not None and their_pids is not None and pids != their_pids:
        errors.append(f"the authority's evidence counts {their_pids} tasks, the profile {pids}")
    if their_pids is None:
        errors.append("the authority's evidence has no single PIDS_LIMIT")
    if profile.count(FORMULA) != 1:
        errors.append("RLIMIT_NPROC is not derived as PIDS_LIMIT * MAX_LIVE_ENVIRONMENTS * 2")
    if len(re.findall(r"^pub const RLIMIT_NPROC\b", profile, re.MULTILINE)) != 1:
        errors.append("RLIMIT_NPROC is defined other than once")
    if not re.search(
        r"^const _: \(\) = assert!\(\s*" + re.escape(ASSERTION), profile, re.MULTILINE
    ):
        errors.append("the compile-time assertion of the backstop is gone")
    return errors


def _sources() -> tuple[str, str, str]:
    return (
        PROFILE.read_text(encoding="utf-8"),
        AUTHORITY.read_text(encoding="utf-8"),
        AUTHORITY_EVIDENCE.read_text(encoding="utf-8"),
    )


def test_the_backstop_is_derived_from_the_cap_the_authority_enforces() -> None:
    assert backstop_errors(*_sources()) == []


@pytest.mark.parametrize(
    ("where", "old", "new", "said"),
    [
        (0, FORMULA, "pub const RLIMIT_NPROC: u64 = 8192;", "not derived"),
        (0, FORMULA, "pub const RLIMIT_NPROC: u64 = 256;", "not derived"),
        (0, FORMULA, FORMULA.replace(" * 2;", ";"), "not derived"),
        (0, "pub const MAX_LIVE_ENVIRONMENTS: u64 = 16;", "", "no single MAX_LIVE"),
        (
            0,
            "pub const MAX_LIVE_ENVIRONMENTS: u64 = 16;",
            "pub const MAX_LIVE_ENVIRONMENTS: u64 = 8;",
            "sized for 8",
        ),
        (1, "MAX_LIVE_ENVIRONMENTS: i64 = 16;", "MAX_LIVE_ENVIRONMENTS: i64 = 32;", "allows 32"),
        (2, "    const PIDS_LIMIT: u64 = 256;", "    const PIDS_LIMIT: u64 = 255;", "counts 255"),
        (0, ASSERTION, "RLIMIT_NPROC >= PIDS_LIMIT", "assertion"),
    ],
    ids=[
        "a-bare-backstop",
        "the-old-value",
        "no-margin",
        "no-cap-in-the-profile",
        "a-smaller-cap-in-the-profile",
        "the-authority-raised-alone",
        "the-evidence-counting-another-bound",
        "the-assertion-weakened",
    ],
)
def test_each_way_the_derivation_can_drift_is_caught(
    where: int, old: str, new: str, said: str
) -> None:
    sources = list(_sources())
    assert sources[where].count(old) == 1, old
    sources[where] = sources[where].replace(old, new)
    errors = backstop_errors(*sources)
    assert any(said in error for error in errors), errors


def test_the_relays_stay_bounded_by_their_cgroup_alone() -> None:
    """ADR-0048, unchanged by ADR-0056: a relay of the shared relay uid has no
    `nproc` of its own to couple -- its own pids cgroup is its bound."""
    text = RELAY_PLAN.read_text(encoding="utf-8")
    assert "RELAY_PIDS_LIMIT" in text
    assert "nproc" not in text and "RLIMIT_NPROC" not in text


def test_the_neighbour_controls_target_is_the_backstop_once() -> None:
    """The negative control must find what it puts back at 256, exactly once,
    and put back something that still compiles: a plain value and an
    assertion that holds for it."""
    text = PROFILE.read_text(encoding="utf-8")
    assert len(dw.NEIGHBOUR_MUTATIONS) == 1
    (_what, rel, old, new) = dw.NEIGHBOUR_MUTATIONS[0]
    assert (REPO_ROOT / rel) == PROFILE
    assert text.count(old) == 1
    assert "pub const RLIMIT_NPROC: u64 = 256;" in new
    assert "RLIMIT_NPROC >= PIDS_LIMIT" in new
    assert [package for package, _ in dw.NEIGHBOUR_TESTS] == ["dwkd-broker", "dwkd-authority"]
    for _package, name in dw.NEIGHBOUR_TESTS:
        assert name in (*dw.WORKLOAD_BROKER_TESTS, *dw.WORKLOAD_AUTHORITY_TESTS), name
        assert "neighbour" in name or "task_bound" in name, name
