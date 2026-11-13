"""F-17's address partition rests on one fact about the policy engine
(ADR-0061, Proposed, §3): within `crates/dwkd-authority/src/policy`, an
action's destination address is read by `address_in` and nowhere else.

The partition decides a workload's egress once per piece of the address space
the policy's own ranges cut. That is exact only because the evaluator's answer
depends on an address through `ip_in` membership alone, which is
`address_in`'s. A new reader -- a predicate that turns on the address some
other way -- fails here, and the partition must be argued again before it
lands. (The property tests in `policy/partition_tests.rs` hold the partition
to the evaluator; this holds their premise to the source. It lives here, not
in `policy/`, because the policy core does no IO, its tests included: TX004.)
"""

from __future__ import annotations

import shutil
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
POLICY = REPO_ROOT / "crates" / "dwkd-authority" / "src" / "policy"


def _production(text: str) -> str:
    """A file's source without its own unit tests, which are not the
    evaluator."""
    return text.split("\nmod tests", 1)[0]


def _readers(policy: Path) -> list[str]:
    readers: list[str] = []
    for path in sorted(policy.glob("*.rs")):
        if path.name.endswith("_tests.rs") or path.name == "testing.rs":
            continue
        for line in _production(path.read_text(encoding="utf-8")).splitlines():
            code = line.lstrip()
            if code.startswith("//"):
                continue
            if "destination_ip()" in code:
                readers.append(f"{path.name}: {code}")
    return readers


def test_only_address_in_reads_the_destination_address() -> None:
    assert _readers(POLICY) == ["predicate.rs: .destination_ip()"], (
        "the address is read only by address_in (ADR-0061 §3)"
    )
    predicate = (POLICY / "predicate.rs").read_text(encoding="utf-8")
    body = predicate.split("fn address_in(", 1)[1].split("\n}\n", 1)[0]
    assert ".destination_ip()" in body


def test_the_premise_check_sees_a_second_reader(tmp_path: Path) -> None:
    """The check is not vacuous: a policy file that reads the address
    anywhere else -- outside its own unit tests and comments -- is found."""
    copy = tmp_path / "policy"
    shutil.copytree(POLICY, copy)
    novel = "\n".join(
        (
            "// a comment naming destination_ip() is not a reader",
            "fn near(action: &Action) -> bool {",
            "    action.destination_ip().is_some()",
            "}",
            "",
            "mod tests {",
            "    fn t() { let _ = a.destination_ip(); }",
            "}",
            "",
        )
    )
    (copy / "novel_predicate.rs").write_text(novel, encoding="utf-8")
    assert _readers(copy) == [
        "novel_predicate.rs: action.destination_ip().is_some()",
        "predicate.rs: .destination_ip()",
    ]
