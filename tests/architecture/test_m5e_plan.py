"""M5e's plan cites only evidence that exists, and its proposed cases collide with none.

`docs/M5E_ASSURANCE_PLAN.md` §3 is a requirements-to-evidence matrix: each
"existing evidence" cell names the cases a required task is said to require. A
case renamed in its suite, or cited from memory, would leave the plan claiming
coverage nothing measures. So every case the matrix cites is held to a case
table in `scripts/dw.py` -- the tables each evidence task requires by name, a
missing one failing the task -- and every task it names to `dw.TASKS`.

The cases ADR-0054 §8 and ADR-0055 §9 propose for the registry evidence are
held to their own shape: well-formed, unique across both ADRs, and new, so
none can already mean something else when it is implemented. Both ADRs must
still read as Proposed: neither is accepted by being cited.

This is M5e.1's groundwork, not its evidence: it reads documents and tables,
and runs nothing.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

from dwcheck.checks_adr import _status

REPO_ROOT = Path(__file__).resolve().parents[2]
PLAN = REPO_ROOT / "docs" / "M5E_ASSURANCE_PLAN.md"
NPM_ADR = REPO_ROOT / "docs" / "adr" / "0054-m5e-npm-hygiene-profile.md"
PIP_ADR = REPO_ROOT / "docs" / "adr" / "0055-m5e-pip-hygiene-profile.md"

sys.path.insert(0, str(REPO_ROOT / "scripts"))
import dw  # noqa: E402  - imported after the path is extended

_CASE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)+")
_SHORTHAND = re.compile(r"-[a-z0-9]+(?:-[a-z0-9]+)*")
_WILDCARD = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*-\*")
_PROPOSED = re.compile(r"^\| `((?:npm|npx|pip)-[a-z0-9-]+)` \|", re.MULTILINE)


def _required_cases() -> set[str]:
    """Every case name any evidence task requires: each table of
    `(suite, case)` pairs `scripts/dw.py` holds."""
    cases: set[str] = set()
    for name in dir(dw):
        table = getattr(dw, name)
        if (
            isinstance(table, tuple)
            and table
            and all(
                isinstance(row, tuple) and len(row) == 2 and all(isinstance(x, str) for x in row)
                for row in table
            )
        ):
            cases.update(case for _, case in table)
    return cases


def _matrix_cells() -> list[tuple[str, str]]:
    """`(row id, existing-evidence cell)` for each row of §3's matrix."""
    text = PLAN.read_text(encoding="utf-8")
    start = text.index("## 3. Requirements-to-evidence matrix")
    end = text.index("## 4. ", start)
    cells = []
    for line in text[start:end].splitlines():
        match = re.match(r"^\| (R\d+) \| (.*?) \| ", line)
        if match:
            cells.append((match.group(1), match.group(2)))
    return cells


def _cited(cell: str) -> tuple[list[str], list[str], list[str]]:
    """The cell's cases, wildcard prefixes and tasks, in order; `-suffix`
    after a case or a wildcard shares its first word, as the matrix writes
    long lists."""
    cases: list[str] = []
    prefixes: list[str] = []
    tasks: list[str] = []
    first = ""
    for token in re.findall(r"`([^`]+)`", cell):
        if token.endswith("-evidence"):
            tasks.append(token)
        elif _WILDCARD.fullmatch(token):
            prefixes.append(token[:-1])
            first = token.split("-", 1)[0]
        elif _CASE.fullmatch(token):
            cases.append(token)
            first = token.split("-", 1)[0]
        elif _SHORTHAND.fullmatch(token) and first:
            cases.append(first + token)
    return cases, prefixes, tasks


def test_every_case_the_matrix_cites_is_required_by_a_task() -> None:
    required = _required_cases()
    cited = 0
    for row, cell in _matrix_cells():
        cases, prefixes, tasks = _cited(cell)
        cited += len(cases)
        missing = [case for case in cases if case not in required]
        assert not missing, f"{row} cites cases no task requires: {missing}"
        for prefix in prefixes:
            assert any(case.startswith(prefix) for case in required), f"{row}: `{prefix}*`"
        for task in tasks:
            assert task in dw.TASKS, f"{row} names a task that does not exist: {task}"
    # A parser that matches nothing would pass vacuously.
    assert len(_matrix_cells()) == 18
    assert cited >= 80, cited


def test_the_proposed_registry_cases_are_well_formed_unique_and_new() -> None:
    npm = _PROPOSED.findall(NPM_ADR.read_text(encoding="utf-8"))
    pip = _PROPOSED.findall(PIP_ADR.read_text(encoding="utf-8"))
    assert len(npm) >= 20, npm
    assert len(pip) >= 20, pip
    proposed = npm + pip
    assert len(proposed) == len(set(proposed)), "a proposed case is named twice"
    taken = sorted(set(proposed) & _required_cases())
    assert not taken, f"proposed cases that already name another task's case: {taken}"


def test_both_package_manager_adrs_are_still_proposed() -> None:
    for adr in (NPM_ADR, PIP_ADR):
        assert _status(adr.read_text(encoding="utf-8")).startswith("proposed"), adr.name
