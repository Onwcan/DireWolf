"""Deterministic suite discovery.

Same tree in, same suites out: same set, same order, same identifiers. Suites
are TOML (``tomllib``, standard library, data only — no object construction, no
code), keys are a closed set, and anything unexpected is an error rather than a
silently ignored setting. A field the loader ignored would be a rule nobody
enforced.
"""

from __future__ import annotations

import math
import re
import tomllib
from collections.abc import Iterable
from pathlib import Path
from typing import Any, Final

from direwolf_evals.model import DEFAULT_TIMEOUT_S, Eval, Suite
from direwolf_evals.preconditions import NEEDS, PLATFORMS
from direwolf_evals.scoring import is_scorer, scorer_names

__all__ = ["DiscoveryError", "discover", "suite_paths"]

SUITE_KEYS: Final = frozenset({"id", "title", "description", "score", "requires", "gate", "eval"})
EVAL_KEYS: Final = frozenset(
    {
        "name",
        "description",
        "runner",
        "scorer",
        "fixture",
        "seed",
        "timeout_s",
        "runs",
        "requires",
        "pending_reason",
        "tags",
        "gate",
        "platforms",
        "needs",
    }
)


_RESTATES_REQUIREMENT: Final = re.compile(r"^\s*requires\s+M[0-9]", re.IGNORECASE)
_MILESTONE: Final = re.compile(r"M[0-9]+(?:\.[0-9]+)?")


class DiscoveryError(Exception):
    """A suite file is missing, malformed, or has an unknown shape."""


def suite_paths(root: Path) -> list[Path]:
    """Every suite file, in one order on every machine."""
    directory = root / "suites"
    if not directory.is_dir():
        raise DiscoveryError(f"no suite directory at {directory}")
    return sorted(directory.glob("*.toml"), key=lambda p: p.name)


def discover(root: Path) -> list[Suite]:
    """Load every suite under ``root`` (the ``evals/`` directory)."""
    suites = [_suite(path, root) for path in suite_paths(root)]
    ids = [s.id for s in suites]
    duplicates = {i for i in ids if ids.count(i) > 1}
    if duplicates:
        raise DiscoveryError(f"duplicate suite ids: {sorted(duplicates)}")
    return sorted(suites, key=lambda s: s.id)


def _suite(path: Path, root: Path) -> Suite:
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise DiscoveryError(f"{path.name}: {exc}") from exc

    _reject_unknown(path.name, raw, SUITE_KEYS)
    suite_id = _text(path.name, raw, "id")
    evals = [
        _eval(path.name, suite_id, entry, _strs(path.name, raw, "requires"), _flag(raw, "gate"))
        for entry in _tables(path.name, raw)
    ]
    names = [e.name for e in evals]
    duplicates = {n for n in names if names.count(n) > 1}
    if duplicates:
        raise DiscoveryError(f"{path.name}: duplicate eval names: {sorted(duplicates)}")

    return Suite(
        id=suite_id,
        title=_text(path.name, raw, "title"),
        description=_text(path.name, raw, "description"),
        score_meaning=_text(path.name, raw, "score"),
        requires=_strs(path.name, raw, "requires"),
        gate=_flag(raw, "gate"),
        source=path.relative_to(root.parent).as_posix(),
        # Sorted by id: execution order does not depend on file order.
        evals=tuple(sorted(evals, key=lambda e: e.id)),
    )


def _eval(
    source: str,
    suite_id: str,
    raw: dict[str, Any],
    suite_requires: tuple[str, ...],
    suite_gate: bool,
) -> Eval:
    _reject_unknown(source, raw, EVAL_KEYS)
    name = _text(source, raw, "name")
    requires = _milestones(source, name, set(suite_requires) | set(_strs(source, raw, "requires")))
    pending = _pending_reason(source, name, raw, requires)
    return Eval(
        id=f"{suite_id}/{name}",
        suite=suite_id,
        name=name,
        description=_text(source, raw, "description"),
        runner=_runner(source, name, raw, requires),
        scorer=_scorer(source, name, raw),
        fixture=_optional_text(source, name, raw, "fixture"),
        seed=_int(source, name, raw, "seed", 0, minimum=0),
        timeout_s=_float(source, name, raw, "timeout_s", DEFAULT_TIMEOUT_S),
        runs=_int(source, name, raw, "runs", 1, minimum=1),
        requires=requires,
        pending_reason=pending,
        tags=_strs(source, raw, "tags"),
        gate=_bool(source, name, raw, "gate", suite_gate),
        platforms=_closed(source, name, raw, "platforms", PLATFORMS),
        needs=_closed(source, name, raw, "needs", NEEDS),
    )


def _closed(
    source: str, name: str, raw: dict[str, Any], key: str, allowed: frozenset[str]
) -> tuple[str, ...]:
    """A precondition vocabulary is closed. "Linux" or "second_identity" would
    never match, and the eval would be *not exercised* everywhere with a reason
    that reads correctly -- dormancy through a typo."""
    values = _strs(source, raw, key)
    unknown = sorted(set(values) - allowed)
    if unknown:
        raise DiscoveryError(f"{source}: {name}: unknown {key} {unknown}; known: {sorted(allowed)}")
    return tuple(sorted(set(values)))


def _milestones(source: str, name: str, values: set[str]) -> tuple[str, ...]:
    """`requires` decides whether an eval runs, so a typo in it is not cosmetic.

    "m3" or "M 3" would never match an available milestone, and the eval would
    sit at PENDING for ever with a reason that reads correctly — the same class
    of silent dormancy the `pending_reason` fix removed, arriving through the
    other field. Shape is checked here; whether the milestone *exists* is
    answered by AVAILABLE_MILESTONES at run time.
    """
    for value in sorted(values):
        if not _MILESTONE.fullmatch(value):
            raise DiscoveryError(
                f"{source}: {name}: {value!r} is not a milestone; expected a form like "
                f"'M3' or 'M2.5'"
            )
    return tuple(sorted(values))


def _optional_text(source: str, name: str, raw: dict[str, Any], key: str) -> str | None:
    value = raw.get(key)
    if value is None:
        return None
    if not isinstance(value, str) or not value.strip():
        raise DiscoveryError(f"{source}: {name}: {key!r} must be a non-empty string")
    return value


def _int(
    source: str, name: str, raw: dict[str, Any], key: str, default: int, *, minimum: int
) -> int:
    """A suite file is data from a contributor, and every malformed value has to
    be a configuration error with a location — never a ValueError from a bare
    `int()` that takes the whole run down with it."""
    value = raw.get(key, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise DiscoveryError(f"{source}: {name}: {key!r} must be an integer, got {value!r}")
    if value < minimum:
        raise DiscoveryError(f"{source}: {name}: {key!r} must be at least {minimum}, got {value}")
    return value


def _float(source: str, name: str, raw: dict[str, Any], key: str, default: float) -> float:
    value = raw.get(key, default)
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise DiscoveryError(f"{source}: {name}: {key!r} must be a number, got {value!r}")
    number = float(value)
    if not math.isfinite(number) or number <= 0:
        raise DiscoveryError(
            f"{source}: {name}: {key!r} must be a positive finite number, got {number!r}"
        )
    return number


def _bool(source: str, name: str, raw: dict[str, Any], key: str, default: bool) -> bool:
    """`bool("false")` is True. A gate flag that reads as the opposite of what it
    says would quietly move an eval in or out of the merge gate."""
    if key not in raw:
        return default
    value = raw[key]
    if not isinstance(value, bool):
        raise DiscoveryError(f"{source}: {name}: {key!r} must be true or false, got {value!r}")
    return value


def _runner(source: str, name: str, raw: dict[str, Any], requires: tuple[str, ...]) -> str | None:
    """The runner, which may be absent only while a milestone is outstanding.

    An eval that needs a component nobody has built has no honest runner to
    name, and a placeholder pointing at somebody else's runner is worse than
    nothing: the day the milestone lands it starts reporting a pass for a
    property it never measured. Absent is allowed; wrong is not. Whether an
    absent runner is tolerable at *run* time is decided by milestone
    availability, in `direwolf_evals.runner`, not here.
    """
    value = raw.get("runner")
    if value is None:
        if not requires:
            raise DiscoveryError(
                f"{source}: {name}: 'runner' is required unless the eval declares the "
                f"milestone it is waiting for in 'requires'"
            )
        return None
    if not isinstance(value, str) or not value.strip():
        raise DiscoveryError(f"{source}: {name}: 'runner' must be a non-empty string")
    return value


def _scorer(source: str, name: str, raw: dict[str, Any]) -> str:
    """Checked against the closed registry here, before anything runs.

    A typo'd scorer used to survive discovery and raise at scoring time, outside
    the runner's containment, taking the whole process with it. Rejecting it
    here means one bad suite file is a configuration error naming the valid
    options, and no eval runs on a suite that cannot be scored.
    """
    value = raw.get("scorer", "binary")
    if not isinstance(value, str) or not is_scorer(value):
        raise DiscoveryError(
            f"{source}: {name}: unknown scorer {value!r}; valid scorers are {scorer_names()}"
        )
    return value


def _pending_reason(
    source: str, name: str, raw: dict[str, Any], requires: tuple[str, ...]
) -> str | None:
    """The human half of a pending reason. Never a switch that disables an eval.

    The machine half -- "requires M3" -- is generated from `requires` when the
    result is recorded, so this field must not restate it: a hand-written
    milestone here could disagree with the real requirement and hide the fact
    that a security property had been deferred somewhere else.
    """
    value = raw.get("pending_reason")
    if value is None:
        return None
    if not isinstance(value, str):
        raise DiscoveryError(f"{source}: {name}: pending_reason must be a string")
    text = value.strip()
    if not text:
        raise DiscoveryError(f"{source}: {name}: pending_reason must say what is missing")
    if not requires:
        raise DiscoveryError(
            f"{source}: {name}: pending_reason without 'requires' would explain a state "
            f"that can never happen; milestone availability is what makes an eval pending"
        )
    if _RESTATES_REQUIREMENT.match(text):
        raise DiscoveryError(
            f"{source}: {name}: pending_reason must not restate the requirement "
            f"({text.split(':')[0]!r}); that half is generated from requires={list(requires)}. "
            f"Give only the detail, e.g. 'there is no authority process to lie to.'"
        )
    return text


def _reject_unknown(source: str, raw: dict[str, Any], allowed: Iterable[str]) -> None:
    unknown = sorted(set(raw) - set(allowed))
    if unknown:
        raise DiscoveryError(f"{source}: unknown keys {unknown}; extend the loader deliberately")


def _tables(source: str, raw: dict[str, Any]) -> list[dict[str, Any]]:
    entries = raw.get("eval", [])
    if not isinstance(entries, list) or not all(isinstance(e, dict) for e in entries):
        raise DiscoveryError(f"{source}: [[eval]] must be an array of tables")
    return [e for e in entries if isinstance(e, dict)]


def _text(source: str, raw: dict[str, Any], key: str) -> str:
    value = raw.get(key)
    if not isinstance(value, str) or not value.strip():
        raise DiscoveryError(f"{source}: {key!r} must be a non-empty string")
    return value


def _strs(source: str, raw: dict[str, Any], key: str) -> tuple[str, ...]:
    value = raw.get(key, [])
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise DiscoveryError(f"{source}: {key!r} must be an array of strings")
    return tuple(str(v) for v in value)


def _flag(raw: dict[str, Any], key: str) -> bool:
    return bool(raw.get(key, False))
