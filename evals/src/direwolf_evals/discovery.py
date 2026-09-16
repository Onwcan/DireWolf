"""Deterministic suite discovery.

Same tree in, same suites out: same set, same order, same identifiers. Suites
are TOML (``tomllib``, standard library, data only — no object construction, no
code), keys are a closed set, and anything unexpected is an error rather than a
silently ignored setting. A field the loader ignored would be a rule nobody
enforced.
"""

from __future__ import annotations

import tomllib
from collections.abc import Iterable
from pathlib import Path
from typing import Any, Final

from direwolf_evals.model import DEFAULT_TIMEOUT_S, Eval, Suite

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
    }
)


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
    requires = tuple(sorted(set(suite_requires) | set(_strs(source, raw, "requires"))))
    pending = raw.get("pending_reason")
    if pending is not None and not isinstance(pending, str):
        raise DiscoveryError(f"{source}: {name}: pending_reason must be a string")
    if pending is not None and not pending.strip():
        raise DiscoveryError(f"{source}: {name}: pending_reason must say what is missing")
    return Eval(
        id=f"{suite_id}/{name}",
        suite=suite_id,
        name=name,
        description=_text(source, raw, "description"),
        runner=_text(source, raw, "runner"),
        scorer=str(raw.get("scorer", "binary")),
        fixture=str(raw["fixture"]) if raw.get("fixture") is not None else None,
        seed=int(raw.get("seed", 0)),
        timeout_s=float(raw.get("timeout_s", DEFAULT_TIMEOUT_S)),
        runs=int(raw.get("runs", 1)),
        requires=requires,
        pending_reason=pending,
        tags=_strs(source, raw, "tags"),
        gate=bool(raw["gate"]) if "gate" in raw else suite_gate,
    )


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
