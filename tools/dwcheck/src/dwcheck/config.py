"""Load and validate ``architecture.toml``.

Validation is strict and noisy on purpose: a boundary rule that silently does
nothing because a key was misspelled is worse than no rule, because it reads as
a passing check.
"""

from __future__ import annotations

import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

__all__ = [
    "AdrException",
    "AdrSettings",
    "ArchitectureConfig",
    "ConfigError",
    "CrateRule",
    "CratesSettings",
    "DependencyRule",
    "PythonRule",
    "TextRule",
    "VersionMirror",
    "load",
]

SUPPORTED_SCHEMA_VERSION = 1


class ConfigError(Exception):
    """``architecture.toml`` is missing, malformed, or has an unknown shape."""


@dataclass(frozen=True, slots=True)
class PythonRule:
    id: str
    paths: tuple[str, ...]
    exempt_paths: tuple[str, ...]
    banned_modules: tuple[str, ...]
    banned_attributes: tuple[str, ...]
    reason: str


@dataclass(frozen=True, slots=True)
class TextRule:
    id: str
    paths: tuple[str, ...]
    exempt_paths: tuple[str, ...]
    suffixes: tuple[str, ...]
    """File name suffixes the rule reads, e.g. ``(".py",)`` or ``(".rs",)``."""
    patterns: tuple[str, ...]
    reason: str


@dataclass(frozen=True, slots=True)
class DependencyRule:
    id: str
    manifests: tuple[str, ...]
    banned: tuple[str, ...]
    reason: str


@dataclass(frozen=True, slots=True)
class CrateRule:
    id: str
    crate: str
    forbidden_dependencies: tuple[str, ...]
    reason: str


@dataclass(frozen=True, slots=True)
class AdrException:
    """One authorised departure from an ADR's accepted content in history.

    ``sha256`` pins the content the exception authorises, so the override covers
    exactly one correction rather than making the file mutable from then on.
    """

    file: str
    sha256: str
    reason: str


@dataclass(frozen=True, slots=True)
class AdrSettings:
    """Where the ADRs live, where their digests are recorded, and the overrides."""

    directory: str
    manifest: str
    history_exceptions: tuple[AdrException, ...] = ()


@dataclass(frozen=True, slots=True)
class CratesSettings:
    manifest: str
    directory: str
    require_workspace_dependencies: bool
    undependable: tuple[str, ...]
    shared: tuple[str, ...]
    """In-tree crates both daemons may link. Each must be a leaf (RS009)."""


@dataclass(frozen=True, slots=True)
class VersionMirror:
    path: str
    kind: str
    """``toml`` -- read the value through tomllib at ``section``.
    ``regex`` -- read and write it with ``pattern`` (for non-TOML files)."""
    section: str
    pattern: str


@dataclass(frozen=True, slots=True)
class ArchitectureConfig:
    root: Path
    version_source: str
    version_mirrors: tuple[VersionMirror, ...]
    python_rules: tuple[PythonRule, ...]
    text_rules: tuple[TextRule, ...]
    dependency_rules: tuple[DependencyRule, ...]
    crates: CratesSettings
    crate_rules: tuple[CrateRule, ...]
    authority_crates: tuple[str, ...]
    authority_allowed_third_party: tuple[str, ...]
    docs_exempt_paths: tuple[str, ...]
    adr: AdrSettings = field(default=AdrSettings("docs/adr", "docs/adr/accepted.sha256"))
    rules_file: Path = field(default=Path("architecture.toml"))


def load(root: Path, rules_file: Path | None = None) -> ArchitectureConfig:
    """Read the rules for the tree rooted at ``root``.

    ``rules_file`` defaults to ``root/architecture.toml``. It is separate so a
    test can point the real rules at a fixture tree.
    """
    path = rules_file if rules_file is not None else root / "architecture.toml"
    try:
        raw = tomllib.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ConfigError(f"no architecture rules at {path}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"{path}: malformed TOML: {exc}") from exc

    schema = raw.get("schema_version")
    if schema != SUPPORTED_SCHEMA_VERSION:
        raise ConfigError(
            f"{path}: schema_version {schema!r} is not supported "
            f"(this dwcheck understands {SUPPORTED_SCHEMA_VERSION})"
        )

    version_tbl = _table(raw, "version", path)
    crates_tbl = _table(raw, "crates", path)
    docs_tbl = _table(raw, "docs", path)
    adr_tbl = _table(raw, "adr", path)
    authority_tbl = _table(raw, "authority", path)

    return ArchitectureConfig(
        root=root,
        rules_file=path,
        version_source=_str(version_tbl, "source", path),
        version_mirrors=tuple(
            VersionMirror(
                path=_str(m, "path", path),
                kind=_choice(m, "kind", ("toml", "regex"), path),
                section=_str(m, "section", path),
                pattern=_str(m, "pattern", path),
            )
            for m in _tables(version_tbl, "mirrors", path)
        ),
        python_rules=tuple(
            PythonRule(
                id=_str(r, "id", path),
                paths=_strs(r, "paths", path),
                exempt_paths=_strs(r, "exempt_paths", path),
                banned_modules=_strs(r, "banned_modules", path),
                banned_attributes=_strs(r, "banned_attributes", path),
                reason=_str(r, "reason", path),
            )
            for r in _tables(raw, "python_rules", path)
        ),
        text_rules=tuple(
            TextRule(
                id=_str(r, "id", path),
                paths=_strs(r, "paths", path),
                exempt_paths=_strs(r, "exempt_paths", path),
                suffixes=_suffixes(r, path),
                patterns=_strs(r, "patterns", path),
                reason=_str(r, "reason", path),
            )
            for r in _tables(raw, "text_rules", path)
        ),
        dependency_rules=tuple(
            DependencyRule(
                id=_str(r, "id", path),
                manifests=_strs(r, "manifests", path),
                banned=_strs(r, "banned", path),
                reason=_str(r, "reason", path),
            )
            for r in _tables(raw, "dependency_rules", path)
        ),
        crates=CratesSettings(
            manifest=_str(crates_tbl, "manifest", path),
            directory=_str(crates_tbl, "directory", path),
            require_workspace_dependencies=_bool(
                crates_tbl, "require_workspace_dependencies", path
            ),
            undependable=_strs(crates_tbl, "undependable", path),
            shared=_strs(crates_tbl, "shared", path),
        ),
        crate_rules=tuple(
            CrateRule(
                id=_str(r, "id", path),
                crate=_str(r, "crate", path),
                forbidden_dependencies=_strs(r, "forbidden_dependencies", path),
                reason=_str(r, "reason", path),
            )
            for r in _tables(raw, "crate_rules", path)
        ),
        authority_crates=_strs(authority_tbl, "crates", path),
        authority_allowed_third_party=_strs(authority_tbl, "allowed_third_party", path),
        docs_exempt_paths=_strs(docs_tbl, "exempt_paths", path),
        adr=AdrSettings(
            directory=_str(adr_tbl, "directory", path),
            manifest=_str(adr_tbl, "manifest", path),
            history_exceptions=tuple(
                AdrException(
                    file=_str(e, "file", path),
                    sha256=_sha256(e, "sha256", path),
                    reason=_str(e, "reason", path),
                )
                for e in _tables(adr_tbl, "history_exceptions", path)
            ),
        ),
    )


# --- typed accessors -------------------------------------------------------
# tomllib hands back `Any`; these turn a bad key into a clear error at load
# time rather than a silently skipped rule at check time.


def _table(d: dict[str, Any], key: str, path: Path) -> dict[str, Any]:
    value = d.get(key)
    if not isinstance(value, dict):
        raise ConfigError(f"{path}: [{key}] must be a table")
    return value


def _tables(d: dict[str, Any], key: str, path: Path) -> list[dict[str, Any]]:
    value = d.get(key, [])
    if not isinstance(value, list) or not all(isinstance(v, dict) for v in value):
        raise ConfigError(f"{path}: {key} must be an array of tables")
    return [v for v in value if isinstance(v, dict)]


def _str(d: dict[str, Any], key: str, path: Path) -> str:
    value = d.get(key)
    if not isinstance(value, str):
        raise ConfigError(f"{path}: {key!r} must be a string, got {type(value).__name__}")
    return value


def _choice(d: dict[str, Any], key: str, allowed: tuple[str, ...], path: Path) -> str:
    value = _str(d, key, path)
    if value not in allowed:
        raise ConfigError(f"{path}: {key!r} must be one of {allowed}, got {value!r}")
    return value


def _sha256(d: dict[str, Any], key: str, path: Path) -> str:
    """A digest that is not a digest would make an override match nothing, and a
    silently-inert override is worse than none: it reads as authorised."""
    value = _str(d, key, path).strip().lower()
    if len(value) != 64 or any(c not in "0123456789abcdef" for c in value):
        raise ConfigError(f"{path}: {key!r} must be a 64-character hex sha256, got {value!r}")
    return value


def _bool(d: dict[str, Any], key: str, path: Path) -> bool:
    value = d.get(key)
    if not isinstance(value, bool):
        raise ConfigError(f"{path}: {key!r} must be a boolean")
    return value


def _suffixes(d: dict[str, Any], path: Path) -> tuple[str, ...]:
    """A text rule with no suffix would read nothing and report success."""
    value = _strs(d, "suffixes", path)
    if not value or not all(s.startswith(".") and len(s) > 1 for s in value):
        raise ConfigError(f"{path}: 'suffixes' must list at least one suffix such as \".rs\"")
    return value


def _strs(d: dict[str, Any], key: str, path: Path) -> tuple[str, ...]:
    value = d.get(key)
    if value is None:
        raise ConfigError(f"{path}: {key!r} is required (use [] for none)")
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"{path}: {key!r} must be an array of strings")
    return tuple(v for v in value if isinstance(v, str))
