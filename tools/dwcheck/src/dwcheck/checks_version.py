"""One project version, one source of truth.

The repository-root ``VERSION`` file is authoritative. Every manifest that also
carries a version is a *mirror*, and mirrors are written by ``--write`` rather
than edited by hand -- three hand-edited copies drift, and the drift is only
noticed when a release is half-built.

The version string is deliberately plain semver with no pre-release suffix.
Cargo spells a pre-release ``0.1.0-alpha.1`` and PEP 440 spells the same thing
``0.1.0a1``; a byte-equality check across ecosystems is only possible while both
spellings coincide, and a lossy comparison is not worth the convenience.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path
from typing import Any

from dwcheck import Finding
from dwcheck.config import ArchitectureConfig, VersionMirror

__all__ = ["check_version", "write_version"]

_REASON = (
    "The project has one version. Manifests mirror the root VERSION file and are written "
    "by `dwcheck version --write`, never edited by hand."
)


def check_version(config: ArchitectureConfig) -> list[Finding]:
    findings: list[Finding] = []
    source_path = config.root / config.version_source
    try:
        expected = source_path.read_text(encoding="utf-8").strip()
    except OSError:
        return [
            Finding(
                path=config.version_source,
                line=0,
                rule="VER001-version-source-missing",
                message="the authoritative VERSION file is missing",
                reason=_REASON,
            )
        ]

    if not expected:
        findings.append(
            Finding(
                path=config.version_source,
                line=0,
                rule="VER001-version-source-missing",
                message="VERSION is empty",
                reason=_REASON,
            )
        )
        return findings

    for mirror in config.version_mirrors:
        path = config.root / mirror.path
        where = f"[{mirror.section}] " if mirror.section else ""
        actual = _read_mirror(path, mirror)
        if actual is None:
            findings.append(
                Finding(
                    path=mirror.path,
                    line=0,
                    rule="VER002-version-mirror-unreadable",
                    message=f"no version found ({where or 'top level'})",
                    reason=_REASON,
                )
            )
        elif actual != expected:
            findings.append(
                Finding(
                    path=mirror.path,
                    line=_line_of(path, actual),
                    rule="VER003-version-drift",
                    message=(
                        f"{where}version is {actual!r}, "
                        f"VERSION says {expected!r}; run `dwcheck version --write`"
                    ),
                    reason=_REASON,
                )
            )
    return findings


def write_version(config: ArchitectureConfig) -> list[str]:
    """Rewrite every mirror from ``VERSION``. Returns the paths changed."""
    expected = (config.root / config.version_source).read_text(encoding="utf-8").strip()
    changed: list[str] = []
    for mirror in config.version_mirrors:
        path = config.root / mirror.path
        if _read_mirror(path, mirror) == expected:
            continue
        text = path.read_text(encoding="utf-8")
        updated, count = re.subn(
            mirror.pattern,
            lambda m: f"{m.group('prefix')}{expected}{m.group('suffix')}",
            text,
            count=1,
        )
        if count != 1:
            raise RuntimeError(
                f"{mirror.path}: version pattern matched {count} times, expected exactly 1"
            )
        path.write_text(updated, encoding="utf-8", newline="\n")
        if _read_mirror(path, mirror) != expected:
            raise RuntimeError(f"{mirror.path}: rewrite did not take effect; fix by hand")
        changed.append(mirror.path)
    return changed


def _read_mirror(path: Path, mirror: VersionMirror) -> str | None:
    """Read the mirrored version.

    TOML mirrors are read by parsing, not by regex: the regex is used only for
    writing, so a version hidden in an unexpected table cannot masquerade as the
    real one. Non-TOML mirrors -- a generated ``_version.py`` -- have no parser
    to appeal to, so the same pattern reads and writes them.
    """
    if mirror.kind == "regex":
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            return None
        match = re.search(mirror.pattern, text)
        return match.group("version") if match else None
    try:
        data: Any = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return None
    for key in mirror.section.split("."):
        if not isinstance(data, dict) or key not in data:
            return None
        data = data[key]
    if not isinstance(data, dict):
        return None
    value = data.get("version")
    return value if isinstance(value, str) else None


def _line_of(path: Path, needle: str) -> int:
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return 0
    for lineno, line in enumerate(text.splitlines(), start=1):
        if needle in line:
            return lineno
    return 0
