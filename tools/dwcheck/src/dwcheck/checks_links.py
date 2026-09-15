"""Documentation link checks.

Two failures matter and both are cheap to catch:

* a relative link to a file that does not exist -- the architecture package is
  a hypertext, and a dead link is a reader who stops reading;
* a reference to ``ADR-NNNN`` with no such record -- ADRs are cited as
  authority, so a citation that resolves to nothing is worse than a missing
  link.

External URLs are *not* fetched. A link checker that makes network requests is
a CI job that fails when someone else's site is down, which trains people to
re-run CI until it passes.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

from dwcheck import Finding

__all__ = ["check_links"]

_INLINE_LINK = re.compile(r"\[[^\]]*\]\(\s*<?([^()<>\s]+?)>?\s*(?:\"[^\"]*\")?\s*\)")
_ADR_REFERENCE = re.compile(r"\bADR-(\d{4})\b")
_FENCE = re.compile(r"^\s*(```|~~~)")
_EXTERNAL = ("http://", "https://", "mailto:", "tel:", "ftp://")
_SKIP_DIRS = frozenset({".git", ".venv", "venv", "target", "node_modules", "__pycache__"})


def check_links(root: Path, exempt_paths: tuple[str, ...] = ()) -> list[Finding]:
    findings: list[Finding] = []
    adr_dir = root / "docs" / "adr"
    known_adrs = {p.name[:4] for p in adr_dir.glob("[0-9][0-9][0-9][0-9]-*.md")}

    for md in _markdown_files(root, exempt_paths):
        rel = md.relative_to(root).as_posix()
        text = md.read_text(encoding="utf-8", errors="replace")
        findings.extend(_check_targets(md, rel, text))
        findings.extend(_check_adr_references(rel, text, known_adrs))
    return findings


def _check_targets(md: Path, rel: str, text: str) -> Iterator[Finding]:
    for lineno, line in _code_free_lines(text):
        for match in _INLINE_LINK.finditer(line):
            target = match.group(1)
            if target.startswith(_EXTERNAL) or target.startswith("#"):
                continue
            resource = target.split("#", 1)[0].split("?", 1)[0]
            if not resource:
                continue
            resolved = (md.parent / resource).resolve()
            if resolved.exists():
                continue
            yield Finding(
                path=rel,
                line=lineno,
                rule="DOC001-broken-relative-link",
                message=f"link target does not exist: {target}",
                reason=(
                    "The architecture package is read as a hypertext; a dead link is a reader "
                    "who stops reading. Relative targets are resolved against the linking file."
                ),
            )


def _check_adr_references(rel: str, text: str, known: set[str]) -> Iterator[Finding]:
    for lineno, line in _code_free_lines(text):
        for match in _ADR_REFERENCE.finditer(line):
            number = match.group(1)
            if number not in known:
                yield Finding(
                    path=rel,
                    line=lineno,
                    rule="DOC002-missing-adr",
                    message=f"cites ADR-{number}, which does not exist in docs/adr/",
                    reason=(
                        "ADRs are cited as authority. A citation that resolves to nothing is "
                        "worse than no citation, because it reads as though a decision was made."
                    ),
                )


def _code_free_lines(text: str) -> Iterator[tuple[int, str]]:
    """Yield lines outside fenced code blocks.

    Mermaid diagrams and shell transcripts contain bracket-and-paren shapes
    that are not links; linting them produces noise that gets the whole check
    switched off.
    """
    in_fence = False
    for lineno, line in enumerate(text.splitlines(), start=1):
        if _FENCE.match(line):
            in_fence = not in_fence
            continue
        if not in_fence:
            yield lineno, line


def _markdown_files(root: Path, exempt_paths: tuple[str, ...]) -> Iterator[Path]:
    exempt = [(root / e).resolve() for e in exempt_paths]
    for path in sorted(root.rglob("*.md")):
        if any(part in _SKIP_DIRS for part in path.relative_to(root).parts):
            continue
        resolved = path.resolve()
        if any(resolved == e or e in resolved.parents for e in exempt):
            continue
        yield path
