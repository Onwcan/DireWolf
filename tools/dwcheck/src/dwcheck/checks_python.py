"""Python source checks: banned imports, banned attribute calls, banned text.

The import check parses each file with ``ast`` rather than grepping, so that
``# import socket`` in a comment and ``"socket"`` in a docstring do not trip it
while ``from socket import socket`` does.
"""

from __future__ import annotations

import ast
import re
from collections.abc import Iterator
from pathlib import Path

from dwcheck import Finding
from dwcheck.config import ArchitectureConfig, PythonRule, TextRule

__all__ = ["check_python_imports", "check_text"]

_SKIP_DIRS = frozenset(
    {".git", ".venv", "venv", "target", "__pycache__", ".mypy_cache", ".ruff_cache", "node_modules"}
)


def check_python_imports(config: ArchitectureConfig) -> list[Finding]:
    findings: list[Finding] = []
    for rule in config.python_rules:
        for file in _files(config.root, rule.paths, rule.exempt_paths, suffix=".py"):
            findings.extend(_check_file(config.root, file, rule))
    return findings


def check_text(config: ArchitectureConfig) -> list[Finding]:
    findings: list[Finding] = []
    for rule in config.text_rules:
        patterns = [(p, re.compile(p)) for p in rule.patterns]
        for suffix in rule.suffixes:
            for file in _files(config.root, rule.paths, rule.exempt_paths, suffix=suffix):
                findings.extend(_check_text_file(config.root, file, rule, patterns))
    return findings


def _check_file(root: Path, file: Path, rule: PythonRule) -> Iterator[Finding]:
    text = file.read_text(encoding="utf-8", errors="replace")
    try:
        tree = ast.parse(text, filename=str(file))
    except SyntaxError as exc:
        yield Finding(
            path=_rel(root, file),
            line=exc.lineno or 0,
            rule=rule.id,
            message=f"could not parse: {exc.msg}",
            reason=rule.reason,
        )
        return

    banned_attrs = set(rule.banned_attributes)
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if _module_banned(alias.name, rule.banned_modules):
                    yield _import_finding(root, file, node.lineno, rule, alias.name)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if node.level:  # relative import; nothing global to ban
                continue
            if _module_banned(module, rule.banned_modules):
                yield _import_finding(root, file, node.lineno, rule, module)
                continue
            for alias in node.names:
                dotted = f"{module}.{alias.name}" if module else alias.name
                if dotted in banned_attrs:
                    yield Finding(
                        path=_rel(root, file),
                        line=node.lineno,
                        rule=rule.id,
                        message=f"forbidden import of `{dotted}`",
                        reason=rule.reason,
                    )
        elif isinstance(node, ast.Call):
            dynamic = _dynamic_import_target(node)
            if dynamic and _module_banned(dynamic, rule.banned_modules):
                yield Finding(
                    path=_rel(root, file),
                    line=node.lineno,
                    rule=rule.id,
                    message=f"forbidden dynamic import of `{dynamic}`",
                    reason=rule.reason,
                )
        elif isinstance(node, ast.Attribute):
            attr_path = _dotted(node)
            if attr_path and attr_path in banned_attrs:
                yield Finding(
                    path=_rel(root, file),
                    line=node.lineno,
                    rule=rule.id,
                    message=f"forbidden use of `{attr_path}`",
                    reason=rule.reason,
                )


def _check_text_file(
    root: Path, file: Path, rule: TextRule, patterns: list[tuple[str, re.Pattern[str]]]
) -> Iterator[Finding]:
    for lineno, line in enumerate(
        file.read_text(encoding="utf-8", errors="replace").splitlines(), start=1
    ):
        for source, compiled in patterns:
            match = compiled.search(line)
            if match:
                yield Finding(
                    path=_rel(root, file),
                    line=lineno,
                    rule=rule.id,
                    message=f"matches /{source}/: {match.group(0)!r}",
                    reason=rule.reason,
                )


def _import_finding(root: Path, file: Path, line: int, rule: PythonRule, module: str) -> Finding:
    return Finding(
        path=_rel(root, file),
        line=line,
        rule=rule.id,
        message=f"forbidden import of `{module}`",
        reason=rule.reason,
    )


def _dynamic_import_target(node: ast.Call) -> str | None:
    """Module name from `__import__("x")` or `importlib.import_module("x")`.

    Only the literal form. A computed name cannot be resolved statically, and
    pretending otherwise would be the kind of false assurance this checker is
    documented not to provide -- but the literal form is what someone writes to
    get around a lint, and catching it costs nothing.
    """
    func = node.func
    name = (
        func.id
        if isinstance(func, ast.Name)
        else _dotted(func)
        if isinstance(func, ast.Attribute)
        else None
    )
    if name not in {"__import__", "importlib.import_module", "import_module"}:
        return None
    if not node.args:
        return None
    first = node.args[0]
    return first.value if isinstance(first, ast.Constant) and isinstance(first.value, str) else None


def _module_banned(module: str, banned: tuple[str, ...]) -> bool:
    """True when ``module`` is a banned module or a submodule of one."""
    return any(module == b or module.startswith(f"{b}.") for b in banned)


def _dotted(node: ast.Attribute) -> str | None:
    """Render ``os.path.join``-style attribute chains; ``None`` if not a chain."""
    parts: list[str] = []
    current: ast.expr = node
    while isinstance(current, ast.Attribute):
        parts.append(current.attr)
        current = current.value
    if not isinstance(current, ast.Name):
        return None
    parts.append(current.id)
    return ".".join(reversed(parts))


def _files(
    root: Path, paths: tuple[str, ...], exempt: tuple[str, ...], *, suffix: str
) -> Iterator[Path]:
    exempt_dirs = [(root / e).resolve() for e in exempt]
    for entry in paths:
        base = root / entry
        if not base.exists():
            continue
        for file in sorted(base.rglob(f"*{suffix}")):
            if any(part in _SKIP_DIRS for part in file.parts):
                continue
            resolved = file.resolve()
            if any(resolved == d or d in resolved.parents for d in exempt_dirs):
                continue
            yield file


def _rel(root: Path, file: Path) -> str:
    try:
        return file.relative_to(root).as_posix()
    except ValueError:
        return file.as_posix()
