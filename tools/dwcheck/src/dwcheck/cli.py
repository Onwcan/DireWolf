"""Command-line entry point for ``dwcheck``."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from dwcheck import Finding, Report
from dwcheck.checks_links import check_links
from dwcheck.checks_manifests import (
    check_crates,
    check_lockfile_closure,
    check_python_dependencies,
)
from dwcheck.checks_python import check_python_imports, check_text
from dwcheck.checks_version import check_version, write_version
from dwcheck.config import ArchitectureConfig, ConfigError, load

__all__ = ["main"]

_EPILOG = """\
These checks are development hygiene, not a security boundary. Every one of them
is static analysis over source text; the OS process and privilege boundary
between the runtime and dwkd-authority is the actual control. Do not cite a
passing dwcheck run as evidence of containment. See docs/ARCHITECTURE.md section 6.
"""


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="dwcheck",
        description="DireWolf architecture boundary checks.",
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=Path.cwd(),
        help="repository root to check (default: current directory)",
    )
    parser.add_argument(
        "--rules",
        type=Path,
        default=None,
        help="rules file (default: <root>/architecture.toml)",
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("all", help="run every check")
    sub.add_parser("imports", help="Python import and provider-name rules")
    sub.add_parser("deps", help="declared dependencies and the Rust crate graph")
    sub.add_parser("links", help="relative markdown links and ADR references")
    version_parser = sub.add_parser("version", help="one version, one source of truth")
    version_parser.add_argument(
        "--write",
        action="store_true",
        help="rewrite every manifest version from VERSION instead of checking",
    )

    args = parser.parse_args(argv)
    root: Path = args.root.resolve()

    try:
        config = load(root, args.rules)
    except ConfigError as exc:
        print(f"dwcheck: {exc}", file=sys.stderr)
        return 2

    if args.command == "version" and args.write:
        try:
            changed = write_version(config)
        except (OSError, RuntimeError) as exc:
            print(f"dwcheck: {exc}", file=sys.stderr)
            return 2
        for path in changed:
            print(f"updated {path}")
        if not changed:
            print("all versions already match VERSION")
        return 0

    report = Report()
    for name in _selected(str(args.command)):
        report.extend(_run(name, config))

    if report.ok:
        print(f"dwcheck: ok ({', '.join(_selected(str(args.command)))})")
        return 0

    print(report.render(), file=sys.stderr)
    print(
        f"\ndwcheck: {len(report.findings)} boundary violation(s). "
        f"These are hygiene checks; see {config.rules_file.name} for what each rule protects.",
        file=sys.stderr,
    )
    return 1


def _selected(command: str) -> list[str]:
    if command == "all":
        return ["imports", "deps", "links", "version"]
    return [command]


def _run(name: str, config: ArchitectureConfig) -> list[Finding]:
    if name == "imports":
        return check_python_imports(config) + check_text(config)
    if name == "deps":
        return (
            check_python_dependencies(config)
            + check_crates(config)
            + check_lockfile_closure(config)
        )
    if name == "links":
        return check_links(config.root, config.docs_exempt_paths)
    if name == "version":
        return check_version(config)
    raise ValueError(f"unknown check: {name}")


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
