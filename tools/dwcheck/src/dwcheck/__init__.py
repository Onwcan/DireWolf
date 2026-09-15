"""DireWolf architecture boundary checks.

``dwcheck`` enforces the rules in the repository-root ``architecture.toml``.

These checks are **development hygiene, not a security boundary.** Every one of
them is a static check over source text; a prompt-injected ``exec()`` inside the
runtime can call ``__import__("socket")`` and no rule here will ever run. The
actual controls are the OS process and privilege boundary between the runtime
and ``dwkd-authority``, the absence of a network route on the runtime identity,
and the absence of any credential in the runtime's address space. See
``docs/ARCHITECTURE.md`` §6.

A passing ``dwcheck`` run is evidence that the architecture has not eroded
through ordinary development. It is not evidence of containment.
"""

from __future__ import annotations

from dataclasses import dataclass, field

__all__ = ["Finding", "Report", "__version__"]

__version__ = "0.0.0"


@dataclass(frozen=True, slots=True, order=True)
class Finding:
    """One boundary violation, addressed to whoever has to fix it."""

    path: str
    """Repository-relative path, POSIX separators."""

    line: int
    """1-based line number, or 0 when the finding is about a file as a whole."""

    rule: str
    """Rule id from ``architecture.toml``, e.g. ``PY001-...``."""

    message: str
    """What is wrong, in one line."""

    reason: str = ""
    """Why the rule exists. Printed once per rule, not once per finding."""

    def location(self) -> str:
        return f"{self.path}:{self.line}" if self.line else self.path


@dataclass(slots=True)
class Report:
    """Accumulated findings across checks."""

    findings: list[Finding] = field(default_factory=list)
    checked_files: int = 0

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    def extend(self, findings: list[Finding]) -> None:
        self.findings.extend(findings)

    @property
    def ok(self) -> bool:
        return not self.findings

    def render(self) -> str:
        """Format findings for a terminal: locations first, rationale last.

        A boundary check that only says "denied" trains people to route around
        it, so every rule prints the reason it exists.
        """
        if self.ok:
            return ""
        lines: list[str] = []
        for finding in sorted(self.findings):
            lines.append(f"{finding.location()}: [{finding.rule}] {finding.message}")

        reasons = {f.rule: f.reason for f in self.findings if f.reason}
        if reasons:
            lines.append("")
            for rule, reason in sorted(reasons.items()):
                lines.append(f"--- {rule}")
                lines.append("\n".join("    " + ln for ln in reason.strip().splitlines()))
        return "\n".join(lines)
