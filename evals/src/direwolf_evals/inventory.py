"""Which security properties can be measured now, and which cannot.

The point of this table is to make "we cannot test that yet" a visible,
countable state. A dashboard that shows only what runs today will read as
though the untested properties were fine.

Each entry names the property, the milestone that must exist before it can be
measured at all, and — when it is measurable now — the suite that measures it.
The milestones are the ones in `docs/ROADMAP.md`; a test asserts that.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

__all__ = ["INVENTORY", "SecurityProperty", "available", "pending"]


@dataclass(frozen=True, slots=True)
class SecurityProperty:
    property: str
    milestone: str
    """The milestone that must ship before this can be measured."""
    suite: str | None
    """The suite measuring it today, or ``None`` while it is pending."""
    note: str


INVENTORY: Final[tuple[SecurityProperty, ...]] = (
    # --- measurable now: M2 shipped the wire -------------------------------
    SecurityProperty(
        "Malformed DWKP is structurally rejected",
        "M2",
        "protocol-security",
        "Shared invalid vectors, decided by the real decoder.",
    ),
    SecurityProperty(
        "Framing is bounded and desynchronisation is fatal",
        "M2",
        "protocol-security",
        "Sizes, truncation, mixed streams, poisoned decoder.",
    ),
    SecurityProperty(
        "Reserved operations have no wire form",
        "M2",
        "protocol-security",
        "Every reserved name is refused as an unknown operation.",
    ),
    SecurityProperty(
        "Per-family compatibility (reject / preserve / retain)",
        "M2",
        "protocol-compat",
        "ADR-0023's three rules, measured separately.",
    ),
    SecurityProperty(
        "Canonical encoding is stable and idempotent",
        "M2",
        "protocol-compat",
        "Checked against the independent V8-derived oracle.",
    ),
    SecurityProperty(
        "The eval gate rejects a known-bad result",
        "M2.5",
        "harness-selftest",
        "Proved by a meta-test, not by a fixture left failing in CI.",
    ),
    SecurityProperty(
        "A process can be interrupted at a named point",
        "M2.5",
        "harness-selftest",
        "Against the dummy child; real processes are instrumented from M3.",
    ),
    # --- measurable now: M3 shipped the authority (M3e, ADR-0041) -----------
    SecurityProperty(
        "Peer identity on the kernel socket",
        "M3",
        "authority-security",
        "A real second uid against the real server (SO_PEERCRED): Linux, and only "
        "where a second identity exists; CI's eval gate provides one.",
    ),
    SecurityProperty(
        "The authority process boundary holds under a hostile client",
        "M3",
        "authority-security",
        "The real dwkd-authority process, attacked over its socket; every case "
        "contained, and audited where it is security-significant.",
    ),
    SecurityProperty(
        "Lease epoch fencing rejects a stale epoch",
        "M3",
        "authority-security",
        "Stale epochs and holders, a restart and a poisoned store, through the real process.",
    ),
    SecurityProperty(
        "Policy decisions are explainable and deny by default",
        "M3",
        "authority-security",
        "Each shipped pack's default rule, with its rule_source, through the real "
        "engine -- in process until M4 can build a canonical action.",
    ),
    SecurityProperty(
        "Capability attenuation never widens authority",
        "M3",
        "authority-security",
        "Generated delegation chains over the real lattice; the 10^6 campaign is "
        "`make capability-evidence`.",
    ),
    # --- pending: the mechanism does not exist yet -------------------------
    SecurityProperty(
        "Filesystem canonicalisation resists traversal and TOCTOU",
        "M4",
        None,
        "Needs the filesystem broker (openat2, inode identity).",
    ),
    SecurityProperty(
        "Exec mediation normalises argv and scrubs the environment",
        "M4",
        None,
        "Needs the exec broker.",
    ),
    SecurityProperty(
        "Secrets never reach the runtime's address space",
        "M4",
        None,
        "Needs the secret broker and injection modes.",
    ),
    SecurityProperty(
        "Sandbox and egress isolation (PROXY_ONLY)",
        "M5",
        None,
        "Needs the sandbox and the egress proxy.",
    ),
    SecurityProperty(
        "Approval binding survives drift, replay and substitution",
        "M6",
        None,
        "Needs the approval registry; ADR-0021's eleven fields.",
    ),
    SecurityProperty(
        "Budgets are subtractive and cannot be amplified by fan-out",
        "M6",
        None,
        "Needs the budget ledger.",
    ),
    SecurityProperty(
        "Model egress enforces privacy class and credential binding",
        "M7",
        None,
        "Needs provider egress; no live call will be made in evals.",
    ),
)


def available() -> tuple[SecurityProperty, ...]:
    return tuple(p for p in INVENTORY if p.suite is not None)


def pending() -> tuple[SecurityProperty, ...]:
    return tuple(p for p in INVENTORY if p.suite is None)
