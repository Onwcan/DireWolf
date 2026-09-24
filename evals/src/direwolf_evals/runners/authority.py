"""M3 runners: the authority, measured as the product.

None of these reimplements anything. The transport evals run the real-process
suites in ``crates/dwkd-authority/tests`` — which spawn the released
``dwkd-authority`` binary, talk to it over a real Unix-domain socket and read
``audit.log`` through the verifier — and read the one ``DWKP-EVIDENCE`` line
each passing case prints. The capability and policy evals run the existing
evidence paths over the real lattice and the real engine. A runner that did
its own attenuation, fencing or policy arithmetic in Python would measure its
own copy of the property, which is how a green dashboard and a broken product
coexist.

Every case a runner expects is listed here, so a case that silently stopped
running is a FAIL naming it, not a smaller denominator. Every evidence line
must name the binary that served it, and that binary must exist, so a runner
that never launched the server cannot pass.

**How close did it get?** Each transport result carries, per layer, how many
cases were contained there (EVALS.md §3): ``peer-gate`` (refused on the
kernel-reported uid, before a byte was read), ``framing``, ``decoder``,
``connection-protocol``, ``state-fence``, ``capability-policy``,
``resource-bound`` and ``filesystem``. A denial at the peer gate is stronger
than one after dispatch, and the counts make erosion visible.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final

from direwolf_evals.model import Outcome, Status
from direwolf_evals.preconditions import PEER_ENV

if TYPE_CHECKING:  # pragma: no cover - import cycle only matters to type checkers
    from direwolf_evals.runners import Context

__all__ = [
    "capability_attenuation",
    "epoch_fencing",
    "hostile_dwkp_client",
    "parse_evidence",
    "peer_credential_check",
    "policy_denies_by_default",
]

PREFIX: Final = "DWKP-EVIDENCE "
LAYERS: Final = (
    "peer-gate",
    "framing",
    "decoder",
    "connection-protocol",
    "state-fence",
    "capability-policy",
    "resource-bound",
    "filesystem",
)
MAX_ARTIFACT: Final = 1500

POLICY_INPUTS: Final = (
    "taint_level",
    "origin",
    "privacy_class",
    "workspace_sensitivity",
    "active_skills",
    "skill_trust",
    "standing_grant",
    "policy_mode",
    "subject",
    "uid",
    "lease_holder",
)

HOSTILE_CASES: Final = frozenset(
    {
        # framing
        "oversized-frame",
        "invalid-frame-length",
        "reserved-content-type",
        "truncated-frame",
        # the production decoder
        "duplicate-json-key",
        "malformed-json",
        "non-utf8",
        "depth-bomb",
        "malformed-id",
        "missing-envelope-field",
        "number-out-of-domain",
        "unknown-field",
        "forbidden-envelope-field",
        "unknown-operation",
        # ToolInvoke is defined from M4b (ADR-0043) with exactly one tool: a call
        # naming another is refused by the decoder, not dispatched.
        "tool-invoke-names-no-other-tool",
        "reserved-canonical-preview",
        "reserved-model-call",
        "unsupported-envelope-version",
        "unsupported-schema-version",
        "schema-downgrade-v1-refusal",
        "event-type-message",
        # policy inputs the runtime tries to assert
        *(
            f"policy-input-{field}-in-{place}"
            for field in POLICY_INPUTS
            for place in ("envelope", "payload")
        ),
        # the connection protocol
        "non-handshake-first",
        "duplicate-handshake",
        "version-downgrade-or-mismatch",
        "wrong-direction-response",
        # the state layer
        "stale-epoch",
        "replayed-admit-run",
        "conflicting-admit-run",
        "old-key-stale-epoch",
        "query-proposal-forces-no-decision",
        "ended-admission-replay",
        "operation-ordering-abuse",
        "session-guessing",
        "correlation-causation-reuse",
        "same-uid-inherit-lease",
        "connection-close-reconnect",
        # resources
        "connection-limit",
        "slowloris-silent",
        "slowloris-partial-frame",
        "response-backpressure",
        "connect-disconnect-storm",
        "protocol-abuse-flood",
        "replay-storm",
    }
)

PEER_CASES: Final = frozenset(
    {
        "foreign-uid-valid-handshake",
        "foreign-uid-malformed-payload",
        "foreign-uid-flood",
        "foreign-uid-impersonation",
    }
)

FENCING_CASES: Final = frozenset(
    {
        "same-uid-second-connection",
        "reconnect-inherits-nothing",
        "stale-epoch-after-rotation",
        "old-key-stale-epoch",
        "ended-admission-replay",
        "sigkill-restart",
        "poisoned-store-stops-serving",
    }
)

POLICY_CASES: Final = frozenset(
    {"default-deny-safe", "default-deny-balanced", "default-deny-power"}
)

CHAINS: Final = 20_000
"""Delegation chains per capability-attenuation eval run: enough to exercise
every step kind many times over in seconds. The full 10^6 campaign is
``make capability-evidence``."""


@dataclass(frozen=True, slots=True)
class Evidence:
    """One verified case, as its suite reported it."""

    suite: str
    case: str
    layer: str
    contained: bool
    audited: bool
    server: str | None


def parse_evidence(output: str) -> list[Evidence]:
    """Every evidence line in ``output``. A malformed line is an error, not a
    skipped line: a report the runner cannot read is not evidence."""
    found: list[Evidence] = []
    for line in output.splitlines():
        # Anywhere in the line, not only at its start: with `--nocapture` and
        # parallel tests, libtest may have printed "test name ... " just before
        # a case's line. The evidence runs to the end of the line either way,
        # because each is written whole.
        at = line.find(PREFIX)
        if at < 0:
            continue
        raw: Any = json.loads(line[at + len(PREFIX) :])
        if not isinstance(raw, dict):
            raise ValueError(f"an evidence line is not an object: {line[:200]}")
        layer = raw.get("layer")
        if layer not in LAYERS:
            raise ValueError(f"unknown containment layer {layer!r}")
        server = raw.get("server")
        found.append(
            Evidence(
                suite=str(raw["suite"]),
                case=str(raw["case"]),
                layer=str(layer),
                contained=raw["contained"] is True,
                audited=raw["audited"] is True,
                server=str(server) if isinstance(server, str) else None,
            )
        )
    return found


@dataclass(frozen=True, slots=True)
class _Cargo:
    returncode: int
    output: str


def _cargo(
    ctx: Context,
    tests: Sequence[str],
    *,
    filters: Sequence[str] = (),
    ignored: bool = False,
    env: dict[str, str] | None = None,
    release: bool = False,
) -> _Cargo:
    """``cargo test`` over named test targets of the authority crate."""
    command = ["cargo", "test", "--locked", "-p", "dwkd-authority"]
    if release:
        command.append("--release")
    for test in tests:
        command += ["--test", test]
    command += ["--", "--nocapture", "--test-threads=4", *filters]
    if ignored:
        command.append("--ignored")
    completed = subprocess.run(
        command,
        cwd=str(ctx.repo_root),
        env={**os.environ, **(env or {})},
        capture_output=True,
        text=True,
        timeout=ctx.evaluation.timeout_s,
        check=False,
    )
    return _Cargo(completed.returncode, completed.stdout + completed.stderr)


def _tail(text: str) -> str:
    return text[-MAX_ARTIFACT:]


def _transport(run: _Cargo, expected: frozenset[str], suites: set[str]) -> Outcome:
    """Judge real-process evidence: every expected case present, contained,
    audited where it said it would be, and served by the real binary."""
    if run.returncode != 0:
        return Outcome(
            Status.FAIL,
            {"cases": 0.0},
            f"the real-process suite failed (exit {run.returncode})",
            {"output": _tail(run.output)},
        )
    try:
        evidence = [e for e in parse_evidence(run.output) if e.suite in suites]
    except (ValueError, KeyError) as exc:
        return Outcome(Status.ERROR, {}, f"unreadable evidence: {exc}")
    seen = {e.case for e in evidence}
    missing = sorted(expected - seen)
    uncontained = sorted(e.case for e in evidence if not e.contained)
    servers = {e.server for e in evidence if e.server is not None}
    fake = sorted(
        s
        for s in servers
        if Path(s).name.removesuffix(".exe") != "dwkd-authority" or not Path(s).exists()
    )
    layers = Counter(e.layer for e in evidence)
    metrics = {
        "cases": float(len(seen)),
        "expected_cases": float(len(expected)),
        "contained": float(sum(1 for e in evidence if e.contained)),
        "audited": float(sum(1 for e in evidence if e.audited)),
        "server_binaries": float(len(servers)),
        "rejection_rate": (len(seen) - len(set(uncontained))) / len(expected) if expected else 0.0,
        **{f"layer_{name.replace('-', '_')}": float(layers.get(name, 0)) for name in LAYERS},
    }
    metrics["rejection_rate"] = min(1.0, max(0.0, metrics["rejection_rate"]))
    artifacts = {
        "layers": " ".join(f"{name}={layers[name]}" for name in LAYERS if layers.get(name)),
        "server": ", ".join(sorted(servers))[:MAX_ARTIFACT],
    }
    problems = []
    if missing:
        problems.append(f"missing cases: {', '.join(missing)}")
    if uncontained:
        problems.append(f"NOT CONTAINED: {', '.join(uncontained)}")
    if not servers and suites & {
        "hostile",
        "peer",
        "fencing",
        "restart",
        "poison",
        "stress",
        "socket",
    }:
        problems.append("no evidence named the server that produced it")
    if fake:
        problems.append(f"evidence from something that is not the built binary: {fake}")
    if problems:
        return Outcome(Status.FAIL, metrics, "; ".join(problems)[:MAX_ARTIFACT], artifacts)
    return Outcome(Status.PASS, metrics, "", artifacts)


def hostile_dwkp_client(ctx: Context) -> Outcome:
    """EVALS.md §3: a completely compromised runtime against the real process.

    Runs ``transport_hostile`` and ``transport_stress``: framing, the strict
    decoder, twenty-two attempts to assert a policy input, the handshake-first
    connection protocol, every state-layer fence a runtime can reach, and
    resource exhaustion. Score: the fraction of expected cases contained.
    """
    run = _cargo(ctx, ["transport_hostile", "transport_stress"])
    return _transport(run, HOSTILE_CASES, {"hostile", "stress"})


def peer_credential_check(ctx: Context) -> Outcome:
    """A connection from another uid is refused, on the uid the kernel reports.

    Runs ``transport_foreign`` with the second identity the harness found
    (``needs = ["second-identity"]`` keeps this from running without one).
    """
    user = os.environ.get(PEER_ENV, "")
    run = _cargo(ctx, ["transport_foreign"], ignored=True, env={PEER_ENV: user})
    return _transport(run, PEER_CASES, {"peer", "socket"})


def epoch_fencing(ctx: Context) -> Outcome:
    """Stale epochs, stale holders, restarts and a poisoned store, through the
    real process: ``transport_server``."""
    run = _cargo(ctx, ["transport_server"])
    return _transport(run, FENCING_CASES, {"fencing", "restart", "poison"})


def policy_denies_by_default(ctx: Context) -> Outcome:
    """For each shipped pack, an action no rule allows is denied by the pack's
    own mandatory ``default`` rule, naming it and the line it is written at.

    In process (``state_query``'s evidence test), through the real authority
    and the real engine: a proposal over DWKP is refused with
    ``NO_CANONICAL_ACTION`` until M4 can build the complete canonical action
    policy decides on (ADR-0040), so there is no truthful wire path yet.
    """
    run = _cargo(ctx, ["state_query"], filters=["policy_denies_by_default_evidence"], ignored=True)
    if run.returncode != 0:
        return Outcome(
            Status.FAIL,
            {},
            f"the evidence test failed (exit {run.returncode})",
            {"output": _tail(run.output)},
        )
    try:
        evidence = [e for e in parse_evidence(run.output) if e.suite == "policy"]
    except (ValueError, KeyError) as exc:
        return Outcome(Status.ERROR, {}, f"unreadable evidence: {exc}")
    seen = {e.case for e in evidence}
    missing = sorted(POLICY_CASES - seen)
    denied = all(e.contained and e.audited for e in evidence)
    metrics = {"packs": float(len(seen)), "audited": float(sum(e.audited for e in evidence))}
    if missing or not denied:
        return Outcome(Status.FAIL, metrics, f"missing {missing}; all denied and audited: {denied}")
    return Outcome(Status.PASS, metrics)


_LINE = re.compile(r"^(?P<key>[a-z ]+):\s+(?P<value>\d+)\s*$")


def capability_attenuation(ctx: Context) -> Outcome:
    """A child capability set never exceeds its parent: the delegation-chain
    campaign (``tests/evidence.rs``) over the real lattice, shortened to
    :data:`CHAINS` chains. Zero escalations, and widening attempts refused."""
    run = _cargo(
        ctx,
        ["evidence"],
        filters=["one_million_delegation_chains_with_zero_escalations"],
        ignored=True,
        env={"DW_EVIDENCE_CHAINS": str(CHAINS), "DW_EVIDENCE_SEED": str(ctx.seed or 1)},
    )
    counts: dict[str, int] = {}
    for line in run.output.splitlines():
        match = _LINE.match(line.strip())
        if match:
            counts[match["key"].strip()] = int(match["value"])
    metrics = {key.replace(" ", "_"): float(value) for key, value in sorted(counts.items())}
    chains = counts.get("chains", 0)
    escalations = counts.get("escalations", -1)
    attempts = counts.get("widening attempts", 0)
    refused = counts.get("refused", 0)
    if run.returncode != 0 or chains != CHAINS or escalations != 0 or attempts == 0 or refused == 0:
        return Outcome(
            Status.FAIL,
            metrics,
            f"exit {run.returncode}, chains {chains}, escalations {escalations}, "
            f"widening attempts {attempts}, refused {refused}",
            {"output": _tail(run.output)},
        )
    return Outcome(Status.PASS, metrics)
