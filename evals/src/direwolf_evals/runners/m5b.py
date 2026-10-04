"""M5b runner: PROXY_ONLY egress, measured as the product.

Like every runner since M3, this reimplements nothing. It runs the real
evidence task -- `scripts/dw.py sandbox-egress-evidence`: the released broker
preparing PROXY_ONLY environments in a real OCI runtime, the real setup and
relay containers in the environment's own network namespace, every workload
byte crossing the real relay and the broker's real CONNECT proxy, and the real
authority deriving the grant -- and judges the evidence lines each passing
case prints after its assertions held (ADR-0048).

Every case the runner expects is listed here. A case that silently stopped
running is a FAIL naming it, never a smaller denominator; a weakened or
drifted topology the measurement did not catch is a FAIL; a bypass whose
mechanism is not one the topology, the capabilities or the seccomp profile
explains is a FAIL; the task's own failure -- including NOT EXERCISED -- is a
FAIL.

The judging function takes the task's output and nothing else, so the meta
tests can hand it a regression and watch the gate fail.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from typing import TYPE_CHECKING, Any, Final

from direwolf_evals.model import Outcome, Status

if TYPE_CHECKING:  # pragma: no cover - import cycle only matters to type checkers
    from direwolf_evals.runners import Context

__all__ = ["BYPASS_CASES", "M5B_CASES", "judge_egress", "sandbox_egress"]

MAX_ARTIFACT: Final = 1500
PREFIX: Final = "SANDBOX-EVIDENCE "

# Every direct path a process that ignores the proxy can try. Each must be
# refused by the topology (no route, or nothing listening in its own
# namespace), the capabilities or the seccomp profile -- never answered.
BYPASS_CASES: Final = frozenset(
    {
        ("sandbox-egress", "bypass-tcp-external"),
        ("sandbox-egress", "bypass-tcp-external-dns"),
        ("sandbox-egress", "bypass-tcp-cloud-metadata"),
        ("sandbox-egress", "bypass-tcp-bridge-host"),
        ("sandbox-egress", "bypass-tcp-desktop-host"),
        ("sandbox-egress", "bypass-tcp-private-lan"),
        ("sandbox-egress", "bypass-tcp-link-local-neighbour"),
        ("sandbox-egress", "bypass-tcp-host-loopback-origin"),
        ("sandbox-egress", "bypass-tcp-ipv6-external"),
        ("sandbox-egress", "bypass-tcp-ipv4-mapped"),
        ("sandbox-egress", "bypass-tcp-nat64-metadata"),
        ("sandbox-egress", "bypass-udp-external"),
        ("sandbox-egress", "bypass-udp-ipv6-external"),
        ("sandbox-egress", "bypass-raw-ipv4"),
        ("sandbox-egress", "bypass-raw-ipv6"),
        ("sandbox-egress", "bypass-packet"),
        ("sandbox-egress", "bypass-vsock"),
        ("sandbox-egress", "bypass-icmp"),
    }
)

# The cases that state the M5b properties, by class.
M5B_CASES: Final = frozenset(
    {
        # The strict topology: clean, three containers, one peer.
        ("sandbox-egress", "proxy-only-prepare-clean"),
        ("sandbox-egress", "proxy-only-host-proxy-environment"),
        ("sandbox-egress", "proxy-only-host-proxy-relay"),
        ("sandbox-egress", "proxy-only-host-relay-digest"),
        ("sandbox-egress", "proxy-only-container-proxy-reachable"),
        ("sandbox-egress", "proxy-only-container-direct-egress-refused"),
        ("sandbox-egress", "proxy-only-container-direct-dns-refused"),
        ("sandbox-egress", "proxy-only-container-raw-sockets-refused"),
        ("sandbox-egress", "proxy-only-environment-and-relay-only"),
        ("sandbox-egress", "proxy-only-socket-mounted-in-relay-only"),
        ("sandbox-egress", "proxy-only-socket-directory-relay-uid-only"),
        ("sandbox-egress", "proxy-only-destroy-removes-every-role"),
        ("sandbox-egress", "proxy-only-destroy-closes-listener"),
        # Tunnels through the real relay obey the grant, the guard, the pin
        # and the server name.
        ("sandbox-egress", "tunnel-granted-carries-bytes"),
        ("sandbox-egress", "tunnel-via-proxy-variable"),
        ("sandbox-egress", "tunnel-host-not-granted"),
        ("sandbox-egress", "tunnel-port-not-granted"),
        ("sandbox-egress", "tunnel-address-literal-refused"),
        ("sandbox-egress", "resolver-blocked"),
        ("sandbox-egress", "resolver-metadata-blocked"),
        ("sandbox-egress", "resolver-mixed-refused-outright"),
        ("sandbox-egress", "resolver-failure"),
        ("sandbox-egress", "resolver-timeout"),
        ("sandbox-egress", "resolver-rebinding-pinned"),
        ("sandbox-egress", "tunnel-sni-mismatch-closed"),
        ("sandbox-egress", "tunnel-sni-missing-closed"),
        ("sandbox-egress", "tunnel-ech-refused"),
        ("sandbox-egress", "tunnel-plain-http-refused"),
        ("sandbox-egress", "audit-observability-no-payload"),
        # Budgets at the socket, and the fronting residual shown honestly.
        ("sandbox-egress", "budget-upload-exact-at-socket"),
        ("sandbox-egress", "budget-upload-spent-stays-spent"),
        ("sandbox-egress", "budget-download-exhausted"),
        ("sandbox-egress", "budget-tunnel-limit"),
        ("sandbox-egress", "fronting-residual-carried-and-bounded"),
        # No path for a process that ignores the proxy.
        *BYPASS_CASES,
        ("sandbox-egress", "bypass-dns-external"),
        ("sandbox-egress", "bypass-dns-embedded-runtime-resolver"),
        ("sandbox-egress", "bypass-dns-local-stub"),
        ("sandbox-egress", "bypass-library-resolver"),
        ("sandbox-egress", "bypass-proxy-variable-redirected"),
        ("sandbox-egress", "bypass-proxy-variable-other-peer"),
        ("sandbox-egress", "bypass-origin-never-reached"),
        # The variables are the broker's; nothing ambient reaches them.
        ("sandbox-egress", "proxy-variables-broker-owned"),
        ("sandbox-egress", "proxy-variables-ambient-ignored"),
        # Weakened and drifted topologies are detected.
        ("sandbox-egress", "weakened-bridge-network"),
        ("sandbox-egress", "weakened-missing-relay"),
        ("sandbox-egress", "weakened-proxy-variables-removed"),
        ("sandbox-egress", "drift-relay-stopped"),
        ("sandbox-egress", "drift-extra-peer-listening"),
        ("sandbox-egress", "drift-fake-resolver-in-namespace"),
        ("sandbox-egress", "drift-setup-left-running"),
        ("sandbox-egress", "drift-egress-directory-opened"),
        ("sandbox-egress", "weakened-relay-tampered"),
        ("sandbox-egress", "weakened-topology-count"),
        # Lifecycle: crashes, restart, foreign resources, production.
        ("sandbox-egress", "crash-environment-relay-started"),
        ("sandbox-egress", "restart-proxy-closed-fails-closed"),
        ("sandbox-egress", "foreign-resources-untouched"),
        ("sandbox-egress", "production-no-fixture-resolver"),
        ("sandbox-egress", "production-loopback-blocked-no-exception"),
        # The authority derives the grant from the run, and audits it.
        ("sandbox-authority-egress", "grant-from-run-exact-https"),
        ("sandbox-authority-egress", "grant-wildcard-and-plain-http-not-destinations"),
        ("sandbox-authority-egress", "audit-intent-records-grant"),
        ("sandbox-authority-egress", "tunnel-through-authority-prepared-environment"),
        ("sandbox-authority-egress", "audit-destroyed-counters"),
        ("sandbox-authority-egress", "reconcile-helper-orphan-reaped"),
    }
)

WEAKENED_COUNT: Final = re.compile(r"detected-(\d+)-of-(\d+)")
# What may refuse a bypass: the topology, the capabilities, the seccomp
# profile -- or, for ICMP only, the platform's ping range.
MECHANISM: Final = re.compile(
    r"mechanism=(topology-no-route|topology-nothing-listening|capabilities|seccomp|"
    r"platform-or-capabilities)\b"
)


def _records(output: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line in output.splitlines():
        at = line.find(PREFIX)
        if at < 0:
            continue
        raw: Any = json.loads(line[at + len(PREFIX) :])
        if not isinstance(raw, dict):
            raise ValueError(f"an evidence line is not an object: {line[:200]}")
        records.append(raw)
    return records


def judge_egress(output: str, code: int) -> Outcome:
    """Every expected case reported, every weakened topology detected, every
    bypass refused by a mechanism that explains it, and the evidence task
    itself passed."""
    try:
        records = _records(output)
    except (ValueError, json.JSONDecodeError) as exc:
        return Outcome(Status.ERROR, {}, f"unreadable evidence: {exc}")
    exercised = [
        r for r in records if not str(r.get("outcome", "")).lower().startswith("not-exercised")
    ]
    seen = {(str(r.get("suite")), str(r.get("case"))) for r in exercised}
    found = M5B_CASES & seen
    missing = sorted(f"{s}/{c}" for s, c in M5B_CASES - seen)
    weakened = next(
        (
            WEAKENED_COUNT.fullmatch(str(r.get("outcome")))
            for r in exercised
            if r.get("case") == "weakened-topology-count"
        ),
        None,
    )
    all_detected = weakened is not None and weakened.group(1) == weakened.group(2)
    unexplained = sorted(
        str(r.get("case"))
        for r in exercised
        if (str(r.get("suite")), str(r.get("case"))) in BYPASS_CASES
        and not MECHANISM.search(str(r.get("outcome", "")))
    )
    metrics = {
        "cases": float(len(found)),
        "expected_cases": float(len(M5B_CASES)),
        "weakened_detected": float(weakened.group(1)) if weakened else 0.0,
        "bypasses_unexplained": float(len(unexplained)),
        "rejection_rate": (len(found) / len(M5B_CASES))
        if all_detected and not unexplained and code == 0
        else 0.0,
    }
    problems = []
    if code != 0:
        problems.append(f"the evidence task failed (exit {code})")
    if missing:
        problems.append(f"missing cases: {', '.join(missing)}")
    if not all_detected:
        problems.append("a weakened topology escaped detection, or none was measured")
    if unexplained:
        problems.append(f"bypasses refused by no known mechanism: {', '.join(unexplained)}")
    if problems:
        return Outcome(
            Status.FAIL,
            metrics,
            "; ".join(problems)[:MAX_ARTIFACT],
            {"output": output[-MAX_ARTIFACT:]},
        )
    return Outcome(Status.PASS, metrics)


def sandbox_egress(ctx: Context) -> Outcome:
    """ADR-0048: a PROXY_ONLY environment reaches only its proxy; the proxy
    enforces the run's grant, the IP guard, one pinned resolution, server-name
    agreement and budgets at the socket; every bypass fails; every weakened
    topology is detected -- the real evidence task."""
    completed = subprocess.run(
        [sys.executable, "scripts/dw.py", "sandbox-egress-evidence"],
        cwd=str(ctx.repo_root),
        env=dict(os.environ),
        capture_output=True,
        text=True,
        errors="replace",
        timeout=ctx.evaluation.timeout_s,
        check=False,
    )
    return judge_egress(completed.stdout + completed.stderr, completed.returncode)
