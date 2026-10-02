"""M5a runner: the execution-environment foundation, measured as the product.

Like every runner since M3, this reimplements nothing. It runs the real
evidence task -- `scripts/dw.py sandbox-foundation-evidence`: the released
broker driving a real OCI runtime, real containers, the digest-pinned probe,
and the real authority recording the lifecycle -- and judges the evidence
lines each passing case prints after its assertions held (ADR-0047).

Every case the runner expects is listed here. A case that silently stopped
running is a FAIL naming it, never a smaller denominator; a weakened profile
the measurement did not catch is a FAIL; the task's own failure -- including
NOT EXERCISED -- is a FAIL.

The judging function takes the task's output and nothing else, so the meta
tests can hand it a regression -- a missing case, an undetected weakening --
and watch the gate fail.
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

__all__ = ["M5A_CASES", "judge_sandbox", "sandbox_foundation"]

MAX_ARTIFACT: Final = 1500
PREFIX: Final = "SANDBOX-EVIDENCE "

# The cases that state the M5a properties, by class.
M5A_CASES: Final = frozenset(
    {
        # Every oci-strict hard rule measured on a real container, both vantages.
        ("sandbox-broker", "prepare-clean"),
        ("sandbox-broker", "host-image-pinned"),
        ("sandbox-broker", "host-probe-digest"),
        ("sandbox-broker", "host-not-privileged"),
        ("sandbox-broker", "host-user-non-root"),
        ("sandbox-broker", "host-root-read-only"),
        ("sandbox-broker", "host-capabilities-dropped"),
        ("sandbox-broker", "host-no-new-privileges"),
        ("sandbox-broker", "host-seccomp-profile"),
        ("sandbox-broker", "host-pid-private"),
        ("sandbox-broker", "host-ipc-private"),
        ("sandbox-broker", "host-network-isolated"),
        ("sandbox-broker", "host-no-runtime-socket"),
        ("sandbox-broker", "host-no-devices"),
        ("sandbox-broker", "host-resource-limits"),
        ("sandbox-broker", "container-uid-gid"),
        ("sandbox-broker", "container-capabilities-empty"),
        ("sandbox-broker", "container-seccomp-profile-active"),
        ("sandbox-broker", "container-root-read-only"),
        ("sandbox-broker", "container-network-isolated"),
        ("sandbox-broker", "container-cgroup-limits"),
        ("sandbox-broker", "escape-mount-blocked"),
        ("sandbox-broker", "escape-unshare-blocked"),
        ("sandbox-broker", "escape-setns-blocked"),
        ("sandbox-broker", "escape-keyring-blocked"),
        # Measurement detects each weakened profile, rather than trusting
        # construction.
        ("sandbox-broker", "baseline-conforming"),
        ("sandbox-broker", "weakened-writable-root"),
        ("sandbox-broker", "weakened-root-user"),
        ("sandbox-broker", "weakened-privileged"),
        ("sandbox-broker", "weakened-runtime-socket-mounted"),
        ("sandbox-broker", "weakened-capability-added"),
        ("sandbox-broker", "weakened-no-new-privileges-disabled"),
        ("sandbox-broker", "weakened-seccomp-unconfined"),
        ("sandbox-broker", "weakened-seccomp-default-profile"),
        ("sandbox-broker", "weakened-host-pid"),
        ("sandbox-broker", "weakened-host-ipc"),
        ("sandbox-broker", "weakened-host-network"),
        ("sandbox-broker", "weakened-mutable-image-tag"),
        ("sandbox-broker", "weakened-extra-device"),
        ("sandbox-broker", "weakened-resource-limits-dropped"),
        ("sandbox-broker", "weakened-count"),
        # A probe that is not the pinned one is never believed.
        ("sandbox-broker", "tamper-changed-byte"),
        ("sandbox-broker", "tamper-substituted-probe"),
        ("sandbox-broker", "tamper-malformed-output"),
        ("sandbox-broker", "tamper-truncated-output"),
        ("sandbox-broker", "tamper-extra-field"),
        # Foreign containers survive; temporary state does not persist; runs are
        # isolated; drift is found.
        ("sandbox-broker", "foreign-not-listed"),
        ("sandbox-broker", "foreign-survive"),
        ("sandbox-broker", "persistence-tmp-marker-not-inherited"),
        ("sandbox-broker", "run-isolation-tmp"),
        ("sandbox-broker", "drift-pids-limit-raised"),
        # The authority's lifecycle: intent before effect, exact reaping.
        ("sandbox-authority", "prepare-intent-durable-before-broker"),
        ("sandbox-authority", "effective-assurance-container-isolation"),
        ("sandbox-authority", "crash-w4-after-broker-reaped"),
        ("sandbox-authority", "orphan-ended-record-reaped"),
        ("sandbox-authority", "foreign-copied-labels-survive"),
        ("sandbox-authority", "ambiguous-twins-untouched"),
        ("sandbox-authority", "drift-destroyed"),
    }
)

WEAKENED_COUNT: Final = re.compile(r"detected-(\d+)-of-(\d+)")


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


def judge_sandbox(output: str, code: int) -> Outcome:
    """Every expected case reported by the real suites, every weakened
    profile detected, and the evidence task itself passed."""
    try:
        records = _records(output)
    except (ValueError, json.JSONDecodeError) as exc:
        return Outcome(Status.ERROR, {}, f"unreadable evidence: {exc}")
    seen = {
        (str(r.get("suite")), str(r.get("case")))
        for r in records
        if not str(r.get("outcome", "")).lower().startswith("not-exercised")
    }
    found = M5A_CASES & seen
    missing = sorted(f"{s}/{c}" for s, c in M5A_CASES - seen)
    weakened = next(
        (
            WEAKENED_COUNT.fullmatch(str(r.get("outcome")))
            for r in records
            if r.get("case") == "weakened-count"
        ),
        None,
    )
    all_detected = weakened is not None and weakened.group(1) == weakened.group(2)
    metrics = {
        "cases": float(len(found)),
        "expected_cases": float(len(M5A_CASES)),
        "weakened_detected": float(weakened.group(1)) if weakened else 0.0,
        "rejection_rate": (len(found) / len(M5A_CASES)) if all_detected and code == 0 else 0.0,
    }
    problems = []
    if code != 0:
        problems.append(f"the evidence task failed (exit {code})")
    if missing:
        problems.append(f"missing cases: {', '.join(missing)}")
    if not all_detected:
        problems.append("a weakened profile escaped detection, or none was measured")
    if problems:
        return Outcome(
            Status.FAIL,
            metrics,
            "; ".join(problems)[:MAX_ARTIFACT],
            {"output": output[-MAX_ARTIFACT:]},
        )
    return Outcome(Status.PASS, metrics)


def sandbox_foundation(ctx: Context) -> Outcome:
    """ADR-0047: the oci-strict hard rules measured on a real container from
    the runtime's record and from inside, every weakened profile detected,
    every tampered probe refused, foreign containers spared, exact orphans
    reaped, temporary state not persisted -- the real evidence task."""
    completed = subprocess.run(
        [sys.executable, "scripts/dw.py", "sandbox-foundation-evidence"],
        cwd=str(ctx.repo_root),
        env=dict(os.environ),
        capture_output=True,
        text=True,
        errors="replace",
        timeout=ctx.evaluation.timeout_s,
        check=False,
    )
    return judge_sandbox(completed.stdout + completed.stderr, completed.returncode)
