"""M5e runner: the integrated M5 gate, judged as the product.

Like every runner since M3, this reimplements nothing. It runs the gate task
-- `scripts/dw.py m5e-gate-check`, in CI's `m5e-gate` job, over the bundles
this run's M5 evidence jobs uploaded -- and reads the two verdicts it prints:
the inventory verdict, which the task enforces itself, and the M5e acceptance
verdict, which only this eval enforces.

A pass needs the task to exit 0, its inventory verdict COMPLETE and its
acceptance verdict READY. A NOT READY verdict is a FAIL naming its blockers;
the task's own failure -- a missing or foreign bundle, a case that fails its
judgement again, NOT EXERCISED off its job -- is a FAIL. The judging function
takes the task's output and exit code and nothing else, so the meta tests can
hand it each verdict and watch the gate fail.
"""

from __future__ import annotations

import os
import re
import subprocess
import sys
from typing import TYPE_CHECKING, Final

from direwolf_evals.model import Outcome, Status

if TYPE_CHECKING:  # pragma: no cover - import cycle only matters to type checkers
    from direwolf_evals.runners import Context

__all__ = ["EGRESS_TASKS", "INVENTORY", "READY", "egress", "gate", "judge_egress", "judge_gate"]

MAX_ARTIFACT: Final = 1500
INVENTORY: Final = "M5 gate: inventory verdict: COMPLETE"
# The acceptance verdict's own line, colour codes aside.
READY: Final = re.compile(r"^(?:\x1b\[[0-9;]*m)*M5e acceptance verdict: READY(?:\x1b\[[0-9;]*m)*$")
NOT_READY: Final = "M5e acceptance verdict: NOT READY"
# The evidence tasks whose bundles measure a real PROXY_ONLY workload end
# to end: the egress topology and its bypasses, and an agent-shaped run's
# workloads through it.
EGRESS_TASKS: Final = ("sandbox-egress-evidence", "sandbox-agent-evidence")
JUDGED_AGAIN: Final = re.compile(r"^  ([a-z0-9-]+): ([0-9]+) case\(s\) judged again$")


def judge_gate(output: str, code: int) -> Outcome:
    """The gate task passed, its inventory complete and M5e READY."""
    lines = output.splitlines()
    complete = any(INVENTORY in line for line in lines)
    ready = any(READY.match(line) for line in lines) and NOT_READY not in output
    metrics = {
        "inventory_complete": 1.0 if complete and code == 0 else 0.0,
        "acceptance_ready": 1.0 if ready and code == 0 else 0.0,
    }
    problems = []
    if code != 0:
        problems.append(f"the gate task failed (exit {code})")
    if not complete:
        problems.append("no complete inventory verdict")
    if not ready:
        problems.append("the M5e acceptance verdict is not READY")
    if problems:
        return Outcome(
            Status.FAIL,
            metrics,
            "; ".join(problems)[:MAX_ARTIFACT],
            {"output": output[-MAX_ARTIFACT:]},
        )
    return Outcome(Status.PASS, metrics)


def judge_egress(output: str, code: int) -> Outcome:
    """The gate task passed with a complete inventory, and judged again a
    case or more of each egress task's bundle: M5's sandboxed workload
    egress, end to end (`pending-kernel/sandbox-egress`)."""
    lines = output.splitlines()
    complete = any(INVENTORY in line for line in lines)
    judged: dict[str, int] = {}
    for line in lines:
        found = JUDGED_AGAIN.match(line)
        if found:
            judged[found[1]] = int(found[2])
    problems = []
    if code != 0:
        problems.append(f"the gate task failed (exit {code})")
    if not complete:
        problems.append("no complete inventory verdict")
    for task in EGRESS_TASKS:
        if judged.get(task, 0) < 1:
            problems.append(f"no case of {task} judged again")
    metrics = {
        "inventory_complete": 1.0 if complete and code == 0 else 0.0,
        "egress_cases_judged": float(sum(judged.get(t, 0) for t in EGRESS_TASKS)),
    }
    if problems:
        return Outcome(
            Status.FAIL,
            metrics,
            "; ".join(problems)[:MAX_ARTIFACT],
            {"output": output[-MAX_ARTIFACT:]},
        )
    return Outcome(Status.PASS, metrics)


def _run_gate(ctx: Context) -> tuple[str, int]:
    completed = subprocess.run(
        [sys.executable, "scripts/dw.py", "m5e-gate-check"],
        cwd=str(ctx.repo_root),
        env=dict(os.environ),
        capture_output=True,
        text=True,
        errors="replace",
        timeout=ctx.evaluation.timeout_s,
        check=False,
    )
    return completed.stdout + completed.stderr, completed.returncode


def egress(ctx: Context) -> Outcome:
    """M5 (G6): sandboxed workload egress, end to end -- the gate task's own
    judgement, again, of the egress and agent evidence this run kept, which
    measure a real PROXY_ONLY workload through the released stack."""
    return judge_egress(*_run_gate(ctx))


def gate(ctx: Context) -> Outcome:
    """M5e.6: this run's M5 evidence bundles judged again, and the M5e
    acceptance verdict -- the real gate task, in its own job."""
    return judge_gate(*_run_gate(ctx))
