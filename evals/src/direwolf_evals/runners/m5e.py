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

__all__ = ["INVENTORY", "READY", "gate", "judge_gate"]

MAX_ARTIFACT: Final = 1500
INVENTORY: Final = "M5 gate: inventory verdict: COMPLETE"
# The acceptance verdict's own line, colour codes aside.
READY: Final = re.compile(r"^(?:\x1b\[[0-9;]*m)*M5e acceptance verdict: READY(?:\x1b\[[0-9;]*m)*$")
NOT_READY: Final = "M5e acceptance verdict: NOT READY"


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


def gate(ctx: Context) -> Outcome:
    """M5e.6: this run's M5 evidence bundles judged again, and the M5e
    acceptance verdict -- the real gate task, in its own job."""
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
    return judge_gate(completed.stdout + completed.stderr, completed.returncode)
