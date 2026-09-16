"""The human summary. The JSONL file is the source of truth; this is for eyes.

Two rules shape it. Pending and skipped are counted apart from passes, because
a summary that adds them together is the exact lie this milestone exists to
prevent. And a failure prints the command that reproduces it, because the first
thing anyone wants after a red line is to run that one eval again.
"""

from __future__ import annotations

from direwolf_evals.model import Status
from direwolf_evals.results import RunReport
from direwolf_evals.statistics import wilson_interval

__all__ = ["render"]

_ICON = {
    Status.PASS: "PASS",
    Status.FAIL: "FAIL",
    Status.ERROR: "ERR ",
    Status.PENDING: "PEND",
    Status.SKIP: "SKIP",
}


def render(report: RunReport, *, verbose: bool = False) -> str:
    lines: list[str] = []
    by_suite: dict[str, list[str]] = {}

    for result in report.ordered:
        suffix = ""
        if result.runs > 1:
            successes = sum(
                1 for r in report.results if r.eval_id == result.eval_id and r.status is Status.PASS
            )
            rate = wilson_interval(successes, result.runs)
            suffix = f"  {rate.describe()}"
        elif result.score is not None:
            suffix = f"  score={result.score:.4f}"
        line = f"  {_ICON[result.status]}  {result.eval_id}{suffix}"
        if result.reason and (verbose or result.status is not Status.PASS):
            line += f"\n        {result.reason}"
        by_suite.setdefault(result.suite, []).append(line)

    for suite in sorted(by_suite):
        lines.append(suite)
        lines.extend(by_suite[suite])

    counts = report.counts()
    lines.append("")
    lines.append(
        "  ".join(f"{name}={counts[name]}" for name in ("pass", "fail", "error", "pending", "skip"))
        + f"  evals={len(report.results)}  {report.duration_ms() / 1000:.2f}s"
    )
    if counts["pending"]:
        lines.append(
            f"  {counts['pending']} pending: not run, and not a pass. "
            f"See `python -m direwolf_evals inventory`."
        )
    failing = [r for r in report.ordered if r.status in (Status.FAIL, Status.ERROR)]
    if failing:
        lines.append("")
        lines.append("reproduce:")
        for result in failing:
            lines.append(
                f"  python -m direwolf_evals run --eval {result.eval_id} --seed {result.seed}"
            )
    return "\n".join(lines)
