"""The result record, and its machine-readable form.

Versioned, because results are compared between commits and a format change
must be visible rather than inferred. JSONL, because a line per result diffs
well, streams, and needs no library to read.

Large data never goes in a result. A runner that wants to show a failing input
puts a bounded string in ``artifacts``; anything bigger belongs in a file the
result references.
"""

from __future__ import annotations

import json
import platform
import sys
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

from direwolf_evals.model import Status

__all__ = [
    "RESULT_VERSION",
    "Result",
    "RunReport",
    "environment",
    "read_jsonl",
    "write_jsonl",
]

RESULT_VERSION: Final = 1
MAX_ARTIFACT_CHARS: Final = 2000


def environment() -> dict[str, str]:
    """What ran the eval. Recorded, never compared against a baseline."""
    return {
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "system": platform.system(),
        "machine": platform.machine(),
        "executable": Path(sys.executable).name,
    }


@dataclass(frozen=True, slots=True)
class Result:
    """One run of one eval."""

    eval_id: str
    suite: str
    status: Status
    score: float | None
    """The suite's measure for this eval; ``None`` when it does not apply
    (pending, skipped, errored). What it *means* is the suite's ``score``."""
    runs: int
    run_index: int
    duration_ms: float
    seed: int
    reason: str = ""
    metrics: dict[str, float] = field(default_factory=dict)
    artifacts: dict[str, str] = field(default_factory=dict)
    fixture: str | None = None
    fixture_digest: str | None = None
    requires: tuple[str, ...] = ()

    def to_json(self, env: dict[str, str]) -> dict[str, Any]:
        return {
            "result_version": RESULT_VERSION,
            "eval_id": self.eval_id,
            "suite": self.suite,
            "status": str(self.status),
            "score": self.score,
            "runs": self.runs,
            "run_index": self.run_index,
            "duration_ms": round(self.duration_ms, 3),
            "seed": self.seed,
            "reason": self.reason,
            "metrics": {k: self.metrics[k] for k in sorted(self.metrics)},
            "artifacts": {
                k: self.artifacts[k][:MAX_ARTIFACT_CHARS] for k in sorted(self.artifacts)
            },
            "fixture": self.fixture,
            "fixture_digest": self.fixture_digest,
            "requires": list(self.requires),
            "environment": env,
        }


@dataclass(slots=True)
class RunReport:
    """Every result of one invocation, plus the counts a gate acts on."""

    results: list[Result] = field(default_factory=list)

    def add(self, result: Result) -> None:
        self.results.append(result)

    @property
    def ordered(self) -> list[Result]:
        return sorted(self.results, key=lambda r: (r.eval_id, r.run_index))

    def counts(self) -> dict[str, int]:
        counts = {str(s): 0 for s in Status}
        for result in self.results:
            counts[str(result.status)] += 1
        return counts

    @property
    def failed(self) -> bool:
        """A run fails on FAIL or ERROR. Pending and skipped are not failures,
        and are not successes either: the gate reports them separately."""
        return any(r.status in (Status.FAIL, Status.ERROR) for r in self.results)

    def duration_ms(self) -> float:
        return sum(r.duration_ms for r in self.results)


def write_jsonl(path: Path, results: Iterable[Result], env: dict[str, str] | None = None) -> None:
    """Write results as one JSON object per line, ordered for diffing."""
    env = environment() if env is None else env
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [
        json.dumps(result.to_json(env), ensure_ascii=True, sort_keys=True)
        for result in sorted(results, key=lambda r: (r.eval_id, r.run_index))
    ]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")


def read_jsonl(path: Path) -> Iterator[dict[str, Any]]:
    """Read a results file written by :func:`write_jsonl`."""
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            parsed: dict[str, Any] = json.loads(line)
            yield parsed
