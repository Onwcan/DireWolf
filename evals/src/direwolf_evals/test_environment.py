"""A test double for "something ran", and nothing more.

`docs/EVALS.md` needs a mock `ExecutionEnvironment` so that suites can exercise
success, failure, timeout, crash and partial-result handling before anything can
really execute. This is that double.

**It is not the product interface.** DireWolf's real `ExecutionEnvironment`
arrives at M5, in `dwkd-broker`, in Rust, behind the authority boundary. This
module:

* lives in the eval package, which no daemon and no runtime module may import
  (`architecture.toml`, rule PY003);
* runs nothing. It returns a recorded outcome for a declared job. There is no
  shell, no subprocess, no filesystem write and no network;
* names itself after what it is, so nobody can mistake it for the real thing.

If you find yourself wanting to add "just run this command" here, that is the
moment the eval harness would become a second path from cognition to effect.
The answer is the fault-injection harness (:mod:`direwolf_evals.process`),
which drives one fixed dummy program.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Final

__all__ = ["EvalTestEnvironment", "JobOutcome", "SimulatedBehaviour"]


class SimulatedBehaviour(StrEnum):
    """What the double pretends happened."""

    SUCCESS = "success"
    FAILURE = "failure"
    TIMEOUT = "timeout"
    CRASH = "crash"
    PARTIAL = "partial"


@dataclass(frozen=True, slots=True)
class JobOutcome:
    behaviour: SimulatedBehaviour
    exit_code: int
    output: str
    truncated: bool
    duration_ms: float

    @property
    def succeeded(self) -> bool:
        return self.behaviour is SimulatedBehaviour.SUCCESS


_EXIT_CODES: Final = {
    SimulatedBehaviour.SUCCESS: 0,
    SimulatedBehaviour.FAILURE: 1,
    SimulatedBehaviour.TIMEOUT: 124,
    SimulatedBehaviour.CRASH: 70,
    SimulatedBehaviour.PARTIAL: 0,
}


@dataclass(frozen=True, slots=True)
class EvalTestEnvironment:
    """Deterministic, side-effect-free stand-in for an execution environment."""

    name: str = "eval-test-environment"

    def run(
        self,
        job: str,
        behaviour: SimulatedBehaviour,
        *,
        output: str = "",
        duration_ms: float = 0.0,
    ) -> JobOutcome:
        """Return the declared outcome for ``job``. Executes nothing."""
        if not job:
            raise ValueError("a job needs a name, so a failure can name it")
        truncated = behaviour is SimulatedBehaviour.PARTIAL
        text = output if not truncated else output[: max(1, len(output) // 2)]
        return JobOutcome(
            behaviour=behaviour,
            exit_code=_EXIT_CODES[behaviour],
            output=text,
            truncated=truncated,
            duration_ms=duration_ms,
        )
