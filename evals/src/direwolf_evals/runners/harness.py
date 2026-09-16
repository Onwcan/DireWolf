"""The harness proving itself: checkpoints, pausing, timeouts, crashes.

These evals measure the *measuring equipment*. Until M3 there is no real
process to interrupt, so each one drives the dummy child in
:mod:`direwolf_evals.dummy_child`. When the authority daemon exists it will emit
the same checkpoint lines and these runners will not change.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from direwolf_evals.model import Outcome, Status
from direwolf_evals.process import ChildTimeoutError, UnsupportedOnPlatformError, spawn
from direwolf_evals.test_environment import EvalTestEnvironment, SimulatedBehaviour

if TYPE_CHECKING:  # pragma: no cover
    from direwolf_evals.runners import Context

__all__ = ["checkpoint", "crash", "pause_resume", "test_environment", "timeout"]


def checkpoint(ctx: Context) -> Outcome:
    """Named checkpoints arrive, in order, and the child ends cleanly.

    Score: 1.0 when every expected checkpoint was observed in order.
    """
    expected = ["start", "middle", "end"]
    script = "checkpoint:start,emit:working,checkpoint:middle,checkpoint:end,exit:0"
    with spawn(script) as child:
        try:
            for name in expected:
                child.wait_for_checkpoint(name, timeout=ctx.evaluation.timeout_s)
            code = child.wait(timeout=ctx.evaluation.timeout_s)
        except ChildTimeoutError as exc:
            return Outcome(
                Status.FAIL, {"checkpoints_seen": float(len(child.checkpoints()))}, str(exc)
            )
        seen = child.checkpoints()
    ordered = seen == expected
    return Outcome(
        status=Status.PASS if ordered and code == 0 else Status.FAIL,
        metrics={
            "checkpoints_expected": float(len(expected)),
            "checkpoints_seen": float(len(seen)),
        },
        reason="" if ordered and code == 0 else f"saw {seen}, exit {code}",
    )


def pause_resume(ctx: Context) -> Outcome:
    """A child blocked at a checkpoint stays blocked until released.

    Score: 1.0 when the child waits and then continues on command. The
    OS-level variant (SIGSTOP/SIGCONT) is attempted as well; where the platform
    has no equivalent, that half is reported as unsupported rather than passed.
    """
    script = "checkpoint:ready,pause:gate,checkpoint:after,exit:0"
    with spawn(script) as child:
        try:
            child.wait_for_checkpoint("ready", timeout=ctx.evaluation.timeout_s)
            child.wait_for_checkpoint("gate", timeout=ctx.evaluation.timeout_s)
            still_waiting = child.process.poll() is None
            os_level = "unsupported"
            try:
                child.pause()
                child.unpause()
                os_level = "supported"
            except UnsupportedOnPlatformError:
                pass
            child.resume()
            child.wait_for_checkpoint("after", timeout=ctx.evaluation.timeout_s)
            code = child.wait(timeout=ctx.evaluation.timeout_s)
        except ChildTimeoutError as exc:
            return Outcome(Status.FAIL, {}, str(exc))
    passed = still_waiting and code == 0
    return Outcome(
        status=Status.PASS if passed else Status.FAIL,
        metrics={"blocked_at_checkpoint": float(still_waiting), "exit_code": float(code)},
        reason="" if passed else f"blocked={still_waiting} exit={code}",
        artifacts={"os_level_pause": os_level},
    )


def timeout(ctx: Context) -> Outcome:
    """A hung child is detected and terminated, not waited on forever.

    Score: 1.0 when the timeout fires and the process is gone afterwards.
    """
    with spawn("checkpoint:ready,hang") as child:
        child.wait_for_checkpoint("ready", timeout=ctx.evaluation.timeout_s)
        detected = False
        try:
            child.wait(timeout=0.5)
        except ChildTimeoutError:
            detected = True
        child.terminate()
        try:
            child.wait(timeout=ctx.evaluation.timeout_s)
        except ChildTimeoutError:
            return Outcome(
                Status.FAIL, {"timeout_detected": float(detected)}, "the child survived terminate()"
            )
        gone = child.process.poll() is not None
    return Outcome(
        status=Status.PASS if detected and gone else Status.FAIL,
        metrics={"timeout_detected": float(detected), "terminated": float(gone)},
        reason="" if detected and gone else f"detected={detected} terminated={gone}",
    )


def crash(ctx: Context) -> Outcome:
    """An unexpected exit is reported as such, with its code and its output.

    Score: 1.0 when the crash is observed with the expected exit code and the
    output produced before it is still captured — a harness that loses the last
    lines before a crash loses the evidence.
    """
    with spawn("checkpoint:ready,emit:before-crash,crash") as child:
        child.wait_for_checkpoint("ready", timeout=ctx.evaluation.timeout_s)
        code = child.wait(timeout=ctx.evaluation.timeout_s)
        captured = child.stdout
    kept_output = any(line == "OUT before-crash" for line in captured)
    expected_code = code == 70
    return Outcome(
        status=Status.PASS if kept_output and expected_code else Status.FAIL,
        metrics={"exit_code": float(code), "output_retained": float(kept_output)},
        reason="" if kept_output and expected_code else f"exit={code} retained={kept_output}",
    )


def test_environment(_ctx: Context) -> Outcome:
    """The test-only environment double reports each outcome class distinctly.

    Score: the fraction of behaviours (success, failure, timeout, crash,
    partial) that produce the documented outcome. This is a test double, not an
    execution path: it runs nothing.
    """
    environment = EvalTestEnvironment()
    expectations = {
        SimulatedBehaviour.SUCCESS: (0, False),
        SimulatedBehaviour.FAILURE: (1, False),
        SimulatedBehaviour.TIMEOUT: (124, False),
        SimulatedBehaviour.CRASH: (70, False),
        SimulatedBehaviour.PARTIAL: (0, True),
    }
    failures = []
    for behaviour, (code, truncated) in expectations.items():
        outcome = environment.run("fixture-job", behaviour, output="0123456789")
        if outcome.exit_code != code or outcome.truncated != truncated:
            failures.append(f"{behaviour}: exit {outcome.exit_code} truncated {outcome.truncated}")
    return Outcome(
        status=Status.PASS if not failures else Status.FAIL,
        metrics={
            "behaviours": float(len(expectations)),
            "as_documented": float(len(expectations) - len(failures)),
        },
        reason="" if not failures else "; ".join(failures),
    )
