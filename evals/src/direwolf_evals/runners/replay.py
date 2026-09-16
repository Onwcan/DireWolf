"""Replay: recorded responses, deterministically, with no provider anywhere.

A replay fixture holds what a future model-driven eval needs — the input, the
recorded response, any structured tool-call-shaped output, and the metadata a
scorer will read — and nothing that pretends to be transport. There is no
``ModelProvider`` here, no client, no base URL and no credential: M7 owns the
provider path, and building a fake one now would be exactly the "fake IPC" M2.5
is told not to build.

What these runners measure today:

* **fixture integrity** — the recorded content still hashes to what the fixture
  says, so a silently edited expectation is a failure rather than a new truth;
* **replay determinism** — rendering the same fixture twice produces the same
  bytes, which is the property a future model eval will rest its scoring on.
"""

from __future__ import annotations

import json
from typing import TYPE_CHECKING, Any

from direwolf.wire import jcs
from direwolf_evals.fixtures import digest_bytes, load_fixture
from direwolf_evals.model import Outcome, Status

if TYPE_CHECKING:  # pragma: no cover
    from direwolf_evals.runners import Context

__all__ = ["deterministic", "fixture_integrity", "render_case"]


def render_case(case: dict[str, Any]) -> bytes:
    """One canonical rendering of a replayed exchange.

    RFC 8785 is reused here for the same reason the protocol uses it: the bytes
    must not depend on key order or on how a number was spelled, so "the same
    answer" is a byte comparison rather than a judgement call.
    """
    return jcs.canonicalize(
        {
            "id": case["id"],
            "input": case["input"],
            "response": case["response"],
            "metadata": case.get("metadata", {}),
        }
    )


def deterministic(ctx: Context) -> Outcome:
    """Replaying a fixture twice yields identical bytes for every case.

    Score: the fraction of cases that replayed identically.
    """
    fixture = _fixture(ctx)
    cases = fixture.require("cases")
    failures = []
    for case in cases:
        first = render_case(case)
        second = render_case(json.loads(json.dumps(case)))
        if first != second:
            failures.append(f"{case.get('id', '?')}: replay is not byte-identical")
    return Outcome(
        status=Status.PASS if not failures else Status.FAIL,
        metrics={
            "cases": float(len(cases)),
            "identical": float(len(cases) - len(failures)),
            "determinism_rate": (len(cases) - len(failures)) / len(cases) if cases else 0.0,
        },
        reason="" if not failures else "; ".join(failures[:3]),
    )


def fixture_integrity(ctx: Context) -> Outcome:
    """Each case's recorded digest still matches its content.

    Score: the fraction of cases whose digest matches. A fixture edited without
    updating its digest is a changed expectation nobody reviewed.
    """
    fixture = _fixture(ctx)
    cases = fixture.require("cases")
    failures = []
    for case in cases:
        recorded = case.get("digest")
        if not recorded:
            failures.append(f"{case.get('id', '?')}: no digest recorded")
            continue
        actual = digest_bytes(render_case(case))
        if actual != recorded:
            failures.append(f"{case['id']}: digest {actual} does not match recorded {recorded}")
    return Outcome(
        status=Status.PASS if not failures else Status.FAIL,
        metrics={
            "cases": float(len(cases)),
            "intact": float(len(cases) - len(failures)),
        },
        reason="" if not failures else "; ".join(failures[:3]),
        artifacts={"provenance": fixture.provenance},
    )


def _fixture(ctx: Context) -> Any:
    if ctx.evaluation.fixture is None:
        raise ValueError(f"{ctx.evaluation.id} needs a fixture")
    return load_fixture(ctx.evals_root / "fixtures", ctx.evaluation.fixture)
