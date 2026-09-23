"""The runner registry: the only way a suite file can name executable code.

A suite says ``runner = "protocol.hostile_vectors"``. That string is looked up
in a table declared here, in Python, under review. It is not an import path, not
a dotted attribute walk, and not a callable pulled out of a fixture: a suite file
is data, and data must not be able to choose arbitrary code (`docs/EVALS.md`;
the same reasoning that keeps opaque payloads off DWKP).
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from direwolf_evals.model import Eval, Outcome
from direwolf_evals.runners import authority, harness, protocol, replay

__all__ = ["RUNNERS", "Context", "Runner", "resolve"]


@dataclass(frozen=True, slots=True)
class Context:
    """What a runner is given: the eval, where things are, and its seed."""

    evaluation: Eval
    repo_root: Path
    evals_root: Path
    seed: int
    run_index: int


Runner = Callable[[Context], Outcome]

RUNNERS: dict[str, Runner] = {
    # Protocol: hostile input decided by the real decoder, never a copy of it.
    "protocol.hostile_vectors": protocol.hostile_vectors,
    "protocol.framing": protocol.framing,
    "protocol.reserved_operations": protocol.reserved_operations,
    "protocol.compatibility": protocol.compatibility,
    "protocol.canonical_determinism": protocol.canonical_determinism,
    # Replay: recorded responses, no provider, no network.
    "replay.deterministic": replay.deterministic,
    "replay.fixture_integrity": replay.fixture_integrity,
    # M3: the authority as the product -- the real process, the real socket,
    # the real lattice and engine. Never a model of them.
    "authority.hostile_dwkp_client": authority.hostile_dwkp_client,
    "authority.peer_credential_check": authority.peer_credential_check,
    "authority.epoch_fencing": authority.epoch_fencing,
    "authority.policy_denies_by_default": authority.policy_denies_by_default,
    "authority.capability_attenuation": authority.capability_attenuation,
    # The harness proving itself against a dummy process.
    "harness.checkpoint": harness.checkpoint,
    "harness.pause_resume": harness.pause_resume,
    "harness.timeout": harness.timeout,
    "harness.crash": harness.crash,
    "harness.test_environment": harness.test_environment,
}


def resolve(name: str) -> Runner:
    runner = RUNNERS.get(name)
    if runner is None:
        raise KeyError(f"unknown runner {name!r}; add it to direwolf_evals.runners.RUNNERS")
    return runner
