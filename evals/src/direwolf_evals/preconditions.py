"""What an eval needs from the machine it runs on, and whether it has it.

A milestone decides whether a property *exists* (``requires``). Some properties
exist and still cannot be measured on every machine:

* ``platforms`` — the DWKP server runs only on Linux (ADR-0041), so its
  transport evals cannot run on macOS or Windows. That is a fact about the
  product, stated, not a gap to paper over.
* ``needs = ["second-identity"]`` — a cross-uid property is measured only by a
  process running as **another operating-system user**, which a one-user
  workstation does not have. ``DW_PEER_AS`` names that user, ``sudo -n -u``
  must be able to start a process as it without a password, and the uid that
  process reports must be neither this process's nor root's.

An eval whose precondition is unmet is **not exercised**: SKIP, with a reason
generated here, never a pass and never pending (the component exists). The
merge gate lists it separately; CI's gate runs with
``DW_EVAL_REQUIRE_EXERCISED=1``, where "not exercised" fails, and provides
both Linux and the second identity. A local run says, loudly, what it did not
measure.

Closed vocabularies: a platform or need this module does not know is a
discovery error, so a typo cannot silently turn an eval off.
"""

from __future__ import annotations

import functools
import os
import shutil
import subprocess
import sys
from collections.abc import Sequence
from typing import Final

__all__ = [
    "NEEDS",
    "NOT_EXERCISED",
    "PLATFORMS",
    "current_platform",
    "second_identity",
    "unmet",
]

PLATFORMS: Final = frozenset({"linux", "macos", "windows"})
NEEDS: Final = frozenset({"second-identity"})

NOT_EXERCISED: Final = "not exercised"
"""The prefix of every precondition reason. Stable, so a reader can grep."""

PEER_ENV: Final = "DW_PEER_AS"


def current_platform() -> str:
    """``linux``, ``macos`` or ``windows`` — or the raw name of anything else,
    which no eval declares and which therefore runs nothing platform-bound."""
    # Read into a plain `str`: a type checker narrows `sys.platform` to the
    # platform it runs on and would call the other branches unreachable.
    name: str = str(sys.platform)
    if name.startswith("linux"):
        return "linux"
    if name == "darwin":
        return "macos"
    if name in ("win32", "cygwin"):
        return "windows"
    return name


@functools.cache
def second_identity() -> str | None:
    """The user ``DW_PEER_AS`` names, if it is provably a second, ordinary
    identity.

    Proven by numbers, not by reading configuration or trusting a name:
    ``sudo -n -u <user> id -u`` must start a real process as that user, and the
    uid that process reports must differ from this process's effective uid and
    must not be root's (root is outside the threat model; the hostile peer is
    an ordinary local user). Anything less is no second identity and the eval
    is not exercised -- which the strict gate fails. Cached for the process —
    the answer does not change during a run.
    """
    user = os.environ.get(PEER_ENV, "").strip()
    if not user or current_platform() != "linux" or shutil.which("sudo") is None:
        return None
    try:
        probe = subprocess.run(
            ["sudo", "-n", "-u", user, "id", "-u"],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    reported = probe.stdout.strip()
    if probe.returncode != 0 or not reported.isdigit():
        return None
    if int(reported) in (0, _effective_uid()):
        return None
    return user


def _effective_uid() -> int:
    """This process's effective uid, on the one platform that asks."""
    geteuid = getattr(os, "geteuid", None)
    return int(geteuid()) if callable(geteuid) else -1


def unmet(platforms: Sequence[str], needs: Sequence[str]) -> str | None:
    """Why this machine cannot exercise an eval, or ``None`` if it can."""
    here = current_platform()
    if platforms and here not in platforms:
        return f"{NOT_EXERCISED}: runs on {', '.join(sorted(platforms))}, not {here}"
    for need in sorted(needs):
        if need == "second-identity" and second_identity() is None:
            return (
                f"{NOT_EXERCISED}: needs a second operating-system identity; set {PEER_ENV} "
                f"to a user that `sudo -n -u` can switch to, other than this one and root"
            )
    return None
