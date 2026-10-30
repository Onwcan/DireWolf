#!/usr/bin/env python3
"""Hand an evidence job's fixture configuration across `sudo --user "$USER"`.

    python3 scripts/ci_handoff.py --pass DW_BROKER_AS --pass DW_PEER_AS \\
        --group dwwrite -- make filesystem-operations-evidence

Three hosted jobs run their evidence as a fresh session of the runner's own
user, so that the groups the job just added it to are in force: `sudo --user
"$USER"` re-reads the group database. Until CI #106 they also relied on a bare
`--preserve-env` to carry the step's `DW_*` configuration across. On the
Ubuntu 26.04 image `sudo` is sudo-rs, whose `env_reset` cannot be disabled
(sudoers-rs(5)), so that carried nothing: each job reported its hosted-only
half NOT EXERCISED, and failed, as it must (run 40954372045).

Nothing is left implicit now. Before the switch this script proves each named
variable is present, written in the closed character set of an identity, a
group or a flag, and that a `*_PRIVILEGED` flag is handed over only on a
GitHub-hosted runner. The switch passes each value as an argument of `env`,
which no `sudo` filters, and nothing else of the step's environment but
`PATH`. After it the same script, now the target process, proves it is the
runner's user (numeric, never root), holds each named group (numeric), and
holds exactly the values that left -- their digest travels in argv -- and only
then becomes the command, by `exec`. A prerequisite missing fails here, before
anything runs; the evidence task still fails NOT EXERCISED on its own when a
half it requires is not provisioned.
"""

from __future__ import annotations

import argparse
import contextlib
import grp
import hashlib
import os
import pwd
import re
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path

# An identity, a group or a flag: nothing a shell, `env` or `sudo` reads
# specially, and never a path or a secret.
VALUE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}")
NAME = re.compile(r"DW_[A-Z0-9_]+")


class HandoffError(Exception):
    """A prerequisite the evidence needs is not there."""


def digest(values: Mapping[str, str]) -> str:
    """The handed-over values, canonically: `name=value` lines, sorted."""
    text = "".join(f"{name}={values[name]}\n" for name in sorted(values))
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def before(
    environ: Mapping[str, str], names: Sequence[str], groups: Sequence[str], uid: int
) -> dict[str, str]:
    """What leaves: each named variable, validated, from the step's environment."""
    if uid == 0:
        raise HandoffError("the evidence runs as the runner's own user, never as root")
    if not names:
        raise HandoffError("nothing to hand over: name each variable with --pass")
    values: dict[str, str] = {}
    for name in names:
        if not NAME.fullmatch(name):
            raise HandoffError(f"{name}: only DW_* configuration is handed over")
        value = environ.get(name, "")
        if not value:
            raise HandoffError(f"{name} is unset before the identity switch")
        if not VALUE.fullmatch(value):
            raise HandoffError(f"{name}={value!r} is not an identity, a group or a flag")
        values[name] = value
    privileged = [name for name in values if name.endswith("_PRIVILEGED")]
    if privileged and environ.get("RUNNER_ENVIRONMENT") != "github-hosted":
        raise HandoffError(
            f"{', '.join(privileged)} provisions the host: only a disposable GitHub-hosted "
            f"runner is handed it (RUNNER_ENVIRONMENT is "
            f"{environ.get('RUNNER_ENVIRONMENT', 'unset')!r})"
        )
    for group in groups:
        if not VALUE.fullmatch(group):
            raise HandoffError(f"{group!r} is not a group name")
    return values


def after(
    environ: Mapping[str, str],
    names: Sequence[str],
    expected: str,
    ids: tuple[int, int],
    want_uid: int,
    gids: Sequence[int],
    want_gids: Mapping[str, int],
) -> dict[str, str]:
    """What arrived: the same values, in the runner's own non-root session,
    holding every named group -- or nothing runs."""
    real, effective = ids
    if real != want_uid or effective != want_uid:
        raise HandoffError(f"running as uid {real}/{effective}, not the runner's uid {want_uid}")
    if real == 0:
        raise HandoffError("the evidence would run as root")
    missing = [name for name in names if not environ.get(name)]
    if missing:
        raise HandoffError(f"lost across the identity switch: {', '.join(missing)}")
    values = {name: environ[name] for name in names}
    if digest(values) != expected:
        raise HandoffError("the values that arrived are not the values that left")
    stray = sorted(name for name in environ if NAME.fullmatch(name) and name not in values)
    if stray:
        raise HandoffError(f"configuration nobody handed over arrived: {', '.join(stray)}")
    held = set(gids)
    absent = [f"{group} (gid {gid})" for group, gid in want_gids.items() if gid not in held]
    if absent:
        raise HandoffError(f"the session does not hold: {', '.join(absent)}")
    return values


def switch(
    values: Mapping[str, str],
    names: Sequence[str],
    groups: Sequence[str],
    user: str,
    uid: int,
    path: str,
    command: Sequence[str],
) -> list[str]:
    """The identity switch, as one argv: `sudo` runs `env`, `env` sets exactly
    `PATH` and the handed-over values, and this script checks them again."""
    return [
        "sudo",
        "--non-interactive",
        "--user",
        user,
        "env",
        f"PATH={path}",
        *(f"{name}={values[name]}" for name in names),
        sys.executable,
        str(Path(__file__).resolve()),
        *(f"--pass={name}" for name in names),
        *(f"--group={group}" for group in groups),
        f"--after-uid={uid}",
        f"--after-digest={digest(values)}",
        "--",
        *command,
    ]


def _identity(value: str) -> str:
    """A value's numeric meaning on this host, for the log."""
    meanings = []
    with contextlib.suppress(KeyError):
        meanings.append(f"uid {pwd.getpwnam(value).pw_uid}")
    with contextlib.suppress(KeyError):
        meanings.append(f"gid {grp.getgrnam(value).gr_gid}")
    return ", ".join(meanings) or "no user or group of that name"


def _gids(groups: Sequence[str]) -> dict[str, int]:
    found: dict[str, int] = {}
    for group in groups:
        try:
            found[group] = grp.getgrnam(group).gr_gid
        except KeyError as exc:
            raise HandoffError(f"no group {group!r} on this host") from exc
    return found


def _report(stage: str, values: Mapping[str, str]) -> None:
    held = ",".join(str(gid) for gid in sorted(set(os.getgroups())))
    print(
        f"handoff {stage}: uid={os.getuid()} euid={os.geteuid()} gid={os.getgid()} groups={held}",
        flush=True,
    )
    for name in sorted(values):
        print(f"handoff {stage}: {name}={values[name]} ({_identity(values[name])})", flush=True)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ci_handoff", description=__doc__.splitlines()[0])
    parser.add_argument("--pass", dest="names", action="append", default=[], metavar="NAME")
    parser.add_argument("--group", dest="groups", action="append", default=[], metavar="GROUP")
    parser.add_argument("--after-uid", type=int, help=argparse.SUPPRESS)
    parser.add_argument("--after-digest", default="", help=argparse.SUPPRESS)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("no command: ci_handoff.py --pass NAME ... -- make <task>")
    try:
        if args.after_uid is None:
            values = before(os.environ, args.names, args.groups, os.getuid())
            _gids(args.groups)
            _report("before", values)
            argv_ = switch(
                values,
                args.names,
                args.groups,
                pwd.getpwuid(os.getuid()).pw_name,
                os.getuid(),
                os.environ.get("PATH", ""),
                command,
            )
            # Replaced, not spawned: the switch's exit status is the job's.
            os.execvp(argv_[0], argv_)  # noqa: S606 - a fixed argv, no shell
        values = after(
            os.environ,
            args.names,
            args.after_digest,
            (os.getuid(), os.geteuid()),
            args.after_uid,
            [os.getgid(), *os.getgroups()],
            _gids(args.groups),
        )
        _report("after", values)
        print(f"handoff verified; running: {' '.join(command)}", flush=True)
        # The verified process becomes the evidence: same pid, same identity,
        # same environment.
        os.execvp(command[0], command)  # noqa: S606 - a fixed argv, no shell
    except HandoffError as exc:
        print(f"ci_handoff: {exc}", file=sys.stderr, flush=True)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
