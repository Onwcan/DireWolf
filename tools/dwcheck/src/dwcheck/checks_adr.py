"""Accepted ADRs are immutable: this check proves they have not been edited.

The rule is in ``docs/adr/README.md``: an accepted ADR is historical evidence,
and a changed decision produces a *new* ADR that supersedes or amends it. The
rule was broken once, in M2, by appending a dated note to ADR-0019 -- a change
that looked harmless and that no gate would have caught.

There are two mechanisms here, and they are not equally strong. Saying which is
which is the point of this docstring.

**The trust anchor is Git history.** :func:`check_adr_history` finds, for every
ADR, the earliest commit reachable from a base revision in which that ADR
already had an immutable status -- the revision in which it became Accepted --
and compares the working tree against the content it had *there*. A contributor
cannot alter that anchor by editing anything in their own change, because the
anchor is not in their change: it is in the history their change is proposed
against. In CI the base is the merge base with the target branch, which branch
protection keeps outside the pull request's reach.

**The manifest is only a tripwire.** ``docs/adr/accepted.sha256`` records a
digest per accepted ADR. It catches accidental drift, and it works with no Git
history at all -- a release tarball, a shallow clone. It is *not* an
immutability control: it lives in the same mutable working tree as the ADRs, so
whoever edits an ADR can also run ``dwcheck adr --record``, and the two edits
together pass. That combination is exactly what the history anchor exists to
catch. A passing manifest check is not evidence that an accepted record is
unchanged.

The one escape hatch, ``[[adr.history_exceptions]]`` in ``architecture.toml``,
authorises one file to hold one specific content. It does not make that file
mutable: changing it again means changing the recorded digest too, and that is a
line in a diff which says, in words, that ADR immutability is being overridden.
The value is that the override is legible; a re-run of ``--record`` looks like
routine hygiene.

Digests are taken over the file with CRLF normalised to LF, so a Windows
checkout and a Linux one agree. The status line is excluded from the history
comparison, because a superseding ADR has to be able to banner-mark the record
it supersedes; the decision, context and consequences are what is anchored.

What this does not cover, so that nobody reads more into a green run:

* **Once an alteration is merged, it is history.** The anchor is the acceptance
  revision reachable from the base, so this is a gate on the way *in*. It rests
  on branch protection keeping the base branch out of a pull request's reach.
  Anyone who can force-push the base can move the anchor.
* **Nothing here verifies signatures.** Commit and tag signing are a separate
  question and are not required by this project today.
* **The rules file is in the tree too.** Repointing ``[adr].directory`` at an
  empty path would silence every rule here;
  ``tests/architecture/test_boundaries.py`` asserts the anchor actually covered
  this repository's records, and past that, static analysis over a tree the
  author controls bottoms out at review.
* **A shallow clone is refused, not approximated** -- see :func:`_resolve_base`.
"""

from __future__ import annotations

import hashlib
import re
import shutil
import subprocess
from pathlib import Path

from dwcheck import Finding
from dwcheck.config import ArchitectureConfig

__all__ = ["check_adr", "check_adr_history", "record_adr"]

_STATUS = re.compile(r"^\*\*Status:\*\*\s*(?P<status>[^·\n]+)", re.MULTILINE)
_STATUS_LINE = re.compile(r"^\*\*Status:\*\*.*$", re.MULTILINE)
_IMMUTABLE = ("accepted", "superseded")
_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_ADR_GLOB = "[0-9][0-9][0-9][0-9]-*.md"
_ADR_NAME = re.compile(r"^[0-9]{4}-.*\.md$")

_REASON = (
    "Accepted ADRs are immutable (docs/adr/README.md). A changed decision is a new ADR that "
    "supersedes or amends the old one; the old one stays as the record of what was decided and "
    "why. If you meant to add a record, add an ADR. If you meant to supersede one, add the "
    "superseding ADR and update the index in docs/adr/README.md."
)

_HISTORY_REASON = (
    "An ADR that was already Accepted in repository history cannot have its accepted content "
    "altered by a change that also updates docs/adr/accepted.sha256: the anchor is the revision "
    "in which the ADR became Accepted, which is not part of the proposed change. Superseding "
    "happens through a new superseding ADR and the index in docs/adr/README.md, not by rewriting "
    "the historical record. If an accepted record genuinely has to be corrected, say so in "
    "[[adr.history_exceptions]] in architecture.toml, with the reason, and have it reviewed."
)


def _digest_bytes(data: bytes) -> str:
    return hashlib.sha256(data.replace(b"\r\n", b"\n")).hexdigest()


def _digest(path: Path) -> str:
    return _digest_bytes(path.read_bytes())


def _status(text: str) -> str:
    """The status word, with the markdown emphasis some records use stripped."""
    match = _STATUS.search(text)
    if not match:
        return ""
    return match.group("status").strip().strip("*").strip().lower()


def _is_immutable(text: str) -> bool:
    return _status(text).startswith(_IMMUTABLE)


def _body(text: str) -> str:
    """The decision itself: the file without its status line.

    The status line is where a superseded record is banner-marked, so it has to
    stay writable; everything else is the record.
    """
    return _STATUS_LINE.sub("", text.replace("\r\n", "\n"))


def _immutable_adrs(config: ArchitectureConfig) -> list[Path]:
    directory = config.root / config.adr.directory
    if not directory.is_dir():
        return []
    out = []
    for path in sorted(directory.glob(_ADR_GLOB)):
        if _is_immutable(path.read_text(encoding="utf-8", errors="replace")):
            out.append(path)
    return out


def _load_manifest(path: Path) -> dict[str, str]:
    recorded: dict[str, str] = {}
    if not path.is_file():
        return recorded
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        digest, _, name = stripped.partition("  ")
        if digest and name:
            recorded[name.strip()] = digest
    return recorded


def check_adr(config: ArchitectureConfig) -> list[Finding]:
    """The manifest tripwire: every immutable ADR matches its recorded digest.

    This is the offline half. It is defeated by updating the manifest in the
    same change, which is what :func:`check_adr_history` exists to catch.
    """
    manifest_rel = config.adr.manifest
    manifest = config.root / manifest_rel
    recorded = _load_manifest(manifest)
    findings: list[Finding] = []

    if not manifest.is_file():
        return [
            Finding(
                path=manifest_rel,
                line=0,
                rule="ADR002-adr-not-recorded",
                message="no ADR digest manifest; run `dwcheck adr --record`",
                reason=_REASON,
            )
        ]

    seen: set[str] = set()
    for path in _immutable_adrs(config):
        name = path.name
        seen.add(name)
        rel = f"{config.adr.directory}/{name}"
        actual = _digest(path)
        expected = recorded.get(name)
        if expected is None:
            findings.append(
                Finding(
                    path=rel,
                    line=0,
                    rule="ADR002-adr-not-recorded",
                    message=(
                        "accepted ADR is not in "
                        f"{manifest_rel}; record it in the commit that adds it"
                    ),
                    reason=_REASON,
                )
            )
        elif expected != actual:
            findings.append(
                Finding(
                    path=rel,
                    line=0,
                    rule="ADR001-accepted-adr-modified",
                    message=(
                        f"content changed since it was accepted "
                        f"(recorded {expected[:12]}, found {actual[:12]})"
                    ),
                    reason=_REASON,
                )
            )

    for name in sorted(set(recorded) - seen):
        findings.append(
            Finding(
                path=manifest_rel,
                line=0,
                rule="ADR003-recorded-adr-missing",
                message=(
                    f"`{name}` is recorded but is not an accepted ADR any more "
                    f"(deleted, renamed, or its status changed)"
                ),
                reason=_REASON,
            )
        )
    return findings


# --- the history anchor -----------------------------------------------------


class _HistoryUnavailableError(Exception):
    """Git history could not be read: no git, no repository, or no such base."""


def _run_git(root: Path, args: list[str], stdin: bytes | None = None) -> bytes:
    git = shutil.which("git")
    if git is None:
        raise _HistoryUnavailableError("git is not on PATH")
    try:
        # Fixed argv, no shell. The only caller-supplied value is the base
        # revision, and _resolve_base refuses one starting with "-" so that it
        # can never be read as a git option.
        completed = subprocess.run(
            [git, "-C", str(root), *args],
            input=stdin,
            capture_output=True,
            check=False,
            timeout=120,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:  # pragma: no cover
        raise _HistoryUnavailableError(str(exc)) from exc
    if completed.returncode != 0:
        detail = completed.stderr.decode("utf-8", "replace").strip().splitlines()
        raise _HistoryUnavailableError(detail[0] if detail else f"git {args[0]} failed")
    return completed.stdout


def _resolve_base(root: Path, base: str) -> str:
    if base.startswith("-"):
        raise _HistoryUnavailableError(f"{base!r} is not a revision")
    # A shallow clone answers "when did this become Accepted?" with whatever
    # commit the truncation left behind, which looks like an anchor and is not
    # one. Refuse it rather than degrade quietly: that is the whole failure mode
    # this check exists to remove.
    if _run_git(root, ["rev-parse", "--is-shallow-repository"]).decode().strip() == "true":
        raise _HistoryUnavailableError(
            "the clone is shallow, so acceptance revisions are truncated"
        )
    return _run_git(root, ["rev-parse", "--verify", f"{base}^{{commit}}"]).decode().strip()


def _touching_commits(root: Path, base: str, directory: str) -> dict[str, list[str]]:
    """``ADR file name -> commits that touched it, oldest first``.

    One ``git log`` for the whole directory rather than one per ADR: on Windows
    a subprocess per file turns a millisecond check into several seconds.
    """
    out = _run_git(
        root,
        [
            "log",
            "--format=%H",
            "--name-only",
            "--reverse",
            "--no-renames",
            base,
            "--",
            directory,
        ],
    ).decode("utf-8", "replace")
    commits: dict[str, list[str]] = {}
    current = ""
    for raw in out.splitlines():
        line = raw.strip()
        if not line:
            continue
        if _COMMIT.match(line):
            current = line
            continue
        name = line.rsplit("/", 1)[-1]
        if current and _ADR_NAME.match(name):
            commits.setdefault(name, []).append(current)
    return commits


def _read_blobs(root: Path, specs: list[str]) -> dict[str, bytes]:
    """``<commit>:<path> -> contents``, in one ``git cat-file --batch``."""
    if not specs:
        return {}
    stdout = _run_git(root, ["cat-file", "--batch"], stdin=("\n".join(specs) + "\n").encode())
    blobs: dict[str, bytes] = {}
    offset = 0
    for spec in specs:
        newline = stdout.find(b"\n", offset)
        if newline < 0:  # pragma: no cover - truncated output
            break
        header = stdout[offset:newline].decode("utf-8", "replace").split()
        offset = newline + 1
        if len(header) != 3 or header[1] != "blob":
            continue  # "missing", or a tree where a blob was expected
        size = int(header[2])
        blobs[spec] = stdout[offset : offset + size]
        offset += size + 1  # the newline cat-file appends after the contents
    return blobs


def _accepted_content(
    root: Path, base: str, directory: str
) -> tuple[dict[str, bytes], dict[str, str]]:
    """For each ADR, the content it had in the revision where it became Accepted.

    Returns ``(name -> content, name -> commit)``. ADRs that were never accepted
    in this history are absent, which is how a brand-new ADR is allowed.
    """
    touching = _touching_commits(root, base, directory)
    specs = [f"{commit}:{directory}/{name}" for name, cs in touching.items() for commit in cs]
    blobs = _read_blobs(root, specs)

    content: dict[str, bytes] = {}
    where: dict[str, str] = {}
    for name, cs in touching.items():
        for commit in cs:  # oldest first: the acceptance revision wins
            blob = blobs.get(f"{commit}:{directory}/{name}")
            if blob is not None and _is_immutable(blob.decode("utf-8", "replace")):
                content[name] = blob
                where[name] = commit
                break
    return content, where


def check_adr_history(
    config: ArchitectureConfig,
    base: str = "HEAD",
    *,
    require_history: bool = True,
) -> list[Finding]:
    """Compare every ADR against the revision in which it became Accepted.

    ``base`` is the revision the change is proposed against: ``HEAD`` locally,
    the merge base with the target branch in CI. ``require_history=False`` turns
    an unreadable history into no finding rather than a failure, for trees that
    genuinely have none -- a release tarball, or a fixture directory.
    """
    directory = config.adr.directory
    exceptions = {e.file: e for e in config.adr.history_exceptions}
    findings: list[Finding] = []

    try:
        resolved = _resolve_base(config.root, base)
        accepted, where = _accepted_content(config.root, resolved, directory)
    except _HistoryUnavailableError as exc:
        if not require_history:
            return []
        return [
            Finding(
                path=directory,
                line=0,
                rule="ADR007-adr-history-unavailable",
                message=(
                    f"cannot anchor accepted ADRs to history at {base!r}: {exc}. "
                    f"CI needs the full history (actions/checkout fetch-depth: 0)"
                ),
                reason=_HISTORY_REASON,
            )
        ]

    used: set[str] = set()
    for name in sorted(accepted):
        rel = f"{directory}/{name}"
        path = config.root / directory / name
        anchor = accepted[name].decode("utf-8", "replace")
        commit = where[name][:12]

        if not path.is_file():
            findings.append(
                Finding(
                    path=rel,
                    line=0,
                    rule="ADR005-accepted-adr-withdrawn",
                    message=(
                        f"accepted in {commit} and no longer in the tree; an accepted record is "
                        f"superseded, not deleted"
                    ),
                    reason=_HISTORY_REASON,
                )
            )
            continue

        text = path.read_text(encoding="utf-8", errors="replace")
        if not _is_immutable(text):
            findings.append(
                Finding(
                    path=rel,
                    line=0,
                    rule="ADR005-accepted-adr-withdrawn",
                    message=(
                        f"accepted in {commit}, and its status is now "
                        f"{_status(text) or 'missing'!r}; acceptance is not reversible"
                    ),
                    reason=_HISTORY_REASON,
                )
            )
            continue

        if _body(text) == _body(anchor):
            continue

        exception = exceptions.get(name)
        actual = _digest(path)
        if exception is not None:
            # Consulted either way: when it does not match, the mismatch is
            # reported below rather than a second time as a stale override.
            used.add(name)
            if exception.sha256 == actual:
                continue

        detail = (
            f"; [[adr.history_exceptions]] authorises {exception.sha256[:12]}, found {actual[:12]}"
            if exception is not None
            else ""
        )
        findings.append(
            Finding(
                path=rel,
                line=0,
                rule="ADR004-accepted-adr-altered-since-acceptance",
                message=(
                    f"content differs from the revision that accepted it ({commit}); "
                    f"updating {config.adr.manifest} does not authorise this{detail}"
                ),
                reason=_HISTORY_REASON,
            )
        )

    for name in sorted(set(exceptions) - used):
        findings.append(
            Finding(
                path=config.rules_file.name,
                line=0,
                rule="ADR006-stale-adr-history-exception",
                message=(
                    f"[[adr.history_exceptions]] for `{name}` authorises nothing: the ADR now "
                    f"matches its history, is absent, or the recorded digest is wrong. An "
                    f"override that is not overriding anything should be deleted"
                ),
                reason=_HISTORY_REASON,
            )
        )
    return findings


def record_adr(config: ArchitectureConfig) -> Path:
    """Rewrite the manifest from the ADRs on disk. Deliberate, never automatic."""
    manifest = config.root / config.adr.manifest
    lines = [
        "# Digests of ADRs whose status is Accepted or Superseded, which are immutable",
        "# (docs/adr/README.md). Rewritten by `dwcheck adr --record`, which belongs in the",
        "# same commit as a new ADR.",
        "#",
        "# THIS FILE IS A TRIPWIRE, NOT THE TRUST ANCHOR. It lives in the same mutable tree",
        "# as the ADRs, so one change can edit an accepted ADR and update this file too. The",
        "# anchor is Git history: `dwcheck adr` also compares each ADR against the revision",
        "# in which it became Accepted. See tools/dwcheck/src/dwcheck/checks_adr.py.",
        "#",
        "# sha256 of the file with CRLF normalised to LF.",
    ]
    for path in _immutable_adrs(config):
        lines.append(f"{_digest(path)}  {path.name}")
    manifest.parent.mkdir(parents=True, exist_ok=True)
    manifest.write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")
    return manifest
