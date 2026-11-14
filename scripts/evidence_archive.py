#!/usr/bin/env python3
"""Durable, verifiable archives of DireWolf's hosted security evidence (F-10).

GitHub Actions keeps an artifact for its retention period -- 7 days for every
evidence artifact DireWolf uploads -- and then deletes it. This tool copies a
finished run's evidence artifacts into a directory the owner controls, outside
the repository, with a manifest that lets anyone check the copy later without
GitHub:

    python3 scripts/evidence_archive.py capture --run <run id> --archive-root <dir>
        [--staged <dir of downloaded ZIPs>] [--token-env <VARIABLE>] [--strict]
    python3 scripts/evidence_archive.py verify <archive> [--strict] [--replay-gate]
    python3 scripts/evidence_archive.py inventory --archive-root <dir>
        [--verify] [--backup-root <dir>]
    python3 scripts/evidence_archive.py inspect <archive> [--entry <artifact>/<file>]
    python3 scripts/evidence_archive.py restore <archive> --to <new directory>

docs/EVIDENCE_ARCHIVE.md is the guide: the archive format, what a SHA-256 does
and does not prove, storage, backup and recovery.

Two classes of run: `ci.yml` (the M5 gate's fourteen evidence bundles) and
`fuzz.yml` (the coverage-guided libFuzzer records, one per target). Each
archived bundle is judged by the M5 gate's own bundle check (`dw._gate_bundle`)
and each fuzz record by `dw.fuzz_verdict`, both unchanged and against the
ARCHIVED run's identity. An archive is HISTORICAL / OFFLINE evidence: nothing
here writes where CI reads, and the M5 gate refuses every bundle that is not of
the run it judges, so an archive can never stand in for a current run.

Only the standard library. `capture` reads GitHub's REST API (read-only; a
token only to download, which GitHub requires even for a public repository);
`verify`, `inventory`, `inspect` and `restore` never use the network.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import io
import json
import os
import re
import secrets
import shutil
import stat
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
import zipfile
import zlib
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import IO, NamedTuple, Protocol, override

sys.path.insert(0, str(Path(__file__).resolve().parent))
import dw  # the gate's own validators, imported after the path is extended

REPO_ROOT = Path(__file__).resolve().parent.parent

ARCHIVE_SCHEMA = "direwolf.evidence-archive"
ARCHIVE_VERSION = 1
TOOL_NAME = "scripts/evidence_archive.py"
TOOL_VERSION = 1
LABEL = "HISTORICAL / OFFLINE"
LABEL_TEXT = (
    "HISTORICAL / OFFLINE: a preserved copy of one past hosted run's evidence. It is never "
    "current hosted acceptance, and the M5 gate refuses any bundle that is not of the run "
    "it judges."
)
# What each part of a manifest rests on; written into every manifest verbatim.
PROVENANCE = {
    "github": (
        "Read from GitHub's REST API over TLS when the archive was captured. GitHub does not "
        "sign these answers: the archive records them, and cannot prove them later."
    ),
    "zip": (
        "Each archived ZIP's SHA-256 equals the digest GitHub's API reported for that artifact "
        "(digest_verified), or, where GitHub reported none, is what GitHub served to an "
        "authenticated download (digest_verified false)."
    ),
    "evidence": "Observed in the archived bytes, and computed again from them by every verify.",
    "capture": "The capturing machine's own record; written, never verified.",
}
DEFAULT_REPO = "Onwcan/DireWolf"
API_BASE = "https://api.github.com"
API_VERSION = "2022-11-28"
USER_AGENT = "direwolf-evidence-archive"

M5_CLASS = "m5-evidence"
FUZZ_CLASS = "fuzz-campaign"
WORKFLOW_CLASSES = {
    ".github/workflows/ci.yml": M5_CLASS,
    ".github/workflows/fuzz.yml": FUZZ_CLASS,
}

# The expected inventory of each class, frozen per version. A manifest names
# the version it was captured against, so an archive keeps verifying after the
# gate grows. tests/architecture/test_evidence_archive.py fails when the
# current version no longer equals `dw.M5E_GATE_TASKS` or `dw.FUZZ_TARGETS`;
# the fix is a new version, never an edit of an old one.
M5_CONTRACTS: dict[int, tuple[tuple[str, str], ...]] = {
    1: (
        ("sandbox-foundation-evidence", "sandbox-foundation"),
        ("sandbox-egress-evidence", "sandbox-egress"),
        ("sandbox-workload-evidence", "sandbox-workload"),
        ("sandbox-secret-evidence", "sandbox-secret"),
        ("sandbox-workspace-evidence", "sandbox-workspace"),
        ("sandbox-restart-evidence", "sandbox-restart"),
        ("sandbox-capacity-evidence", "sandbox-capacity"),
        ("sandbox-registry-evidence", "sandbox-registry"),
        ("sandbox-proxy-weakened-evidence", "sandbox-proxy-weakened"),
        ("sandbox-hygiene-evidence", "sandbox-hygiene"),
        ("sandbox-agent-evidence", "sandbox-agent"),
        ("sandbox-release-evidence", "sandbox-release"),
        ("net-http-evidence", "net-http"),
        ("eval-check", "evals"),
    ),
}
M5_CONTRACT_VERSION = 1
FUZZ_CONTRACTS: dict[int, tuple[str, ...]] = {
    1: (
        "frame_decoder",
        "dwkp_decode",
        "canonical_roundtrip",
        "envelope_version",
        "url_parse",
        "location_resolve",
        "policy_loader",
        "policy_evaluate",
    ),
}
FUZZ_CONTRACT_VERSION = 1
CONTRACT_NAMES = {M5_CLASS: "m5e-gate", FUZZ_CLASS: "fuzz-targets"}
# Artifacts a workflow may upload besides the expected ones: kept, never judged.
DIAGNOSTIC_ARTIFACTS = {M5_CLASS: frozenset({"eval-results"}), FUZZ_CLASS: frozenset[str]()}

# Bounds, each checked before the bytes are read or kept.
MAX_ZIP_BYTES = 64 * 1024 * 1024
MAX_ENTRIES = 256
MAX_ENTRY_BYTES = dw.M5E_GATE_MAX_FILE
MAX_TOTAL_BYTES = 128 * 1024 * 1024
MAX_MANIFEST_BYTES = 16 * 1024 * 1024
MAX_API_BYTES = 16 * 1024 * 1024
MAX_FUZZ_RECORD_BYTES = 1024 * 1024
MAX_PAGES = 20
HTTP_TIMEOUT = 60
MAX_NOTE = 500

STATUSES = ("ARCHIVED", "EXPIRED", "UNAVAILABLE")

# An artifact or entry name: one flat path component, portable to every
# filesystem a restore may write to. No separator, no `.` or `..`, no trailing
# dot, no Windows device name.
_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
_WINDOWS_DEVICES = frozenset(
    {"CON", "PRN", "AUX", "NUL"} | {f"{p}{n}" for p in ("COM", "LPT") for n in range(1, 10)}
)
_RUN_ID = re.compile(r"[1-9][0-9]{0,19}")
_SHA = re.compile(r"[0-9a-f]{40}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
_REPO = re.compile(r"[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9._-]{1,100}")
_TOKEN = re.compile(r"[A-Za-z0-9_]{20,255}")
_ARCHIVE_DIR = re.compile(r"[1-9][0-9]{0,19}-a[1-9][0-9]{0,4}")
_JOB_TASK = re.compile(r"\(make (?P<task>[a-z0-9-]+)\)$")
_REDIRECTS = (301, 302, 303, 307, 308)

_RUN_FIELDS = (
    "id",
    "attempt",
    "number",
    "workflow_name",
    "workflow_path",
    "workflow_id",
    "head_sha",
    "head_branch",
    "event",
    "status",
    "conclusion",
    "created_at",
    "run_started_at",
    "updated_at",
    "html_url",
)


class ArchiveError(Exception):
    """A capture, verification or restore refused; the message says why."""


class Entry(NamedTuple):
    """One file of an artifact's ZIP: its flat name and its bytes."""

    path: str
    data: bytes


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def canonical_json(value: object) -> bytes:
    """The one serialisation of a manifest: keys sorted, two-space indent,
    ASCII only (anything else escaped), no NaN or infinity, a final newline."""
    text = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True, allow_nan=False)
    return (text + "\n").encode("ascii")


def strict_json(data: bytes, what: str) -> object:
    """UTF-8 JSON with no repeated key and no NaN or infinity."""
    try:
        return dw._strict_json(data.decode("utf-8"))
    except (UnicodeDecodeError, ValueError, RecursionError, dw.TaskError) as exc:
        raise ArchiveError(f"{what} is not strict JSON: {exc}") from exc


def _dict(value: object, what: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ArchiveError(f"{what} is not an object")
    return value


def _list(value: object, what: str) -> list[object]:
    if not isinstance(value, list):
        raise ArchiveError(f"{what} is not a list")
    return value


def check_name(name: object, what: str) -> str:
    """`name` if it is one safe, flat, portable path component."""
    if (
        not isinstance(name, str)
        or not _NAME.fullmatch(name)
        or name.endswith(".")
        or name.split(".")[0].upper() in _WINDOWS_DEVICES
    ):
        raise ArchiveError(f"{what}: {str(name)[:80]!r} is not a safe flat file name")
    return name


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
    except ValueError:
        return False
    return True


def outside_repository(path: Path, what: str) -> Path:
    """`path`, refused when it lies inside this checkout: an archive or a
    restore never lands where a build, a test or CI reads."""
    if _inside(path, REPO_ROOT):
        raise ArchiveError(
            f"{what} {path} is inside the repository ({REPO_ROOT}); use a directory outside it"
        )
    return path


# ---- ZIP inspection -------------------------------------------------------------


def zip_entries(data: bytes, what: str) -> list[Entry]:
    """Every file of an artifact's ZIP, read in memory, never extracted, and
    refused -- not repaired -- if the ZIP is truncated, padded, encrypted or
    oversized, or holds anything but uniquely named regular files at its top
    level: no directory, symbolic link, traversal or case collision."""
    if len(data) > MAX_ZIP_BYTES:
        raise ArchiveError(f"{what}: {len(data)} bytes, over the {MAX_ZIP_BYTES}-byte bound")
    if not data.startswith(b"PK\x03\x04"):
        raise ArchiveError(f"{what}: not a ZIP archive (no local file header at offset 0)")
    try:
        archive = zipfile.ZipFile(io.BytesIO(data))
    except (zipfile.BadZipFile, zipfile.LargeZipFile, ValueError, OSError, EOFError) as exc:
        raise ArchiveError(f"{what}: unreadable ZIP (truncated or corrupt): {exc}") from exc
    entries: list[Entry] = []
    with archive:
        tail = 22 + len(archive.comment)
        if len(data) < tail or data[-tail : -tail + 4] != b"PK\x05\x06":
            raise ArchiveError(f"{what}: bytes after the ZIP's end of central directory")
        infos = archive.infolist()
        if not infos:
            raise ArchiveError(f"{what}: the ZIP holds no file")
        if len(infos) > MAX_ENTRIES:
            raise ArchiveError(f"{what}: {len(infos)} entries, over the bound of {MAX_ENTRIES}")
        names: set[str] = set()
        folded: set[str] = set()
        total = 0
        for info in infos:
            name = info.filename
            if name in names:
                raise ArchiveError(f"{what}: the entry {name[:80]!r} appears twice")
            if name.casefold() in folded:
                raise ArchiveError(f"{what}: {name[:80]!r} collides with another entry's name")
            check_name(name, f"{what}: entry")
            names.add(name)
            folded.add(name.casefold())
            kind = stat.S_IFMT(info.external_attr >> 16)
            if info.is_dir() or kind not in (0, stat.S_IFREG):
                raise ArchiveError(f"{what}: {name} is not a regular file (a link or directory)")
            if info.flag_bits & 0x1:
                raise ArchiveError(f"{what}: {name} is encrypted")
            if info.compress_type not in (zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED):
                raise ArchiveError(f"{what}: {name} uses compression {info.compress_type}")
            if info.file_size > MAX_ENTRY_BYTES:
                raise ArchiveError(
                    f"{what}: {name} is {info.file_size} bytes uncompressed, over {MAX_ENTRY_BYTES}"
                )
            total += info.file_size
            if total > MAX_TOTAL_BYTES:
                raise ArchiveError(f"{what}: over {MAX_TOTAL_BYTES} bytes uncompressed in all")
            try:
                with archive.open(info) as stream:
                    content = stream.read(MAX_ENTRY_BYTES + 1)
            except (zipfile.BadZipFile, OSError, EOFError, zlib.error, ValueError) as exc:
                raise ArchiveError(f"{what}: {name} is corrupt: {exc}") from exc
            if len(content) != info.file_size:
                raise ArchiveError(f"{what}: {name} is not the size its header records")
            entries.append(Entry(name, content))
    return sorted(entries, key=lambda entry: entry.path)


def entry_records(entries: Sequence[Entry]) -> list[dict[str, object]]:
    return [
        {"path": entry.path, "bytes": len(entry.data), "sha256": sha256_hex(entry.data)}
        for entry in entries
    ]


# ---- classes and contracts ------------------------------------------------------


def contract_expected(cls: str, version: int) -> list[str]:
    """The artifact names a complete archive of `cls` at contract `version` holds."""
    if cls == M5_CLASS and version in M5_CONTRACTS:
        return sorted(f"m5e-evidence-{job}" for _, job in M5_CONTRACTS[version])
    if cls == FUZZ_CLASS and version in FUZZ_CONTRACTS:
        return sorted(f"fuzz-evidence-{target}" for target in FUZZ_CONTRACTS[version])
    raise ArchiveError(f"no contract {version!r} for the class {cls!r}")


def current_contract(cls: str) -> int:
    return M5_CONTRACT_VERSION if cls == M5_CLASS else FUZZ_CONTRACT_VERSION


def classify(cls: str, version: int, name: str) -> str:
    """What an artifact of a run of `cls` is, from its exact name alone."""
    if name in contract_expected(cls, version):
        return "m5e-bundle" if cls == M5_CLASS else "fuzz-record"
    reproducer = name.removeprefix("fuzz-artifacts-")
    if cls == FUZZ_CLASS and reproducer != name and reproducer in FUZZ_CONTRACTS[version]:
        return "fuzz-reproducer"
    if name in DIAGNOSTIC_ARTIFACTS[cls]:
        return "diagnostic"
    return "unclassified"


# ---- GitHub ---------------------------------------------------------------------


class GitHub(Protocol):
    """What a capture needs from GitHub: read-only JSON, and an artifact's ZIP."""

    authenticated: bool

    def get_json(self, path: str) -> object: ...

    def get_artifact_zip(self, artifact_id: int, limit: int) -> bytes: ...


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Redirects are followed by hand, so a token never follows one."""

    @override
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: object,
        newurl: str,
    ) -> None:
        return None


def _read_bounded(response: IO[bytes], limit: int, what: str) -> bytes:
    data = response.read(limit + 1)
    if len(data) > limit:
        raise ArchiveError(f"{what}: more than {limit} bytes")
    return data


class HttpGitHub:
    """GitHub's REST API over HTTPS. A token, when there is one, is sent to
    the API host only: never printed, never written into an archive, and never
    forwarded to the storage host an artifact download redirects to."""

    def __init__(self, repo: str, token: str | None, base: str = API_BASE) -> None:
        self.repo = repo
        self._token = token
        self.base = base
        self.authenticated = token is not None
        self._opener = urllib.request.build_opener(_NoRedirect)

    def _request(self, url: str, accept: str, auth: bool) -> urllib.request.Request:
        if urllib.parse.urlsplit(url).scheme != "https":
            raise ArchiveError("only https URLs are fetched")
        request = urllib.request.Request(url, method="GET")  # noqa: S310 - https, checked above
        request.add_header("Accept", accept)
        request.add_header("User-Agent", USER_AGENT)
        request.add_header("X-GitHub-Api-Version", API_VERSION)
        if auth and self._token is not None:
            request.add_unredirected_header("Authorization", f"Bearer {self._token}")
        return request

    def get_json(self, path: str) -> object:
        request = self._request(self.base + path, "application/vnd.github+json", auth=True)
        try:
            with self._opener.open(request, timeout=HTTP_TIMEOUT) as response:
                data = _read_bounded(response, MAX_API_BYTES, f"GitHub's answer to {path}")
        except urllib.error.HTTPError as exc:
            raise ArchiveError(f"GitHub answered HTTP {exc.code} to GET {path}") from None
        except (urllib.error.URLError, OSError) as exc:
            raise ArchiveError(f"GET {path} failed: {getattr(exc, 'reason', exc)}") from None
        return strict_json(data, f"GitHub's answer to {path}")

    def get_artifact_zip(self, artifact_id: int, limit: int) -> bytes:
        if self._token is None:
            raise ArchiveError(
                "NO CREDENTIALS: GitHub serves artifact ZIPs only to a signed-in client, even "
                "for a public repository; stage the downloaded ZIPs (--staged) or name a "
                "read-only token's variable (--token-env)"
            )
        path = f"/repos/{self.repo}/actions/artifacts/{artifact_id}/zip"
        request = self._request(self.base + path, "application/vnd.github+json", auth=True)
        location = ""
        try:
            with self._opener.open(request, timeout=HTTP_TIMEOUT):
                pass
        except urllib.error.HTTPError as exc:
            if exc.code not in _REDIRECTS:
                raise ArchiveError(f"GitHub answered HTTP {exc.code} to the download") from None
            location = exc.headers.get("Location") or ""
        except (urllib.error.URLError, OSError) as exc:
            raise ArchiveError(f"the download failed: {getattr(exc, 'reason', exc)}") from None
        else:
            raise ArchiveError("GitHub answered the download without a redirect")
        target = urllib.parse.urlsplit(location)
        if target.scheme != "https" or not target.hostname:
            raise ArchiveError("GitHub's download redirect is not an https URL")
        # The redirect is a short-lived signed URL, a credential of its own:
        # only its host is ever named.
        host = target.hostname
        second = self._request(location, "application/octet-stream", auth=False)
        try:
            with self._opener.open(second, timeout=HTTP_TIMEOUT) as response:
                return _read_bounded(response, limit, f"the ZIP from {host}")
        except urllib.error.HTTPError as exc:
            raise ArchiveError(f"{host} answered HTTP {exc.code}") from None
        except (urllib.error.URLError, OSError) as exc:
            raise ArchiveError(f"the download from {host} failed: {exc}") from None


def _get(record: object, key: str, what: str) -> object:
    if not isinstance(record, dict) or key not in record:
        raise ArchiveError(f"{what}: no {key!r}")
    return record[key]


def _int(record: object, key: str, what: str) -> int:
    value = _get(record, key, what)
    if not isinstance(value, int) or isinstance(value, bool):
        raise ArchiveError(f"{what}: {key!r} is not an integer")
    return value


def _str(record: object, key: str, what: str) -> str:
    value = _get(record, key, what)
    if not isinstance(value, str):
        raise ArchiveError(f"{what}: {key!r} is not a string")
    return value


def _opt_str(record: object, key: str, what: str) -> str | None:
    value = _get(record, key, what)
    if value is not None and not isinstance(value, str):
        raise ArchiveError(f"{what}: {key!r} is neither a string nor null")
    return value


def _pages(github: GitHub, path: str, key: str, what: str) -> list[object]:
    """Every item of a paginated list, refused unless the pages add up to the
    total GitHub reports: a partial answer is never taken for the whole."""
    items: list[object] = []
    total: int | None = None
    for page in range(1, MAX_PAGES + 1):
        answer = github.get_json(f"{path}?per_page=100&page={page}")
        count = _int(answer, "total_count", what)
        listed = _list(_get(answer, key, what), f"{what}: {key}")
        if total is None:
            total = count
        elif count != total:
            raise ArchiveError(f"{what}: the total changed between pages ({total}, then {count})")
        items.extend(listed)
        if not listed or len(items) >= total:
            break
    if total is None or len(items) != total:
        raise ArchiveError(f"{what}: a partial answer, {len(items)} listed of {total} reported")
    return items


def fetch_run(
    github: GitHub, repo: str, run_id: str
) -> tuple[dict[str, object], list[dict[str, object]]]:
    """The run, its repository and this attempt's jobs, and its artifacts,
    each checked against the others."""
    what = f"run {run_id}"
    raw = github.get_json(f"/repos/{repo}/actions/runs/{run_id}")
    if _int(raw, "id", what) != int(run_id):
        raise ArchiveError(f"{what}: GitHub answered for another run")
    repository = _get(raw, "repository", what)
    full_name = _str(repository, "full_name", f"{what}'s repository")
    repository_id = _int(repository, "id", f"{what}'s repository")
    if full_name != repo:
        raise ArchiveError(f"{what} is of {full_name!r}, not {repo!r}")
    status = _str(raw, "status", what)
    if status != "completed":
        raise ArchiveError(f"{what} is {status!r}: only a completed run is archived")
    sha = _str(raw, "head_sha", what)
    if not _SHA.fullmatch(sha):
        raise ArchiveError(f"{what}: its commit {sha[:60]!r} is not a commit SHA")
    attempt = _int(raw, "run_attempt", what)
    if attempt < 1:
        raise ArchiveError(f"{what}: attempt {attempt}")
    workflow_path = _str(raw, "path", what)
    if workflow_path not in WORKFLOW_CLASSES:
        raise ArchiveError(f"{what} is of {workflow_path!r}: only {sorted(WORKFLOW_CLASSES)}")
    run: dict[str, object] = {
        "id": int(run_id),
        "attempt": attempt,
        "number": _int(raw, "run_number", what),
        "workflow_name": _str(raw, "name", what),
        "workflow_path": workflow_path,
        "workflow_id": _int(raw, "workflow_id", what),
        "head_sha": sha,
        "head_branch": _opt_str(raw, "head_branch", what),
        "event": _str(raw, "event", what),
        "status": status,
        "conclusion": _opt_str(raw, "conclusion", what),
        "created_at": _opt_str(raw, "created_at", what),
        "run_started_at": _opt_str(raw, "run_started_at", what),
        "updated_at": _opt_str(raw, "updated_at", what),
        "html_url": _str(raw, "html_url", what),
    }
    jobs_path = f"/repos/{repo}/actions/runs/{run_id}/attempts/{attempt}/jobs"
    jobs = [_job(item, run) for item in _pages(github, jobs_path, "jobs", f"{what}'s jobs")]
    artifacts_path = f"/repos/{repo}/actions/runs/{run_id}/artifacts"
    artifacts = [
        _artifact(item, run, repository_id)
        for item in _pages(github, artifacts_path, "artifacts", f"{what}'s artifacts")
    ]
    folded = [str(item["name"]).casefold() for item in artifacts]
    if len(set(folded)) != len(folded):
        raise ArchiveError(f"{what}: two artifacts share a name: {sorted(folded)}")
    record: dict[str, object] = {
        "api": API_BASE,
        "sources": {
            "run": f"{API_BASE}/repos/{repo}/actions/runs/{run_id}",
            "jobs": f"{API_BASE}{jobs_path}",
            "artifacts": f"{API_BASE}{artifacts_path}",
            "html": run["html_url"],
        },
        "repository": {"full_name": full_name, "id": repository_id},
        "run": run,
        "jobs": sorted(jobs, key=lambda job: (str(job["name"]), str(job["id"]).zfill(20))),
    }
    return record, sorted(artifacts, key=lambda item: str(item["name"]))


def _job(raw: object, run: Mapping[str, object]) -> dict[str, object]:
    job_id = _int(raw, "id", "a job")
    what = f"job {job_id}"
    if (_int(raw, "run_id", what), _int(raw, "run_attempt", what)) != (run["id"], run["attempt"]):
        raise ArchiveError(f"{what} is not of run {run['id']} attempt {run['attempt']}")
    if _str(raw, "head_sha", what) != run["head_sha"]:
        raise ArchiveError(f"{what} is of another commit")
    labels = _list(_get(raw, "labels", what), f"{what}'s labels")
    steps = [
        {
            "number": _int(step, "number", f"{what}'s step"),
            "name": _str(step, "name", f"{what}'s step"),
            "conclusion": _opt_str(step, "conclusion", f"{what}'s step"),
        }
        for step in _list(_get(raw, "steps", what), f"{what}'s steps")
    ]
    group = raw.get("runner_group_name") if isinstance(raw, dict) else None
    return {
        "id": job_id,
        "name": _str(raw, "name", what),
        "status": _str(raw, "status", what),
        "conclusion": _opt_str(raw, "conclusion", what),
        "started_at": _opt_str(raw, "started_at", what),
        "completed_at": _opt_str(raw, "completed_at", what),
        "runner_group": group if isinstance(group, str) else None,
        "labels": sorted(label for label in labels if isinstance(label, str)),
        "steps": sorted(steps, key=lambda step: str(step["number"]).zfill(6)),
    }


def _artifact(raw: object, run: Mapping[str, object], repository_id: int) -> dict[str, object]:
    artifact_id = _int(raw, "id", "an artifact")
    what = f"artifact {artifact_id}"
    name = check_name(_str(raw, "name", what), what)
    origin = _get(raw, "workflow_run", what)
    if (
        _int(origin, "id", what) != run["id"]
        or _str(origin, "head_sha", what) != run["head_sha"]
        or _int(origin, "repository_id", what) != repository_id
    ):
        raise ArchiveError(f"{what} ({name}) is not of run {run['id']} at {run['head_sha']}")
    digest = _opt_str(raw, "digest", what)
    if digest is not None and not _DIGEST.fullmatch(digest):
        raise ArchiveError(f"{what} ({name}): its digest {digest[:80]!r} is not a SHA-256")
    size = _int(raw, "size_in_bytes", what)
    expired = _get(raw, "expired", what)
    if size < 0 or not isinstance(expired, bool):
        raise ArchiveError(f"{what} ({name}): a negative size or no expiry flag")
    return {
        "name": name,
        "id": artifact_id,
        "size_in_bytes": size,
        "digest": digest,
        "created_at": _opt_str(raw, "created_at", what),
        "expires_at": _opt_str(raw, "expires_at", what),
        "expired": expired,
    }


# ---- what the evidence says -----------------------------------------------------


def _run_identity(github: object) -> tuple[str, str, str]:
    run = _dict(_get(github, "run", "github"), "github.run")
    return str(run["id"]), str(run["attempt"]), str(run["head_sha"])


def _jobs(github: object) -> list[dict[str, object]]:
    jobs = _list(_get(github, "jobs", "github"), "github.jobs")
    return [_dict(job, "a job") for job in jobs]


def _job_ref(job: Mapping[str, object] | None) -> dict[str, object] | None:
    if job is None:
        return None
    return {"id": job["id"], "name": job["name"], "conclusion": job["conclusion"]}


def _step(job: Mapping[str, object] | None, name: str) -> str | None:
    if job is None:
        return None
    steps = [s for s in _list(job["steps"], "steps") if isinstance(s, dict) and s["name"] == name]
    outcome = steps[0]["conclusion"] if len(steps) == 1 else None
    return outcome if isinstance(outcome, str) else None


def _job_running(jobs: Sequence[Mapping[str, object]], task: str) -> dict[str, object] | None:
    """The one job whose name ends `(make <task>)`."""
    found = []
    for job in jobs:
        match = _JOB_TASK.search(str(job["name"]))
        if match and match["task"] == task:
            found.append(dict(job))
    return found[0] if len(found) == 1 else None


def evaluate_m5(
    github: Mapping[str, object], version: int, archived: Mapping[str, Sequence[Entry]]
) -> tuple[dict[str, object], list[str], list[str]]:
    """Each archived bundle judged by the M5 gate's own bundle check
    (`dw._gate_bundle`, unchanged) against the archived run: its fields and
    provenance, its kept record, each file at its digest, and the judgements
    its task must have made. Returns the evidence record, the problems that
    make the evidence FAIL, and the inconsistencies that make the archive
    itself wrong (a bundle of another run, attempt or commit)."""
    run_id, attempt, sha = _run_identity(github)
    jobs = _jobs(github)
    bundles: list[dict[str, object]] = []
    problems: list[str] = []
    inconsistent: list[str] = []
    with tempfile.TemporaryDirectory(prefix="dw-archive-m5-") as scratch:
        for task, job in sorted(M5_CONTRACTS[version], key=lambda pair: pair[1]):
            name = f"m5e-evidence-{job}"
            if name not in archived:
                continue
            directory = Path(scratch) / name
            directory.mkdir()
            for entry in archived[name]:
                (directory / check_name(entry.path, name)).write_bytes(entry.data)
            hosted_job = _job_running(jobs, task)
            row: dict[str, object] = {
                "artifact": name,
                "task": task,
                "job": job,
                "status": "REJECTED",
                "reason": None,
                "run_id": None,
                "run_attempt": None,
                "sha": None,
                "ref": None,
                "runner": None,
                "judged": [],
                "census_lines": None,
                "hosted_job": _job_ref(hosted_job),
                "bundle_step": _step(hosted_job, "Run make m5e-evidence-bundle"),
            }
            said = _bundle_identity(directory)
            if said is not None and not _same_run(said, run_id, attempt, sha):
                inconsistent.append(
                    f"{name}: its bundle is of run {said[0]!r} attempt {said[1]!r} at "
                    f"{said[2]!r}, not of the archived run {run_id} attempt {attempt} at {sha}"
                )
            try:
                judged = dw._gate_bundle(directory, task, (run_id, attempt, sha))
            except dw.TaskError as exc:
                row["reason"] = str(exc)[:500]
                problems.append(f"{name}: refused by the M5 gate's bundle check: {row['reason']}")
            else:
                bundle = _dict(strict_json((directory / "bundle.json").read_bytes(), name), name)
                cleanup = bundle["cleanup"]
                row.update(
                    status="VERIFIED",
                    run_id=bundle["run_id"],
                    run_attempt=bundle["run_attempt"],
                    sha=bundle["sha"],
                    ref=bundle["ref"],
                    runner=bundle["runner"],
                    judged=[
                        {key: item[key] for key in ("file", "judge", "table", "bytes", "sha256")}
                        for item in judged
                    ],
                    census_lines=len(cleanup) if isinstance(cleanup, list) else None,
                )
            bundles.append(row)
    evidence: dict[str, object] = {
        "kind": "m5e-gate-bundles",
        "bundle_schema": dw.M5E_BUNDLE_SCHEMA,
        "bundle_version": dw.M5E_BUNDLE_VERSION,
        "check": "dw._gate_bundle against the archived run's id, attempt and commit",
        "bundles": bundles,
        "hosted_gate_job": _job_ref(_job_running(jobs, "m5e-gate-check")),
    }
    return evidence, problems, inconsistent


def _same_run(said: tuple[object, object, object], run_id: str, attempt: str, sha: str) -> bool:
    """The archived run, at the archived attempt or an earlier one (a job that
    passed and was not run again), as the gate itself counts it."""
    return (
        said[0] == run_id
        and said[2] == sha
        and isinstance(said[1], str)
        and dw._RUN_NUMBER.fullmatch(said[1]) is not None
        and int(said[1]) <= int(attempt)
    )


def _bundle_identity(directory: Path) -> tuple[object, object, object] | None:
    try:
        bundle = dw._read_bounded_json(directory / "bundle.json", directory.name)
    except dw.TaskError:
        return None
    if not isinstance(bundle, dict):
        return None
    return bundle.get("run_id"), bundle.get("run_attempt"), bundle.get("sha")


_FUZZ_FIELDS = (
    "status",
    "engine",
    "coverage_guided",
    "requested_seconds",
    "input_timeout_seconds",
    "exit_code",
    "toolchain",
    "rustc",
    "cargo_fuzz",
    "commit",
    "trigger",
    "run_id",
    "run_attempt",
    "seeds",
    "corpus_files_before",
    "corpus_files_after",
    "started_at",
    "fuzz_started_at",
    "finished_at",
    "crash",
)
_LIBFUZZER_FIELDS = (
    "reported_seconds",
    "runs",
    "initial_coverage",
    "final_coverage",
    "coverage_counters",
)


def evaluate_fuzz(
    github: Mapping[str, object], version: int, archived: Mapping[str, Sequence[Entry]]
) -> tuple[dict[str, object], list[str], list[str]]:
    """Each archived libFuzzer record judged by `dw.fuzz_verdict`, unchanged,
    as the run's own `make fuzz-report` judged it: against the archived run's
    identity, the budget the plan fixes for the trigger, and how its job's
    `make fuzz` step ended. The campaign passes only when every target of the
    contract passed, at one budget, in a job that succeeded; the stable
    mutation smoke job is not coverage-guided and is never counted."""
    run_id, attempt, sha = _run_identity(github)
    event = str(_dict(github["run"], "github.run")["event"])
    planned = dw.FUZZ_BUDGETS.get(event)
    jobs = _jobs(github)
    rows: list[dict[str, object]] = []
    problems: list[str] = []
    inconsistent: list[str] = []
    budgets: set[object] = set()
    for target in sorted(FUZZ_CONTRACTS[version]):
        name = f"fuzz-evidence-{target}"
        ran = [j for j in jobs if j["name"] == f"coverage-guided {target} (make fuzz)"]
        job = ran[0] if len(ran) == 1 else None
        if job is None:
            problems.append(f"{target}: the run has no one coverage-guided job for it")
        elif job["conclusion"] != "success":
            problems.append(f"{target}: its job finished {job['conclusion']!r}")
        if name not in archived:
            continue
        step = _step(job, "make fuzz")
        row: dict[str, object] = {
            "target": target,
            "artifact": name,
            "verdict": "FAIL",
            "detail": "",
            "job": _job_ref(job),
            "make_fuzz_step": step,
            "record": None,
            "libfuzzer": None,
            "reproducer": None,
        }
        entries = archived[name]
        record: object = None
        if [entry.path for entry in entries] != [f"{target}.json"]:
            row["detail"] = f"the artifact is not exactly {target}.json"
        elif len(entries[0].data) > MAX_FUZZ_RECORD_BYTES:
            row["detail"] = f"the record is over {MAX_FUZZ_RECORD_BYTES} bytes"
        else:
            try:
                record = strict_json(entries[0].data, f"{name}'s record")
            except ArchiveError as exc:
                row["detail"] = str(exc)[:300]
        if isinstance(record, dict):
            said = (record.get("run_id"), record.get("run_attempt"), record.get("commit"))
            ours = _same_run(said, run_id, attempt, sha) and record.get("target") == target
            if not ours:
                inconsistent.append(
                    f"{name}: its record is of {record.get('target')!r}, run {said[0]!r} attempt "
                    f"{said[1]!r} at {said[2]!r}, not of {target} in the archived run {run_id} "
                    f"attempt {attempt} at {sha}"
                )
            environ = {
                "GITHUB_RUN_ID": run_id,
                "GITHUB_RUN_ATTEMPT": str(said[1]) if ours else attempt,
                "GITHUB_SHA": sha,
            }
            if planned is not None:
                environ["DW_FUZZ_SECONDS"] = str(planned)
            verdict, detail = dw.fuzz_verdict(target, record, step or "", environ)
            libfuzzer = record.get("libfuzzer")
            row.update(
                verdict=verdict,
                detail=str(detail)[:500],
                record={key: record.get(key) for key in _FUZZ_FIELDS},
                libfuzzer=(
                    {key: libfuzzer.get(key) for key in _LIBFUZZER_FIELDS}
                    if isinstance(libfuzzer, dict)
                    else None
                ),
            )
            budgets.add(record.get("requested_seconds"))
            crash = record.get("crash")
            reproducer = f"fuzz-artifacts-{target}"
            if reproducer in archived:
                digests = {sha256_hex(entry.data) for entry in archived[reproducer]}
                wanted = crash.get("sha256") if isinstance(crash, dict) else None
                row["reproducer"] = {"artifact": reproducer, "matches_record": wanted in digests}
        elif not row["detail"]:
            row["detail"] = "the record is not a JSON object"
        if row["verdict"] != "PASS":
            problems.append(f"{target}: {row['verdict']} -- {row['detail']}")
        rows.append(row)
    budget = budgets.pop() if len(budgets) == 1 else None
    if budgets:
        problems.append("the targets' records name different budgets")
    smoke = [j for j in jobs if str(j["name"]).startswith("stable mutation fuzzing")]
    seconds = budget if isinstance(budget, int) and not isinstance(budget, bool) else None
    evidence: dict[str, object] = {
        "kind": "coverage-guided-libfuzzer",
        "record_schema": dw.FUZZ_EVIDENCE_SCHEMA,
        "trigger": event,
        "planned_seconds": planned,
        "budget_seconds": seconds,
        "budget": None
        if seconds is None
        else ("full" if seconds >= dw.FUZZ_BUDGETS["schedule"] else "short"),
        "check": "dw.fuzz_verdict against the archived run and its job's make fuzz step",
        "targets": rows,
        "stable_smoke_job_not_counted": _job_ref(smoke[0] if len(smoke) == 1 else None),
    }
    return evidence, problems, inconsistent


def evaluate(
    cls: str, github: Mapping[str, object], version: int, archived: Mapping[str, Sequence[Entry]]
) -> tuple[dict[str, object], list[str], list[str]]:
    if cls == M5_CLASS:
        return evaluate_m5(github, version, archived)
    if cls == FUZZ_CLASS:
        return evaluate_fuzz(github, version, archived)
    raise ArchiveError(f"no class {cls!r}")


def verdict_of(
    cls: str, version: int, artifacts: Sequence[Mapping[str, object]], problems: Sequence[str]
) -> dict[str, object]:
    """Completeness against the contract, and the evidence verdict: PASS only
    when every expected artifact is archived and judged a pass; FAIL when
    anything archived or recorded fails; INCOMPLETE otherwise."""
    expected = contract_expected(cls, version)
    archived = {str(a["name"]) for a in artifacts if a["status"] == "ARCHIVED"}
    missing = sorted(set(expected) - archived)
    evidence = "FAIL" if problems else "INCOMPLETE" if missing else "PASS"
    return {
        "completeness": "INCOMPLETE" if missing else "COMPLETE",
        "expected": len(expected),
        "archived_expected": len(set(expected) & archived),
        "missing": missing,
        "not_archived": [
            {"name": a["name"], "status": a["status"], "reason": a["reason"]}
            for a in artifacts
            if a["status"] != "ARCHIVED"
        ],
        "evidence": evidence,
        "problems": sorted(problems),
    }


# ---- capture --------------------------------------------------------------------


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _tool_record() -> dict[str, object]:
    def digest(path: Path) -> str | None:
        try:
            return sha256_hex(path.read_bytes())
        except OSError:
            return None

    commit: str | None = None
    with contextlib.suppress(OSError, subprocess.SubprocessError):
        out = subprocess.run(
            ["git", "-C", str(REPO_ROOT), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            check=False,
            timeout=30,
        )
        if out.returncode == 0 and _SHA.fullmatch(out.stdout.strip()):
            commit = out.stdout.strip()
    return {
        "name": TOOL_NAME,
        "version": TOOL_VERSION,
        "sha256": digest(Path(__file__)),
        "dw_sha256": digest(Path(dw.__file__)),
        "checkout_commit": commit,
    }


def _staged_zip(staged: Path, name: str) -> bytes | None:
    path = staged / f"{name}.zip"
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise ArchiveError(f"the staged {path.name} is unreadable: {exc}") from exc
    if not stat.S_ISREG(info.st_mode):
        raise ArchiveError(f"the staged {path.name} is not a regular file (a link or directory)")
    if info.st_size > MAX_ZIP_BYTES:
        raise ArchiveError(f"the staged {path.name} is over {MAX_ZIP_BYTES} bytes")
    return path.read_bytes()


def capture(
    github: GitHub,
    repo: str,
    run_id: str,
    archive_root: Path,
    *,
    attempt: int | None = None,
    staged: Path | None = None,
    strict: bool = False,
    note: str | None = None,
    now: Callable[[], str] = _now,
    report: Callable[[str], None] = print,
) -> Path:
    """Archive one completed run's evidence under `archive_root`/runs/, as a
    new directory written whole and verified before it takes its name.
    Refuses an inconsistent capture always; an incomplete one, or one whose
    evidence does not pass, when `strict`; and never replaces an archive."""
    if not _RUN_ID.fullmatch(run_id):
        raise ArchiveError(f"{run_id[:40]!r} is not a run id")
    if not _REPO.fullmatch(repo):
        raise ArchiveError(f"{repo[:80]!r} is not owner/name")
    if note is not None and (len(note) > MAX_NOTE or not note.isprintable()):
        raise ArchiveError(f"the note must be printable and at most {MAX_NOTE} characters")
    outside_repository(archive_root, "the archive root")
    if staged is not None and _lstat_kind(staged) != "dir":
        raise ArchiveError(f"the staged directory {staged} is not a directory")
    record, listed = fetch_run(github, repo, run_id)
    run = _dict(record["run"], "run")
    if attempt is not None and attempt != run["attempt"]:
        raise ArchiveError(
            f"run {run_id} is at attempt {run['attempt']}, not {attempt}: GitHub lists one "
            "set of artifacts per run, so only its latest attempt is archived"
        )
    cls = WORKFLOW_CLASSES[str(run["workflow_path"])]
    version = current_contract(cls)
    final = archive_root / "runs" / f"{run_id}-a{run['attempt']}"
    if final.exists() or final.is_symlink():
        raise ArchiveError(
            f"{final} already exists, and an archive is never replaced: verify it with "
            f"`verify {final}`, or capture into another archive root"
        )
    artifacts: list[dict[str, object]] = []
    blobs: dict[str, bytes] = {}
    archived: dict[str, list[Entry]] = {}
    inconsistent: list[str] = []
    for item in listed:
        name = str(item["name"])
        row: dict[str, object] = {
            "name": name,
            "class": classify(cls, version, name),
            "github": {key: value for key, value in item.items() if key != "name"},
            "status": "UNAVAILABLE",
            "reason": None,
            "zip": None,
            "entries": [],
        }
        artifacts.append(row)
        if item["expired"]:
            row.update(status="EXPIRED", reason="GitHub reports the artifact expired")
            continue
        source = "operator-staged"
        data = _staged_zip(staged, name) if staged is not None else None
        if data is None:
            source = "github-download"
            try:
                data = github.get_artifact_zip(int(str(item["id"])), MAX_ZIP_BYTES)
            except ArchiveError as exc:
                row["reason"] = f"not staged, and not downloaded: {exc}"[:500]
                continue
        digest = item["digest"]
        if digest is None and source == "operator-staged":
            row["reason"] = "GitHub reports no digest, so the staged bytes cannot be verified"
            continue
        actual = sha256_hex(data)
        if len(data) != item["size_in_bytes"] or (
            digest is not None and digest != f"sha256:{actual}"
        ):
            inconsistent.append(
                f"{name}: the {source} ZIP ({len(data)} bytes, sha256 {actual[:16]}...) is not "
                f"the artifact GitHub records ({item['size_in_bytes']} bytes, {digest})"
            )
            continue
        entries = zip_entries(data, name)
        row.update(
            status="ARCHIVED",
            zip={
                "file": f"artifacts/{name}.zip",
                "bytes": len(data),
                "sha256": actual,
                "source": source,
                "digest_verified": digest is not None,
            },
            entries=entry_records(entries),
        )
        blobs[name] = data
        archived[name] = entries
    if staged is not None:
        known = {f"{a['name']}.zip" for a in artifacts}
        ignored = sorted(p.name for p in staged.iterdir() if p.name not in known)
        if ignored:
            report(f"ignored in the staged directory (no artifact of this run): {ignored[:20]}")
    evidence, problems, wrong = evaluate(cls, record, version, archived)
    inconsistent.extend(wrong)
    if inconsistent:
        raise ArchiveError(
            f"refused: {len(inconsistent)} inconsistency(ies) between GitHub's record and the "
            "evidence: " + "; ".join(inconsistent[:10])
        )
    if not blobs:
        reasons = sorted({str(a["reason"]) for a in artifacts if a["reason"]})
        raise ArchiveError(f"refused: no artifact could be archived ({'; '.join(reasons[:3])})")
    verdict = verdict_of(cls, version, artifacts, problems)
    if strict and (verdict["completeness"] != "COMPLETE" or verdict["evidence"] != "PASS"):
        raise ArchiveError(
            f"refused (--strict): {verdict['completeness']}, evidence {verdict['evidence']}; "
            f"missing {verdict['missing']}; problems: {'; '.join(problems[:5]) or 'none'}"
        )
    manifest = {
        "schema": ARCHIVE_SCHEMA,
        "version": ARCHIVE_VERSION,
        "label": LABEL_TEXT,
        "provenance": PROVENANCE,
        "class": cls,
        "contract": {
            "name": CONTRACT_NAMES[cls],
            "version": version,
            "expected": contract_expected(cls, version),
        },
        "capture": {
            "captured_at": now(),
            "tool": _tool_record(),
            "authenticated": github.authenticated,
            "staged": staged is not None,
            "strict": strict,
            "note": note,
        },
        "github": record,
        "artifacts": artifacts,
        "evidence": evidence,
        "verdict": verdict,
    }
    return _write_archive(final, manifest, blobs, report)


def _fresh_directory(parent: Path, prefix: str) -> Path:
    """A new, uniquely named directory in `parent`, made as `mkdir` makes one:
    with the parent's permissions. `tempfile.mkdtemp` gives its directory a
    private ACL on Windows (owner, Administrators and SYSTEM only), which a
    rename carries into the archive: one made from an elevated shell is then
    unreadable to the same user unelevated."""
    for _ in range(100):
        candidate = parent / f"{prefix}{secrets.token_hex(8)}"
        try:
            candidate.mkdir()
        except FileExistsError:
            continue
        return candidate
    raise ArchiveError(f"no fresh directory could be made in {parent}")


def _fsync_dir(path: Path) -> None:
    if os.name != "posix":
        return
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _write_new(path: Path, data: bytes) -> None:
    with path.open("xb") as handle:
        handle.write(data)
        handle.flush()
        os.fsync(handle.fileno())


def _write_archive(
    final: Path,
    manifest: Mapping[str, object],
    blobs: Mapping[str, bytes],
    report: Callable[[str], None],
) -> Path:
    """Write the archive into a fresh `.capture-*` directory beside its final
    name, verify that directory as an archive, then rename it into place. An
    interrupted capture leaves a `.capture-*` directory, never a half archive
    under an archive's name, and never touches another archive."""
    runs = final.parent
    runs.mkdir(parents=True, exist_ok=True)
    scratch = _fresh_directory(runs, f".capture-{final.name}-")
    try:
        (scratch / "artifacts").mkdir()
        for name, data in sorted(blobs.items()):
            _write_new(scratch / "artifacts" / f"{name}.zip", data)
        body = canonical_json(manifest)
        _write_new(scratch / "manifest.json", body)
        _write_new(scratch / "manifest.sha256", f"{sha256_hex(body)}  manifest.json\n".encode())
        _fsync_dir(scratch / "artifacts")
        _fsync_dir(scratch)
        result = verify_archive(scratch)
        if result.problems:
            raise ArchiveError(
                "the new archive did not verify, and nothing was kept: "
                + "; ".join(result.problems[:5])
            )
        if final.exists() or final.is_symlink():
            raise ArchiveError(f"{final} appeared during the capture; nothing was replaced")
        scratch.rename(final)
        _fsync_dir(runs)
    except BaseException:
        shutil.rmtree(scratch, ignore_errors=True)
        raise
    report(f"archived in {final}")
    return final


# ---- verification ---------------------------------------------------------------


class Verification(NamedTuple):
    manifest: dict[str, object] | None
    manifest_sha256: str | None
    problems: list[str]
    archived: dict[str, list[Entry]]


def _lstat_kind(path: Path) -> str:
    try:
        mode = path.lstat().st_mode
    except OSError:
        return "missing"
    if stat.S_ISLNK(mode):
        return "link"
    if stat.S_ISDIR(mode):
        return "dir"
    return "file" if stat.S_ISREG(mode) else "other"


def _read_file(path: Path, limit: int, what: str) -> bytes:
    kind = _lstat_kind(path)
    if kind != "file":
        raise ArchiveError(f"{what} is {'absent' if kind == 'missing' else 'a ' + kind}")
    size = path.lstat().st_size
    if size > limit:
        raise ArchiveError(f"{what} is {size} bytes, over {limit}")
    return path.read_bytes()


def verify_archive(path: Path) -> Verification:
    """`_verify_archive`, with a path the operating system will not let this
    process read reported as a problem -- with the reason -- never a crash."""
    try:
        return _verify_archive(path)
    except OSError as exc:
        reason = exc.strerror or type(exc).__name__
        return Verification(None, None, [f"{path} is unreadable to this process: {reason}"], {})


def _verify_archive(path: Path) -> Verification:
    """Verify an archive offline: its layout; its manifest's form, schema and
    canonical bytes; each ZIP at its recorded and GitHub-reported digest and
    size, and safe to read; each entry at its digest; the classification; the
    run identity; and every verdict the manifest states, computed again from
    the archived bytes. Never uses the network. Returns every problem found."""
    archived: dict[str, list[Entry]] = {}
    if _lstat_kind(path) != "dir":
        return Verification(None, None, [f"{path} is not a directory"], archived)
    problems: list[str] = []
    layout = sorted(p.name for p in path.iterdir())
    if layout != ["artifacts", "manifest.json", "manifest.sha256"]:
        problems.append(f"the archive holds {layout}, not artifacts/, manifest.json and its digest")
    try:
        body = _read_file(path / "manifest.json", MAX_MANIFEST_BYTES, "manifest.json")
        side = _read_file(path / "manifest.sha256", 256, "manifest.sha256")
    except ArchiveError as exc:
        return Verification(None, None, [*problems, str(exc)], archived)
    digest = sha256_hex(body)
    if side != f"{digest}  manifest.json\n".encode():
        problems.append("manifest.sha256 is not the manifest's SHA-256")
    try:
        manifest = _dict(strict_json(body, "manifest.json"), "the manifest")
    except ArchiveError as exc:
        return Verification(None, digest, [*problems, str(exc)], archived)
    try:
        if canonical_json(manifest) != body:
            problems.append("manifest.json is not in its canonical form")
        problems.extend(_verify_manifest(path, manifest, archived))
    except (ArchiveError, KeyError, TypeError, ValueError, AttributeError) as exc:
        problems.append(f"the manifest is malformed: {type(exc).__name__}: {exc}")
    return Verification(manifest, digest, problems, archived)


_MANIFEST_FIELDS = {
    "schema",
    "version",
    "label",
    "provenance",
    "class",
    "contract",
    "capture",
    "github",
    "artifacts",
    "evidence",
    "verdict",
}
_GITHUB_FIELDS = {"api", "sources", "repository", "run", "jobs"}


def _verify_manifest(
    path: Path, manifest: Mapping[str, object], archived: dict[str, list[Entry]]
) -> list[str]:
    if set(manifest) != _MANIFEST_FIELDS:
        return [f"the manifest's fields are {sorted(manifest)}, not {sorted(_MANIFEST_FIELDS)}"]
    if (manifest["schema"], manifest["version"]) != (ARCHIVE_SCHEMA, ARCHIVE_VERSION):
        return [
            f"unsupported manifest {manifest['schema']!r} version {manifest['version']!r}; this "
            f"tool reads {ARCHIVE_SCHEMA} version {ARCHIVE_VERSION}"
        ]
    problems: list[str] = []
    if manifest["label"] != LABEL_TEXT:
        problems.append("the manifest's label is not the HISTORICAL / OFFLINE label")
    if manifest["provenance"] != PROVENANCE:
        problems.append("the manifest's statement of provenance is altered")
    github = _dict(manifest["github"], "github")
    run = _dict(github.get("run"), "github.run")
    if set(github) != _GITHUB_FIELDS or set(run) != set(_RUN_FIELDS):
        return [*problems, "github or github.run does not have exactly its fields"]
    cls = manifest["class"]
    if cls not in (M5_CLASS, FUZZ_CLASS) or WORKFLOW_CLASSES.get(str(run["workflow_path"])) != cls:
        workflow = run["workflow_path"]
        return [*problems, f"the class {cls!r} is not that of the workflow {workflow!r}"]
    cls = str(cls)
    contract = _dict(manifest["contract"], "contract")
    version = contract.get("version")
    if not isinstance(version, int) or isinstance(version, bool):
        return [*problems, f"the contract version {version!r} is not an integer"]
    expected = contract_expected(cls, version)
    if contract != {"name": CONTRACT_NAMES[cls], "version": version, "expected": expected}:
        problems.append(f"the manifest's contract is not {CONTRACT_NAMES[cls]} version {version}")
    run_id, attempt, sha = run["id"], run["attempt"], run["head_sha"]
    if not (
        isinstance(run_id, int)
        and not isinstance(run_id, bool)
        and isinstance(attempt, int)
        and not isinstance(attempt, bool)
        and attempt >= 1
        and isinstance(sha, str)
        and _SHA.fullmatch(sha)
    ):
        return [*problems, "the run's id, attempt or commit is malformed"]
    if _ARCHIVE_DIR.fullmatch(path.name) and path.name != f"{run_id}-a{attempt}":
        problems.append(f"the archive is named {path.name}, but holds run {run_id}-a{attempt}")
    rows = [_dict(item, "an artifact") for item in _list(manifest["artifacts"], "artifacts")]
    names = [str(row.get("name")) for row in rows]
    if names != sorted(names):
        problems.append("the artifacts are not in name order")
    folded = [name.casefold() for name in names]
    if len(set(folded)) != len(folded):
        problems.append(f"an artifact is listed twice: {names}")
    present: list[str] = []
    if _lstat_kind(path / "artifacts") == "dir":
        present = sorted(p.name for p in (path / "artifacts").iterdir())
    else:
        problems.append("artifacts/ is not a directory")
    wanted: list[str] = []
    for row in rows:
        problems.extend(_verify_artifact(path, row, cls, version, wanted, archived))
    extra = sorted(set(present) - set(wanted))
    if extra:
        problems.append(f"files in artifacts/ that the manifest does not list: {extra[:20]}")
    # Every judgement the manifest states, made again from the archived bytes.
    evidence, judged, inconsistent = evaluate(cls, github, version, archived)
    problems.extend(f"inconsistent evidence: {item}" for item in inconsistent)
    if manifest["evidence"] != evidence:
        problems.append(
            "the manifest's evidence is not what the archived bytes say: "
            + _first_difference(manifest["evidence"], evidence)
        )
    verdict = verdict_of(cls, version, rows, judged)
    if manifest["verdict"] != verdict:
        problems.append(
            "the manifest's verdict is not what the archived bytes say: "
            + _first_difference(manifest["verdict"], verdict)
        )
    return problems


_ARTIFACT_FIELDS = {"name", "class", "github", "status", "reason", "zip", "entries"}
_ZIP_FIELDS = {"file", "bytes", "sha256", "source", "digest_verified"}


def _verify_artifact(
    path: Path,
    item: Mapping[str, object],
    cls: str,
    version: int,
    wanted: list[str],
    archived: dict[str, list[Entry]],
) -> list[str]:
    name = check_name(item.get("name"), "an artifact")
    if set(item) != _ARTIFACT_FIELDS:
        return [f"{name}: its fields are {sorted(item)}"]
    problems: list[str] = []
    should = classify(cls, version, name)
    if item["class"] != should:
        problems.append(f"{name}: classified {item['class']!r}, but its name makes it {should!r}")
    github = _dict(item["github"], f"{name}: github")
    status = item["status"]
    if status not in STATUSES:
        return [*problems, f"{name}: the status {status!r}"]
    if status != "ARCHIVED":
        if item["zip"] is not None or item["entries"] != [] or not isinstance(item["reason"], str):
            problems.append(f"{name}: {status}, yet it records a ZIP, entries or no reason")
        if status == "EXPIRED" and github.get("expired") is not True:
            problems.append(f"{name}: EXPIRED, though GitHub did not say so")
        return problems
    record = _dict(item["zip"], f"{name}: zip")
    if set(record) != _ZIP_FIELDS:
        return [*problems, f"{name}: its ZIP record's fields are {sorted(record)}"]
    file_name = f"{name}.zip"
    wanted.append(file_name)
    if record["file"] != f"artifacts/{file_name}":
        problems.append(f"{name}: its ZIP is recorded at {record['file']!r}")
    try:
        data = _read_file(path / "artifacts" / file_name, MAX_ZIP_BYTES, f"artifacts/{file_name}")
    except ArchiveError as exc:
        return [*problems, f"{name}: {exc}"]
    actual = sha256_hex(data)
    if record["sha256"] != actual or record["bytes"] != len(data):
        problems.append(f"{name}: the ZIP is not the one recorded (sha256 {actual[:16]}...)")
    if github.get("size_in_bytes") != len(data):
        problems.append(f"{name}: {len(data)} bytes, GitHub recorded {github.get('size_in_bytes')}")
    reported = github.get("digest")
    if record["digest_verified"] is True:
        if reported != f"sha256:{actual}":
            problems.append(f"{name}: the ZIP is not at GitHub's digest {reported}")
    elif not (
        record["digest_verified"] is False
        and reported is None
        and record["source"] == "github-download"
    ):
        problems.append(
            f"{name}: unverified bytes, yet GitHub reported a digest or they were staged"
        )
    if record["source"] not in ("github-download", "operator-staged"):
        problems.append(f"{name}: the source {record['source']!r}")
    try:
        entries = zip_entries(data, name)
    except ArchiveError as exc:
        return [*problems, str(exc)]
    if item["entries"] != entry_records(entries):
        problems.append(f"{name}: its entries are not those recorded")
    archived[name] = entries
    return problems


def _first_difference(recorded: object, computed: object, where: str = "") -> str:
    if isinstance(recorded, dict) and isinstance(computed, dict):
        for key in sorted(set(recorded) | set(computed), key=str):
            if recorded.get(key) != computed.get(key):
                return _first_difference(recorded.get(key), computed.get(key), f"{where}.{key}")
    if isinstance(recorded, list) and isinstance(computed, list) and len(recorded) == len(computed):
        for index, (one, other) in enumerate(zip(recorded, computed, strict=True)):
            if one != other:
                return _first_difference(one, other, f"{where}[{index}]")
    return f"{where or 'value'}: recorded {str(recorded)[:120]!r}, computed {str(computed)[:120]!r}"


def summary_lines(path: Path, result: Verification) -> list[str]:
    """What an archive is and what its verification found, labelled."""
    lines = [f"{LABEL} verification of {path} -- never current hosted acceptance"]
    manifest = result.manifest
    github = manifest.get("github") if manifest is not None else None
    run = github.get("run") if isinstance(github, dict) else None
    if manifest is None or not isinstance(run, dict):
        lines.append(f"integrity: FAILED ({len(result.problems)} problem(s))")
        lines.extend(f"  - {problem}" for problem in result.problems[:40])
        return lines
    lines.append(
        f"run {run.get('id')} attempt {run.get('attempt')}: {run.get('workflow_name')} "
        f"#{run.get('number')} ({run.get('event')}, {run.get('head_branch')}) at "
        f"{run.get('head_sha')}; its hosted conclusion: {run.get('conclusion')}"
    )
    lines.append(f"class {manifest.get('class')}; manifest sha256 {result.manifest_sha256}")
    if result.problems:
        lines.append(f"integrity: FAILED ({len(result.problems)} problem(s))")
        lines.extend(f"  - {problem}" for problem in result.problems[:40])
        return lines
    verdict = _dict(manifest["verdict"], "verdict")
    lines.append(
        f"integrity: OK -- {len(result.archived)} ZIP(s) at their recorded SHA-256 and GitHub's "
        "digest, every entry at its digest, every verdict computed again from the bytes"
    )
    lines.append(
        f"completeness: {verdict['completeness']} -- {verdict['archived_expected']} of "
        f"{verdict['expected']} expected artifact(s); missing: {verdict['missing'] or 'none'}"
    )
    for item in _list(verdict["not_archived"], "not_archived"):
        if isinstance(item, dict):
            lines.append(f"  not archived: {item['name']} {item['status']}: {item['reason']}")
    lines.append(f"evidence: {verdict['evidence']}")
    lines.extend(f"  - {problem}" for problem in _list(verdict["problems"], "problems"))
    return lines


def replay_gate(result: Verification) -> list[str]:
    """The M5 gate itself (`dw.m5e_gate_verdict`, unchanged) over a verified
    archive's bundles in a scratch directory, as the run's own `m5e-gate` job
    judged them -- HISTORICAL / OFFLINE, and with THIS checkout's case tables:
    for an archive of another commit a difference is expected, and is never an
    integrity problem."""
    manifest = result.manifest
    if manifest is None or result.problems:
        raise ArchiveError("the archive did not verify; nothing is replayed")
    if manifest["class"] != M5_CLASS:
        raise ArchiveError("only an archive of M5 evidence has a gate to replay")
    run_id, attempt, sha = _run_identity(manifest["github"])
    lines = [
        f"{LABEL} replay of the M5 gate over run {run_id}'s archived bundles, judged with "
        "this checkout's case tables -- never current hosted acceptance"
    ]
    environ = {
        "GITHUB_ACTIONS": "true",
        "RUNNER_ENVIRONMENT": "github-hosted",
        "GITHUB_JOB": dw.M5E_GATE_JOB,
        "GITHUB_RUN_ID": run_id,
        "GITHUB_RUN_ATTEMPT": attempt,
        "GITHUB_SHA": sha,
    }
    with tempfile.TemporaryDirectory(prefix="dw-archive-replay-") as scratch:
        root = Path(scratch) / "m5e-gate"
        root.mkdir()
        for name, entries in result.archived.items():
            if not name.startswith("m5e-evidence-"):
                continue
            (root / name).mkdir()
            for entry in entries:
                (root / name / check_name(entry.path, name)).write_bytes(entry.data)
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                verdict, _ = dw.m5e_gate_verdict(environ, root, REPO_ROOT)
        except dw.TaskError as exc:
            lines.append(f"replayed gate: REFUSED -- {str(exc)[:1500]}")
            return lines
    lines.extend(f"replayed gate: {line}" for line in verdict)
    return lines


# ---- inventory, inspection, restore ----------------------------------------------


def inventory(archive_root: Path, *, deep: bool, backup_root: Path | None) -> list[str]:
    """Every archive under `archive_root`/runs, one line each, and anything
    else there; `deep` verifies each one in full."""
    runs = archive_root / "runs"
    if _lstat_kind(runs) != "dir":
        raise ArchiveError(f"no archive under {archive_root} (no runs/ directory)")
    lines = [f"{LABEL} evidence archives in {runs}"]
    for entry in sorted(runs.iterdir(), key=lambda p: p.name):
        if entry.name.startswith(".capture-"):
            lines.append(f"  {entry.name}: an interrupted capture, not an archive (safe to remove)")
            continue
        if not _ARCHIVE_DIR.fullmatch(entry.name) or _lstat_kind(entry) != "dir":
            lines.append(f"  {entry.name}: not an archive")
            continue
        manifest: dict[str, object] | None
        if deep:
            result = verify_archive(entry)
            manifest, sha = result.manifest, result.manifest_sha256
            integrity = "OK" if not result.problems else f"FAILED ({len(result.problems)})"
        else:
            integrity = "not verified here (use --verify)"
            try:
                body = _read_file(entry / "manifest.json", MAX_MANIFEST_BYTES, "manifest.json")
                manifest = _dict(strict_json(body, "manifest.json"), "the manifest")
                sha = sha256_hex(body)
            except (ArchiveError, OSError) as exc:
                manifest, sha, integrity = None, None, f"FAILED ({exc})"
        lines.append("  " + _inventory_line(entry, manifest, sha, integrity, backup_root))
    return lines


def _inventory_line(
    entry: Path,
    manifest: Mapping[str, object] | None,
    sha: str | None,
    integrity: str,
    backup_root: Path | None,
) -> str:
    if manifest is None:
        return f"{entry.name}: unreadable manifest; integrity {integrity}"
    try:
        run = _dict(_dict(manifest["github"], "github")["run"], "run")
        capture = _dict(manifest["capture"], "capture")
        verdict = _dict(manifest["verdict"], "verdict")
        rows = [_dict(a, "artifact") for a in _list(manifest["artifacts"], "artifacts")]
    except (ArchiveError, KeyError) as exc:
        return f"{entry.name}: malformed manifest ({exc}); integrity {integrity}"
    size = sum(
        int(str(_dict(row["zip"], "zip")["bytes"])) for row in rows if row.get("zip") is not None
    )
    expiries = sorted(
        str(_dict(row["github"], "github").get("expires_at"))
        for row in rows
        if isinstance(row.get("github"), dict) and _dict(row["github"], "github").get("expires_at")
    )
    backup = "not checked (use --backup-root)"
    if backup_root is not None:
        copy = backup_root / "runs" / entry.name / "manifest.sha256"
        try:
            copied = copy.read_text(encoding="ascii").split()[0]
        except (OSError, UnicodeDecodeError, IndexError):
            backup = "MISSING"
        else:
            backup = "present, same manifest digest" if copied == sha else "DIFFERS"
    return (
        f"{entry.name}: {manifest.get('class')} {run.get('workflow_name')} #{run.get('number')} "
        f"at {str(run.get('head_sha'))[:12]} ({run.get('event')}); captured "
        f"{capture.get('captured_at')}; {verdict.get('completeness')} "
        f"{verdict.get('archived_expected')}/{verdict.get('expected')}, missing "
        f"{verdict.get('missing') or 'none'}; evidence {verdict.get('evidence')}; integrity "
        f"{integrity}; {size} bytes; GitHub's copy expires "
        f"{expiries[0] if expiries else 'unknown'}; backup {backup}; manifest sha256 {sha}"
    )


def _verified(path: Path) -> Verification:
    result = verify_archive(path)
    if result.problems or result.manifest is None:
        raise ArchiveError(
            f"{path} did not verify ({len(result.problems)} problem(s)): "
            + "; ".join(result.problems[:5])
        )
    return result


def inspect_entry(path: Path, entry: str) -> bytes:
    """One archived file's bytes, read from its verified ZIP in memory."""
    result = _verified(path)
    artifact, _, name = entry.partition("/")
    entries = result.archived.get(artifact)
    if entries is None:
        raise ArchiveError(
            f"no archived artifact {artifact!r}; there are {sorted(result.archived)}"
        )
    found = [item for item in entries if item.path == name]
    if len(found) != 1:
        raise ArchiveError(f"{artifact} holds no {name!r}; it holds {[e.path for e in entries]}")
    return found[0].data


def restore(path: Path, destination: Path) -> Path:
    """Write a verified archive's files, read-only, into a NEW directory
    outside the repository: one directory per artifact, as the download
    action lays bundles out, with the manifest and a notice that this is
    HISTORICAL / OFFLINE evidence. Never writes into an existing directory."""
    result = _verified(path)
    outside_repository(destination, "the restore destination")
    if destination.exists() or destination.is_symlink():
        raise ArchiveError(f"{destination} already exists: a restore never writes into it")
    parent = destination.parent
    if _lstat_kind(parent) != "dir":
        raise ArchiveError(f"{parent} is not a directory")
    manifest = result.manifest
    if manifest is None:
        raise ArchiveError("no manifest")
    run_id, attempt, sha = _run_identity(manifest["github"])
    scratch = _fresh_directory(parent, ".restore-")
    try:
        for name, entries in sorted(result.archived.items()):
            (scratch / name).mkdir()
            for entry in entries:
                target = scratch / name / check_name(entry.path, name)
                _write_new(target, entry.data)
                target.chmod(0o444)
        _write_new(scratch / "manifest.json", canonical_json(manifest))
        notice = (
            f"{LABEL_TEXT}\n\nRun {run_id} attempt {attempt} at {sha}; manifest sha256 "
            f"{result.manifest_sha256}. Restored from {path.name} for inspection only. Copying "
            "these bundles where a run's M5 gate reads them proves nothing: the gate refuses "
            "every bundle that is not of the run it judges.\n"
        )
        _write_new(scratch / "HISTORICAL-OFFLINE.txt", notice.encode())
        scratch.rename(destination)
    except BaseException:
        shutil.rmtree(scratch, ignore_errors=True)
        raise
    return destination


# ---- command line -----------------------------------------------------------------


def _token(variable: str | None) -> str | None:
    """The token in `variable`, never printed: only its shape is checked."""
    if variable is None:
        return None
    if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", variable):
        raise ArchiveError("--token-env names an environment variable, not a token")
    value = os.environ.get(variable)
    if not value:
        raise ArchiveError(f"the variable {variable} is unset or empty")
    if not _TOKEN.fullmatch(value):
        raise ArchiveError(f"the value of {variable} is not shaped like a GitHub token")
    return value


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="evidence_archive",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    commands = parser.add_subparsers(dest="command", required=True)
    p = commands.add_parser("capture", help="archive one completed run's evidence")
    p.add_argument("--run", required=True, help="the workflow run id")
    p.add_argument("--archive-root", required=True, type=Path, help="outside the repository")
    p.add_argument("--attempt", type=int, help="refuse unless the run is at this attempt")
    p.add_argument("--staged", type=Path, help="a directory of downloaded <artifact>.zip files")
    p.add_argument("--token-env", help="the environment variable that holds a read-only token")
    p.add_argument("--repo", default=DEFAULT_REPO, help=f"owner/name (default {DEFAULT_REPO})")
    p.add_argument("--strict", action="store_true", help="refuse unless COMPLETE and PASS")
    p.add_argument("--note", help="an operator's note, kept in the manifest")
    p = commands.add_parser("verify", help="verify an archive offline")
    p.add_argument("archive", type=Path)
    p.add_argument("--strict", action="store_true", help="fail unless COMPLETE and PASS")
    p.add_argument("--replay-gate", action="store_true", help="replay the M5 gate (M5 only)")
    p = commands.add_parser("inventory", help="list the archives under a root")
    p.add_argument("--archive-root", required=True, type=Path)
    p.add_argument("--verify", action="store_true", help="verify each archive in full")
    p.add_argument("--backup-root", type=Path, help="a second copy to compare manifests with")
    p = commands.add_parser("inspect", help="summarise a verified archive, or print one file")
    p.add_argument("archive", type=Path)
    p.add_argument("--entry", help="<artifact name>/<file name>")
    p = commands.add_parser("restore", help="write a verified archive's files to a new directory")
    p.add_argument("archive", type=Path)
    p.add_argument("--to", required=True, type=Path, help="a directory that does not exist yet")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        return _dispatch(args)
    except (ArchiveError, dw.TaskError) as exc:
        print(f"evidence_archive: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130


def _dispatch(args: argparse.Namespace) -> int:
    if args.command == "capture":
        github = HttpGitHub(args.repo, _token(args.token_env))
        final = capture(
            github,
            args.repo,
            args.run,
            args.archive_root,
            attempt=args.attempt,
            staged=args.staged,
            strict=args.strict,
            note=args.note,
        )
        for line in summary_lines(final, verify_archive(final)):
            print(line)
        return 0
    if args.command == "verify":
        result = verify_archive(args.archive)
        for line in summary_lines(args.archive, result):
            print(line)
        if result.problems or result.manifest is None:
            return 1
        if args.replay_gate:
            for line in replay_gate(result):
                print(line)
        verdict = _dict(result.manifest["verdict"], "verdict")
        if args.strict and (verdict["completeness"], verdict["evidence"]) != ("COMPLETE", "PASS"):
            print("strict: the archive is not COMPLETE with evidence PASS", file=sys.stderr)
            return 1
        return 0
    if args.command == "inventory":
        lines = inventory(args.archive_root, deep=args.verify, backup_root=args.backup_root)
        for line in lines:
            print(line)
        return 1 if args.verify and any("integrity FAILED" in line for line in lines) else 0
    if args.command == "inspect":
        if args.entry:
            sys.stdout.buffer.write(inspect_entry(args.archive, args.entry))
            return 0
        result = _verified(args.archive)
        for line in summary_lines(args.archive, result):
            print(line)
        for name, entries in sorted(result.archived.items()):
            print(f"  {name}: " + ", ".join(f"{e.path} ({len(e.data)} bytes)" for e in entries))
        return 0
    destination = restore(args.archive, args.to)
    print(f"{LABEL}: restored {args.archive.name} read-only into {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
