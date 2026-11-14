"""F-10: durable archives of hosted evidence (`scripts/evidence_archive.py`).

GitHub keeps each evidence artifact 7 days. The archive tool copies a finished
run's artifacts outside the repository with a manifest, and verifies the copy
offline later. What these tests hold:

* a complete M5 run (the gate's fourteen bundles) and a complete coverage-
  guided fuzz campaign (eight records) archive, verify and restore;
* every bundle is judged by the M5 gate's own bundle check and every record by
  `dw.fuzz_verdict`, unchanged, against the ARCHIVED run;
* a capture refuses what does not agree with GitHub's record (another run,
  attempt, commit or workflow; bytes not at GitHub's digest; a partial API
  answer; duplicate names), and with `strict`, anything incomplete;
* an archive never replaces another, and an interrupted capture leaves no
  archive behind;
* verification finds every change to the bytes, the manifest or the layout,
  every unsafe ZIP (traversal, links, duplicates, case collisions, bombs,
  truncation, padding, encryption), and every verdict the bytes do not bear
  out -- a fuzz campaign called PASS among them;
* verification, inventory, inspection and restore never touch the network,
  and a token is never written or forwarded;
* an archive can never stand in for a current run: CI never runs the tool, a
  restore never writes inside the repository, and the M5 gate refuses
  restored bundles of any other run.

Everything is synthetic and built here: bundles sealed by the gate's own
functions, records shaped as `make fuzz` writes them, and a fake GitHub.
"""

from __future__ import annotations

import email.message
import hashlib
import io
import json
import re
import shutil
import socket
import stat
import sys
import urllib.error
import urllib.parse
import urllib.request
import warnings
import zipfile
from collections.abc import Callable, Iterator, Mapping
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO_ROOT / "scripts"))
import dw  # noqa: E402  - imported after the path is extended
import evidence_archive as ea  # noqa: E402

REPO = "Onwcan/DireWolf"
REPO_ID = 1367331485
SHA = "0123456789abcdef0123456789abcdef01234567"
OTHER_SHA = "fedcba9876543210fedcba9876543210fedcba98"
M5_RUN = "43000000001"
FUZZ_RUN = "43000000002"
CENSUS = "cleanup: no evidence container remains; 0 pre-existing kept"
NOW = "2026-11-15T00:00:00Z"
# Version 1 of the contracts, frozen: an archive captured against it verifies forever.
CONTRACT_V1_SHA256 = "68439e976f134459a6f3be974dff4377e8d7940a20f65060695b39a171f49c5a"
HOSTED = {
    "GITHUB_ACTIONS": "true",
    "RUNNER_ENVIRONMENT": "github-hosted",
    "GITHUB_REF": "refs/heads/main",
    "RUNNER_OS": "Linux",
    "ImageOS": "ubuntu26",
    "ImageVersion": "20261101.186.1",
}


# --- building blocks ---------------------------------------------------------------


def _zip(files: Mapping[str, bytes], *, mode: int = 0o100644) -> bytes:
    """A ZIP laid out as upload-artifact lays one out: flat, deflated."""
    out = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")  # a duplicate name, on purpose
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, data in files.items():
                info = zipfile.ZipInfo(name, date_time=(2026, 11, 14, 12, 0, 0))
                info.external_attr = mode << 16
                info.create_system = 3
                info.compress_type = zipfile.ZIP_DEFLATED
                archive.writestr(info, data)
    return out.getvalue()


def _zip_pairs(pairs: list[tuple[str, bytes]]) -> bytes:
    out = io.BytesIO()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as archive:
            for name, data in pairs:
                archive.writestr(name, data)
    return out.getvalue()


def _bundle_files(
    scratch: Path,
    task: str,
    job: str,
    *,
    run_id: str = M5_RUN,
    attempt: str = "1",
    sha: str = SHA,
) -> dict[str, bytes]:
    """`task`'s bundle, kept and sealed by the gate's own functions."""
    kept = scratch / f"{job}-{run_id}-{attempt}-{sha[:6]}"
    judged = []
    for judge, table in dw.M5E_GATE_JUDGEMENTS[task]:
        fixed = dw.M5E_JUDGE_PREFIX[judge]
        prefix = fixed if fixed is not None else dw.SANDBOX_EVIDENCE_PREFIX
        judged.append((judge, table, prefix, f"synthetic output judged against {table}\n"))
    cleanup = [] if task in dw.M5E_CENSUS_FREE else [CENSUS]
    directory = dw.save_judged_evidence(task, kept, judged, cleanup)
    environ = {
        **HOSTED,
        "GITHUB_JOB": job,
        "GITHUB_RUN_ID": run_id,
        "GITHUB_RUN_ATTEMPT": attempt,
        "GITHUB_SHA": sha,
    }
    record = dw.m5e_bundle_record(environ, kept)
    (directory / "bundle.json").write_text(
        json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
    )
    return {path.name: path.read_bytes() for path in sorted(directory.iterdir())}


def _fuzz_record(
    target: str,
    *,
    run_id: str = FUZZ_RUN,
    attempt: str = "1",
    sha: str = SHA,
    seconds: int = 900,
    reported: int | None = None,
    status: str = "PASS",
    trigger: str = "workflow_dispatch",
    **more: object,
) -> dict[str, object]:
    """A record shaped as `make fuzz` writes one (`dw._fuzz_one`)."""
    record: dict[str, object] = {
        "schema": dw.FUZZ_EVIDENCE_SCHEMA,
        "engine": "libfuzzer",
        "target": target,
        "commit": sha,
        "trigger": trigger,
        "run_id": run_id,
        "run_attempt": attempt,
        "toolchain": dw.FUZZ_NIGHTLY,
        "rustc": "rustc 1.93.0-nightly",
        "cargo_fuzz": f"cargo-fuzz {dw.CARGO_FUZZ_VERSION}",
        "requested_seconds": seconds,
        "input_timeout_seconds": dw.FUZZ_INPUT_TIMEOUT,
        "corpus": f"fuzz/corpus/{target}",
        "seeds": 4,
        "corpus_files_before": 4,
        "status": status,
        "phase": "fuzz",
        "started_at": 1_800_000_000,
        "fuzz_started_at": 1_800_000_100,
        "detail": f"libFuzzer ran its whole {seconds} s budget",
        "exit_code": 0,
        "coverage_guided": True,
        "libfuzzer": {
            "coverage_counters": 4096,
            "initial_coverage": 812,
            "final_coverage": 1450,
            "runs": 12_345_678,
            "reported_seconds": seconds if reported is None else reported,
        },
        "crash": None,
        "corpus_files_after": 61,
        "finished_at": 1_800_001_001,
        "log_tail": ["Done 12345678 runs in 901 second(s)"],
    }
    record.update(more)
    return record


def _job(
    job_id: int, name: str, run_id: str, steps: list[str], conclusion: str = "success"
) -> dict[str, object]:
    return {
        "id": job_id,
        "run_id": int(run_id),
        "run_attempt": 1,
        "head_sha": SHA,
        "name": name,
        "status": "completed",
        "conclusion": conclusion,
        "started_at": "2026-11-14T12:00:00Z",
        "completed_at": "2026-11-14T12:20:00Z",
        "runner_group_name": "GitHub Actions",
        "labels": ["ubuntu-latest"],
        "steps": [
            {"number": n + 1, "name": step, "conclusion": conclusion}
            for n, step in enumerate(steps)
        ],
    }


class Scenario:
    """A run as GitHub's REST API describes it, and its artifacts' bytes."""

    def __init__(self, run_id: str, path: str, event: str) -> None:
        self.run_id = run_id
        self.run: dict[str, object] = {
            "id": int(run_id),
            "name": "CI" if path.endswith("ci.yml") else "Fuzz",
            "path": path,
            "run_number": 172,
            "run_attempt": 1,
            "workflow_id": 358652906,
            "head_sha": SHA,
            "head_branch": "main",
            "event": event,
            "status": "completed",
            "conclusion": "success",
            "created_at": "2026-11-14T12:00:00Z",
            "run_started_at": "2026-11-14T12:00:00Z",
            "updated_at": "2026-11-14T12:30:00Z",
            "html_url": f"https://github.com/{REPO}/actions/runs/{run_id}",
            "repository": {"full_name": REPO, "id": REPO_ID},
        }
        self.jobs: list[dict[str, object]] = []
        self.artifacts: list[dict[str, object]] = []
        self.blobs: dict[int, bytes] = {}

    def add(self, name: str, data: bytes, **override: object) -> None:
        artifact_id = 14_000_000_000 + len(self.artifacts)
        artifact: dict[str, object] = {
            "id": artifact_id,
            "name": name,
            "size_in_bytes": len(data),
            "digest": "sha256:" + hashlib.sha256(data).hexdigest(),
            "expired": False,
            "created_at": "2026-11-14T12:10:00Z",
            "expires_at": "2026-11-21T12:10:00Z",
            "workflow_run": {"id": int(self.run_id), "repository_id": REPO_ID, "head_sha": SHA},
        }
        artifact.update(override)
        self.artifacts.append(artifact)
        self.blobs[artifact_id] = data

    def artifact(self, name: str) -> dict[str, object]:
        return next(a for a in self.artifacts if a["name"] == name)


class FakeGitHub:
    """The read-only API capture uses, served from a scenario."""

    def __init__(
        self,
        scenario: Scenario,
        *,
        authenticated: bool = True,
        totals: Mapping[str, int] | None = None,
        failing: frozenset[str] = frozenset(),
        served: Mapping[str, bytes] | None = None,
    ) -> None:
        self.scenario = scenario
        self.authenticated = authenticated
        self.totals = dict(totals or {})
        self.failing = failing
        self.served = dict(served or {})
        self.downloads: list[int] = []

    def get_json(self, path: str) -> object:
        parts = urllib.parse.urlsplit(path)
        query = dict(urllib.parse.parse_qsl(parts.query))
        page, per_page = int(query.get("page", "1")), int(query.get("per_page", "30"))
        base = f"/repos/{REPO}/actions/runs/{self.scenario.run_id}"
        if parts.path == base:
            return json.loads(json.dumps(self.scenario.run))
        if parts.path == f"{base}/attempts/1/jobs":
            key, items = "jobs", self.scenario.jobs
        elif parts.path == f"{base}/artifacts":
            key, items = "artifacts", self.scenario.artifacts
        else:
            raise ea.ArchiveError(f"GitHub answered HTTP 404 to GET {path}")
        chosen = items[(page - 1) * per_page : page * per_page]
        total = self.totals.get(key, len(items))
        return {"total_count": total, key: json.loads(json.dumps(chosen))}

    def get_artifact_zip(self, artifact_id: int, limit: int) -> bytes:  # noqa: ARG002
        self.downloads.append(artifact_id)
        if not self.authenticated:
            raise ea.ArchiveError("NO CREDENTIALS: GitHub serves artifact ZIPs only signed in")
        name = next(str(a["name"]) for a in self.scenario.artifacts if a["id"] == artifact_id)
        if name in self.failing:
            raise ea.ArchiveError("GitHub answered HTTP 500 to the download")
        return self.served.get(name, self.scenario.blobs[artifact_id])


@pytest.fixture(scope="module")
def bundles(tmp_path_factory: pytest.TempPathFactory) -> dict[str, bytes]:
    """The fourteen bundles of one passing M5 run, as ZIPs."""
    scratch = tmp_path_factory.mktemp("bundles")
    return {
        f"m5e-evidence-{job}": _zip(_bundle_files(scratch, task, job))
        for task, job in dw.M5E_GATE_TASKS.items()
    }


def _m5_scenario(bundles: Mapping[str, bytes], drop: str | None = None) -> Scenario:
    scenario = Scenario(M5_RUN, ".github/workflows/ci.yml", "push")
    for number, (task, job) in enumerate(dw.M5E_GATE_TASKS.items()):
        steps = [f"Run make {task}", "Run make m5e-evidence-bundle", "Run actions/upload-artifact"]
        scenario.jobs.append(_job(100 + number, f"{job} (make {task})", M5_RUN, steps))
    scenario.jobs.append(_job(200, "M5 gate (make m5e-gate-check)", M5_RUN, ["Run make"]))
    scenario.jobs.append(_job(201, "CI", M5_RUN, ["Fail unless every required job succeeded"]))
    for name, data in bundles.items():
        if name != drop:
            scenario.add(name, data)
    return scenario


def _fuzz_scenario(
    records: Mapping[str, Mapping[str, object]] | None = None,
    *,
    event: str = "workflow_dispatch",
    conclusions: Mapping[str, str] | None = None,
    drop: str | None = None,
) -> Scenario:
    scenario = Scenario(FUZZ_RUN, ".github/workflows/fuzz.yml", event)
    scenario.jobs.append(_job(300, "stable mutation fuzzing (make fuzz-smoke)", FUZZ_RUN, ["x"]))
    scenario.jobs.append(_job(301, "coverage-guided budget (make fuzz-plan)", FUZZ_RUN, ["x"]))
    for number, target in enumerate(dw.FUZZ_TARGETS):
        conclusion = (conclusions or {}).get(target, "success")
        steps = ["make fuzz", "make fuzz-report", "Keep this target's evidence record"]
        name = f"coverage-guided {target} (make fuzz)"
        scenario.jobs.append(_job(310 + number, name, FUZZ_RUN, steps, conclusion))
        if target == drop:
            continue
        record = (records or {}).get(target) or _fuzz_record(target, trigger=event)
        data = (json.dumps(record, indent=2, sort_keys=True) + "\n").encode()
        scenario.add(f"fuzz-evidence-{target}", _zip({f"{target}.json": data}))
    scenario.jobs.append(_job(330, "Fuzz", FUZZ_RUN, ["Fail unless every fuzz job succeeded"]))
    return scenario


def _capture(
    scenario: Scenario,
    root: Path,
    *,
    github: FakeGitHub | None = None,
    strict: bool = False,
    staged: Path | None = None,
    attempt: int | None = None,
    note: str | None = None,
) -> Path:
    return ea.capture(
        github or FakeGitHub(scenario),
        REPO,
        scenario.run_id,
        root,
        attempt=attempt,
        staged=staged,
        strict=strict,
        note=note,
        now=lambda: NOW,
        report=lambda _line: None,
    )


def _ok(archive: Path) -> ea.Verification:
    result = ea.verify_archive(archive)
    assert result.problems == [], result.problems
    return result


def _manifest(archive: Path) -> dict[str, object]:
    loaded = json.loads((archive / "manifest.json").read_text(encoding="utf-8"))
    assert isinstance(loaded, dict)
    return loaded


def _d(value: object) -> dict[str, object]:
    assert isinstance(value, dict)
    return value


def _l(value: object) -> list[object]:
    assert isinstance(value, list)
    return value


def _forge(archive: Path, change: Callable[[dict[str, object]], None]) -> None:
    """Rewrite the manifest as a careful forger would: canonical, and with its
    digest file recomputed, so that only deeper checks can catch it."""
    manifest = _manifest(archive)
    change(manifest)
    body = ea.canonical_json(manifest)
    (archive / "manifest.json").write_bytes(body)
    digest = hashlib.sha256(body).hexdigest()
    (archive / "manifest.sha256").write_bytes(f"{digest}  manifest.json\n".encode())


def _problems(archive: Path) -> str:
    return "\n".join(ea.verify_archive(archive).problems)


def _rows(manifest: Mapping[str, object]) -> list[dict[str, object]]:
    rows = manifest["artifacts"]
    assert isinstance(rows, list)
    return rows


def _row(manifest: Mapping[str, object], name: str) -> dict[str, object]:
    return next(row for row in _rows(manifest) if row["name"] == name)


def _verdict(manifest: Mapping[str, object]) -> dict[str, object]:
    verdict = manifest["verdict"]
    assert isinstance(verdict, dict)
    return verdict


@pytest.fixture
def no_network(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Any attempt to reach the network fails the test."""

    def refuse(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("the network was used")

    monkeypatch.setattr(socket, "socket", refuse)
    monkeypatch.setattr(socket, "create_connection", refuse)
    monkeypatch.setattr(socket, "getaddrinfo", refuse)
    monkeypatch.setattr(urllib.request, "urlopen", refuse)
    yield


# --- the contract --------------------------------------------------------------------


def test_the_current_contracts_are_the_gate_and_the_fuzz_matrix() -> None:
    """A new task of the M5 gate or a new fuzz target needs a new contract
    version here; an old version is never edited, so old archives verify."""
    assert dict(ea.M5_CONTRACTS[ea.M5_CONTRACT_VERSION]) == dw.M5E_GATE_TASKS
    assert ea.FUZZ_CONTRACTS[ea.FUZZ_CONTRACT_VERSION] == dw.FUZZ_TARGETS
    version_one = json.dumps([ea.M5_CONTRACTS[1], ea.FUZZ_CONTRACTS[1]]).encode()
    assert hashlib.sha256(version_one).hexdigest() == CONTRACT_V1_SHA256
    assert len(ea.contract_expected(ea.M5_CLASS, 1)) == 14
    assert len(ea.contract_expected(ea.FUZZ_CLASS, 1)) == 8
    with pytest.raises(ea.ArchiveError, match="no contract"):
        ea.contract_expected(ea.M5_CLASS, 2)


def test_artifacts_are_classified_by_their_exact_names() -> None:
    assert ea.classify(ea.M5_CLASS, 1, "m5e-evidence-sandbox-egress") == "m5e-bundle"
    assert ea.classify(ea.M5_CLASS, 1, "eval-results") == "diagnostic"
    assert ea.classify(ea.M5_CLASS, 1, "m5e-evidence-sandbox-egres") == "unclassified"
    assert ea.classify(ea.FUZZ_CLASS, 1, "fuzz-evidence-url_parse") == "fuzz-record"
    assert ea.classify(ea.FUZZ_CLASS, 1, "fuzz-artifacts-url_parse") == "fuzz-reproducer"
    assert ea.classify(ea.FUZZ_CLASS, 1, "fuzz-evidence-not_a_target") == "unclassified"
    assert ea.classify(ea.FUZZ_CLASS, 1, "m5e-evidence-evals") == "unclassified"


# --- complete runs ---------------------------------------------------------------------


def test_a_complete_m5_run_archives_and_verifies(tmp_path: Path, bundles: dict[str, bytes]) -> None:
    archive = _capture(_m5_scenario(bundles), tmp_path / "root", strict=True, note="CI #172")
    assert archive == tmp_path / "root" / "runs" / f"{M5_RUN}-a1"
    result = _ok(archive)
    manifest = _manifest(archive)
    verdict = _verdict(manifest)
    assert (verdict["completeness"], verdict["evidence"]) == ("COMPLETE", "PASS")
    assert verdict["archived_expected"] == verdict["expected"] == 14
    assert manifest["label"] == ea.LABEL_TEXT and manifest["class"] == ea.M5_CLASS
    evidence = manifest["evidence"]
    assert isinstance(evidence, dict)
    rows = evidence["bundles"]
    assert isinstance(rows, list) and len(rows) == 14
    assert all(row["status"] == "VERIFIED" for row in rows)
    assert all(row["hosted_job"] is not None for row in rows)
    assert evidence["hosted_gate_job"] == {
        "id": 200,
        "name": "M5 gate (make m5e-gate-check)",
        "conclusion": "success",
    }
    for row in _rows(manifest):
        zipped = row["zip"]
        assert isinstance(zipped, dict) and zipped["digest_verified"] is True
        assert zipped["source"] == "github-download"
    capture = manifest["capture"]
    assert isinstance(capture, dict) and capture["note"] == "CI #172"
    assert sorted(result.archived) == sorted(bundles)
    lines = ea.summary_lines(archive, result)
    assert lines[0].startswith("HISTORICAL / OFFLINE verification")
    assert "never current hosted acceptance" in lines[0]
    assert any(line.startswith("integrity: OK") for line in lines)
    assert "evidence: PASS" in lines


def test_a_complete_fuzz_campaign_archives_and_verifies(tmp_path: Path) -> None:
    archive = _capture(_fuzz_scenario(), tmp_path / "root", strict=True)
    _ok(archive)
    manifest = _manifest(archive)
    assert (_verdict(manifest)["completeness"], _verdict(manifest)["evidence"]) == (
        "COMPLETE",
        "PASS",
    )
    evidence = manifest["evidence"]
    assert isinstance(evidence, dict)
    assert (evidence["budget_seconds"], evidence["budget"]) == (900, "full")
    assert evidence["planned_seconds"] is None  # a manual run: the operator chose 900
    targets = evidence["targets"]
    assert isinstance(targets, list) and len(targets) == 8
    first = targets[0]
    assert first["verdict"] == "PASS" and first["make_fuzz_step"] == "success"
    assert first["libfuzzer"] == {
        "coverage_counters": 4096,
        "initial_coverage": 812,
        "final_coverage": 1450,
        "runs": 12_345_678,
        "reported_seconds": 900,
    }
    assert first["record"]["toolchain"] == dw.FUZZ_NIGHTLY
    smoke = evidence["stable_smoke_job_not_counted"]
    assert isinstance(smoke, dict) and smoke["name"].startswith("stable mutation")


def test_a_pull_request_campaign_is_short_and_judged_at_its_planned_budget(
    tmp_path: Path,
) -> None:
    records = {t: _fuzz_record(t, seconds=30, trigger="pull_request") for t in dw.FUZZ_TARGETS}
    archive = _capture(_fuzz_scenario(records, event="pull_request"), tmp_path, strict=True)
    evidence = _manifest(archive)["evidence"]
    assert isinstance(evidence, dict)
    assert (evidence["planned_seconds"], evidence["budget"]) == (30, "short")
    # A pull request's records of another budget than the plan's: FAIL.
    records = {t: _fuzz_record(t, seconds=60, trigger="pull_request") for t in dw.FUZZ_TARGETS}
    archive = _capture(_fuzz_scenario(records, event="pull_request"), tmp_path / "b")
    assert _verdict(_manifest(archive))["evidence"] == "FAIL"
    assert "not the 30 s planned" in str(_verdict(_manifest(archive))["problems"])


def test_the_same_capture_twice_makes_the_same_manifest(
    tmp_path: Path, bundles: dict[str, bytes]
) -> None:
    one = _capture(_m5_scenario(bundles), tmp_path / "one")
    two = _capture(_m5_scenario(bundles), tmp_path / "two")
    assert (one / "manifest.json").read_bytes() == (two / "manifest.json").read_bytes()
    body = (one / "manifest.json").read_bytes()
    assert body == ea.canonical_json(json.loads(body)) and body.endswith(b"}\n")


def test_staged_zips_are_taken_only_at_githubs_digest(
    tmp_path: Path, bundles: dict[str, bytes]
) -> None:
    staged = tmp_path / "downloads"
    staged.mkdir()
    for name, data in bundles.items():
        (staged / f"{name}.zip").write_bytes(data)
    (staged / "notes.txt").write_text("not an artifact", encoding="utf-8")
    github = FakeGitHub(_m5_scenario(bundles), authenticated=False)
    archive = _capture(_m5_scenario(bundles), tmp_path / "root", staged=staged, github=github)
    _ok(archive)
    assert github.downloads == []
    for row in _rows(_manifest(archive)):
        zipped = row["zip"]
        assert isinstance(zipped, dict)
        assert (zipped["source"], zipped["digest_verified"]) == ("operator-staged", True)
    # A staged ZIP that is not the artifact GitHub records: refused, whole.
    (staged / "m5e-evidence-evals.zip").write_bytes(bundles["m5e-evidence-sandbox-agent"])
    with pytest.raises(ea.ArchiveError, match="not the artifact GitHub records"):
        _capture(_m5_scenario(bundles), tmp_path / "again", staged=staged, github=github)
    assert not (tmp_path / "again" / "runs" / f"{M5_RUN}-a1").exists()


def test_bytes_github_gave_no_digest_for_are_taken_only_from_github(
    tmp_path: Path, bundles: dict[str, bytes]
) -> None:
    """Staged bytes need GitHub's digest to be checked against; without one
    they are UNAVAILABLE. Downloaded ones are kept, marked unverified."""
    staged = tmp_path / "downloads"
    staged.mkdir()
    for name, data in bundles.items():
        (staged / f"{name}.zip").write_bytes(data)
    scenario = _m5_scenario(bundles)
    scenario.artifact("m5e-evidence-evals")["digest"] = None
    github = FakeGitHub(scenario, authenticated=False)
    archive = _capture(scenario, tmp_path / "staged", staged=staged, github=github)
    _ok(archive)
    row = _row(_manifest(archive), "m5e-evidence-evals")
    assert row["status"] == "UNAVAILABLE" and "cannot be verified" in str(row["reason"])
    archive = _capture(scenario, tmp_path / "downloaded")
    _ok(archive)
    zipped = _d(_row(_manifest(archive), "m5e-evidence-evals")["zip"])
    assert (zipped["source"], zipped["digest_verified"]) == ("github-download", False)
    lines = ea.summary_lines(archive, _ok(archive))
    assert "evidence: PASS" in lines
    # Without GitHub's digest, GitHub's recorded size still holds the bytes,
    # even when every hash the archive keeps has been recomputed.
    path = archive / "artifacts" / "m5e-evidence-evals.zip"
    files = {e.path: e.data for e in ea.zip_entries(path.read_bytes(), "evals")}
    files["added.txt"] = b"added after the capture\n"
    forged = _zip(files)
    path.write_bytes(forged)

    def rehash(manifest: dict[str, object]) -> None:
        row = _row(manifest, "m5e-evidence-evals")
        _d(row["zip"]).update(sha256=hashlib.sha256(forged).hexdigest(), bytes=len(forged))
        row["entries"] = ea.entry_records(ea.zip_entries(forged, "evals"))

    _forge(archive, rehash)
    assert f"{len(forged)} bytes, GitHub recorded" in _problems(archive)


def test_a_staged_link_is_refused(tmp_path: Path, bundles: dict[str, bytes]) -> None:
    staged = tmp_path / "downloads"
    staged.mkdir()
    real = tmp_path / "elsewhere.zip"
    real.write_bytes(bundles["m5e-evidence-evals"])
    try:
        (staged / "m5e-evidence-evals.zip").symlink_to(real)
    except OSError:
        pytest.skip("this platform cannot make a symbolic link")
    with pytest.raises(ea.ArchiveError, match="not a regular file"):
        _capture(_m5_scenario(bundles), tmp_path / "root", staged=staged)


# --- incomplete and inconsistent captures --------------------------------------------


def test_a_missing_artifact_is_incomplete_and_strict_refuses_it(
    tmp_path: Path, bundles: dict[str, bytes]
) -> None:
    scenario = _m5_scenario(bundles, drop="m5e-evidence-sandbox-restart")
    with pytest.raises(ea.ArchiveError, match=r"refused \(--strict\): INCOMPLETE"):
        _capture(scenario, tmp_path / "strict", strict=True)
    archive = _capture(scenario, tmp_path / "lenient")
    _ok(archive)
    verdict = _verdict(_manifest(archive))
    assert verdict["completeness"] == "INCOMPLETE" and verdict["evidence"] == "INCOMPLETE"
    assert verdict["missing"] == ["m5e-evidence-sandbox-restart"]
    # An archived ZIP deleted later is missing from the archive itself.
    (archive / "artifacts" / "m5e-evidence-evals.zip").unlink()
    assert "artifacts/m5e-evidence-evals.zip is absent" in _problems(archive)


def test_an_expired_artifact_is_reported_never_archived(
    tmp_path: Path, bundles: dict[str, bytes]
) -> None:
    scenario = _m5_scenario(bundles)
    scenario.artifact("m5e-evidence-net-http")["expired"] = True
    github = FakeGitHub(scenario)
    archive = _capture(scenario, tmp_path, github=github)
    _ok(archive)
    manifest = _manifest(archive)
    row = _row(manifest, "m5e-evidence-net-http")
    assert row["status"] == "EXPIRED" and row["zip"] is None
    assert scenario.artifact("m5e-evidence-net-http")["id"] not in github.downloads
    assert _verdict(manifest)["not_archived"] == [
        {
            "name": "m5e-evidence-net-http",
            "status": "EXPIRED",
            "reason": "GitHub reports the artifact expired",
        }
    ]
    lines = ea.inventory(tmp_path, deep=True, backup_root=None)
    assert "INCOMPLETE 13/14" in lines[1] and "integrity OK" in lines[1]


def test_a_failed_download_is_unavailable(tmp_path: Path, bundles: dict[str, bytes]) -> None:
    scenario = _m5_scenario(bundles)
    github = FakeGitHub(scenario, failing=frozenset({"m5e-evidence-sandbox-agent"}))
    archive = _capture(scenario, tmp_path, github=github)
    row = _row(_manifest(archive), "m5e-evidence-sandbox-agent")
    assert row["status"] == "UNAVAILABLE"
    assert "HTTP 500" in str(row["reason"])
    # A download that is not the artifact GitHub records is refused, whole:
    # the same size with one byte changed, against GitHub's digest...
    flipped = bytearray(bundles["m5e-evidence-evals"])
    flipped[len(flipped) // 2] ^= 0x01
    wrong = FakeGitHub(scenario, served={"m5e-evidence-evals": bytes(flipped)})
    with pytest.raises(ea.ArchiveError, match="not the artifact GitHub records"):
        _capture(scenario, tmp_path / "wrong", github=wrong)
    # ... and, where GitHub reports no digest, another size than its record's.
    scenario.artifact("m5e-evidence-evals")["digest"] = None
    longer = FakeGitHub(
        scenario, served={"m5e-evidence-evals": bundles["m5e-evidence-evals"] + b"!"}
    )
    with pytest.raises(ea.ArchiveError, match="not the artifact GitHub records"):
        _capture(scenario, tmp_path / "longer", github=longer)


@pytest.mark.usefixtures("no_network")
def test_without_credentials_nothing_is_downloaded(
    tmp_path: Path, bundles: dict[str, bytes]
) -> None:
    with pytest.raises(ea.ArchiveError, match="NO CREDENTIALS"):
        ea.HttpGitHub(REPO, None).get_artifact_zip(1, 10)
    github = FakeGitHub(_m5_scenario(bundles), authenticated=False)
    with pytest.raises(ea.ArchiveError, match=r"no artifact could be archived.*NO CREDENTIALS"):
        _capture(_m5_scenario(bundles), tmp_path, github=github)
    assert not (tmp_path / "runs" / f"{M5_RUN}-a1").exists()


@pytest.mark.usefixtures("no_network")
def test_a_token_is_checked_by_shape_and_never_echoed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    planted = "ghp-not!a!token-THE-PLANTED-VALUE"
    monkeypatch.setenv("DW_ARCHIVE_TEST_TOKEN", planted)
    code = ea.main(
        [
            "capture",
            "--run",
            "1",
            "--archive-root",
            str(tmp_path),
            "--token-env",
            "DW_ARCHIVE_TEST_TOKEN",
        ]
    )
    said = capsys.readouterr()
    assert code == 1 and "not shaped like a GitHub token" in said.err
    assert planted not in said.err + said.out
    monkeypatch.delenv("DW_ARCHIVE_TEST_TOKEN")
    again = ["capture", "--run", "1", "--archive-root", str(tmp_path)]
    assert ea.main([*again, "--token-env", "DW_ARCHIVE_TEST_TOKEN"]) == 1
    assert "unset or empty" in capsys.readouterr().err
    with pytest.raises(ea.ArchiveError, match="names an environment variable"):
        ea._token("ghp_" + "a" * 36)


def test_the_token_never_follows_the_download_redirect(monkeypatch: pytest.MonkeyPatch) -> None:
    token = "ghp_" + "t" * 36
    github = ea.HttpGitHub(REPO, token)
    sent: list[urllib.request.Request] = []
    signed = "https://results.blob.example.net/artifact.zip?sig=SIGNED-URL-SECRET"
    moved = email.message.Message()
    moved["Location"] = signed

    def answer(request: urllib.request.Request, **_options: object) -> io.BytesIO:
        sent.append(request)
        if len(sent) == 1:
            raise urllib.error.HTTPError(request.full_url, 302, "Found", moved, None)
        return io.BytesIO(b"PK\x03\x04 the bytes")

    monkeypatch.setattr(github._opener, "open", answer)
    assert github.get_artifact_zip(7, 1024) == b"PK\x03\x04 the bytes"
    first, second = sent
    assert first.full_url == f"{ea.API_BASE}/repos/{REPO}/actions/artifacts/7/zip"
    assert first.unredirected_hdrs.get("Authorization") == f"Bearer {token}"
    assert "Authorization" not in first.headers  # never copied onto a redirect
    assert second.full_url == signed
    assert second.get_header("Authorization") is None
    assert "Authorization" not in second.unredirected_hdrs
    # A failure names the storage host only: the signed URL is a credential.
    sent.clear()

    def refuse(request: urllib.request.Request, **_options: object) -> io.BytesIO:
        sent.append(request)
        if len(sent) == 1:
            raise urllib.error.HTTPError(request.full_url, 302, "Found", moved, None)
        nothing = email.message.Message()
        raise urllib.error.HTTPError(request.full_url, 403, "Forbidden", nothing, None)

    monkeypatch.setattr(github._opener, "open", refuse)
    with pytest.raises(ea.ArchiveError) as raised:
        github.get_artifact_zip(7, 1024)
    assert "results.blob.example.net answered HTTP 403" in str(raised.value)
    assert "SIGNED-URL-SECRET" not in str(raised.value) and token not in str(raised.value)
    with pytest.raises(ea.ArchiveError, match="only https"):
        github._request("http://api.github.com/x", "a", auth=True)
    moved.replace_header("Location", "http://results.blob.example.net/artifact.zip")
    sent.clear()
    monkeypatch.setattr(github._opener, "open", answer)
    with pytest.raises(ea.ArchiveError, match="redirect is not an https URL"):
        github.get_artifact_zip(7, 1024)
    assert len(sent) == 1


def test_a_partial_api_answer_is_refused(tmp_path: Path, bundles: dict[str, bytes]) -> None:
    scenario = _m5_scenario(bundles)
    for key in ("artifacts", "jobs"):
        github = FakeGitHub(scenario, totals={key: len(getattr(scenario, key)) + 1})
        with pytest.raises(ea.ArchiveError, match="a partial answer"):
            _capture(scenario, tmp_path / key, github=github)
    many = Scenario(M5_RUN, ".github/workflows/ci.yml", "push")

    class Shifting(FakeGitHub):
        def get_json(self, path: str) -> object:
            answer = super().get_json(path)
            if "page=2" in path and isinstance(answer, dict) and "artifacts" in answer:
                answer["total_count"] = 999
            return answer

    for number in range(150):
        many.add(f"unclassified-{number:03d}", _zip({"x.txt": b"x"}))
    with pytest.raises(ea.ArchiveError, match="the total changed between pages"):
        _capture(many, tmp_path / "shifting", github=Shifting(many))


def test_two_artifacts_of_one_name_are_refused(tmp_path: Path, bundles: dict[str, bytes]) -> None:
    scenario = _m5_scenario(bundles)
    scenario.add("M5E-evidence-evals", bundles["m5e-evidence-evals"])
    with pytest.raises(ea.ArchiveError, match="two artifacts share a name"):
        _capture(scenario, tmp_path)


@pytest.mark.parametrize(
    ("change", "said"),
    [
        (lambda run: run.update(status="in_progress"), "only a completed run"),
        (lambda run: run.update(path=".github/workflows/m5e5-evidence.yml"), "only \\["),
        (lambda run: run.update(id=1), "answered for another run"),
        (lambda run: run.update(repository={"full_name": "fork/DireWolf", "id": 1}), "not 'Onwcan"),
        (lambda run: run.update(head_sha="not-a-sha"), "is not a commit SHA"),
    ],
)
def test_a_run_github_does_not_describe_as_archivable_is_refused(
    tmp_path: Path,
    bundles: dict[str, bytes],
    change: Callable[[dict[str, object]], None],
    said: str,
) -> None:
    scenario = _m5_scenario(bundles)
    change(scenario.run)
    with pytest.raises(ea.ArchiveError, match=said):
        _capture(scenario, tmp_path)


@pytest.mark.parametrize(
    ("field", "value", "said"),
    [
        ("id", int(M5_RUN) + 1, "is not of run"),
        ("head_sha", OTHER_SHA, "is not of run"),
        ("repository_id", 7, "is not of run"),
    ],
)
def test_an_artifact_of_another_run_commit_or_repository_is_refused(
    tmp_path: Path, bundles: dict[str, bytes], field: str, value: object, said: str
) -> None:
    scenario = _m5_scenario(bundles)
    origin = scenario.artifact("m5e-evidence-evals")["workflow_run"]
    assert isinstance(origin, dict)
    origin[field] = value
    with pytest.raises(ea.ArchiveError, match=said):
        _capture(scenario, tmp_path)


def test_a_job_of_another_attempt_is_refused(tmp_path: Path, bundles: dict[str, bytes]) -> None:
    scenario = _m5_scenario(bundles)
    scenario.jobs[0]["run_attempt"] = 2
    with pytest.raises(ea.ArchiveError, match="is not of run"):
        _capture(scenario, tmp_path)
    scenario = _m5_scenario(bundles)
    scenario.jobs[0]["head_sha"] = OTHER_SHA
    with pytest.raises(ea.ArchiveError, match="is of another commit"):
        _capture(scenario, tmp_path)
    with pytest.raises(ea.ArchiveError, match="at attempt 1, not 2"):
        _capture(_m5_scenario(bundles), tmp_path, attempt=2)


@pytest.mark.parametrize(
    ("seal", "said"),
    [
        ({"run_id": "43999999999"}, "not of the archived run"),
        ({"attempt": "2"}, "not of the archived run"),
        ({"sha": OTHER_SHA}, "not of the archived run"),
    ],
)
def test_a_bundle_sealed_in_another_run_attempt_or_commit_is_refused(
    tmp_path: Path, bundles: dict[str, bytes], seal: dict[str, str], said: str
) -> None:
    files = _bundle_files(tmp_path / "kept", "sandbox-restart-evidence", "sandbox-restart", **seal)
    stale = dict(bundles, **{"m5e-evidence-sandbox-restart": _zip(files)})
    with pytest.raises(ea.ArchiveError, match=said):
        _capture(_m5_scenario(stale), tmp_path / "root")
    assert not (tmp_path / "root" / "runs" / f"{M5_RUN}-a1").exists()


def test_a_bundle_the_gate_refuses_is_kept_as_a_failure(
    tmp_path: Path, bundles: dict[str, bytes]
) -> None:
    """A run's own broken bundle is evidence too: kept, verified, and FAIL --
    never PASS. With `strict`, refused."""
    files = _bundle_files(tmp_path / "kept", "net-http-evidence", "net-http")
    files["judged-0.txt"] = b"edited after it was judged\n"
    broken = dict(bundles, **{"m5e-evidence-net-http": _zip(files)})
    with pytest.raises(ea.ArchiveError, match="evidence FAIL"):
        _capture(_m5_scenario(broken), tmp_path / "strict", strict=True)
    archive = _capture(_m5_scenario(broken), tmp_path / "lenient")
    _ok(archive)
    manifest = _manifest(archive)
    assert _verdict(manifest)["evidence"] == "FAIL"
    evidence = manifest["evidence"]
    assert isinstance(evidence, dict)
    row = next(b for b in evidence["bundles"] if b["artifact"] == "m5e-evidence-net-http")
    assert row["status"] == "REJECTED" and "not the output the task judged" in row["reason"]

    # Called VERIFIED by a forger, the bytes still say otherwise.
    def lie(manifest: dict[str, object]) -> None:
        for bundle in _l(_d(manifest["evidence"])["bundles"]):
            row = _d(bundle)
            if row["artifact"] == "m5e-evidence-net-http":
                row["status"], row["reason"] = "VERIFIED", None
        _verdict(manifest).update(evidence="PASS", problems=[])

    _forge(archive, lie)
    assert "the manifest's evidence is not what the archived bytes say" in _problems(archive)


# --- the fuzz campaign's verdict -------------------------------------------------------


@pytest.mark.parametrize(
    ("changes", "reported", "conclusions", "said"),
    [
        # PASS on the record without libFuzzer's own report of the whole budget.
        ({}, 640, {}, "says PASS without libFuzzer's own report of the whole budget"),
        ({"status": "FAIL", "detail": "crash-deadbeef"}, None, {"url_parse": "failure"}, "FAIL"),
        ({"status": "TIMEOUT"}, None, {"url_parse": "failure"}, "TIMEOUT"),
        # The stable mutation smoke harness is not coverage-guided evidence.
        ({"engine": "stable-mutation"}, None, {}, "not a coverage-guided libFuzzer run"),
        ({"coverage_guided": False}, None, {}, "says PASS without"),
        # A record left running: the step's outcome decides, never a pass.
        ({"status": "RUNNING"}, None, {}, "exited without recording an outcome"),
        # A passing record in a job that failed.
        ({}, None, {"url_parse": "failure"}, "its job finished 'failure'"),
    ],
)
def test_a_fuzz_campaign_passes_only_on_every_targets_whole_budget(
    tmp_path: Path,
    changes: dict[str, object],
    reported: int | None,
    conclusions: dict[str, str],
    said: str,
) -> None:
    url_parse = {**_fuzz_record("url_parse", reported=reported), **changes}
    scenario = _fuzz_scenario({"url_parse": url_parse}, conclusions=conclusions)
    with pytest.raises(ea.ArchiveError, match="refused \\(--strict\\)"):
        _capture(scenario, tmp_path / "strict", strict=True)
    archive = _capture(scenario, tmp_path / "lenient")
    _ok(archive)
    verdict = _verdict(_manifest(archive))
    assert verdict["evidence"] == "FAIL"
    assert said in "\n".join(str(p) for p in _l(verdict["problems"]))


def test_a_campaign_with_a_target_missing_is_incomplete_never_pass(tmp_path: Path) -> None:
    archive = _capture(_fuzz_scenario(drop="policy_loader"), tmp_path)
    verdict = _verdict(_manifest(archive))
    assert (verdict["completeness"], verdict["evidence"]) == ("INCOMPLETE", "INCOMPLETE")
    assert verdict["missing"] == ["fuzz-evidence-policy_loader"]


def test_records_of_different_budgets_fail_the_campaign(tmp_path: Path) -> None:
    archive = _capture(
        _fuzz_scenario({"url_parse": _fuzz_record("url_parse", seconds=60)}), tmp_path
    )
    verdict = _verdict(_manifest(archive))
    assert verdict["evidence"] == "FAIL"
    assert "different budgets" in str(verdict["problems"])


def test_a_fuzz_record_of_another_run_is_refused(tmp_path: Path) -> None:
    for record in (
        _fuzz_record("url_parse", run_id="43999999999"),
        _fuzz_record("url_parse", sha=OTHER_SHA),
        _fuzz_record("url_parse", attempt="2"),
        {**_fuzz_record("url_parse"), "target": "dwkp_decode"},
    ):
        with pytest.raises(ea.ArchiveError, match="not of url_parse in the archived run"):
            _capture(_fuzz_scenario({"url_parse": record}), tmp_path)


def test_a_reproducer_is_kept_and_matched_to_its_record(tmp_path: Path) -> None:
    crash = b"\x00\xffcrashing input"
    digest = hashlib.sha256(crash).hexdigest()
    record = _fuzz_record(
        "url_parse",
        status="FAIL",
        detail="libFuzzer found a crash",
        crash={"artifact": "./fuzz/artifacts/url_parse/crash-1", "sha256": digest, "bytes": 15},
    )
    scenario = _fuzz_scenario({"url_parse": record}, conclusions={"url_parse": "failure"})
    scenario.add("fuzz-artifacts-url_parse", _zip({"crash-1": crash}))
    archive = _capture(scenario, tmp_path)
    _ok(archive)
    manifest = _manifest(archive)
    assert _row(manifest, "fuzz-artifacts-url_parse")["class"] == "fuzz-reproducer"
    evidence = manifest["evidence"]
    assert isinstance(evidence, dict)
    row = next(t for t in evidence["targets"] if t["target"] == "url_parse")
    assert row["reproducer"] == {"artifact": "fuzz-artifacts-url_parse", "matches_record": True}
    assert _verdict(manifest)["evidence"] == "FAIL"


def test_a_forged_pass_of_a_failed_campaign_is_found(tmp_path: Path) -> None:
    scenario = _fuzz_scenario(
        {"url_parse": _fuzz_record("url_parse", status="FAIL", detail="crash")},
        conclusions={"url_parse": "failure"},
    )
    archive = _capture(scenario, tmp_path)

    def lie(manifest: dict[str, object]) -> None:
        for row in _l(_d(manifest["evidence"])["targets"]):
            _d(row)["verdict"] = "PASS"
        _verdict(manifest).update(evidence="PASS", problems=[])

    _forge(archive, lie)
    problems = _problems(archive)
    assert "the manifest's evidence is not what the archived bytes say" in problems
    assert "the manifest's verdict is not what the archived bytes say" in problems


# --- an archive is never replaced, and never half-written ------------------------------


def test_a_second_capture_never_replaces_an_archive(
    tmp_path: Path, bundles: dict[str, bytes]
) -> None:
    archive = _capture(_m5_scenario(bundles), tmp_path)
    before = {p.name: p.read_bytes() for p in sorted(archive.rglob("*")) if p.is_file()}
    with pytest.raises(ea.ArchiveError, match="already exists, and an archive is never replaced"):
        _capture(_m5_scenario(bundles), tmp_path)
    after = {p.name: p.read_bytes() for p in sorted(archive.rglob("*")) if p.is_file()}
    assert before == after
    assert [p.name for p in (tmp_path / "runs").iterdir()] == [archive.name]


def test_an_interrupted_capture_leaves_no_archive(
    tmp_path: Path, bundles: dict[str, bytes], monkeypatch: pytest.MonkeyPatch
) -> None:
    real = ea._write_new
    written: list[Path] = []

    def dies(path: Path, data: bytes) -> None:
        if len(written) == 5:
            raise KeyboardInterrupt
        written.append(path)
        real(path, data)

    monkeypatch.setattr(ea, "_write_new", dies)
    with pytest.raises(KeyboardInterrupt):
        _capture(_m5_scenario(bundles), tmp_path)
    assert list((tmp_path / "runs").iterdir()) == []  # the scratch directory went too
    monkeypatch.setattr(ea, "_write_new", real)
    # A capture killed outright leaves its `.capture-*` directory: listed as
    # such, never as an archive, and no obstacle to the next capture.
    leftover = tmp_path / "runs" / f".capture-{M5_RUN}-a1-killed"
    leftover.mkdir()
    (leftover / "manifest.json").write_text("{", encoding="utf-8")
    archive = _capture(_m5_scenario(bundles), tmp_path)
    _ok(archive)
    lines = ea.inventory(tmp_path, deep=True, backup_root=None)
    assert any("an interrupted capture, not an archive" in line for line in lines)
    assert sum("integrity OK" in line for line in lines) == 1


def test_an_archive_that_does_not_verify_is_never_named(
    tmp_path: Path, bundles: dict[str, bytes], monkeypatch: pytest.MonkeyPatch
) -> None:
    planted = ea.Verification(None, None, ["a planted problem"], {})
    monkeypatch.setattr(ea, "verify_archive", lambda _path: planted)
    with pytest.raises(ea.ArchiveError, match="did not verify, and nothing was kept"):
        _capture(_m5_scenario(bundles), tmp_path)
    assert list((tmp_path / "runs").iterdir()) == []


def test_an_archive_root_inside_the_repository_is_refused(bundles: dict[str, bytes]) -> None:
    for inside in (REPO_ROOT / "target" / "evidence-archive", REPO_ROOT):
        with pytest.raises(ea.ArchiveError, match="is inside the repository"):
            _capture(_m5_scenario(bundles), inside)
    assert not (REPO_ROOT / "target" / "evidence-archive").exists()


# --- verification finds every change ---------------------------------------------------


@pytest.fixture
def m5_archive(tmp_path: Path, bundles: dict[str, bytes]) -> Path:
    return _capture(_m5_scenario(bundles), tmp_path / "root")


def test_a_changed_zip_byte_is_found(m5_archive: Path) -> None:
    path = m5_archive / "artifacts" / "m5e-evidence-sandbox-egress.zip"
    data = bytearray(path.read_bytes())
    data[len(data) // 2] ^= 0x01
    path.write_bytes(bytes(data))
    problems = _problems(m5_archive)
    assert "m5e-evidence-sandbox-egress: the ZIP is not the one recorded" in problems
    assert "not at GitHub's digest" in problems


def test_a_changed_file_inside_a_zip_is_found_however_carefully_hidden(m5_archive: Path) -> None:
    name = "m5e-evidence-sandbox-workload"
    path = m5_archive / "artifacts" / f"{name}.zip"
    files = {e.path: e.data for e in ea.zip_entries(path.read_bytes(), name)}
    files["judged-0.txt"] = b"a quieter version of what happened\n"
    forged = _zip(files)
    path.write_bytes(forged)
    assert "not at GitHub's digest" in _problems(m5_archive)
    digest = hashlib.sha256(forged).hexdigest()

    def rehash(manifest: dict[str, object]) -> None:
        row = _row(manifest, name)
        _d(row["zip"]).update(sha256=digest, bytes=len(forged))
        _d(row["github"]).update(digest=f"sha256:{digest}", size_in_bytes=len(forged))

    _forge(m5_archive, rehash)
    problems = _problems(m5_archive)
    assert f"{name}: its entries are not those recorded" in problems

    def entries_too(manifest: dict[str, object]) -> None:
        _row(manifest, name)["entries"] = ea.entry_records(ea.zip_entries(forged, name))

    _forge(m5_archive, entries_too)
    # Every outer hash agrees now; the bundle's own record does not.
    assert "the manifest's evidence is not what the archived bytes say" in _problems(m5_archive)


@pytest.mark.parametrize(
    ("change", "said"),
    [
        (lambda m: m.update(version=2), "unsupported manifest"),
        (lambda m: m.update(schema="direwolf.other"), "unsupported manifest"),
        (lambda m: m["contract"].update(version=99), "no contract 99"),
        (lambda m: m.update(label="CURRENT HOSTED ACCEPTANCE"), "not the HISTORICAL / OFFLINE"),
        (lambda m: m.update(extra=True), "the manifest's fields are"),
        (lambda m: m.update(**{"class": ea.FUZZ_CLASS}), "is not that of the workflow"),
        (lambda m: m["github"]["run"].update(id=43999999999), "but holds run"),
        (lambda m: m["github"]["run"].update(attempt=2), "but holds run"),
        (lambda m: m["github"]["run"].update(head_sha=OTHER_SHA), "not of the archived run"),
        (lambda m: m["github"]["run"].update(workflow_path=".github/x.yml"), "not that of"),
        (lambda m: m["contract"]["expected"].pop(), "contract is not m5e-gate"),
        (lambda m: _rows(m).reverse(), "not in name order"),
        (lambda m: _rows(m).append(dict(_rows(m)[0])), "listed twice"),
        (lambda m: _rows(m).pop(), "files in artifacts/ that the manifest does not list"),
        (lambda m: _rows(m)[0].update(**{"class": "diagnostic"}), "classified 'diagnostic'"),
        (lambda m: _rows(m)[0].update(status="DELETED"), "the status 'DELETED'"),
        (lambda m: _rows(m)[0].update(status="EXPIRED"), "EXPIRED, yet it records a ZIP"),
        (
            lambda m: _rows(m)[0].update(status="EXPIRED", zip=None, entries=[], reason="x"),
            "EXPIRED, though GitHub did not say so",
        ),
        (lambda m: _d(_rows(m)[0]["zip"]).update(digest_verified=False), "unverified bytes"),
        (lambda m: _d(_rows(m)[0]["zip"]).update(file="../x.zip"), "recorded at"),
        (lambda m: _l(_rows(m)[0]["entries"]).pop(), "its entries are not those recorded"),
        (lambda m: _verdict(m).update(completeness="INCOMPLETE"), "verdict is not what"),
        (lambda m: _verdict(m).update(missing=["m5e-evidence-x"]), "verdict is not what"),
        (lambda m: m.update(provenance={}), "statement of provenance is altered"),
        (lambda m: m["evidence"]["bundles"].pop(), "evidence is not what"),
    ],
)
def test_a_manifest_that_does_not_agree_with_its_bytes_is_found(
    m5_archive: Path, change: Callable[[dict[str, object]], None], said: str
) -> None:
    _forge(m5_archive, change)
    assert said in _problems(m5_archive)


def test_a_manifest_changed_without_its_digest_or_form_is_found(m5_archive: Path) -> None:
    body = (m5_archive / "manifest.json").read_bytes()
    (m5_archive / "manifest.json").write_bytes(body.replace(b'"PASS"', b'"FAIL"', 1))
    assert "manifest.sha256 is not the manifest's SHA-256" in _problems(m5_archive)
    loose = json.dumps(json.loads(body)).encode()
    (m5_archive / "manifest.json").write_bytes(loose)
    digest = hashlib.sha256(loose).hexdigest()
    (m5_archive / "manifest.sha256").write_bytes(f"{digest}  manifest.json\n".encode())
    assert "not in its canonical form" in _problems(m5_archive)


@pytest.mark.parametrize(
    ("body", "said"),
    [
        (b"{not json", "not strict JSON"),
        (b'{"schema": 1, "schema": 2}', "a repeated key"),
        (b'{"a": NaN}', "NaN is not JSON"),
        (b"[]", "the manifest is not an object"),
        (b"\xff\xfe", "not strict JSON"),
    ],
)
def test_a_malformed_manifest_is_found(m5_archive: Path, body: bytes, said: str) -> None:
    (m5_archive / "manifest.json").write_bytes(body)
    digest = hashlib.sha256(body).hexdigest()
    (m5_archive / "manifest.sha256").write_bytes(f"{digest}  manifest.json\n".encode())
    assert said in _problems(m5_archive)


def test_unexpected_files_and_links_in_an_archive_are_found(m5_archive: Path) -> None:
    (m5_archive / "artifacts" / "extra.zip").write_bytes(b"PK\x03\x04")
    (m5_archive / "README").write_text("x", encoding="utf-8")
    problems = _problems(m5_archive)
    assert "that the manifest does not list: ['extra.zip']" in problems
    assert "the archive holds" in problems
    target = m5_archive / "artifacts" / "m5e-evidence-evals.zip"
    moved = m5_archive.parent / "elsewhere.zip"
    shutil.move(target, moved)
    try:
        target.symlink_to(moved)
    except OSError:
        pytest.skip("this platform cannot make a symbolic link")
    assert "artifacts/m5e-evidence-evals.zip is a link" in _problems(m5_archive)


def test_a_truncated_or_padded_zip_in_an_archive_is_found(m5_archive: Path) -> None:
    path = m5_archive / "artifacts" / "m5e-evidence-evals.zip"
    data = path.read_bytes()
    path.write_bytes(data[: len(data) - 30])
    assert "unreadable ZIP" in _problems(m5_archive) or "after the ZIP" in _problems(m5_archive)
    path.write_bytes(data + b"appended")
    assert "bytes after the ZIP's end of central directory" in _problems(m5_archive)


# --- unsafe ZIPs -------------------------------------------------------------------------


@pytest.mark.parametrize(
    "name",
    [
        "../escape.txt",
        "../../etc/passwd",
        "/etc/passwd",
        "nested/judged.json",
        "nested\\judged.json",
        "..",
        ".hidden",
        "trailing.",
        "CON",
        "nul.txt",
        "with space.txt",
        "directory/",
    ],
)
def test_a_zip_entry_outside_one_flat_safe_name_is_refused(name: str) -> None:
    with pytest.raises(ea.ArchiveError, match="not a safe flat file name"):
        ea.zip_entries(_zip_pairs([(name, b"x")]), "a")


def test_a_symbolic_link_or_directory_entry_is_refused() -> None:
    link = _zip({"judged.json": b"/etc/shadow"}, mode=stat.S_IFLNK | 0o777)
    with pytest.raises(ea.ArchiveError, match="not a regular file"):
        ea.zip_entries(link, "a")
    device = _zip({"judged.json": b""}, mode=stat.S_IFCHR | 0o600)
    with pytest.raises(ea.ArchiveError, match="not a regular file"):
        ea.zip_entries(device, "a")
    directory = _zip({"judged.json": b""}, mode=stat.S_IFDIR | 0o755)
    with pytest.raises(ea.ArchiveError, match="not a regular file"):
        ea.zip_entries(directory, "a")


def test_duplicate_and_case_colliding_entries_are_refused() -> None:
    twice = _zip_pairs([("judged.json", b"one"), ("judged.json", b"two")])
    with pytest.raises(ea.ArchiveError, match="appears twice"):
        ea.zip_entries(twice, "a")
    folded = _zip_pairs([("judged.json", b"one"), ("Judged.JSON", b"two")])
    with pytest.raises(ea.ArchiveError, match="collides with another entry"):
        ea.zip_entries(folded, "a")


def test_an_oversized_or_bomb_entry_is_refused_before_it_is_kept(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    bomb = _zip({"judged-0.txt": b"\0" * (ea.MAX_ENTRY_BYTES + 1)})
    assert len(bomb) < 100_000  # a few kilobytes that would grow past the bound
    with pytest.raises(ea.ArchiveError, match="bytes uncompressed, over"):
        ea.zip_entries(bomb, "a")
    monkeypatch.setattr(ea, "MAX_TOTAL_BYTES", 10)
    with pytest.raises(ea.ArchiveError, match="uncompressed in all"):
        ea.zip_entries(_zip({"a": b"123456", "b": b"123456"}), "a")
    monkeypatch.setattr(ea, "MAX_ENTRIES", 1)
    with pytest.raises(ea.ArchiveError, match="entries, over the bound"):
        ea.zip_entries(_zip({"a": b"1", "b": b"2"}), "a")
    monkeypatch.setattr(ea, "MAX_ZIP_BYTES", 10)
    with pytest.raises(ea.ArchiveError, match="over the 10-byte bound"):
        ea.zip_entries(_zip({"a": b"1"}), "a")


def test_a_truncated_padded_prefixed_or_corrupt_zip_is_refused() -> None:
    good = _zip({"judged.json": b'{"a": 1}' * 50, "judged-0.txt": b"text" * 50})
    assert [e.path for e in ea.zip_entries(good, "a")] == ["judged-0.txt", "judged.json"]
    for cut in (len(good) - 1, len(good) - 22, len(good) // 2, 30, 4):
        with pytest.raises(ea.ArchiveError, match=r"unreadable ZIP|after the ZIP"):
            ea.zip_entries(good[:cut], "a")
    with pytest.raises(ea.ArchiveError, match="bytes after the ZIP"):
        ea.zip_entries(good + b"\0", "a")
    with pytest.raises(ea.ArchiveError, match="no local file header"):
        ea.zip_entries(b"MZ" + good, "a")
    with pytest.raises(ea.ArchiveError, match="no local file header"):
        ea.zip_entries(b"", "a")
    damaged = bytearray(good)
    damaged[30 + len("judged.json") + 2] ^= 0xFF  # inside the first entry's deflated data
    with pytest.raises(ea.ArchiveError):
        ea.zip_entries(bytes(damaged), "a")
    empty = io.BytesIO()
    with zipfile.ZipFile(empty, "w"):
        pass
    with pytest.raises(ea.ArchiveError, match="no local file header"):
        ea.zip_entries(empty.getvalue(), "a")
    # The same empty directory behind a forged local header: still no file.
    disguised = b"PK\x03\x04" + bytes(26) + empty.getvalue()
    with pytest.raises(ea.ArchiveError, match="holds no file"):
        ea.zip_entries(disguised, "a")


def test_an_encrypted_or_exotically_compressed_entry_is_refused() -> None:
    plain = bytearray(_zip({"judged.json": b"{}"}))
    central = plain.index(b"PK\x01\x02")
    plain[6] |= 0x1  # the local header's general purpose flags
    plain[central + 8] |= 0x1  # and the central directory's
    with pytest.raises(ea.ArchiveError, match="is encrypted"):
        ea.zip_entries(bytes(plain), "a")
    out = io.BytesIO()
    with zipfile.ZipFile(out, "w", zipfile.ZIP_BZIP2) as archive:
        archive.writestr("judged.json", b"{}")
    with pytest.raises(ea.ArchiveError, match="uses compression 12"):
        ea.zip_entries(out.getvalue(), "a")


def test_an_unsafe_artifact_name_from_github_is_refused(
    tmp_path: Path, bundles: dict[str, bytes]
) -> None:
    scenario = _m5_scenario(bundles)
    scenario.add("../../escape", _zip({"a": b"x"}))
    with pytest.raises(ea.ArchiveError, match="not a safe flat file name"):
        _capture(scenario, tmp_path)


def test_an_unsafe_zip_from_github_is_refused_never_archived(
    tmp_path: Path, bundles: dict[str, bytes]
) -> None:
    scenario = _m5_scenario(bundles)
    scenario.add("eval-results", _zip_pairs([("../results.jsonl", b"{}")]))
    with pytest.raises(ea.ArchiveError, match="not a safe flat file name"):
        _capture(scenario, tmp_path)
    assert not (tmp_path / "runs" / f"{M5_RUN}-a1").exists()


# --- offline use: inventory, inspection, restore ----------------------------------------


@pytest.mark.usefixtures("no_network")
def test_verify_inventory_inspect_and_restore_never_use_the_network(
    m5_archive: Path, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert ea.main(["verify", str(m5_archive), "--strict"]) == 0
    assert "integrity: OK" in capsys.readouterr().out
    root = m5_archive.parent.parent
    assert ea.main(["inventory", "--archive-root", str(root), "--verify"]) == 0
    assert "COMPLETE 14/14" in capsys.readouterr().out
    assert ea.main(["inspect", str(m5_archive)]) == 0
    assert "m5e-evidence-evals: bundle.json" in capsys.readouterr().out
    assert ea.main(["inspect", str(m5_archive), "--entry", "m5e-evidence-evals/bundle.json"]) == 0
    assert '"job": "evals"' in capsys.readouterr().out
    assert ea.main(["restore", str(m5_archive), "--to", str(tmp_path / "restored")]) == 0


def test_inventory_reports_backups_and_strangers(m5_archive: Path, tmp_path: Path) -> None:
    root = m5_archive.parent.parent
    backup = tmp_path / "backup"
    shutil.copytree(root, backup)
    (root / "runs" / "notes").mkdir()
    lines = ea.inventory(root, deep=False, backup_root=backup)
    assert "backup present, same manifest digest" in lines[1]
    assert "integrity not verified here" in lines[1]
    assert "GitHub's copy expires 2026-11-21T12:10:00Z" in lines[1]
    assert lines[2] == "  notes: not an archive"
    copied = backup / "runs" / m5_archive.name / "manifest.sha256"
    copied.write_text("f" * 64 + "  manifest.json\n", encoding="ascii")
    assert "backup DIFFERS" in ea.inventory(root, deep=False, backup_root=backup)[1]
    shutil.rmtree(backup / "runs" / m5_archive.name)
    assert "backup MISSING" in ea.inventory(root, deep=True, backup_root=backup)[1]
    (m5_archive / "manifest.sha256").write_text("0" * 64 + "  manifest.json\n", encoding="ascii")
    lines = ea.inventory(root, deep=True, backup_root=None)
    assert "integrity FAILED" in lines[1]
    assert ea.main(["inventory", "--archive-root", str(root), "--verify"]) == 1
    with pytest.raises(ea.ArchiveError, match="no runs/ directory"):
        ea.inventory(tmp_path / "nothing", deep=False, backup_root=None)


def test_a_restore_is_read_only_new_and_labelled(m5_archive: Path, tmp_path: Path) -> None:
    destination = ea.restore(m5_archive, tmp_path / "restored")
    names = sorted(p.name for p in destination.iterdir())
    assert names == sorted([*dw_artifacts(), "HISTORICAL-OFFLINE.txt", "manifest.json"])
    bundle = destination / "m5e-evidence-evals" / "bundle.json"
    assert stat.S_IMODE(bundle.stat().st_mode) & 0o222 == 0
    notice = (destination / "HISTORICAL-OFFLINE.txt").read_text(encoding="utf-8")
    assert notice.startswith("HISTORICAL / OFFLINE") and M5_RUN in notice
    with pytest.raises(ea.ArchiveError, match="already exists: a restore never writes into it"):
        ea.restore(m5_archive, destination)
    occupied = tmp_path / "workspace"
    occupied.mkdir()
    (occupied / "keep.txt").write_text("mine", encoding="utf-8")
    with pytest.raises(ea.ArchiveError, match="already exists"):
        ea.restore(m5_archive, occupied)
    assert (occupied / "keep.txt").read_text(encoding="utf-8") == "mine"


def test_an_archive_this_process_cannot_read_is_a_problem_not_a_crash(
    m5_archive: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """An archive made from an elevated shell can be unreadable to the same
    user unelevated: verify, inventory and the command line say so."""
    real = Path.iterdir

    def denied(self: Path) -> Iterator[Path]:
        if self == m5_archive:
            raise PermissionError(13, "Access is denied")
        return real(self)

    monkeypatch.setattr(Path, "iterdir", denied)
    result = ea.verify_archive(m5_archive)
    assert result.manifest is None
    assert result.problems == [f"{m5_archive} is unreadable to this process: Access is denied"]
    assert ea.main(["verify", str(m5_archive)]) == 1
    said = capsys.readouterr()
    assert "integrity: FAILED" in said.out and "Traceback" not in said.err
    lines = ea.inventory(m5_archive.parent.parent, deep=True, backup_root=None)
    assert "integrity FAILED (1)" in lines[1]


def test_an_archive_takes_its_roots_permissions_not_a_private_temporary_directorys(
    tmp_path: Path, bundles: dict[str, bytes]
) -> None:
    """Made as `mkdir` makes a directory -- never `tempfile.mkdtemp`, whose
    directory is 0700 on POSIX and private by ACL on Windows."""
    archive = _capture(_m5_scenario(bundles), tmp_path / "root")
    _ok(archive)
    sibling = tmp_path / "root" / "runs" / "a-plain-directory"
    sibling.mkdir()
    assert stat.S_IMODE(archive.stat().st_mode) == stat.S_IMODE(sibling.stat().st_mode)
    restored = ea.restore(archive, tmp_path / "restored")
    assert stat.S_IMODE(restored.stat().st_mode) == stat.S_IMODE(sibling.stat().st_mode)


def test_a_corrupted_archive_is_neither_restored_nor_inspected(
    m5_archive: Path, tmp_path: Path
) -> None:
    path = m5_archive / "artifacts" / "m5e-evidence-evals.zip"
    path.write_bytes(path.read_bytes()[:-5])
    with pytest.raises(ea.ArchiveError, match="did not verify"):
        ea.restore(m5_archive, tmp_path / "restored")
    assert not (tmp_path / "restored").exists()
    with pytest.raises(ea.ArchiveError, match="did not verify"):
        ea.inspect_entry(m5_archive, "m5e-evidence-evals/bundle.json")


def dw_artifacts() -> list[str]:
    return [f"m5e-evidence-{job}" for job in dw.M5E_GATE_TASKS.values()]


# --- an archive never stands in for a current run --------------------------------------


def test_restored_bundles_never_pass_another_runs_gate(m5_archive: Path, tmp_path: Path) -> None:
    """Restored where a later run's M5 gate reads, the archived bundles are
    refused: each is of another run, and the restore's own notice and
    manifest are no bundle of the gate."""
    restored = ea.restore(m5_archive, tmp_path / "m5e-gate")
    later = {
        **HOSTED,
        "GITHUB_JOB": dw.M5E_GATE_JOB,
        "GITHUB_RUN_ID": "43999999999",
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_SHA": OTHER_SHA,
    }
    with pytest.raises(dw.TaskError) as refused:
        dw.m5e_gate_verdict(later, restored, REPO_ROOT)
    said = str(refused.value)
    assert "not this run's" in said
    assert "bundle(s) no task of the gate uploads" in said
    # Its bundles alone, in the right layout, are still another run's.
    alone = tmp_path / "alone"
    alone.mkdir()
    for name in dw_artifacts():
        shutil.copytree(restored / name, alone / name)
    with pytest.raises(dw.TaskError, match="not this run's"):
        dw.m5e_gate_verdict(later, alone, REPO_ROOT)


def test_a_restore_never_lands_where_ci_reads(m5_archive: Path) -> None:
    for inside in (REPO_ROOT / "target" / "m5e-gate", REPO_ROOT / "target" / "restored"):
        with pytest.raises(ea.ArchiveError, match="is inside the repository"):
            ea.restore(m5_archive, inside)
        assert not inside.exists() or inside.name == "m5e-gate"


def test_ci_never_runs_the_archive_tool() -> None:
    """The archive is the owner's, outside CI: no workflow names the tool, and
    the M5 gate still downloads only its own run's bundles."""
    workflows = REPO_ROOT / ".github" / "workflows"
    for path in sorted(workflows.glob("*.yml")):
        text = path.read_text(encoding="utf-8")
        assert "evidence_archive" not in text, path.name
        assert "run-id:" not in text, path.name
    makefile = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
    assert "evidence_archive" not in makefile


def test_the_m5_gate_and_fuzz_judges_are_used_unchanged() -> None:
    """Every archived bundle goes through `dw._gate_bundle` and every record
    through `dw.fuzz_verdict`: the archive adds no judge of its own."""
    import inspect

    source = inspect.getsource(ea)
    assert "dw._gate_bundle(directory, task, (run_id, attempt, sha))" in source
    assert 'dw.fuzz_verdict(target, record, step or "", environ)' in source
    assert "def m5e_gate_verdict" not in source and "def fuzz_verdict" not in source


def test_a_replayed_gate_is_labelled_historical(
    m5_archive: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[tuple[Mapping[str, str], list[str]]] = []

    def gate(environ: Mapping[str, str], root: Path, _repo: Path) -> tuple[list[str], list[str]]:
        seen.append((dict(environ), sorted(p.name for p in root.iterdir())))
        return [f"{dw._INVENTORY_VERDICT}: 14 bundles"], []

    monkeypatch.setattr(dw, "m5e_gate_verdict", gate)
    lines = ea.replay_gate(_ok(m5_archive))
    assert lines[0].startswith("HISTORICAL / OFFLINE replay") and "never current" in lines[0]
    environ, present = seen[0]
    assert (environ["GITHUB_RUN_ID"], environ["GITHUB_SHA"]) == (M5_RUN, SHA)
    assert present == sorted(dw_artifacts())

    def refuse(*_arguments: object) -> tuple[list[str], list[str]]:
        raise dw.TaskError("M5 gate: 1 problem(s): a case no bundle judged")

    monkeypatch.setattr(dw, "m5e_gate_verdict", refuse)
    assert ea.replay_gate(_ok(m5_archive))[-1].startswith("replayed gate: REFUSED")


def test_the_real_gate_replays_an_archive_of_its_own_tables(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With a gate of one attributed task, replayed over an archive whose
    bundle passes it: the replay is the gate's own verdict."""
    monkeypatch.setattr(dw, "M5E_GATE_TASKS", {"sandbox-restart-evidence": "sandbox-restart"})
    monkeypatch.setattr(
        dw, "M5E_GATE_JUDGEMENTS", {"sandbox-restart-evidence": (("attributed", "RESTART_CASES"),)}
    )
    monkeypatch.setattr(dw, "ATTRIBUTED_CASES", frozenset(dw.RESTART_CASES))
    monkeypatch.setattr(dw, "M5E_NOT_YET_REQUIRED", ())
    monkeypatch.setitem(ea.M5_CONTRACTS, 1, (("sandbox-restart-evidence", "sandbox-restart"),))
    lines = []
    for suite, case in dw.RESTART_CASES:
        record: dict[str, object] = {"suite": suite, "case": case, "outcome": "ok"}
        contract = dw.attribution(suite, case)
        if contract is not None:
            level, mechanisms = contract
            record.update(level=level, enforcement=sorted(mechanisms)[0])
        lines.append(dw.SANDBOX_EVIDENCE_PREFIX + json.dumps(record))
    kept = tmp_path / "kept"
    directory = dw.save_judged_evidence(
        "sandbox-restart-evidence",
        kept,
        [("attributed", "RESTART_CASES", dw.SANDBOX_EVIDENCE_PREFIX, "\n".join(lines))],
        [CENSUS],
    )
    environ = {
        **HOSTED,
        "GITHUB_JOB": "sandbox-restart",
        "GITHUB_RUN_ID": M5_RUN,
        "GITHUB_RUN_ATTEMPT": "1",
        "GITHUB_SHA": SHA,
    }
    record_ = dw.m5e_bundle_record(environ, kept)
    (directory / "bundle.json").write_text(json.dumps(record_), encoding="utf-8")
    scenario = Scenario(M5_RUN, ".github/workflows/ci.yml", "push")
    scenario.jobs.append(_job(1, "sandbox-restart (make sandbox-restart-evidence)", M5_RUN, []))
    files = {p.name: p.read_bytes() for p in sorted(directory.iterdir())}
    scenario.add("m5e-evidence-sandbox-restart", _zip(files))
    archive = _capture(scenario, tmp_path / "root", strict=True)
    lines = ea.replay_gate(_ok(archive))
    assert any(dw._INVENTORY_VERDICT in line for line in lines), lines
    assert "attributed inventory: 7 of 7 cases" in "\n".join(lines)


def test_the_guide_documents_every_command_and_limit() -> None:
    guide = (REPO_ROOT / "docs" / "EVIDENCE_ARCHIVE.md").read_text(encoding="utf-8")
    for needed in (
        "scripts/evidence_archive.py capture",
        "scripts/evidence_archive.py verify",
        "scripts/evidence_archive.py inventory",
        "scripts/evidence_archive.py inspect",
        "scripts/evidence_archive.py restore",
        "--staged",
        "--token-env",
        "--replay-gate",
        "HISTORICAL / OFFLINE",
        "direwolf.evidence-archive",
        "authenticity",
        "tamper evidence",
        "timestamp",
    ):
        assert needed.lower() in guide.lower(), needed
    assert re.search(r"7 days", guide)
