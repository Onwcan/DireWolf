#!/usr/bin/env python3
"""DireWolf developer task runner.

This is not a build system. Every task below is a short, printed sequence of
calls to `uv`, `cargo` and the tools they install; nothing is hidden, and the
exact command that failed is on the line above the failure.

It exists because the repository must be checkable on Linux, macOS,
Windows/WSL2 *and* native Windows, and `make` is absent on the last of those.
The Makefile is the documented interface and delegates here; CI runs the same
tasks, so a green CI means the same commands passed that a contributor runs.

    python scripts/dw.py <task>        # equivalent to `make <task>`
    python scripts/dw.py --list

Only the standard library, and only syntax that runs on Python 3.9: this file
executes *before* the toolchain is set up, so it cannot assume the environment
it is about to create.
"""

from __future__ import annotations

import argparse
import base64
import fnmatch
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.parse
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# Minimum versions. Rust's real floor is `rust-toolchain.toml`, which rustup
# honours automatically; this is only for a clear message when rustup is absent.
MIN_PYTHON = (3, 12)
CARGO_TOOLS = {
    # tool name -> crate to install. cargo-deny is the single Rust supply-chain
    # gate: advisories, licences, bans, duplicates and sources. cargo-audit is
    # deliberately not used as well; it reads the same RustSec database.
    "cargo-deny": "cargo-deny",
}

# The four cargo-fuzz targets in fuzz/. Their bodies are shared with the stable
# harness in crates/dwk-proto/tests/fuzz_smoke.rs.
# The coverage-guided targets, grouped by the surface they attack, because the
# two surfaces take different seeds: DWKP vectors are the wrong corpus for a
# TOML parser and vice versa.
PROTO_FUZZ_TARGETS = (
    "frame_decoder",
    "dwkp_decode",
    "canonical_roundtrip",
    "envelope_version",
    # M5c (ADR-0050 §16): the URL canonicaliser and the `Location` resolver.
    "url_parse",
    "location_resolve",
)
POLICY_FUZZ_TARGETS = ("policy_loader", "policy_evaluate")
FUZZ_TARGETS = PROTO_FUZZ_TARGETS + POLICY_FUZZ_TARGETS
# libFuzzer needs nightly. Pinned by date so a fuzz run is repeatable and a bump
# is a reviewed change, exactly like rust-toolchain.toml.
FUZZ_NIGHTLY = "nightly-2026-09-01"
CARGO_FUZZ_VERSION = "0.13.2"

GREEN, RED, DIM, BOLD, OFF = "\033[32m", "\033[31m", "\033[2m", "\033[1m", "\033[0m"
if os.environ.get("NO_COLOR") or not sys.stdout.isatty():
    GREEN = RED = DIM = BOLD = OFF = ""


class TaskError(Exception):
    """A task failed; the message is what the contributor should do next."""


# --- running ---------------------------------------------------------------


def run(*command: str, cwd: Path | None = None) -> None:
    """Run a command, echoing it first. Raises TaskError on failure."""
    printable = " ".join(command)
    print(f"{DIM}$ {printable}{OFF}", flush=True)
    result = subprocess.run(list(command), cwd=str(cwd or ROOT), check=False)
    if result.returncode != 0:
        raise TaskError(f"`{printable}` failed with exit code {result.returncode}")


def uv(*args: str) -> None:
    run(_uv_bin(), *args)


def uvrun(module: str, *args: str) -> None:
    """Run a tool from the locked environment, so local == CI.

    Always `python -m <module>`, never the generated console-script `.exe`.
    The shim adds nothing, and on managed Windows machines an Application
    Control policy blocks a freshly created executable until it has been
    scanned -- which turns a fresh `uv sync` into an intermittent failure of
    whichever gate runs first. The module form has no such file to block.
    """
    run(_uv_bin(), "run", "--frozen", "python", "-m", module, *args)


def _uv_bin() -> str:
    found = shutil.which("uv")
    if found:
        return found
    raise TaskError(
        "uv is not installed.\n"
        "  Linux/macOS/WSL2:  curl -LsSf https://astral.sh/uv/install.sh | sh\n"
        "  or, in any Python: python -m pip install --user uv\n"
        "See CONTRIBUTING.md."
    )


# --- tasks -----------------------------------------------------------------


def task_preflight() -> None:
    """Verify the toolchain a contributor needs before anything is built."""
    problems = []

    if sys.version_info < MIN_PYTHON:
        want = f"{MIN_PYTHON[0]}.{MIN_PYTHON[1]}"
        have = f"{sys.version_info[0]}.{sys.version_info[1]}"
        problems.append(f"Python {want}+ is required; this interpreter is {have}.")
    for tool, hint in (
        ("git", "install git"),
        ("cargo", "install Rust via https://rustup.rs (rustup reads rust-toolchain.toml)"),
        ("rustup", "install Rust via https://rustup.rs"),
        ("uv", "python -m pip install --user uv, or https://docs.astral.sh/uv/"),
    ):
        if shutil.which(tool) is None:
            problems.append(f"`{tool}` is not on PATH: {hint}")

    print(f"{BOLD}platform{OFF}   {platform.system()} {platform.machine()} ({_platform_note()})")
    print(f"{BOLD}python{OFF}     {sys.version.split()[0]}  {sys.executable}")
    for tool in ("git", "cargo", "rustc", "uv"):
        path = shutil.which(tool)
        print(f"{BOLD}{tool:<10}{OFF} {_version_of(tool) if path else RED + 'MISSING' + OFF}")

    if problems:
        raise TaskError("\n  ".join(["missing prerequisites:", *problems]))


def task_tools() -> None:
    """Install the cargo-hosted tools the gates need. Idempotent."""
    for tool, crate in CARGO_TOOLS.items():
        if shutil.which(tool):
            print(f"{DIM}{tool} already installed{OFF}")
            continue
        print(
            f"{BOLD}installing {tool}{OFF} - compiled from source; "
            f"expect 2-5 minutes the first time, then never again"
        )
        run("cargo", "install", crate, "--locked")


def task_dev() -> None:
    """Establish or verify a usable development checkout. Idempotent."""
    task_preflight()
    uv("sync", "--all-packages")
    run("cargo", "build", "--workspace")
    try:
        task_tools()
    except TaskError as exc:
        # Setup is about getting you working; `make check` is the gate that is
        # strict. Some managed machines refuse to execute a freshly compiled
        # build script, and failing setup outright over a tool only one check
        # needs would be the wrong trade.
        print(f"{RED}warning: {exc}{OFF}", file=sys.stderr)
        print("`make security` will report the Rust half as not run until this is fixed.")
    task_arch()
    print()
    print(f"{GREEN}Development environment ready.{OFF}")
    print("  make check      every gate CI runs")
    print("  make test       Rust and Python tests")
    print("  make fmt        format Rust and Python")
    print("  make help       all tasks")
    print()
    print(f"{DIM}The binary: ./target/debug/direwolf --version{OFF}")


def task_fmt() -> None:
    """Format Rust and Python in place."""
    run("cargo", "fmt", "--all")
    uvrun("ruff", "format", ".")
    uvrun("ruff", "check", "--fix-only", ".")


def task_fmt_check() -> None:
    """Fail if anything is unformatted."""
    run("cargo", "fmt", "--all", "--check")
    uvrun("ruff", "format", "--check", ".")


def task_lint() -> None:
    """clippy with -D warnings, and ruff check."""
    run("cargo", "clippy", "--workspace", "--all-targets", "--", "-D", "warnings")
    uvrun("ruff", "check", ".")


def task_typecheck() -> None:
    """mypy --strict over every Python package."""
    uvrun(
        "mypy",
        "runtime/src",
        "tools/dwcheck/src",
        "evals/src",
        "runtime/tests",
        "evals/tests",
        "tests",
        "scripts",
    )


def task_test() -> None:
    """cargo test and pytest."""
    run("cargo", "test", "--workspace")
    uvrun("pytest")


def task_arch() -> None:
    """Architecture boundary checks. Hygiene, not containment.

    Two passes, because they are two different strengths of claim.

    `all` is every offline check: it reads source text and manifests, needs no
    toolchain, and its authority-closure rule (RS006) reads Cargo.lock -- which
    pins versions, not feature selections, and therefore OVER-approximates.

    `closure` is the exact one. It asks Cargo for the resolved graph and works
    out which optional dependencies a feature actually turns on, so the trusted
    computing base inventory describes what the binary links rather than what
    the lockfile mentions. It needs cargo, which is why it is separate -- and
    it runs here, inside `make check`, rather than being left to a reviewer.
    """
    uvrun("dwcheck", "--root", str(ROOT), "all")
    uvrun("dwcheck", "--root", str(ROOT), "closure")


# --- Accepted ADRs against the history that accepted them --------------------
#
# `dwcheck adr --adr-base <rev>` anchors every accepted ADR to the revision in
# which it became Accepted, as reachable from <rev> (checks_adr.py). Which <rev>
# is the gate: in a pull request the merge base with the target branch, on a
# push the previous tip of the branch (`github.event.before`) -- both outside
# the change being checked. Locally, and for a run with neither, HEAD.
#
# A push can replace the previous tip instead of building on it (a
# force-push): the old tip is then reachable from no ref, and a full-depth
# checkout -- which fetches refs -- does not contain it. On a hosted runner that
# exact commit is requested from origin and verified before anything is
# anchored to it; if origin does not serve it, the check fails. Nothing weaker
# is put in its place: not HEAD, not a merge base, not the digest manifest.

# A full commit identifier, as GitHub reports `github.event.before`.
_FULL_COMMIT = re.compile(r"[0-9a-f]{40}")
# What `github.event.before` is when the push created the branch: no commit.
_NO_COMMIT = "0" * 40
# A branch name as the workflow may pass it: no option, no revision syntax,
# no shell metacharacter. `git check-ref-format` is asked as well.
_BRANCH_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._/-]*")

GitRunner = Callable[..., subprocess.CompletedProcess[str]]


def _git(*args: str) -> subprocess.CompletedProcess[str]:
    """`git -C ROOT <args>`, captured; a non-zero exit is the caller's to judge.
    Fixed argv, no shell: every caller-supplied word is validated first."""
    return subprocess.run(
        ["git", "-C", str(ROOT), *args], capture_output=True, text=True, check=False
    )


def _is_commit(git: GitRunner, revision: str) -> bool:
    """Whether `revision` -- a full commit identifier -- names a commit object
    this clone holds: it resolves, as a commit, to exactly itself."""
    resolved = git("rev-parse", "--verify", "--quiet", f"{revision}^{{commit}}")
    return resolved.returncode == 0 and resolved.stdout.strip() == revision


def adr_history_anchor(base_ref: str, before: str, *, hosted: bool, git: GitRunner = _git) -> str:
    """The revision accepted ADRs are anchored to.

    `base_ref` is a pull request's target branch (`github.base_ref`), `before`
    a push's previous tip (`github.event.before`), `hosted` whether this is a
    GitHub-hosted run, the only place that may fetch. Raises TaskError -- and
    runs nothing -- for any input that is not what it claims to be, and for a
    previous tip that is not here and cannot be fetched and verified."""
    if base_ref:
        if (
            not _BRANCH_NAME.fullmatch(base_ref)
            or ".." in base_ref
            or git("check-ref-format", f"refs/heads/{base_ref}").returncode != 0
        ):
            raise TaskError(
                f"the pull request's base branch {base_ref!r} is not a branch name; "
                "nothing is anchored to it"
            )
        if hosted:
            fetched = git(
                "fetch",
                "--no-tags",
                "--quiet",
                "origin",
                f"+refs/heads/{base_ref}:refs/remotes/origin/{base_ref}",
            )
            if fetched.returncode != 0:
                raise TaskError(
                    f"could not fetch the base branch {base_ref!r}: {fetched.stderr.strip()}"
                )
        merged = git("merge-base", f"refs/remotes/origin/{base_ref}", "HEAD")
        base = merged.stdout.strip()
        if merged.returncode != 0 or not _FULL_COMMIT.fullmatch(base):
            raise TaskError(
                f"no merge base between origin/{base_ref} and HEAD: {merged.stderr.strip()}"
            )
        return base
    if before and before != _NO_COMMIT:
        if not _FULL_COMMIT.fullmatch(before):
            raise TaskError(
                f"the previous push's tip {before!r} is not a full commit identifier; "
                "nothing is anchored to it"
            )
        if _is_commit(git, before):
            return before
        if not hosted:
            raise TaskError(
                f"the previous push's tip {before} is not in this clone; fetch that commit "
                "and run again (only a hosted run fetches it by itself)"
            )
        print(
            f"the previous push's tip {before} is not in this checkout (a push replaced it); "
            "requesting exactly that commit from origin",
            flush=True,
        )
        fetched = git("fetch", "--no-tags", "--quiet", "origin", before)
        if fetched.returncode != 0 or not _is_commit(git, before):
            detail = fetched.stderr.strip() or "it did not resolve to itself afterwards"
            raise TaskError(
                f"cannot verify accepted ADRs against the history before this push: its "
                f"previous tip {before} (github.event.before) is not in this checkout and "
                f"origin did not serve it ({detail}). It is reachable from no branch -- the "
                "push replaced it -- and nothing weaker is put in its place: not HEAD, not a "
                "merge base, not docs/adr/accepted.sha256. In a clone that holds it, run "
                f"`uv run --frozen python -m dwcheck --adr-base {before} --require-adr-history "
                "adr`; a later push on top of this one is anchored to a tip that exists"
            )
        return before
    return "HEAD"


def task_adr_history() -> None:
    """Accepted ADRs against the history that accepted them (CI: merge base or previous tip).

    In CI the workflow passes the pull request's target branch as
    DW_ADR_BASE_REF and the push's previous tip as DW_ADR_BEFORE; with neither
    -- locally, a manual run, a push that created the branch -- the anchor is
    HEAD, as `make arch` uses. A history that cannot be read fails
    (`--require-adr-history`); it is never skipped.
    """
    base = adr_history_anchor(
        os.environ.get("DW_ADR_BASE_REF", ""),
        os.environ.get("DW_ADR_BEFORE", ""),
        hosted=os.environ.get("GITHUB_ACTIONS", "") == "true",
        git=_git,
    )
    print(f"anchoring accepted ADRs to {base}", flush=True)
    uvrun("dwcheck", "--adr-base", base, "--require-adr-history", "adr")


def task_schema() -> None:
    """Regenerate schemas/ from dwk-proto, then the Python bindings from schemas/."""
    # One direction only (ADR-0033): Rust types -> JSON Schema -> Python.
    run("cargo", "run", "--quiet", "--locked", "-p", "protogen", "--", "write")
    run(_uv_bin(), "run", "--frozen", "python", "scripts/gen_proto_python.py")


def task_schema_check() -> None:
    """Fail if schemas/, the operation inventory or the Python bindings are stale."""
    run("cargo", "run", "--quiet", "--locked", "-p", "protogen", "--", "check")
    run(_uv_bin(), "run", "--frozen", "python", "scripts/gen_proto_python.py", "--check")


def task_eval() -> None:
    """Run every evaluation suite and write JSONL results."""
    uvrun("direwolf_evals", "run")


def task_eval_check() -> None:
    """The eval merge gate: the deterministic subset, compared with the baseline.

    An eval this machine cannot exercise -- the DWKP server on macOS or
    Windows, a cross-uid property with no second identity -- is listed as NOT
    EXERCISED, never passed. Strict -- DW_EVAL_REQUIRE_EXERCISED=1, and always
    under GitHub Actions -- not exercising a gating eval fails the gate.

    Strict, it then reads the M5 suites' own verdicts in the results it wrote
    (`require_m5_eval_results`), which the M5 gate keeps from the `evals` job.
    """
    args = ["check"]
    strict = eval_gate_is_strict(os.environ)
    if strict:
        args.append("--require-exercised")
    uvrun("direwolf_evals", *args)
    if strict:
        try:
            results = EVAL_RESULTS.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise TaskError(f"the eval gate's results are unreadable: {exc}") from exc
        require_m5_eval_results(results, M5_EVAL_CASES)


def eval_gate_is_strict(environ: Mapping[str, str]) -> bool:
    """Whether "not exercised" fails the eval gate.

    Fail-closed in both directions a mistake could take. Under GitHub Actions
    the gate is strict whatever the environment says, so a job that loses its
    DW_EVAL_REQUIRE_EXERCISED line cannot turn a missing cross-uid run into a
    green check. And any value other than empty or "0" is strict, so a typo
    ("true", "yes") never quietly means lenient.
    """
    if environ.get("GITHUB_ACTIONS") == "true":
        return True
    return environ.get("DW_EVAL_REQUIRE_EXERCISED", "").strip() not in ("", "0")


def task_eval_one() -> None:
    """Re-run one eval by id, at its seed. ID=<eval id> [SEED=<n>]."""
    eval_id = os.environ.get("ID")
    if not eval_id:
        raise TaskError("set ID=<eval id>, e.g. `make eval-one ID=protocol-security/framing`")
    seed = os.environ.get("SEED")
    args = ["run", "--eval", eval_id, "--verbose"]
    if seed:
        args += ["--seed", seed]
    uvrun("direwolf_evals", *args)


def task_capability_evidence() -> None:
    """The 10^6 delegation-chain capability evidence campaign (CAPABILITIES.md section 3).

    Not part of `check`: it is evidence, produced deliberately, and a merge gate
    does not need a million chains to notice a regression -- the fast suite runs
    a thousand of them. Seed with DW_EVIDENCE_SEED to replay a run, and
    DW_EVIDENCE_CHAINS to shorten one while debugging.
    """
    run(
        "cargo",
        "test",
        "--locked",
        "--release",
        "-p",
        "dwkd-authority",
        "--test",
        "evidence",
        "--",
        "--ignored",
        "--nocapture",
    )


def task_fuzz_smoke() -> None:
    """Type-check the cargo-fuzz targets, then stable mutation fuzzing (not coverage-guided)."""
    # The fuzz crate is outside the workspace; building it without libFuzzer
    # proves the targets still compile on stable with no C++ toolchain.
    run(
        "cargo",
        "check",
        "--locked",
        "--manifest-path",
        "fuzz/Cargo.toml",
        "--no-default-features",
        "--bins",
    )
    # Two hostile-input surfaces, reported separately: the DWKP decoder, which
    # reads frames from the least trusted process in the system, and the M3c
    # policy loader, which reads operator TOML through the first third-party
    # parser the authority links.
    for crate in ("dwk-proto", "dwkd-authority"):
        run(
            "cargo",
            "test",
            "--release",
            "--locked",
            "-p",
            crate,
            "--test",
            "fuzz_smoke",
            "--",
            "--nocapture",
        )


def task_policy_benchmark() -> None:
    """The 300-rule policy evaluation benchmark (ROADMAP M3: p99 < 200us).

    Not part of `check`: it is evidence, produced deliberately, and a timing
    threshold on a shared CI runner is a flaky gate rather than a security
    control. Release mode, because a debug build measures the borrow checker
    rather than the evaluator -- the harness says so and declines to report a
    verdict from one.

    Evaluation only: the policy is compiled before the clock starts, and load
    time is reported separately rather than mixed into the p99.
    """
    run(
        "cargo",
        "test",
        "--locked",
        "--release",
        "-p",
        "dwkd-authority",
        "--lib",
        "policy::benchmark",
        "--",
        "--ignored",
        "--nocapture",
    )


STATE_SUITES = (
    "state_store",
    "state_lease",
    "state_admission",
    "state_query",
    "state_audit",
    "state_crash",
    "state_concurrency",
    "state_hostile",
    "state_wire",
    "state_restart",
)


def task_authority_state_evidence() -> None:
    """M3d's durable-state evidence, on real files (ADR-0039).

    Every state suite -- store creation and refusal, SQLite corruption
    quarantine, leases and epoch fencing, admission and idempotency, both
    gates, the audit chain and its verifier, crash windows A-G in process and
    in a killed child process, and many-connection contention -- then the
    diagnostic latency of each audited operation, then the measured authority
    closure. Exits non-zero on any invariant failure. Not part of `check`
    only because the latency figures are evidence, not a gate: the suites
    themselves run in `cargo test` like everything else.
    """
    suites: list[str] = []
    for suite in STATE_SUITES:
        suites += ["--test", suite]
    run("cargo", "test", "--locked", "-p", "dwkd-authority", *suites)
    run(
        "cargo",
        "test",
        "--locked",
        "--release",
        "-p",
        "dwkd-authority",
        "--test",
        "state_probe",
        "state_operation_latency",
        "--",
        "--ignored",
        "--nocapture",
    )
    uvrun("dwcheck", "closure", "--report")


FS_EVIDENCE_PREFIX = "FS-EVIDENCE "
# Every category the M4a resolver is measured against (ADR-0042 section 14). A
# category with no EXERCISED case fails the task: a green run must have raced,
# followed, crossed and aliased something, not merely compiled.
FS_EVIDENCE_CATEGORIES = (
    "normal",
    "platform",
    "traversal",
    "symlink",
    "magic-link",
    "mount-crossing",
    "hardlink",
    "unicode",
    "resource-kind",
    "root-replacement",
    "toctou",
    "leak",
    "performance",
    "state",
    "admission",
)
# The race campaigns, by name: libtest exits 0 when a filter selects nothing,
# so a renamed test would otherwise vanish from the evidence silently.
FS_TOCTOU_CASES = (
    "file-symlink-exchange",
    "directory-symlink-exchange",
    "parent-rename",
    "parent-moved-out-and-back",
    "leaf-replaced",
    "root-path-exchange",
)
# The two parent campaigns must show the chain re-verification firing in their
# own count (ADR-0042 section 14): at least one RACE each. Each attacker makes
# its first move inside the check's window, so one is guaranteed; the free
# moves may add more, as the scheduler allows.
FS_RACE_REQUIRED_CASES = ("parent-rename", "parent-moved-out-and-back")
FS_RACE_COUNT = re.compile(r"-race-(\d+)$")
# Further evidence of the chain re-verification firing, required by name and
# outcome in addition to -- never instead of -- the parent campaigns' own RACE
# counts. The first changes the tree under a chain it opened; the other two
# move a parent at a fixed point of the production walk, just before the
# walk's chain check, and require RACE at the parent's depth.
FS_CHAIN_WITNESS_CASES = (
    "chain-reverified-after-change",
    "parent-renamed-before-chain-check",
    "parent-moved-out-before-chain-check",
)
FS_CHAIN_WITNESS_OUTCOME = "refused:RACE"
# M4b: admission resolves every new concrete fs.read declaration through the
# same resolver (ADR-0043 section 8). Each named case must report.
FS_ADMISSION_CASES = (
    "grant-through-resolver",
    "missing-concrete-scope",
    "root-replaced",
    "workspace-unbound",
    "non-nfc-declaration",
    "stored-grant-rehydrated",
)
# Cases no ordinary machine can produce: a bind mount or a casefold filesystem
# needs privileges, a cross-device hard link is impossible by construction, and
# an inode recycled with the same birth time depends on the allocator. They are
# printed as NOT EXERCISED, never counted. Any OTHER case not exercised fails.
FS_ENVIRONMENTAL = (
    "bind-mount-inside-workspace",
    "casefold-filesystem",
    "cross-device-link",
    "recreated-same-inode",
)


def task_filesystem_canonicalization_evidence() -> None:
    """M4a's canonical filesystem evidence (ADR-0042), on real directories.

    The production resolver against symlinks, magic links, mount points, hard
    links, NFC/NFD aliases, special files and a replaced root; the TOCTOU race
    campaigns (an attacker thread exchanging names while the resolver walks);
    the descriptor-leak and cost measurements; then the state layer binding a
    root to a workspace, resolving for a run, and migrating an M3 store; then
    admission resolving every new concrete fs.read declaration (M4b). Each
    case prints one `FS-EVIDENCE` line after its assertions held; this task
    requires every category, every race campaign with zero escapes, a RACE in
    each parent campaign's own count, every chain re-verification witness
    refusing as RACE, and lists what the machine could not exercise. Linux
    only: the resolver is openat2.
    """
    if not sys.platform.startswith("linux"):
        raise TaskError(
            "NOT EXERCISED: the canonical resolver is Linux-only (openat2, ADR-0042); "
            "on this platform it refuses every root as UNSUPPORTED_PLATFORM. Use WSL2 on Windows"
        )
    resolver = run_captured(
        "cargo",
        "test",
        "--locked",
        "--release",
        "-p",
        "dwkd-authority",
        "--lib",
        "resource::fs::",
        "--",
        "--nocapture",
    )
    state = run_captured(
        "cargo",
        "test",
        "--locked",
        "-p",
        "dwkd-authority",
        "--test",
        "resource_workspace",
        "--test",
        "admission_fs",
        "--",
        "--nocapture",
    )
    # Joined on a line break: an output that does not end in one must not
    # merge its last evidence line with the next output's first.
    require_filesystem_evidence(f"{resolver}\n{state}")
    uvrun("dwcheck", "closure", "--report")


def require_filesystem_evidence(output: str) -> None:
    """Check the `FS-EVIDENCE` lines a run printed; raise TaskError if short."""
    exercised: dict[str, list[tuple[str, str, int]]] = {}
    unexercised: list[tuple[str, str, str]] = []
    for line in output.splitlines():
        at = line.find(FS_EVIDENCE_PREFIX)
        if at < 0:
            continue
        try:
            record = json.loads(line[at + len(FS_EVIDENCE_PREFIX) :])
        except json.JSONDecodeError as exc:
            raise TaskError(f"unreadable evidence line: {line[:200]}") from exc
        if not isinstance(record, dict) or not isinstance(record.get("count"), int):
            raise TaskError(f"malformed evidence line: {line[:200]}")
        category, case, outcome = (
            str(record.get("category")),
            str(record.get("case")),
            str(record.get("outcome")),
        )
        if outcome.startswith("not-exercised"):
            unexercised.append((category, case, outcome))
        else:
            exercised.setdefault(category, []).append((case, outcome, record["count"]))

    problems: list[str] = []
    for category in FS_EVIDENCE_CATEGORIES:
        if not exercised.get(category):
            problems.append(f"category `{category}` has no exercised case")
    races = {
        case: (outcome, count)
        for case, outcome, count in exercised.get("toctou", [])
        if case in FS_TOCTOU_CASES
    }
    for case in FS_TOCTOU_CASES:
        reported = races.get(case)
        if reported is None:
            problems.append(f"race campaign `{case}` did not report")
        elif not reported[0].startswith("escaped-0-unexpected-0-"):
            problems.append(f"race campaign `{case}`: {reported[0]}")
    for case in FS_RACE_REQUIRED_CASES:
        reported = races.get(case)
        caught = FS_RACE_COUNT.search(reported[0]) if reported else None
        if reported is not None and (caught is None or int(caught.group(1)) < 1):
            problems.append(f"race campaign `{case}` caught no RACE: {reported[0]}")
    witnessed = {
        case: (outcome, count)
        for case, outcome, count in exercised.get("toctou", [])
        if case in FS_CHAIN_WITNESS_CASES
    }
    for case in FS_CHAIN_WITNESS_CASES:
        reported = witnessed.get(case)
        if reported is None:
            problems.append(f"chain witness `{case}` did not report")
        elif reported[0] != FS_CHAIN_WITNESS_OUTCOME or reported[1] < 1:
            problems.append(f"chain witness `{case}`: {reported[0]} x{reported[1]}")
    for category, case, outcome in unexercised:
        if case not in FS_ENVIRONMENTAL:
            problems.append(f"{category}/{case} was not exercised ({outcome})")
    admitted = {case for case, _, _ in exercised.get("admission", [])}
    for case in FS_ADMISSION_CASES:
        if case not in admitted:
            problems.append(f"admission case `{case}` did not report")

    for category in FS_EVIDENCE_CATEGORIES:
        cases = exercised.get(category, [])
        total = sum(count for _, _, count in cases)
        print(f"  {category:<17} {len(cases):>3} cases  {total:>7} observations")
    raced = sum(count for _, count in races.values())
    print(f"  race campaigns: {len(races)}, {raced} raced resolutions, 0 escapes required")
    print(f"  chain witnesses: {len(witnessed)} of {len(FS_CHAIN_WITNESS_CASES)}, RACE required")
    for category, case, outcome in unexercised:
        print(f"  NOT EXERCISED  {category}/{case}: {outcome}")
    if problems:
        raise TaskError("filesystem evidence incomplete:\n  " + "\n  ".join(problems))
    print(f"{GREEN}filesystem canonicalization evidence: complete{OFF}")


TRANSPORT_SUITES = ("transport_server", "transport_hostile", "transport_stress")

# The cross-uid suite: both tests are `#[ignore]`d, so that a plain `cargo test`
# stays runnable on a one-user machine, and this task selects them BY NAME.
# `--ignored` with a filter that matched nothing would be a green "0 passed";
# `_require_foreign_evidence` makes that a failure.
FOREIGN_TESTS = (
    "linux::a_real_foreign_uid_is_refused_by_the_identity_the_kernel_reports",
    "linux::a_foreign_uid_cannot_remove_replace_or_shadow_the_socket",
)
# Every case those tests report, one evidence line each, printed only after
# the case's assertions held. The same set as the peer-credential-check eval's.
FOREIGN_CASES = (
    "foreign-uid-valid-handshake",
    "foreign-uid-malformed-payload",
    "foreign-uid-flood",
    "foreign-uid-impersonation",
)


def task_authority_transport_evidence() -> None:
    """M3e's real-process evidence (ADR-0041): the released `dwkd-authority`
    binary, a real Unix-domain socket and a client in another process.

    With DW_PEER_AS set, the second identity is proven first -- by numbers, see
    `second_identity` -- so a broken prerequisite fails before anything else
    runs. Then the same-uid suites (the full request path, holders, fencing,
    restart after SIGKILL, a poisoned store, socket-name attacks, the hostile
    client, resource pressure); then the cross-uid suite, selected by name and
    required to report every case, with a client running as that user through
    `sudo -n -u`; then the measured authority closure. Linux only: that is
    where the server runs.

    Without a second identity the cross-uid half is NOT EXERCISED and this task
    fails after running everything else -- it never reports a pass it did not
    earn. CI's Linux job provides one.
    """
    if not sys.platform.startswith("linux"):
        raise TaskError(
            "NOT EXERCISED: the DWKP server runs only on Linux (ADR-0041); use WSL2 on Windows"
        )
    user = os.environ.get("DW_PEER_AS", "").strip()
    if user:
        second_identity("DW_PEER_AS")
    suites: list[str] = []
    for suite in TRANSPORT_SUITES:
        suites += ["--test", suite]
    run("cargo", "test", "--locked", "-p", "dwkd-authority", *suites, "--", "--nocapture")
    if user:
        output = run_captured(
            "cargo",
            "test",
            "--locked",
            "-p",
            "dwkd-authority",
            "--test",
            "transport_foreign",
            "--",
            "--ignored",
            "--exact",
            "--nocapture",
            *FOREIGN_TESTS,
        )
        require_foreign_evidence(output)
    uvrun("dwcheck", "closure", "--report")
    if not user:
        raise TaskError(
            "NOT EXERCISED: the cross-uid half needs a second identity. Set DW_PEER_AS to a "
            "user `sudo -n -u` can switch to (CI uses `nobody`); every same-uid suite above ran"
        )


def second_identity(variable: str) -> tuple[str, int, int]:
    """The user `variable` names, proven to be a second, ordinary identity.

    By numbers, not names: `sudo -n -u <user> id -u` must start a real process
    as that user; the uid that process reports must differ from this process's
    effective uid, and must not be root, which is outside the threat model.
    Prints both uids, for the CI log.

    Returns (user, this uid, the second uid); raises TaskError otherwise. The
    harness switches users; the authority never does.
    """
    user = os.environ.get(variable, "").strip()
    if not user:
        raise TaskError(f"NOT EXERCISED: {variable} names no second identity")
    if not sys.platform.startswith("linux") or shutil.which("sudo") is None:
        raise TaskError(f"NOT EXERCISED: {variable}={user} needs Linux and `sudo`")
    own = os.geteuid()
    try:
        switched = subprocess.run(
            ["sudo", "-n", "-u", user, "id", "-u"],
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise TaskError(f"NOT EXERCISED: `sudo -n -u {user}` could not run: {exc}") from exc
    reported = switched.stdout.strip()
    if switched.returncode != 0 or not reported.isdigit():
        raise TaskError(
            f"NOT EXERCISED: `sudo -n -u {user} id -u` did not start a process as {user} "
            f"(exit {switched.returncode}): {switched.stderr.strip()[:300]}"
        )
    peer = int(reported)
    print(
        f"second identity: this process runs as uid {own}; {variable}={user} runs as uid {peer}",
        flush=True,
    )
    if peer == own:
        raise TaskError(
            f"{variable}={user} runs as uid {peer}, this process's own: one identity, not two"
        )
    if peer == 0:
        raise TaskError(
            f"{variable}={user} is root, outside the threat model; the hostile peer must be an "
            "ordinary local user such as `nobody`"
        )
    return user, own, peer


def fresh_session_keyring() -> Callable[[], None]:
    """What a child runs before exec to join a new, empty session keyring
    (Linux): afterwards it possesses no keyring it did not create -- not the
    user keyring -- exactly as a service with a private keyring, or a CI
    runner, does not. The secret suites then observe what the authority
    observes (`secret/backend/keychain.rs`, the provisioning contract).
    """
    import ctypes

    numbers = {"x86_64": 250, "aarch64": 219}
    number = numbers.get(platform.machine())
    if number is None:
        raise TaskError(f"no keyctl syscall number for {platform.machine()}")
    keyctl_join_session_keyring = 1

    def join() -> None:
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.syscall(number, keyctl_join_session_keyring, None) < 0:
            raise OSError(ctypes.get_errno(), "keyctl(KEYCTL_JOIN_SESSION_KEYRING)")

    return join


def run_captured(*command: str, fresh_keyring: bool = False) -> str:
    """`run`, also returning everything the command printed -- stdout and
    stderr, interleaved as it happened -- which is echoed as it arrives.
    With `fresh_keyring`, the command runs in a new, empty session keyring
    (`fresh_session_keyring`)."""
    printable = " ".join(command)
    print(f"{DIM}$ {printable}{OFF}", flush=True)
    lines: list[str] = []
    with subprocess.Popen(
        list(command),
        cwd=str(ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        errors="replace",
        preexec_fn=fresh_session_keyring() if fresh_keyring else None,
    ) as process:
        if process.stdout is None:
            raise TaskError(f"`{printable}`: no output stream")
        for line in process.stdout:
            print(line, end="", flush=True)
            lines.append(line)
        returncode = process.wait()
    if returncode != 0:
        raise TaskError(f"`{printable}` failed with exit code {returncode}")
    return "".join(lines)


def require_foreign_evidence(output: str) -> None:
    """The cross-uid suite counts only if both tests ran and every case reported.

    libtest exits 0 when a filter selects nothing, so a renamed test, a changed
    `cfg` or a lost `--ignored` would otherwise be a green run that proved
    nothing. Each case's evidence line is printed after its assertions held.
    """
    summaries = [line for line in output.splitlines() if line.startswith("test result: ")]
    expected = f"test result: ok. {len(FOREIGN_TESTS)} passed; 0 failed; 0 ignored"
    if len(summaries) != 1 or not summaries[0].startswith(expected):
        raise TaskError(
            f"the cross-uid suite did not run both of its tests: expected `{expected}`, "
            f"got {summaries or 'no summary'}"
        )
    reported: set[str] = set()
    for line in output.splitlines():
        at = line.find(EVIDENCE_PREFIX)
        if at < 0:
            continue
        try:
            evidence = json.loads(line[at + len(EVIDENCE_PREFIX) :])
        except json.JSONDecodeError as exc:
            raise TaskError(f"unreadable evidence line: {line[:200]}") from exc
        if isinstance(evidence, dict) and evidence.get("contained") is True:
            reported.add(str(evidence.get("case")))
    missing = sorted(set(FOREIGN_CASES) - reported)
    if missing:
        raise TaskError(f"the cross-uid suite did not report: {', '.join(missing)}")
    print(f"cross-uid evidence: {len(FOREIGN_TESTS)} tests, {len(FOREIGN_CASES)} cases contained")


EVIDENCE_PREFIX = "DWKP-EVIDENCE "

BROKER_EVIDENCE_PREFIX = "BROKER-EVIDENCE "

# M4b's same-identity suites: the released authority and broker binaries as
# real processes, the private channel, and a scripted hostile peer on each end.
# Every (suite, case) below is printed by exactly one test, after its
# assertions held; a missing one fails the task.
BROKER_CASES = (
    ("broker-fs-read", "fs-read-end-to-end"),
    ("broker-fs-read", "max-bytes-before-effect"),
    ("broker-fs-read", "zero-broker-contact-for-non-effects"),
    ("broker-fs-read", "shipped-pack-denies-unevaluable"),
    ("broker-fs-read", "preview-zero-effect-and-differential"),
    ("broker-fs-read", "broker-down-and-restart"),
    ("broker-fs-read", "no-broker-configured"),
    ("broker-fs-read", "authority-verifies-broker-uid"),
    ("broker-fs-read", "largest-result-one-frame"),
    ("broker-fs-read", "cross-process-toctou"),
    ("broker-fs-read", "authority-restart"),
    ("broker-fs-read", "public-protocol-hostile"),
    ("broker-fs-read", "shared-broker-uid-refused"),
    ("broker-fs-read", "require-approval-not-performed"),
    ("broker-state", "crash-sweep"),
    ("broker-state", "interrupted-once"),
    ("broker-state", "overlong-delivery"),
    ("broker-state", "admission-replay-no-remint"),
    ("broker-state", "no-readable-fd-before-intent"),
    ("broker-state", "open-fails-after-intent-object-changed"),
    ("broker-state", "open-fails-after-intent-object-unreadable"),
    ("broker-state", "m4b-swap-rename"),
    ("broker-state", "m4b-swap-symlink"),
    ("broker-state", "in-place-rewrite"),
    ("broker-state", "hostile-broker-honest"),
    ("broker-state", "hostile-broker-wrongchannel"),
    ("broker-state", "hostile-broker-wronginvocation"),
    ("broker-state", "hostile-broker-toomanybytes"),
    ("broker-state", "hostile-broker-bothresults"),
    ("broker-state", "hostile-broker-garbage"),
    ("broker-state", "hostile-broker-oversizedheader"),
    ("broker-state", "hostile-broker-closeafterauthorisation"),
    ("broker-state", "hostile-broker-stall"),
    ("broker-state", "hostile-broker-nohello"),
    ("broker-state", "hostile-broker-refuse"),
    ("private-protocol", "non-authority-peer"),
    ("private-protocol", "honest-exchange"),
    ("private-protocol", "replay-other-connection"),
    ("private-protocol", "replay-changed-bytes"),
    ("private-protocol", "replay-other-descriptor"),
    ("private-protocol", "replay-after-restart"),
    ("private-protocol", "second-on-same-connection"),
    ("private-protocol", "descriptor-count-and-kind"),
    ("private-protocol", "descriptor-count-refused-closed"),
    ("private-protocol", "read-bound-exact"),
    ("private-protocol", "malformed-authorisations"),
    ("private-protocol", "descriptor-pressure"),
    ("private-protocol", "stalled-peer"),
    ("private-protocol", "refuses-untrusted-configuration"),
)

# The three-identity suite: `#[ignore]`d, selected BY NAME, required to run
# every test and report every case -- as FOREIGN_TESTS above.
BROKER_FOREIGN_TESTS = (
    "linux::three_identities_read_only_through_the_checked_descriptor",
    "linux::a_listener_of_another_identity_is_sent_nothing",
    "linux::the_broker_identity_reaches_no_authority_state_and_no_dwkp",
)
BROKER_FOREIGN_CASES = (
    ("broker-foreign", "broker-uid-cannot-open-by-path"),
    ("broker-foreign", "three-identity-fs-read"),
    ("broker-foreign", "runtime-uid-cannot-reach-broker"),
    ("broker-foreign", "authority-verifies-broker-uid"),
    ("broker-foreign", "broker-uid-reaches-no-authority-state"),
    ("broker-foreign", "broker-uid-cannot-speak-dwkp"),
)


FSOP_EVIDENCE_PREFIX = "FSOP-EVIDENCE "

# M4c's same-identity evidence (ADR-0044): the released authority and broker
# end to end for every tool, the in-process race and crash campaigns on the
# real channel, the hostile private-protocol cases for the new operations, and
# the local half of the write permission experiment. Every (suite, case) is
# printed by exactly one test after its assertions held; a missing one -- or
# one whose outcome says it was not exercised -- fails the task.
FSOP_CASES = (
    ("fs-ops", "fs.stat"),
    ("fs-ops", "fs.list"),
    ("fs-ops", "fs.search"),
    ("fs-ops", "fs.write-existing"),
    ("fs-ops", "fs.write-vacant"),
    ("fs-ops", "fs.patch"),
    ("fs-ops", "fs.move"),
    ("fs-ops", "fs.delete"),
    ("fs-ops", "audit-holds-no-content"),
    ("fs-ops", "taint-read-family-only"),
    ("fs-ops", "preview-zero-effect"),
    ("fs-ops", "preview-invoke-differential"),
    ("fs-ops", "obligation-unenforceable"),
    ("fs-ops", "obligation-both-versions"),
    ("fs-ops", "compound-denial"),
    ("fs-ops", "idempotency-key"),
    ("fs-ops", "hardlink-write-patch"),
    ("fs-ops", "hardlink-move-delete"),
    ("fs-ops", "symlink-containment"),
    ("fs-ops", "fs.list-unaddressable"),
    ("fs-ops", "fs.search-bounds"),
    ("fs-ops", "fs.create-scope-semantics"),
    ("fs-ops", "public-versioning"),
    ("fs-ops", "resource-leaks"),
    ("fs-ops", "patch-inline-bound-exceeded"),
    ("fs-ops", "patch-inline-bound-exact"),
    ("fs-ops-state", "R1-write-existing-target-swapped"),
    ("fs-ops-state", "R2-write-vacant-name-occupied"),
    ("fs-ops-state", "R3-move-destination-occupied"),
    ("fs-ops-state", "R4-move-source-swapped"),
    ("fs-ops-state", "R5-delete-target-swapped"),
    ("fs-ops-state", "R6-delete-empty-dir-swapped-for-a-full-one"),
    ("fs-ops-state", "R7-patch-rewritten-in-place"),
    ("fs-ops-state", "R8-target-swapped-for-a-symlink"),
    ("fs-ops-state", "R9-parent-swapped"),
    ("fs-ops-state", "A-write-after-intent"),
    ("fs-ops-state", "B-move-after-open"),
    ("fs-ops-state", "C-delete-after-broker"),
    ("fs-ops-state", "D-patch-after-outcome"),
    ("fs-ops-state", "E-read-after-broker"),
    ("fs-ops-state", "F-write-before-exchange"),
    ("fs-ops-state", "G-write-after-exchange"),
    ("fs-ops-state", "H-patch-after-sync"),
    ("fs-ops-state", "I-create-after-rename"),
    ("fs-ops-state", "J-move-after-rename"),
    ("fs-ops-state", "K-delete-after-stage"),
    ("fs-ops-state", "K2-delete-after-unlink"),
    ("fs-ops-state", "U-restore-failed"),
    ("fs-ops-state", "staging-F-write-before-exchange"),
    ("fs-ops-state", "staging-G-write-after-exchange"),
    ("fs-ops-state", "staging-I-create-after-rename"),
    ("fs-ops-state", "staging-K-delete-after-stage"),
    ("fs-ops-state", "staging-K2-delete-after-unlink"),
    ("fs-ops-state", "staging-S1-replace-before-record"),
    ("fs-ops-state", "staging-S2-patch-before-check"),
    ("fs-ops-state", "staging-S3-create-before-check"),
    ("fs-ops-state", "staging-S4-delete-before-check"),
    ("fs-ops-state", "staging-S5-repeated-crash-injection"),
    ("fs-ops-state", "staging-S6-unrelated-by-spelling"),
    ("fs-ops-state", "staging-R1-root-renamed-and-replaced"),
    ("fs-ops-state", "staging-R2-symlink-at-root-path"),
    ("fs-ops-state", "staging-R3-lookalike-in-replacement-root"),
    ("fs-ops-state", "staging-R4-original-root-renamed-then-restored"),
    ("fs-ops-state", "staging-R5-parent-replaced-beneath-the-root"),
    ("broker-window", "replace-target-swapped-before-check"),
    ("broker-window", "patch-base-rewritten-before-check"),
    ("broker-window", "create-name-taken-before-check"),
    ("broker-window", "move-source-swapped-before-check"),
    ("broker-window", "delete-target-swapped-before-check"),
    ("broker-window", "replace-target-swapped-after-check"),
    ("broker-window", "patch-base-rewritten-after-check"),
    ("broker-window", "create-name-taken-after-check"),
    ("broker-window", "move-source-swapped-after-check"),
    ("broker-window", "move-destination-taken-after-check"),
    ("broker-window", "delete-target-swapped-after-check"),
    ("broker-window", "replace-restore-fails"),
    ("broker-window", "move-restore-fails"),
    ("broker-window", "delete-restore-fails"),
    ("broker-window", "shared-directory"),
    ("broker-window", "reclaim-pre-effect-staging"),
    ("broker-window", "reclaim-post-effect-staging"),
    ("broker-window", "reclaim-by-spelling"),
    ("broker-durability", "A-staging-directory-created"),
    ("broker-durability", "B-record-written"),
    ("broker-durability", "C-new-written"),
    ("broker-durability", "D-exchange-or-rename"),
    ("broker-durability", "E-undo"),
    ("broker-durability", "F-taken-into-staging"),
    ("broker-durability", "G-staging-entries-removed"),
    ("broker-durability", "H-staging-directory-removed"),
    ("patch-frame", "largest-decodable-patch-request"),
    ("patch-frame", "largest-valid-patch-request"),
    ("grant-rehydration", "stored-grant-rehydrated-after-delete"),
    ("grant-rehydration", "admission-replay"),
    ("grant-rehydration", "new-admission-of-deleted-path"),
    ("grant-rehydration", "invoke-on-deleted-path"),
    ("grant-rehydration", "replaced-object-same-path"),
    ("grant-rehydration", "lookups-new-declaration"),
    ("grant-rehydration", "lookups-admission-replay"),
    ("grant-rehydration", "lookups-stored-grant-after-delete"),
    ("grant-rehydration", "lookups-tool-target"),
    ("private-protocol", "v2-write-given-a-file"),
    ("private-protocol", "v2-write-given-an-o-path-directory"),
    ("private-protocol", "v2-write-given-another-directory"),
    ("private-protocol", "v2-write-given-two"),
    ("private-protocol", "v2-move-given-one"),
    ("private-protocol", "v2-stat-given-a-readable-descriptor"),
    ("private-protocol", "v2-patch-given-its-descriptors-reversed"),
    ("private-protocol", "v2-delete-naming-another-object"),
    ("private-protocol", "v2-reclaim-given-a-file"),
    ("private-protocol", "v2-reclaim-given-two"),
    ("private-protocol", "v2-reclaim-given-another-directory"),
    ("private-protocol", "v2-descriptor-roles"),
    ("permission-model", "descriptor-is-not-a-grant"),
    ("permission-model", "lookup-needs-search"),
    ("permission-model", "write-bit-is-the-grant"),
    ("permission-model", "noreplace-exchange-supported"),
)

# The three-identity half: `#[ignore]`d, selected BY NAME, required to run every
# test and report every case.
FSOP_FOREIGN_TESTS = (
    "linux::a_held_directory_is_not_a_right_to_change_its_names",
    "linux::a_write_enabled_workspace_is_changed_by_the_broker_uid_and_only_where_granted",
)
FSOP_FOREIGN_CASES = (
    ("fs-ops-foreign", "observe-through-descriptors-cross-uid"),
    ("fs-ops-foreign", "no-grant-write-existing"),
    ("fs-ops-foreign", "no-grant-write-vacant"),
    ("fs-ops-foreign", "no-grant-move"),
    ("fs-ops-foreign", "no-grant-delete"),
    ("fs-ops-foreign", "descriptor-is-not-a-namespace-grant-cross-uid"),
    ("fs-ops-foreign", "permission-grant"),
    ("fs-ops-foreign", "write-existing-cross-uid"),
    ("fs-ops-foreign", "write-vacant-cross-uid"),
    ("fs-ops-foreign", "patch-move-delete-cross-uid"),
    ("fs-ops-foreign", "outside-the-grant-cross-uid"),
    ("fs-ops-foreign", "group-not-keepable-cross-uid"),
    ("fs-ops-foreign", "grant-is-ambient"),
    ("fs-ops-foreign", "runtime-uid-outside-the-grant"),
)


def task_broker_fs_read_evidence() -> None:
    """M4b's brokered fs.read evidence (ADR-0043); three identities need DW_BROKER_AS, DW_PEER_AS.

    With DW_BROKER_AS (the broker's own user) and DW_PEER_AS (a hostile local
    user, the runtime's position) set, both are proven first -- by numbers,
    distinct from this process, from root and from each other. Then the broker
    binary is built, and the same-identity suites run: the real authority and
    broker end to end, the crash-point sweep, the hostile broker and the
    hostile authority-side peer on the real private channel, and the
    cross-process TOCTOU campaign. Every case must report. Then the
    three-identity suite, selected by name, with the broker started as its own
    user through `sudo -n -u` by the TEST HARNESS -- never by the authority.

    Without both identities that half is NOT EXERCISED and this task fails after
    running everything else. CI's Linux job creates a broker user and provides
    both. Linux only: the channel needs SO_PEERCRED and SCM_RIGHTS.
    """
    if not sys.platform.startswith("linux"):
        raise TaskError(
            "NOT EXERCISED: the private broker channel runs only on Linux (ADR-0043); "
            "use WSL2 on Windows"
        )
    broker_user = os.environ.get("DW_BROKER_AS", "").strip()
    peer_user = os.environ.get("DW_PEER_AS", "").strip()
    identities = bool(broker_user and peer_user)
    if identities:
        _, _, broker_uid = second_identity("DW_BROKER_AS")
        _, _, peer_uid = second_identity("DW_PEER_AS")
        if broker_uid == peer_uid:
            raise TaskError(
                f"DW_BROKER_AS={broker_user} and DW_PEER_AS={peer_user} are both uid {peer_uid}: "
                "the broker and the hostile runtime must be two identities"
            )
    # The authority's suites spawn the broker binary Cargo builds beside it.
    run("cargo", "build", "--locked", "-p", "dwkd-broker")
    authority = run_captured(
        "cargo",
        "test",
        "--locked",
        "-p",
        "dwkd-authority",
        "--test",
        "broker_fs_read",
        "--test",
        "broker_state",
        "--",
        "--nocapture",
    )
    broker = run_captured(
        "cargo",
        "test",
        "--locked",
        "-p",
        "dwkd-broker",
        "--test",
        "private_protocol",
        "--",
        "--nocapture",
    )
    require_broker_evidence(f"{authority}\n{broker}", BROKER_CASES)
    if identities:
        foreign = run_captured(
            "cargo",
            "test",
            "--locked",
            "-p",
            "dwkd-authority",
            "--test",
            "broker_foreign",
            "--",
            "--ignored",
            "--exact",
            "--nocapture",
            *BROKER_FOREIGN_TESTS,
        )
        require_broker_foreign_evidence(foreign)
    uvrun("dwcheck", "closure", "--report")
    if not identities:
        raise TaskError(
            "NOT EXERCISED: the three-identity half needs DW_BROKER_AS (the broker's own user) "
            "and DW_PEER_AS (a hostile local user), both reachable through `sudo -n -u`; "
            "every same-identity suite above ran"
        )


def _broker_evidence(output: str) -> set[tuple[str, str]]:
    reported: set[tuple[str, str]] = set()
    for line in output.splitlines():
        at = line.find(BROKER_EVIDENCE_PREFIX)
        if at < 0:
            continue
        try:
            record = json.loads(line[at + len(BROKER_EVIDENCE_PREFIX) :])
        except json.JSONDecodeError as exc:
            raise TaskError(f"unreadable evidence line: {line[:200]}") from exc
        if not isinstance(record, dict) or not record.get("outcome"):
            raise TaskError(f"malformed evidence line: {line[:200]}")
        reported.add((str(record.get("suite")), str(record.get("case"))))
    return reported


def require_broker_evidence(output: str, cases: tuple[tuple[str, str], ...]) -> None:
    """Every (suite, case) must have printed its evidence line."""
    reported = _broker_evidence(output)
    missing = [f"{suite}/{case}" for suite, case in cases if (suite, case) not in reported]
    if missing:
        raise TaskError("broker evidence incomplete, not reported: " + ", ".join(missing))
    print(f"{GREEN}broker evidence: {len(cases)} cases reported{OFF}")


def require_broker_foreign_evidence(output: str) -> None:
    """The three-identity suite counts only if every test ran and every case reported."""
    summaries = [line for line in output.splitlines() if line.startswith("test result: ")]
    expected = f"test result: ok. {len(BROKER_FOREIGN_TESTS)} passed; 0 failed; 0 ignored"
    if len(summaries) != 1 or not summaries[0].startswith(expected):
        raise TaskError(
            f"the three-identity suite did not run all of its tests: expected `{expected}`, "
            f"got {summaries or 'no summary'}"
        )
    require_broker_evidence(output, BROKER_FOREIGN_CASES)


def task_filesystem_operations_evidence() -> None:
    """M4c's filesystem-operation evidence (ADR-0044); three identities and the
    write group need DW_BROKER_AS, DW_PEER_AS and DW_WRITE_GROUP.

    With all three set, the two users are proven first -- by numbers, distinct
    from this process, from root and from each other. Then the broker binary is
    built and the same-identity suites run: every tool end to end through the
    released daemons, previews, compound denials, idempotency keys, hard links,
    symlinks, bounds and leaks; the race campaigns and the crash campaigns
    (authority crash points and debug-broker crash points) on the real channel;
    reclamation against a replaced, renamed or symlinked root; the durability
    order of every namespace change the broker makes (a trace of its system
    calls -- not a power cut); the zero-lookup proof, inside the authority crate
    where its counter lives; the hostile private-protocol cases for the new
    operations; and the local half of the write permission experiment. Every
    case must report. Then the
    three-identity suite, selected by name: the broker as its own user, a
    workspace with no grant (nothing changes, WRITE_DENIED) and one the harness
    grants to DW_WRITE_GROUP (everything changes, only there, and the grant is
    shown to be ambient). The harness applies the grant and prints exactly what
    it granted; the product never does.

    Without the identities and the group that half is NOT EXERCISED and this
    task fails after running everything else. CI's Linux job creates the broker
    user and the group. Linux only.
    """
    if not sys.platform.startswith("linux"):
        raise TaskError(
            "NOT EXERCISED: the filesystem operations run only on Linux (ADR-0044); "
            "use WSL2 on Windows"
        )
    broker_user = os.environ.get("DW_BROKER_AS", "").strip()
    peer_user = os.environ.get("DW_PEER_AS", "").strip()
    group = os.environ.get("DW_WRITE_GROUP", "").strip()
    identities = bool(broker_user and peer_user and group)
    if identities:
        _, _, broker_uid = second_identity("DW_BROKER_AS")
        _, _, peer_uid = second_identity("DW_PEER_AS")
        if broker_uid == peer_uid:
            raise TaskError(
                f"DW_BROKER_AS={broker_user} and DW_PEER_AS={peer_user} are both uid {peer_uid}: "
                "the broker and the hostile runtime must be two identities"
            )
    # The suites spawn the broker binary Cargo builds beside the authority.
    run("cargo", "build", "--locked", "-p", "dwkd-broker")
    authority = run_captured(
        "cargo",
        "test",
        "--locked",
        "-p",
        "dwkd-authority",
        "--test",
        "broker_fs_ops",
        "--test",
        "fs_ops_state",
        "--test",
        "broker_state",
        "--",
        "--nocapture",
    )
    # The lookup counter exists only in the authority's own unit tests, so
    # the zero-lookup proof runs there (`src/state/lookup_tests.rs`).
    lookups = run_captured(
        "cargo",
        "test",
        "--locked",
        "-p",
        "dwkd-authority",
        "--lib",
        "lookup_tests",
        "--",
        "--nocapture",
    )
    frame = run_captured(
        "cargo",
        "test",
        "--locked",
        "-p",
        "dwk-proto",
        "--test",
        "dwkp_v2",
        "--",
        "--nocapture",
    )
    broker = run_captured(
        "cargo",
        "test",
        "--locked",
        "-p",
        "dwkd-broker",
        "--bins",
        "--test",
        "private_protocol",
        "--test",
        "permission_model",
        "--",
        "--nocapture",
    )
    require_fsop_evidence(f"{authority}\n{lookups}\n{frame}\n{broker}", FSOP_CASES)
    if identities:
        foreign = run_captured(
            "cargo",
            "test",
            "--locked",
            "-p",
            "dwkd-authority",
            "--test",
            "fs_ops_foreign",
            "--",
            "--ignored",
            "--exact",
            "--nocapture",
            *FSOP_FOREIGN_TESTS,
        )
        require_fsop_foreign_evidence(foreign)
    uvrun("dwcheck", "closure", "--report")
    if not identities:
        raise TaskError(
            "NOT EXERCISED: the three-identity half needs DW_BROKER_AS (the broker's own user), "
            "DW_PEER_AS (a hostile local user) and DW_WRITE_GROUP (a group holding the broker's "
            "user and this one); every same-identity suite above ran"
        )


def _fsop_evidence(output: str) -> set[tuple[str, str]]:
    """Every (suite, case) an FSOP-EVIDENCE line reported as exercised."""
    reported: set[tuple[str, str]] = set()
    for line in output.splitlines():
        at = line.find(FSOP_EVIDENCE_PREFIX)
        if at < 0:
            continue
        try:
            record = json.loads(line[at + len(FSOP_EVIDENCE_PREFIX) :])
        except json.JSONDecodeError as exc:
            raise TaskError(f"unreadable evidence line: {line[:200]}") from exc
        if not isinstance(record, dict) or not record.get("outcome") or not record.get("suite"):
            raise TaskError(f"malformed evidence line: {line[:200]}")
        if str(record["outcome"]).startswith("not-exercised"):
            continue
        reported.add((str(record["suite"]), str(record.get("case"))))
    return reported


def require_fsop_evidence(output: str, cases: tuple[tuple[str, str], ...]) -> None:
    """Every (suite, case) must have printed its evidence line, exercised."""
    reported = _fsop_evidence(output)
    missing = [f"{suite}/{case}" for suite, case in cases if (suite, case) not in reported]
    if missing:
        raise TaskError(
            "filesystem-operation evidence incomplete, not reported: " + ", ".join(missing)
        )
    print(f"{GREEN}filesystem-operation evidence: {len(cases)} cases reported{OFF}")


def require_fsop_foreign_evidence(output: str) -> None:
    """The three-identity suite counts only if every test ran and every case reported."""
    summaries = [line for line in output.splitlines() if line.startswith("test result: ")]
    expected = f"test result: ok. {len(FSOP_FOREIGN_TESTS)} passed; 0 failed; 0 ignored"
    if len(summaries) != 1 or not summaries[0].startswith(expected):
        raise TaskError(
            f"the three-identity suite did not run all of its tests: expected `{expected}`, "
            f"got {summaries or 'no summary'}"
        )
    require_fsop_evidence(output, FSOP_FOREIGN_CASES)


PROC_EVIDENCE_PREFIX = "PROC-EVIDENCE "

# M4d's evidence (ADR-0045). Each (suite, case) is printed by exactly one test,
# after its assertions held; a missing one -- or one whose outcome says it was
# not exercised -- fails the task. The suites, and what they are:
#   process-frame            the private-protocol frames at their bounds;
#   argv-classifier          argv literal, and every argv_safe rule;
#   authority-process        the authority's state machine against a FAKE
#                            broker: decisions, durable order, idempotency,
#                            UNKNOWN, lookups, argv_allowlist, crash windows.
#                            Not process-execution evidence;
#   production-floor         the released daemons: no process can be launched;
#   hygiene-override         real git and python3 undoing the environment form
#                            of workspace_exec_hygiene (why it is denied);
#   broker-process           the REAL broker module and helper starting real
#                            targets: re-proof, races, output, kill, table;
#   broker-private-protocol  the real broker binary over its socket: descriptor
#                            counts, crash points, restart and generations.
PROC_CASES = (
    ("process-frame", "largest-valid-launch-request"),
    ("process-frame", "largest-status-result"),
    ("argv-classifier", "argv-literal-shell-text-is-data"),
    ("argv-classifier", "argv-safe-interpreter"),
    ("argv-classifier", "argv-safe-runner"),
    ("argv-classifier", "argv-safe-exec-style-option"),
    ("argv-classifier", "argv-safe-git-config-alias-external"),
    ("argv-classifier", "argv-safe-cargo-external"),
    ("argv-classifier", "argv-safe-names-a-program"),
    ("authority-process", "new-process-declaration"),
    ("authority-process", "admission-replay"),
    ("authority-process", "stored-process-grant"),
    ("authority-process", "launch-lookup"),
    ("authority-process", "changed-hash"),
    ("authority-process", "deleted-executable"),
    ("authority-process", "preview-zero-effect"),
    ("authority-process", "preview-hash-drift"),
    ("authority-process", "wrong-run-status"),
    ("authority-process", "wrong-run-kill"),
    ("authority-process", "R10-process-handle-substituted"),
    ("authority-process", "R11-process-of-another-run"),
    ("authority-process", "stale-generation"),
    ("authority-process", "argv-allowlist-positive"),
    ("authority-process", "argv-allowlist-negative"),
    ("authority-process", "durable-intent-before-exec"),
    ("authority-process", "status-output-taints"),
    ("authority-process", "status-retry-safe"),
    ("authority-process", "exec-key-reuse"),
    ("authority-process", "kill-key-reuse"),
    ("authority-process", "launch-unconfirmed"),
    ("authority-process", "kill-unconfirmed"),
    ("authority-process", "launch-refused"),
    ("authority-process", "restart-open-launch"),
    ("authority-process", "restart-running-process"),
    ("authority-process", "production-floor-opted-out"),
    ("authority-process", "production-floor-opted-in"),
    ("authority-process", "no-capability"),
    ("authority-process", "inspect-gate"),
    ("authority-process", "signal-gate"),
    ("authority-process", "policy-deny"),
    ("authority-process", "policy-approval"),
    ("authority-process", "network-deny-obligation"),
    ("authority-process", "workspace-exec-hygiene-obligation"),
    ("authority-process", "max-output-bytes-1024"),
    ("authority-process", "crash-E1-before-intent"),
    ("authority-process", "crash-E2-after-intent"),
    ("authority-process", "crash-E3-broker-accepted-then-lost"),
    ("authority-process", "crash-E4-helper-created-broker-lost"),
    ("authority-process", "crash-E5-before-target-exec"),
    ("authority-process", "crash-E6-exec-handshake-lost"),
    ("authority-process", "crash-E7-result-before-outcome"),
    ("authority-process", "crash-E8-outcome-before-response"),
    ("authority-process", "crash-K1-before-intent"),
    ("authority-process", "crash-K2-after-intent"),
    ("authority-process", "crash-K3-broker-accepted-then-lost"),
    ("authority-process", "crash-K4-before-signal-broker-lost"),
    ("authority-process", "crash-K5-signal-may-have-happened"),
    ("authority-process", "crash-K6-result-before-outcome"),
    ("authority-process", "crash-S1-after-validation"),
    ("authority-process", "crash-S2-broker-inspection-lost"),
    ("authority-process", "crash-S3-result-before-outcome"),
    ("production-floor", "released-opted-out"),
    ("production-floor", "released-opted-in"),
    ("production-floor", "released-preview"),
    ("production-floor", "released-status-kill-no-process"),
    ("production-floor", "shipped-balanced"),
    ("production-floor", "shipped-power"),
    ("production-floor", "shipped-safe"),
    ("hygiene-override", "git-repository-hook-despite-env"),
    ("hygiene-override", "git-argv-config-runs-a-command"),
    ("hygiene-override", "python-argv-restores-cwd-import"),
    ("broker-process", "argv-literal"),
    ("broker-process", "env-built-from-nothing"),
    ("broker-process", "rlimits-applied"),
    ("broker-process", "fd-hygiene-target"),
    ("broker-process", "stdin"),
    ("broker-process", "no-new-privs"),
    ("broker-process", "digest-mismatch"),
    ("broker-process", "rewritten-after-hash"),
    ("broker-process", "truncated-after-hash"),
    ("broker-process", "group-writable"),
    ("broker-process", "setuid"),
    ("broker-process", "script"),
    ("broker-process", "foreign-owner"),
    ("broker-process", "path-replaced-after-handoff"),
    ("broker-process", "R1-executable-path-replaced"),
    ("broker-process", "R2-executable-renamed"),
    ("broker-process", "R3-executable-deleted"),
    ("broker-process", "R4-executable-rewritten-in-place"),
    ("broker-process", "R5-executable-truncated"),
    ("broker-process", "R6-executable-chmod"),
    ("broker-process", "cwd-replaced-after-handoff"),
    ("broker-process", "R7-cwd-path-replaced"),
    ("broker-process", "descriptors-reversed"),
    ("broker-process", "executable-identity-mismatch"),
    ("broker-process", "R8-executable-descriptor-substituted"),
    ("broker-process", "cwd-not-a-directory"),
    ("broker-process", "cwd-identity-mismatch"),
    ("broker-process", "R9-cwd-descriptor-substituted"),
    ("broker-process", "executable-o-path"),
    ("broker-process", "inherited-descriptor"),
    ("broker-process", "exec-failure"),
    ("broker-process", "leak-24-launches"),
    ("broker-process", "status-running"),
    ("broker-process", "kill-signals-process-and-group"),
    ("broker-process", "kill-after-exit"),
    ("broker-process", "wall-clock"),
    ("broker-process", "stale-generation"),
    ("broker-process", "R12-broker-generation-stale"),
    ("broker-process", "unknown-handle"),
    ("broker-process", "handle-reuse"),
    ("broker-process", "helper-direct-invocation"),
    ("broker-process", "output-none"),
    ("broker-process", "output-stdout-only"),
    ("broker-process", "output-stderr-only"),
    ("broker-process", "output-binary"),
    ("broker-process", "output-exact-cap"),
    ("broker-process", "output-cap-plus-one"),
    ("broker-process", "output-close-stdout-early"),
    ("broker-process", "output-write-then-sleep"),
    ("broker-process", "output-12MiB-both-streams"),
    ("broker-process", "table-bound"),
    ("broker-private-protocol", "launch-none-descriptors"),
    ("broker-private-protocol", "launch-one-descriptors"),
    ("broker-private-protocol", "launch-two-descriptors"),
    ("broker-private-protocol", "launch-three-descriptors"),
    ("broker-private-protocol", "launch-descriptors-reversed"),
    ("broker-private-protocol", "status-kill-with-descriptor"),
    ("broker-private-protocol", "stale-generation"),
    ("broker-private-protocol", "kill-then-status"),
    ("broker-private-protocol", "environment-not-inherited"),
    ("broker-private-protocol", "broker-restart-orphans"),
    ("broker-private-protocol", "broker-restart-generation"),
    ("broker-private-protocol", "crash-process_before_helper"),
    ("broker-private-protocol", "crash-process_helper_spawned"),
    ("broker-private-protocol", "crash-process_helper_before_exec"),
    ("broker-private-protocol", "crash-process_exec_confirmed"),
)

# The three-identity half: `#[ignore]`d, selected BY NAME, required to run every
# test and report every case, each line carrying the three numeric uids.
PROC_FOREIGN_TESTS = ("linux::the_broker_identity_executes_a_descriptor_it_cannot_reach_by_name",)
PROC_FOREIGN_CASES = (
    ("process-foreign", "broker-uid-cannot-name-the-executable"),
    ("process-foreign", "descriptor-bound-exec-cross-uid"),
    ("process-foreign", "path-replaced-after-handoff-cross-uid"),
    ("process-foreign", "runtime-uid-cannot-launch"),
    ("process-foreign", "runtime-uid-cannot-status-or-kill"),
    ("process-foreign", "runtime-uid-helper-does-nothing"),
)


def task_process_broker_evidence() -> None:
    """M4d's process-execution evidence (ADR-0045); the three-identity half needs
    DW_BROKER_AS and DW_PEER_AS.

    With both set, the two users are proven first -- by numbers, distinct from
    this process, from root and from each other. Then the broker binary is
    built and the same-identity suites run: the private-protocol frames at
    their bounds; the argv classifier; the authority's process state machine
    against a fake broker (decisions, durable order, idempotency, UNKNOWN,
    lookups, crash windows -- labelled as such, never counted as execution);
    the released daemons, which launch nothing; the hygiene override attacks
    with the real git and python3; the real broker module and launch helper
    starting real targets (re-proof, the race campaign, output, kill, the
    table); and the real broker binary over its socket (descriptor counts,
    crash points, restart). Every case must report, every suite must have run
    at least one test. Then the three-identity suite, selected by name: the
    broker as its own user executes a descriptor it cannot reach by name, and
    a hostile runtime user gets nothing from its socket or its helper.

    Without the identities that half is NOT EXERCISED and this task fails after
    running everything else. CI's Linux job creates the broker user. Linux
    only.
    """
    if not sys.platform.startswith("linux"):
        raise TaskError(
            "NOT EXERCISED: process execution runs only on Linux (ADR-0045); use WSL2 on Windows"
        )
    broker_user = os.environ.get("DW_BROKER_AS", "").strip()
    peer_user = os.environ.get("DW_PEER_AS", "").strip()
    identities = bool(broker_user and peer_user)
    if identities:
        _, _, broker_uid = second_identity("DW_BROKER_AS")
        _, _, peer_uid = second_identity("DW_PEER_AS")
        if broker_uid == peer_uid:
            raise TaskError(
                f"DW_BROKER_AS={broker_user} and DW_PEER_AS={peer_user} are both uid {peer_uid}: "
                "the broker and the hostile runtime must be two identities"
            )
    # The suites spawn the broker binary Cargo builds beside the authority.
    run("cargo", "build", "--locked", "-p", "dwkd-broker")
    suites = [
        run_captured(
            "cargo", "test", "--locked", "-p", "dwk-proto", "--test", "dwkp_v3", "--", "--nocapture"
        ),
        # The lookup counter and the fake broker exist only in the authority's
        # own unit tests, so the state machine and the classifier run there.
        run_captured(
            "cargo",
            "test",
            "--locked",
            "-p",
            "dwkd-authority",
            "--lib",
            "state::process",
            "--",
            "--nocapture",
        ),
        run_captured(
            "cargo",
            "test",
            "--locked",
            "-p",
            "dwkd-authority",
            "--lib",
            "resource::exec",
            "--",
            "--nocapture",
        ),
        run_captured(
            "cargo",
            "test",
            "--locked",
            "-p",
            "dwkd-authority",
            "--test",
            "process_production",
            "--test",
            "hygiene_override",
            "--",
            "--nocapture",
        ),
        run_captured(
            "cargo",
            "test",
            "--locked",
            "-p",
            "dwkd-broker",
            "--bins",
            "--test",
            "private_protocol",
            "--",
            "--nocapture",
        ),
    ]
    for output in suites:
        require_tests_ran(output)
    require_proc_evidence("\n".join(suites), PROC_CASES)
    if identities:
        foreign = run_captured(
            "cargo",
            "test",
            "--locked",
            "-p",
            "dwkd-authority",
            "--test",
            "process_foreign",
            "--",
            "--ignored",
            "--exact",
            "--nocapture",
            *PROC_FOREIGN_TESTS,
        )
        require_proc_foreign_evidence(foreign)
    uvrun("dwcheck", "closure", "--report")
    if not identities:
        raise TaskError(
            "NOT EXERCISED: the three-identity half needs DW_BROKER_AS (the broker's own user) "
            "and DW_PEER_AS (a hostile local user); every same-identity suite above ran"
        )


SECRET_EVIDENCE_PREFIX = "SECRET-EVIDENCE "  # noqa: S105 - a log prefix, not a credential

# M4e's evidence (ADR-0046). Each (suite, case) is printed by exactly one test,
# after its assertions held; a missing one -- or one whose outcome says it was
# not exercised -- fails the task. The suites, and what they are:
#   secret-metadata            the operator's metadata grammar: deferred
#                              backends, mode D unreachable, header and
#                              environment names refused, origin binding;
#   secret-backend             the REAL kernel keyring and REAL age files, and
#                              every hostile store;
#   secret-redaction           exact-value and known-shape redaction, the
#                              documented limitations, the scan bound;
#   authority-secret-pipeline  the authority's mode A state machine against a
#                              FAKE broker (backend reads counted, durable order,
#                              gates, revisions, R1-R10 crash windows) and the
#                              process-output return path. Not transport
#                              evidence;
#   broker-secret-primitives   the REAL broker binary: the one-shot descriptor,
#                              every hostile descriptor and message, the mode
#                              B/C injection primitive, output redaction while
#                              drained, residue, the production hardening;
#   authority-secret           the REAL daemons and a separate runtime process:
#                              return-path redaction, the runtime's address
#                              space, mode A through the real broker, residue,
#                              durable state, audit, logs.
SECRET_CASES = (
    ("secret-metadata", "header-crlf"),
    ("secret-metadata", "env-control-variable"),
    ("secret-metadata", "mode-fields"),
    ("secret-metadata", "origin-binding"),
    ("secret-metadata", "handle-grammar"),
    ("secret-metadata", "unknown-member"),
    ("secret-metadata", "env-backend"),
    ("secret-metadata", "exec-backend"),
    ("secret-metadata", "mode-d-plaintext-to-model"),
    ("secret-backend", "keyring-round-trip"),
    ("secret-backend", "keyring-item-missing"),
    ("secret-backend", "keyring-oversized-refused-by-kernel"),
    ("secret-backend", "keyring-removed-fails-closed"),
    ("secret-backend", "keyring-provisioning-mask"),
    ("secret-backend", "keyring-owner-bits-suffice"),
    ("secret-backend", "keyring-owner-view-only"),
    ("secret-backend", "keyring-default-mask-unpossessed"),
    ("secret-backend", "keyring-owner-read-missing-unpossessed"),
    ("secret-backend", "age-decrypt"),
    ("secret-backend", "age-no-identity"),
    ("secret-backend", "age-store-readable-by-others"),
    ("secret-backend", "age-store-foreign-owner"),
    ("secret-backend", "age-store-symlink"),
    ("secret-backend", "age-truncated"),
    ("secret-backend", "age-garbage"),
    ("secret-backend", "age-oversized-file"),
    ("secret-backend", "age-oversized-plaintext"),
    ("secret-backend", "age-missing"),
    ("secret-backend", "age-wrong-identity"),
    ("secret-backend", "age-scrypt-passphrase"),
    ("secret-redaction", "exact-value"),
    ("secret-redaction", "transformed-hex"),
    ("secret-redaction", "transformed-reversed"),
    ("secret-redaction", "transformed-split"),
    ("secret-redaction", "short-value-not-indexed"),
    ("secret-redaction", "overlap-precedence"),
    ("secret-redaction", "shape-github"),
    ("secret-redaction", "shape-openai"),
    ("secret-redaction", "shape-slack"),
    ("secret-redaction", "shape-aws"),
    ("secret-redaction", "shape-jwt"),
    ("secret-redaction", "shape-pem-private-key"),
    ("secret-redaction", "shape-bearer"),
    ("secret-redaction", "shape-connection-string"),
    ("secret-redaction", "shape-keyword"),
    ("secret-redaction", "shape-near-misses"),
    ("secret-redaction", "offset-sweep-64KiB"),
    ("secret-redaction", "bound-64-secrets-256KiB"),
    ("authority-secret-pipeline", "stored-grant-replaced"),
    ("authority-secret-pipeline", "stored-grant-revoked"),
    ("authority-secret-pipeline", "stored-grant-removed"),
    ("authority-secret-pipeline", "admission-new-declaration"),
    ("authority-secret-pipeline", "admission-unconfigured-or-revoked"),
    ("authority-secret-pipeline", "admission-replay"),
    ("authority-secret-pipeline", "backend-item-missing-after-intent"),
    ("authority-secret-pipeline", "header-breaking-value"),
    ("authority-secret-pipeline", "origin-suffix-attack"),
    ("authority-secret-pipeline", "origin-prefix-attack"),
    ("authority-secret-pipeline", "origin-parent-domain"),
    ("authority-secret-pipeline", "origin-wrong-port"),
    ("authority-secret-pipeline", "origin-userinfo"),
    ("authority-secret-pipeline", "mode-downgrade-fd-only-to-egress"),
    ("authority-secret-pipeline", "not-configured"),
    ("authority-secret-pipeline", "revoked"),
    ("authority-secret-pipeline", "capability-gate"),
    ("authority-secret-pipeline", "broker-refused"),
    ("authority-secret-pipeline", "broker-unreachable-before-send"),
    ("authority-secret-pipeline", "broker-lost-after-send"),
    ("authority-secret-pipeline", "broker-wrong-answer"),
    ("authority-secret-pipeline", "use-count-only-injected"),
    ("authority-secret-pipeline", "intent-durable-before-read"),
    ("authority-secret-pipeline", "one-backend-read"),
    ("authority-secret-pipeline", "one-shot-handoff"),
    ("authority-secret-pipeline", "replay"),
    ("authority-secret-pipeline", "use-count"),
    ("authority-secret-pipeline", "durable-state"),
    ("authority-secret-pipeline", "crash-R1-before-metadata"),
    ("authority-secret-pipeline", "process-stdout-live-value"),
    ("authority-secret-pipeline", "process-stderr-live-value"),
    ("authority-secret-pipeline", "audit-redaction-hit-no-bytes"),
    ("authority-secret-pipeline", "policy-gate"),
    ("authority-secret-pipeline", "obligation-unenforceable"),
    ("authority-secret-pipeline", "crash-R9-output-before-redaction"),
    ("authority-secret-pipeline", "crash-R2-after-metadata"),
    ("authority-secret-pipeline", "crash-R3-after-intent"),
    ("authority-secret-pipeline", "crash-R4-backend-returned"),
    ("authority-secret-pipeline", "crash-R5-redaction-registered"),
    ("authority-secret-pipeline", "crash-R6-descriptor-created"),
    ("authority-secret-pipeline", "crash-R8-broker-may-have-consumed"),
    ("authority-secret-pipeline", "crash-R10-outcome-before-durable"),
    ("authority-secret-pipeline", "crash-S9-durable-before-response"),
    ("broker-secret-primitives", "broker-rlimit-core"),
    ("broker-secret-primitives", "broker-not-dumpable"),
    ("broker-secret-primitives", "crash-r7-broker-after-read"),
    ("broker-secret-primitives", "egress-render-one-descriptor"),
    ("broker-secret-primitives", "egress-descriptor-reused-after-consumption"),
    ("broker-secret-primitives", "egress-replay-new-connection"),
    ("broker-secret-primitives", "egress-broker-residue"),
    ("broker-secret-primitives", "egress-hostile-missing"),
    ("broker-secret-primitives", "egress-hostile-extra"),
    ("broker-secret-primitives", "egress-hostile-directory"),
    ("broker-secret-primitives", "egress-hostile-regular-file"),
    ("broker-secret-primitives", "egress-hostile-writable"),
    ("broker-secret-primitives", "egress-hostile-stalled-writer-open"),
    ("broker-secret-primitives", "egress-hostile-zero-length"),
    ("broker-secret-primitives", "egress-hostile-oversized"),
    ("broker-secret-primitives", "egress-hostile-carriage-return"),
    ("broker-secret-primitives", "egress-hostile-line-feed"),
    ("broker-secret-primitives", "egress-hostile-nul"),
    ("broker-secret-primitives", "egress-malformed-old-private-version"),
    ("broker-secret-primitives", "egress-malformed-unknown-kind"),
    ("broker-secret-primitives", "egress-malformed-header-with-space"),
    ("broker-secret-primitives", "egress-malformed-value-field"),
    ("broker-secret-primitives", "egress-malformed-mode-field"),
    ("broker-secret-primitives", "spawn-missing-secret-descriptor"),
    ("broker-secret-primitives", "spawn-descriptors-reversed"),
    ("broker-secret-primitives", "egress-authority-disconnects"),
    ("broker-secret-primitives", "spawn-env-nul"),
    ("broker-secret-primitives", "spawn-env-ld-preload"),
    ("broker-secret-primitives", "mode-b-target-environment-only"),
    ("broker-secret-primitives", "mode-b-echo-redacted-across-writes"),
    ("broker-secret-primitives", "mode-c-target-fd3"),
    ("broker-secret-primitives", "mode-c-grandchild-inheritance"),
    ("broker-secret-primitives", "mode-c-echo-redacted-while-drained"),
    ("broker-secret-primitives", "mode-c-residue"),
    ("broker-secret-primitives", "mode-b-residue"),
    # A file's bytes, read through fs.read, are gone from the broker once the
    # exchange has closed: heap- and mapping-sized bounds, and repeated reads.
    ("broker-secret-primitives", "fs-read-residue-bound-64"),
    ("broker-secret-primitives", "fs-read-residue-bound-4096"),
    ("broker-secret-primitives", "fs-read-residue-bound-65536"),
    ("broker-secret-primitives", "fs-read-residue-bound-100000"),
    ("broker-secret-primitives", "fs-read-residue-bound-131072"),
    ("broker-secret-primitives", "fs-read-residue-bound-262144"),
    ("broker-secret-primitives", "fs-read-residue-repeated"),
    ("authority-secret", "authority-rlimit-core"),
    ("authority-secret", "authority-not-dumpable"),
    ("authority-secret", "mode-a-real-broker"),
    ("authority-secret", "mode-a-one-shot"),
    ("authority-secret", "mode-a-authority-residue"),
    ("authority-secret", "mode-a-broker-residue"),
    ("authority-secret", "mode-a-durable-state-scan"),
    # M5c D11 (ADR-0050 §§8, 20): an echoed credential, by the way it comes
    # back -- the runtime's answer, the authority's process and the broker's
    # own encoding clean (asserted); the broker's library buffers measured.
    *(
        ("authority-secret", f"mode-a-echo-{kind}{path}")
        for path in (
            "body",
            "chunked-body",
            "straddling-the-bound",
            "past-the-bound",
            "kept-header",
            "dropped-header",
            "location",
            "malformed",
            "truncated",
        )
        for kind in ("", "broker-library-residue-")
    ),
    ("authority-secret", "mode-a-echo-audited"),
    ("authority-secret", "mode-a-echo-durable-state-scan"),
    ("authority-secret", "return-path-fs-read-live-value"),
    ("authority-secret", "return-path-binary-around-value"),
    ("authority-secret", "return-path-across-read-boundary"),
    ("authority-secret", "return-path-shape-github"),
    ("authority-secret", "return-path-shape-openai"),
    ("authority-secret", "return-path-shape-slack"),
    ("authority-secret", "return-path-shape-aws"),
    ("authority-secret", "return-path-shape-jwt"),
    ("authority-secret", "return-path-shape-pem_private_key"),
    ("authority-secret", "return-path-shape-connection_string"),
    ("authority-secret", "return-path-shape-keyword"),
    ("authority-secret", "return-path-transformed-value"),
    ("authority-secret", "runtime-address-space"),
    ("authority-secret", "authority-residue-after-redaction"),
    ("authority-secret", "broker-residue-after-fs-read"),
    ("authority-secret", "audit-redaction-hit"),
    ("authority-secret", "daemon-logs-scan"),
    ("authority-secret", "durable-state-scan"),
)

# The three-identity half and the core-dump contract: `#[ignore]`d, selected
# BY NAME, required to run every test and report every case.
SECRET_FOREIGN_TESTS = (
    "linux::three_identities_keep_the_value_from_the_broker_store_and_the_runtime",
    "linux::a_crashing_hardened_daemon_writes_no_core_where_a_dumpable_process_does",
)
SECRET_FOREIGN_CASES = (
    ("authority-secret", "broker-uid-cannot-read-metadata"),
    ("authority-secret", "broker-uid-cannot-read-age-store"),
    ("authority-secret", "broker-uid-keyring-has-no-value"),
    ("authority-secret", "broker-uid-cannot-read-the-key-by-serial"),
    ("authority-secret", "runtime-uid-cannot-read-metadata"),
    ("authority-secret", "runtime-uid-cannot-read-age-store"),
    ("authority-secret", "runtime-uid-keyring-has-no-value"),
    ("authority-secret", "runtime-uid-cannot-read-the-key-by-serial"),
    ("authority-secret", "runtime-uid-receives-placeholder"),
    ("authority-secret", "runtime-memory-root-scan"),
    ("authority-secret", "authority-memory-root-scan"),
    ("authority-secret", "broker-memory-root-scan"),
    ("authority-secret", "runtime-uid-cannot-reach-broker"),
    ("authority-secret", "core-dump-control"),
    ("authority-secret", "core-dump-hardened-broker-and-authority"),
)


def task_secret_broker_evidence() -> None:
    """M4e's secret evidence (ADR-0046); the three-identity half needs
    DW_BROKER_AS and DW_PEER_AS, and the core-dump contract DW_M4E_CORE_EVIDENCE=1.

    The same-identity suites run first: the public protocol corpus (no member
    for secret material), private protocol version 4, the metadata grammar,
    the real keyring and age backends, redaction, the authority's mode A state
    machine against a fake broker (labelled so), the broker's own secret unit
    tests, the real broker binary's secret primitives, and the real daemons
    with a separate runtime process. Every case must report; every suite must
    have run at least one test. The authority's suites run in a fresh session
    keyring (`fresh_session_keyring`): like a service, or a CI runner, they
    possess no user keyring, so a keychain key is read with its owner's bits
    alone -- the provisioning contract -- on every machine, and the cases that
    only a non-possessing process can observe always run. Then, selected by name, three genuine
    identities -- the store and keyring closed to the broker's and the
    runtime's uids, the runtime's placeholder, root reading the hardened
    daemons' and the runtime's memory -- and the core-dump contract, which
    changes kernel.core_pattern for its duration and so runs only where
    DW_M4E_CORE_EVIDENCE=1 says it may.

    Without the identities, or without the core opt-in, that half is NOT
    EXERCISED and this task fails after running everything else. Linux only.
    """
    if not sys.platform.startswith("linux"):
        raise TaskError(
            "NOT EXERCISED: the secret evidence runs only on Linux (ADR-0046); use WSL2 on Windows"
        )
    # Mode A's consumer is net.http (ADR-0050 §8): its cases need the same
    # local HTTPS origins as the net.http evidence.
    missing = unusable_tool()
    if missing is not None:
        raise TaskError(
            f"NOT EXERCISED: mode A's consumer needs bash, openssl and python3: {missing}"
        )
    broker_user = os.environ.get("DW_BROKER_AS", "").strip()
    peer_user = os.environ.get("DW_PEER_AS", "").strip()
    core = os.environ.get("DW_M4E_CORE_EVIDENCE", "").strip() == "1"
    identities = bool(broker_user and peer_user)
    if identities:
        _, _, broker_uid = second_identity("DW_BROKER_AS")
        _, _, peer_uid = second_identity("DW_PEER_AS")
        if broker_uid == peer_uid:
            raise TaskError(
                f"DW_BROKER_AS={broker_user} and DW_PEER_AS={peer_user} are both uid {peer_uid}: "
                "the broker and the hostile runtime must be two identities"
            )
    run("cargo", "build", "--locked", "-p", "dwkd-broker")
    # The public protocol corpus: no member for secret material. A failure
    # stops the task here (`uvrun` raises).
    uvrun("pytest", "-q", "-p", "no:cacheprovider", "tests/protocol/test_no_secret_value_fields.py")
    suites = [
        run_captured(
            "cargo", "test", "--locked", "-p", "dwk-proto", "--lib", "secret", "--", "--nocapture"
        ),
        run_captured(
            "cargo",
            "test",
            "--locked",
            "-p",
            "dwkd-authority",
            "--lib",
            "secret::",
            "--",
            "--nocapture",
            fresh_keyring=True,
        ),
        run_captured(
            "cargo",
            "test",
            "--locked",
            "-p",
            "dwkd-authority",
            "--lib",
            "state::secret_use",
            "--",
            "--nocapture",
            fresh_keyring=True,
        ),
        run_captured(
            "cargo",
            "test",
            "--locked",
            "-p",
            "dwkd-broker",
            "--bins",
            "secret",
            "--",
            "--nocapture",
        ),
        run_captured(
            "cargo",
            "test",
            "--locked",
            "-p",
            "dwkd-broker",
            "--test",
            "secret_primitives",
            "--",
            "--nocapture",
        ),
        run_captured(
            "cargo",
            "test",
            "--locked",
            "-p",
            "dwkd-authority",
            "--test",
            "secret_evidence",
            "--",
            "--nocapture",
            "--test-threads=1",
            fresh_keyring=True,
        ),
    ]
    for output in suites:
        require_tests_ran(output)
    require_secret_evidence("\n".join(suites), SECRET_CASES)
    if identities and core:
        foreign = run_captured(
            "cargo",
            "test",
            "--locked",
            "-p",
            "dwkd-authority",
            "--test",
            "secret_evidence",
            "--",
            "--ignored",
            "--exact",
            "--nocapture",
            "--test-threads=1",
            *SECRET_FOREIGN_TESTS,
            fresh_keyring=True,
        )
        summaries = [line for line in foreign.splitlines() if line.startswith("test result: ")]
        expected = f"test result: ok. {len(SECRET_FOREIGN_TESTS)} passed; 0 failed; 0 ignored"
        if len(summaries) != 1 or not summaries[0].startswith(expected):
            raise TaskError(
                f"the three-identity secret suite did not run all of its tests: expected "
                f"`{expected}`, got {summaries or 'no summary'}"
            )
        require_secret_evidence(foreign, SECRET_FOREIGN_CASES)
    uvrun("dwcheck", "closure", "--report")
    if not (identities and core):
        raise TaskError(
            "NOT EXERCISED: the three-identity half needs DW_BROKER_AS (the broker's own user) and "
            "DW_PEER_AS (a hostile local user), and the core-dump contract DW_M4E_CORE_EVIDENCE=1 "
            "(it changes kernel.core_pattern); every same-identity suite above ran"
        )


def require_secret_evidence(output: str, cases: tuple[tuple[str, str], ...]) -> None:
    """Every (suite, case) must have printed its SECRET-EVIDENCE line, exercised."""
    if not cases:
        raise TaskError("secret evidence: zero cases required")
    reported: set[tuple[str, str]] = set()
    for line in output.splitlines():
        at = line.find(SECRET_EVIDENCE_PREFIX)
        if at < 0:
            continue
        try:
            record = json.loads(line[at + len(SECRET_EVIDENCE_PREFIX) :])
        except json.JSONDecodeError as exc:
            raise TaskError(f"unreadable evidence line: {line[:200]}") from exc
        if not isinstance(record, dict) or not record.get("outcome") or not record.get("suite"):
            raise TaskError(f"malformed evidence line: {line[:200]}")
        if str(record["outcome"]).lower().startswith("not-exercised"):
            continue
        reported.add((str(record["suite"]), str(record.get("case"))))
    if not reported:
        raise TaskError("secret evidence: zero cases reported")
    missing = [f"{suite}/{case}" for suite, case in cases if (suite, case) not in reported]
    if missing:
        raise TaskError(
            f"{len(missing)} secret evidence case(s) did not report: " + ", ".join(missing[:40])
        )


def require_tests_ran(output: str) -> None:
    """Every `test result:` line passed, and at least one test ran in all."""
    summaries = [line for line in output.splitlines() if line.startswith("test result: ")]
    passed = 0
    for summary in summaries:
        match = re.match(r"test result: ok\. (\d+) passed; 0 failed;", summary)
        if match is None:
            raise TaskError(f"a suite did not pass: {summary}")
        passed += int(match.group(1))
    if passed == 0:
        raise TaskError(f"a suite ran zero tests: {summaries or 'no summary'}")


# --- M5a: the sandbox foundation (ADR-0047) ---------------------------------

SANDBOX_EVIDENCE_PREFIX = "SANDBOX-EVIDENCE "

# M5e.2 (R2, R3): the broker's own host judgement and decision, in process --
# one nonconforming record at a time under each topology, each refused. Never
# a container's measurement: the real weakened containers of M5a are
# NO_NETWORK's, and no weakened PROXY_ONLY container is built here.
ASSURANCE_EVIDENCE_PREFIX = "ASSURANCE-EVIDENCE "
BROKER_ASSURANCE_TEST = (
    "sandbox::inspect::tests::"
    "every_hard_rule_is_refused_in_proxy_only_and_host_uts_in_both_topologies"
)
BROKER_ASSURANCE_CASES = tuple(
    ("broker-assurance", case)
    for case in (
        "no-network-conforming-kept",
        "proxy-only-conforming-kept",
        "no-network-weakened-host-uts-refused",
        "proxy-only-weakened-host-uts-refused",
        "proxy-only-weakened-writable-root-refused",
        "proxy-only-weakened-root-user-refused",
        "proxy-only-weakened-privileged-refused",
        "proxy-only-weakened-capability-added-refused",
        "proxy-only-weakened-no-new-privileges-disabled-refused",
        "proxy-only-weakened-seccomp-unconfined-refused",
        # ADR-0057 §3, U4: the runtime's default profile, as the real
        # NO_NETWORK case leaves it; and the swap limit, alone and with the
        # pids limit as that case lifts both.
        "proxy-only-weakened-seccomp-default-profile-refused",
        "proxy-only-weakened-host-pid-refused",
        "proxy-only-weakened-host-ipc-refused",
        "proxy-only-weakened-host-network-refused",
        "proxy-only-weakened-mutable-image-tag-refused",
        "proxy-only-weakened-runtime-socket-mounted-refused",
        "proxy-only-weakened-extra-device-refused",
        "proxy-only-weakened-resource-limits-dropped-refused",
        "proxy-only-weakened-swap-limit-lifted-refused",
        "proxy-only-weakened-pids-and-swap-limits-lifted-refused",
    )
)
# M5e.2 (R3) against a real runtime's own record: the egress evidence keeps
# the record the runtime holds of a real PROXY_ONLY environment the broker
# prepared and measured clean (`DW_CAPTURED_RECORD_DIR`), then the broker's
# production judgement keeps it and refuses each hard rule broken in it, in
# process. Still `in-process`: the runtime never ran a weakened record, and
# no weakened PROXY_ONLY container is built.
CAPTURED_ASSURANCE_TEST = (
    "sandbox::inspect::tests::"
    "a_real_proxy_only_record_is_kept_and_each_hard_rule_broken_in_it_refused"
)
# The fixed directory the test reads, emptied before and after: the
# broker's source reads no variable (TX042), so its path is the crate's own.
CAPTURED_RECORD_DIR = ROOT / "target" / "m5e-captured-proxy-only"
CAPTURED_ASSURANCE_CASES = tuple(
    ("broker-assurance", f"captured-{case}")
    for _, case in (
        *(c for c in BROKER_ASSURANCE_CASES if c[1].startswith("proxy-only-")),
        ("broker-assurance", "proxy-only-weakened-task-backstop-at-256-refused"),
    )
)

# A convenience alias for the evidence image, and nothing more: every decision
# and every record binds the image's content identity, and the one test that
# names this tag does so to show that a container created from a tag is caught.
SANDBOX_IMAGE_TAG = "direwolf/sandbox-evidence:m5a"

# The broker and authority suites that need a real OCI runtime. Each is
# `#[ignore]`d, selected here by name, and required to run every test.
SANDBOX_BROKER_TESTS = (
    "linux::the_strict_profile_measures_clean_from_both_vantages_and_is_destroyed_exactly",
    "linux::every_weakened_profile_is_detected",
    "linux::a_tampered_probe_is_never_believed_and_never_leaves_a_container",
    "linux::foreign_containers_survive_listing_measurement_and_destruction",
    "linux::drift_is_measured_from_both_vantages",
    "linux::temporary_state_does_not_persist_and_two_runs_are_isolated",
    "linux::exit_semantics_distinguish_stopped_gone_unreachable_and_unavailable",
    "linux::a_broker_crash_after_creation_leaves_only_a_labelled_reapable_container",
    "linux::resource_limits_hold_under_bounded_pressure",
    "linux::latency_of_prepare_measure_and_destroy",
)
SANDBOX_AUTHORITY_TESTS = (
    "linux::the_lifecycle_is_durable_before_every_effect",
    "linux::reconciliation_after_crashes_reaps_exactly_and_spares_foreign_containers",
    "linux::drift_found_by_the_authority_destroys_the_environment",
)

# Every (suite, case) the real-container suites must report, exercised.
SANDBOX_CASES = (
    ("sandbox-broker", "prepare-clean"),
    ("sandbox-broker", "runtime-version-reported"),
    *(
        ("sandbox-broker", case)
        for case in (
            "host-image-pinned",
            "host-probe-digest",
            "host-not-privileged",
            "host-user-non-root",
            "host-root-read-only",
            "host-capabilities-dropped",
            "host-no-new-privileges",
            "host-seccomp-profile",
            "host-pid-private",
            "host-ipc-private",
            "host-uts-private",
            "host-network-isolated",
            "host-mounts-exact",
            "host-no-runtime-socket",
            "host-no-devices",
            "host-resource-limits",
            "host-labels-exact",
            "host-workspace-identity",
            "container-uid-gid",
            "container-capabilities-empty",
            "container-no-new-privileges",
            "container-seccomp-filter",
            "container-seccomp-profile-active",
            "container-root-read-only",
            "container-workspace-writable",
            "container-tmp-writable",
            "container-no-runtime-socket",
            "container-devices-minimal",
            "container-pid-private",
            "container-network-isolated",
            "container-rlimits",
            "container-cgroup-limits",
            "container-proc-restricted",
            "escape-mount-blocked",
            "escape-unshare-blocked",
            "escape-setns-blocked",
            "escape-keyring-blocked",
        )
    ),
    ("sandbox-broker", "measure-clean-again"),
    ("sandbox-broker", "list-owned-exact-labels"),
    ("sandbox-broker", "destroy-removed"),
    ("sandbox-broker", "destroy-already-gone"),
    *(
        ("sandbox-broker", case)
        for case in (
            "baseline-conforming",
            "weakened-writable-root",
            "weakened-root-user",
            "weakened-privileged",
            "weakened-runtime-socket-mounted",
            "weakened-capability-added",
            "weakened-no-new-privileges-disabled",
            "weakened-seccomp-unconfined",
            "weakened-seccomp-default-profile",
            "weakened-host-pid",
            "weakened-host-ipc",
            "weakened-host-uts",
            "weakened-host-network",
            "weakened-mutable-image-tag",
            "weakened-extra-device",
            "weakened-resource-limits-dropped",
        )
    ),
    ("sandbox-broker", "weakened-count"),
    *(
        ("sandbox-broker", case)
        for case in (
            "tamper-changed-byte",
            "tamper-substituted-probe",
            "tamper-malformed-output",
            "tamper-truncated-output",
            "tamper-extra-field",
            "tamper-flood-output",
            "tamper-hang-timeout",
        )
    ),
    *(
        ("sandbox-broker", case)
        for case in (
            "foreign-not-listed",
            "foreign-destroy-refused",
            "foreign-measure-refused",
            "foreign-survive",
            "destroy-by-label-exact",
        )
    ),
    ("sandbox-broker", "drift-pids-limit-raised"),
    ("sandbox-broker", "run-isolation-distinct-environments"),
    ("sandbox-broker", "run-isolation-tmp"),
    ("sandbox-broker", "run-isolation-destroy-one-leaves-other"),
    ("sandbox-broker", "persistence-tmp-marker-not-inherited"),
    ("sandbox-broker", "exit-stopped-unobservable-inside"),
    ("sandbox-broker", "exit-gone-not-found"),
    ("sandbox-broker", "exit-runtime-unavailable"),
    ("sandbox-broker", "exit-image-missing-never-pulled"),
    ("sandbox-broker", "topology-proxy-only-needs-its-grant"),
    ("sandbox-broker", "topology-no-network-needs-evidence-flag"),
    ("sandbox-broker", "refusals-create-nothing"),
    ("sandbox-broker", "crash-w3-broker-after-create-labelled"),
    ("sandbox-broker", "crash-w3-reaped-by-label"),
    ("sandbox-broker", "resource-pids-bounded"),
    ("sandbox-broker", "resource-fds-bounded"),
    ("sandbox-broker", "resource-memory-oom-killed"),
    ("sandbox-broker", "resource-file-size-bounded"),
    ("sandbox-broker", "subprocess-and-thread-creation"),
    ("sandbox-broker", "latency"),
    ("sandbox-authority", "prepare-intent-durable-before-broker"),
    ("sandbox-authority", "prepare-ready-recorded"),
    ("sandbox-authority", "effective-assurance-container-isolation"),
    ("sandbox-authority", "one-environment-per-run"),
    ("sandbox-authority", "measure-clean"),
    ("sandbox-authority", "destroy-intent-durable-before-broker"),
    ("sandbox-authority", "destroy-recorded"),
    ("sandbox-authority", "destroy-idempotent"),
    ("sandbox-authority", "audit-lifecycle"),
    ("sandbox-authority", "crash-w2-after-intent-lost"),
    ("sandbox-authority", "crash-w4-after-broker-reaped"),
    ("sandbox-authority", "crash-w6-destroy-intent-completed"),
    ("sandbox-authority", "orphan-ended-record-reaped"),
    ("sandbox-authority", "foreign-copied-labels-survive"),
    ("sandbox-authority", "foreign-unrelated-survive"),
    ("sandbox-authority", "ambiguous-twins-untouched"),
    ("sandbox-authority", "drift-destroyed"),
)


def _static_elf(path: Path) -> str:
    """How `path` links, from its ELF headers: `static` or `static-pie`.

    Raises TaskError for anything that would need a loader or a shared
    library inside a `FROM scratch` image: a `PT_INTERP`, or a `DT_NEEDED`.
    """
    data = path.read_bytes()
    if data[:4] != b"\x7fELF" or data[4] != 2 or data[5] != 1:
        raise TaskError(f"{path}: not a 64-bit little-endian ELF file")
    e_type = int.from_bytes(data[16:18], "little")
    phoff = int.from_bytes(data[32:40], "little")
    phentsize = int.from_bytes(data[54:56], "little")
    phnum = int.from_bytes(data[56:58], "little")
    dynamic = None
    for index in range(phnum):
        at = phoff + index * phentsize
        p_type = int.from_bytes(data[at : at + 4], "little")
        if p_type == 3:  # PT_INTERP
            raise TaskError(f"{path}: has an interpreter; it is not static")
        if p_type == 2:  # PT_DYNAMIC
            offset = int.from_bytes(data[at + 8 : at + 16], "little")
            size = int.from_bytes(data[at + 32 : at + 40], "little")
            dynamic = (offset, size)
    if dynamic is not None:
        offset, size = dynamic
        for at in range(offset, offset + size, 16):
            tag = int.from_bytes(data[at : at + 8], "little")
            if tag == 0:  # DT_NULL
                break
            if tag == 1:  # DT_NEEDED
                raise TaskError(f"{path}: needs a shared library; it is not static")
    if e_type == 3:  # ET_DYN without an interpreter: static-pie
        return "static-pie"
    if e_type == 2:
        return "static"
    raise TaskError(f"{path}: ELF type {e_type} is not an executable")


def _one_byte_changed(source: Path, target: Path) -> int:
    """Copy `source` to `target` with one byte of its section header table
    flipped -- bytes the loader never reads, so the copy still runs, and a
    different file. Returns the offset changed."""
    data = bytearray(source.read_bytes())
    shoff = int.from_bytes(data[40:48], "little")
    shentsize = int.from_bytes(data[58:60], "little")
    shnum = int.from_bytes(data[60:62], "little")
    if shoff == 0 or shoff + shentsize * shnum != len(data):
        raise TaskError(f"{source}: the section header table is not the file's last bytes")
    offset = len(data) - 1
    data[offset] ^= 0x01
    target.write_bytes(bytes(data))
    target.chmod(0o755)
    return offset


def _trusted_client(found: Path, into: Path) -> tuple[Path, str]:
    """The runtime client the evidence hands the broker, and how it was chosen.

    The broker re-proves the client against M4's executable contract: owner
    root or this uid, no group or other write, no set-id bit, on a trusted
    filesystem. A client that meets it is used where it is; one that does not
    (Docker Desktop's WSL client is mode 0775 on an ISO9660 mount) is copied,
    byte for byte, into a private directory this uid owns -- what an operator
    does to install a trusted client -- and the copy's digest is the one the
    evidence pins. The contract is never relaxed.
    """
    uid = os.getuid()
    real = found.resolve()

    def trusted(path: Path) -> bool:
        st = path.stat()
        if st.st_uid not in (0, uid) or st.st_mode & 0o6022:
            return False
        for parent in path.parents:
            pst = parent.stat()
            sticky = pst.st_mode & 0o1000
            if pst.st_uid not in (0, uid) or (pst.st_mode & 0o022 and not sticky):
                return False
        mounts = Path("/proc/self/mounts").read_text(encoding="utf-8", errors="replace")
        best = ("", "")
        for line in mounts.splitlines():
            fields = line.split()
            if (
                len(fields) >= 3
                and str(path).startswith(fields[1])
                and len(fields[1]) > len(best[0])
            ):
                best = (fields[1], fields[2])
        return best[1] not in ("9p", "v9fs", "nfs", "nfs4", "cifs", "smb3", "fuse", "iso9660")

    if trusted(real):
        return real, f"{real} (used where it is)"
    into.mkdir(mode=0o700, parents=True, exist_ok=True)
    copy = into / "docker"
    shutil.copyfile(real, copy)
    copy.chmod(0o755)
    if not trusted(copy):
        raise TaskError(f"cannot install a trusted copy of {real} at {copy}")
    return copy, f"{copy} (a copy of {real}, which the executable contract refuses)"


def _docker(client: Path, socket: str, *args: str, check: bool = True) -> str:
    """The runtime client, as the evidence's own setup runs it -- never the
    broker's path: explicit host, no inherited configuration."""
    result = subprocess.run(
        [str(client), "--host", f"unix://{socket}", *args],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    if check and result.returncode != 0:
        raise TaskError(f"`docker {' '.join(args)}` failed: {result.stderr.strip()[:400]}")
    return result.stdout


def _build_image(
    client: Path,
    socket: str,
    context: Path,
    binary: Path,
    platform_: str,
    fixture: str | None,
    extra: dict[str, Path] | None = None,
) -> str:
    """One `FROM scratch` image holding `binary` at the probe's path -- and,
    for M5b, `extra` files at their paths (the relay, the egress evidence's
    workload fixture): built offline from local bytes, its identity the
    content digest the runtime returns. Nothing is pulled."""
    shutil.rmtree(context, ignore_errors=True)
    context.mkdir(parents=True)
    shutil.copyfile(binary, context / "sandbox-probe")
    lines = [
        "FROM scratch",
        "COPY --chmod=0755 sandbox-probe /usr/libexec/direwolf/sandbox-probe",
    ]
    for target, source in (extra or {}).items():
        name = Path(target).name
        shutil.copyfile(source, context / name)
        lines.append(f"COPY --chmod=0755 {name} {target}")
    if fixture is not None:
        lines.append(f"ENV DW_FIXTURE={fixture}")
    (context / "Dockerfile").write_text("\n".join(lines) + "\n", encoding="utf-8")
    iid = context / "iid"
    _docker(
        client,
        socket,
        "build",
        "--quiet",
        "--pull=false",
        "--network",
        "none",
        "--platform",
        platform_,
        "--iidfile",
        str(iid),
        str(context),
    )
    image = iid.read_text(encoding="utf-8").strip()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
        raise TaskError(f"the built image has no content identity: {image!r}")
    return image


# The real tools the hygiene evidence runs (M5d.2, ADR-0052 §5a), at their
# paths in the tools image.
TOOLS_GIT_PATH = "/usr/bin/git"
TOOLS_PYTEST_PATH = "/usr/local/bin/pytest"
# The pure-Python packages pytest needs, taken from the locked environment.
TOOLS_PYTEST_PACKAGES = (
    "pytest",
    "_pytest",
    "pluggy",
    "iniconfig",
    "packaging",
    "pygments",
    "py.py",
)
# A marker git reads from the image's system configuration: what
# `GIT_CONFIG_NOSYSTEM` must keep it from reading.
TOOLS_GIT_SYSTEM_MARKER = "system"


def _ldd_closure(binaries: list[Path]) -> set[Path]:
    """Every shared object `binaries` load, and the loader, as the host's
    `ldd` names them: what a `FROM scratch` image must hold for them to run."""
    found: set[Path] = set()
    for binary in binaries:
        out = subprocess.run(
            ["ldd", str(binary)], capture_output=True, text=True, check=False
        ).stdout
        for line in out.splitlines():
            words = line.split()
            if "=>" in words:
                path = words[words.index("=>") + 1]
            elif words and words[0].startswith("/"):
                path = words[0]
            else:
                continue
            if path.startswith("/"):
                found.add(Path(path))
    return found


def _place(rootfs: Path, source: Path, target: str, mode: int | None = None) -> None:
    """Copy `source`'s bytes -- through any symlink -- to `target` under
    `rootfs`."""
    destination = rootfs / target.lstrip("/")
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source.resolve(), destination)
    shutil.copymode(source.resolve(), destination)
    if mode is not None:
        destination.chmod(mode)


def _tools_image(
    client: Path,
    socket: str,
    context: Path,
    binaries: tuple[Path, Path],
    platform_: str,
    relay: Path | None = None,
) -> tuple[str, dict[str, str]]:
    """M5d.2's tools image (ADR-0052 §5a): the probe and the fixture, the
    host's real `git` and Python with its standard library, pytest from the
    locked environment, every shared object they load, and a system git
    configuration carrying a marker -- built offline `FROM scratch` from
    local bytes and named by content. With `relay` (M5d.5), the pinned relay
    too, at its path: the image a `PROXY_ONLY` environment needs. Returns
    the image and the variables the suites read (paths and digests). Without
    git or Python: NOT EXERCISED."""
    probe, fixture = binaries
    git = Path(TOOLS_GIT_PATH)
    python_link = Path("/usr/bin/python3")
    if not git.exists() or not python_link.exists():
        raise TaskError(
            "NOT EXERCISED: the hygiene evidence needs the host's /usr/bin/git and python3"
        )
    python = python_link.resolve()
    if not re.fullmatch(r"python3\.\d+", python.name) or python.parent != Path("/usr/bin"):
        raise TaskError(
            f"NOT EXERCISED: /usr/bin/python3 resolves to {python}, not /usr/bin/python3.N"
        )
    stdlib = Path("/usr/lib") / python.name
    found = subprocess.run(
        [
            _uv_bin(),
            "run",
            "--frozen",
            "python",
            "-c",
            "import os, pytest; print(os.path.dirname(os.path.dirname(pytest.__file__)))",
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    site = Path(found.stdout.strip())
    if found.returncode != 0 or not (site / "pytest").is_dir():
        raise TaskError("NOT EXERCISED: pytest is not in the locked environment")
    shutil.rmtree(context, ignore_errors=True)
    rootfs = context / "rootfs"
    rootfs.mkdir(parents=True)
    _place(rootfs, probe, "/usr/libexec/direwolf/sandbox-probe", 0o755)
    _place(rootfs, fixture, SANDBOX_FIXTURE_PATH, 0o755)
    if relay is not None:
        _place(rootfs, relay, SANDBOX_RELAY_PATH, 0o755)
    _place(rootfs, git, TOOLS_GIT_PATH, 0o755)
    _place(rootfs, python, str(python), 0o755)
    shutil.copytree(
        stdlib,
        rootfs / str(stdlib).lstrip("/"),
        symlinks=False,
        ignore=shutil.ignore_patterns(
            "__pycache__", "test", "tests", "idlelib", "tkinter", "turtledemo", "ensurepip"
        ),
        ignore_dangling_symlinks=True,
    )
    packages = rootfs / "usr/lib/python3/dist-packages"
    packages.mkdir(parents=True, exist_ok=True)
    for name in TOOLS_PYTEST_PACKAGES:
        source = site / name
        if source.is_dir():
            shutil.copytree(source, packages / name, ignore=shutil.ignore_patterns("__pycache__"))
        elif source.is_file():
            shutil.copyfile(source, packages / name)
    pytest = rootfs / TOOLS_PYTEST_PATH.lstrip("/")
    pytest.parent.mkdir(parents=True, exist_ok=True)
    pytest.write_text(
        f"#!{python}\nimport sys\nfrom pytest import console_main\nsys.exit(console_main())\n",
        encoding="utf-8",
    )
    pytest.chmod(0o755)
    loaded = [git, python, *sorted((stdlib / "lib-dynload").glob("*.so"))]
    for library in sorted(_ldd_closure(loaded)):
        _place(rootfs, library, str(library))
    gitconfig = rootfs / "etc/gitconfig"
    gitconfig.parent.mkdir(parents=True, exist_ok=True)
    gitconfig.write_text(f"[direwolf]\n\tmarker = {TOOLS_GIT_SYSTEM_MARKER}\n", encoding="utf-8")
    (context / "Dockerfile").write_text("FROM scratch\nCOPY rootfs/ /\n", encoding="utf-8")
    iid = context / "iid"
    _docker(
        client,
        socket,
        "build",
        "--quiet",
        "--pull=false",
        "--network",
        "none",
        "--platform",
        platform_,
        "--iidfile",
        str(iid),
        str(context),
    )
    image = iid.read_text(encoding="utf-8").strip()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
        raise TaskError(f"the built image has no content identity: {image!r}")

    def digest(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    variables = {
        "DW_SANDBOX_TOOLS_IMAGE": image,
        "DW_SANDBOX_GIT_SHA256": digest(git.resolve()),
        "DW_SANDBOX_PYTHON": str(python),
        "DW_SANDBOX_PYTHON_SHA256": digest(python),
        "DW_SANDBOX_PYTEST_SHA256": digest(pytest),
    }
    return image, variables


def task_sandbox_foundation_evidence() -> None:
    """M5a's real-container evidence (ADR-0047): a real OCI runtime, real
    containers, the real broker -- and, for the lifecycle, the real authority.

    Setup first, and separate from the evidence: the probe and the fixture are
    built statically and proved static from their ELF headers; their digests
    are pinned; the evidence images are built offline `FROM scratch` and
    named by content; a trusted runtime client is chosen. Then the broker's
    and the authority's real-container suites run, every case must report at
    its level with what enforced it (M5e.1, `require_attributed_evidence`),
    no container the evidence made may remain, and every container that was
    there before must still be there.

    First, in process (M5e.2, R2 and R3): the broker's own host judgement and
    its own decision, given one nonconforming record at a time -- every hard
    rule judged under `PROXY_ONLY` as under `NO_NETWORK`, host UTS under both
    -- each refused, each line `in-process`, never offered as a container's
    measurement.

    No reachable runtime, no container, no measurement: NOT EXERCISED, which
    fails. Linux only.
    """
    if not sys.platform.startswith("linux"):
        raise TaskError("NOT EXERCISED: the sandbox evidence needs Linux and an OCI runtime")
    unit = run_captured(
        "cargo",
        "test",
        "--locked",
        "-p",
        "dwkd-broker",
        "--bin",
        "dwkd-broker",
        "--",
        BROKER_ASSURANCE_TEST,
        "--exact",
        "--nocapture",
        "--test-threads=1",
    )
    require_tests_ran(unit)
    require_attributed_evidence(unit, BROKER_ASSURANCE_CASES, ASSURANCE_EVIDENCE_PREFIX)
    found = shutil.which("docker")
    if found is None:
        raise TaskError("NOT EXERCISED: no container runtime client (`docker`) on PATH")
    socket = os.environ.get("DW_SANDBOX_SOCKET", "/var/run/docker.sock")
    target_root = Path(os.environ.get("CARGO_TARGET_DIR", str(ROOT / "target")))
    work = Path(os.environ.get("DW_SANDBOX_WORK", str(Path.home() / ".cache" / "dw-m5a")))
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(mode=0o700, parents=True)
    client, chosen = _trusted_client(Path(found), work / "client")
    try:
        server = json.loads(
            _docker(client, socket, "version", "--format", "{{json .Server}}").strip()
        )
    except (TaskError, json.JSONDecodeError) as exc:
        raise TaskError(f"NOT EXERCISED: the runtime at {socket} does not answer: {exc}") from exc
    if server.get("Os") != "linux":
        raise TaskError(f"NOT EXERCISED: the runtime is not a Linux one: {server.get('Os')}")
    arch = {"amd64": "x86_64", "arm64": "aarch64"}.get(str(server.get("Arch")))
    if arch is None:
        raise TaskError(f"the runtime's architecture {server.get('Arch')!r} is not supported")
    triple = f"{arch}-unknown-linux-gnu"
    platform_ = f"linux/{server.get('Arch')}"
    before = set(
        _docker(client, socket, "container", "ls", "--all", "--no-trunc", "--quiet").split()
    )

    # The probe and the fixture, static.
    static = target_root / "sandbox-static"
    env = dict(os.environ, RUSTFLAGS="-C target-feature=+crt-static")
    command = [
        "cargo",
        "build",
        "--locked",
        "--release",
        "-p",
        "dwk-sandbox-probe",
        "--bin",
        "dwk-sandbox-probe",
        "--example",
        "sandbox_fixture",
        "--target",
        triple,
        "--target-dir",
        str(static),
    ]
    print(f"{DIM}$ RUSTFLAGS='-C target-feature=+crt-static' {' '.join(command)}{OFF}", flush=True)
    if subprocess.run(command, cwd=str(ROOT), env=env, check=False).returncode != 0:
        raise TaskError("the static probe did not build")
    probe = static / triple / "release" / "dwk-sandbox-probe"
    fixture = static / triple / "release" / "examples" / "sandbox_fixture"
    linking = {name: _static_elf(path) for name, path in (("probe", probe), ("fixture", fixture))}
    probe_sha = hashlib.sha256(probe.read_bytes()).hexdigest()
    fixture_sha = hashlib.sha256(fixture.read_bytes()).hexdigest()
    changed = work / "probe-changed"
    offset = _one_byte_changed(probe, changed)

    images: dict[str, str] = {}
    for name, binary, variant in (
        ("real", probe, None),
        ("tampered-byte", changed, None),
        ("substituted", fixture, None),
        ("malformed", fixture, "malformed"),
        ("truncated", fixture, "truncated"),
        ("extra-field", fixture, "extra-field"),
        ("flood", fixture, "flood"),
        ("hang", fixture, "hang"),
        ("fixture", fixture, "none"),
    ):
        images[name] = _build_image(
            client, socket, work / "images" / name, binary, platform_, variant
        )
    _docker(client, socket, "image", "tag", images["real"], SANDBOX_IMAGE_TAG)
    inspected = json.loads(
        _docker(client, socket, "image", "inspect", "--format", "{{json .}}", images["real"])
    )
    if inspected.get("Architecture") != server.get("Arch") or inspected.get("Os") != "linux":
        raise TaskError(f"the evidence image is not linux/{server.get('Arch')}")

    print(f"{BOLD}sandbox evidence setup{OFF}")
    version = f"{server.get('Version')} (api {server.get('ApiVersion')})"
    print(f"  runtime            {version}, {platform_}")
    print(f"  runtime client     {chosen}")
    print(f"  probe              {linking['probe']}, sha256 {probe_sha}")
    print(f"  fixture            {linking['fixture']}, sha256 {fixture_sha}")
    print(f"  changed probe      one byte flipped at offset {offset}")
    print(f"  image (content id) {images['real']}  repo digests: {inspected.get('RepoDigests')}")
    for name, image in images.items():
        print(f"  image {name:<13}{image}")

    os.environ.update(
        {
            "DW_SANDBOX_RUNTIME": str(client),
            "DW_SANDBOX_SOCKET": socket,
            "DW_SANDBOX_IMAGE": images["real"],
            "DW_SANDBOX_IMAGE_TAG": SANDBOX_IMAGE_TAG,
            "DW_SANDBOX_PROBE_SHA256": probe_sha,
            "DW_SANDBOX_FIXTURE_SHA256": fixture_sha,
            "DW_SANDBOX_IMAGE_TAMPERED_BYTE": images["tampered-byte"],
            "DW_SANDBOX_IMAGE_SUBSTITUTED": images["substituted"],
            "DW_SANDBOX_IMAGE_MALFORMED": images["malformed"],
            "DW_SANDBOX_IMAGE_TRUNCATED": images["truncated"],
            "DW_SANDBOX_IMAGE_EXTRA_FIELD": images["extra-field"],
            "DW_SANDBOX_IMAGE_FLOOD": images["flood"],
            "DW_SANDBOX_IMAGE_HANG": images["hang"],
            "DW_SANDBOX_IMAGE_FIXTURE": images["fixture"],
        }
    )
    outputs: list[str] = []
    try:
        run("cargo", "build", "--locked", "-p", "dwkd-broker")
        for package, test, names in (
            ("dwkd-broker", "sandbox_foundation", SANDBOX_BROKER_TESTS),
            ("dwkd-authority", "sandbox_lifecycle", SANDBOX_AUTHORITY_TESTS),
        ):
            output = run_captured(
                "cargo",
                "test",
                "--locked",
                "-p",
                package,
                "--test",
                test,
                "--",
                "--ignored",
                "--exact",
                "--nocapture",
                "--test-threads=1",
                *names,
            )
            summaries = [line for line in output.splitlines() if line.startswith("test result: ")]
            expected = f"test result: ok. {len(names)} passed; 0 failed; 0 ignored"
            if len(summaries) != 1 or not summaries[0].startswith(expected):
                raise TaskError(
                    f"the {test} suite did not run all of its tests: expected `{expected}`, "
                    f"got {summaries or 'no summary'}"
                )
            outputs.append(output)
    finally:
        after = set(
            _docker(client, socket, "container", "ls", "--all", "--no-trunc", "--quiet").split()
        )
        for image in set(images.values()):
            _docker(client, socket, "image", "rm", "--force", image, check=False)
        _docker(client, socket, "image", "rm", SANDBOX_IMAGE_TAG, check=False)
    left = sorted(after - before)
    removed = sorted(before - after)
    if left:
        raise TaskError(f"the evidence left {len(left)} container(s) behind: {left}")
    if removed:
        raise TaskError(
            f"{len(removed)} container(s) that predate the evidence are gone: {removed}"
        )
    report_cleanup(f"cleanup: no evidence container remains; {len(before)} pre-existing kept")
    records = require_attributed_evidence("\n".join(outputs), SANDBOX_CASES)
    latency = [r for r in records if r.get("case") == "latency"]
    if latency:
        print(f"{BOLD}latency{OFF} {json.dumps(latency[0], sort_keys=True)}")
    uvrun("dwcheck", "closure", "--report")


# --- M5b: PROXY_ONLY and the CONNECT proxy (ADR-0048) -----------------------

SANDBOX_RELAY_PATH = "/usr/libexec/direwolf/sandbox-relay"
SANDBOX_FIXTURE_PATH = "/usr/libexec/direwolf/sandbox-fixture"
# The largest file the broker hashes (`MAX_PROBE_BYTES` in
# crates/dwkd-broker/src/sandbox/digest.rs, which an architecture test holds
# this equal to): it reads a workload's executable out of the container before
# every launch, and a larger one is refused EXECUTABLE_CHANGED whatever its
# bytes. Two padded copies of the fixture stand at that line on a real runtime:
# one exactly at it, which runs; and one the size of the interpreter hosted run
# 42112947252 had refused, which does not.
EXECUTABLE_COPY_BOUND = 64 << 20
SANDBOX_FIXTURE_AT_BOUND_PATH = "/usr/libexec/direwolf/sandbox-fixture-at-bound"
SANDBOX_FIXTURE_PAST_BOUND_PATH = "/usr/libexec/direwolf/sandbox-fixture-past-bound"
SANDBOX_FIXTURE_PAST_BOUND_BYTES = 68_023_040

EGRESS_BROKER_TESTS = (
    "linux::a_proxy_only_environment_measures_clean_and_reaches_only_its_proxy",
    "linux::tunnels_through_the_real_topology_obey_the_grant_the_guard_and_the_server_name",
    "linux::budgets_hold_at_the_socket_in_the_real_topology",
    "linux::a_process_that_ignores_the_proxy_has_no_path",
    "linux::ambient_proxy_settings_never_reach_an_environment",
    "linux::weakened_topologies_are_detected",
    "linux::crashes_and_restarts_fail_closed_and_leave_only_labelled_reapable_resources",
    "linux::a_production_broker_has_no_exception_and_no_fixture",
)
EGRESS_AUTHORITY_TESTS = ("linux::a_proxy_only_environment_reaches_exactly_the_runs_https_hosts",)

# Every (suite, case) the M5b real-topology suites must report, exercised.
EGRESS_CASES = (
    *(
        ("sandbox-egress", case)
        for case in (
            "proxy-only-prepare-clean",
            "proxy-only-host-network-isolated",
            "proxy-only-host-proxy-environment",
            "proxy-only-host-proxy-relay",
            "proxy-only-host-relay-digest",
            "proxy-only-container-network-isolated",
            "proxy-only-container-proxy-reachable",
            "proxy-only-container-direct-egress-refused",
            "proxy-only-container-direct-dns-refused",
            "proxy-only-container-raw-sockets-refused",
            "proxy-only-container-capabilities-empty",
            "proxy-only-host-capabilities-dropped",
            "proxy-only-environment-and-relay-only",
            "proxy-only-relay-shares-the-namespace-unprivileged",
            "proxy-only-listener-open",
            "proxy-only-socket-mounted-in-relay-only",
            "proxy-only-socket-directory-relay-uid-only",
            "proxy-only-listed-with-roles",
            "proxy-only-measure-clean-again",
            "proxy-only-destroy-removes-every-role",
            "proxy-only-destroy-closes-listener",
            "proxy-only-destroy-counters",
            "proxy-only-destroy-idempotent",
            "tunnel-granted-carries-bytes",
            "tunnel-via-proxy-variable",
            "tunnel-host-not-granted",
            "tunnel-port-not-granted",
            "tunnel-address-literal-refused",
            "resolver-blocked",
            "resolver-metadata-blocked",
            "resolver-mixed-refused-outright",
            "resolver-failure",
            "resolver-timeout",
            "resolver-rebinding-pinned",
            "tunnel-sni-mismatch-closed",
            "tunnel-sni-missing-closed",
            "tunnel-ech-refused",
            "tunnel-plain-http-refused",
            "counters-at-destroy-by-disposition",
            "audit-observability-no-payload",
            "budget-upload-exhausted",
            "budget-upload-spent-stays-spent",
            "budget-upload-exact-at-socket",
            "budget-download-exhausted",
            "budget-tunnel-limit",
            "fronting-residual-carried-and-bounded",
            "bypass-tcp-external",
            "bypass-tcp-external-dns",
            "bypass-tcp-cloud-metadata",
            "bypass-tcp-bridge-host",
            "bypass-tcp-desktop-host",
            "bypass-tcp-private-lan",
            "bypass-tcp-link-local-neighbour",
            "bypass-tcp-host-loopback-origin",
            "bypass-tcp-ipv6-external",
            "bypass-tcp-ipv4-mapped",
            "bypass-tcp-nat64-metadata",
            "bypass-udp-external",
            "bypass-udp-ipv6-external",
            "bypass-proxy-address-other-ports",
            "bypass-dns-external",
            "bypass-dns-embedded-runtime-resolver",
            "bypass-dns-local-stub",
            "bypass-dns-desktop-host",
            "bypass-dns-ipv6-external",
            "bypass-library-resolver",
            "bypass-library-resolver-public-name",
            "bypass-raw-ipv4",
            "bypass-raw-ipv6",
            "bypass-packet",
            "bypass-vsock",
            "bypass-icmp",
            "bypass-proxy-variable-redirected",
            "bypass-proxy-variable-other-peer",
            "bypass-origin-never-reached",
            "proxy-variables-broker-owned",
            "proxy-variables-ambient-ignored",
            "runtime-client-config-proxies-ignored",
            "weakened-bridge-network",
            "weakened-missing-relay",
            "weakened-proxy-variables-removed",
            "drift-relay-stopped",
            "drift-extra-peer-listening",
            "drift-fake-resolver-in-namespace",
            "drift-setup-left-running",
            "drift-egress-directory-opened",
            "weakened-relay-tampered",
            "weakened-topology-count",
            "crash-environment-network-set",
            "crash-environment-relay-started",
            "restart-proxy-closed-fails-closed",
            "foreign-resources-untouched",
            "production-proxy-only-prepared",
            "production-no-fixture-resolver",
            "production-loopback-blocked-no-exception",
            "production-proxy-only-needs-its-grant",
        )
    ),
    *(
        ("sandbox-authority-egress", case)
        for case in (
            "grant-from-run-exact-https",
            "grant-wildcard-and-plain-http-not-destinations",
            "audit-intent-records-grant",
            "tunnel-through-authority-prepared-environment",
            "wildcard-covered-name-not-granted",
            "audit-measured-counters",
            "audit-destroyed-counters",
            "reconcile-helper-orphan-reaped",
        )
    ),
)


def _runtime_state(client: Path, socket: str) -> tuple[set[str], set[str]]:
    """Every container and every network the runtime holds, by id."""
    containers = set(
        _docker(client, socket, "container", "ls", "--all", "--no-trunc", "--quiet").split()
    )
    networks = set(_docker(client, socket, "network", "ls", "--no-trunc", "--quiet").split())
    return containers, networks


def task_sandbox_egress_evidence() -> None:
    """M5b's real-topology evidence (ADR-0048): `PROXY_ONLY` environments in a
    real OCI runtime -- the environment, its setup and its relay real
    containers in one real network namespace -- and the real broker's CONNECT
    proxy behind them, with the real authority for the grant.

    Setup first: the probe, the relay and the workload fixture are built
    statically and proved static; the probe's and the relay's digests are
    pinned; the evidence images are built offline `FROM scratch` and named by
    content (the product's: probe and relay; the evidence's: with the
    workload fixture; and one whose relay differs by a byte). The destinations
    are fixtures -- the broker's evidence-only resolver file and a loopback
    origin -- and the boundary is not.

    Then every suite must run every test and every case must report at its
    level with what enforced it (M5e.1); no container or network the evidence
    made may remain, and every one that was there before must still be there.
    No runtime: NOT EXERCISED, which fails.
    Linux only.
    """
    if not sys.platform.startswith("linux"):
        raise TaskError("NOT EXERCISED: the egress evidence needs Linux and an OCI runtime")
    found = shutil.which("docker")
    if found is None:
        raise TaskError("NOT EXERCISED: no container runtime client (`docker`) on PATH")
    socket = os.environ.get("DW_SANDBOX_SOCKET", "/var/run/docker.sock")
    target_root = Path(os.environ.get("CARGO_TARGET_DIR", str(ROOT / "target")))
    work = Path(os.environ.get("DW_EGRESS_WORK", str(Path.home() / ".cache" / "dw-m5b")))
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(mode=0o700, parents=True)
    client, chosen = _trusted_client(Path(found), work / "client")
    try:
        server = json.loads(
            _docker(client, socket, "version", "--format", "{{json .Server}}").strip()
        )
    except (TaskError, json.JSONDecodeError) as exc:
        raise TaskError(f"NOT EXERCISED: the runtime at {socket} does not answer: {exc}") from exc
    if server.get("Os") != "linux":
        raise TaskError(f"NOT EXERCISED: the runtime is not a Linux one: {server.get('Os')}")
    arch = {"amd64": "x86_64", "arm64": "aarch64"}.get(str(server.get("Arch")))
    if arch is None:
        raise TaskError(f"the runtime's architecture {server.get('Arch')!r} is not supported")
    triple = f"{arch}-unknown-linux-gnu"
    platform_ = f"linux/{server.get('Arch')}"
    before_containers, before_networks = _runtime_state(client, socket)

    static = target_root / "sandbox-static"
    env = dict(os.environ, RUSTFLAGS="-C target-feature=+crt-static")
    command = [
        "cargo",
        "build",
        "--locked",
        "--release",
        "-p",
        "dwk-sandbox-probe",
        "--bin",
        "dwk-sandbox-probe",
        "--example",
        "sandbox_fixture",
        "-p",
        "dwk-sandbox-relay",
        "--bin",
        "dwk-sandbox-relay",
        "--target",
        triple,
        "--target-dir",
        str(static),
    ]
    print(f"{DIM}$ RUSTFLAGS='-C target-feature=+crt-static' {' '.join(command)}{OFF}", flush=True)
    if subprocess.run(command, cwd=str(ROOT), env=env, check=False).returncode != 0:
        raise TaskError("the static probe, relay and fixture did not build")
    release = static / triple / "release"
    probe = release / "dwk-sandbox-probe"
    relay = release / "dwk-sandbox-relay"
    fixture = release / "examples" / "sandbox_fixture"
    linking = {
        name: _static_elf(path)
        for name, path in (("probe", probe), ("relay", relay), ("fixture", fixture))
    }
    probe_sha = hashlib.sha256(probe.read_bytes()).hexdigest()
    relay_sha = hashlib.sha256(relay.read_bytes()).hexdigest()
    changed_relay = work / "relay-changed"
    offset = _one_byte_changed(relay, changed_relay)

    images = {
        "product": _build_image(
            client,
            socket,
            work / "images" / "product",
            probe,
            platform_,
            None,
            {SANDBOX_RELAY_PATH: relay},
        ),
        "fixture": _build_image(
            client,
            socket,
            work / "images" / "fixture",
            probe,
            platform_,
            None,
            {SANDBOX_RELAY_PATH: relay, SANDBOX_FIXTURE_PATH: fixture},
        ),
        "tampered-relay": _build_image(
            client,
            socket,
            work / "images" / "tampered-relay",
            probe,
            platform_,
            None,
            {SANDBOX_RELAY_PATH: changed_relay},
        ),
    }
    print(f"{BOLD}egress evidence setup{OFF}")
    version = f"{server.get('Version')} (api {server.get('ApiVersion')})"
    print(f"  runtime            {version}, {platform_}")
    print(f"  runtime client     {chosen}")
    print(f"  probe              {linking['probe']}, sha256 {probe_sha}")
    print(f"  relay              {linking['relay']}, sha256 {relay_sha}")
    print(f"  fixture            {linking['fixture']} (evidence image only)")
    print(f"  changed relay      one byte flipped at offset {offset}")
    for name, image in images.items():
        print(f"  image {name:<14}{image}")

    os.environ.update(
        {
            "DW_SANDBOX_RUNTIME": str(client),
            "DW_SANDBOX_SOCKET": socket,
            "DW_SANDBOX_PROBE_SHA256": probe_sha,
            "DW_EGRESS_RELAY_SHA256": relay_sha,
            "DW_EGRESS_IMAGE": images["product"],
            "DW_EGRESS_IMAGE_FIXTURE": images["fixture"],
            "DW_EGRESS_IMAGE_TAMPERED_RELAY": images["tampered-relay"],
        }
    )
    # Where the PROXY_ONLY environment's own record is kept for R3: the fixed
    # directory the broker's unit test reads (it reads no variable, TX042).
    captured = CAPTURED_RECORD_DIR
    shutil.rmtree(captured, ignore_errors=True)
    captured.mkdir(mode=0o700, parents=True)
    os.environ["DW_CAPTURED_RECORD_DIR"] = str(captured)
    outputs: list[str] = []
    try:
        run("cargo", "build", "--locked", "-p", "dwkd-broker")
        for package, test, names in (
            ("dwkd-broker", "sandbox_egress", EGRESS_BROKER_TESTS),
            ("dwkd-authority", "sandbox_lifecycle", EGRESS_AUTHORITY_TESTS),
        ):
            output = run_captured(
                "cargo",
                "test",
                "--locked",
                "-p",
                package,
                "--test",
                test,
                "--",
                "--ignored",
                "--exact",
                "--nocapture",
                "--test-threads=1",
                *names,
            )
            summaries = [line for line in output.splitlines() if line.startswith("test result: ")]
            expected = f"test result: ok. {len(names)} passed; 0 failed; 0 ignored"
            if len(summaries) != 1 or not summaries[0].startswith(expected):
                raise TaskError(
                    f"the {test} suite did not run all of its tests: expected `{expected}`, "
                    f"got {summaries or 'no summary'}"
                )
            outputs.append(output)
    finally:
        after_containers, after_networks = _runtime_state(client, socket)
        for image in set(images.values()):
            _docker(client, socket, "image", "rm", "--force", image, check=False)
    left = sorted(after_containers - before_containers)
    removed = sorted(before_containers - after_containers)
    left_networks = sorted(after_networks - before_networks)
    removed_networks = sorted(before_networks - after_networks)
    if left or left_networks:
        raise TaskError(
            f"the evidence left {len(left)} container(s) and {len(left_networks)} network(s) "
            f"behind: {left + left_networks}"
        )
    if removed or removed_networks:
        raise TaskError(
            f"{len(removed) + len(removed_networks)} resource(s) that predate the evidence are "
            f"gone: {removed + removed_networks}"
        )
    report_cleanup(
        f"cleanup: no evidence container or network remains; {len(before_containers)} "
        f"container(s) and {len(before_networks)} network(s) pre-existing kept"
    )
    require_attributed_evidence("\n".join(outputs), EGRESS_CASES)
    # R3 over the record the runtime kept of the real PROXY_ONLY environment
    # above: the production judgement in process, each line `in-process`.
    if not (captured / "proxy-only-record.json").is_file():
        raise TaskError("NOT EXERCISED: no PROXY_ONLY environment's record was captured")
    try:
        unit = run_captured(
            "cargo",
            "test",
            "--locked",
            "-p",
            "dwkd-broker",
            "--bin",
            "dwkd-broker",
            "--",
            "--ignored",
            "--exact",
            "--nocapture",
            "--test-threads=1",
            CAPTURED_ASSURANCE_TEST,
        )
    finally:
        shutil.rmtree(captured, ignore_errors=True)
    require_tests_ran(unit)
    require_attributed_evidence(unit, CAPTURED_ASSURANCE_CASES, ASSURANCE_EVIDENCE_PREFIX)
    uvrun("dwcheck", "closure", "--report")


# --- M5d.1: a workload in a READY environment (ADR-0052) ---------------------

WORKLOAD_BROKER_TESTS = (
    "linux::a_workload_runs_as_the_environment_user_with_exactly_its_arguments",
    "linux::output_and_the_wall_clock_are_bounded_and_a_timed_out_workload_is_ended",
    "linux::a_process_tree_is_ended_whatever_it_did_to_leave",
    "linux::only_the_pinned_bytes_run",
    "linux::a_workload_runs_only_in_the_clean_recorded_environment",
    "linux::nothing_outside_the_workspace_is_reachable_from_a_workload",
    "linux::an_agent_shaped_workload_is_contained_and_ended",
    "linux::the_broker_refuses_an_environment_identity_and_reports_its_posture",
    "linux::a_broker_killed_mid_workload_leaves_it_to_the_environments_destruction",
    # M5d.2: started and collected, one at a time per environment; the
    # trusted launcher with the real tools.
    "linux::a_running_workload_holds_no_connection_and_its_environment_takes_no_second",
    "linux::the_trusted_launcher_keeps_workspace_exec_hygiene_with_the_real_tools",
    # M5e.2 (R9): runs that see and reach none of each other and leave
    # nothing to the next.
    "linux::closure::runs_see_none_of_each_others_processes_and_leave_nothing_to_the_next",
    # M5e.2 (R8; ADR-0056, the owner's Option B): a neighbour at its own task
    # bound leaves another environment measured and served -- finding F-R8's
    # reproducer, required since the remedy.
    "linux::closure::a_neighbour_at_its_task_bound_leaves_another_environment_and_the_broker_serving",
)
# M5e.2 (R8 at the cap, ADR-0056 §6): every live environment the authority
# allows of uid 10001, all but one at their bound, the last served. It fills
# the cap, so it is selected by name by `sandbox-capacity-evidence` alone,
# which refuses before anything is built anywhere but a disposable
# GitHub-hosted runner.
CAPACITY_TESTS = (
    "linux::closure::"
    "at_the_live_environment_cap_the_last_environment_is_prepared_measured_and_served",
)
CAPACITY_CASES = tuple(
    ("sandbox-closure", case)
    for case in (
        "capacity-environments-at-their-own-bound",
        "capacity-last-environment-prepared-and-measured-clean",
        "capacity-last-workload-served",
        "capacity-all-destroyed-exactly",
    )
)
# M5e.2 (R11; the owner's OD-E8): the container runtime restarted under a
# running authority. The test restarts the runner's engine, so it is
# selected by name by `sandbox-restart-evidence` alone, which refuses before
# anything is built anywhere but a disposable GitHub-hosted runner.
RESTART_TESTS = (
    "linux::restart::"
    "the_runtime_restarts_under_a_running_authority_and_nothing_is_believed_or_replayed",
)
RESTART_CASES = tuple(
    ("sandbox-restart", case)
    for case in (
        "restart-in-flight-not-believed",
        "restart-reconciled-within-bound",
        "restart-interrupted-environment-not-believed",
        "restart-idle-environment-reconciled",
        "restart-in-flight-never-rerun",
        "restart-foreign-untouched",
        "restart-new-workload-served",
    )
)
WORKLOAD_AUTHORITY_TESTS = (
    "linux::a_workload_is_decided_recorded_run_in_its_environment_and_never_run_twice",
    "linux::every_gate_refuses_before_anything_runs",
    "linux::the_budget_is_charged_at_the_intent_and_never_refunded",
    "linux::a_crash_in_every_workload_window_leaves_it_unknown_and_never_run_again",
    "linux::an_uncertain_ending_takes_its_environment_down",
    # M5d.2: the public route, through a real DWKP client.
    "linux::the_public_route_runs_process_exec_where_the_authority_decides",
    "linux::an_uncertain_public_launch_is_unknown_and_takes_its_environment_down",
    "linux::od9_a_concrete_grant_runs_only_the_manifests_bytes_in_the_image",
    "linux::a_public_launch_is_refused_by_its_budget_and_by_bytes_that_are_not_pinned",
    "linux::the_shipped_packs_run_git_and_pytest_with_hygiene_kept_by_the_launcher",
    "linux::production_serve_prepares_its_own_environment_and_survives_its_own_death",
    # M5e.2 (R8; ADR-0056): the neighbour through the authority's
    # `process.exec`, a real DWKP client for each run.
    "linux::a_run_at_its_task_bound_leaves_another_runs_process_exec_served",
)

# Every (suite, case) the M5d.1 real-container suites must report, exercised.
#   sandbox-workload            the released broker running workloads in a REAL
#                               environment it prepared, this process playing
#                               the authority: identity, arguments, variables,
#                               bounds, wall clock, process trees ended,
#                               executable digests, environment drift, escape
#                               attempts, an agent-shaped workload, the
#                               broker's start-up identity and posture checks,
#                               a broker killed mid-workload;
#   sandbox-authority-workload  the REAL authority, the released broker and the
#                               REAL runtime: both gates for a sandbox action,
#                               the ledger, refusals before any intent, the
#                               budget, crash windows W8-W11, an uncertain
#                               ending taking its environment down; and (M5d.2)
#                               the public route through a REAL DWKP client --
#                               the server seam and the released `serve
#                               --sandbox-config` -- OD-9, the shipped packs.
WORKLOAD_CASES = (
    *(
        ("sandbox-workload", case)
        for case in (
            "workload-runs-as-uid-10001",
            "workload-no-capabilities",
            "workload-no-new-privileges",
            "workload-seccomp-filter",
            "workload-cwd-workspace",
            "workload-residue-clean",
            "workload-arguments-exact-bytes",
            "workload-flags-in-arguments-inert",
            "workload-environment-container-only",
            "workload-exit-code",
            "workload-killed-by-signal",
            "workload-ambiguous-exit-unobservable",
            "workload-log-has-no-argument-or-output",
            "workload-output-bounded",
            "workload-output-counted",
            "workload-wall-clock-timed-out",
            "workload-timed-out-reaped",
            "workload-output-held-open-child-reaped",
            "workload-tree-reaped",
            "workload-setsid-reaped",
            "workload-daemon-reaped",
            "workload-nothing-persists",
            "workload-no-zombies",
            "workload-fork-loop-reaped",
            "workload-environment-reusable-after-reap",
            "workload-executable-substituted-refused",
            "workload-executable-missing-refused",
            "workload-executable-other-file-refused",
            "workload-executable-at-the-copy-bound-runs",
            "workload-executable-past-the-copy-bound-refused",
            "workload-refused-ran-nothing",
            "workload-drifted-environment-refused",
            "workload-stopped-environment-refused",
            "workload-foreign-environment-refused",
            "workload-missing-environment-refused",
            "workload-nothing-ran-in-a-refused-environment",
            "workload-root-read-only",
            "workload-etc-read-only",
            "workload-dot-dot-escape-refused",
            "workload-tmp-writable",
            "workload-workspace-writable-as-10001",
            "workload-no-runtime-socket",
            "workload-no-host-path",
            "workload-direct-tcp-refused",
            "workload-direct-dns-refused",
            "agent-shaped-plan-and-workers-wrote",
            "agent-shaped-network-refused",
            "agent-shaped-helpers-and-workers-ended",
            "agent-shaped-residue-clean",
            "agent-shaped-files-on-host-as-10001",
            "identity-authority-workload-uid-refused",
            "identity-authority-relay-uid-refused",
            "posture-reported-matches-host",
            "broker-crash-before-exec-nothing-ran",
            "broker-crash-mid-workload-no-answer",
            "broker-crash-workload-still-running",
            "broker-restart-destroy-ends-it",
            # M5d.2: start and collect.
            "workload-start-answered-before-it-ends",
            "workload-second-in-environment-refused",
            "broker-serves-others-while-a-workload-runs",
            "workload-collected-ending-repeats",
            "workload-collect-other-generation-indeterminate",
            "broker-restart-collection-indeterminate",
            "workload-environment-removed-mid-run-not-clean",
            "broker-holds-nothing-after-an-answered-exchange",
            "broker-holds-nothing-after-its-workloads",
            # M5d.2: workspace_exec_hygiene by the trusted launcher, with the
            # real git, Python and pytest (ADR-0052 §5a) -- and what it
            # leaves to the environment.
            "hygiene-launcher-adds-exactly-its-variables",
            "hygiene-git-system-config-not-read",
            "hygiene-python-working-directory-not-on-path",
            "hygiene-pytest-cache-not-written",
            "hygiene-residual-repository-config-read",
            "hygiene-residual-conftest-runs",
        )
    ),
    # M5e.2 (R9), on the same real runtime: runs that see none of each
    # other's processes, cannot name each other's environment, and leave
    # nothing to the next.
    *(
        ("sandbox-closure", case)
        for case in (
            "cross-run-processes-not-visible",
            "cross-run-other-environment-refused",
            "cross-run-destroy-spares-the-other",
            "cross-run-next-environment-holds-nothing-of-the-last",
            # R8 (ADR-0056): a neighbour held by its own bound, another
            # environment measured and served beside it, the broker
            # answering, both destroyed exactly.
            "neighbour-holds-its-own-task-bound",
            "neighbour-workload-served-beside-a-bound-environment",
            "neighbour-measured-clean-beside-a-bound-environment",
            "neighbour-broker-answers-beside-a-bound-environment",
            "neighbour-both-kept-then-destroyed-exactly",
        )
    ),
    *(
        ("sandbox-authority-workload", case)
        for case in (
            "authority-workload-completed",
            "authority-workload-ledger-completed",
            "authority-workload-environment-kept-when-clean",
            "authority-workload-audited",
            "authority-workload-taint-raised",
            "authority-workload-obligation-output-bound",
            "authority-workload-replayed-never-rerun",
            "authority-workload-key-reused-differently-refused",
            "authority-workload-no-environment-refused",
            "authority-workload-never-on-the-host",
            "authority-workload-not-in-manifest-refused",
            "authority-workload-bounds-refused",
            "authority-workload-policy-denied",
            "authority-workload-obligation-unenforceable-denied",
            "authority-workload-no-capability-denied",
            "authority-workload-refusals-record-no-intent",
            "authority-workload-drifted-environment-destroyed",
            "authority-workload-no-ready-environment-refused",
            "authority-workload-budget-seconds-charged-whole",
            "authority-workload-budget-count-exhausted",
            "crash-w8-unknown",
            "crash-w8-environment-destroyed",
            "crash-w8-never-ran",
            "crash-w10-unknown-environment-destroyed",
            "crash-w10-never-rerun",
            "crash-w11-outcome-kept",
            "unknown-ending-recorded",
            "unknown-ending-environment-destroyed",
            "unknown-ending-never-rerun",
            "crash-w9-running-after-start",
            "crash-w9-unknown-environment-destroyed",
            "crash-w9-never-run-again",
            # M5d.2: the public route over DWKP (the server seam).
            "public-exec-environment-prepared-by-the-authority",
            "public-exec-result-names-environment-assurance-identity",
            "public-exec-runs-as-the-sandbox-user",
            "public-exec-caller-from-the-transport",
            "public-exec-never-on-the-host",
            "public-exec-output-bounded",
            "public-exec-detached-child-reaped",
            "public-exec-authority-answers-during-a-workload",
            "public-exec-broker-answers-during-a-workload",
            "public-exec-two-runs-at-once-in-two-environments",
            "public-exec-key-from-another-holder-fenced",
            "public-exec-long-workload-timed-out-and-reaped",
            "public-exec-key-never-runs-twice",
            "public-exec-cross-tool-key-refused",
            "public-exec-smuggled-environment-refused",
            "public-no-lifecycle-operation",
            "public-exec-unknown-outcome-reported",
            "public-exec-unknown-destroys-environment",
            "public-exec-budget-exhausted-refused",
            "public-exec-unpinned-image-bytes-refused",
            "public-exec-ended-runs-environment-reclaimed",
            # OD-9: a concrete grant is the manifest's executable.
            "od9-concrete-grant-runs-the-manifests-executable",
            "od9-concrete-grant-covers-nothing-else",
            "od9-host-resolved-grant-covers-no-image-executable",
            # The shipped packs, with the tools image.
            *(
                f"shipped-{pack}-{case}"
                for pack in ("balanced", "power")
                for case in (
                    "git-runs-with-hygiene",
                    "pytest-runs-with-its-cache-off",
                    "hygiene-undone-or-unevidenced-denied",
                )
            ),
            # The released `dwkd-authority serve --sandbox-config`.
            "production-serve-attaches-the-operators-environment",
            "production-serve-prepares-and-runs",
            "production-crash-mid-workload-unknown-destroyed",
            "production-replay-after-restart-refused",
            # M5e.2 (R8; ADR-0056): through the authority's `process.exec`.
            "neighbour-run-holds-its-own-task-bound",
            "neighbour-authority-answers-beside-a-bound-run",
            "neighbour-environment-judged-clean-beside-a-bound-run",
            "neighbour-process-exec-completed-beside-a-bound-run",
            "neighbour-environments-kept-ready",
        )
    ),
)


def _padded(source: Path, target: Path, size: int) -> str:
    """`source`'s bytes at `target`, zero-padded to exactly `size`: bytes the
    loader never reads past the file's end of sections, so the copy still runs,
    as another file of that size. Returns its SHA-256."""
    data = source.read_bytes()
    if len(data) > size:
        raise TaskError(f"{source}: {len(data)} bytes do not fit in {size}")
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(data + bytes(size - len(data)))
    target.chmod(0o755)
    return hashlib.sha256(target.read_bytes()).hexdigest()


def _workload_setup() -> tuple[Path, str, dict[str, str], set[str], dict[str, str]]:
    """The M5d.1 evidence's setup, separate from the evidence: a trusted
    runtime client; the probe and the fixture built statically and proved
    static from their ELF headers, their digests pinned; one image built
    offline `FROM scratch` holding both and named by content. Returns the
    client, the socket, the environment the suites read, the containers that
    predate the evidence, and the images to remove."""
    if not sys.platform.startswith("linux"):
        raise TaskError("NOT EXERCISED: the workload evidence needs Linux and an OCI runtime")
    found = shutil.which("docker")
    if found is None:
        raise TaskError("NOT EXERCISED: no container runtime client (`docker`) on PATH")
    socket = os.environ.get("DW_SANDBOX_SOCKET", "/var/run/docker.sock")
    target_root = Path(os.environ.get("CARGO_TARGET_DIR", str(ROOT / "target")))
    work = Path(os.environ.get("DW_WORKLOAD_WORK", str(Path.home() / ".cache" / "dw-m5d")))
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(mode=0o700, parents=True)
    client, chosen = _trusted_client(Path(found), work / "client")
    try:
        server = json.loads(
            _docker(client, socket, "version", "--format", "{{json .Server}}").strip()
        )
    except (TaskError, json.JSONDecodeError) as exc:
        raise TaskError(f"NOT EXERCISED: the runtime at {socket} does not answer: {exc}") from exc
    if server.get("Os") != "linux":
        raise TaskError(f"NOT EXERCISED: the runtime is not a Linux one: {server.get('Os')}")
    arch = {"amd64": "x86_64", "arm64": "aarch64"}.get(str(server.get("Arch")))
    if arch is None:
        raise TaskError(f"the runtime's architecture {server.get('Arch')!r} is not supported")
    triple = f"{arch}-unknown-linux-gnu"
    platform_ = f"linux/{server.get('Arch')}"
    before = set(
        _docker(client, socket, "container", "ls", "--all", "--no-trunc", "--quiet").split()
    )
    static = target_root / "sandbox-static"
    env = dict(os.environ, RUSTFLAGS="-C target-feature=+crt-static")
    command = [
        "cargo",
        "build",
        "--locked",
        "--release",
        "-p",
        "dwk-sandbox-probe",
        "--bin",
        "dwk-sandbox-probe",
        "--example",
        "sandbox_fixture",
        "--target",
        triple,
        "--target-dir",
        str(static),
    ]
    print(f"{DIM}$ RUSTFLAGS='-C target-feature=+crt-static' {' '.join(command)}{OFF}", flush=True)
    if subprocess.run(command, cwd=str(ROOT), env=env, check=False).returncode != 0:
        raise TaskError("the static probe and fixture did not build")
    release = static / triple / "release"
    probe = release / "dwk-sandbox-probe"
    fixture = release / "examples" / "sandbox_fixture"
    linking = {name: _static_elf(path) for name, path in (("probe", probe), ("fixture", fixture))}
    probe_sha = hashlib.sha256(probe.read_bytes()).hexdigest()
    fixture_sha = hashlib.sha256(fixture.read_bytes()).hexdigest()
    at_bound = work / "padded" / Path(SANDBOX_FIXTURE_AT_BOUND_PATH).name
    past_bound = work / "padded" / Path(SANDBOX_FIXTURE_PAST_BOUND_PATH).name
    at_bound_sha = _padded(fixture, at_bound, EXECUTABLE_COPY_BOUND)
    past_bound_sha = _padded(fixture, past_bound, SANDBOX_FIXTURE_PAST_BOUND_BYTES)
    images = {
        "workload": _build_image(
            client,
            socket,
            work / "images" / "workload",
            probe,
            platform_,
            None,
            # M5d.2 (OD-9): the fixture again at a path the host also has, so
            # a grant resolved on the host is shown to cover nothing in it.
            {
                SANDBOX_FIXTURE_PATH: fixture,
                "/usr/bin/true": fixture,
                SANDBOX_FIXTURE_AT_BOUND_PATH: at_bound,
                SANDBOX_FIXTURE_PAST_BOUND_PATH: past_bound,
            },
        )
    }
    tools, tool_variables = _tools_image(
        client, socket, work / "images" / "tools", (probe, fixture), platform_
    )
    images["tools"] = tools
    scope = Path("/proc/sys/kernel/yama/ptrace_scope")
    print(f"{BOLD}workload evidence setup{OFF}")
    version = f"{server.get('Version')} (api {server.get('ApiVersion')})"
    print(f"  runtime            {version}, {platform_}")
    print(f"  runtime client     {chosen}")
    print(f"  probe              {linking['probe']}, sha256 {probe_sha}")
    print(f"  fixture            {linking['fixture']}, sha256 {fixture_sha} (the workload)")
    print(f"  at the copy bound  {EXECUTABLE_COPY_BOUND} bytes, sha256 {at_bound_sha}")
    print(f"  past the bound     {SANDBOX_FIXTURE_PAST_BOUND_BYTES} bytes, sha256 {past_bound_sha}")
    print(f"  image (content id) {images['workload']}")
    print(
        f"  tools image        {images['tools']} "
        f"(git, {tool_variables['DW_SANDBOX_PYTHON']}, pytest)"
    )
    print(
        "  yama ptrace_scope  "
        + (scope.read_text(encoding="utf-8").strip() if scope.exists() else "absent")
    )
    variables = {
        "DW_SANDBOX_RUNTIME": str(client),
        "DW_SANDBOX_SOCKET": socket,
        "DW_SANDBOX_WORKLOAD_IMAGE": images["workload"],
        "DW_SANDBOX_PROBE_SHA256": probe_sha,
        "DW_SANDBOX_FIXTURE_SHA256": fixture_sha,
        "DW_SANDBOX_FIXTURE_AT_BOUND_SHA256": at_bound_sha,
        "DW_SANDBOX_FIXTURE_PAST_BOUND_SHA256": past_bound_sha,
        **tool_variables,
    }
    return client, socket, variables, before, images


def task_sandbox_workload_evidence() -> None:
    """M5d.1's and M5d.2's real-container evidence (ADR-0052 §17): workloads
    in a real OCI environment -- the released broker running them through its
    real runtime client, the real authority deciding and recording them, and
    (M5d.2) a real DWKP client reaching them through the public route, the
    released `serve --sandbox-config` included.

    Every suite must run every test and every case must report at its level
    with what enforced it (M5e.1); no container the evidence made may remain,
    and every container that was there before must still be there. No
    runtime: NOT EXERCISED, which fails. Linux only.
    """
    client, socket, variables, before, images = _workload_setup()
    os.environ.update(variables)
    outputs: list[str] = []
    try:
        run("cargo", "build", "--locked", "-p", "dwkd-broker")
        for package, test, names in (
            ("dwkd-broker", "sandbox_workload", WORKLOAD_BROKER_TESTS),
            ("dwkd-authority", "sandbox_workload", WORKLOAD_AUTHORITY_TESTS),
        ):
            output = run_captured(
                "cargo",
                "test",
                "--locked",
                "-p",
                package,
                "--test",
                test,
                "--",
                "--ignored",
                "--exact",
                "--nocapture",
                "--test-threads=1",
                *names,
            )
            summaries = [line for line in output.splitlines() if line.startswith("test result: ")]
            expected = f"test result: ok. {len(names)} passed; 0 failed; 0 ignored"
            if len(summaries) != 1 or not summaries[0].startswith(expected):
                raise TaskError(
                    f"the {package} {test} suite did not run all of its tests: expected "
                    f"`{expected}`, got {summaries or 'no summary'}"
                )
            outputs.append(output)
    finally:
        after = set(
            _docker(client, socket, "container", "ls", "--all", "--no-trunc", "--quiet").split()
        )
        for image in set(images.values()):
            _docker(client, socket, "image", "rm", "--force", image, check=False)
    left = sorted(after - before)
    removed = sorted(before - after)
    if left:
        raise TaskError(f"the evidence left {len(left)} container(s) behind: {left}")
    if removed:
        raise TaskError(
            f"{len(removed)} container(s) that predate the evidence are gone: {removed}"
        )
    report_cleanup(f"cleanup: no evidence container remains; {len(before)} pre-existing kept")
    require_attributed_evidence("\n".join(outputs), WORKLOAD_CASES)
    uvrun("dwcheck", "closure", "--report")


def restart_refusal(environ: Mapping[str, str]) -> str | None:
    """Why this host's runtime must not be restarted, or None. Never
    inferred: `DW_RUNTIME_RESTART=1`, on a GitHub-hosted runner -- the test
    checks again, and that the engine is the runner's own systemd unit and
    not Docker Desktop, before it restarts anything."""
    if environ.get("DW_RUNTIME_RESTART", "").strip() != "1":
        return (
            "DW_RUNTIME_RESTART=1 is not set: restarting the runtime is the hosted "
            "`sandbox-restart` job's alone"
        )
    if (
        environ.get("GITHUB_ACTIONS") != "true"
        or environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
    ):
        return (
            "this is not a disposable GitHub-hosted runner: a developer's daemon is never restarted"
        )
    return None


def task_sandbox_restart_evidence() -> None:
    """M5e.2's runtime restart (R11; the owner's OD-E8), hosted only: the
    runner's Docker Engine restarted under a running authority while one
    run's workload is in flight and another run's environment is idle.

    The interrupted workload is never believed finished and never run again;
    reconciliation on the same incarnation destroys what stopped and measures
    what still runs; a container that is not DireWolf's is untouched; a new
    workload runs after; all within the environment deadline. Anywhere but a
    disposable GitHub-hosted runner this refuses before anything is built:
    NOT EXERCISED, which fails. Every case must report at `privileged-oci`
    with what enforced it. No container the evidence made may remain, and
    every container that predates it must. Linux only.
    """
    if not sys.platform.startswith("linux"):
        raise TaskError("NOT EXERCISED: the runtime restart runs only on Linux")
    refusal = restart_refusal(os.environ)
    if refusal is not None:
        raise TaskError(f"NOT EXERCISED: {refusal}")
    client, socket, variables, before, images = _workload_setup()
    os.environ.update(variables)
    try:
        system = _docker(client, socket, "info", "--format", "{{.OperatingSystem}}")
        if "Docker Desktop" in system:
            raise TaskError(f"NOT EXERCISED: the runtime is {system.strip()}, not a runner's")
        run("cargo", "build", "--locked", "-p", "dwkd-broker")
        output = run_captured(
            "cargo",
            "test",
            "--locked",
            "-p",
            "dwkd-authority",
            "--test",
            "sandbox_workload",
            "--",
            "--ignored",
            "--exact",
            "--nocapture",
            "--test-threads=1",
            *RESTART_TESTS,
        )
        summaries = [line for line in output.splitlines() if line.startswith("test result: ")]
        expected = f"test result: ok. {len(RESTART_TESTS)} passed; 0 failed; 0 ignored"
        if len(summaries) != 1 or not summaries[0].startswith(expected):
            raise TaskError(
                f"the runtime restart did not run: expected `{expected}`, "
                f"got {summaries or 'no summary'}"
            )
    finally:
        after = set(
            _docker(client, socket, "container", "ls", "--all", "--no-trunc", "--quiet").split()
        )
        for image in set(images.values()):
            _docker(client, socket, "image", "rm", "--force", image, check=False)
    left = sorted(after - before)
    removed = sorted(before - after)
    if left:
        raise TaskError(f"the evidence left {len(left)} container(s) behind: {left}")
    if removed:
        raise TaskError(
            f"{len(removed)} container(s) that predate the evidence are gone: {removed}"
        )
    report_cleanup(f"cleanup: no evidence container remains; {len(before)} pre-existing kept")
    require_attributed_evidence(output, RESTART_CASES)


def capacity_refusal(environ: Mapping[str, str]) -> str | None:
    """Why this host must not fill the live-environment cap, or None. Never
    inferred: `DW_CAPACITY_EVIDENCE=1`, on a GitHub-hosted runner -- the test
    checks again, and the runner's memory, its kernel's task tables, that
    its runtime is not Docker Desktop and that no process of the sandbox uid
    runs there, before it prepares anything."""
    if environ.get("DW_CAPACITY_EVIDENCE", "").strip() != "1":
        return (
            "DW_CAPACITY_EVIDENCE=1 is not set: filling the live-environment cap is the "
            "hosted `sandbox-capacity` job's alone"
        )
    if (
        environ.get("GITHUB_ACTIONS") != "true"
        or environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
    ):
        return "this is not a disposable GitHub-hosted runner: a developer's host is never filled"
    return None


def task_sandbox_capacity_evidence() -> None:
    """M5e.2's R8 at the authority's cap (ADR-0056 §6), hosted only: every
    live environment the authority allows, of the one sandbox uid, all but
    one holding their own task bound, and the last prepared, measured clean
    and served beside them -- sleeping threads, bounded by each environment's
    own cgroup and the workload's wall clock.

    Anywhere but a disposable GitHub-hosted runner this refuses before
    anything is built: NOT EXERCISED, which fails. Every case must report at
    `real-oci` with what enforced it. No container the evidence made may
    remain, and every container that predates it must. Linux only.
    """
    if not sys.platform.startswith("linux"):
        raise TaskError("NOT EXERCISED: the capacity evidence runs only on Linux")
    refusal = capacity_refusal(os.environ)
    if refusal is not None:
        raise TaskError(f"NOT EXERCISED: {refusal}")
    client, socket, variables, before, images = _workload_setup()
    os.environ.update(variables)
    try:
        system = _docker(client, socket, "info", "--format", "{{.OperatingSystem}}")
        if "Docker Desktop" in system:
            raise TaskError(f"NOT EXERCISED: the runtime is {system.strip()}, not a runner's")
        run("cargo", "build", "--locked", "-p", "dwkd-broker")
        output = run_captured(
            "cargo",
            "test",
            "--locked",
            "-p",
            "dwkd-broker",
            "--test",
            "sandbox_workload",
            "--",
            "--ignored",
            "--exact",
            "--nocapture",
            "--test-threads=1",
            *CAPACITY_TESTS,
        )
        summaries = [line for line in output.splitlines() if line.startswith("test result: ")]
        expected = f"test result: ok. {len(CAPACITY_TESTS)} passed; 0 failed; 0 ignored"
        if len(summaries) != 1 or not summaries[0].startswith(expected):
            raise TaskError(
                f"the capacity evidence did not run: expected `{expected}`, "
                f"got {summaries or 'no summary'}"
            )
    finally:
        after = set(
            _docker(client, socket, "container", "ls", "--all", "--no-trunc", "--quiet").split()
        )
        for image in set(images.values()):
            _docker(client, socket, "image", "rm", "--force", image, check=False)
    left = sorted(after - before)
    removed = sorted(before - after)
    if left:
        raise TaskError(f"the evidence left {len(left)} container(s) behind: {left}")
    if removed:
        raise TaskError(
            f"{len(removed)} container(s) that predate the evidence are gone: {removed}"
        )
    report_cleanup(f"cleanup: no evidence container remains; {len(before)} pre-existing kept")
    require_attributed_evidence(output, CAPACITY_CASES)


# --- M5e.2's R3: ADR-0057's E6, a hard rule weakened in a real PROXY_ONLY environment ---
#
# The owner's R-B (ADR-0057 §8) requires real `PROXY_ONLY` containers weakened
# one hard rule at a time, measured from both vantages and refused by the
# production broker (M5E_ASSURANCE_PLAN.md §§3a, 3b; issue #19). The broker
# never asks for a weaker container, so the weakening is the runtime's: the
# released broker prepares its genuine `PROXY_ONLY` topology through a
# test-only socket between the real client and the real daemon that changes
# exactly one field of the environment's `create` (the egress suite's `e6`
# module, ADR-0058). Every case's raw observations -- the create as sent and
# as received, the daemon's record, the probe's stream and report, the
# broker's answer and events -- are written out by the test, digested there,
# checked again here independently, and published into the job's log with
# their digests, so the owner can verify the hosted run offline
# (`make sandbox-proxy-weakened-review`).

E6_SUITE = "sandbox-proxy-weakened"
E6_TESTS = ("linux::e6::every_hard_rule_weakened_in_a_real_proxy_only_environment_is_refused",)
E6_CONTROL = "e6-faulty-runtime-forwards-a-conforming-environment-kept"
E6_COUNT = "e6-row-count"
# ADR-0057 §1a's fifteen rows (the seccomp rule twice; the resource limits'
# task backstop a second case of its row). For each case: its row, the
# invariants that must fail (each of the vantage §1a names), and the fields of
# the environment's `create` the faulty runtime changes -- no other.
E6_ROWS: dict[str, tuple[str, tuple[str, ...], tuple[str, ...]]] = {
    "e6-weakened-writable-root-refused": (
        "read-only-root",
        ("HOST_ROOT_READ_ONLY", "CONTAINER_ROOT_READ_ONLY"),
        ("HostConfig.ReadonlyRootfs",),
    ),
    "e6-weakened-root-user-refused": (
        "non-root-user",
        ("HOST_USER_NON_ROOT", "CONTAINER_UID_GID"),
        ("User",),
    ),
    "e6-weakened-privileged-refused": (
        "not-privileged",
        (
            "HOST_NOT_PRIVILEGED",
            "CONTAINER_CAPABILITIES_EMPTY",
            "CONTAINER_DEVICES_MINIMAL",
            "CONTAINER_PROC_RESTRICTED",
        ),
        ("HostConfig.Privileged",),
    ),
    "e6-weakened-runtime-socket-mounted-refused": (
        "no-runtime-socket",
        ("HOST_NO_RUNTIME_SOCKET", "HOST_MOUNTS_EXACT", "CONTAINER_NO_RUNTIME_SOCKET"),
        ("HostConfig.Binds",),
    ),
    "e6-weakened-capability-added-refused": (
        "capabilities-dropped",
        ("HOST_CAPABILITIES_DROPPED", "CONTAINER_CAPABILITIES_EMPTY"),
        ("HostConfig.CapAdd",),
    ),
    "e6-weakened-no-new-privileges-disabled-refused": (
        "no-new-privileges",
        ("HOST_NO_NEW_PRIVILEGES", "CONTAINER_NO_NEW_PRIVILEGES"),
        ("HostConfig.SecurityOpt",),
    ),
    "e6-weakened-seccomp-unconfined-refused": (
        "seccomp-not-unconfined",
        ("HOST_SECCOMP_PROFILE", "CONTAINER_SECCOMP_PROFILE_ACTIVE"),
        ("HostConfig.SecurityOpt",),
    ),
    "e6-weakened-seccomp-default-profile-refused": (
        "seccomp-not-runtime-default",
        ("HOST_SECCOMP_PROFILE", "CONTAINER_SECCOMP_PROFILE_ACTIVE"),
        ("HostConfig.SecurityOpt",),
    ),
    "e6-weakened-host-pid-refused": (
        "private-pid-namespace",
        ("HOST_PID_NAMESPACE_PRIVATE", "CONTAINER_PID_NAMESPACE_PRIVATE"),
        ("HostConfig.PidMode",),
    ),
    "e6-weakened-host-ipc-refused": (
        "private-ipc-namespace",
        ("HOST_IPC_NAMESPACE_PRIVATE",),
        ("HostConfig.IpcMode",),
    ),
    "e6-weakened-host-uts-refused": (
        "private-uts-namespace",
        ("HOST_UTS_NAMESPACE_PRIVATE",),
        ("HostConfig.UTSMode",),
    ),
    "e6-weakened-mutable-image-tag-refused": (
        "digest-pinned-image",
        ("HOST_IMAGE_PINNED",),
        ("Image",),
    ),
    "e6-weakened-extra-device-refused": (
        "no-additional-devices",
        ("HOST_NO_DEVICES", "CONTAINER_DEVICES_MINIMAL"),
        ("HostConfig.Devices",),
    ),
    "e6-weakened-resource-limits-dropped-refused": (
        "resource-limits",
        ("HOST_RESOURCE_LIMITS", "CONTAINER_CGROUP_LIMITS"),
        ("HostConfig.MemorySwap", "HostConfig.PidsLimit"),
    ),
    "e6-weakened-task-backstop-at-256-refused": (
        "resource-limits",
        ("HOST_RESOURCE_LIMITS", "CONTAINER_RLIMITS"),
        ("HostConfig.Ulimits",),
    ),
    "e6-weakened-host-network-refused": (
        "isolated-network",
        (
            "HOST_NETWORK_ISOLATED",
            "CONTAINER_NETWORK_ISOLATED",
            "CONTAINER_DIRECT_EGRESS_REFUSED",
            "CONTAINER_DIRECT_DNS_REFUSED",
        ),
        ("HostConfig.NetworkMode",),
    ),
}
# The one case whose environment is given the host's network namespace. The
# broker must make no peer there (ADR-0059): its setup would add the proxy
# address to the host's own loopback, and its relay serve the run's proxy on
# the host's network -- what the hosted run at `3ca842c` observed
# (F-E6-HOSTNET). The host's loopback is kept before and after, and must not
# have changed. A disposable runner's alone: a broker without that gate
# changes the host.
E6_HOST_NETWORK = "e6-weakened-host-network-refused"
E6_HOST_LOOPBACK = "host-loopback.txt"
_E6_ADDRESS = re.compile(r"[0-9]{1,3}(?:\.[0-9]{1,3}){3}/[0-9]{1,2}")
E6_ROW_NAMES = tuple(dict.fromkeys(row for row, _, _ in E6_ROWS.values()))
E6_CASES = tuple((E6_SUITE, case) for case in (E6_CONTROL, *E6_ROWS, E6_COUNT))
# `PROXY_ONLY`'s own invariants: reported for every case, never required to
# pass under a weakening -- how the two interact is observed (ADR-0057 U3).
E6_TOPOLOGY = (
    "HOST_PROXY_ENVIRONMENT",
    "HOST_PROXY_RELAY",
    "HOST_RELAY_DIGEST",
    "CONTAINER_PROXY_REACHABLE",
)
E6_VERDICTS = frozenset(("PASS", "FAIL", "UNOBSERVABLE"))
# What the test keeps of each case, every one of them digested.
E6_RAW_FILES = (
    "create-sent.json",
    "create-received.json",
    "record.json",
    "probe-stream.bin",
    "probe-report.json",
    "measurement.txt",
    "requests.txt",
    "broker-events.txt",
)
E6_RAW_PREFIX = "E6-RAW "
E6_FILE_PREFIX = "E6-EVIDENCE-FILE "
E6_MANIFEST_PREFIX = "E6-EVIDENCE-MANIFEST "


def _proxy_only_images(
    client: Path, socket: str, server: Mapping[str, object], target_root: Path, work: Path
) -> tuple[dict[str, str], dict[str, str]]:
    """The egress evidence's own setup, for E6: the probe, the relay and the
    workload fixture built statically and proved static; their digests
    pinned; the evidence images built offline `FROM scratch` and named by
    content (the product's, the fixture's, and one whose relay differs by a
    byte). The images by name, and the variables the egress suite reads."""
    arch = {"amd64": "x86_64", "arm64": "aarch64"}.get(str(server.get("Arch")))
    if arch is None:
        raise TaskError(f"the runtime's architecture {server.get('Arch')!r} is not supported")
    triple = f"{arch}-unknown-linux-gnu"
    platform_ = f"linux/{server.get('Arch')}"
    static = target_root / "sandbox-static"
    env = dict(os.environ, RUSTFLAGS="-C target-feature=+crt-static")
    command = [
        "cargo",
        "build",
        "--locked",
        "--release",
        "-p",
        "dwk-sandbox-probe",
        "--bin",
        "dwk-sandbox-probe",
        "--example",
        "sandbox_fixture",
        "-p",
        "dwk-sandbox-relay",
        "--bin",
        "dwk-sandbox-relay",
        "--target",
        triple,
        "--target-dir",
        str(static),
    ]
    print(f"{DIM}$ RUSTFLAGS='-C target-feature=+crt-static' {' '.join(command)}{OFF}", flush=True)
    if subprocess.run(command, cwd=str(ROOT), env=env, check=False).returncode != 0:
        raise TaskError("the static probe, relay and fixture did not build")
    release = static / triple / "release"
    probe = release / "dwk-sandbox-probe"
    relay = release / "dwk-sandbox-relay"
    fixture = release / "examples" / "sandbox_fixture"
    linking = {
        name: _static_elf(path)
        for name, path in (("probe", probe), ("relay", relay), ("fixture", fixture))
    }
    probe_sha = hashlib.sha256(probe.read_bytes()).hexdigest()
    relay_sha = hashlib.sha256(relay.read_bytes()).hexdigest()
    changed_relay = work / "relay-changed"
    _one_byte_changed(relay, changed_relay)
    images = {
        "product": _build_image(
            client,
            socket,
            work / "images" / "product",
            probe,
            platform_,
            None,
            {SANDBOX_RELAY_PATH: relay},
        ),
        "fixture": _build_image(
            client,
            socket,
            work / "images" / "fixture",
            probe,
            platform_,
            None,
            {SANDBOX_RELAY_PATH: relay, SANDBOX_FIXTURE_PATH: fixture},
        ),
        "tampered-relay": _build_image(
            client,
            socket,
            work / "images" / "tampered-relay",
            probe,
            platform_,
            None,
            {SANDBOX_RELAY_PATH: changed_relay},
        ),
    }
    print(f"{BOLD}E6 evidence setup{OFF}")
    print(f"  runtime            {server.get('Version')} (api {server.get('ApiVersion')})")
    print(f"  probe              {linking['probe']}, sha256 {probe_sha}")
    print(f"  relay              {linking['relay']}, sha256 {relay_sha}")
    for name, image in images.items():
        print(f"  image {name:<14}{image}")
    variables = {
        "DW_SANDBOX_RUNTIME": str(client),
        "DW_SANDBOX_SOCKET": socket,
        "DW_SANDBOX_PROBE_SHA256": probe_sha,
        "DW_EGRESS_RELAY_SHA256": relay_sha,
        "DW_EGRESS_IMAGE": images["product"],
        "DW_EGRESS_IMAGE_FIXTURE": images["fixture"],
        "DW_EGRESS_IMAGE_TAMPERED_RELAY": images["tampered-relay"],
    }
    return images, variables


def _e6_fields(outcome: str) -> dict[str, str]:
    """An E6 outcome's `name:value` parts; a part without a colon is kept
    whole, as its own name."""
    fields: dict[str, str] = {}
    for part in outcome.split(";"):
        name, _, value = part.partition(":")
        fields[name] = value
    return fields


def _e6_verdicts(text: str) -> dict[str, str] | None:
    """`INV=VERDICT+...` as a mapping; `{}` for `none`; `None` if malformed."""
    if text == "none":
        return {}
    pairs: dict[str, str] = {}
    for item in text.split("+"):
        name, _, verdict = item.partition("=")
        if not _INVARIANT.fullmatch(name) or verdict not in E6_VERDICTS or name in pairs:
            return None
        pairs[name] = verdict
    return pairs


def e6_outcome_problem(case: str, outcome: str, enforcement: object) -> str | None:
    """Why an E6 line does not show what its case must, or `None`.

    The control says it was kept, every required invariant passing, the
    topology's four passing, forwarded unchanged and destroyed. A row says it
    was refused by exactly the invariants its row names, of the vantage its
    enforcement claims; it reports every other invariant that did not pass and
    the topology's four, whatever their verdicts; it names the fields the
    runtime changed, and for the host's network that the host's loopback
    gained nothing (ADR-0059). The count says every case was refused and every
    row covered."""
    if case == E6_CONTROL:
        fields = _e6_fields(outcome)
        topology = _e6_verdicts(fields.get("topology", ""))
        if not outcome.startswith("kept:every-required-invariant-pass;"):
            return f"the control must be kept, every required invariant passing: {outcome!r}"
        if topology != dict.fromkeys(E6_TOPOLOGY, "PASS"):
            return f"the control's topology must pass whole: {fields.get('topology')!r}"
        if "forwarded-unchanged" not in fields or fields.get("destroyed") != "removed":
            return "the control must be forwarded unchanged and destroyed"
        return None
    if case == E6_COUNT:
        wanted = (
            f"refused-{len(E6_ROWS)}-of-{len(E6_ROWS)}-cases;"
            f"rows-{len(E6_ROW_NAMES)}-of-{len(E6_ROW_NAMES)}"
        )
        if outcome != wanted:
            return f"every case refused and every row covered: {outcome!r} must be {wanted!r}"
        return None
    row = E6_ROWS.get(case)
    if row is None:
        return "an E6 case with no row"
    _, caught, changed = row
    fields = _e6_fields(outcome)
    if not outcome.startswith("refused:"):
        return f"a weakened PROXY_ONLY environment must be refused: {outcome!r}"
    named = _named_invariants(fields["refused"])
    if named is None or sorted(named) != sorted(caught):
        return f"refused by {fields['refused']!r}, which must be exactly {'+'.join(caught)}"
    measured = _VANTAGE[
        (
            any(name.startswith("HOST_") for name in named),
            any(name.startswith("CONTAINER_") for name in named),
        )
    ]
    if measured != enforcement:
        return f"its invariants were {measured}, not {enforcement}"
    also = _e6_verdicts(fields.get("also", ""))
    if also is None or set(also) & set(caught) or any(v == "PASS" for v in also.values()):
        return f"what else did not pass is not reported: {fields.get('also')!r}"
    topology = _e6_verdicts(fields.get("topology", ""))
    if topology is None or sorted(topology) != sorted(E6_TOPOLOGY):
        return f"the topology's four invariants are not reported: {fields.get('topology')!r}"
    if fields.get("weakened") != "+".join(changed):
        return f"the weakening must be {'+'.join(changed)!r}, not {fields.get('weakened')!r}"
    added = fields.get("host-loopback-added")
    if case == E6_HOST_NETWORK:
        # ADR-0059: no peer in the host's namespace, so nothing gained.
        if added != "none":
            return f"the host's loopback must have gained nothing: {added!r}"
    elif added != "not-applicable":
        return f"a case that touches no host reports its loopback: {added!r}"
    return None


def e6_refusal(environ: Mapping[str, str]) -> str | None:
    """Why E6's qualifying evidence must not run here, or None. Never
    inferred: `DW_E6_EVIDENCE=1`, on a GitHub-hosted runner -- the
    disposable environment ADR-0057's E6 asks for (M5E_ASSURANCE_PLAN.md §3b,
    criterion 1). The test checks again before the one case that touches the
    host, and that the runtime is not Docker Desktop."""
    if environ.get("DW_E6_EVIDENCE", "").strip() != "1":
        return (
            "DW_E6_EVIDENCE=1 is not set: E6's qualifying evidence is the hosted "
            "`sandbox-proxy-weakened` job's alone"
        )
    if (
        environ.get("GITHUB_ACTIONS") != "true"
        or environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
    ):
        return "this is not a disposable GitHub-hosted runner"
    return None


def _e6_raw_lines(output: str) -> dict[tuple[str, str], tuple[str, int]]:
    """Every `E6-RAW` line the test printed: (case, file) -> (sha256, bytes)."""
    found: dict[tuple[str, str], tuple[str, int]] = {}
    for line in output.splitlines():
        at = line.find(E6_RAW_PREFIX)
        if at < 0:
            continue
        try:
            record = json.loads(line[at + len(E6_RAW_PREFIX) :])
        except json.JSONDecodeError as exc:
            raise TaskError(f"unreadable E6-RAW line: {line[:200]}") from exc
        case, file, digest, size = (
            record.get("case"),
            record.get("file"),
            record.get("sha256"),
            record.get("bytes"),
        )
        if not (
            isinstance(case, str)
            and isinstance(file, str)
            and isinstance(digest, str)
            and re.fullmatch(r"[0-9a-f]{64}", digest)
            and isinstance(size, int)
        ):
            raise TaskError(f"malformed E6-RAW line: {line[:200]}")
        if (case, file) in found:
            raise TaskError(f"E6-RAW {case}/{file} reported twice")
        found[(case, file)] = (digest, size)
    return found


def _e6_json(data: bytes, what: str) -> dict[str, object]:
    try:
        value = json.loads(data)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise TaskError(f"{what} is not JSON") from exc
    if not isinstance(value, dict):
        raise TaskError(f"{what} is not one JSON object")
    return value


def _e6_at(value: object, *path: str) -> object:
    for key in path:
        if not isinstance(value, dict):
            return None
        value = value.get(key)
    return value


def _e6_changed(a: object, b: object, path: str = "") -> list[str]:
    """Every path at which two JSON values differ, objects member by member
    (as the test's own comparison is)."""
    if isinstance(a, dict) and isinstance(b, dict):
        out: list[str] = []
        for key in sorted(set(a) | set(b)):
            inner = f"{path}.{key}" if path else key
            if key in a and key in b:
                out.extend(_e6_changed(a[key], b[key], inner))
            else:
                out.append(inner)
        return out
    return [] if a == b and type(a) is type(b) else [path]


def _e6_list(value: object) -> list[object]:
    return list(value) if isinstance(value, list) else []


def _e6_strings(value: object) -> list[str]:
    return [item for item in _e6_list(value) if isinstance(item, str)]


def _e6_recorded(case: str, record: dict[str, object], tag: str) -> bool:
    """Whether the daemon's own record shows the case's weakening -- the
    Python twin of the test's `recorded` predicates."""
    host = _e6_at(record, "HostConfig")
    security = _e6_strings(_e6_at(host, "SecurityOpt"))
    checks: dict[str, bool] = {
        "e6-weakened-writable-root-refused": _e6_at(host, "ReadonlyRootfs") is False,
        "e6-weakened-root-user-refused": _e6_at(record, "Config", "User") == "0:0",
        "e6-weakened-privileged-refused": _e6_at(host, "Privileged") is True,
        "e6-weakened-runtime-socket-mounted-refused": any(
            isinstance(m, dict) and m.get("Destination") == "/var/run/docker.sock"
            for m in _e6_list(_e6_at(record, "Mounts"))
        ),
        "e6-weakened-capability-added-refused": bool(
            {"NET_RAW", "CAP_NET_RAW"} & set(_e6_strings(_e6_at(host, "CapAdd")))
        ),
        "e6-weakened-no-new-privileges-disabled-refused": not any(
            o.startswith("no-new-privileges") for o in security
        ),
        "e6-weakened-seccomp-unconfined-refused": "seccomp=unconfined" in security,
        "e6-weakened-seccomp-default-profile-refused": not any(
            o.startswith("seccomp=") for o in security
        ),
        "e6-weakened-host-pid-refused": _e6_at(host, "PidMode") == "host",
        "e6-weakened-host-ipc-refused": _e6_at(host, "IpcMode") == "host",
        "e6-weakened-host-uts-refused": _e6_at(host, "UTSMode") == "host",
        "e6-weakened-host-network-refused": _e6_at(host, "NetworkMode") == "host",
        "e6-weakened-mutable-image-tag-refused": _e6_at(record, "Config", "Image") == tag,
        "e6-weakened-extra-device-refused": any(
            isinstance(d, dict) and d.get("PathInContainer") == "/dev/extra"
            for d in _e6_list(_e6_at(host, "Devices"))
        ),
        "e6-weakened-resource-limits-dropped-refused": _e6_at(host, "PidsLimit") != 256
        and _e6_at(host, "MemorySwap") == -1,
        "e6-weakened-task-backstop-at-256-refused": any(
            isinstance(u, dict)
            and u.get("Name") == "nproc"
            and u.get("Soft") == 256
            and u.get("Hard") == 256
            for u in _e6_list(_e6_at(host, "Ulimits"))
        ),
    }
    return checks[case]


def _e6_demux(raw: bytes) -> bytes | None:
    """An exec stream's stdout, by its 8-byte frame headers; `None` if it is
    not a multiplexed stream."""
    out = bytearray()
    at = 0
    while at < len(raw):
        header = raw[at : at + 8]
        if len(header) < 8 or header[0] not in (1, 2) or header[1:4] != b"\0\0\0":
            return None
        size = int.from_bytes(header[4:8], "big")
        payload = raw[at + 8 : at + 8 + size]
        if len(payload) != size:
            return None
        if header[0] == 1:
            out += payload
        at += 8 + size
    return bytes(out)


def _e6_files_of(case: str) -> tuple[str, ...]:
    """The raw files the test keeps of `case`: every case's, and for the
    host's network the host's loopback before and after."""
    return (*E6_RAW_FILES, E6_HOST_LOOPBACK) if case == E6_HOST_NETWORK else E6_RAW_FILES


def _e6_gate_read(requests: list[str], container: str) -> str | None:
    """Why the broker's requests do not show it reading the environment's
    record once the environment started, before it made any peer -- the
    peer's gate (ADR-0059) -- or `None`."""
    started = f"POST /containers/{container}/start 204"
    read = f"GET /containers/{container}/json 200"
    if started not in requests:
        return "the environment was never started"
    after = requests[requests.index(started) + 1 :]
    if read not in after:
        return "the broker never read the environment's record"
    peer = next((i for i, r in enumerate(after) if r.startswith("POST /containers/create ")), None)
    if peer is not None and peer < after.index(read):
        return "the broker made a peer before it read the environment's record"
    return None


def _e6_loopback(data: bytes) -> tuple[list[str], list[str]]:
    """The host's IPv4 loopback addresses before and after, as the test kept
    them (`before <address>` and `after <address>`, one per line), or
    TaskError."""
    kept: dict[str, list[str]] = {"before": [], "after": []}
    for line in data.decode("utf-8", "replace").splitlines():
        when, _, address = line.partition(" ")
        if when not in kept or not _E6_ADDRESS.fullmatch(address):
            raise TaskError(f"E6 {E6_HOST_NETWORK}: an unreadable loopback line: {line[:80]!r}")
        kept[when].append(address)
    return kept["before"], kept["after"]


def e6_check_raw(
    output: str, raw: Path, lines: list[dict[str, object]], tag: str
) -> dict[tuple[str, str], bytes]:
    """E6's raw observations, checked again from their bytes -- independently
    of the test that made them -- before a line is believed.

    For the control and every exercised row: each of its raw files
    (`E6_RAW_FILES`, and the host's loopback for the host's network), once,
    at the digest and length the test printed when it wrote it, and nothing
    else; the create as the client sent it is the same strict plan for every
    case (its labels aside), and the daemon received it unchanged (the
    control) or changed in exactly the row's fields; the daemon's record shows
    the weakening; the probe's stream holds exactly its report; every inside
    verdict of the broker's answer is the probe's own, every invariant the
    row names failed, and the topology's verdicts are the line's; the broker
    was told nothing was kept (a row) or kept it (the control), and its own
    event says so; the broker read the environment's record before it made
    any peer (ADR-0059); its requests built the whole topology -- except for
    the host's network, where it made no setup and no relay, its own event
    says it withheld them, the measurement found no relay, and the host's
    loopback is what it was, the proxy address on it neither before nor
    after, as the line says. Any other finding fails the task. The checked
    bytes, by (case, file)."""
    printed = _e6_raw_lines(output)
    outcomes = {str(line["case"]): str(line["outcome"]) for line in lines}
    exercised = [E6_CONTROL] + [c for c in E6_ROWS if not outcomes[c].startswith("not-exercised")]
    files: dict[tuple[str, str], bytes] = {}
    for case in exercised:
        where = raw / case
        present = sorted(p.name for p in where.iterdir()) if where.is_dir() else []
        wanted = sorted(_e6_files_of(case))
        if present != wanted:
            raise TaskError(f"E6 {case}: raw files {present}, not {wanted}")
        for name in wanted:
            data = (where / name).read_bytes()
            said = printed.get((case, name))
            digest = hashlib.sha256(data).hexdigest()
            if said != (digest, len(data)):
                raise TaskError(
                    f"E6 {case}/{name}: {digest} ({len(data)} bytes) is not what the test "
                    f"printed when it wrote it: {said}"
                )
            files[(case, name)] = data
    extra = sorted({case for case, _ in printed} - set(exercised))
    if extra:
        raise TaskError(f"E6 raw observations of cases not exercised: {extra}")
    plans: dict[str, object] = {}
    for case in exercised:
        sent = _e6_json(files[(case, "create-sent.json")], f"E6 {case}: the create sent")
        received = _e6_json(files[(case, "create-received.json")], f"E6 {case}: received")
        if _e6_at(sent, "Labels", "io.direwolf.role") != "environment":
            raise TaskError(f"E6 {case}: the create kept is not the environment's")
        # The plan, its labels aside; its environment a set (the client
        # orders the proxy variables differently from one call to the next).
        plan = {
            k: sorted(_e6_strings(v)) if k == "Env" else v for k, v in sent.items() if k != "Labels"
        }
        plans[case] = plan
        if case == E6_CONTROL:
            if files[(case, "create-sent.json")] != files[(case, "create-received.json")]:
                raise TaskError("E6 control: the create was not forwarded byte for byte")
        else:
            changed = _e6_changed(sent, received)
            if changed != sorted(E6_ROWS[case][2]):
                raise TaskError(f"E6 {case}: the daemon received {changed} changed")
            if plan != plans[E6_CONTROL]:
                raise TaskError(f"E6 {case}: the client asked for another plan")
            record = _e6_json(files[(case, "record.json")], f"E6 {case}: the record")
            if not _e6_recorded(case, record, tag):
                raise TaskError(f"E6 {case}: the daemon's record does not show the weakening")
        stdout = _e6_demux(files[(case, "probe-stream.bin")])
        if stdout is None or stdout != files[(case, "probe-report.json")]:
            raise TaskError(f"E6 {case}: the probe's report is not its stream's stdout")
        report = _e6_json(stdout, f"E6 {case}: the probe's report")
        answer = files[(case, "measurement.txt")].decode("utf-8").splitlines()
        retained = answer[0] if answer else ""
        verdicts = {name: verdict for name, _, verdict in (a.partition(" ") for a in answer[1:])}
        checks = report.get("checks")
        if not isinstance(checks, list) or not checks:
            raise TaskError(f"E6 {case}: the probe's report holds no checks")
        for check in checks:
            if not isinstance(check, dict) or verdicts.get(
                str(check.get("invariant"))
            ) != check.get("verdict"):
                raise TaskError(f"E6 {case}: {check} is not the broker's inside verdict")
        events = files[(case, "broker-events.txt")].decode("utf-8", "replace")
        requests = files[(case, "requests.txt")].decode("utf-8", "replace")
        if "POST /containers/create 201 role=environment" not in requests:
            raise TaskError(f"E6 {case}: the broker's environment was never created")
        record = _e6_json(files[(case, "record.json")], f"E6 {case}: the record")
        unread = _e6_gate_read(requests.splitlines(), str(record.get("Id")))
        if unread is not None:
            raise TaskError(f"E6 {case}: {unread}")
        host = case == E6_HOST_NETWORK
        for role in ("setup", "relay"):
            made = f"role={role}" in requests
            if made and host:
                raise TaskError(f"E6 {case}: the broker made a {role} in the host's namespace")
            if not made and not host:
                raise TaskError(f"E6 {case}: the broker's {role} was never created")
        withheld = "relay_withheld network=FAIL" in events
        if withheld != host or ("relay_withheld" in events) != host:
            raise TaskError(f"E6 {case}: the broker's own event of its peer: withheld={withheld}")
        fields = _e6_fields(outcomes[case])
        if host:
            before, after = _e6_loopback(files[(case, E6_HOST_LOOPBACK)])
            if "127.0.0.1/8" not in before:
                raise TaskError(f"E6 {case}: not the host's loopback: {before}")
            if "169.254.7.1/32" in before + after or sorted(after) != sorted(before):
                raise TaskError(
                    f"E6 {case}: the host's loopback changed, or holds the proxy address: "
                    f"{before} -> {after}"
                )
            if fields.get("host-loopback-added") != "none":
                raise TaskError(f"E6 {case}: the line's loopback is not what the host kept")
            for invariant in ("HOST_PROXY_RELAY", "HOST_RELAY_DIGEST"):
                if verdicts.get(invariant) != "FAIL":
                    found = verdicts.get(invariant)
                    raise TaskError(f"E6 {case}: {invariant} is {found}, with no peer made")
        topology = _e6_verdicts(fields.get("topology", "")) or {}
        if any(verdicts.get(name) != verdict for name, verdict in topology.items()):
            raise TaskError(f"E6 {case}: the line's topology is not the broker's answer")
        if case == E6_CONTROL:
            if retained != "retained=true" or "retained=true" not in events:
                raise TaskError("E6 control: not kept by the broker")
            if any(v != "PASS" for k, v in verdicts.items() if k in E6_TOPOLOGY):
                raise TaskError("E6 control: the topology did not pass")
            continue
        if retained != "retained=false" or "retained=false" not in events:
            raise TaskError(f"E6 {case}: the broker did not refuse it")
        for invariant in E6_ROWS[case][1]:
            if verdicts.get(invariant) != "FAIL":
                raise TaskError(f"E6 {case}: {invariant} is {verdicts.get(invariant)}, not FAIL")
    return files


def _e6_provenance(
    client: Path, chosen: str, server: Mapping[str, object], images: Mapping[str, str]
) -> dict[str, object]:
    """Where E6's evidence ran, and from what (§3b criterion 2)."""
    environ = os.environ
    commit = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=str(ROOT), capture_output=True, text=True, check=False
    ).stdout.strip()
    dirty = subprocess.run(
        ["git", "status", "--porcelain"], cwd=str(ROOT), capture_output=True, text=True, check=False
    ).stdout.strip()
    run_url = None
    if environ.get("GITHUB_RUN_ID"):
        run_url = (
            f"{environ.get('GITHUB_SERVER_URL', 'https://github.com')}/"
            f"{environ.get('GITHUB_REPOSITORY', '')}/actions/runs/{environ['GITHUB_RUN_ID']}"
            f"/attempts/{environ.get('GITHUB_RUN_ATTEMPT', '1')}"
        )
    return {
        "commit": commit,
        "github_sha": environ.get("GITHUB_SHA"),
        "worktree_clean": not dirty,
        "run": run_url,
        "job": environ.get("GITHUB_JOB"),
        "runner": {
            "environment": environ.get("RUNNER_ENVIRONMENT"),
            "os": environ.get("RUNNER_OS"),
            "arch": environ.get("RUNNER_ARCH"),
            "image": environ.get("ImageOS"),
            "image_version": environ.get("ImageVersion"),
            "kernel": platform.release(),
        },
        "runtime": {
            "version": server.get("Version"),
            "api": server.get("ApiVersion"),
            "os": server.get("Os"),
            "arch": server.get("Arch"),
            "kernel": server.get("KernelVersion"),
        },
        "client": {
            "path": str(client),
            "identity": chosen,
            "sha256": hashlib.sha256(client.read_bytes()).hexdigest(),
        },
        "probe_sha256": environ.get("DW_SANDBOX_PROBE_SHA256"),
        "relay_sha256": environ.get("DW_EGRESS_RELAY_SHA256"),
        "images": dict(images),
        "tests": list(E6_TESTS),
    }


def _e6_publish(
    files: Mapping[tuple[str, str], bytes],
    provenance: Mapping[str, object],
    census: str,
) -> str:
    """Every checked observation into the log, each with its digest, then
    one manifest of them all and of where they came from: the hosted run's
    log is the evidence's record (§3b criterion 10). The manifest's own
    digest, which the review recomputes."""
    entries = []
    for (case, name), data in sorted(files.items()):
        entry = {
            "case": case,
            "file": name,
            "bytes": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
        }
        entries.append(entry)
        print(
            E6_FILE_PREFIX
            + json.dumps(
                {**entry, "base64": base64.b64encode(data).decode("ascii")},
                sort_keys=True,
                separators=(",", ":"),
            ),
            flush=True,
        )
    manifest = {
        "schema": "direwolf.m5e2.e6-evidence",
        "version": 1,
        "provenance": dict(provenance),
        "census": census,
        "cases": [case for _, case in E6_CASES],
        "files": entries,
    }
    text = json.dumps(manifest, sort_keys=True, separators=(",", ":"))
    digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
    print(E6_MANIFEST_PREFIX + json.dumps({"manifest": manifest, "sha256": digest}), flush=True)
    return digest


def task_sandbox_proxy_weakened_evidence() -> None:
    """M5e.2's R3 at the real-container level -- ADR-0057's E6, the owner's
    R-B -- hosted only: every hard rule of `oci-strict` weakened, one at a
    time, in a real `PROXY_ONLY` environment the released broker prepared
    through its production path, measured from both vantages and refused by
    its production decision; and the conforming control through the same
    faulty runtime, kept.

    Anywhere but a disposable GitHub-hosted runner this refuses before
    anything is built: NOT EXERCISED, which fails. Every case must report at
    `real-oci` with what caught it and what else moved; each case's raw
    observations are then checked again from their bytes (`e6_check_raw`)
    and published into the log with their digests and the run's provenance
    (`_e6_publish`). No container or network the evidence made may remain,
    and every one that predates it must. Linux only.
    """
    if not sys.platform.startswith("linux"):
        raise TaskError("NOT EXERCISED: E6 runs only on Linux")
    refusal = e6_refusal(os.environ)
    if refusal is not None:
        raise TaskError(f"NOT EXERCISED: {refusal}")
    found = shutil.which("docker")
    if found is None:
        raise TaskError("NOT EXERCISED: no container runtime client (`docker`) on PATH")
    socket = os.environ.get("DW_SANDBOX_SOCKET", "/var/run/docker.sock")
    target_root = Path(os.environ.get("CARGO_TARGET_DIR", str(ROOT / "target")))
    work = Path(os.environ.get("DW_E6_WORK", str(Path.home() / ".cache" / "dw-m5e2-e6")))
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(mode=0o700, parents=True)
    client, chosen = _trusted_client(Path(found), work / "client")
    try:
        server = json.loads(
            _docker(client, socket, "version", "--format", "{{json .Server}}").strip()
        )
    except (TaskError, json.JSONDecodeError) as exc:
        raise TaskError(f"NOT EXERCISED: the runtime at {socket} does not answer: {exc}") from exc
    if server.get("Os") != "linux":
        raise TaskError(f"NOT EXERCISED: the runtime is not a Linux one: {server.get('Os')}")
    system = _docker(client, socket, "info", "--format", "{{.OperatingSystem}}")
    if "Docker Desktop" in system:
        raise TaskError(f"NOT EXERCISED: the runtime is {system.strip()}, not a runner's")
    before_containers, before_networks = _runtime_state(client, socket)
    images: dict[str, str] = {}
    tag = f"direwolf-e6-mutable:{os.getpid()}"
    try:
        images, variables = _proxy_only_images(client, socket, server, target_root, work)
        _docker(client, socket, "image", "tag", images["product"], tag)
        raw = work / "raw"
        raw.mkdir(mode=0o700)
        os.environ.update(
            {**variables, "DW_E6_IMAGE_TAG": tag, "DW_E6_RAW_DIR": str(raw), "DW_E6_EVIDENCE": "1"}
        )
        run("cargo", "build", "--locked", "-p", "dwkd-broker")
        output = run_captured(
            "cargo",
            "test",
            "--locked",
            "-p",
            "dwkd-broker",
            "--test",
            "sandbox_egress",
            "--",
            "--ignored",
            "--exact",
            "--nocapture",
            "--test-threads=1",
            *E6_TESTS,
        )
        summaries = [line for line in output.splitlines() if line.startswith("test result: ")]
        expected = f"test result: ok. {len(E6_TESTS)} passed; 0 failed; 0 ignored"
        if len(summaries) != 1 or not summaries[0].startswith(expected):
            raise TaskError(
                f"E6 did not run: expected `{expected}`, got {summaries or 'no summary'}"
            )
    finally:
        after_containers, after_networks = _runtime_state(client, socket)
        _docker(client, socket, "image", "rm", tag, check=False)
        for image in set(images.values()):
            _docker(client, socket, "image", "rm", "--force", image, check=False)
    left = sorted(after_containers - before_containers)
    removed = sorted(before_containers - after_containers)
    left_networks = sorted(after_networks - before_networks)
    removed_networks = sorted(before_networks - after_networks)
    if left or left_networks:
        raise TaskError(
            f"the evidence left {len(left)} container(s) and {len(left_networks)} network(s) "
            f"behind: {left + left_networks}"
        )
    if removed or removed_networks:
        raise TaskError(
            f"{len(removed) + len(removed_networks)} resource(s) that predate the evidence are "
            f"gone: {removed + removed_networks}"
        )
    census = (
        f"no evidence container or network remains; {len(before_containers)} container(s) "
        f"and {len(before_networks)} network(s) pre-existing kept"
    )
    report_cleanup(f"cleanup: {census}")
    lines = require_attributed_evidence(output, E6_CASES)
    files = e6_check_raw(output, raw, lines, tag)
    provenance = _e6_provenance(client, chosen, server, {**images, "mutable-tag": tag})
    digest = _e6_publish(files, provenance, census)
    print(
        f"{GREEN}E6: {len(E6_ROWS)} cases over {len(E6_ROW_NAMES)} rows refused, the control "
        f"kept; {len(files)} raw observations checked and published, manifest sha256 "
        f"{digest}{OFF}"
    )


def e6_review(log: str) -> str:
    """A hosted E6 log, verified offline: every published observation
    decoded at its digest, the manifest's digest recomputed, the lines
    attributed as the task requires, and every observation checked again
    (`e6_check_raw`) from the decoded bytes. The manifest's digest."""
    manifests = []
    published: dict[tuple[str, str], bytes] = {}
    for line in log.splitlines():
        for prefix in (E6_FILE_PREFIX, E6_MANIFEST_PREFIX):
            at = line.find(prefix)
            if at < 0:
                continue
            record = json.loads(line[at + len(prefix) :])
            if prefix == E6_MANIFEST_PREFIX:
                manifests.append(record)
                continue
            data = base64.b64decode(record["base64"], validate=True)
            if hashlib.sha256(data).hexdigest() != record["sha256"] or len(data) != record["bytes"]:
                raise TaskError(f"E6 review: {record['case']}/{record['file']} is not its digest")
            key = (record["case"], record["file"])
            if key in published:
                raise TaskError(f"E6 review: {key} published twice")
            published[key] = data
    if len(manifests) != 1:
        raise TaskError(f"E6 review: {len(manifests)} manifests, not one")
    manifest, said = manifests[0]["manifest"], manifests[0]["sha256"]
    text = json.dumps(manifest, sort_keys=True, separators=(",", ":"))
    if hashlib.sha256(text.encode("utf-8")).hexdigest() != said:
        raise TaskError("E6 review: the manifest is not its digest")
    listed = {(f["case"], f["file"]): f["sha256"] for f in manifest["files"]}
    if listed != {k: hashlib.sha256(v).hexdigest() for k, v in published.items()}:
        raise TaskError("E6 review: the published files are not the manifest's")
    lines = require_attributed_evidence(log, E6_CASES)
    tag = str(manifest["provenance"]["images"].get("mutable-tag", ""))
    with tempfile.TemporaryDirectory() as scratch:
        raw = Path(scratch)
        for (case, name), data in published.items():
            (raw / case).mkdir(exist_ok=True)
            (raw / case / name).write_bytes(data)
        e6_check_raw(log, raw, lines, tag)
    return str(said)


def task_sandbox_proxy_weakened_review() -> None:
    """Verify a downloaded hosted `sandbox-proxy-weakened` job log offline
    (`DW_E6_LOG=<file>`): what the owner's review of E6 runs, needing no
    runtime. Reads the file and nothing else."""
    path = os.environ.get("DW_E6_LOG", "")
    if not path:
        raise TaskError("set DW_E6_LOG to a downloaded `sandbox-proxy-weakened` job log")
    digest = e6_review(Path(path).read_text(encoding="utf-8", errors="replace"))
    print(f"{GREEN}E6 review: every observation verified; manifest sha256 {digest}{OFF}")


# --- M5e.4: pip as it is today, and npm refused (M5E_ASSURANCE_PLAN.md §§6, 8) ---

# The registry tools' pins (OD-E4): each tool's exact version, its upstream
# archive and that archive's SHA-256. A version change is a reviewed diff of
# that file, never a download that floats.
REGISTRY_PINS = ROOT / "tests" / "sandbox" / "registry_tools.toml"
# Where each pinned archive may come from, https only: its URL's host first,
# then the hosts a redirect may name -- for a GitHub release asset, the
# storage GitHub answers with. Nothing else is ever fetched.
REGISTRY_TOOL_HOSTS: dict[str, tuple[str, ...]] = {
    "python": (
        "github.com",
        "release-assets.githubusercontent.com",
        "objects.githubusercontent.com",
    ),
    "pip": ("files.pythonhosted.org",),
    "node": ("nodejs.org",),
}
REGISTRY_ARCHIVE_LIMIT = 256 * 1024 * 1024
# Where the registry tools image holds each tool.
REGISTRY_PYTHON_HOME = "/opt/direwolf/python"
REGISTRY_NODE_HOME = "/opt/direwolf/node"
REGISTRY_NPM_PATH = f"{REGISTRY_NODE_HOME}/bin/npm"
# The one `npm` the image holds: npm's own CLI, started by the pinned Node.js
# by absolute path (a `FROM scratch` image has no `/usr/bin/env`). M5e.4 never
# runs it -- the authority refuses it first -- but the operator's policy and
# the image manifest pin these bytes, so the refusal is of a real, pinned npm.
REGISTRY_NPM_LAUNCHER = (
    f"#!{REGISTRY_NODE_HOME}/bin/node\n"
    f"require('{REGISTRY_NODE_HOME}/lib/node_modules/npm/lib/cli.js')(process)\n"
)
REGISTRY_SUITE = "sandbox-registry"
_EXACT_VERSION = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
_SHA256_HEX = re.compile(r"[0-9a-f]{64}")


def _pinned_interpreter(path: Path, entry: dict[str, object]) -> dict[str, str]:
    """`[python]`'s two facts about the interpreter its archive holds, taken
    out of `entry` and checked: a size the broker can hash (a larger one would
    be refused EXECUTABLE_CHANGED at every launch) and a lowercase SHA-256."""
    size = entry.pop("executable_bytes", None)
    digest = entry.pop("executable_sha256", None)
    if not isinstance(size, int) or isinstance(size, bool) or size < 1:
        raise TaskError(f"{path}: [python] executable_bytes is a byte count, not {size!r}")
    if size > EXECUTABLE_COPY_BOUND:
        raise TaskError(
            f"{path}: [python] executable_bytes {size} is past the broker's bound of "
            f"{EXECUTABLE_COPY_BOUND}: every launch would be refused EXECUTABLE_CHANGED"
        )
    if not isinstance(digest, str) or not _SHA256_HEX.fullmatch(digest):
        raise TaskError(f"{path}: [python] executable_sha256 is 64 lowercase hex digits")
    return {"executable_bytes": str(size), "executable_sha256": digest}


def load_registry_pins(path: Path = REGISTRY_PINS) -> dict[str, dict[str, str]]:
    """The registry tools' pins, each checked, or TaskError: format 1;
    exactly `python`, `pip` and `node`; each an exact `N.N.N` version, a
    lowercase SHA-256, and an https URL on its own host -- no port, query,
    fragment or credentials -- whose path names that version; `node` also
    npm's exact version; `python` also its interpreter's size, within the
    broker's bound, and SHA-256. A pin is never guessed and never defaulted."""
    import tomllib  # Python 3.11+: only the registry evidence reads it

    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as exc:
        raise TaskError(f"{path}: unreadable registry pins: {exc}") from exc
    if data.get("format") != 1:
        raise TaskError(f"{path}: `format` must be 1, not {data.get('format')!r}")
    tools = sorted(key for key in data if key != "format")
    if tools != sorted(REGISTRY_TOOL_HOSTS):
        raise TaskError(f"{path}: the pins are exactly {sorted(REGISTRY_TOOL_HOSTS)}, not {tools}")
    pins: dict[str, dict[str, str]] = {}
    for tool, hosts in REGISTRY_TOOL_HOSTS.items():
        entry = dict(data[tool]) if isinstance(data[tool], dict) else {}
        interpreter = _pinned_interpreter(path, entry) if tool == "python" else {}
        keys = {"version", "url", "sha256"} | ({"npm_version"} if tool == "node" else set())
        if set(entry) != keys or not all(isinstance(value, str) for value in entry.values()):
            raise TaskError(f"{path}: [{tool}] holds exactly {sorted(keys)}, each a string")
        for key in sorted(keys - {"url", "sha256"}):
            if not _EXACT_VERSION.fullmatch(entry[key]):
                raise TaskError(f"{path}: [{tool}] {key} is an exact N.N.N, not {entry[key]!r}")
        if not _SHA256_HEX.fullmatch(entry["sha256"]):
            raise TaskError(f"{path}: [{tool}] sha256 is 64 lowercase hex digits")
        url = urllib.parse.urlsplit(entry["url"])
        if (
            url.scheme != "https"
            or url.hostname != hosts[0]
            or url.netloc != hosts[0]
            or url.query
            or url.fragment
        ):
            raise TaskError(f"{path}: [{tool}] url is https://{hosts[0]}/..., not {entry['url']!r}")
        if entry["version"] not in Path(urllib.parse.unquote(url.path)).name:
            raise TaskError(f"{path}: [{tool}] url's file does not name version {entry['version']}")
        pins[tool] = {**entry, **interpreter}
    return pins


def _registry_redirects(tool: str) -> type:
    """A redirect handler that follows only https to the tool's own hosts."""
    import urllib.request

    allowed = REGISTRY_TOOL_HOSTS[tool]

    class Redirects(urllib.request.HTTPRedirectHandler):
        def redirect_request(
            self,
            req: urllib.request.Request,
            fp: object,
            code: int,
            msg: str,
            headers: object,
            newurl: str,
        ) -> urllib.request.Request | None:
            target = urllib.parse.urlsplit(newurl)
            if target.scheme != "https" or target.hostname not in allowed:
                raise TaskError(
                    f"{tool}: a redirect to {target.scheme}://{target.hostname} is refused "
                    f"(only https to {', '.join(allowed)})"
                )
            return super().redirect_request(req, fp, code, msg, headers, newurl)  # type: ignore[arg-type]

    return Redirects


def _fetch_verified(
    tool: str, url: str, sha256: str, into: Path, *, opener: object | None = None
) -> Path:
    """`url`'s bytes as a new file in `into`, once their SHA-256 is `sha256`.

    https only, from the tool's hosts only, redirects included; at most
    REGISTRY_ARCHIVE_LIMIT bytes. Any other answer, or a byte that differs,
    raises TaskError and leaves no file behind: a mismatch fails closed, and
    nothing reads an archive before its digest is checked. The disposable
    runner's only download (`opener` is the tests')."""
    import urllib.request

    asked = urllib.parse.urlsplit(url)
    if asked.scheme != "https" or asked.hostname != REGISTRY_TOOL_HOSTS[tool][0]:
        raise TaskError(f"{tool}: {url} is not https on {REGISTRY_TOOL_HOSTS[tool][0]}")
    name = Path(urllib.parse.unquote(urllib.parse.urlsplit(url).path)).name
    if not name or name.startswith("."):
        raise TaskError(f"{tool}: {url} names no file")
    target = into / name
    partial = into / f"{name}.partial"
    hasher = hashlib.sha256()
    size = 0
    fetch = opener or urllib.request.build_opener(_registry_redirects(tool))
    # https on the tool's own host, checked above; every redirect and the
    # final answer are checked again.
    request = urllib.request.Request(  # noqa: S310
        url, headers={"User-Agent": "direwolf-registry-evidence"}
    )
    try:
        with fetch.open(request, timeout=120) as response, partial.open("xb") as out:  # type: ignore[attr-defined]
            final = urllib.parse.urlsplit(response.geturl())
            if final.scheme != "https" or final.hostname not in REGISTRY_TOOL_HOSTS[tool]:
                raise TaskError(f"{tool}: answered from {final.scheme}://{final.hostname}")
            while chunk := response.read(1 << 20):
                size += len(chunk)
                if size > REGISTRY_ARCHIVE_LIMIT:
                    raise TaskError(f"{tool}: {name} is over {REGISTRY_ARCHIVE_LIMIT} bytes")
                hasher.update(chunk)
                out.write(chunk)
    except TaskError:
        partial.unlink(missing_ok=True)
        raise
    except OSError as exc:
        partial.unlink(missing_ok=True)
        raise TaskError(f"{tool}: {url} could not be fetched: {exc}") from exc
    got = hasher.hexdigest()
    if got != sha256:
        partial.unlink(missing_ok=True)
        raise TaskError(f"{tool}: {name} is sha256 {got}, not the pinned {sha256}: refused")
    partial.rename(target)
    return target


def _extract_tar(archive: Path, into: Path, top: str) -> Path:
    """`archive`'s one top-level directory `top`, extracted under `into`
    through tarfile's `data` filter -- no absolute name, no `..`, no link
    leaving it, no device, no set-id bit. A member outside `top` refuses."""
    import tarfile

    with tarfile.open(archive) as tar:
        members = tar.getmembers()
        for member in members:
            if member.name != top and not member.name.startswith(f"{top}/"):
                raise TaskError(f"{archive.name}: {member.name!r} is outside {top}/")
        try:
            tar.extractall(into, members=members, filter="data")
        except tarfile.FilterError as exc:
            raise TaskError(f"{archive.name}: refused by the data filter: {exc}") from exc
    return into / top


def _unzip_wheel(wheel: Path, into: Path) -> int:
    """`wheel`'s members under `into`: each a relative name of plain segments,
    no `..`, no backslash, no link. Returns how many."""
    import zipfile

    with zipfile.ZipFile(wheel) as archive:
        members = archive.infolist()
        for info in members:
            parts = info.filename.split("/")
            if (
                info.filename.startswith("/")
                or "\\" in info.filename
                or ".." in parts
                or (info.external_attr >> 16) & 0o170000 == 0o120000
            ):
                raise TaskError(f"{wheel.name}: refused member {info.filename!r}")
        archive.extractall(into)  # noqa: S202 - every member's name is checked above
    return len(members)


def _registry_tools_image(
    client: Path,
    socket: str,
    context: Path,
    binaries: tuple[Path, Path],
    platform_: str,
    pins: dict[str, dict[str, str]],
) -> tuple[str, dict[str, str]]:
    """M5e.4's registry tools image, built on the disposable runner only.

    Each pinned archive is fetched and checked against its recorded SHA-256
    before a byte of it is read (`_fetch_verified`): a standalone CPython at
    REGISTRY_PYTHON_HOME, its bundled pip replaced by the pinned pip wheel;
    Node.js at REGISTRY_NODE_HOME with the npm it bundles, `bin/npm` the one
    launcher REGISTRY_NPM_LAUNCHER; the probe and the relay at their paths;
    every shared object they load. Built offline `FROM scratch` with
    `--network none` and named by content; then each tool's version is read
    from inside the image -- no network, uid 10001, read-only, no capability
    -- and must be its pin's, or this raises, the image removed first. No
    trust store and no pip or npm configuration is baked in: pip trusts what
    its caller names (`--cert`), as pip does today. The archives are kept
    beside the build context, never in it: only `rootfs/` reaches the
    runtime. Returns the image and the variables the suite reads."""
    probe, relay = binaries
    downloads = context.parent / f"{context.name}-downloads"
    shutil.rmtree(context, ignore_errors=True)
    shutil.rmtree(downloads, ignore_errors=True)
    downloads.mkdir(parents=True)
    rootfs = context / "rootfs"
    opt = rootfs / "opt" / "direwolf"
    opt.mkdir(parents=True)
    _place(rootfs, probe, "/usr/libexec/direwolf/sandbox-probe", 0o755)
    _place(rootfs, relay, SANDBOX_RELAY_PATH, 0o755)
    archives = {
        tool: _fetch_verified(tool, pin["url"], pin["sha256"], downloads)
        for tool, pin in pins.items()
    }

    minor = ".".join(pins["python"]["version"].split(".")[:2])
    python_home = _extract_tar(archives["python"], opt, Path(REGISTRY_PYTHON_HOME).name)
    python = python_home / "bin" / f"python{minor}"
    if python.is_symlink() or not python.is_file():
        raise TaskError(f"the CPython build has no interpreter at bin/python{minor}")
    # The bytes the broker hashes before every launch: the archive's own
    # interpreter, at the size the pin holds within the broker's bound.
    python_size = python.stat().st_size
    python_sha = hashlib.sha256(python.read_bytes()).hexdigest()
    pinned_interpreter = (pins["python"]["executable_bytes"], pins["python"]["executable_sha256"])
    if (str(python_size), python_sha) != pinned_interpreter:
        raise TaskError(
            f"the interpreter is {python_size} bytes, sha256 {python_sha}, not the pinned "
            f"{pinned_interpreter[0]} bytes, sha256 {pinned_interpreter[1]}: refused"
        )
    site = python_home / "lib" / f"python{minor}" / "site-packages"
    if not site.is_dir():
        raise TaskError(f"the CPython build has no {site.relative_to(python_home)}")
    for bundled in [*site.glob("pip"), *site.glob("pip-*.dist-info")]:
        shutil.rmtree(bundled)
    members = _unzip_wheel(archives["pip"], site)

    node_top = f"node-v{pins['node']['version']}-linux-x64"
    node_home = _extract_tar(archives["node"], opt, node_top).rename(opt / "node")
    node = node_home / "bin" / "node"
    package = node_home / "lib" / "node_modules" / "npm" / "package.json"
    if node.is_symlink() or not node.is_file() or not package.is_file():
        raise TaskError(f"{archives['node'].name} has no bin/node or bundled npm")
    npm = node_home / "bin" / "npm"
    npm.unlink(missing_ok=True)
    npm.write_bytes(REGISTRY_NPM_LAUNCHER.encode("utf-8"))  # its bytes, never a newline's
    npm.chmod(0o755)

    loaded = [
        python,
        node,
        *sorted(python_home.glob("lib/libpython*.so*")),
        *sorted((python_home / "lib" / f"python{minor}" / "lib-dynload").glob("*.so")),
    ]
    for library in sorted(_ldd_closure([p for p in loaded if not p.is_symlink()])):
        if not library.is_relative_to(rootfs):
            _place(rootfs, library, str(library))
    (context / "Dockerfile").write_text("FROM scratch\nCOPY rootfs/ /\n", encoding="utf-8")
    iid = context / "iid"
    _docker(
        client,
        socket,
        "build",
        "--quiet",
        "--pull=false",
        "--network",
        "none",
        "--platform",
        platform_,
        "--iidfile",
        str(iid),
        str(context),
    )
    image = iid.read_text(encoding="utf-8").strip()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
        raise TaskError(f"the built image has no content identity: {image!r}")

    def inside(*argv: str) -> str:
        return _docker(
            client,
            socket,
            "run",
            "--rm",
            "--network",
            "none",
            "--read-only",
            "--user",
            "10001:10001",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--platform",
            platform_,
            image,
            *argv,
        ).strip()

    image_python = f"{REGISTRY_PYTHON_HOME}/bin/python{minor}"
    wanted = {
        "python": pins["python"]["version"],
        "pip": pins["pip"]["version"],
        "node": pins["node"]["version"],
        "npm": pins["node"]["npm_version"],
    }
    try:
        found = {
            "python": inside(image_python, "-I", "-c", "import sys; print(sys.version.split()[0])"),
            "pip": inside(image_python, "-I", "-c", "import pip; print(pip.__version__)"),
            "node": inside(f"{REGISTRY_NODE_HOME}/bin/node", "--version").removeprefix("v"),
            "npm": inside(
                f"{REGISTRY_NODE_HOME}/bin/node",
                "-p",
                f"require('{REGISTRY_NODE_HOME}/lib/node_modules/npm/package.json').version",
            ),
        }
        for tool, version in wanted.items():
            if found[tool] != version:
                raise TaskError(
                    f"the image's {tool} reports {found[tool]!r}, not the pinned {version}: refused"
                )
    except BaseException:
        # An image that fails its checks is never left behind: the task's
        # own cleanup begins only once setup has returned.
        _docker(client, socket, "image", "rm", "--force", image, check=False)
        raise

    def digest(path: Path) -> str:
        return hashlib.sha256(path.read_bytes()).hexdigest()

    npm_sha, node_sha = digest(npm), digest(node)
    print(f"{BOLD}registry tools image{OFF} (built on this runner, offline, FROM scratch)")
    for tool in ("python", "pip", "node"):
        print(
            f"  {tool:<8} {pins[tool]['version']:<9} archive sha256 {pins[tool]['sha256']} "
            f"(checked before use)\n           {pins[tool]['url']}"
        )
    print(f"  pip      {found['pip']:<9} {members} members, in {site.relative_to(rootfs)}")
    print(f"  npm      {found['npm']:<9} bundled with Node.js {found['node']}")
    print(
        f"  {image_python} {python_size} bytes, sha256 {python_sha} "
        f"(the broker hashes at most {EXECUTABLE_COPY_BOUND})"
    )
    print(f"  {REGISTRY_NODE_HOME}/bin/node sha256 {node_sha}")
    print(f"  {REGISTRY_NPM_PATH} sha256 {npm_sha}")
    print(f"  image              {image}")
    print(
        "  versions read inside the image: "
        + ", ".join(f"{tool} {found[tool]}" for tool in ("python", "pip", "node", "npm"))
    )
    variables = {
        "DW_REGISTRY_IMAGE": image,
        "DW_REGISTRY_PYTHON": image_python,
        "DW_REGISTRY_PYTHON_SHA256": python_sha,
        "DW_REGISTRY_PYTHON_VERSION": found["python"],
        "DW_REGISTRY_PIP_VERSION": found["pip"],
        "DW_REGISTRY_NPM": REGISTRY_NPM_PATH,
        "DW_REGISTRY_NPM_SHA256": npm_sha,
    }
    return image, variables


def _registry_setup(
    pins: dict[str, dict[str, str]],
) -> tuple[Path, str, dict[str, str], set[str], set[str], list[str]]:
    """M5e.4's setup, separate from the evidence: a trusted runtime client;
    the probe and the relay built statically and proved static from their
    ELF headers, their digests pinned; the registry tools image. Returns the
    client, the socket, the variables the suite reads, the containers and
    the networks that predate the evidence, and the images to remove."""
    found = shutil.which("docker")
    if found is None:
        raise TaskError("NOT EXERCISED: no container runtime client (`docker`) on PATH")
    socket = os.environ.get("DW_SANDBOX_SOCKET", "/var/run/docker.sock")
    target_root = Path(os.environ.get("CARGO_TARGET_DIR", str(ROOT / "target")))
    work = Path(os.environ.get("DW_REGISTRY_WORK", str(Path.home() / ".cache" / "dw-m5e4")))
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(mode=0o700, parents=True)
    client, chosen = _trusted_client(Path(found), work / "client")
    try:
        server = json.loads(
            _docker(client, socket, "version", "--format", "{{json .Server}}").strip()
        )
    except (TaskError, json.JSONDecodeError) as exc:
        raise TaskError(f"NOT EXERCISED: the runtime at {socket} does not answer: {exc}") from exc
    if server.get("Os") != "linux" or server.get("Arch") != "amd64":
        # The pins are x86_64 Linux archives (registry_tools.toml).
        raise TaskError(
            f"NOT EXERCISED: the registry tools are pinned for linux/amd64, not "
            f"{server.get('Os')}/{server.get('Arch')}"
        )
    triple = "x86_64-unknown-linux-gnu"
    platform_ = "linux/amd64"
    before = set(
        _docker(client, socket, "container", "ls", "--all", "--no-trunc", "--quiet").split()
    )
    networks = set(_docker(client, socket, "network", "ls", "--no-trunc", "--quiet").split())
    static = target_root / "sandbox-static"
    env = dict(os.environ, RUSTFLAGS="-C target-feature=+crt-static")
    command = [
        "cargo",
        "build",
        "--locked",
        "--release",
        "-p",
        "dwk-sandbox-probe",
        "--bin",
        "dwk-sandbox-probe",
        "-p",
        "dwk-sandbox-relay",
        "--bin",
        "dwk-sandbox-relay",
        "--target",
        triple,
        "--target-dir",
        str(static),
    ]
    print(f"{DIM}$ RUSTFLAGS='-C target-feature=+crt-static' {' '.join(command)}{OFF}", flush=True)
    if subprocess.run(command, cwd=str(ROOT), env=env, check=False).returncode != 0:
        raise TaskError("the static probe and relay did not build")
    release = static / triple / "release"
    probe = release / "dwk-sandbox-probe"
    relay = release / "dwk-sandbox-relay"
    linking = {name: _static_elf(path) for name, path in (("probe", probe), ("relay", relay))}
    digests = {
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in (("probe", probe), ("relay", relay))
    }
    print(f"{BOLD}registry evidence setup{OFF}")
    print(
        f"  runtime            {server.get('Version')} (api {server.get('ApiVersion')}), "
        f"{platform_}"
    )
    print(f"  runtime client     {chosen}")
    for name in ("probe", "relay"):
        print(f"  {name:<18} {linking[name]}, sha256 {digests[name]}")
    image, tools = _registry_tools_image(
        client, socket, work / "images" / "registry", (probe, relay), platform_, pins
    )
    variables = {
        "DW_SANDBOX_RUNTIME": str(client),
        "DW_SANDBOX_SOCKET": socket,
        "DW_SANDBOX_PROBE_SHA256": digests["probe"],
        "DW_EGRESS_RELAY_SHA256": digests["relay"],
        **tools,
    }
    return client, socket, variables, before, networks, [image]


# The registry suite: pip as it is today, and npm refused. Both download
# nothing -- the image is built first, by the task -- and reach only the
# fixture origins on this runner's loopback.
REGISTRY_TESTS = (
    "linux::pip_as_it_is_today_reaches_only_the_granted_fixture_registry",
    "linux::npm_is_refused_before_anything_is_prepared",
)
# Every case the registry suite must report, at `dwkp-end-to-end`: a real
# DWKP client on the released `serve --sandbox-config`, the released broker,
# the runner's Docker Engine, a measured `PROXY_ONLY` environment per case.
# Named `registry-*`, apart from the cases ADR-0054 §8 and ADR-0055 §9
# propose for the profiles (M5e.5).
REGISTRY_CASES = tuple(
    (REGISTRY_SUITE, case)
    for case in (
        "registry-tools-pinned-in-the-environment",
        "registry-pip-granted-index-installs",
        "registry-pip-dependency-from-granted-index",
        "registry-pip-ungranted-index-refused",
        "registry-pip-ungranted-index-installs-when-granted",
        "registry-pip-file-on-ungranted-host-refused",
        "registry-pip-redirect-to-ungranted-host-refused",
        "registry-pip-direct-route-refused",
        "registry-pip-direct-by-name-unresolved",
        "registry-pip-untrusted-issuer-refused",
        "registry-pip-sdist-built-today",
        "registry-pip-pth-not-run-by-install",
        "registry-pip-pth-runs-at-a-later-start",
        "registry-intent-names-only-the-granted-registry",
        "registry-egress-counted-at-destruction",
        "registry-census-clean",
        "registry-npm-install-refused-before-preparation",
        "registry-npm-ci-refused-before-preparation",
        "registry-npm-nothing-prepared-or-reached",
    )
)
# What each registry line's outcome must begin with (`outcome_problem`): an
# install that shows what it installed; a refusal that shows nothing was
# installed; the gap a source distribution's build is today, shown, never
# hidden; npm's refusal by the obligation.
REGISTRY_OUTCOMES = {
    "registry-tools-pinned-in-the-environment": "pinned:",
    "registry-pip-granted-index-installs": "installed:",
    "registry-pip-dependency-from-granted-index": "installed:",
    "registry-pip-ungranted-index-refused": "refused:nothing-installed",
    "registry-pip-ungranted-index-installs-when-granted": "installed:",
    "registry-pip-file-on-ungranted-host-refused": "refused:nothing-installed",
    "registry-pip-redirect-to-ungranted-host-refused": "refused:nothing-installed",
    "registry-pip-direct-route-refused": "refused:nothing-installed",
    "registry-pip-direct-by-name-unresolved": "refused:nothing-installed",
    "registry-pip-untrusted-issuer-refused": "refused:nothing-installed",
    "registry-pip-sdist-built-today": "built-today:backend-marker-present",
    "registry-pip-pth-not-run-by-install": "not-run:pth-marker-absent",
    "registry-pip-pth-runs-at-a-later-start": "runs-later:pth-marker-present",
    "registry-intent-names-only-the-granted-registry": "granted:",
    "registry-egress-counted-at-destruction": "counted:",
    "registry-census-clean": "clean:",
    "registry-npm-install-refused-before-preparation": "refused:OBLIGATION_UNENFORCEABLE",
    "registry-npm-ci-refused-before-preparation": "refused:OBLIGATION_UNENFORCEABLE",
    "registry-npm-nothing-prepared-or-reached": "nothing:",
}


def registry_refusal(environ: Mapping[str, str]) -> str | None:
    """Why this host must not run the registry evidence, or None. Never
    inferred: `DW_REGISTRY_EVIDENCE=1`, on a GitHub-hosted runner -- the
    package-manager tools are downloaded and run on a disposable runner only
    (owner direction 3), never installed on a developer's host. The suite
    checks again before it starts anything."""
    if environ.get("DW_REGISTRY_EVIDENCE", "").strip() != "1":
        return (
            "DW_REGISTRY_EVIDENCE=1 is not set: the registry tools are downloaded and run "
            "only by the hosted `sandbox-registry` job"
        )
    if (
        environ.get("GITHUB_ACTIONS") != "true"
        or environ.get("RUNNER_ENVIRONMENT") != "github-hosted"
    ):
        return (
            "this is not a disposable GitHub-hosted runner: registry tools are never "
            "installed on a developer's host"
        )
    return None


def registry_census_problems(
    before: set[str], after: set[str], networks: set[str], networks_after: set[str]
) -> list[str]:
    """What the registry evidence's census finds wrong, as text: a container
    it left, a container that predates it gone, or the runtime's networks
    changed. Nothing found is the empty list."""
    problems: list[str] = []
    if after - before:
        problems.append(
            f"the evidence left {len(after - before)} container(s): {sorted(after - before)}"
        )
    if before - after:
        problems.append(
            f"{len(before - after)} container(s) that predate the evidence are gone: "
            f"{sorted(before - after)}"
        )
    if networks_after != networks:
        problems.append(
            f"the runtime's networks changed: made {sorted(networks_after - networks)}, "
            f"lost {sorted(networks - networks_after)}"
        )
    return problems


def task_sandbox_registry_evidence() -> None:
    """M5e.4's evidence (M5E_ASSURANCE_PLAN.md §§6, 8), hosted only: pip as
    it is today against M5e.3's fixture registries, and npm refused before
    anything is prepared.

    Anywhere but a disposable GitHub-hosted runner this refuses before
    anything is fetched or built: NOT EXERCISED, which fails. There, the
    registry tools image is built from its pins, each archive checked before
    use; then a real DWKP client on the released `serve --sandbox-config`,
    with the released broker and the runner's Docker Engine, runs pip in a
    fresh measured `PROXY_ONLY` environment per case -- installing from the
    granted fixture index, refused by the proxy's grant, by the namespace's
    topology and by its own TLS verification -- and asks for `npm install`
    and `npm ci`, which the authority refuses before any environment.

    Every case must report at `dwkp-end-to-end` with what enforced or
    observed it, its outcome showing what it claims (`outcome_problem`). No
    container or network the evidence made may remain, and every one that
    predates it must. The images are removed. Linux only.
    """
    if not sys.platform.startswith("linux"):
        raise TaskError("NOT EXERCISED: the registry evidence runs only on Linux")
    refusal = registry_refusal(os.environ)
    if refusal is not None:
        raise TaskError(f"NOT EXERCISED: {refusal}")
    pins = load_registry_pins()
    client, socket, variables, before, networks, images = _registry_setup(pins)
    os.environ.update(variables)
    try:
        system = _docker(client, socket, "info", "--format", "{{.OperatingSystem}}")
        if "Docker Desktop" in system:
            raise TaskError(f"NOT EXERCISED: the runtime is {system.strip()}, not a runner's")
        run("cargo", "build", "--locked", "-p", "dwkd-broker")
        output = run_captured(
            "cargo",
            "test",
            "--locked",
            "-p",
            "dwkd-authority",
            "--test",
            "sandbox_registry",
            "--",
            "--ignored",
            "--exact",
            "--nocapture",
            "--test-threads=1",
            *REGISTRY_TESTS,
        )
        summaries = [line for line in output.splitlines() if line.startswith("test result: ")]
        expected = f"test result: ok. {len(REGISTRY_TESTS)} passed; 0 failed; 0 ignored"
        if len(summaries) != 1 or not summaries[0].startswith(expected):
            raise TaskError(
                f"the registry suite did not run all of its tests: expected `{expected}`, "
                f"got {summaries or 'no summary'}"
            )
    finally:
        after = set(
            _docker(client, socket, "container", "ls", "--all", "--no-trunc", "--quiet").split()
        )
        networks_after = set(
            _docker(client, socket, "network", "ls", "--no-trunc", "--quiet").split()
        )
        for image in images:
            _docker(client, socket, "image", "rm", "--force", image, check=False)
    problems = registry_census_problems(before, after, networks, networks_after)
    if problems:
        raise TaskError("cleanup failed: " + "; ".join(problems))
    report_cleanup(
        f"cleanup: no evidence container or network remains; {len(before)} pre-existing "
        f"container(s) and {len(networks)} network(s) kept; the images removed"
    )
    require_attributed_evidence(output, REGISTRY_CASES)


# ---- M5e.5: the npm and pip profiles, evidenced (hosted only) ----------------
#
# ADR-0054 §8's and ADR-0055 §9's cases, by name, against the profiles the
# authority keeps only under its evidence-only start-up option (TX060)
# (plan §10, "M5e.5's sequencing"). Nothing here is required by `ci`: the
# owner runs it by hand (`.github/workflows/m5e5-evidence.yml`) until M5e.4's
# repair has passed hosted and the owner adds it.
HYGIENE_SUITE = "sandbox-hygiene"
HYGIENE_FLAG = "DW_HYGIENE_EVIDENCE"
# The image's trust files (ADR-0054 §4, ADR-0055 §5; the preparation
# handoff's D3), the system store a third authority sits in, and the image's
# own pip configuration (ADR-0055 §9's `pip-image-configuration-not-read`).
HYGIENE_NPM_TRUST = "/etc/direwolf/npm-ca.pem"
HYGIENE_PIP_TRUST = "/etc/direwolf/pip-ca.pem"
HYGIENE_SYSTEM_STORES = ("/etc/ssl/certs/ca-certificates.crt", "/etc/ssl/cert.pem")
HYGIENE_PIP_CONF = (
    "[global]\nindex-url = https://ungranted-registry.test:18444/simple/\nno-binary = :all:\n"
)
HYGIENE_PIP_PATH = f"{REGISTRY_PYTHON_HOME}/bin/pip"
HYGIENE_NPX_PATH = f"{REGISTRY_NODE_HOME}/bin/npx"
# `npx`, pinned beside npm so its refusal is of a real, pinned npx.
HYGIENE_NPX_LAUNCHER = (
    f"#!{REGISTRY_NODE_HOME}/bin/node\n"
    f"require('{REGISTRY_NODE_HOME}/lib/node_modules/npm/bin/npx-cli.js')\n"
)


def hygiene_pip_launcher(minor: str) -> str:
    """pip, started by the pinned interpreter by absolute path: the CPython
    build's own `bin/pip` needs `/bin/sh`, which a `FROM scratch` image lacks
    (the preparation handoff §7). Its last component is `pip`, the profile's
    identity (ADR-0055 §1)."""
    return (
        f"#!{REGISTRY_PYTHON_HOME}/bin/python{minor} -I\n"
        "import sys\n"
        "from pip._internal.cli.main import main\n"
        "sys.exit(main())\n"
    )


HYGIENE_TESTS = (
    "linux::npm_under_its_proposed_profile",
    "linux::pip_under_its_proposed_profile",
    "linux::without_a_trust_file_both_fail_closed",
    "linux::without_the_option_nothing_changes",
    "linux::the_shipped_packs_decide",
)
# ADR-0054 §8's 22 and ADR-0055 §9's 21, by their exact names; and the
# preparation handoff's D4, the interpreter's way around pip's profile.
HYGIENE_NPM_CASES = (
    "npm-ci-granted-registry-installs",
    "npm-install-granted-registry-installs",
    "npm-ungranted-registry-refused",
    "npm-tarball-on-ungranted-host-refused",
    "npm-redirect-to-ungranted-host-refused",
    "npm-direct-route-refused",
    "npm-lifecycle-scripts-not-run",
    "npm-project-npmrc-cannot-reenable-scripts",
    "npm-project-npmrc-cannot-disable-tls",
    "npm-project-npmrc-cannot-replace-ca",
    "npm-missing-trust-file-fails-closed",
    "npm-git-dependency-not-prepared",
    "npm-untrusted-issuer-refused",
    "npm-tampered-tarball-refused",
    "npm-writes-only-workspace-and-tmp",
    "npm-undoing-arguments-refused",
    "npm-other-subcommands-refused",
    "npm-non-registry-specs-refused",
    "npx-still-refused",
    "npm-refused-without-the-evidence-option",
    "npm-shipped-packs-behaviour",
    "npm-plan-records-prefix-and-profile",
)
HYGIENE_PIP_CASES = (
    "pip-install-granted-index-installs",
    "pip-install-dependency-resolved-from-granted-index",
    "pip-ungranted-index-refused",
    "pip-file-on-ungranted-host-refused",
    "pip-redirect-to-ungranted-host-refused",
    "pip-direct-route-refused",
    "pip-sdist-never-built",
    "pip-only-binary-cannot-be-undone-by-variable-or-file",
    "pip-image-configuration-not-read",
    "pip-untrusted-issuer-refused",
    "pip-os-trust-store-not-used",
    "pip-missing-trust-file-fails-closed",
    "pip-undoing-arguments-refused",
    "pip-other-subcommands-refused",
    "pip-non-name-specs-refused",
    "pip-no-cache-reused",
    "pip-writes-only-workspace-and-tmp",
    "pip-installed-pth-not-executed-by-install",
    "pip-refused-without-the-evidence-option",
    "pip-shipped-packs-behaviour",
    "pip-plan-records-prefix-and-profile",
)
HYGIENE_EXTRA_CASES = ("pip-interpreter-module-refused",)
HYGIENE_CASES = tuple(
    (HYGIENE_SUITE, case) for case in (*HYGIENE_NPM_CASES, *HYGIENE_PIP_CASES, *HYGIENE_EXTRA_CASES)
)
# What each line's outcome must begin with (`outcome_problem`).
HYGIENE_OUTCOMES = {
    "npm-ci-granted-registry-installs": "installed:",
    "npm-install-granted-registry-installs": "installed:",
    "npm-ungranted-registry-refused": "refused:nothing-installed",
    "npm-tarball-on-ungranted-host-refused": "refused:nothing-installed",
    "npm-redirect-to-ungranted-host-refused": "refused:nothing-installed",
    "npm-direct-route-refused": "refused:nothing-installed;ENETUNREACH",
    "npm-lifecycle-scripts-not-run": "not-run:",
    "npm-project-npmrc-cannot-reenable-scripts": "not-run:",
    "npm-project-npmrc-cannot-disable-tls": "refused:nothing-installed",
    "npm-project-npmrc-cannot-replace-ca": "installed:image-trust-file-in-force",
    # Not that TLS failed -- npm would fall back to Node.js's bundled roots,
    # pip to nothing -- but that nothing was tunnelled at all.
    "npm-missing-trust-file-fails-closed": ("refused:nothing-installed;no-tunnel;launcher-refused"),
    "npm-git-dependency-not-prepared": "not-prepared:no-prepare-marker",
    "npm-untrusted-issuer-refused": "refused:nothing-installed",
    "npm-tampered-tarball-refused": "refused:EINTEGRITY",
    "npm-writes-only-workspace-and-tmp": "contained:",
    "npm-undoing-arguments-refused": "refused:OBLIGATION_UNENFORCEABLE",
    "npm-other-subcommands-refused": "refused:OBLIGATION_UNENFORCEABLE",
    "npm-non-registry-specs-refused": "refused:OBLIGATION_UNENFORCEABLE",
    "npx-still-refused": "refused:OBLIGATION_UNENFORCEABLE",
    "npm-refused-without-the-evidence-option": "refused:OBLIGATION_UNENFORCEABLE",
    "npm-shipped-packs-behaviour": "decided:",
    "npm-plan-records-prefix-and-profile": "recorded:launch-HYGIENE_NPM",
    "pip-install-granted-index-installs": "installed:",
    "pip-install-dependency-resolved-from-granted-index": "installed:",
    "pip-ungranted-index-refused": "refused:nothing-installed",
    "pip-file-on-ungranted-host-refused": "refused:nothing-installed",
    "pip-redirect-to-ungranted-host-refused": "refused:nothing-installed",
    "pip-direct-route-refused": "refused:nothing-installed;ENETUNREACH",
    "pip-sdist-never-built": "not-built:backend-marker-absent",
    "pip-only-binary-cannot-be-undone-by-variable-or-file": "not-built:",
    "pip-image-configuration-not-read": "not-read:",
    "pip-untrusted-issuer-refused": "refused:nothing-installed",
    "pip-os-trust-store-not-used": "refused:nothing-installed",
    "pip-missing-trust-file-fails-closed": (
        "refused:nothing-installed;no-tunnel;cert-bundle-missing"
    ),
    "pip-undoing-arguments-refused": "refused:OBLIGATION_UNENFORCEABLE",
    "pip-other-subcommands-refused": "refused:OBLIGATION_UNENFORCEABLE",
    "pip-non-name-specs-refused": "refused:OBLIGATION_UNENFORCEABLE",
    "pip-no-cache-reused": "refetched:",
    "pip-writes-only-workspace-and-tmp": "contained:",
    "pip-installed-pth-not-executed-by-install": "not-run:pth-marker-absent",
    "pip-refused-without-the-evidence-option": "today:launch-HYGIENE",
    "pip-shipped-packs-behaviour": "denied:",
    "pip-plan-records-prefix-and-profile": "recorded:launch-HYGIENE_PIP",
    "pip-interpreter-module-refused": "refused:OBLIGATION_UNENFORCEABLE",
}


def hygiene_refusal(environ: Mapping[str, str]) -> str | None:
    """Why this host must not run the hygiene evidence, or None: the same
    rule as the registry's (owner direction 3), with its own flag."""
    if environ.get(HYGIENE_FLAG, "").strip() != "1":
        return (
            f"{HYGIENE_FLAG}=1 is not set: the npm and pip profiles' evidence runs only in the "
            "manual `sandbox-hygiene` job, on a disposable GitHub-hosted runner"
        )
    return registry_refusal({**environ, "DW_REGISTRY_EVIDENCE": "1"})


# Where the environment mounts its workspace and its two temporary
# directories (`dwk-sandbox-profile`'s WORKSPACE_TARGET, TMP_TARGET and
# VAR_TMP_TARGET). The hygiene images carry each as an empty directory, so
# the runtime makes no mount point in a container's own layer and
# `docker container diff` shows writes, not mounts
# (`*-writes-only-workspace-and-tmp`).
# Paths inside an image, never this host's.
HYGIENE_MOUNT_POINTS = ("/workspace", "/tmp", "/var/tmp")  # noqa: S108


def hygiene_rootfs(base: Path, context: Path, pki: Path, minor: str, *, trusted: bool) -> Path:
    """One hygiene image's root at `context/rootfs`, copied from the
    registry tools image's checked rootfs (`base/rootfs`): `pip` and `npx`
    launchers, the image `pip.conf`, the third authority in the system
    store, an empty directory at each of HYGIENE_MOUNT_POINTS, and -- when
    `trusted` -- the run's anchor (`pki/ca.pem`) at both trust paths. No
    runtime is touched. Returns the rootfs."""
    shutil.rmtree(context, ignore_errors=True)
    shutil.copytree(base / "rootfs", context / "rootfs", symlinks=True)
    rootfs = context / "rootfs"
    pip = rootfs / HYGIENE_PIP_PATH.lstrip("/")
    pip.unlink(missing_ok=True)
    pip.write_bytes(hygiene_pip_launcher(minor).encode("utf-8"))
    pip.chmod(0o755)
    npx = rootfs / HYGIENE_NPX_PATH.lstrip("/")
    npx.unlink(missing_ok=True)
    npx.write_bytes(HYGIENE_NPX_LAUNCHER.encode("utf-8"))
    npx.chmod(0o755)
    etc = rootfs / "etc"
    (etc / "direwolf").mkdir(parents=True, exist_ok=True)
    if trusted:
        for path in (HYGIENE_NPM_TRUST, HYGIENE_PIP_TRUST):
            _place(rootfs, pki / "ca.pem", path, 0o644)
    for path in HYGIENE_SYSTEM_STORES:
        _place(rootfs, pki / "system.pem", path, 0o644)
    (etc / "pip.conf").write_text(HYGIENE_PIP_CONF, encoding="utf-8")
    for point in HYGIENE_MOUNT_POINTS:
        directory = rootfs / point.lstrip("/")
        directory.mkdir(parents=True, exist_ok=True)
        directory.chmod(0o755)
    return rootfs


def _hygiene_images(
    client: Path,
    socket: str,
    base: Path,
    pki: Path,
    platform_: str,
    minor: str,
) -> tuple[list[str], dict[str, str]]:
    """The two images M5e.5's evidence runs in, built from the registry tools
    image's checked rootfs (`base`), offline `FROM scratch`: one with the
    run's anchor at both trust paths, the third authority in the system
    store, the image `pip.conf`, `pip` and `npx`; one the same without the
    trust files. Returns the images and the variables the suite reads."""
    if not (base / "rootfs").is_dir():
        raise TaskError(f"no registry tools rootfs at {base}")
    images: list[str] = []
    variables: dict[str, str] = {}
    for name, trusted in (("hygiene", True), ("hygiene-no-trust", False)):
        context = base.parent / name
        rootfs = hygiene_rootfs(base, context, pki, minor, trusted=trusted)
        pip = rootfs / HYGIENE_PIP_PATH.lstrip("/")
        npx = rootfs / HYGIENE_NPX_PATH.lstrip("/")
        (context / "Dockerfile").write_text("FROM scratch\nCOPY rootfs/ /\n", encoding="utf-8")
        iid = context / "iid"
        _docker(
            client,
            socket,
            "build",
            "--quiet",
            "--pull=false",
            "--network",
            "none",
            "--platform",
            platform_,
            "--iidfile",
            str(iid),
            str(context),
        )
        image = iid.read_text(encoding="utf-8").strip()
        if not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
            raise TaskError(f"the {name} image has no content identity: {image!r}")
        images.append(image)
        present = (rootfs / HYGIENE_PIP_TRUST.lstrip("/")).is_file()
        if present != trusted:
            raise TaskError(f"the {name} image's trust files are not as built")
        variables["DW_HYGIENE_IMAGE" if trusted else "DW_HYGIENE_IMAGE_NO_TRUST"] = image
        if trusted:
            variables["DW_HYGIENE_PIP"] = HYGIENE_PIP_PATH
            variables["DW_HYGIENE_PIP_SHA256"] = hashlib.sha256(pip.read_bytes()).hexdigest()
            variables["DW_HYGIENE_NPX"] = HYGIENE_NPX_PATH
            variables["DW_HYGIENE_NPX_SHA256"] = hashlib.sha256(npx.read_bytes()).hexdigest()
        print(f"  {name:<18} {image} (trust files: {'yes' if trusted else 'no'})")
    print(f"  {HYGIENE_PIP_PATH} sha256 {variables['DW_HYGIENE_PIP_SHA256']}")
    print(f"  {HYGIENE_NPX_PATH} sha256 {variables['DW_HYGIENE_NPX_SHA256']}")
    return images, variables


def task_sandbox_hygiene_evidence() -> None:
    """M5e.5's evidence (ADR-0054 §8, ADR-0055 §9), hosted only: npm and pip
    under their proposed profiles, through the released authority started
    with its evidence-only start-up option for both, the released broker
    and the runner's Docker Engine, against M5e.3's fixture registries.

    Anywhere but a disposable GitHub-hosted runner with DW_HYGIENE_EVIDENCE=1
    it refuses before anything is fetched or built: NOT EXERCISED, which
    fails. Every case must report at `dwkp-end-to-end`, attributed, its
    outcome showing what it claims; no container or network the evidence made
    may remain; the images are removed. Required by no `ci` job until the
    owner adds it after M5e.4's repair passes hosted."""
    if not sys.platform.startswith("linux"):
        raise TaskError("NOT EXERCISED: the hygiene evidence runs only on Linux")
    refusal = hygiene_refusal(os.environ)
    if refusal is not None:
        raise TaskError(f"NOT EXERCISED: {refusal}")
    pins = load_registry_pins()
    client, socket, variables, before, networks, images = _registry_setup(pins)
    work = Path(os.environ.get("DW_REGISTRY_WORK", str(Path.home() / ".cache" / "dw-m5e4")))
    pki = work / "hygiene-pki"
    shutil.rmtree(pki, ignore_errors=True)
    run("bash", "tests/net_http/make-pki.sh", str(pki))
    minor = ".".join(pins["python"]["version"].split(".")[:2])
    try:
        made, hygiene = _hygiene_images(
            client, socket, work / "images" / "registry", pki, "linux/amd64", minor
        )
        images += made
        os.environ.update({**variables, **hygiene, "DW_HYGIENE_PKI": str(pki), HYGIENE_FLAG: "1"})
        system = _docker(client, socket, "info", "--format", "{{.OperatingSystem}}")
        if "Docker Desktop" in system:
            raise TaskError(f"NOT EXERCISED: the runtime is {system.strip()}, not a runner's")
        run("cargo", "build", "--locked", "-p", "dwkd-broker")
        output = run_captured(
            "cargo",
            "test",
            "--locked",
            "-p",
            "dwkd-authority",
            "--test",
            "sandbox_hygiene",
            "--",
            "--ignored",
            "--exact",
            "--nocapture",
            "--test-threads=1",
            *HYGIENE_TESTS,
        )
        summaries = [line for line in output.splitlines() if line.startswith("test result: ")]
        expected = f"test result: ok. {len(HYGIENE_TESTS)} passed; 0 failed; 0 ignored"
        if len(summaries) != 1 or not summaries[0].startswith(expected):
            raise TaskError(
                f"the hygiene suite did not run all of its tests: expected `{expected}`, "
                f"got {summaries or 'no summary'}"
            )
    finally:
        after = set(
            _docker(client, socket, "container", "ls", "--all", "--no-trunc", "--quiet").split()
        )
        networks_after = set(
            _docker(client, socket, "network", "ls", "--no-trunc", "--quiet").split()
        )
        for image in images:
            _docker(client, socket, "image", "rm", "--force", image, check=False)
    problems = registry_census_problems(before, after, networks, networks_after)
    if problems:
        raise TaskError("cleanup failed: " + "; ".join(problems))
    report_cleanup(
        f"cleanup: no evidence container or network remains; {len(before)} pre-existing "
        f"container(s) and {len(networks)} network(s) kept; the images removed"
    )
    require_attributed_evidence(output, HYGIENE_CASES)


# ADR-0054 §9's and ADR-0055 §10's mutation review (the preparation handoff
# §9, the owner's OD-E7): each guard weakened in turn. A `unit` mutant must
# fail the obligation's or the launcher's unit tests -- anywhere; a `hosted`
# one only the hosted evidence can kill, and is reported NOT EXERCISED off a
# disposable GitHub-hosted runner, never as killed. Every file is restored
# and proved byte-identical, whatever happens.
_HYGIENE_RS = "crates/dwkd-authority/src/resource/exec/hygiene.rs"
_PROFILE_RS = "crates/dwk-sandbox-profile/src/lib.rs"
_SANDBOX_RS = "crates/dwkd-authority/src/sandbox.rs"
_LAUNCH_RS = "crates/dwk-sandbox-probe/src/launch.rs"
# The tests each guard's unit mutants must fail, by name.
_KEEPS_NPM = ("npm_keeps_ci_and_install_of_registry_names_with_its_prefix",)
_UNDOES_NPM = ("npm_refuses_each_argument_that_would_undo_it_in_every_spelling",)
_UNDOES_PIP = ("pip_refuses_each_argument_that_would_undo_or_widen_it",)
_NPM_EVIDENCE = ("npm_under_its_proposed_profile",)
_PIP_EVIDENCE = ("pip_under_its_proposed_profile",)
# (name, file, the guard's text, its weakening, unit or hosted, the tests at
# least one of which must fail for the mutant to be killed).
HYGIENE_MUTATIONS: tuple[tuple[str, str, str, str, str, tuple[str, ...]], ...] = (
    (
        "default: a profile on with no flag",
        _HYGIENE_RS,
        "    pub const NONE: Self = Self {\n        npm: false,\n        pip: false,\n    };",
        "    pub const NONE: Self = Self {\n        npm: true,\n        pip: true,\n    };",
        "unit",
        ("with_no_profile_every_decision_is_todays",),
    ),
    (
        "fence: the option kept outside the evidence's workspace",
        _SANDBOX_RS,
        "        if !profiles.is_none() && !matches!(self.workspace, "
        "WorkspaceSetting::UnverifiedEvidence) {\n",
        "        if false && !matches!(self.workspace, WorkspaceSetting::UnverifiedEvidence) {\n",
        "unit",
        ("an_unaccepted_profile_is_kept_only_in_the_evidence_harness_configuration",),
    ),
    (
        "npm subcommands: run allowed",
        _HYGIENE_RS,
        'const NPM_SUBCOMMANDS: &[&str] = &["ci", "install"];',
        'const NPM_SUBCOMMANDS: &[&str] = &["ci", "install", "run"];',
        "unit",
        ("npm_refuses_every_other_subcommand_alias_and_separator",),
    ),
    (
        "npm specs: a git URL allowed",
        _HYGIENE_RS,
        "        _ => specs.iter().all(|spec| npm_registry_spec(spec)),",
        "        _ => true,",
        "unit",
        ("npm_refuses_every_spec_that_is_not_a_registry_name",),
    ),
    *(
        (
            f"npm refusals: {option} removed",
            _HYGIENE_RS,
            f'    "{option}",\n',
            "",
            "unit",
            _UNDOES_NPM,
        )
        for option in (
            "userconfig",
            "globalconfig",
            "location",
            "script-shell",
            "node-options",
            "foreground-scripts",
            "cafile",
        )
    ),
    (
        "npm refusals: the pinned booleans unpinned",
        _HYGIENE_RS,
        'const NPM_PINNED_TRUE: &[&str] = &["ignore-scripts", "strict-ssl"];',
        "const NPM_PINNED_TRUE: &[&str] = &[];",
        "unit",
        _UNDOES_NPM,
    ),
    (
        "npm prefix: --ignore-scripts dropped",
        _HYGIENE_RS,
        'const NPM_PREFIX: &[&str] = &[\n    "--ignore-scripts",\n',
        "const NPM_PREFIX: &[&str] = &[\n",
        "unit",
        _KEEPS_NPM,
    ),
    (
        "npx: moved out of UNEVIDENCED",
        _HYGIENE_RS,
        'const UNEVIDENCED: &[&str] = &["npm", "npx", "pnpm", "yarn", "bun", "cargo"];',
        'const UNEVIDENCED: &[&str] = &["npm", "pnpm", "yarn", "bun", "cargo"];',
        "unit",
        (
            "a_tool_without_real_tool_evidence_is_not_kept",
            "npx_the_runners_and_the_wrappers_stay_refused_with_a_profile_on",
        ),
    ),
    (
        "pip subcommands: download allowed",
        _HYGIENE_RS,
        '    if *subcommand != "install" ',
        '    if *subcommand != "install" && *subcommand != "download" ',
        "unit",
        ("pip_refuses_every_other_subcommand_and_an_install_of_nothing",),
    ),
    (
        "pip specs: a URL allowed",
        _HYGIENE_RS,
        "                '.' | '-' | '_' | '*' | '+' | '!' | '=' | '<' | '>' | '~' | ',' | ' '\n",
        "                '.' | '-' | '_' | '*' | '+' | '!' | '=' | '<' | '>' | '~' | ','"
        " | ' ' | ':' | '/' | '@'\n",
        "unit",
        ("pip_refuses_every_spec_that_is_not_a_name",),
    ),
    *(
        (
            f"pip refusals: {option} removed",
            _HYGIENE_RS,
            f'    "{option}",\n',
            "",
            "unit",
            _UNDOES_PIP,
        )
        for option in (
            "no-binary",
            "editable",
            "isolated",
            "trusted-host",
            "client-cert",
            "requirement",
            "find-links",
            "user",
            "src",
            "cache-dir",
        )
    ),
    (
        "pip binary-only: --only-binary dropped from the prefix",
        _HYGIENE_RS,
        'const PIP_PREFIX: &[&str] = &[\n    "--only-binary=:all:",\n',
        "const PIP_PREFIX: &[&str] = &[\n",
        "unit",
        ("pip_keeps_install_of_names_with_its_prefix_after_the_subcommand",),
    ),
    # ADR-0055 §5, revised for F-PIP-TRUST: the prefix's `legacy-certs` is what
    # keeps pip's `truststore` context, and with it `certifi`'s roots and the
    # system's store, out of the trust. The unit mutant names another value;
    # the hosted one drops it, which only `pip-os-trust-store-not-used` -- last
    # in its test -- can catch: the evidence that the case can fail.
    (
        "pip trust: the prefix names another deprecated feature",
        _HYGIENE_RS,
        '    "--disable-pip-version-check",\n    "--use-deprecated=legacy-certs",\n',
        '    "--disable-pip-version-check",\n    "--use-deprecated=legacy-resolver",\n',
        "unit",
        ("pip_keeps_install_of_names_with_its_prefix_after_the_subcommand",),
    ),
    (
        "pip trust: --use-deprecated=legacy-certs dropped from the prefix",
        _HYGIENE_RS,
        '    "--disable-pip-version-check",\n    "--use-deprecated=legacy-certs",\n',
        '    "--disable-pip-version-check",\n',
        "hosted",
        _PIP_EVIDENCE,
    ),
    (
        "pip interpreter: -m pip allowed (D4)",
        _HYGIENE_RS,
        'matches!(module.split(\'.\').next(), Some("pip" | "ensurepip"))',
        "module.is_empty()",
        "unit",
        ("with_pips_profile_the_interpreter_cannot_run_pip_or_ensurepip",),
    ),
    (
        "npm trust: the launcher names no trust file for npm",
        _LAUNCH_RS,
        "            Self::Npm => Some(profile::NPM_TRUST_FILE),\n",
        "            Self::Npm => None,\n",
        "unit",
        ("only_npms_profile_needs_its_trust_file_before_it_launches",),
    ),
    (
        "npm trust: an empty trust file accepted",
        _LAUNCH_RS,
        "        .is_ok_and(|meta| meta.is_file() && meta.len() > 0)\n",
        "        .is_ok_and(|meta| meta.is_file())\n",
        "unit",
        ("a_trust_file_is_present_only_when_regular_readable_and_non_empty",),
    ),
    (
        "npm trust: the launcher's check removed",
        _LAUNCH_RS,
        "        .is_some_and(|file| !trust_present(file))\n",
        "        .is_some_and(|file| file.is_empty() && !trust_present(file))\n",
        "hosted",
        ("without_a_trust_file_both_fail_closed",),
    ),
    (
        "npm variables: npm_config_cafile dropped",
        _PROFILE_RS,
        '    ("npm_config_cafile", NPM_TRUST_FILE),\n',
        "",
        "hosted",
        _NPM_EVIDENCE,
    ),
    (
        "npm variables: npm_config_userconfig dropped",
        _PROFILE_RS,
        '    ("npm_config_userconfig", "/dev/null"),\n',
        "",
        "hosted",
        _NPM_EVIDENCE,
    ),
    (
        "npm variables: npm_config_globalconfig dropped",
        _PROFILE_RS,
        '    ("npm_config_globalconfig", "/dev/null"),\n',
        "",
        "hosted",
        _NPM_EVIDENCE,
    ),
    (
        "pip variables: PIP_CONFIG_FILE dropped",
        _PROFILE_RS,
        '    ("PIP_CONFIG_FILE", "/dev/null"),\n',
        "",
        "hosted",
        _PIP_EVIDENCE,
    ),
)
# Weakenings no test can observe while another layer of the same profile
# stands, each with why: applied by no run, never counted as killed, listed
# so the review is complete. Each target is still held to its file.
HYGIENE_EQUIVALENT_MUTATIONS: tuple[tuple[str, str, str, str], ...] = (
    (
        "pip binary-only: PIP_ONLY_BINARY dropped",
        _PROFILE_RS,
        '    ("PIP_ONLY_BINARY", ":all:"),\n',
        "the authority's prefix puts `--only-binary=:all:` on every profiled pip "
        "invocation, and pip's command line outranks the variable; removing the prefix's "
        "copy is the unit mutant 'pip binary-only: --only-binary dropped from the prefix'",
    ),
)
HYGIENE_UNIT_TESTS = (
    ("dwkd-authority", "--lib", "resource::exec::hygiene"),
    ("dwkd-authority", "--lib", "sandbox::tests"),
    ("dwk-sandbox-probe", "--bin", "dwk-sandbox-probe"),
)
_FAILED_TEST = re.compile(r"^test (\S+) \.\.\. FAILED$", re.MULTILINE)


def failed_tests(output: str) -> set[str]:
    """Every test `cargo test`'s output says failed: its `test <name> ...
    FAILED` lines and the names its closing `failures:` list gives."""
    failed = set(_FAILED_TEST.findall(output))
    listing = False
    for line in output.splitlines():
        if line.strip() == "failures:":
            listing = True
        elif listing and line.startswith("    ") and re.fullmatch(r"[\w:]+", line.strip()):
            failed.add(line.strip())
        elif line.startswith("test result:"):
            listing = False
    return failed


def mutant_verdict(output: str, any_step_failed: bool, expect: tuple[str, ...]) -> str:
    """A mutant's verdict from what its run printed: `killed` only when one
    of the tests `expect` names failed; `not-compiled` when the mutant did
    not build, which kills nothing; `failed-elsewhere` when a step failed
    but not one of those tests; `survived` when every step passed."""
    if "could not compile" in output or re.search(r"^error\[E\d+\]", output, re.MULTILINE):
        return "not-compiled"
    failed = failed_tests(output)
    if any(test == name or test.endswith(f"::{name}") for test in failed for name in expect):
        return "killed"
    return "failed-elsewhere" if any_step_failed else "survived"


def _mutant_outcome(
    rel: str, old: str, new: str, command: list[list[str]], expect: tuple[str, ...]
) -> tuple[str, list[str]]:
    """Apply one mutation, run every step of `command`, restore the file
    byte-identical: the verdict (`mutant_verdict`, or `not-applied` when the
    target is not in the file exactly once) and the tests that failed."""
    path = ROOT / rel
    original = path.read_bytes()
    digest = hashlib.sha256(original).hexdigest()
    text = original.decode("utf-8")
    if text.count(old) != 1:
        return "not-applied", []
    outputs: list[str] = []
    any_step_failed = False
    try:
        path.write_bytes(text.replace(old, new).encode("utf-8"))
        for step in command:
            result = subprocess.run(
                step,
                cwd=str(ROOT),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                errors="replace",
                check=False,
            )
            outputs.append(result.stdout)
            any_step_failed = any_step_failed or result.returncode != 0
    finally:
        path.write_bytes(original)
    if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
        raise TaskError(f"{rel} was not restored byte-identical")
    output = "".join(outputs)
    return mutant_verdict(output, any_step_failed, expect), sorted(failed_tests(output))


def task_sandbox_registry_mutations() -> None:
    """The profiles' mutation review (ADR-0054 §9, ADR-0055 §10): every
    `unit` mutant must be killed by the unit tests, here or hosted; every
    `hosted` one by the hosted evidence, only in the manual job -- anywhere
    else it is reported NOT EXERCISED and fails the task, never counted. A
    mutant is killed only when a test it names failed: one that does not
    build, or fails another test, is reported as such and fails the task.
    Each file is restored and proved byte-identical. The equivalent
    mutants are listed with why, and run by nothing."""
    unit = [
        ["cargo", "test", "--locked", "-p", crate, kind, "--", filter]
        if kind == "--lib"
        else ["cargo", "test", "--locked", "-p", crate, kind, crate]
        for crate, kind, filter in HYGIENE_UNIT_TESTS
    ]
    hosted = hygiene_refusal(os.environ) is None and sys.platform.startswith("linux")
    results: list[tuple[str, str, str]] = []
    for name, rel, old, new, kind, expect in HYGIENE_MUTATIONS:
        if kind == "hosted" and not hosted:
            print(f"  {'not-exercised':<16} {kind:<6} {name}", flush=True)
            results.append((name, kind, "not-exercised"))
            continue
        command = (
            unit
            if kind == "unit"
            else [[sys.executable, str(ROOT / "scripts" / "dw.py"), "sandbox-hygiene-evidence"]]
        )
        outcome, failed = _mutant_outcome(rel, old, new, command, expect)
        shown = ", ".join(failed[:3]) + (" ..." if len(failed) > 3 else "")
        print(
            f"  {outcome:<16} {kind:<6} {name}; expected {' or '.join(expect)}; "
            f"failed: {shown or 'none'}; {rel} restored byte-identical",
            flush=True,
        )
        results.append((name, kind, outcome))
    for name, _rel, _old, why in HYGIENE_EQUIVALENT_MUTATIONS:
        print(f"  {'equivalent':<16} {'-':<6} {name}: {why}", flush=True)
    bad = [r for r in results if r[2] != "killed"]
    for name, kind, outcome in bad:
        print(f"{RED}  {outcome}: {name} ({kind}){OFF}")
    killed = sum(1 for r in results if r[2] == "killed")
    print(
        f"{BOLD}{killed}/{len(results)} mutants killed; "
        f"{len(HYGIENE_EQUIVALENT_MUTATIONS)} equivalent, not run{OFF}"
    )
    if bad:
        raise TaskError(
            f"{len(bad)} mutant(s) not killed: "
            + ", ".join(f"{name} [{outcome}]" for name, _, outcome in bad)
        )


# ADR-0056 §6's negative control: the task backstop put back at the
# per-environment value it replaced. R8's two neighbour tests -- the
# broker's and the authority's -- must then each fail with finding F-R8's
# own signature, the coupling the remedy removed; a test that passes, or
# fails any other way, or a mutant that does not compile, fails the control.
# The file is restored and proved byte-identical whatever happens.
NEIGHBOUR_MUTATIONS = (
    (
        "the task backstop is the per-environment 256 again (finding F-R8)",
        "crates/dwk-sandbox-profile/src/lib.rs",
        "pub const RLIMIT_NPROC: u64 = PIDS_LIMIT * MAX_LIVE_ENVIRONMENTS * 2;\n"
        "const _: () = assert!(\n"
        "    RLIMIT_NPROC >= 2 * MAX_LIVE_ENVIRONMENTS * PIDS_LIMIT,\n",
        "pub const RLIMIT_NPROC: u64 = 256;\n"
        "const _: () = assert!(\n"
        "    RLIMIT_NPROC >= PIDS_LIMIT,\n",
    ),
)
NEIGHBOUR_TESTS = (
    ("dwkd-broker", WORKLOAD_BROKER_TESTS[-1]),
    ("dwkd-authority", WORKLOAD_AUTHORITY_TESTS[-1]),
)
NEIGHBOUR_SIGNATURE = "finding F-R8"


def _neighbour_outcomes() -> list[str]:
    """R8's two neighbour tests against the source as it is now: for each,
    `F-R8` when it failed with the finding's signature, else what it did."""
    client, socket, variables, before, images = _workload_setup()
    os.environ.update(variables)
    outcomes: list[str] = []
    try:
        run("cargo", "build", "--locked", "-p", "dwkd-broker")
        for package, name in NEIGHBOUR_TESTS:
            command = (
                "cargo",
                "test",
                "--locked",
                "-p",
                package,
                "--test",
                "sandbox_workload",
                "--",
                "--ignored",
                "--exact",
                "--nocapture",
                "--test-threads=1",
                name,
            )
            print(f"{DIM}$ {' '.join(command)}{OFF}", flush=True)
            result = subprocess.run(
                command,
                cwd=str(ROOT),
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                errors="replace",
                check=False,
            )
            failed = "test result: FAILED. 0 passed; 1 failed" in result.stdout
            if result.returncode != 0 and failed and NEIGHBOUR_SIGNATURE in result.stdout:
                outcomes.append("F-R8")
                # What it measured, as the test said it: the evidence of the kill.
                for line in result.stdout.splitlines():
                    if NEIGHBOUR_SIGNATURE in line:
                        print(f"{DIM}  {name.rsplit('::', 1)[-1]}: {line.strip()[:600]}{OFF}")
            elif result.returncode == 0:
                outcomes.append(f"{name} passed")
            else:
                outcomes.append(f"{name} failed without the finding's signature")
                print(result.stdout[-4000:])
    finally:
        after = set(
            _docker(client, socket, "container", "ls", "--all", "--no-trunc", "--quiet").split()
        )
        for image in set(images.values()):
            _docker(client, socket, "image", "rm", "--force", image, check=False)
    if sorted(after - before) or sorted(before - after):
        raise TaskError(
            f"the control left {sorted(after - before)} and removed {sorted(before - after)}"
        )
    return outcomes


def task_sandbox_neighbour_mutations() -> None:
    """ADR-0056 §6's negative control for R8: with the task backstop put
    back at 256, both neighbour tests must fail as finding F-R8 did -- the
    neighbour refused while the other environment holds its bound -- so a
    pass of theirs means the remedy, not a test that cannot see the
    coupling. Needs a runtime; restores the file byte-identically and checks.
    Linux only."""
    if not sys.platform.startswith("linux"):
        raise TaskError("NOT EXERCISED: the neighbour control needs Linux and an OCI runtime")
    killed: list[str] = []
    for what, rel, old, new in NEIGHBOUR_MUTATIONS:
        path = ROOT / rel
        original = path.read_bytes()
        digest = hashlib.sha256(original).hexdigest()
        text = original.decode("utf-8")
        if text.count(old) != 1:
            raise TaskError(f"mutation `{what}`: its target is not in {rel} exactly once")
        print(f"{BOLD}mutant: {what}{OFF}")
        try:
            path.write_bytes(text.replace(old, new).encode("utf-8"))
            outcomes = _neighbour_outcomes()
        finally:
            path.write_bytes(original)
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise TaskError(f"{rel} was not restored byte-identically")
        print(f"{DIM}restored {rel} (sha256 {digest[:16]}...){OFF}")
        if outcomes != ["F-R8"] * len(NEIGHBOUR_TESTS):
            raise TaskError(
                f"mutant `{what}` not caught as F-R8 by every neighbour test: {outcomes}"
            )
        killed.append(what)
        print(f"{GREEN}mutant killed as F-R8 by {len(NEIGHBOUR_TESTS)} tests: {what}{OFF}")
    print(
        f"{GREEN}neighbour control: {len(killed)} of {len(NEIGHBOUR_MUTATIONS)} killed as F-R8{OFF}"
    )


# The mutation review (ADR-0052 §17): each line weakens one guard M5d.1's
# evidence exists to prove, in the source, one at a time. Each mutant must
# compile and must fail either the guards' unit suites or
# `sandbox-workload-evidence`; the file is then restored, and its SHA-256
# proves it byte-identical. A mutant that survives, or does not compile,
# fails the review.
WORKLOAD_MUTATIONS = (
    # The broker's deployment (ADR-0052 §13).
    (
        "a daemon may have the workload's uid",
        "crates/dwkd-broker/src/posture.rs",
        '            SANDBOX_UID => "every workload\'s",',
        '            SANDBOX_UID if false => "every workload\'s",',
    ),
    (
        "a daemon may have the relay's uid",
        "crates/dwkd-broker/src/posture.rs",
        '            RELAY_UID => "every relay\'s",',
        '            RELAY_UID if false => "every relay\'s",',
    ),
    (
        "Yama's ptrace_scope 0 counts as a closed startup window",
        "crates/dwkd-broker/src/posture.rs",
        "self.scope.is_some_and(|scope| scope >= 1)\n",
        "self.scope.is_some_and(|scope| scope < 4)\n",
    ),
    (
        "a binary its own uid owns counts as execute-only",
        "crates/dwkd-broker/src/posture.rs",
        "    owner == 0 && mode & 0o044 == 0",
        "    mode & 0o044 == 0",
    ),
    (
        "the broker serves with its startup window open",
        "crates/dwkd-broker/src/main.rs",
        "    if !posture.startup_window_closed() {",
        "    if false && !posture.startup_window_closed() {",
    ),
    # The environment's task bound (ADR-0056 §1): since `RLIMIT_NPROC` is a
    # host-wide backstop, the pids limit is what bounds one environment, and
    # a record without it must never be used.
    (
        "a record without its pids limit passes the resource judgement",
        "crates/dwkd-broker/src/sandbox/inspect.rs",
        '            number(&["HostConfig", "PidsLimit"], PIDS_LIMIT),\n',
        "            Some(true),\n",
    ),
    # The broker's plan and its checks before anything runs (§5).
    (
        "a workload runs as root",
        "crates/dwkd-broker/src/sandbox/workload_plan.rs",
        '    format!("{SANDBOX_UID}:{SANDBOX_GID}")',
        '    "0:0".to_owned()',
    ),
    (
        "a workload runs outside the workspace",
        "crates/dwkd-broker/src/sandbox/workload_plan.rs",
        '    argv.extend(words(&["--workdir", WORKSPACE_TARGET]));',
        '    argv.extend(words(&["--workdir", "/"]));',
    ),
    (
        "the executable's bytes are not proved",
        "crates/dwkd-broker/src/sandbox/oci.rs",
        "        if self.executable_digest(&handle.container, workload) != Verdict::Pass {",
        "        if false\n            && self.executable_digest(&handle.container, workload)"
        " != Verdict::Pass {",
    ),
    (
        "a drifted environment is worked in",
        "crates/dwkd-broker/src/sandbox/oci.rs",
        "        if failed.is_empty() {\n            Ok(())",
        "        if failed.is_empty() || true {\n            Ok(())",
    ),
    (
        "the output bound is not the workload's",
        "crates/dwkd-broker/src/sandbox/oci.rs",
        "        let limit = usize::try_from(workload.stream_limit.get()).unwrap_or(usize::MAX);",
        "        let limit = 4\n            * usize::try_from(workload.stream_limit.get())"
        ".unwrap_or(usize::MAX);",
    ),
    (
        "the wall clock is not the workload's",
        "crates/dwkd-broker/src/sandbox/oci.rs",
        "        let deadline = (since + wall_clock).min(reserve);",
        "        let deadline = (since + 4 * wall_clock).min(reserve);",
    ),
    (
        "an exit the runtime client also uses is believed",
        "crates/dwkd-broker/src/sandbox/oci.rs",
        "    if running && code == 125 {",
        "    if running && code == 125 && false {",
    ),
    # What is left after it (§5 step 5).
    (
        "reap signals nothing",
        "crates/dwk-sandbox-probe/src/linux.rs",
        "let _ = nix::sys::signal::kill(Pid::from_raw(-1), nix::sys::signal::Signal::SIGKILL);",
        "let _ = nix::sys::signal::kill(Pid::from_raw(-1), None);",
    ),
    (
        "the environment's init reaps no orphan",
        "crates/dwk-sandbox-probe/src/linux.rs",
        "        match nix::sys::wait::waitpid(Pid::from_raw(-1), None) {",
        "        match Err::<(), Errno>(Errno::ECHILD) {",
    ),
    (
        "a survivor reap names is a clean residue",
        "crates/dwkd-broker/src/sandbox/oci.rs",
        "        (_, remaining) => (Verdict::Fail, found, remaining),",
        "        (_, remaining) => (Verdict::Pass, found, remaining),",
    ),
    # The authority's decision (§§2, 4, 8, 10).
    (
        "a workload runs below container isolation",
        "crates/dwkd-authority/src/state/workload.rs",
        "    level.rank() >= AssuranceLevel::ContainerIsolation.rank()",
        "    level.rank() >= AssuranceLevel::ProcessIsolation.rank()",
    ),
    (
        "a workload runs in an environment that is not READY",
        "crates/dwkd-authority/src/state/workload.rs",
        '    if state != "READY" {',
        '    if state == "NEVER" {',
    ),
    (
        "the capability gate is not consulted",
        "crates/dwkd-authority/src/state/workload.rs",
        "    pub(super) fn workload_permits(&self) -> bool {\n"
        "        self.record.capability_satisfied()\n"
        "            && self.record.policy_satisfied()",
        "    pub(super) fn workload_permits(&self) -> bool {\n"
        "        self.record.policy_satisfied()",
    ),
    (
        "policy is not consulted",
        "crates/dwkd-authority/src/state/workload.rs",
        "    pub(super) fn workload_permits(&self) -> bool {\n"
        "        self.record.capability_satisfied()\n"
        "            && self.record.policy_satisfied()\n"
        "            && self.obligations_enforced",
        "    pub(super) fn workload_permits(&self) -> bool {\n"
        "        self.record.capability_satisfied()\n"
        "            && self.obligations_enforced",
    ),
    (
        "a workload is decided as a host action",
        "crates/dwkd-authority/src/state/workload.rs",
        "CanonicalAction::new(capability, Environment::Sandbox)",
        "CanonicalAction::new(capability, Environment::Host)",
    ),
    (
        "an obligation the authority cannot keep is accepted",
        "crates/dwkd-authority/src/state/workload.rs",
        "            _ => false,\n        };\n        enforced &= ok;",
        "            _ => true,\n        };\n        enforced &= ok;",
    ),
    (
        "the output obligation does not bound the streams",
        "crates/dwkd-authority/src/state/workload.rs",
        "stream_limit = stream_limit.min(u32::try_from(per_stream).unwrap_or(u32::MAX));",
        "stream_limit = stream_limit.max(u32::try_from(per_stream).unwrap_or(u32::MAX));",
    ),
    (
        "the run's workload count is not charged",
        "crates/dwkd-authority/src/state/workload.rs",
        "    if count.saturating_add(1) > budget.workloads",
        "    if count > budget.workloads",
    ),
    (
        "the run's wall-clock seconds are not charged",
        "crates/dwkd-authority/src/state/workload.rs",
        "        || seconds.saturating_add(u64::from(checked.wall_clock.get())) > budget.seconds",
        "        || seconds > budget.seconds",
    ),
    (
        "a repeated key runs the workload again",
        "crates/dwkd-authority/src/state/workload.rs",
        "    if let Some((invocation, bound_digest)) = bound {",
        "    if let Some((invocation, bound_digest)) = bound.filter(|_| false) {",
    ),
    # Fail-closed endings (§§8, 9).
    (
        "an uncertain ending keeps its environment",
        "crates/dwkd-authority/src/state/workload.rs",
        '        Ending::Unknown { .. } => Some("WORKLOAD_UNKNOWN"),',
        "        Ending::Unknown { .. } => None,",
    ),
    (
        "an unobservable residue keeps its environment",
        "crates/dwkd-authority/src/state/workload.rs",
        '(done.residue != Verdict::Pass).then_some("WORKLOAD_RESIDUE")',
        '(done.residue == Verdict::Fail).then_some("WORKLOAD_RESIDUE")',
    ),
    (
        "an environment the broker found drifted is kept",
        "crates/dwkd-authority/src/state/workload.rs",
        '        Ending::Failed { reason } => environment_drifted(reason).then_some("DRIFTED"),',
        "        Ending::Failed { reason } => environment_drifted(reason)\n"
        '            .then_some("DRIFTED")\n            .filter(|_| false),',
    ),
    (
        "an interrupted workload keeps its environment",
        "crates/dwkd-authority/src/state/workload.rs",
        "    for (invocation, run, environment) in &found {",
        "    for (invocation, run, environment) in found.iter().take(0) {",
    ),
    (
        "an interrupted workload is not ended UNKNOWN",
        "crates/dwkd-authority/src/state/workload.rs",
        "WHERE state = 'LAUNCHING' RETURNING invocation_id,",
        "WHERE state = 'COMPLETED' AND 0 RETURNING invocation_id,",
    ),
    # M5d.2: the public route (ADR-0052 §2). Where it runs.
    (
        "a sandboxed launch is decided by the host floor",
        "crates/dwkd-authority/src/state/workload_route.rs",
        "        if let Some(exec) = &call.process_exec\n            && self.attached().is_some()\n"
        "        {\n            return match",
        "        if let Some(exec) = &call.process_exec\n            && self.attached().is_some()\n"
        "            && false\n        {\n            return match",
    ),
    (
        "a denied launch prepares an environment",
        "crates/dwkd-authority/src/state/workload.rs",
        "    if !plan.permits() {\n        return Ok(Ok(Decided {",
        "    if false && !plan.permits() {\n        return Ok(Ok(Decided {",
    ),
    (
        "a run prepares environments without bound",
        "crates/dwkd-authority/src/state/workload.rs",
        "            if environments(work, run)? >= MAX_ENVIRONMENTS_PER_RUN {",
        "            if environments(work, run)? >= i64::MAX {",
    ),
    (
        "a run bound to another image runs in this one",
        "crates/dwkd-authority/src/state/workload.rs",
        "        && (bound != *image || bound.image.as_str() != environment.image)",
        "        && false\n"
        "        && (bound != *image || bound.image.as_str() != environment.image)",
    ),
    (
        "an environment that can never run again is never reclaimed",
        "crates/dwkd-authority/src/state/workload_route.rs",
        "        self.reclaim_one()?;\n        let full",
        "        let full",
    ),
    (
        "live environments are unbounded across runs",
        "crates/dwkd-authority/src/state/workload_route.rs",
        "Ok(workload::live_environments(work)? >= workload::MAX_LIVE_ENVIRONMENTS)",
        "Ok(workload::live_environments(work)? >= i64::MAX)",
    ),
    (
        "a busy environment takes a second launch",
        "crates/dwkd-authority/src/state/workload.rs",
        "        if busy.is_some() {",
        "        if busy.is_some() && false {",
    ),
    # Keys (§2): one namespace, both directions.
    (
        "a key another tool bound is not refused for a launch",
        "crates/dwkd-authority/src/state/workload_route.rs",
        "    Ok(found.is_some())\n}\n\n/// Record a refusal of the fence",
        "    Ok(found.is_some() && false)\n}\n\n/// Record a refusal of the fence",
    ),
    (
        "a launch's key is not refused for another tool",
        "crates/dwkd-authority/src/state/tool.rs",
        "SELECT invocation_id FROM workload_idempotency \\\n             WHERE subject = ?1",
        "SELECT invocation_id FROM workload_idempotency \\\n             WHERE 0 AND subject = ?1",
    ),
    # Starvation (§8): a running launch holds neither the worker nor the
    # broker's channel.
    (
        "a running sandboxed launch holds the authority's worker",
        "crates/dwkd-authority/src/state/workload_route.rs",
        "            && self.attached().is_some()\n        {\n"
        "            return self.sandboxed(caller, message, &exec, true, version);",
        "            && self.attached().is_some()\n            && false\n        {\n"
        "            return self.sandboxed(caller, message, &exec, true, version);",
    ),
    # The broker's supervisor (§3): bounded, one per environment, one
    # generation.
    (
        "a second workload shares an environment",
        "crates/dwkd-broker/src/sandbox/supervisor.rs",
        "            &slot.invocation == invocation"
        " || (&slot.environment == environment && !slot.ended())",
        "            &slot.invocation == invocation",
    ),
    (
        "the supervisor's table is unbounded",
        "crates/dwkd-broker/src/sandbox/supervisor.rs",
        "        if table.len() >= MAX_SUPERVISED_WORKLOADS {",
        "        if table.len() >= usize::MAX {",
    ),
    (
        "another generation's collection is believed",
        "crates/dwkd-broker/src/sandbox/supervisor.rs",
        "        if collect.generation != self.generation {",
        "        if false && collect.generation != self.generation {",
    ),
    # workspace_exec_hygiene (§5a).
    (
        "the broker ignores the hygiene launch",
        "crates/dwkd-broker/src/sandbox/workload_plan.rs",
        "    let profile = if workload.launch == WorkloadLaunch::Hygiene {",
        "    let profile = if false && workload.launch == WorkloadLaunch::Hygiene {",
    ),
    (
        "the launcher sets none of the obligation's variables",
        "crates/dwk-sandbox-probe/src/launch.rs",
        "        for (variable, value) in profile::HYGIENE_ENVIRONMENT {",
        "        for (variable, value) in profile::HYGIENE_ENVIRONMENT.iter().take(0) {",
    ),
    (
        "an invocation that undoes the obligation keeps it",
        "crates/dwkd-authority/src/state/workload.rs",
        "                    Hygiene::Unenforceable(_) => false,",
        "                    Hygiene::Unenforceable(_) => true,",
    ),
    (
        "git's configuration overrides are not refused",
        "crates/dwkd-authority/src/resource/exec/hygiene.rs",
        "        if GIT_OVERRIDES.iter().any(|option| is_option(arg, option)) {",
        "        if false && GIT_OVERRIDES.iter().any(|option| is_option(arg, option)) {",
    ),
    (
        "pytest's cache is not turned off",
        "crates/dwkd-authority/src/resource/exec/hygiene.rs",
        'const PYTEST_PREFIX: &[&str] = &["-p", "no:cacheprovider"];',
        "const PYTEST_PREFIX: &[&str] = &[];",
    ),
    (
        "a tool without real-tool evidence keeps the obligation",
        "crates/dwkd-authority/src/resource/exec/hygiene.rs",
        'const UNEVIDENCED: &[&str] = &["npm", "npx", "pnpm", "yarn", "bun", "cargo"];',
        "const UNEVIDENCED: &[&str] = &[];",
    ),
    # The operator's file (§2a).
    (
        "a wrapper or runner of an unevidenced tool keeps the obligation",
        "crates/dwkd-authority/src/resource/exec/hygiene.rs",
        '    if (super::argv::is_runner(name) || name == "uv") && names_unevidenced(args) {',
        "    if false\n"
        '        && (super::argv::is_runner(name) || name == "uv") && names_unevidenced(args) {',
    ),
    (
        "an unknown member of the operator's file is accepted",
        "crates/dwkd-authority/src/sandbox/operator.rs",
        "        if !allowed.contains(&name) {",
        "        if false && !allowed.contains(&name) {",
    ),
    (
        "the operator's file may write its version in another base",
        "crates/dwkd-authority/src/sandbox/operator.rs",
        'if version.radix() == 10 && version.as_str() == "1" => {}',
        'if version.as_str() == "1" => {}',
    ),
)


def _workload_guard_suites() -> None:
    """The suites that prove M5d.1's and M5d.2's guards without a runtime:
    the broker's plan, posture, deployment, classification and supervisor,
    and the authority's ledger, schema and route (against a fake broker),
    its hygiene families and the operator's file."""
    run("cargo", "test", "--locked", "-p", "dwkd-broker", "--bin", "dwkd-broker")
    run(
        "cargo",
        "test",
        "--locked",
        "-p",
        "dwkd-authority",
        "--lib",
        "--",
        "state::",
        "resource::exec::hygiene",
        "sandbox::operator",
    )


def task_sandbox_workload_mutations() -> None:
    """Weaken each M5d.1 and M5d.2 guard in turn; a unit suite or the
    evidence must catch every one.

    Slow: a mutant no unit suite catches runs the whole
    sandbox-workload-evidence. Every file is restored byte-identically
    whatever happens, and checked. Never run it beside another build.
    """
    killed: list[str] = []
    for what, rel, old, new in WORKLOAD_MUTATIONS:
        path = ROOT / rel
        original = path.read_bytes()
        digest = hashlib.sha256(original).hexdigest()
        text = original.decode("utf-8")
        if text.count(old) != 1:
            raise TaskError(f"mutation `{what}`: its target is not in {rel} exactly once")
        print(f"{BOLD}mutant: {what}{OFF}")
        outcome = "survived"
        try:
            path.write_bytes(text.replace(old, new).encode("utf-8"))
            try:
                run(
                    "cargo",
                    "test",
                    "--locked",
                    "--no-run",
                    "-p",
                    "dwk-proto",
                    "-p",
                    "dwk-sandbox-probe",
                    "-p",
                    "dwkd-broker",
                    "-p",
                    "dwkd-authority",
                )
            except TaskError:
                outcome = "did not compile"
            else:
                try:
                    _workload_guard_suites()
                except TaskError as exc:
                    outcome = f"killed by a unit suite: {str(exc)[:160]}"
                else:
                    try:
                        task_sandbox_workload_evidence()
                    except TaskError as exc:
                        outcome = f"killed by the evidence: {str(exc)[:160]}"
        finally:
            path.write_bytes(original)
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise TaskError(f"{rel} was not restored byte-identically")
        print(f"{DIM}restored {rel} (sha256 {digest[:16]}...){OFF}")
        if not outcome.startswith("killed"):
            raise TaskError(f"mutant `{what}` {outcome}: nothing guards it")
        killed.append(what)
        print(f"{GREEN}mutant {outcome[:60]}: {what}{OFF}")
    print(
        f"{GREEN}sandbox workload mutation review: {len(killed)} of "
        f"{len(WORKLOAD_MUTATIONS)} killed{OFF}"
    )


# M5d.3 (ADR-0052 §7): a sandboxed `process.exec` that consumes a credential.
SECRET_SANDBOX_BROKER_TESTS = (
    "linux::a_descriptor_secret_reaches_the_program_on_descriptor_three_and_nowhere_else",
    "linux::an_environment_secret_reaches_the_program_as_its_variable_and_nowhere_else",
    "linux::the_output_is_redacted_of_the_value_even_split_across_reads",
    "linux::every_malformed_handoff_is_refused_and_the_value_is_read_only_after_the_judgement",
    "linux::the_launcher_runs_nothing_for_a_frame_or_a_name_it_does_not_accept",
    "linux::a_broker_that_stops_after_reading_the_value_runs_nothing",
)
SECRET_SANDBOX_AUTHORITY_TESTS = (
    "linux::the_public_route_delivers_a_credential_to_the_sandboxed_launch_and_never_to_the_runtime",
    "linux::a_crash_in_a_credential_bearing_launch_leaves_it_unknown_and_its_environment_gone",
    "linux::the_shipped_packs_never_let_a_launch_use_a_credential",
    "linux::production_serve_delivers_a_credential_from_the_operators_files_and_survives_its_death",
)

# Every (suite, case) M5d.3's evidence must report, exercised.
#   authority-workload-secret  the REAL authority and REAL kernel-keyring values
#                              against a FAKE broker that reads the one-shot pipe
#                              it is handed (labelled so: not delivery) -- read
#                              once after both intents, C before B, both gates,
#                              every refusal and denial reading nothing, the
#                              revision checks, failures before anything ran,
#                              every crash window, no host fallback;
#   sandbox-secret             the released broker handing a synthetic value to
#                              a workload in a REAL environment it prepared, over
#                              its runtime client's standard input, through the
#                              pinned probe as the launcher: fd 3 and the
#                              operator's variable, the residual inheritance
#                              measured, absence from the runtime's records,
#                              events and logs, redaction across reads, every
#                              malformed handoff and frame refused;
#   sandbox-authority-secret   the REAL authority, the released broker, a REAL
#                              runtime and a REAL DWKP client -- the server seam
#                              and the released `serve --sandbox-config
#                              --secrets-file` -- delivery, redaction, refusals,
#                              crash windows, the shipped packs, replays.
SECRET_SANDBOX_UNIT_CASES = tuple(
    ("authority-workload-secret", case)
    for case in (
        "read-once-after-both-intents",
        "kernel-chooses-c-before-b",
        "intent-linked-recorded-counted",
        "no-plaintext-in-kernel-db-or-audit",
        "replay-never-hands-over-again",
        "ordinary-launch-unchanged",
        "preview-reads-nothing",
        "v5-cannot-name-a-credential",
        "refused-not-configured",
        "refused-consumer-not-allowed",
        "refused-another-executable",
        "refused-egress-only",
        "refused-reserved-variable",
        "not-granted-denied",
        "stored-grant-replaced",
        "stored-grant-revoked",
        "no-refusal-reaches-the-broker",
        "default-deny",
        "host-rule-is-no-sandbox-rule",
        "approval-required",
        "obligation-unenforceable",
        "failed-backend-missing",
        "failed-nul-in-a-variable",
        "broker-refusal-failed",
        "unknown-start-unknown-use",
        "missing-redaction-count-unknown",
        "crash-1",
        "crash-2",
        "crash-q",
        "crash-3",
        "crash-4",
        "crash-5",
        "crash-6",
        "crash-8",
        "crash-t",
        "crash-r",
        "crash-0",
        "crash-s",
        "crash-9",
        "no-host-fallback",
    )
)
SECRET_SANDBOX_CASES = (
    *(
        ("sandbox-secret", case)
        for case in (
            "fd-at-spawn-delivers-exactly-the-value",
            "fd-at-spawn-one-shot",
            "fd-at-spawn-stdin-is-dev-null",
            "fd-at-spawn-only-descriptor-three",
            "fd-at-spawn-residue-clean",
            "fd-at-spawn-inherited-by-a-descendant",
            "fd-at-spawn-with-hygiene",
            "fd-at-spawn-not-in-inspect-logs-events-argv",
            "broker-log-names-the-mode-only",
            "env-at-spawn-delivers-exactly-the-value",
            "env-at-spawn-only-its-variable-added",
            "env-at-spawn-no-extra-descriptor",
            "env-at-spawn-inherited-by-a-descendant",
            "env-at-spawn-with-hygiene",
            "env-at-spawn-not-in-inspect-logs-events-argv",
            "redacted-across-reads-fd",
            "redacted-across-reads-env",
            "refused-not-a-pipe",
            "refused-a-write-end",
            "refused-a-stalled-pipe",
            "refused-empty",
            "refused-past-32-kib",
            "refused-nul-in-a-variable",
            "refused-not-three-descriptors",
            "value-unread-when-the-judgement-refuses",
            "collected-only-under-its-generation",
            "an-ordinary-workload-is-unchanged",
            "launcher-accepts-one-exact-frame",
            "launcher-refuses-every-other-frame",
            "launcher-refuses-reserved-names-and-bad-words",
            "crash-after-read-nothing-ran",
        )
    ),
    *(
        ("sandbox-authority-secret", case)
        for case in (
            "public-plan-states-both-actions",
            "public-fd-at-spawn-delivered",
            "public-env-at-spawn-delivered",
            "public-echo-redacted",
            "public-no-plaintext-durable-or-logged",
            "public-never-on-the-host",
            "public-replay-refused",
            "public-preview-reads-nothing",
            "public-ungranted-handle-denied",
            "public-unconfigured-handle-refused",
            "public-ordinary-launch-unchanged",
            "public-hostile-credential-frames-refused",
            "crash-r6-after-handoff",
            "crash-r8-broker-running-it",
            "shipped-safe-denies-a-launch-credential",
            "shipped-balanced-denies-a-launch-credential",
            "shipped-power-denies-a-launch-credential",
            "production-serve-delivers-from-the-operators-files",
            "production-crash-mid-workload-unknown-destroyed",
            "production-replay-after-restart-refused",
            "production-no-plaintext-durable",
        )
    ),
)


def task_sandbox_secret_evidence() -> None:
    """M5d.3's evidence (ADR-0052 §7): secret modes B and C inside the sandbox.

    First the authority's pipeline against a fake broker with real kernel-
    keyring values (every case required: no keyring is NOT EXERCISED, which
    fails); then, on a real OCI runtime, the released broker delivering a
    synthetic credential through the trusted launcher, and the real
    authority reached by a real DWKP client through the seam and the
    released `serve`. Every suite must run every test; no container the
    evidence made may remain, and none that was there may be gone. Linux only.
    """
    unit = run_captured(
        "cargo",
        "test",
        "--locked",
        "-p",
        "dwkd-authority",
        "--lib",
        "--",
        "state::workload_route::tests::secret::",
        "--nocapture",
        "--test-threads=1",
    )
    require_tests_ran(unit)
    require_attributed_evidence(unit, SECRET_SANDBOX_UNIT_CASES, SECRET_EVIDENCE_PREFIX)
    client, socket, variables, before, images = _workload_setup()
    os.environ.update(variables)
    outputs: list[str] = []
    try:
        run("cargo", "build", "--locked", "-p", "dwkd-broker")
        for package, test, names in (
            ("dwkd-broker", "sandbox_secret", SECRET_SANDBOX_BROKER_TESTS),
            ("dwkd-authority", "sandbox_secret", SECRET_SANDBOX_AUTHORITY_TESTS),
        ):
            output = run_captured(
                "cargo",
                "test",
                "--locked",
                "-p",
                package,
                "--test",
                test,
                "--",
                "--ignored",
                "--exact",
                "--nocapture",
                "--test-threads=1",
                *names,
            )
            summaries = [line for line in output.splitlines() if line.startswith("test result: ")]
            expected = f"test result: ok. {len(names)} passed; 0 failed; 0 ignored"
            if len(summaries) != 1 or not summaries[0].startswith(expected):
                raise TaskError(
                    f"the {package} {test} suite did not run all of its tests: expected "
                    f"`{expected}`, got {summaries or 'no summary'}"
                )
            outputs.append(output)
    finally:
        after = set(
            _docker(client, socket, "container", "ls", "--all", "--no-trunc", "--quiet").split()
        )
        for image in set(images.values()):
            _docker(client, socket, "image", "rm", "--force", image, check=False)
    left = sorted(after - before)
    removed = sorted(before - after)
    if left:
        raise TaskError(f"the evidence left {len(left)} container(s) behind: {left}")
    if removed:
        raise TaskError(
            f"{len(removed)} container(s) that predate the evidence are gone: {removed}"
        )
    report_cleanup(f"cleanup: no evidence container remains; {len(before)} pre-existing kept")
    require_attributed_evidence("\n".join(outputs), SECRET_SANDBOX_CASES)
    uvrun("dwcheck", "closure", "--report")


# M5d.3's mutation review: each line weakens one guard of a workload's
# credential, one at a time. Each mutant must compile and must fail the
# guards' unit suites or `sandbox-secret-evidence`; the file is then
# restored, and its SHA-256 proves it byte-identical.
SECRET_SANDBOX_MUTATIONS = (
    # Where the value travels (§2).
    (
        "an ordinary workload attaches standard input",
        "crates/dwkd-broker/src/sandbox/workload_plan.rs",
        "        None,\n        words(&[PROBE_PATH, PROBE_LAUNCH, profile]),",
        '        Some("--interactive"),\n        words(&[PROBE_PATH, PROBE_LAUNCH, profile]),',
    ),
    (
        "the secret plan attaches nothing",
        "crates/dwkd-broker/src/sandbox/workload_secret_plan.rs",
        "    super::workload_plan::run_with(container, workload, Some(ATTACH_STDIN), launcher)",
        "    super::workload_plan::run_with(container, workload, None, launcher)",
    ),
    (
        "the launch helper sends the value unframed",
        "crates/dwkd-broker/src/process/launch.rs",
        "secret_pipe(s.needle.value(), s.delivery == Delivery::Stdin)",
        "secret_pipe(s.needle.value(), false)",
    ),
    (
        "the authority's link sends no secret descriptor",
        "crates/dwkd-authority/src/broker/link.rs",
        "    fds.push(pipe.into_transfer_descriptor());",
        "    drop(pipe);",
    ),
    # The broker's read (§3).
    (
        "the broker reads the value before it judges",
        "crates/dwkd-broker/src/sandbox/mod.rs",
        "        let judged = env\n"
        "            .ready_workload(&work.handle, &work.spec, &work.program)\n"
        "            .map_err(judgement)\n"
        "            .and_then(|()| secret_run(work.secret.as_ref())"
        ".map_err(OutcomeResult::Refused));",
        "        let early = secret_run(work.secret.as_ref()).map_err(OutcomeResult::Refused);\n"
        "        let judged = env\n"
        "            .ready_workload(&work.handle, &work.spec, &work.program)\n"
        "            .map_err(judgement)\n"
        "            .and(early);",
    ),
    (
        "a NUL reaches a variable",
        "crates/dwkd-broker/src/sandbox/mod.rs",
        "    if secret.delivery == SecretDelivery::EnvAtSpawn && value.contains(&0) {",
        "    if false && secret.delivery == SecretDelivery::EnvAtSpawn && value.contains(&0) {",
    ),
    (
        "a secret-bearing start is answered as an ordinary one",
        "crates/dwkd-broker/src/sandbox/mod.rs",
        "                Some(started) => "
        "OutcomeResult::done(BrokerDone::workload_secret_start(started)),",
        "                Some(started) => "
        "OutcomeResult::done(BrokerDone::workload_start(started)),",
    ),
    # The return path (§7).
    (
        "the drain does not redact",
        "crates/dwkd-broker/src/process/run.rs",
        "                redactor.feed(bytes, &mut |out| keep(&mut kept, &mut cut, limit, out));",
        "                let _ = redactor;\n"
        "                keep(&mut kept, &mut cut, limit, bytes);",
    ),
    (
        "the redaction count is not reported",
        "crates/dwkd-broker/src/sandbox/oci.rs",
        "            redactions: secret_bearing"
        ".then(|| u32::try_from(done.redactions).unwrap_or(u32::MAX)),",
        "            redactions: secret_bearing.then_some(0),",
    ),
    # The launcher (§4).
    (
        "the launcher accepts a frame with bytes after it",
        "crates/dwk-sandbox-probe/src/launch.rs",
        "Some(filled) == length.checked_add(prefix)",
        "Some(filled) >= length.checked_add(prefix)",
    ),
    (
        "the launcher lets a proxy variable carry a secret",
        "crates/dwk-sandbox-probe/src/launch.rs",
        "    valid_secret_env_name(name) && !profile::sandbox_secret_name_reserved(name)",
        "    valid_secret_env_name(name)",
    ),
    (
        "the launcher leaves standard input attached",
        "crates/dwk-sandbox-probe/src/launch.rs",
        "        if delivered.is_none() || quiet_stdin().is_none() {",
        "        if delivered.is_none() {",
    ),
    # The authority's decision (§5).
    (
        "permission to run the executable is permission to use the secret",
        "crates/dwkd-authority/src/state/workload.rs",
        "        self.workload_permits() && self.injection.as_ref().is_none_or(SpawnGate::permits)",
        "        self.workload_permits()",
    ),
    (
        "the plan states the injection allowed whatever both gates said",
        "crates/dwkd-authority/src/state/workload_route.rs",
        "            effect: effect_of(gate.permits()),",
        "            effect: effect_of(true),",
    ),
    (
        "mode B before mode C",
        "crates/dwkd-authority/src/secret/select.rs",
        "            [InjectionMode::FdAtSpawn, InjectionMode::EnvAtSpawn]",
        "            [InjectionMode::EnvAtSpawn, InjectionMode::FdAtSpawn]",
    ),
    (
        "any executable is a spawn consumer",
        "crates/dwkd-authority/src/secret/select.rs",
        "            if !consumers.iter().any(|allowed| allowed == *consumer) {",
        "            if false && !consumers.iter().any(|allowed| allowed == *consumer) {",
    ),
    (
        "a variable the environment sets reaches the broker",
        "crates/dwkd-authority/src/state/secret_use/spawn.rs",
        "                .filter(|name| sandbox_secret_name_allowed(name))",
        "                .filter(|_| true)",
    ),
    (
        "a variable's NUL is handed over",
        "crates/dwkd-authority/src/secret/handoff.rs",
        "    !material.expose().contains(&0)",
        "    !material.expose().is_empty()",
    ),
    (
        "a credential is sent with no execution environment",
        "crates/dwkd-authority/src/state/workload_route.rs",
        "            if exec.credential_handle.is_some() {\n"
        "                return self.credential_without_environment(caller, message, invoke);\n"
        "            }",
        "            if exec.credential_handle.is_some() && false {\n"
        "                return self.credential_without_environment(caller, message, invoke);\n"
        "            }",
    ),
    # Durable state (§6).
    (
        "a credential-bearing launch records no use",
        "crates/dwkd-authority/src/state/workload.rs",
        "        (Some((asked, prepared)), Some(gate)) => Ok(Some(spawn::record_intent(\n"
        "            work,\n"
        "            (asked, prepared.clone()),\n"
        "            (active, &gate.record),\n"
        "            invocation,\n"
        "        )?)),",
        "        (Some(_), Some(_)) => Ok(None),",
    ),
    (
        "an unknown ending counts a delivery",
        "crates/dwkd-authority/src/state/secret_use/spawn.rs",
        "        Workload::Unknown { .. } => Ending::Unknown,",
        "        Workload::Unknown { .. } => Ending::Injected,",
    ),
    (
        "a missing redaction count is believed",
        "crates/dwkd-authority/src/state/workload_ops.rs",
        "        ) if done.redactions.is_some() != started.intent.secret.is_some() => {",
        "        ) if false && done.redactions.is_some() != started.intent.secret.is_some() => {",
    ),
)


def _secret_guard_suites() -> None:
    """The suites that prove M5d.3's guards without a runtime: the shared
    contract, the broker's plans and drains, and the authority's selection,
    decision, ledger and route against a fake broker with keyring values."""
    run("cargo", "test", "--locked", "-p", "dwk-proto", "--lib")
    run("cargo", "test", "--locked", "-p", "dwkd-broker", "--bin", "dwkd-broker")
    run(
        "cargo",
        "test",
        "--locked",
        "-p",
        "dwkd-authority",
        "--lib",
        "--",
        "state::",
        "secret::",
    )


def task_sandbox_secret_mutations() -> None:
    """Weaken each M5d.3 guard in turn; a unit suite or the evidence must
    catch every one.

    Slow: a mutant no unit suite catches runs the whole
    sandbox-secret-evidence. Every file is restored byte-identically whatever
    happens, and checked. Never run it beside another build.
    """
    killed: list[str] = []
    for what, rel, old, new in SECRET_SANDBOX_MUTATIONS:
        path = ROOT / rel
        original = path.read_bytes()
        digest = hashlib.sha256(original).hexdigest()
        text = original.decode("utf-8")
        if text.count(old) != 1:
            raise TaskError(f"mutation `{what}`: its target is not in {rel} exactly once")
        print(f"{BOLD}mutant: {what}{OFF}")
        outcome = "survived"
        try:
            path.write_bytes(text.replace(old, new).encode("utf-8"))
            try:
                run(
                    "cargo",
                    "test",
                    "--locked",
                    "--no-run",
                    "-p",
                    "dwk-proto",
                    "-p",
                    "dwk-sandbox-probe",
                    "-p",
                    "dwkd-broker",
                    "-p",
                    "dwkd-authority",
                )
            except TaskError:
                outcome = "did not compile"
            else:
                try:
                    _secret_guard_suites()
                except TaskError as exc:
                    outcome = f"killed by a unit suite: {str(exc)[:160]}"
                else:
                    try:
                        task_sandbox_secret_evidence()
                    except TaskError as exc:
                        outcome = f"killed by the evidence: {str(exc)[:160]}"
        finally:
            path.write_bytes(original)
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise TaskError(f"{rel} was not restored byte-identically")
        print(f"{DIM}restored {rel} (sha256 {digest[:16]}...){OFF}")
        if not outcome.startswith("killed"):
            raise TaskError(f"mutant `{what}` {outcome}: nothing guards it")
        killed.append(what)
        print(f"{GREEN}mutant {outcome[:60]}: {what}{OFF}")
    print(
        f"{GREEN}sandbox secret mutation review: {len(killed)} of "
        f"{len(SECRET_SANDBOX_MUTATIONS)} killed{OFF}"
    )


# --- M5d.4: workspace ownership and the measured disk quota (ADR-0052 §§6, 10) ---

WORKSPACE_EVIDENCE_PREFIX = "WORKSPACE-EVIDENCE "
# The workspace group (OD-3(a)): the workload's own primary gid.
WORKSPACE_GID = 10001
# Each provisioned workspace's size, and the quota the evidence declares.
WORKSPACE_QUOTA = 64 << 20

# The in-process half, printed as WORKSPACE-EVIDENCE lines:
#   broker-exchange  the broker's own unit suite: the workspace group's
#                    convention refused unchanged, no room its own class, and a
#                    REAL full tmpfs -- the test's own, in an unprivileged user
#                    and mount namespace -- refusing a write, a creation and a
#                    deletion with nothing changed;
#   authority-route  the REAL authority and store against a FAKE broker
#                    (labelled so: not containment) -- a workspace not the
#                    contract's refused before the broker hears of it, the
#                    contract said, no name change or reclamation while a
#                    workload may run in the workspace, a replaced root taking
#                    its environment down, drift answered as not clean.
WORKSPACE_UNIT_CASES = (
    *(
        ("broker-exchange", case)
        for case in (
            "broker-group-convention-refused",
            "broker-full-filesystem-write",
            "broker-full-filesystem-create",
            "broker-full-filesystem-delete",
            "broker-full-filesystem-nothing-changed",
        )
    ),
    *(
        ("authority-route", case)
        for case in (
            "authority-unbounded-workspace-refused",
            "authority-refused-before-the-broker",
            "authority-unverified-workspace-said",
            "authority-write-excluded-during-a-workload",
            "authority-other-runs-write-excluded",
            "authority-read-served-during-a-workload",
            "authority-write-after-the-workload",
            "authority-unknown-environment-excludes",
            "authority-destroying-environment-excludes",
            "authority-reclamation-waits-for-the-workload",
            "authority-replaced-workspace-destroys",
            "authority-workspace-drift-answered-not-clean",
        )
    ),
)

# The real-container half, selected by name. What any Linux host with a
# runtime runs: the evidence's own scratch workspace, under the
# unverified-evidence waiver where a case says so.
WORKSPACE_BROKER_TESTS = (
    "linux::workspace::a_broker_not_told_to_allow_it_refuses_an_unverified_workspace",
    "linux::workspace::a_bound_the_probe_does_not_find_is_refused_and_its_container_removed",
    # M5d.1's, again: nothing outside the workspace is reachable from it.
    "linux::nothing_outside_the_workspace_is_reachable_from_a_workload",
)
WORKSPACE_AUTHORITY_TESTS = (
    "linux::workspace::an_unprovisioned_workspace_is_refused_in_production_before_the_broker",
    "linux::workspace::production_serve_refuses_a_workspace_it_cannot_bound",
    "linux::workspace::what_a_workload_makes_takes_the_workspace_umask_and_stays_in_the_workspace",
    "linux::workspace::a_brokered_change_waits_while_a_workload_may_write_the_workspace",
)
# What only an operator-provisioned host runs (`DW_WORKSPACE_PRIVILEGED=1`):
# the group 10001 with this process in it, filesystems of their own made and
# undone here, `sudo` to change them.
WORKSPACE_PRIVILEGED_BROKER_TESTS = (
    "linux::workspace::a_provisioned_workspace_is_accepted_and_judged_again_before_work",
)
WORKSPACE_PRIVILEGED_AUTHORITY_TESTS = (
    "linux::workspace::a_bounded_workspace_is_shared_by_its_group_and_nobody_else",
    "linux::workspace::a_root_not_as_the_contract_says_is_refused_and_never_repaired",
    "linux::workspace::a_workspace_changed_under_a_ready_environment_takes_it_down_first",
    "linux::workspace::a_full_workspace_fails_cleanly_and_borrows_from_no_other",
    "linux::workspace::production_serve_runs_in_a_bounded_workspace",
)

# Every (suite, case) the real-container half must report, exercised.
#   sandbox-workspace            the released broker judging the probe's facts
#                                against the bound it was sent, this process
#                                playing the authority;
#   sandbox-authority-workspace  the REAL authority, the released broker, a
#                                REAL runtime and (M5d.2's route) a REAL DWKP
#                                client, the released `serve --sandbox-config`
#                                included;
#   sandbox-workload             M5d.1's reachability cases, run again.
WORKSPACE_CASES = (
    *(
        ("sandbox-workspace", case)
        for case in (
            "broker-unverified-workspace-refused-without-the-flag",
            "broker-unbounded-directory-refused",
            "broker-forged-capacity-refused",
            "broker-forged-identity-refused",
            "broker-host-and-container-identity-agree",
            "broker-runtime-probe-disagreement-refused",
        )
    ),
    *(
        ("sandbox-workload", case)
        for case in (
            "workload-root-read-only",
            "workload-etc-read-only",
            "workload-dot-dot-escape-refused",
            "workload-tmp-writable",
            "workload-workspace-writable-as-10001",
            "workload-no-runtime-socket",
            "workload-no-host-path",
        )
    ),
    *(
        ("sandbox-authority-workspace", case)
        for case in (
            "authority-unprovisioned-workspace-refused-before-the-broker",
            "authority-unprovisioned-workspace-runs-nothing",
            "production-serve-unprovisioned-workspace-refused",
            "umask-0007-through-the-direct-launcher",
            "workspace-tmp-var-tmp-distinct",
            "exclusion-while-a-workload-runs",
            "exclusion-lifted-when-the-workload-ended",
        )
    ),
)
WORKSPACE_PRIVILEGED_CASES = (
    *(
        ("sandbox-workspace", case)
        for case in (
            "broker-bounded-tmpfs-accepted",
            "broker-bounded-ext4-accepted",
            "broker-capacity-drift-refused-before-work",
        )
    ),
    *(
        ("sandbox-authority-workspace", case)
        for case in (
            "bounded-tmpfs-accepted",
            "host-and-container-identity-agree",
            "workload-makes-broker-reads",
            "broker-makes-workload-modifies",
            "broker-replaces-workload-reads",
            "another-identity-cannot-write-or-read",
            "wrong-gid-refused",
            "missing-setgid-refused",
            "group-only-mode-world-readable-refused",
            "world-writable-root-refused",
            "workload-owned-root-refused",
            "foreign-owned-root-refused",
            "quota-mismatch-refused",
            "unbounded-host-directory-refused",
            "subdirectory-of-a-bounded-filesystem-refused",
            "capacity-drift-destroys-before-the-workload",
            "mount-substitution-destroys-before-the-workload",
            "bounded-ext4-accepted",
            "workload-fills-to-enospc",
            "full-workspace-write-fails-unchanged",
            "other-workspace-unaffected",
            "space-recovered-after-removal",
            "durability-valid-after-a-full-workspace",
            "production-serve-bounded-workspace",
        )
    ),
)
# Both halves, judged as one output on a provisioned host: a table of its own
# name, so what the task judged is kept for the M5 gate by that name.
WORKSPACE_ALL_CASES = WORKSPACE_CASES + WORKSPACE_PRIVILEGED_CASES


def workspace_privileged() -> bool:
    """Whether this run may provision workspaces: filesystems of their own,
    mounted and undone with passwordless sudo. Never inferred: only
    `DW_WORKSPACE_PRIVILEGED=1` says so, and a developer's machine is never
    changed without it."""
    return os.environ.get("DW_WORKSPACE_PRIVILEGED", "").strip() == "1"


def _workspace_base() -> Path:
    """Where the provisioned workspaces are mounted: never inside the
    workload evidence's own directory, which its setup removes."""
    return Path(os.environ.get("DW_WORKSPACE_BASE", str(Path.home() / ".cache" / "dw-m5d4")))


def _mounted_under(base: Path) -> list[str]:
    """Every mount point under `base`, in the order they were mounted."""
    prefix = f"{base}/"
    points = []
    for line in Path("/proc/self/mountinfo").read_text(encoding="utf-8").splitlines():
        fields = line.split()
        if len(fields) > 4 and fields[4].startswith(prefix):
            points.append(fields[4])
    return points


def _provision_workspaces(base: Path) -> dict[str, str]:
    """An operator's provisioning, for the evidence only (ADR-0052 §6):
    two `tmpfs` workspaces and a loop-mounted `ext4` image, each exactly the
    quota's size, `nosuid,nodev`, its root this user's, of the workspace
    group, mode 2770; and a directory provisioned the same on the host's own
    filesystem, bounded by nothing of its own. Nothing the developer owns is
    touched: every path is under `base`, made here and undone after."""
    groups = subprocess.run(["id", "-G"], capture_output=True, text=True, check=True).stdout
    if str(WORKSPACE_GID) not in groups.split():
        raise TaskError(
            f"NOT EXERCISED: this process is not a member of the workspace group "
            f"{WORKSPACE_GID}; the hosted job creates it, adds the runner to it and runs "
            "`make` again under `sudo -u $USER`"
        )
    if subprocess.run(["sudo", "-n", "true"], capture_output=True, check=False).returncode != 0:
        raise TaskError("NOT EXERCISED: DW_WORKSPACE_PRIVILEGED=1 but `sudo -n` cannot run")
    mkfs = shutil.which("mkfs.ext4") or next(
        (p for p in ("/usr/sbin/mkfs.ext4", "/sbin/mkfs.ext4") if Path(p).exists()), None
    )
    if mkfs is None:
        raise TaskError("NOT EXERCISED: no mkfs.ext4 for the loop-mounted workspace")
    if base.exists():
        _unprovision_workspaces(base)
    base.mkdir(mode=0o755, parents=True)
    uid = os.getuid()
    roots = {name: base / name for name in ("tmpfs", "second", "ext4", "unbounded")}
    for name in ("tmpfs", "second"):
        roots[name].mkdir()
        run(
            "sudo",
            "-n",
            "mount",
            "-t",
            "tmpfs",
            "-o",
            f"size={WORKSPACE_QUOTA},mode=2770,uid={uid},gid={WORKSPACE_GID},nosuid,nodev",
            f"dw-workspace-{name}",
            str(roots[name]),
        )
    image = base / "ext4.img"
    with image.open("wb") as handle:
        os.posix_fallocate(handle.fileno(), 0, WORKSPACE_QUOTA)
    run(mkfs, "-q", "-F", "-E", f"root_owner={uid}:{WORKSPACE_GID}", str(image))
    roots["ext4"].mkdir()
    run("sudo", "-n", "mount", "-o", "loop,nosuid,nodev", str(image), str(roots["ext4"]))
    run("sudo", "-n", "chown", f"{uid}:{WORKSPACE_GID}", str(roots["ext4"]))
    run("sudo", "-n", "chmod", "2770", str(roots["ext4"]))
    roots["unbounded"].mkdir()
    os.chown(roots["unbounded"], -1, WORKSPACE_GID)
    roots["unbounded"].chmod(0o2770)
    for name, root in roots.items():
        st = root.stat()
        if (st.st_uid, st.st_gid, st.st_mode & 0o7777) != (uid, WORKSPACE_GID, 0o2770):
            raise TaskError(f"the {name} workspace was not provisioned as the contract says")
    print(f"{BOLD}workspace provisioning{OFF} (undone after)")
    for name, root in roots.items():
        stat = os.statvfs(root)
        print(f"  {name:<10} {root}  {stat.f_blocks * stat.f_frsize} bytes")
    return {
        "DW_WORKSPACE_TMPFS": str(roots["tmpfs"]),
        "DW_WORKSPACE_SECOND": str(roots["second"]),
        "DW_WORKSPACE_EXT4": str(roots["ext4"]),
        "DW_WORKSPACE_UNBOUNDED": str(roots["unbounded"]),
        "DW_WORKSPACE_QUOTA": str(WORKSPACE_QUOTA),
        "DW_WORKSPACE_PEER": os.environ.get("DW_WORKSPACE_PEER", "nobody"),
    }


def _unprovision_workspaces(base: Path) -> None:
    """Undo `_provision_workspaces`, and prove it: no mount left under
    `base` (an over-mount a failed case left included), no loop device on
    the image, and `base` itself gone -- or never made, when the run failed
    before it provisioned anything."""
    for _ in range(8):
        points = _mounted_under(base)
        if not points:
            break
        for point in reversed(points):
            subprocess.run(["sudo", "-n", "umount", point], capture_output=True, check=False)
    left = _mounted_under(base)
    if left:
        raise TaskError(f"cleanup: still mounted under {base}: {left}")
    image = base / "ext4.img"
    if image.exists():
        loops = subprocess.run(
            ["sudo", "-n", "losetup", "--associated", str(image)],
            capture_output=True,
            text=True,
            check=False,
        ).stdout.strip()
        if loops:
            raise TaskError(f"cleanup: a loop device still holds {image}: {loops}")
    if base.exists():
        shutil.rmtree(base)
    if base.exists():
        raise TaskError(f"cleanup: {base} remains")
    report_cleanup("cleanup: no workspace mount, loop device or directory remains")


def task_sandbox_workspace_evidence() -> None:
    """M5d.4's evidence: `_sandbox_workspace_evidence`, its privileged half
    required."""
    _sandbox_workspace_evidence(require_privileged=True)


def _sandbox_workspace_evidence(*, require_privileged: bool) -> None:
    """M5d.4's evidence (ADR-0052 §§6, 10, 17; OD-3(a), OD-6): workspace
    ownership and the measured disk quota.

    In process: the broker's group convention, no-room class and a REAL full
    tmpfs; the authority's contract and exclusions against a FAKE broker.
    Then real containers: the released broker judging the probe's facts
    against the bound it was sent, and the real authority over a real
    runtime -- what any host runs on the evidence's own scratch workspace,
    and, only where `DW_WORKSPACE_PRIVILEGED=1` (the hosted runner),
    operator-provisioned filesystems of their own: interoperation through the
    group, refusals that never repair, drift and mount substitution, a real
    ENOSPC on a dedicated 64 MiB ext4 image with another workspace untouched,
    and the released `serve --sandbox-config` with a quota.

    Every case must report at its level with what enforced it (M5e.1), a
    provisioned host's at its own. Without the privileged half the task
    FAILS, NOT EXERCISED, after reporting the rest: the unverified-workspace waiver is
    never evidence of the production guarantee. No container, mount, loop
    device or directory the evidence made may remain. Linux only.
    """
    unit = run_captured(
        "cargo",
        "test",
        "--locked",
        "-p",
        "dwkd-broker",
        "--bin",
        "dwkd-broker",
        "--",
        "exchange::tests::workspace::",
        "--nocapture",
        "--test-threads=1",
    )
    unit += run_captured(
        "cargo",
        "test",
        "--locked",
        "-p",
        "dwkd-authority",
        "--lib",
        "--",
        "state::workload_route::tests::workspace::",
        "--nocapture",
        "--test-threads=1",
    )
    require_attributed_evidence(unit, WORKSPACE_UNIT_CASES, WORKSPACE_EVIDENCE_PREFIX)
    privileged = workspace_privileged()
    base = _workspace_base()
    client, socket, variables, before, images = _workload_setup()
    os.environ.update(variables)
    suites = [
        ("dwkd-broker", "sandbox_workload", WORKSPACE_BROKER_TESTS),
        ("dwkd-authority", "sandbox_workload", WORKSPACE_AUTHORITY_TESTS),
    ]
    outputs: list[str] = []
    try:
        if privileged:
            os.environ.update(_provision_workspaces(base))
            suites += [
                ("dwkd-broker", "sandbox_workload", WORKSPACE_PRIVILEGED_BROKER_TESTS),
                ("dwkd-authority", "sandbox_workload", WORKSPACE_PRIVILEGED_AUTHORITY_TESTS),
            ]
        run("cargo", "build", "--locked", "-p", "dwkd-broker")
        for package, test, names in suites:
            output = run_captured(
                "cargo",
                "test",
                "--locked",
                "-p",
                package,
                "--test",
                test,
                "--",
                "--ignored",
                "--exact",
                "--nocapture",
                "--test-threads=1",
                *names,
            )
            summaries = [line for line in output.splitlines() if line.startswith("test result: ")]
            expected = f"test result: ok. {len(names)} passed; 0 failed; 0 ignored"
            if len(summaries) != 1 or not summaries[0].startswith(expected):
                raise TaskError(
                    f"the {package} {test} workspace suite did not run all of its tests: "
                    f"expected `{expected}`, got {summaries or 'no summary'}"
                )
            outputs.append(output)
    finally:
        if privileged or base.exists():
            _unprovision_workspaces(base)
        after = set(
            _docker(client, socket, "container", "ls", "--all", "--no-trunc", "--quiet").split()
        )
        for image in set(images.values()):
            _docker(client, socket, "image", "rm", "--force", image, check=False)
    left = sorted(after - before)
    removed = sorted(before - after)
    if left:
        raise TaskError(f"the evidence left {len(left)} container(s) behind: {left}")
    if removed:
        raise TaskError(
            f"{len(removed)} container(s) that predate the evidence are gone: {removed}"
        )
    report_cleanup(f"cleanup: no evidence container remains; {len(before)} pre-existing kept")
    if privileged:
        # One account of both halves: their lines are one output.
        require_attributed_evidence("\n".join(outputs), WORKSPACE_ALL_CASES)
        uvrun("dwcheck", "closure", "--report")
        return
    require_attributed_evidence("\n".join(outputs), WORKSPACE_CASES)
    if not require_privileged:
        # A mutant's run: what could run here ran; the privileged half
        # is NOT EXERCISED, and never counted as a kill.
        print(
            f"NOT EXERCISED (not counted): {len(WORKSPACE_PRIVILEGED_CASES)} privileged "
            "workspace case(s)"
        )
        return
    raise TaskError(
        f"NOT EXERCISED: {len(WORKSPACE_PRIVILEGED_CASES)} case(s) need an "
        "operator-provisioned workspace -- the group 10001, filesystems of their own, "
        "sudo -- which only DW_WORKSPACE_PRIVILEGED=1 provisions (the hosted "
        "`sandbox-workspace` job). The unverified-workspace waiver is not evidence of "
        "the production guarantee: "
        + ", ".join(f"{suite}/{case}" for suite, case in WORKSPACE_PRIVILEGED_CASES)
    )


# The mutation review (ADR-0052 §17): each line weakens one guard of M5d.4's,
# in the source, one at a time. Each mutant must compile and must fail the
# guards' unit suites or the workspace evidence that can run here; the file is
# then restored, and its SHA-256 proves it byte-identical. A mutant that
# survives, or does not compile, fails the review.
WORKSPACE_MUTATIONS = (
    # The authority's contract (state/workspace.rs).
    (
        "a root the workload or a stranger owns is accepted",
        "crates/dwkd-authority/src/state/workspace.rs",
        "    if measured.uid == WORKLOAD_UID"
        " || (measured.uid != 0 && measured.uid != context.authority_uid)\n",
        "    if false\n        && (measured.uid == WORKLOAD_UID"
        " || (measured.uid != 0 && measured.uid != context.authority_uid))\n",
    ),
    (
        "a root of another group is accepted",
        "crates/dwkd-authority/src/state/workspace.rs",
        "    if measured.gid != WORKSPACE_GROUP {",
        "    if false && measured.gid != WORKSPACE_GROUP {",
    ),
    (
        "a root of another mode is accepted",
        "crates/dwkd-authority/src/state/workspace.rs",
        "    if measured.mode != WORKSPACE_ROOT_MODE {",
        "    if measured.mode & WORKSPACE_ROOT_MODE != WORKSPACE_ROOT_MODE {",
    ),
    (
        "an authority outside the group is accepted",
        "crates/dwkd-authority/src/state/workspace.rs",
        '        Some(false) => return Err("WORKSPACE_GROUP_MEMBERSHIP"),',
        "        Some(false) => {}",
    ),
    (
        "a filesystem larger than the quota is accepted",
        "crates/dwkd-authority/src/state/workspace.rs",
        "    if bytes > quota {",
        "    if false && bytes > quota {",
    ),
    (
        "a filesystem far below the quota is accepted",
        "crates/dwkd-authority/src/state/workspace.rs",
        "    if !capacity_within_quota(bytes, quota) {",
        "    if bytes > quota && !capacity_within_quota(bytes, quota) {",
    ),
    (
        "the authority's own files may share the workspace's filesystem",
        "crates/dwkd-authority/src/state/workspace.rs",
        '            Some(found) if found == device => return Err("WORKSPACE_FILESYSTEM_SHARED"),',
        "            Some(found) if found == device && false => {\n"
        '                return Err("WORKSPACE_FILESYSTEM_SHARED");\n'
        "            }",
    ),
    (
        "a bounded workspace is sent with no bound",
        "crates/dwkd-authority/src/state/workspace.rs",
        '    let measured = root.measure().map_err(|_| "WORKSPACE_UNOBSERVABLE")?;',
        "    if quota.get() > 0 {\n        return Ok(None);\n    }\n"
        '    let measured = root.measure().map_err(|_| "WORKSPACE_UNOBSERVABLE")?;',
    ),
    # The exclusion in time (ADR-0044 §3).
    (
        "a brokered change is made while a workload may run",
        "crates/dwkd-authority/src/state/mod.rs",
        "            if workspace::in_use(work, run.as_str())? {",
        "            if false && workspace::in_use(work, run.as_str())? {",
    ),
    (
        "a launching workload does not exclude",
        "crates/dwkd-authority/src/state/workspace.rs",
        "w.state = 'LAUNCHING'",
        "w.state = 'NEVER'",
    ),
    (
        "an environment whose end nothing proved does not exclude",
        "crates/dwkd-authority/src/state/workspace.rs",
        "e.state IN ('UNKNOWN', 'DESTROYING')",
        "e.state IN ('NEVER')",
    ),
    (
        "a reclamation is made while a workload may run",
        "crates/dwkd-authority/src/state/mod.rs",
        "            if self.transact(|work| workspace::in_use(work, item.run()))? {",
        "            if false && self.transact(|work| workspace::in_use(work, item.run()))? {",
    ),
    # Drift before a workload, and how it is answered.
    (
        "a workspace grown under a ready environment keeps it",
        "crates/dwkd-authority/src/state/workload.rs",
        '            | b"WORKSPACE_UNBOUNDED"\n',
        "",
    ),
    (
        "a drifted workspace is answered as the broker's failure",
        "crates/dwkd-authority/src/state/workload_route.rs",
        '        | "WORKSPACE_UNBOUNDED"\n',
        "",
    ),
    # The operator's file.
    (
        "a file that names no workspace contract gets the unverified one",
        "crates/dwkd-authority/src/sandbox/operator.rs",
        '        (None, Some(false) | None) => Err("[workspace] needs quota_bytes".to_owned()),',
        "        (None, Some(false) | None) => Ok(WorkspaceSetting::UnverifiedEvidence),",
    ),
    # The broker's judgement of the probe's facts (sandbox/oci.rs).
    (
        "a workspace whose identity the probe contradicts passes",
        "crates/dwkd-broker/src/sandbox/oci.rs",
        "    let same = if facts.identity() == spec.workspace {",
        "    let same = if true || facts.identity() == spec.workspace {",
    ),
    (
        "a broker outside the group passes ownership",
        "crates/dwkd-broker/src/sandbox/oci.rs",
        "                (Verdict::Pass, Some(true)) => Verdict::Pass,",
        "                (Verdict::Pass, _) => Verdict::Pass,",
    ),
    (
        "the capacity the probe found is not judged",
        "crates/dwkd-broker/src/sandbox/oci.rs",
        "            workspace_capacity(facts, bound),",
        "            Verdict::Pass,",
    ),
    (
        "a bounded environment is judged without the workspace's invariants",
        "crates/dwkd-broker/src/sandbox/oci.rs",
        "        .iter()\n        .all(|invariant| checks.contains(&(*invariant, Verdict::Pass)))",
        "        .iter()\n        .filter(|invariant| !invariant.workspace_contract())\n"
        "        .all(|invariant| checks.contains(&(*invariant, Verdict::Pass)))",
    ),
    (
        "an unverified workspace is served without the operator's flag",
        "crates/dwkd-broker/src/sandbox/mod.rs",
        "        if spec.workspace_bound.is_none() && !self.unverified_workspace {",
        "        if false && spec.workspace_bound.is_none() && !self.unverified_workspace {",
    ),
    # The probe's reading of the mount.
    (
        "the probe says every mount is its filesystem's root",
        "crates/dwk-sandbox-probe/src/linux.rs",
        '        self.root == "/"',
        "        !self.root.is_empty()",
    ),
    # The group's convention and a full filesystem (the broker's exchange).
    (
        "a workspace directory without the group's convention is changed",
        "crates/dwkd-broker/src/exchange/staging.rs",
        "    if parent.st_gid == WORKSPACE_GROUP && parent.st_mode & 0o2070 != 0o2070 {",
        "    if false && parent.st_gid == WORKSPACE_GROUP && parent.st_mode & 0o2070 != 0o2070 {",
    ),
    (
        "no room is reported as an input/output error",
        "crates/dwkd-broker/src/exchange/staging.rs",
        "        Errno::NOSPC | Errno::DQUOT => BrokerRefusal::NoSpace,\n"
        "        _ => BrokerRefusal::IoError,",
        "        Errno::NOSPC | Errno::DQUOT => BrokerRefusal::IoError,\n"
        "        _ => BrokerRefusal::IoError,",
    ),
    (
        "no room for a name change is reported as the caller's",
        "crates/dwkd-broker/src/exchange/staging.rs",
        "        // workspace, which is no one's fault but the writer's.\n"
        "        Errno::NOSPC | Errno::DQUOT => BrokerRefusal::NoSpace,",
        "        // workspace, which is no one's fault but the writer's.\n"
        "        Errno::NOSPC | Errno::DQUOT => otherwise,",
    ),
    # Every launch through the launcher, with the workspace's umask (OD-12).
    (
        "the launcher leaves the runtime's umask",
        "crates/dwk-sandbox-probe/src/launch.rs",
        "    let _previous = nix::sys::stat::umask(Mode::from_bits_truncate(WORKLOAD_UMASK));",
        "    let _previous = nix::sys::stat::umask(Mode::from_bits_truncate(0o022));",
    ),
    (
        "a direct workload bypasses the launcher",
        "crates/dwkd-broker/src/sandbox/workload_plan.rs",
        "        None,\n        words(&[PROBE_PATH, PROBE_LAUNCH, profile]),",
        "        None,\n        if profile == LAUNCH_DIRECT {\n            Vec::new()\n"
        "        } else {\n            words(&[PROBE_PATH, PROBE_LAUNCH, profile])\n        },",
    ),
)


def _workspace_guard_suites() -> None:
    """The suites that prove M5d.4's guards without a runtime: the contract's
    judgements and their wire forms, the probe's mount reading and launcher,
    the broker's plan, judgement, admission and exchange (a real full tmpfs
    included), and the authority's contract, exclusions, drift, route and
    operator file (against a fake broker)."""
    run("cargo", "test", "--locked", "-p", "dwk-proto", "--lib", "--", "sandbox::")
    run("cargo", "test", "--locked", "-p", "dwk-sandbox-probe")
    run("cargo", "test", "--locked", "-p", "dwkd-broker", "--bin", "dwkd-broker")
    run(
        "cargo",
        "test",
        "--locked",
        "-p",
        "dwkd-authority",
        "--lib",
        "--",
        "state::",
        "sandbox::",
    )


def task_sandbox_workspace_mutations() -> None:
    """Weaken each M5d.4 guard in turn; a unit suite or the workspace
    evidence must catch every one.

    Slow: a mutant no unit suite catches runs the workspace evidence -- its
    privileged half too where DW_WORKSPACE_PRIVILEGED=1 provisions it, and
    otherwise the rest, whose NOT EXERCISED is never counted as a kill.
    Every file is restored byte-identically whatever happens, and checked.
    Never run it beside another build.
    """
    killed: list[str] = []
    for what, rel, old, new in WORKSPACE_MUTATIONS:
        path = ROOT / rel
        original = path.read_bytes()
        digest = hashlib.sha256(original).hexdigest()
        text = original.decode("utf-8")
        if text.count(old) != 1:
            raise TaskError(f"mutation `{what}`: its target is not in {rel} exactly once")
        print(f"{BOLD}mutant: {what}{OFF}")
        outcome = "survived"
        try:
            path.write_bytes(text.replace(old, new).encode("utf-8"))
            try:
                run(
                    "cargo",
                    "test",
                    "--locked",
                    "--no-run",
                    "-p",
                    "dwk-proto",
                    "-p",
                    "dwk-sandbox-probe",
                    "-p",
                    "dwkd-broker",
                    "-p",
                    "dwkd-authority",
                )
            except TaskError:
                outcome = "did not compile"
            else:
                try:
                    _workspace_guard_suites()
                except TaskError as exc:
                    outcome = f"killed by a unit suite: {str(exc)[:160]}"
                else:
                    try:
                        _sandbox_workspace_evidence(require_privileged=False)
                    except TaskError as exc:
                        outcome = f"killed by the evidence: {str(exc)[:160]}"
        finally:
            path.write_bytes(original)
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise TaskError(f"{rel} was not restored byte-identically")
        print(f"{DIM}restored {rel} (sha256 {digest[:16]}...){OFF}")
        if not outcome.startswith("killed"):
            raise TaskError(f"mutant `{what}` {outcome}: nothing guards it")
        killed.append(what)
        print(f"{GREEN}mutant {outcome[:60]}: {what}{OFF}")
    print(
        f"{GREEN}sandbox workspace mutation review: {len(killed)} of "
        f"{len(WORKSPACE_MUTATIONS)} killed{OFF}"
    )


# --- M5e.1: every line of evidence attributed (OD-E1) ------------------------

# The plan's M5e.1 (docs/M5E_ASSURANCE_PLAN.md §6) and the owner's OD-E1:
# every line of the foundation, egress, workload, secret and workspace
# evidence says what kind of evidence it is (`level`) and what enforced, or
# observed, what it shows (`enforcement`) -- an existing mechanism only: an
# invariant the broker measured, the kernel refusing under the profile, the
# CONNECT proxy's decision and its counters, the authority's gates, ledger,
# reconciliation or audit. No new per-attempt audit event: a contained
# attempt is attributed, not individually audited (SANDBOX.md §6, which
# names every level and mechanism below). The agent's and the release's
# evidence keep their own, earlier contracts (`require_agent_evidence`,
# `require_release_evidence`).
#
# The levels, from the least to the most of the product: the product's code
# in this process (`in-process`); the REAL authority and store against the
# route tests' FAKE broker, which contains nothing (`fake-broker`); the
# released broker on a REAL runtime, this process playing the authority or
# calling the real authority's own API (`real-oci`); a REAL DWKP client on
# the authority's socket, the seam's or the released `serve`'s
# (`dwkp-end-to-end`); and what only an operator-provisioned host runs -- the
# group 10001, filesystems of their own, sudo -- which only
# `DW_WORKSPACE_PRIVILEGED=1` provisions (`privileged-oci`).
ATTRIBUTION_LEVELS = frozenset(
    ("in-process", "fake-broker", "real-oci", "dwkp-end-to-end", "privileged-oci")
)
# Every mechanism a line may name. `telemetry` is not containment: it is the
# foundation's latency, which must say `measured` and carry its numbers.
ATTRIBUTION_MECHANISMS = frozenset(
    (
        # The broker's measured assurance (ADR-0047), and what it pins.
        "measured-host",
        "measured-inside",
        "measured-both",
        "measured-before-work",
        "probe-digest-pin",
        "probe-report-validation",
        "probe-step-deadline",
        "relay-digest-pin",
        "executable-digest-pin",
        "workspace-contract-measured",
        # The profile, as the kernel holds it.
        "capabilities-and-seccomp",
        "capabilities",
        "seccomp",
        "no-new-privileges",
        "oci-user",
        "read-only-root",
        "container-tmpfs",
        "mount-namespace",
        "pid-namespace",
        "workspace-mount",
        "cgroup-limit",
        "rlimit",
        "filesystem-quota",
        # The environment's network (the egress evidence's own words).
        "topology-no-route",
        "topology-nothing-listening",
        "topology-no-resolver",
        "platform",
        "platform-or-capabilities",
        "proxy-only-topology",
        "egress-socket-acl",
        "egress-listener-lifecycle",
        "egress-disposition-counters",
        "launch-environment",
        "relay-and-connect-proxy-grant",
        "connect-proxy:grant",
        "connect-proxy:canonical-target",
        "connect-proxy:address-guard",
        "connect-proxy:resolver",
        "connect-proxy:resolver-deadline",
        "connect-proxy:server-name",
        "connect-proxy:upload-budget",
        "connect-proxy:download-budget",
        "connect-proxy:tunnel-limit",
        # The broker's own lifecycle, launch and judgement.
        "exact-label-ownership",
        "exact-label-cleanup",
        "fresh-container-per-environment",
        "runtime-client",
        "broker-admission",
        "broker-start-up-admission",
        "broker-start-up-posture",
        "broker-workspace-convention",
        "broker-launch",
        "broker-log-discipline",
        "broker-wall-clock",
        "broker-start-collect",
        "broker-workload-admission",
        "broker-census",
        "broker-judgement-before-exec",
        "broker-fail-closed",
        "broker-secret-admission",
        "ending-classification",
        "output-bound",
        "output-redaction",
        "environment-init-reap",
        "residue-measurement",
        "workload-generation",
        "direct-launcher",
        "hygiene-launcher",
        "trusted-launcher",
        "secret-stdin-handoff",
        # The authority's (ADR-0047 §§11-13, ADR-0052).
        "authority-gates",
        "authority-plan",
        "authority-policy",
        "authority-capability",
        "authority-obligation",
        "authority-image-manifest",
        "authority-request-bounds",
        "authority-run-budget",
        "authority-taint",
        "authority-route",
        "authority-environment-decision",
        "authority-environment-judgement",
        "authority-grant-derivation",
        "authority-workspace-contract",
        "authority-workspace-exclusion",
        "authority-ledger",
        "authority-ledger-intent-first",
        "authority-idempotency",
        "authority-lease-fence",
        "authority-reconciliation",
        "authority-reclamation",
        "authority-audit",
        "authority-audit-at-destruction",
        "kernel-process-credentials",
        "dwkp-schema",
        "secret-metadata",
        "secret-backend",
        "secret-value-validation",
        "secret-not-persisted",
        # The workspace group (ADR-0052 §6), as the agent's evidence words it.
        "workspace-group-10001",
        "workspace-root-2770",
        # What a case observes rather than what enforces: the test's own
        # listing of the environment's processes, and the residuals ADR-0052
        # states -- contained by the environment, never neutralised.
        "runtime-process-list",
        "residual-contained-by-the-environment",
        "residual-inherited-by-descendants",
        # M5e.4: what the workload's own tool did, which is not DireWolf's --
        # its TLS verification refusing an issuer, and what it left in the
        # workspace, measured.
        "workload-tls-verification",
        "workload-effects-measured",
        # M5e.5: npm's own integrity check refusing a tarball its packument
        # does not describe -- the workload's tool's, not DireWolf's.
        "workload-integrity-verification",
        "telemetry",
    )
)

_IN = "in-process"
_FAKE = "fake-broker"
_OCI = "real-oci"
_DWKP = "dwkp-end-to-end"
_PRIV = "privileged-oci"
# The egress evidence's bypass cases say what refused them as they ran
# (`mechanism=` in the outcome): any the attempt's errno can mean.
_DIRECT = ("topology-no-route", "platform")
_RAW = ("capabilities", "topology-no-route", "platform")

# The contract: for each suite, `(pattern, level, mechanism or mechanisms)`,
# the first whose pattern (`fnmatch`) names the case giving its level and
# the mechanisms its line may name. A case no rule names is unattributed,
# which fails; a rule that names no required case is a test failure
# (`tests/architecture/test_m5e_attribution.py`).
ATTRIBUTION: dict[str, tuple[tuple[str, str, str | tuple[str, ...]], ...]] = {
    # M5a: the broker on a real runtime, this process the authority.
    "sandbox-broker": (
        ("latency", _OCI, "telemetry"),
        ("prepare-clean", _OCI, "measured-both"),
        ("runtime-version-reported", _OCI, "measured-host"),
        ("host-*", _OCI, "measured-host"),
        ("container-*", _OCI, "measured-inside"),
        ("escape-*", _OCI, "capabilities-and-seccomp"),
        ("measure-clean-again", _OCI, "measured-both"),
        ("list-owned-exact-labels", _OCI, "exact-label-ownership"),
        ("destroy-*", _OCI, "exact-label-cleanup"),
        ("baseline-conforming", _OCI, "measured-both"),
        # One vantage alone catches these three weakenings; both, the rest.
        ("weakened-host-ipc", _OCI, "measured-host"),
        ("weakened-host-uts", _OCI, "measured-host"),
        ("weakened-mutable-image-tag", _OCI, "measured-host"),
        ("weakened-*", _OCI, "measured-both"),
        ("tamper-changed-byte", _OCI, "probe-digest-pin"),
        ("tamper-substituted-probe", _OCI, "probe-digest-pin"),
        ("tamper-hang-timeout", _OCI, "probe-step-deadline"),
        ("tamper-*", _OCI, "probe-report-validation"),
        ("foreign-*", _OCI, "exact-label-ownership"),
        ("drift-pids-limit-raised", _OCI, "measured-both"),
        ("run-isolation-distinct-environments", _OCI, "fresh-container-per-environment"),
        ("run-isolation-tmp", _OCI, "measured-inside"),
        ("run-isolation-destroy-one-leaves-other", _OCI, "measured-both"),
        ("persistence-tmp-marker-not-inherited", _OCI, "container-tmpfs"),
        ("exit-stopped-unobservable-inside", _OCI, "measured-host"),
        ("exit-*", _OCI, "runtime-client"),
        ("topology-*", _OCI, "broker-admission"),
        ("refusals-create-nothing", _OCI, "broker-admission"),
        ("crash-w3-broker-after-create-labelled", _OCI, "exact-label-ownership"),
        ("crash-w3-reaped-by-label", _OCI, "exact-label-cleanup"),
        ("resource-pids-bounded", _OCI, "cgroup-limit"),
        ("resource-memory-oom-killed", _OCI, "cgroup-limit"),
        ("resource-fds-bounded", _OCI, "rlimit"),
        ("resource-file-size-bounded", _OCI, "rlimit"),
        ("subprocess-and-thread-creation", _OCI, "seccomp"),
    ),
    # M5a: the real authority's own API over the real broker and runtime.
    "sandbox-authority": (
        ("*-intent-durable-before-broker", _OCI, "authority-ledger-intent-first"),
        ("prepare-ready-recorded", _OCI, "authority-ledger"),
        ("destroy-recorded", _OCI, "authority-ledger"),
        ("destroy-idempotent", _OCI, "authority-ledger"),
        ("effective-assurance-container-isolation", _OCI, "authority-environment-judgement"),
        ("measure-clean", _OCI, "authority-environment-judgement"),
        ("drift-destroyed", _OCI, "authority-environment-judgement"),
        ("one-environment-per-run", _OCI, "authority-environment-decision"),
        ("audit-lifecycle", _OCI, "authority-audit"),
        ("crash-*", _OCI, "authority-reconciliation"),
        ("orphan-ended-record-reaped", _OCI, "authority-reconciliation"),
        ("ambiguous-twins-untouched", _OCI, "authority-reconciliation"),
        ("foreign-*", _OCI, "exact-label-ownership"),
    ),
    # M5b: PROXY_ONLY on a real runtime, every byte through the real relay
    # and the broker's real CONNECT proxy.
    "sandbox-egress": (
        ("proxy-only-prepare-clean", _OCI, "measured-both"),
        ("proxy-only-host-*", _OCI, "measured-host"),
        ("proxy-only-container-*", _OCI, "measured-inside"),
        ("proxy-only-environment-and-relay-only", _OCI, "proxy-only-topology"),
        ("proxy-only-relay-shares-the-namespace-unprivileged", _OCI, "proxy-only-topology"),
        ("proxy-only-socket-mounted-in-relay-only", _OCI, "proxy-only-topology"),
        ("proxy-only-listener-open", _OCI, "egress-socket-acl"),
        ("proxy-only-socket-directory-relay-uid-only", _OCI, "egress-socket-acl"),
        ("proxy-only-listed-with-roles", _OCI, "exact-label-ownership"),
        ("proxy-only-measure-clean-again", _OCI, "measured-both"),
        ("proxy-only-destroy-removes-every-role", _OCI, "exact-label-cleanup"),
        ("proxy-only-destroy-closes-listener", _OCI, "egress-listener-lifecycle"),
        ("proxy-only-destroy-counters", _OCI, "egress-disposition-counters"),
        ("proxy-only-destroy-idempotent", _OCI, "exact-label-cleanup"),
        ("tunnel-granted-carries-bytes", _OCI, "relay-and-connect-proxy-grant"),
        ("tunnel-via-proxy-variable", _OCI, "relay-and-connect-proxy-grant"),
        ("tunnel-host-not-granted", _OCI, "connect-proxy:grant"),
        ("tunnel-port-not-granted", _OCI, "connect-proxy:grant"),
        ("tunnel-address-literal-refused", _OCI, "connect-proxy:canonical-target"),
        ("tunnel-sni-*-closed", _OCI, "connect-proxy:server-name"),
        ("tunnel-ech-refused", _OCI, "connect-proxy:server-name"),
        ("tunnel-plain-http-refused", _OCI, "connect-proxy:server-name"),
        ("resolver-failure", _OCI, "connect-proxy:resolver"),
        ("resolver-timeout", _OCI, "connect-proxy:resolver-deadline"),
        ("resolver-*", _OCI, "connect-proxy:address-guard"),
        ("counters-at-destroy-by-disposition", _OCI, "egress-disposition-counters"),
        ("audit-observability-no-payload", _OCI, "egress-disposition-counters"),
        ("budget-upload-*", _OCI, "connect-proxy:upload-budget"),
        ("budget-download-exhausted", _OCI, "connect-proxy:download-budget"),
        ("budget-tunnel-limit", _OCI, "connect-proxy:tunnel-limit"),
        ("fronting-residual-carried-and-bounded", _OCI, "connect-proxy:upload-budget"),
        # The environment's own loopback has nothing on the host's port.
        ("bypass-tcp-host-loopback-origin", _OCI, ("topology-nothing-listening", *_DIRECT)),
        ("bypass-tcp-*", _OCI, _DIRECT),
        ("bypass-udp-*", _OCI, _DIRECT),
        ("bypass-proxy-address-other-ports", _OCI, "topology-nothing-listening"),
        ("bypass-dns-*", _OCI, "topology-no-resolver"),
        ("bypass-library-resolver*", _OCI, "topology-no-resolver"),
        ("bypass-raw-*", _OCI, _RAW),
        ("bypass-packet", _OCI, _RAW),
        ("bypass-vsock", _OCI, ("seccomp", "topology-no-route", "platform")),
        ("bypass-icmp", _OCI, ("topology-no-route", "platform-or-capabilities")),
        ("bypass-proxy-variable-*", _OCI, "topology-no-route"),
        ("bypass-origin-never-reached", _OCI, "topology-no-route"),
        ("proxy-variables-*", _OCI, "launch-environment"),
        ("runtime-client-config-proxies-ignored", _OCI, "launch-environment"),
        ("weakened-proxy-variables-removed", _OCI, "measured-host"),
        ("weakened-relay-tampered", _OCI, "relay-digest-pin"),
        ("weakened-*", _OCI, "measured-both"),
        ("drift-relay-stopped", _OCI, "measured-both"),
        ("drift-extra-peer-listening", _OCI, "measured-inside"),
        ("drift-fake-resolver-in-namespace", _OCI, "measured-inside"),
        ("drift-*", _OCI, "measured-host"),
        ("crash-*", _OCI, "exact-label-cleanup"),
        ("restart-proxy-closed-fails-closed", _OCI, "measured-both"),
        ("foreign-resources-untouched", _OCI, "exact-label-ownership"),
        ("production-proxy-only-prepared", _OCI, "measured-both"),
        ("production-no-fixture-resolver", _OCI, "connect-proxy:resolver"),
        ("production-loopback-blocked-no-exception", _OCI, "connect-proxy:address-guard"),
        ("production-proxy-only-needs-its-grant", _OCI, "broker-admission"),
    ),
    # M5b: the grant the real authority derives, through its own API.
    "sandbox-authority-egress": (
        ("grant-*", _OCI, "authority-grant-derivation"),
        ("audit-intent-records-grant", _OCI, "authority-audit"),
        ("audit-measured-counters", _OCI, "authority-audit"),
        ("audit-destroyed-counters", _OCI, "authority-audit-at-destruction"),
        ("tunnel-through-authority-prepared-environment", _OCI, "relay-and-connect-proxy-grant"),
        ("wildcard-covered-name-not-granted", _OCI, "connect-proxy:grant"),
        ("reconcile-helper-orphan-reaped", _OCI, "authority-reconciliation"),
    ),
    # M5d.1-M5d.2: workloads the broker runs in its real environments.
    "sandbox-workload": (
        ("workload-runs-as-uid-10001", _OCI, "oci-user"),
        ("workload-no-capabilities", _OCI, "capabilities"),
        ("workload-no-new-privileges", _OCI, "no-new-privileges"),
        ("workload-seccomp-filter", _OCI, "seccomp"),
        ("workload-cwd-workspace", _OCI, "broker-launch"),
        ("workload-arguments-exact-bytes", _OCI, "broker-launch"),
        ("workload-flags-in-arguments-inert", _OCI, "broker-launch"),
        ("workload-environment-container-only", _OCI, "launch-environment"),
        ("workload-exit-code", _OCI, "ending-classification"),
        ("workload-killed-by-signal", _OCI, "ending-classification"),
        ("workload-ambiguous-exit-unobservable", _OCI, "ending-classification"),
        ("workload-log-has-no-argument-or-output", _OCI, "broker-log-discipline"),
        ("workload-output-held-open-child-reaped", _OCI, "environment-init-reap"),
        ("workload-output-*", _OCI, "output-bound"),
        ("workload-wall-clock-timed-out", _OCI, "broker-wall-clock"),
        ("workload-residue-clean", _OCI, "residue-measurement"),
        ("workload-environment-removed-mid-run-not-clean", _OCI, "residue-measurement"),
        ("workload-executable-*", _OCI, "executable-digest-pin"),
        ("workload-refused-ran-nothing", _OCI, "executable-digest-pin"),
        ("workload-drifted-environment-refused", _OCI, "measured-before-work"),
        ("workload-stopped-environment-refused", _OCI, "measured-before-work"),
        ("workload-foreign-environment-refused", _OCI, "exact-label-ownership"),
        ("workload-missing-environment-refused", _OCI, "runtime-client"),
        ("workload-nothing-ran-in-a-refused-environment", _OCI, "broker-admission"),
        ("workload-root-read-only", _OCI, "read-only-root"),
        ("workload-etc-read-only", _OCI, "read-only-root"),
        ("workload-dot-dot-escape-refused", _OCI, "read-only-root"),
        ("workload-tmp-writable", _OCI, "container-tmpfs"),
        ("workload-workspace-writable-as-10001", _OCI, "workspace-mount"),
        ("workload-no-runtime-socket", _OCI, "mount-namespace"),
        ("workload-no-host-path", _OCI, "mount-namespace"),
        ("workload-direct-tcp-refused", _OCI, "topology-no-route"),
        ("workload-direct-dns-refused", _OCI, "topology-no-resolver"),
        ("workload-start-answered-before-it-ends", _OCI, "broker-start-collect"),
        ("workload-collected-ending-repeats", _OCI, "broker-start-collect"),
        ("workload-second-in-environment-refused", _OCI, "broker-workload-admission"),
        ("workload-collect-other-generation-indeterminate", _OCI, "workload-generation"),
        ("workload-timed-out-reaped", _OCI, "environment-init-reap"),
        ("workload-tree-reaped", _OCI, "environment-init-reap"),
        ("workload-setsid-reaped", _OCI, "environment-init-reap"),
        ("workload-daemon-reaped", _OCI, "environment-init-reap"),
        ("workload-fork-loop-reaped", _OCI, "environment-init-reap"),
        ("workload-nothing-persists", _OCI, "environment-init-reap"),
        ("workload-no-zombies", _OCI, "environment-init-reap"),
        ("workload-environment-reusable-after-reap", _OCI, "environment-init-reap"),
        ("agent-shaped-plan-and-workers-wrote", _OCI, "workspace-mount"),
        ("agent-shaped-files-on-host-as-10001", _OCI, "workspace-mount"),
        ("agent-shaped-network-refused", _OCI, "topology-no-route"),
        ("agent-shaped-helpers-and-workers-ended", _OCI, "environment-init-reap"),
        ("agent-shaped-residue-clean", _OCI, "residue-measurement"),
        ("identity-authority-*-uid-refused", _OCI, "broker-start-up-admission"),
        ("posture-reported-matches-host", _OCI, "broker-start-up-posture"),
        ("broker-crash-before-exec-nothing-ran", _OCI, "broker-judgement-before-exec"),
        ("broker-crash-mid-workload-no-answer", _OCI, "broker-fail-closed"),
        ("broker-crash-workload-still-running", _OCI, "runtime-process-list"),
        ("broker-restart-destroy-ends-it", _OCI, "exact-label-cleanup"),
        ("broker-restart-collection-indeterminate", _OCI, "workload-generation"),
        ("broker-serves-others-while-a-workload-runs", _OCI, "broker-start-collect"),
        ("broker-holds-nothing-*", _OCI, "broker-census"),
        ("hygiene-residual-*", _OCI, "residual-contained-by-the-environment"),
        ("hygiene-*", _OCI, "hygiene-launcher"),
    ),
    # M5d.1 through the real authority's own API; M5d.2 over a real DWKP
    # client, the seam's and the released `serve --sandbox-config`.
    "sandbox-authority-workload": (
        ("authority-workload-completed", _OCI, "authority-route"),
        ("authority-workload-ledger-completed", _OCI, "authority-ledger"),
        ("authority-workload-environment-kept-when-clean", _OCI, "authority-environment-judgement"),
        ("authority-workload-audited", _OCI, "authority-audit"),
        ("authority-workload-taint-raised", _OCI, "authority-taint"),
        ("authority-workload-obligation-*", _OCI, "authority-obligation"),
        ("authority-workload-replayed-never-rerun", _OCI, "authority-idempotency"),
        ("authority-workload-key-reused-differently-refused", _OCI, "authority-idempotency"),
        ("authority-workload-no-environment-refused", _OCI, "authority-environment-decision"),
        ("authority-workload-never-on-the-host", _OCI, "authority-environment-decision"),
        ("authority-workload-no-ready-environment-refused", _OCI, "authority-environment-decision"),
        ("authority-workload-not-in-manifest-refused", _OCI, "authority-image-manifest"),
        ("authority-workload-bounds-refused", _OCI, "authority-request-bounds"),
        ("authority-workload-policy-denied", _OCI, "authority-policy"),
        ("authority-workload-no-capability-denied", _OCI, "authority-capability"),
        ("authority-workload-refusals-record-no-intent", _OCI, "authority-gates"),
        ("authority-workload-drifted-*", _OCI, "authority-environment-judgement"),
        ("authority-workload-budget-*", _OCI, "authority-run-budget"),
        ("crash-w9-running-after-start", _OCI, "runtime-process-list"),
        ("crash-*", _OCI, "authority-reconciliation"),
        ("unknown-ending-recorded", _OCI, "authority-ledger"),
        ("unknown-ending-environment-destroyed", _OCI, "authority-reconciliation"),
        ("unknown-ending-never-rerun", _OCI, "authority-idempotency"),
        (
            "public-exec-environment-prepared-by-the-authority",
            _DWKP,
            "authority-environment-decision",
        ),
        ("public-exec-result-names-*", _DWKP, "authority-environment-judgement"),
        ("public-exec-runs-as-the-sandbox-user", _DWKP, "oci-user"),
        ("public-exec-caller-from-the-transport", _DWKP, "kernel-process-credentials"),
        ("public-exec-never-on-the-host", _DWKP, "authority-environment-decision"),
        ("public-exec-two-runs-at-once-*", _DWKP, "authority-environment-decision"),
        ("public-exec-output-bounded", _DWKP, "output-bound"),
        ("public-exec-detached-child-reaped", _DWKP, "environment-init-reap"),
        ("public-exec-authority-answers-during-a-workload", _DWKP, "authority-route"),
        ("public-exec-broker-answers-during-a-workload", _DWKP, "broker-start-collect"),
        ("public-exec-key-from-another-holder-fenced", _DWKP, "authority-lease-fence"),
        ("public-exec-long-workload-timed-out-and-reaped", _DWKP, "broker-wall-clock"),
        ("public-exec-key-never-runs-twice", _DWKP, "authority-idempotency"),
        ("public-exec-cross-tool-key-refused", _DWKP, "authority-idempotency"),
        ("public-exec-smuggled-environment-refused", _DWKP, "dwkp-schema"),
        ("public-no-lifecycle-operation", _DWKP, "dwkp-schema"),
        ("public-exec-unknown-outcome-reported", _DWKP, "authority-ledger"),
        ("public-exec-unknown-destroys-environment", _DWKP, "authority-reconciliation"),
        ("public-exec-budget-exhausted-refused", _DWKP, "authority-run-budget"),
        ("public-exec-unpinned-image-bytes-refused", _DWKP, "executable-digest-pin"),
        ("public-exec-ended-runs-environment-reclaimed", _DWKP, "authority-reclamation"),
        ("od9-concrete-grant-runs-the-manifests-executable", _DWKP, "authority-image-manifest"),
        ("od9-concrete-grant-covers-nothing-else", _DWKP, "authority-capability"),
        # Dispatched through the authority's own API, not a DWKP client.
        ("od9-host-resolved-grant-covers-no-image-executable", _OCI, "authority-capability"),
        ("shipped-*-hygiene-undone-or-unevidenced-denied", _DWKP, "authority-obligation"),
        ("shipped-*", _DWKP, "hygiene-launcher"),
        ("production-serve-attaches-*", _DWKP, "authority-environment-decision"),
        ("production-serve-prepares-and-runs", _DWKP, "authority-route"),
        ("production-crash-mid-workload-unknown-destroyed", _DWKP, "authority-reconciliation"),
        ("production-replay-after-restart-refused", _DWKP, "authority-idempotency"),
        # M5e.2 (R8; ADR-0056): the neighbour through `process.exec`.
        ("neighbour-run-holds-its-own-task-bound", _DWKP, "cgroup-limit"),
        ("neighbour-authority-answers-beside-a-bound-run", _DWKP, "authority-route"),
        (
            "neighbour-environment-judged-clean-beside-a-bound-run",
            _DWKP,
            "authority-environment-judgement",
        ),
        ("neighbour-process-exec-completed-beside-a-bound-run", _DWKP, "authority-ledger"),
        ("neighbour-environments-kept-ready", _DWKP, "authority-environment-decision"),
    ),
    # M5d.3: the authority's pipeline against the fake broker, real values in
    # the kernel keyring -- what it decides, records and refuses, never
    # delivery.
    "authority-workload-secret": (
        ("read-once-after-both-intents", _FAKE, "authority-ledger-intent-first"),
        ("kernel-chooses-c-before-b", _FAKE, "authority-plan"),
        ("preview-reads-nothing", _FAKE, "authority-plan"),
        ("intent-linked-recorded-counted", _FAKE, "authority-ledger"),
        ("no-plaintext-in-kernel-db-or-audit", _FAKE, "secret-not-persisted"),
        ("replay-never-hands-over-again", _FAKE, "authority-idempotency"),
        ("ordinary-launch-unchanged", _FAKE, "authority-route"),
        ("v5-cannot-name-a-credential", _FAKE, "dwkp-schema"),
        ("refused-*", _FAKE, "secret-metadata"),
        ("stored-grant-*", _FAKE, "secret-metadata"),
        ("not-granted-denied", _FAKE, "authority-capability"),
        ("no-refusal-reaches-the-broker", _FAKE, "authority-gates"),
        ("default-deny", _FAKE, "authority-policy"),
        ("host-rule-is-no-sandbox-rule", _FAKE, "authority-policy"),
        ("approval-required", _FAKE, "authority-policy"),
        ("obligation-unenforceable", _FAKE, "authority-obligation"),
        ("failed-backend-missing", _FAKE, "secret-backend"),
        ("failed-nul-in-a-variable", _FAKE, "secret-value-validation"),
        ("broker-refusal-failed", _FAKE, "authority-ledger"),
        ("unknown-start-unknown-use", _FAKE, "authority-ledger"),
        ("missing-redaction-count-unknown", _FAKE, "authority-ledger"),
        ("crash-*", _FAKE, "authority-reconciliation"),
        ("no-host-fallback", _FAKE, "authority-environment-decision"),
    ),
    # M5d.3: a synthetic credential in the broker's real environment.
    "sandbox-secret": (
        ("fd-at-spawn-residue-clean", _OCI, "residue-measurement"),
        ("*-inherited-by-a-descendant", _OCI, "residual-inherited-by-descendants"),
        ("*-with-hygiene", _OCI, "hygiene-launcher"),
        ("*-not-in-inspect-logs-events-argv", _OCI, "secret-stdin-handoff"),
        ("fd-at-spawn-*", _OCI, "trusted-launcher"),
        ("env-at-spawn-*", _OCI, "trusted-launcher"),
        ("launcher-*", _OCI, "trusted-launcher"),
        ("broker-log-names-the-mode-only", _OCI, "broker-log-discipline"),
        ("redacted-across-reads-*", _OCI, "output-redaction"),
        ("refused-*", _OCI, "broker-secret-admission"),
        ("value-unread-when-the-judgement-refuses", _OCI, "broker-secret-admission"),
        ("collected-only-under-its-generation", _OCI, "workload-generation"),
        ("an-ordinary-workload-is-unchanged", _OCI, "broker-launch"),
        ("crash-after-read-nothing-ran", _OCI, "broker-judgement-before-exec"),
    ),
    # M5d.3 over a real DWKP client; its crash windows through the
    # authority's own dispatch.
    "sandbox-authority-secret": (
        ("public-plan-states-both-actions", _DWKP, "authority-plan"),
        ("public-preview-reads-nothing", _DWKP, "authority-plan"),
        ("public-*-at-spawn-delivered", _DWKP, "trusted-launcher"),
        ("public-echo-redacted", _DWKP, "output-redaction"),
        ("public-no-plaintext-durable-or-logged", _DWKP, "secret-not-persisted"),
        ("public-never-on-the-host", _DWKP, "authority-environment-decision"),
        ("public-replay-refused", _DWKP, "authority-idempotency"),
        ("public-ungranted-handle-denied", _DWKP, "authority-capability"),
        ("public-unconfigured-handle-refused", _DWKP, "secret-metadata"),
        ("public-ordinary-launch-unchanged", _DWKP, "authority-route"),
        ("public-hostile-credential-frames-refused", _DWKP, "dwkp-schema"),
        ("crash-*", _OCI, "authority-reconciliation"),
        ("shipped-*", _DWKP, "authority-policy"),
        ("production-serve-delivers-from-the-operators-files", _DWKP, "secret-backend"),
        ("production-crash-mid-workload-unknown-destroyed", _DWKP, "authority-reconciliation"),
        ("production-replay-after-restart-refused", _DWKP, "authority-idempotency"),
        ("production-no-plaintext-durable", _DWKP, "secret-not-persisted"),
    ),
    # M5d.4 in process: the broker's exchange code and a real full tmpfs of
    # its own; the authority against the fake broker.
    "broker-exchange": (
        ("broker-group-convention-refused", _IN, "broker-workspace-convention"),
        ("broker-full-filesystem-*", _IN, "filesystem-quota"),
    ),
    "authority-route": (
        ("authority-workspace-drift-answered-not-clean", _FAKE, "authority-environment-judgement"),
        ("authority-unbounded-workspace-refused", _FAKE, "authority-workspace-contract"),
        ("authority-refused-before-the-broker", _FAKE, "authority-workspace-contract"),
        ("authority-unverified-workspace-said", _FAKE, "authority-workspace-contract"),
        ("authority-replaced-workspace-destroys", _FAKE, "authority-workspace-contract"),
        ("authority-*", _FAKE, "authority-workspace-exclusion"),
    ),
    # M5d.4 on a real runtime: the broker judging the probe's facts against
    # the bound it was sent; what only a provisioned host runs is its own
    # level, never the level of a case that ran here.
    "sandbox-workspace": (
        ("broker-unverified-workspace-refused-without-the-flag", _OCI, "broker-admission"),
        ("broker-bounded-*-accepted", _PRIV, "workspace-contract-measured"),
        ("broker-capacity-drift-refused-before-work", _PRIV, "measured-before-work"),
        ("broker-*", _OCI, "workspace-contract-measured"),
    ),
    "sandbox-authority-workspace": (
        (
            "authority-unprovisioned-workspace-refused-before-the-broker",
            _OCI,
            "authority-workspace-contract",
        ),
        ("authority-unprovisioned-workspace-runs-nothing", _OCI, "authority-environment-decision"),
        ("production-serve-unprovisioned-workspace-refused", _DWKP, "authority-workspace-contract"),
        ("umask-0007-through-the-direct-launcher", _OCI, "direct-launcher"),
        ("workspace-tmp-var-tmp-distinct", _OCI, "mount-namespace"),
        ("exclusion-*", _DWKP, "authority-workspace-exclusion"),
        ("bounded-*-accepted", _PRIV, "workspace-contract-measured"),
        ("host-and-container-identity-agree", _PRIV, "workspace-contract-measured"),
        ("subdirectory-of-a-bounded-filesystem-refused", _PRIV, "workspace-contract-measured"),
        ("production-serve-bounded-workspace", _PRIV, "workspace-contract-measured"),
        ("workload-makes-broker-reads", _PRIV, "workspace-group-10001"),
        ("broker-makes-workload-modifies", _PRIV, "workspace-group-10001"),
        ("broker-replaces-workload-reads", _PRIV, "workspace-group-10001"),
        ("another-identity-cannot-write-or-read", _PRIV, "workspace-root-2770"),
        ("wrong-gid-refused", _PRIV, "authority-workspace-contract"),
        ("missing-setgid-refused", _PRIV, "authority-workspace-contract"),
        ("group-only-mode-world-readable-refused", _PRIV, "authority-workspace-contract"),
        ("world-writable-root-refused", _PRIV, "authority-workspace-contract"),
        ("workload-owned-root-refused", _PRIV, "authority-workspace-contract"),
        ("foreign-owned-root-refused", _PRIV, "authority-workspace-contract"),
        ("quota-mismatch-refused", _PRIV, "authority-workspace-contract"),
        ("unbounded-host-directory-refused", _PRIV, "authority-workspace-contract"),
        ("*-destroys-before-the-workload", _PRIV, "authority-workspace-contract"),
        ("workload-fills-to-enospc", _PRIV, "filesystem-quota"),
        ("full-workspace-write-fails-unchanged", _PRIV, "filesystem-quota"),
        ("other-workspace-unaffected", _PRIV, "filesystem-quota"),
        ("space-recovered-after-removal", _PRIV, "filesystem-quota"),
        ("durability-valid-after-a-full-workspace", _PRIV, "authority-ledger"),
    ),
    # M5e.2 in process (R2, R3): the broker's host judgement and decision,
    # one nonconforming record at a time -- never an environment's.
    "broker-assurance": (
        ("*-conforming-kept", _IN, "measured-host"),
        ("*-weakened-*-refused", _IN, "measured-host"),
    ),
    # M5e.2 on a real runtime (R9): one run's environment beside another.
    "sandbox-closure": (
        ("cross-run-processes-not-visible", _OCI, "pid-namespace"),
        ("cross-run-other-environment-refused", _OCI, "exact-label-ownership"),
        ("cross-run-destroy-spares-the-other", _OCI, "exact-label-cleanup"),
        (
            "cross-run-next-environment-holds-nothing-of-the-last",
            _OCI,
            "fresh-container-per-environment",
        ),
        # R8 (ADR-0056): the neighbour's own cgroup bounds it; the backstop
        # leaves another environment measured and served; the broker answers;
        # each destroyed by its own labels -- beside one environment at its
        # bound, and (hosted) beside every other the authority allows.
        ("*-at-their-own-bound", _OCI, "cgroup-limit"),
        ("neighbour-holds-its-own-task-bound", _OCI, "cgroup-limit"),
        ("*-measured-clean*", _OCI, "measured-both"),
        ("neighbour-workload-served-*", _OCI, "rlimit"),
        ("capacity-last-workload-served", _OCI, "rlimit"),
        ("neighbour-broker-answers-*", _OCI, "broker-start-collect"),
        ("*-destroyed-exactly", _OCI, "exact-label-cleanup"),
    ),
    # M5e.2 hosted (R11, OD-E8): the runtime restarted under a running
    # authority -- the runner's root restarts it, so every line is privileged.
    "sandbox-restart": (
        ("restart-in-flight-not-believed", _PRIV, "authority-ledger"),
        ("restart-reconciled-within-bound", _PRIV, "authority-reconciliation"),
        ("restart-interrupted-environment-not-believed", _PRIV, "authority-reconciliation"),
        ("restart-idle-environment-reconciled", _PRIV, "authority-reconciliation"),
        ("restart-in-flight-never-rerun", _PRIV, "authority-idempotency"),
        ("restart-foreign-untouched", _PRIV, "exact-label-ownership"),
        ("restart-new-workload-served", _PRIV, "authority-ledger"),
    ),
    # M5e.2 (R3's E6; ADR-0057, the owner's R-B; ADR-0058): a hard rule
    # weakened in a real PROXY_ONLY environment the released broker prepared,
    # caught by its measurement from the vantage(s) ADR-0057 §1a names and
    # refused by its production decision; the conforming control kept. One
    # vantage alone catches three of the rows; both, the rest. Hosted only.
    E6_SUITE: (
        (E6_CONTROL, _OCI, "measured-both"),
        ("e6-weakened-host-ipc-refused", _OCI, "measured-host"),
        ("e6-weakened-host-uts-refused", _OCI, "measured-host"),
        ("e6-weakened-mutable-image-tag-refused", _OCI, "measured-host"),
        ("e6-weakened-*-refused", _OCI, "measured-both"),
        (E6_COUNT, _OCI, "measured-both"),
    ),
    # M5e.4 (plan §6): pip as it is today against the fixture registries, and
    # npm refused before anything is prepared -- a real DWKP client on the
    # released `serve`, the released broker, the runner's runtime; hosted only.
    "sandbox-registry": (
        ("registry-tools-pinned-in-the-environment", _DWKP, "executable-digest-pin"),
        ("registry-pip-granted-index-installs", _DWKP, "relay-and-connect-proxy-grant"),
        ("registry-pip-dependency-from-granted-index", _DWKP, "relay-and-connect-proxy-grant"),
        ("registry-pip-ungranted-index-refused", _DWKP, "connect-proxy:grant"),
        (
            "registry-pip-ungranted-index-installs-when-granted",
            _DWKP,
            "relay-and-connect-proxy-grant",
        ),
        ("registry-pip-file-on-ungranted-host-refused", _DWKP, "connect-proxy:grant"),
        ("registry-pip-redirect-to-ungranted-host-refused", _DWKP, "connect-proxy:grant"),
        ("registry-pip-direct-route-refused", _DWKP, "topology-no-route"),
        ("registry-pip-direct-by-name-unresolved", _DWKP, "topology-no-resolver"),
        ("registry-pip-untrusted-issuer-refused", _DWKP, "workload-tls-verification"),
        ("registry-pip-sdist-built-today", _DWKP, "residual-contained-by-the-environment"),
        ("registry-pip-pth-not-run-by-install", _DWKP, "workload-effects-measured"),
        ("registry-pip-pth-runs-at-a-later-start", _DWKP, "residual-contained-by-the-environment"),
        ("registry-intent-names-only-the-granted-registry", _DWKP, "authority-audit"),
        ("registry-egress-counted-at-destruction", _DWKP, "authority-audit-at-destruction"),
        ("registry-census-clean", _DWKP, "exact-label-cleanup"),
        ("registry-npm-*-refused-before-preparation", _DWKP, "authority-obligation"),
        ("registry-npm-nothing-prepared-or-reached", _DWKP, "authority-environment-decision"),
    ),
    # M5e.5 (ADR-0054 §8, ADR-0055 §9): npm and pip under their proposed
    # profiles, kept only under the evidence-only option; hosted only.
    "sandbox-hygiene": (
        ("*-granted-registry-installs", _DWKP, "relay-and-connect-proxy-grant"),
        ("pip-install-*-installs", _DWKP, "relay-and-connect-proxy-grant"),
        (
            "pip-install-dependency-resolved-from-granted-index",
            _DWKP,
            "relay-and-connect-proxy-grant",
        ),
        ("*-ungranted-*-refused", _DWKP, "connect-proxy:grant"),
        ("*-direct-route-refused", _DWKP, "topology-no-route"),
        ("npm-lifecycle-scripts-not-run", _DWKP, "hygiene-launcher"),
        ("npm-project-npmrc-cannot-reenable-scripts", _DWKP, "hygiene-launcher"),
        ("npm-project-npmrc-cannot-replace-ca", _DWKP, "hygiene-launcher"),
        ("npm-project-npmrc-cannot-disable-tls", _DWKP, "workload-tls-verification"),
        # npm ignores a missing `cafile`: the launcher refuses the launch.
        ("npm-missing-trust-file-fails-closed", _DWKP, "hygiene-launcher"),
        ("pip-missing-trust-file-fails-closed", _DWKP, "workload-tls-verification"),
        ("*-untrusted-issuer-refused", _DWKP, "workload-tls-verification"),
        ("pip-os-trust-store-not-used", _DWKP, "workload-tls-verification"),
        ("npm-git-dependency-not-prepared", _DWKP, "workload-effects-measured"),
        ("npm-tampered-tarball-refused", _DWKP, "workload-integrity-verification"),
        ("*-writes-only-workspace-and-tmp", _DWKP, "read-only-root"),
        ("*-undoing-arguments-refused", _DWKP, "authority-obligation"),
        ("*-other-subcommands-refused", _DWKP, "authority-obligation"),
        ("*-non-*-specs-refused", _DWKP, "authority-obligation"),
        ("npx-still-refused", _DWKP, "authority-obligation"),
        ("*-refused-without-the-evidence-option", _DWKP, "authority-obligation"),
        ("pip-interpreter-module-refused", _DWKP, "authority-obligation"),
        ("*-shipped-packs-behaviour", _DWKP, "authority-policy"),
        ("*-plan-records-prefix-and-profile", _DWKP, "authority-ledger"),
        ("pip-sdist-never-built", _DWKP, "hygiene-launcher"),
        ("pip-only-binary-cannot-be-undone-by-variable-or-file", _DWKP, "hygiene-launcher"),
        ("pip-image-configuration-not-read", _DWKP, "hygiene-launcher"),
        ("pip-no-cache-reused", _DWKP, "hygiene-launcher"),
        ("pip-installed-pth-not-executed-by-install", _DWKP, "workload-effects-measured"),
    ),
}
# Every case any of the six tasks requires: a line naming another case of
# their suites is a case the inventory lost, or one renamed.
ATTRIBUTED_CASES = frozenset(
    (
        *BROKER_ASSURANCE_CASES,
        *CAPTURED_ASSURANCE_CASES,
        *SANDBOX_CASES,
        *EGRESS_CASES,
        *WORKLOAD_CASES,
        *SECRET_SANDBOX_UNIT_CASES,
        *SECRET_SANDBOX_CASES,
        *WORKSPACE_UNIT_CASES,
        *WORKSPACE_CASES,
        *WORKSPACE_PRIVILEGED_CASES,
        *RESTART_CASES,
        *CAPACITY_CASES,
        *E6_CASES,
        *REGISTRY_CASES,
        *HYGIENE_CASES,
    )
)
# The foundation's latency: its numbers, not containment.
TELEMETRY_FIELDS = (
    "rounds",
    "prepare_ms_median",
    "prepare_ms_p95",
    "measure_ms_median",
    "measure_ms_p95",
    "destroy_ms_median",
    "destroy_ms_p95",
)


def attribution(suite: str, case: str) -> tuple[str, frozenset[str]] | None:
    """The level a case's line must say and the mechanisms it may name, by
    the first rule of its suite that names it; `None` when none does."""
    for pattern, level, mechanisms in ATTRIBUTION.get(suite, ()):
        if fnmatch.fnmatchcase(case, pattern):
            named = (mechanisms,) if isinstance(mechanisms, str) else mechanisms
            return level, frozenset(named)
    return None


# What a line says it showed, held to the account its level and vantage give
# (R17; ADR-0057, the owner's R-B): the production decision's refusal named by
# the invariants that failed, and each detection by the invariants that were
# measured -- so no line reports a weakening kept, a detection with nothing
# named, or a vantage its invariants were not measured from.
ASSURANCE_KEPT = "every-required-invariant-pass-kept"
_INVARIANT = re.compile(r"(?:HOST|CONTAINER)_[A-Z0-9]+(?:_[A-Z0-9]+)*")
# Which vantage measured a set of invariants: (any the host's, any inside).
_VANTAGE = {
    (True, False): "measured-host",
    (False, True): "measured-inside",
    (True, True): "measured-both",
}
# The real-runtime suites whose `weakened-*` cases each name what caught them.
DETECTION_SUITES = frozenset(("sandbox-broker", "sandbox-egress"))


def _named_invariants(text: str) -> list[str] | None:
    """The `+`-joined invariants `text` names; `None` unless each is one."""
    named = text.split("+")
    return named if all(_INVARIANT.fullmatch(name) for name in named) else None


def outcome_problem(suite: str, case: str, outcome: str, enforcement: object) -> str | None:
    """Why `outcome` does not show what its line claims, or `None`.

    The in-process judgement (`broker-assurance`, R2 and R3): a conforming
    record says it was kept; every other says `refused:` and the invariants
    that failed, each of them the host's -- a judgement of the runtime's
    record never names what only the probe inside measures. A real runtime's
    weakened profile or topology says `detected:` and what caught it; and a
    detection's invariants are of the vantage its enforcement claims. A
    registry line (M5e.4) begins with what its case must show
    (`REGISTRY_OUTCOMES`): an install, what it installed; a refusal, that
    nothing was installed; a source distribution's build, that it ran today.
    """
    if suite == E6_SUITE:
        return e6_outcome_problem(case, outcome, enforcement)
    if suite == HYGIENE_SUITE:
        shows = HYGIENE_OUTCOMES.get(case)
        if shows is None:
            return "a hygiene case with no outcome it must show"
        if not outcome.startswith(shows):
            return f"its outcome must begin {shows!r}, not {outcome!r}"
        return None
    if suite == REGISTRY_SUITE:
        shows = REGISTRY_OUTCOMES.get(case)
        if shows is None:
            return "a registry case with no outcome it must show"
        if not outcome.startswith(shows):
            return f"its outcome must begin {shows!r}, not {outcome!r}"
        return None
    if suite == "broker-assurance":
        if case.endswith("-kept"):
            if outcome != ASSURANCE_KEPT:
                return f"a conforming record's line must say {ASSURANCE_KEPT!r}, not {outcome!r}"
            return None
        named = (
            _named_invariants(outcome.removeprefix("refused:"))
            if outcome.startswith("refused:")
            else None
        )
        if named is None:
            return (
                f"the production decision's refusal is not shown: {outcome!r} must be "
                "`refused:` and the invariants that failed"
            )
        inside = [name for name in named if not name.startswith("HOST_")]
        if inside:
            return (
                "a judgement of the runtime's record names the inside vantage, which it "
                f"never measures: {'+'.join(inside)}"
            )
        return None
    detection = outcome.startswith("detected:")
    if (
        suite in DETECTION_SUITES
        and case.startswith("weakened-")
        and not case.endswith("-count")
        and not detection
    ):
        return f"a weakening's line must say `detected:` and what caught it, not {outcome!r}"
    if detection and enforcement in _VANTAGE.values():
        named = _named_invariants(outcome.removeprefix("detected:").split(";", 1)[0])
        if named is None:
            return f"a detection that names no invariant: {outcome!r}"
        measured = _VANTAGE[
            (
                any(name.startswith("HOST_") for name in named),
                any(name.startswith("CONTAINER_") for name in named),
            )
        ]
        if measured != enforcement:
            return f"its invariants were {measured}, not {enforcement}"
    return None


def require_attributed_evidence(
    output: str,
    cases: tuple[tuple[str, str], ...],
    prefix: str = SANDBOX_EVIDENCE_PREFIX,
) -> list[dict[str, object]]:
    """Every (suite, case) reported once, exercised, at its level and
    attributed to what enforced or observed it (M5e.1, OD-E1).

    A line fails the task, its suite and case named, when its JSON is
    unreadable; it has no suite or case; its suite is not one `cases` names,
    or its case is in no task's inventory; it is reported twice (a duplicate
    never stands in for a missing case); it has no outcome; its level or
    enforcement is missing, outside the vocabulary or not the one
    `ATTRIBUTION` gives the case -- a fake broker's line offered as a
    container's, an unprivileged case's as a provisioned host's, a mechanism
    the case does not exercise; its outcome does not show what it claims
    (`outcome_problem`: a weakening kept or never refused, a detection naming
    no invariant, a vantage its invariants were not measured from); or it is
    telemetry without its numbers. A required case that says NOT EXERCISED,
    or never reports, fails as NOT EXERCISED; and zero required cases fail
    too.
    """
    if not cases:
        raise TaskError("attributed evidence: zero cases required")
    suites = {suite for suite, _ in cases}
    required = set(cases)
    seen: dict[tuple[str, str], dict[str, object]] = {}
    unexercised: list[str] = []
    problems: list[str] = []
    for line in output.splitlines():
        at = line.find(prefix)
        if at < 0:
            continue
        try:
            record = json.loads(line[at + len(prefix) :])
        except json.JSONDecodeError as exc:
            raise TaskError(f"unreadable evidence line: {line[:200]}") from exc
        if not isinstance(record, dict):
            raise TaskError(f"malformed evidence line: {line[:200]}")
        suite, case = record.get("suite"), record.get("case")
        if not (isinstance(suite, str) and suite and isinstance(case, str) and case):
            raise TaskError(f"evidence without its suite or case: {line[:200]}")
        named = f"{suite}/{case}"
        if suite not in suites:
            problems.append(f"{named}: a suite this task does not run")
            continue
        if (suite, case) not in ATTRIBUTED_CASES:
            problems.append(f"{named}: a case no task requires -- renamed, or never listed")
            continue
        if (suite, case) in seen:
            problems.append(f"{named}: reported twice")
            continue
        seen[(suite, case)] = record
        outcome = record.get("outcome")
        if not isinstance(outcome, str) or not outcome:
            problems.append(f"{named}: no outcome")
            continue
        if outcome.lower().replace(" ", "-").startswith("not-exercised"):
            if (suite, case) in required:
                unexercised.append(named)
            continue
        contract = attribution(suite, case)
        if contract is None:
            problems.append(f"{named}: no attribution in the contract")
            continue
        level, mechanisms = contract
        said, enforcement = record.get("level"), record.get("enforcement")
        if said != level:
            problems.append(f"{named}: at level {said!r}, which must be {level!r}")
        if not isinstance(enforcement, str) or not enforcement:
            problems.append(f"{named}: names no enforcement")
        elif enforcement not in ATTRIBUTION_MECHANISMS:
            problems.append(f"{named}: enforcement {enforcement!r} is no known mechanism")
        elif enforcement not in mechanisms:
            problems.append(
                f"{named}: enforcement {enforcement!r} is not what this case exercises "
                f"({', '.join(sorted(mechanisms))})"
            )
        shown = outcome_problem(suite, case, outcome, enforcement)
        if shown is not None:
            problems.append(f"{named}: {shown}")
        numbers = [record.get(field) for field in TELEMETRY_FIELDS]
        if "telemetry" in mechanisms and (
            outcome != "measured"
            or not all(isinstance(n, int) and not isinstance(n, bool) and n >= 0 for n in numbers)
        ):
            problems.append(f"{named}: telemetry must say `measured` and carry its numbers")
    if problems:
        raise TaskError(
            f"{len(problems)} evidence line(s) not attributed as the contract says: "
            + "; ".join(problems[:20])
        )
    missing = sorted(f"{suite}/{case}" for suite, case in required if (suite, case) not in seen)
    if unexercised or missing:
        raise TaskError(
            f"NOT EXERCISED: {len(unexercised) + len(missing)} required case(s): "
            + ", ".join([*unexercised, *missing][:40])
        )
    levels: dict[str, int] = {}
    for suite, case in cases:
        level = str(seen[(suite, case)]["level"])
        levels[level] = levels.get(level, 0) + 1
    print(
        f"{GREEN}attributed evidence: {len(cases)} cases reported, each at its level with its "
        "enforcement ("
        + ", ".join(f"{level} {count}" for level, count in sorted(levels.items()))
        + f"){OFF}"
    )
    # Judged and passed: kept for the M5 gate (`save_judged_evidence`).
    keep_judged("attributed", cases, prefix, output)
    return [seen[key] for key in cases]


# --- M5d.5: the agent-shaped workload and three identities (ADR-0052 §§11, 13, 17) ---

# The one-identity suite: any Linux host with a runtime runs it.
AGENT_TESTS = (
    "linux::an_agent_runs_through_the_production_route_and_reaches_only_its_origin",
    "linux::budgets_and_the_wall_clock_bound_an_agent",
    "linux::an_agent_that_outlives_its_daemons_is_destroyed_and_never_run_again",
)
# The three-identity suite: only a disposable host that provisions three
# users, the workspace group and a bounded workspace runs it
# (`DW_AGENT_PRIVILEGED=1`, the hosted `sandbox-agent` job).
AGENT_IDENTITY_TESTS = (
    "linux::three_identities_run_an_agent_and_none_reaches_anothers_state",
    "linux::three_identities_a_broker_refuses_a_sandbox_identity_at_start",
)

# Every (suite, case) the one-identity suite must report, exercised. The
# handoff's matrix (docs/M5D5_IMPLEMENTATION_HANDOFF.md §5) is the prefix:
# A01-A12, and `audit-*` for what the audit records.
AGENT_CASES = tuple(
    ("sandbox-agent", case)
    for case in (
        "a01-production-route-dwkp-to-measured-proxy-only-sandbox",
        "a01-no-host-fallback",
        "a02-agent-plan-workers-and-helper",
        "a02-agent-processes-within-the-environment",
        "a02-agent-identity-measured-from-the-host",
        "a03-relay-identity-measured-from-the-host",
        "a03-https-granted-origin-stock-client",
        "a03-https-granted-origin-tls-verified",
        "a04-agent-ungranted-origin-refused",
        "a04-origin-host-not-granted",
        "a04-origin-port-not-granted",
        "a04-granted-name-blocked-by-the-address-guard",
        "a05-connect-absolute-form-refused",
        "a05-connect-address-literal-refused",
        "a05-connect-host-not-canonical-refused",
        "a05-connect-another-method-refused",
        "a05-connect-smuggled-body-refused",
        "a05-connect-host-header-disagrees-refused",
        "a05-tls-sni-mismatch-closed",
        "a05-tls-sni-missing-closed",
        "a05-tls-certificate-for-another-name-refused-by-the-client",
        "a05-tls-untrusted-issuer-refused-by-the-client",
        "a06-agent-direct-tcp-no-route",
        "a06-agent-direct-udp-no-route",
        "a06-direct-tcp-public-no-route",
        "a06-direct-udp-public-no-route",
        "a06-direct-tcp-bridge-gateway-no-route",
        "a06-host-loopback-origin-is-not-the-environments",
        "a06-direct-dns-no-route",
        "a06-no-resolver-answers",
        "a06-raw-and-packet-sockets-refused",
        "a07-proxy-variables-name-only-the-relay",
        "a07-proxy-variable-redirected-to-another-host",
        "a07-proxy-variable-redirected-to-another-port",
        "a07-proxy-variables-removed",
        "a08-tunnel-limit",
        "a08-upload-budget",
        "a08-download-budget",
        "a08-wall-clock-ends-the-agent",
        "a08-workload-budget-refused",
        "a10-writes-outside-the-workspace-refused",
        "a10-no-runtime-socket-or-daemon-state-in-the-environment",
        "a11-descendants-reaped",
        "a11-census-empty-after-the-invocation",
        "a12-timeout-reaped-environment-kept-clean",
        "a12-broker-lost-outcome-unknown-environment-destroyed",
        "a12-authority-crash-unknown-environment-destroyed",
        "a12-uncertain-agent-never-replayed",
        "audit-environment-intent-names-the-grant",
        "audit-egress-counted-by-disposition-not-per-attempt",
    )
)
# Every (suite, case) the three-identity suite must report: I01-I08, A09,
# and A03 again as three users.
AGENT_IDENTITY_CASES = tuple(
    ("sandbox-agent-identity", case)
    for case in (
        "i01-three-distinct-host-identities",
        "i01-workload-runs-as-10001",
        "i01-relay-runs-as-10002",
        "i02-configured-runtime-admitted",
        "i02-authority-own-uid-refused",
        "i02-broker-uid-refused",
        "i02-another-uid-refused",
        "i03-runtime-cannot-use-the-broker-channel",
        "i04-runtime-cannot-read-or-change-authority-state",
        "i04-runtime-cannot-read-policy-operator-file-or-secret",
        "i05-runtime-cannot-reach-the-oci-socket",
        "i05-workload-cannot-reach-the-oci-socket",
        "i06-broker-start-up-posture-production",
        "i06-broker-refuses-a-workload-authority",
        "i06-broker-refuses-a-relay-authority",
        "i06-runtime-cannot-inspect-a-daemon",
        "i06-workload-is-not-the-brokers-identity",
        "i07-workspace-group-membership",
        "i07-workspace-root-contract-measured",
        "i07-runtime-excluded-from-the-workspace",
        "i08-authority-crash-unknown-environment-destroyed",
        "i08-broker-crash-unknown-environment-destroyed",
        "i08-never-replayed",
        "a03-https-granted-origin-three-identities",
        "a09-agent-and-broker-share-the-bounded-workspace",
    )
)
# What each line of agent evidence must say it is (the handoff's §5): never
# a unit decision called hosted proof, never a logged denial called an audit.
AGENT_EVIDENCE_LEVELS = frozenset(
    ("dwkp-end-to-end", "measured-oci", "real-process-refusal", "hosted-three-identity")
)


def agent_privileged() -> bool:
    """Whether this run may provision three users' worth of host: never
    inferred, only `DW_AGENT_PRIVILEGED=1` (the hosted `sandbox-agent` job,
    a disposable runner) says so."""
    return os.environ.get("DW_AGENT_PRIVILEGED", "").strip() == "1"


def _agent_workspace_base() -> Path:
    """Where the provisioned workspaces are mounted: somewhere the broker's
    own user can traverse, which the runner's home is not promised to be."""
    # A name under the shared temporary directory, made 0755 by this user and
    # removed after (`_provision_workspaces`): the broker's user must reach it.
    default = f"/tmp/dw-m5d5-{os.getuid()}"  # noqa: S108 - see above
    return Path(os.environ.get("DW_AGENT_WORKSPACE_BASE", default))


def _agent_setup() -> tuple[Path, str, dict[str, str], set[str], list[str]]:
    """M5d.5's setup, separate from the evidence: a trusted runtime client;
    the probe, the fixture and the relay built statically and proved static
    from their ELF headers, their digests pinned; the agent image -- M5d.2's
    tools image (the host's Python and its standard library, `_ssl`'s shared
    objects included) with the pinned relay added -- built offline `FROM
    scratch` and named by content. No new dependency, nothing pulled.
    Returns the client, the socket, the variables the suite reads, the
    containers that predate the evidence, and the images to remove."""
    if not sys.platform.startswith("linux"):
        raise TaskError("NOT EXERCISED: the agent evidence needs Linux and an OCI runtime")
    found = shutil.which("docker")
    if found is None:
        raise TaskError("NOT EXERCISED: no container runtime client (`docker`) on PATH")
    socket = os.environ.get("DW_SANDBOX_SOCKET", "/var/run/docker.sock")
    target_root = Path(os.environ.get("CARGO_TARGET_DIR", str(ROOT / "target")))
    work = Path(os.environ.get("DW_AGENT_WORK", str(Path.home() / ".cache" / "dw-m5d5")))
    shutil.rmtree(work, ignore_errors=True)
    work.mkdir(mode=0o700, parents=True)
    client, chosen = _trusted_client(Path(found), work / "client")
    try:
        server = json.loads(
            _docker(client, socket, "version", "--format", "{{json .Server}}").strip()
        )
    except (TaskError, json.JSONDecodeError) as exc:
        raise TaskError(f"NOT EXERCISED: the runtime at {socket} does not answer: {exc}") from exc
    if server.get("Os") != "linux":
        raise TaskError(f"NOT EXERCISED: the runtime is not a Linux one: {server.get('Os')}")
    arch = {"amd64": "x86_64", "arm64": "aarch64"}.get(str(server.get("Arch")))
    if arch is None:
        raise TaskError(f"the runtime's architecture {server.get('Arch')!r} is not supported")
    triple = f"{arch}-unknown-linux-gnu"
    platform_ = f"linux/{server.get('Arch')}"
    before = set(
        _docker(client, socket, "container", "ls", "--all", "--no-trunc", "--quiet").split()
    )
    static = target_root / "sandbox-static"
    env = dict(os.environ, RUSTFLAGS="-C target-feature=+crt-static")
    command = [
        "cargo",
        "build",
        "--locked",
        "--release",
        "-p",
        "dwk-sandbox-probe",
        "--bin",
        "dwk-sandbox-probe",
        "--example",
        "sandbox_fixture",
        "-p",
        "dwk-sandbox-relay",
        "--bin",
        "dwk-sandbox-relay",
        "--target",
        triple,
        "--target-dir",
        str(static),
    ]
    print(f"{DIM}$ RUSTFLAGS='-C target-feature=+crt-static' {' '.join(command)}{OFF}", flush=True)
    if subprocess.run(command, cwd=str(ROOT), env=env, check=False).returncode != 0:
        raise TaskError("the static probe, relay and fixture did not build")
    release = static / triple / "release"
    probe = release / "dwk-sandbox-probe"
    relay = release / "dwk-sandbox-relay"
    fixture = release / "examples" / "sandbox_fixture"
    linking = {
        name: _static_elf(path)
        for name, path in (("probe", probe), ("relay", relay), ("fixture", fixture))
    }
    image, tools = _tools_image(
        client, socket, work / "images" / "agent", (probe, fixture), platform_, relay
    )
    digests = {
        name: hashlib.sha256(path.read_bytes()).hexdigest()
        for name, path in (("probe", probe), ("relay", relay), ("fixture", fixture))
    }
    print(f"{BOLD}agent evidence setup{OFF}")
    print(
        f"  runtime            {server.get('Version')} (api {server.get('ApiVersion')}), "
        f"{platform_}"
    )
    print(f"  runtime client     {chosen}")
    for name in ("probe", "relay", "fixture"):
        print(f"  {name:<18} {linking[name]}, sha256 {digests[name]}")
    print(f"  agent image        {image} (probe, relay, fixture, {tools['DW_SANDBOX_PYTHON']})")
    variables = {
        "DW_SANDBOX_RUNTIME": str(client),
        "DW_SANDBOX_SOCKET": socket,
        "DW_AGENT_IMAGE": image,
        "DW_SANDBOX_PROBE_SHA256": digests["probe"],
        "DW_EGRESS_RELAY_SHA256": digests["relay"],
        "DW_SANDBOX_FIXTURE_SHA256": digests["fixture"],
        "DW_SANDBOX_PYTHON": tools["DW_SANDBOX_PYTHON"],
        "DW_SANDBOX_PYTHON_SHA256": tools["DW_SANDBOX_PYTHON_SHA256"],
    }
    return client, socket, variables, before, [image]


def require_agent_evidence(output: str, cases: tuple[tuple[str, str], ...]) -> None:
    """Every case reported, exercised (`require_sandbox_evidence`), and each
    line saying what kind of evidence it is and what enforced it."""
    for record in require_sandbox_evidence(output, cases):
        if (str(record["suite"]), str(record.get("case"))) not in cases:
            continue
        if record.get("level") not in AGENT_EVIDENCE_LEVELS or not record.get("enforcement"):
            raise TaskError(f"agent evidence without its level or enforcement: {record}")
    # Judged and passed: kept for the M5 gate, by its own verdict (G-Q1).
    keep_judged("agent", cases, SANDBOX_EVIDENCE_PREFIX, output)


def _agent_suite(tests: tuple[str, ...]) -> str:
    """Run `tests` of `sandbox_agent` by name, each required to pass."""
    output = run_captured(
        "cargo",
        "test",
        "--locked",
        "-p",
        "dwkd-authority",
        "--test",
        "sandbox_agent",
        "--",
        "--ignored",
        "--exact",
        "--nocapture",
        "--test-threads=1",
        *tests,
    )
    summaries = [line for line in output.splitlines() if line.startswith("test result: ")]
    expected = f"test result: ok. {len(tests)} passed; 0 failed; 0 ignored"
    if len(summaries) != 1 or not summaries[0].startswith(expected):
        raise TaskError(
            f"the sandbox_agent suite did not run all of its tests: expected `{expected}`, "
            f"got {summaries or 'no summary'}"
        )
    return output


def _socket_dirs_left() -> list[str]:
    """The broker socket directories a separated broker made under /tmp and
    a test did not remove (`dwa-*`, `dwr-*`): what C04 must find empty."""
    tmp = Path("/tmp")  # noqa: S108 - where the suite names them, read-only here
    return sorted(
        str(p) for p in tmp.iterdir() if p.name.startswith(("dwa-", "dwr-")) and p.is_dir()
    )


def _agent_cleanup(
    client: Path,
    socket: str,
    images: list[str],
    base: Path,
    before: set[str],
    sockets_before: set[str],
) -> list[str]:
    """Undo and check what the agent evidence may have made, however far it
    got: every problem found, as text, and nothing raised -- so a failure of
    the evidence itself stays the failure reported. The checks are the
    evidence's own (C04): no workspace mount, loop device or directory under
    `base`, no container it made, every container that predates it, no
    broker socket directory a separated broker left."""
    problems: list[str] = []
    # Provisioning may never have begun (the one-identity suite failed
    # first) or may have stopped part of the way: undo what is there.
    if base.exists() or _mounted_under(base):
        try:
            _unprovision_workspaces(base)
        except (TaskError, OSError) as exc:
            problems.append(str(exc))
    try:
        listed = _docker(client, socket, "container", "ls", "--all", "--no-trunc", "--quiet")
    except TaskError as exc:
        problems.append(f"the runtime did not list its containers: {exc}")
    else:
        after = set(listed.split())
        left = sorted(after - before)
        removed = sorted(before - after)
        if left:
            problems.append(f"the evidence left {len(left)} container(s) behind: {left}")
        if removed:
            problems.append(
                f"{len(removed)} container(s) that predate the evidence are gone: {removed}"
            )
    for image in images:
        _docker(client, socket, "image", "rm", "--force", image, check=False)
    stray = sorted(set(_socket_dirs_left()) - sockets_before)
    if stray:
        problems.append(f"the evidence left broker socket directories behind: {stray}")
    return problems


def task_sandbox_agent_evidence() -> None:
    """M5d.5's evidence: `_sandbox_agent_evidence`, its three-identity half required."""
    _sandbox_agent_evidence(require_privileged=True)


def _sandbox_agent_evidence(*, require_privileged: bool) -> None:
    """M5d.5's evidence (ADR-0052 §§11, 13, 17; the M5d.5 handoff): an
    agent-shaped workload -- a plan, two workers, a daemonised helper, the
    image's Python as a stock HTTPS client verifying its origin -- run
    through the released `dwkd-authority serve --sandbox-config`, the
    released broker and a real runtime, in a measured `PROXY_ONLY`
    environment reaching exactly its granted synthetic origins through the
    real relay and CONNECT proxy; every other path refused and attributed;
    budgets, the wall clock, `reap`, crash windows and non-replay. Then, only
    where `DW_AGENT_PRIVILEGED=1` provisions it (the hosted runner): three
    host identities -- the authority as this user, the broker as
    `DW_BROKER_AS`, the runtime as `DW_PEER_AS` through a relay of its own --
    a bounded workspace of the group 10001, and every cross-identity
    boundary measured from the kernel.

    Every case must report with its level and enforcement. Without the
    three-identity half the task FAILS, NOT EXERCISED, after reporting the
    rest. No container, mount or broker socket directory the evidence made
    may remain, and every container that predates it must. Linux only.
    """
    privileged = agent_privileged()
    if privileged:
        # Fail early, before anything is built: the half that needs the
        # host is what this run exists for.
        for variable in ("DW_BROKER_AS", "DW_PEER_AS", "DW_AGENT_OUTSIDER"):
            if not os.environ.get(variable):
                raise TaskError(f"NOT EXERCISED: DW_AGENT_PRIVILEGED=1 but {variable} is unset")
    client, socket, variables, before, images = _agent_setup()
    os.environ.update(variables)
    base = _agent_workspace_base()
    sockets_before = set(_socket_dirs_left())
    outputs: list[str] = []
    try:
        run("cargo", "build", "--locked", "-p", "dwkd-broker")
        outputs.append(_agent_suite(AGENT_TESTS))
        if privileged:
            os.environ.update(_provision_workspaces(base))
            outputs.append(_agent_suite(AGENT_IDENTITY_TESTS))
    except BaseException:
        # The evidence's own failure is the one this task reports; what
        # cleaning up finds is said beside it, never instead of it.
        for problem in _agent_cleanup(client, socket, images, base, before, sockets_before):
            print(f"{RED}cleanup also failed: {problem}{OFF}", file=sys.stderr, flush=True)
        raise
    problems = _agent_cleanup(client, socket, images, base, before, sockets_before)
    if problems:
        raise TaskError("cleanup failed: " + "; ".join(problems))
    report_cleanup(
        "cleanup: no evidence container, workspace mount or broker socket directory "
        f"remains; {len(before)} pre-existing container(s) kept"
    )
    require_agent_evidence("\n".join(outputs), AGENT_CASES)
    if not privileged and not require_privileged:
        # A mutant's run: what could run here ran; the three-identity half
        # is NOT EXERCISED, and never counted as a kill.
        print(
            f"NOT EXERCISED (not counted): {len(AGENT_IDENTITY_CASES)} three-identity agent case(s)"
        )
        return
    if not privileged:
        raise TaskError(
            f"NOT EXERCISED: {len(AGENT_IDENTITY_CASES)} case(s) need three host identities, "
            "the workspace group 10001 and a bounded workspace -- which only "
            "DW_AGENT_PRIVILEGED=1 provisions, on a disposable host (the hosted `sandbox-agent` "
            "job). One uid playing three roles is not this evidence: "
            + ", ".join(f"{suite}/{case}" for suite, case in AGENT_IDENTITY_CASES)
        )
    require_agent_evidence("\n".join(outputs), AGENT_IDENTITY_CASES)
    uvrun("dwcheck", "closure", "--report")


# The mutation review (ADR-0052 §17; the M5d.5 handoff's C03): each line
# weakens one guard the agent evidence stands on -- identity, the proxy,
# policy, the workload's ending and non-replay -- in the source, one at a
# time. Each mutant must compile and must fail the guards' unit suites or the
# one-identity agent evidence; the file is then restored, and its SHA-256
# proves it byte-identical. A mutant that survives, or does not compile,
# fails the review. The three-identity half is the hosted job's: its NOT
# EXERCISED is never counted as a kill.
AGENT_MUTATIONS = (
    # Identity (ADR-0052 §13).
    (
        "the authority serves a peer it was not told to",
        "crates/dwkd-authority/src/server/config.rs",
        "        self.allowed.contains(&uid)",
        "        true || self.allowed.contains(&uid)",
    ),
    (
        "the broker reads a peer that is not the authority",
        "crates/dwkd-broker/src/listener.rs",
        "        if peer != authority_uid {",
        "        if false && peer != authority_uid {",
    ),
    (
        "a broker serves an authority with the relay's uid",
        "crates/dwkd-broker/src/posture.rs",
        '            RELAY_UID => "every relay\'s",',
        '            RELAY_UID if false => "every relay\'s",',
    ),
    # The CONNECT proxy (ADR-0048).
    (
        "the proxy dials a destination the run was not granted",
        "crates/dwkd-broker/src/egress/tunnel.rs",
        "    if !context.grant.permits(&target.host, target.port) {",
        "    if false && !context.grant.permits(&target.host, target.port) {",
    ),
    (
        "the proxy carries a tunnel whose server name is not its CONNECT host",
        "crates/dwkd-broker/src/egress/tunnel.rs",
        "            Ok(Some(_)) => return EgressDisposition::SniMismatch,",
        "            Ok(Some(_)) => break,",
    ),
    (
        "the proxy holds four times the tunnels the operator allowed",
        "crates/dwkd-broker/src/egress/tunnel.rs",
        "    let Some(_held) = Held::take(&context.tunnels, most) else {",
        "    let Some(_held) = Held::take(&context.tunnels, most.saturating_mul(4)) else {",
    ),
    # Policy and the grant (ADR-0052 §§2, 11).
    (
        "a run's plain-HTTP and TCP grants become proxy destinations",
        "crates/dwkd-authority/src/sandbox.rs",
        "        if verb.namespace() != Namespace::Network || verb.action() != Action::Https {",
        "        if verb.namespace() != Namespace::Network {",
    ),
    (
        "an agent's launch is judged as a host action",
        "crates/dwkd-authority/src/state/workload.rs",
        "CanonicalAction::new(capability, Environment::Sandbox)",
        "CanonicalAction::new(capability, Environment::Host)",
    ),
    # The agent's ending (ADR-0052 §§5, 10).
    (
        "reap signals none of the agent's descendants",
        "crates/dwk-sandbox-probe/src/linux.rs",
        "let _ = nix::sys::signal::kill(Pid::from_raw(-1), nix::sys::signal::Signal::SIGKILL);",
        "let _ = nix::sys::signal::kill(Pid::from_raw(-1), None);",
    ),
    (
        "the agent's wall clock is four times its own",
        "crates/dwkd-broker/src/sandbox/oci.rs",
        "        let deadline = (since + wall_clock).min(reserve);",
        "        let deadline = (since + 4 * wall_clock).min(reserve);",
    ),
    # Non-replay (ADR-0052 §9, W8-W10).
    (
        "a restart leaves an uncertain agent launching and its environment up",
        "crates/dwkd-authority/src/state/workload.rs",
        "         WHERE state = 'LAUNCHING' RETURNING invocation_id, run_id, environment_id\",",
        "         WHERE state = 'NEVER' RETURNING invocation_id, run_id, environment_id\",",
    ),
)


def _agent_guard_suites() -> None:
    """The suites that prove the agent's guards without a runtime: the
    authority's peer policy, sandbox configuration, grant and ledger; the
    broker's start-up, plan, supervisor and CONNECT proxy, and its private
    channel refusing a stranger; the probe's reap."""
    run(
        "cargo",
        "test",
        "--locked",
        "-p",
        "dwkd-authority",
        "--lib",
        "--",
        "server::",
        "sandbox::",
        "state::",
    )
    run("cargo", "test", "--locked", "-p", "dwkd-broker", "--bin", "dwkd-broker")
    run("cargo", "test", "--locked", "-p", "dwkd-broker", "--test", "private_protocol")
    run("cargo", "test", "--locked", "-p", "dwk-sandbox-probe")


def task_sandbox_agent_mutations() -> None:
    """Weaken each M5d.5 agent guard in turn; a unit suite or the agent evidence must catch it.

    Slow: a mutant no unit suite catches runs the one-identity agent
    evidence. Every file is restored byte-identically whatever happens, and
    checked. Never run it beside another build.
    """
    for what, rel, old, _new in AGENT_MUTATIONS:
        if (ROOT / rel).read_text(encoding="utf-8").count(old) != 1:
            raise TaskError(f"mutation `{what}`: its target is not in {rel} exactly once")
    killed: list[str] = []
    for what, rel, old, new in AGENT_MUTATIONS:
        path = ROOT / rel
        original = path.read_bytes()
        digest = hashlib.sha256(original).hexdigest()
        text = original.decode("utf-8")
        print(f"{BOLD}mutant: {what}{OFF}")
        outcome = "survived"
        try:
            path.write_bytes(text.replace(old, new).encode("utf-8"))
            try:
                run(
                    "cargo",
                    "test",
                    "--locked",
                    "--no-run",
                    "-p",
                    "dwk-sandbox-probe",
                    "-p",
                    "dwkd-broker",
                    "-p",
                    "dwkd-authority",
                )
            except TaskError:
                outcome = "did not compile"
            else:
                try:
                    _agent_guard_suites()
                except TaskError as exc:
                    outcome = f"killed by a unit suite: {str(exc)[:160]}"
                else:
                    try:
                        _sandbox_agent_evidence(require_privileged=False)
                    except TaskError as exc:
                        outcome = f"killed by the evidence: {str(exc)[:160]}"
        finally:
            path.write_bytes(original)
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise TaskError(f"{rel} was not restored byte-identically")
        print(f"{DIM}restored {rel} (sha256 {digest[:16]}...){OFF}")
        if not outcome.startswith("killed"):
            raise TaskError(f"mutant `{what}` {outcome}: nothing guards it")
        killed.append(f"{what}: {outcome[:60]}")
        print(f"{GREEN}mutant {outcome[:60]}: {what}{OFF}")
    for line in killed:
        print(f"  {line}")
    print(
        f"{GREEN}sandbox agent mutation review: {len(killed)} of {len(AGENT_MUTATIONS)} killed{OFF}"
    )


# --- M5d.6: a run's release ends its environment (ADR-0052 §8) -------------------

# The in-process half: the REAL authority and store against the route tests'
# FAKE broker -- labelled `fake-broker`: it proves the authority's state
# machine (who may end an environment, what is durable before the broker is
# told, which environment is named, what stays pending, what never reruns),
# never that a container ended.
RELEASE_UNIT_FILTER = "state::workload_route::tests::release::"
RELEASE_UNIT_TESTS = 15
RELEASE_UNIT_CASES = tuple(
    ("authority-release", case)
    for case in (
        "release-destroys-the-runs-environment",
        "release-intent-durable-before-the-broker",
        "release-names-only-its-environment",
        "release-audited-in-order",
        "release-spares-another-runs-environment",
        "release-repeated-no-second-effect",
        "released-run-launch-refused-nothing-prepared",
        "released-runs-key-never-runs-again",
        "release-keeps-the-runs-ledger",
        "release-without-an-environment-destroys-nothing",
        "release-without-a-sandbox-unchanged",
        "release-stale-epoch-refused-nothing-destroyed",
        "release-other-holder-refused-nothing-destroyed",
        "release-of-a-run-not-held-destroys-nothing",
        "release-ends-an-in-flight-workloads-environment",
        "release-in-flight-workload-settled-unknown",
        "release-in-flight-workload-never-rerun",
        "release-during-preparation-environment-destroyed",
        "release-during-preparation-nothing-ran",
        "release-broker-unreachable-destruction-pending",
        "release-broker-unreachable-completed-at-restart",
        "release-answer-lost-destruction-pending",
        "release-answer-lost-completed-at-restart",
        "release-pending-destruction-completed-by-the-next-preparation",
        "release-completes-its-runs-pending-destruction",
        # W12 (`u`), W6 (`k`) and W7 (`l`) through a release.
        *(
            f"release-crash-{letter}-{what}"
            for letter in ("u", "k", "l")
            for what in ("environment-destroyed-at-restart", "never-rerun")
        ),
        # The M5d closeout (CD-3): a lease's end, a new tenure, expiry alone,
        # a restart, a lost broker, W13 (`v`), W6 and W7, a preparation.
        "lease-release-stale-refused-nothing-destroyed",
        "lease-release-other-holder-refused-nothing-destroyed",
        "lease-release-reaps-and-destroys-durably-first",
        "lease-release-destroys-at-most-one-at-once",
        "lease-release-spares-another-sessions-environment",
        "lease-release-audited-in-order",
        "lease-release-repeated-no-second-effect",
        "lease-reaped-runs-launch-refused",
        "lease-pending-destruction-completed-by-the-next-preparation",
        "lease-held-refused-nothing-destroyed",
        "lease-rotation-ends-the-old-tenures-environment",
        "lease-rotation-new-tenure-runs",
        "lease-takeover-ends-the-old-tenures-environment",
        "lease-takeover-in-flight-workload-settled-unknown",
        "lease-takeover-key-never-reruns",
        "lease-takeover-never-inherits",
        "lease-expiry-alone-fences-and-destroys-nothing",
        "lease-expired-reacquire-destroys",
        "restart-destroys-reaped-runs-ready-environments",
        "restart-measures-no-reaped-environment",
        "lease-release-broker-unreachable-pending",
        "lease-release-broker-unreachable-completed-at-restart",
        *(
            f"lease-crash-{letter}-{what}"
            for letter in ("v", "k", "l")
            for what in ("completed-at-restart", "never-rerun")
        ),
        "lease-end-during-preparation-environment-destroyed",
        # The residual CD-3 leaves: a pending destruction holds brokered
        # changes in the workspace until it is removed.
        "lease-pending-destruction-holds-brokered-changes",
        "lease-pending-destruction-removed-then-changes-proceed",
    )
)

# The real-container half, selected by name: the workload harness -- the
# released broker, a real runtime, the real authority over a real DWKP client
# through the server seam, and the authority's own API for what one DWKP
# connection never interleaves (a release while its own launch runs, a crash,
# a lost broker) -- and the agent harness's PROXY_ONLY environment through the
# released `serve --sandbox-config`.
RELEASE_WORKLOAD_TESTS = (
    "linux::release::a_release_over_dwkp_destroys_its_environment_and_nothing_else",
    "linux::release::a_release_ends_an_in_flight_workload_and_every_process_it_left",
    "linux::release::a_release_a_crash_or_a_lost_broker_interrupts_is_completed_at_the_next_start",
    # The M5d closeout (CD-3).
    "linux::release::a_lease_end_over_dwkp_destroys_its_runs_environments_and_nothing_else",
    "linux::release::a_takeover_a_restart_or_a_crash_ends_a_reaped_runs_environment",
)
RELEASE_AGENT_TESTS = ("linux::a_released_run_takes_its_proxy_only_environment_and_relay_down",)
RELEASE_CASES = tuple(
    ("sandbox-release", case)
    for case in (
        # What a release ends: a sandboxed launch as M5d.2 made it.
        "sandboxed-exec-in-a-measured-environment-never-the-host",
        "sandboxed-exec-names-the-pinned-image-and-executable",
        "sandboxed-exec-runs-as-the-environment-user",
        # Over DWKP: the release ends exactly its run's environment.
        "release-stale-epoch-refused-nothing-destroyed",
        "release-other-holder-refused-nothing-destroyed",
        "release-of-a-run-not-held-destroys-nothing",
        "release-over-dwkp-destroys-the-environment",
        "release-audited",
        "release-spares-another-runs-environment",
        "release-spares-foreign-containers",
        "release-other-run-still-runs",
        "release-repeated-over-dwkp-no-second-effect",
        "released-run-launch-refused-over-dwkp",
        "release-without-an-environment-over-dwkp",
        # An in-flight agent-shaped workload and its descendants.
        "release-in-flight-agent-and-descendants-running",
        "release-ends-in-flight-workload-and-descendants",
        "release-in-flight-workload-settled-unknown",
        "release-in-flight-workload-never-rerun",
        # Crashes and a lost broker, reconciled.
        *(
            f"release-crash-{letter}-{what}"
            for letter in ("u", "k", "l")
            for what in ("completed-at-restart", "never-rerun")
        ),
        "release-broker-lost-destruction-pending",
        "release-broker-lost-completed-at-restart",
        # PROXY_ONLY: the relay and setup go with it; the egress is kept.
        "release-removes-the-proxy-only-environment-relay-and-setup",
        "release-destruction-records-the-egress-by-disposition",
        "release-spares-another-runs-proxy-only-environment",
        # The M5d closeout (CD-3): a lease's end over DWKP, a takeover with an
        # agent running, a restart, W13, and PROXY_ONLY.
        "lease-release-over-dwkp-stale-refused",
        "lease-release-over-dwkp-other-holder-refused",
        "lease-release-over-dwkp-destroys-one-at-once",
        "lease-release-over-dwkp-spares-another-session",
        "lease-release-over-dwkp-spares-foreign-containers",
        "lease-release-over-dwkp-repeated-no-second-effect",
        "lease-reaped-run-launch-refused-over-dwkp",
        "lease-pending-destruction-removed-by-the-next-preparation",
        "lease-takeover-in-flight-agent-running",
        "lease-takeover-ends-in-flight-workload-and-descendants",
        "lease-takeover-in-flight-workload-settled-unknown",
        "lease-takeover-workload-never-rerun",
        "restart-destroys-a-reaped-runs-ready-environment",
        "restart-measures-no-reaped-environment",
        "lease-crash-v-completed-at-restart",
        "lease-release-removes-the-proxy-only-environment-relay-and-setup",
    )
)
# What each line must say it is: a fake broker's line is never a container's
# end, and a real case is never a fake broker's.
RELEASE_LEVELS = {
    "authority-release": frozenset({"fake-broker"}),
    "sandbox-release": frozenset({"dwkp-end-to-end", "real-oci"}),
}


def require_release_evidence(output: str, cases: tuple[tuple[str, str], ...]) -> None:
    """Every case reported, exercised (`require_sandbox_evidence`), each line
    of its suite's level and naming what enforced it."""
    for record in require_sandbox_evidence(output, cases):
        suite = str(record["suite"])
        if (suite, str(record.get("case"))) not in cases:
            continue
        if record.get("level") not in RELEASE_LEVELS.get(suite, frozenset()):
            raise TaskError(f"release evidence at the wrong level: {record}")
        if not record.get("enforcement"):
            raise TaskError(f"release evidence without its enforcement: {record}")
    # Judged and passed: kept for the M5 gate, by its own verdict (G-Q1).
    keep_judged("release", cases, SANDBOX_EVIDENCE_PREFIX, output)


def _release_unit_half() -> str:
    """The in-process half: every release unit test run, none filtered away."""
    output = run_captured(
        "cargo",
        "test",
        "--locked",
        "-p",
        "dwkd-authority",
        "--lib",
        "--",
        RELEASE_UNIT_FILTER,
        "--nocapture",
        "--test-threads=1",
    )
    summaries = [line for line in output.splitlines() if line.startswith("test result: ")]
    expected = f"test result: ok. {RELEASE_UNIT_TESTS} passed; 0 failed; 0 ignored"
    if len(summaries) != 1 or not summaries[0].startswith(expected):
        raise TaskError(
            f"the release unit tests did not all run: expected `{expected}`, "
            f"got {summaries or 'no summary'}"
        )
    require_release_evidence(output, RELEASE_UNIT_CASES)
    return output


def _release_workload_half() -> str:
    """The workload harness's release tests over a real runtime; no container
    they made may remain and none that predates them may go."""
    client, socket, variables, before, images = _workload_setup()
    os.environ.update(variables)
    try:
        run("cargo", "build", "--locked", "-p", "dwkd-broker")
        output = run_captured(
            "cargo",
            "test",
            "--locked",
            "-p",
            "dwkd-authority",
            "--test",
            "sandbox_workload",
            "--",
            "--ignored",
            "--exact",
            "--nocapture",
            "--test-threads=1",
            *RELEASE_WORKLOAD_TESTS,
        )
        summaries = [line for line in output.splitlines() if line.startswith("test result: ")]
        expected = f"test result: ok. {len(RELEASE_WORKLOAD_TESTS)} passed; 0 failed; 0 ignored"
        if len(summaries) != 1 or not summaries[0].startswith(expected):
            raise TaskError(
                f"the sandbox_workload release suite did not run all of its tests: expected "
                f"`{expected}`, got {summaries or 'no summary'}"
            )
    finally:
        after = set(
            _docker(client, socket, "container", "ls", "--all", "--no-trunc", "--quiet").split()
        )
        for image in set(images.values()):
            _docker(client, socket, "image", "rm", "--force", image, check=False)
    left = sorted(after - before)
    removed = sorted(before - after)
    if left:
        raise TaskError(f"the evidence left {len(left)} container(s) behind: {left}")
    if removed:
        raise TaskError(
            f"{len(removed)} container(s) that predate the evidence are gone: {removed}"
        )
    report_cleanup(f"cleanup: no evidence container remains; {len(before)} pre-existing kept")
    return output


def _release_agent_half() -> str:
    """The agent harness's PROXY_ONLY release test through the released
    `serve`; its cleanup is the agent evidence's own (C04)."""
    client, socket, variables, before, images = _agent_setup()
    os.environ.update(variables)
    base = _agent_workspace_base()
    sockets_before = set(_socket_dirs_left())
    try:
        output = _agent_suite(RELEASE_AGENT_TESTS)
    except BaseException:
        for problem in _agent_cleanup(client, socket, images, base, before, sockets_before):
            print(f"{RED}cleanup also failed: {problem}{OFF}", file=sys.stderr, flush=True)
        raise
    problems = _agent_cleanup(client, socket, images, base, before, sockets_before)
    if problems:
        raise TaskError("cleanup failed: " + "; ".join(problems))
    report_cleanup(
        "cleanup: no evidence container or broker socket directory remains; "
        f"{len(before)} pre-existing container(s) kept"
    )
    return output


def task_sandbox_release_evidence() -> None:
    """M5d.6's evidence (ADR-0052 §8): a run's release ends its environment.

    In process: the real authority against a FAKE broker (labelled so) --
    who may end a run's environment, the destruction durable in the
    release's transaction before the broker hears of it, exactly the run's
    environment named, an unconfirmed destruction pending until reconciled,
    a preparation the release overtook keeping nothing, crash windows W12,
    W6 and W7, and nothing the run did run again. Then real containers: over
    a real DWKP client, a release removing its environment when it is
    answered and nothing else -- another run's, an unlabelled container of
    the same image, another store's copy of its labels -- fenced and foreign
    releases ending nothing; an in-flight agent-shaped workload and its
    descendants ended with their environment and settled UNKNOWN, never
    rerun; crashes and a lost broker completed at the next start; and a
    PROXY_ONLY environment's relay and setup removed with it, its egress
    recorded by disposition, another run's relay kept.

    Every case must report with its level and what enforced it, none NOT
    EXERCISED. No container or broker socket directory the evidence made may
    remain, and every container that predates it must. Linux only.
    """
    outputs = [_release_unit_half(), _release_workload_half(), _release_agent_half()]
    require_release_evidence("\n".join(outputs[1:]), RELEASE_CASES)
    uvrun("dwcheck", "closure", "--report")


# The mutation review (ADR-0052 §17): each line weakens one guard of the
# release's teardown, in the source, one at a time. Each mutant must compile
# and must fail the authority's state suites or `sandbox-release-evidence`;
# the file is then restored, and its SHA-256 proves it byte-identical. A
# mutant that survives, or does not compile, fails the review.
RELEASE_MUTATIONS = (
    (
        "a release ends nothing of its run",
        "crates/dwkd-authority/src/state/mod.rs",
        '                Reply::Done(true) => environment::begin_run_end(work, run, "RELEASED")?,',
        "                Reply::Done(true) => Vec::new(),",
    ),
    (
        "the environment's destruction is recorded only after the release committed",
        "crates/dwkd-authority/src/state/mod.rs",
        '                Reply::Done(true) => environment::begin_run_end(work, run, "RELEASED")?,\n'
        "                Reply::Done(false) | Reply::Refused(_) => Vec::new(),\n"
        "            };\n"
        "            let reply = match released {\n"
        "                Reply::Done(_) => Reply::Done(()),\n"
        "                Reply::Refused(reason) => Reply::Refused(reason),\n"
        "            };\n"
        "            Ok((reply, teardown))\n"
        "        })?;\n"
        "        self.end_runs(teardown, CrashPoint::ReleaseAfterIntent)?;\n",
        '                Reply::Done(true) => vec![environment::DestroyBegun::Refused("LATER")],\n'
        "                Reply::Done(false) | Reply::Refused(_) => Vec::new(),\n"
        "            };\n"
        "            let reply = match released {\n"
        "                Reply::Done(_) => Reply::Done(()),\n"
        "                Reply::Refused(reason) => Reply::Refused(reason),\n"
        "            };\n"
        "            Ok((reply, teardown))\n"
        "        })?;\n"
        "        let teardown = if teardown.is_empty() {\n"
        "            teardown\n"
        "        } else {\n"
        "            self.shared.crash(CrashPoint::ReleaseAfterIntent)?;\n"
        '            self.transact(|work| environment::begin_run_end(work, run, "RELEASED"))?\n'
        "        };\n"
        "        self.end_runs(teardown, CrashPoint::ReleaseAfterIntent)?;\n",
    ),
    (
        "a fenced release ends the run's environment",
        "crates/dwkd-authority/src/state/mod.rs",
        "                Reply::Done(false) | Reply::Refused(_) => Vec::new(),",
        "                Reply::Done(false) => Vec::new(),\n"
        '                Reply::Refused(_) => environment::begin_run_end(work, run, "RELEASED")?,',
    ),
    (
        "a release acknowledged without effect ends the named run's environment",
        "crates/dwkd-authority/src/state/mod.rs",
        "                Reply::Done(false) | Reply::Refused(_) => Vec::new(),",
        "                Reply::Done(false) => "
        'environment::begin_run_end(work, run, "RELEASED")?,\n'
        "                Reply::Refused(_) => Vec::new(),",
    ),
    (
        "a release ends every environment of its session",
        "crates/dwkd-authority/src/state/environment.rs",
        "AND run_id = ?1 \\",
        "AND run_id IN (SELECT r.run_id FROM run r JOIN run m ON m.session_id = r.session_id "
        "WHERE m.run_id = ?1) \\",
    ),
    (
        "a release ends every live environment",
        "crates/dwkd-authority/src/state/environment.rs",
        "AND run_id = ?1 \\",
        "AND (run_id = ?1 OR ?1 IS NOT NULL) \\",
    ),
    (
        "a preparation keeps an environment its run's release overtook",
        "crates/dwkd-authority/src/state/environment.rs",
        "    if active {\n        return Ok(None);",
        "    if true || active {\n        return Ok(None);",
    ),
    (
        "an unconfirmed destruction is recorded as done",
        "crates/dwkd-authority/src/state/environment_ops.rs",
        "        Err(error) => pending(failure_of(&error)),",
        "        Err(_) => (\n"
        "            DestroyEnding::Gone { container: None, already: true, egress: None },\n"
        "            0,\n"
        "        ),",
    ),
    (
        "a restart leaves a pending destruction pending",
        "crates/dwkd-authority/src/state/environment_ops.rs",
        "        for class in environment::classify(&records, &listed, current) {",
        "        for class in environment::classify(&records, &listed, current)\n"
        "            .into_iter()\n"
        "            .filter(|c| !matches!(c, ReconcileClass::Pending(_)))\n"
        "        {",
    ),
    # Weakening only the route's own run check is an equivalent mutant: the
    # workload ledger refuses a run that is not active again, with the same
    # answer. What a released run must never regain is its state.
    (
        "a release leaves its run active, and executable",
        "crates/dwkd-authority/src/state/admission.rs",
        "SET state = 'RELEASED', ended_ms = ?5 WHERE run_id = ?1 AND session_id = ?2",
        "SET state = state, ended_ms = NULLIF(?5, ?5) WHERE run_id = ?1 AND session_id = ?2",
    ),
    # The M5d closeout (CD-3): a lease's end, a new tenure and a restart.
    (
        "a lease's end destroys nothing of its reaped runs",
        "crates/dwkd-authority/src/state/lease.rs",
        '        teardown.extend(environment::begin_run_end(work, &id, "REAPED")?);',
        "        let _ = &id;",
    ),
    (
        "a run's end removes nothing at once",
        "crates/dwkd-authority/src/state/mod.rs",
        "            self.perform_destroy(record, invocation)?;\n        }\n        Ok(())",
        "            let _ = (record, invocation);\n        }\n        Ok(())",
    ),
    (
        "a lease's end removes every pending destruction at once, unbounded",
        "crates/dwkd-authority/src/state/mod.rs",
        "        let first = teardown\n"
        "            .into_iter()\n"
        "            .find(|begun| matches!(begun, environment::DestroyBegun::Pending { .. }));\n"
        "        if let Some(environment::DestroyBegun::Pending { record, invocation }) "
        "= first {\n",
        "        for begun in teardown {\n"
        "            let environment::DestroyBegun::Pending { record, invocation } = begun else {\n"
        "                continue;\n"
        "            };\n"
        "            self.perform_destroy(record, invocation)?;\n"
        "        }\n"
        "        if let Some(environment::DestroyBegun::Pending { record, invocation }) = None {\n",
    ),
    (
        "a restart keeps a reaped run's READY environment",
        "crates/dwkd-authority/src/state/mod.rs",
        "            environment::begin_reaped_at_start(work)?;",
        "            let _ = &work;",
    ),
)


def _release_guard_suites() -> None:
    """The suites that prove the release's guards without a runtime: the
    authority's state machine, its route and lifecycle tests included."""
    run("cargo", "test", "--locked", "-p", "dwkd-authority", "--lib", "--", "state::")


def task_sandbox_release_mutations() -> None:
    """Weaken each M5d.6 release guard in turn; a unit suite or the release evidence must catch it.

    Slow: a mutant no unit suite catches runs the whole release evidence.
    Every file is restored byte-identically whatever happens, and checked.
    Never run it beside another build.
    """
    for what, rel, old, _new in RELEASE_MUTATIONS:
        if (ROOT / rel).read_text(encoding="utf-8").count(old) != 1:
            raise TaskError(f"mutation `{what}`: its target is not in {rel} exactly once")
    killed: list[str] = []
    for what, rel, old, new in RELEASE_MUTATIONS:
        path = ROOT / rel
        original = path.read_bytes()
        digest = hashlib.sha256(original).hexdigest()
        text = original.decode("utf-8")
        print(f"{BOLD}mutant: {what}{OFF}")
        outcome = "survived"
        try:
            path.write_bytes(text.replace(old, new).encode("utf-8"))
            try:
                run("cargo", "test", "--locked", "--no-run", "-p", "dwkd-authority")
            except TaskError:
                outcome = "did not compile"
            else:
                try:
                    _release_guard_suites()
                except TaskError as exc:
                    outcome = f"killed by a unit suite: {str(exc)[:160]}"
                else:
                    try:
                        task_sandbox_release_evidence()
                    except TaskError as exc:
                        outcome = f"killed by the evidence: {str(exc)[:160]}"
        finally:
            path.write_bytes(original)
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise TaskError(f"{rel} was not restored byte-identically")
        print(f"{DIM}restored {rel} (sha256 {digest[:16]}...){OFF}")
        if not outcome.startswith("killed"):
            raise TaskError(f"mutant `{what}` {outcome}: nothing guards it")
        killed.append(f"{what}: {outcome[:60]}")
        print(f"{GREEN}mutant {outcome[:60]}: {what}{OFF}")
    for line in killed:
        print(f"  {line}")
    print(
        f"{GREEN}sandbox release mutation review: {len(killed)} of {len(RELEASE_MUTATIONS)} "
        f"killed{OFF}"
    )


# --- D11 hardening (ADR-0053) ---------------------------------------------------

D11_EVIDENCE_PREFIX = "D11-EVIDENCE "

# The cases the broker's own suites print on any Linux host with Yama at 1
# and fs.suid_dumpable 0 or 2 (`crates/dwkd-broker/src/http/hardening_tests.rs`):
# real workers, a real same-uid observer, workers held at their first
# instruction -- a readable image (the control) and one its uid cannot read --
# stand-ins weakened one property at a time, and the host facts read before
# every hop.
D11_CASES = (
    "worker-confined-before-hand-over",
    "worker-forbidden-attempts-refused",
    "worker-image-at-exec-readable-binary",
    "readable-image-open-to-its-uid-at-exec",
    "unreadable-image-closed-to-its-uid-at-exec",
    "same-uid-observer-refused",
    "worker-cut-off-before-hand-over",
    "stand-in-without-everything",
    "stand-in-without-a-filter",
    "stand-in-without-non-dumpability",
    "stand-in-without-an-untraced-state",
    "stand-in-without-an-honest-ready-line",
    "stand-in-complete",
    "startup-window-open-hop-refused",
    "unverified-architecture-hop-refused",
    "execute-only-under-suid-dumpable-1-hop-refused",
    "swappable-credential-hop-refused",
    "swappable-plain-hop-performed",
    "swappable-worker-handed-nothing",
    "capped-credential-hop-performed",
)

# The cases that need a host the suites cannot make for themselves, and what
# makes each. Absent, each is NOT EXERCISED -- listed, and a failure.
D11_HOST_CASES = (
    ("host-swap-refusal", "a host with swap, outside any no-swap cgroup"),
    (
        "credential-hop-under-a-real-no-swap-cap",
        "a transient cgroup with memory.swap.max 0 (systemd-run)",
    ),
    (
        "memory-pressure-under-cap",
        "a transient cgroup with memory.swap.max 0 and a memory limit (systemd-run)",
    ),
    (
        "execute-only-image-closed-to-its-uid-at-exec",
        "a root-owned execute-only broker binary (DW_D11_PRIVILEGED=1 and passwordless sudo)",
    ),
    (
        "yama-0-counterexample",
        "Yama lowered to 0 for one run, then restored (DW_D11_PRIVILEGED=1 and passwordless sudo)",
    ),
)

# The broker's unit suites that carry D11 hardening: the program, the
# vouching, the posture, the configuration, the deployment decision, the
# worker, and the real-worker evidence.
D11_SUITES = (
    "http::confine",
    "http::vouch",
    "posture::",
    "config::",
    "tests::the_broker_serves_only",
    "tests::swappable_memory",
    "http::worker::",
    "http::tests::hardening",
)

HARDENING = "http::tests::hardening::"

# Where the privileged half installs a root-owned execute-only broker for
# one case, and removes it after (`hardening_tests.rs`, `XONLY_BINARY`).
D11_XONLY_DIRECTORY = "/usr/local/libexec/direwolf-d11-evidence"


def broker_unit_binary() -> str:
    """Build the broker's unit-test binary and return its path."""
    built = subprocess.run(
        [
            "cargo",
            "test",
            "--locked",
            "-p",
            "dwkd-broker",
            "--bin",
            "dwkd-broker",
            "--no-run",
            "--message-format=json",
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    if built.returncode != 0:
        raise TaskError(f"the broker's unit tests did not build:\n{built.stderr[-2000:]}")
    for line in built.stdout.splitlines():
        try:
            record = json.loads(line)
        except json.JSONDecodeError:
            continue
        target = record.get("target") or {}
        if (
            record.get("reason") == "compiler-artifact"
            and (record.get("profile") or {}).get("test")
            and target.get("name") == "dwkd-broker"
            and record.get("executable")
        ):
            return str(record["executable"])
    raise TaskError("the broker's unit-test binary was not found in cargo's output")


def d11_privileged() -> bool:
    """Whether this run may use passwordless sudo to make the hosts a case
    needs (a root-owned binary, Yama at 0, a system cgroup). Never inferred:
    only `DW_D11_PRIVILEGED=1` says so, and a developer's machine is never
    changed without it."""
    if os.environ.get("DW_D11_PRIVILEGED", "").strip() != "1":
        return False
    return subprocess.run(["sudo", "-n", "true"], capture_output=True, check=False).returncode == 0


def no_swap_scope(*properties: str) -> list[str] | None:
    """A command prefix that runs a command in a fresh transient cgroup whose
    `memory.swap.max` is 0 (and `properties`), proved by reading it from
    inside -- or `None`. The user's own systemd first, needing no privilege;
    then, only where `d11_privileged`, the system's with `setpriv` back to
    this user."""
    props = [f"--property={p}" for p in ("MemorySwapMax=0", *properties)]
    probe = [
        "sh",
        "-c",
        'cat "/sys/fs/cgroup$(sed -n "s/^0:://p" /proc/self/cgroup)/memory.swap.max"',
    ]
    candidates = [["systemd-run", "--user", "--scope", "--quiet", *props, "--"]]
    if d11_privileged():
        candidates.append(
            [
                "sudo",
                "-n",
                "systemd-run",
                "--scope",
                "--quiet",
                *props,
                "--",
                "setpriv",
                f"--reuid={os.getuid()}",
                f"--regid={os.getgid()}",
                "--init-groups",
                "--",
            ]
        )
    for prefix in candidates:
        if shutil.which(prefix[0]) is None:
            continue
        try:
            inside = subprocess.run(
                [*prefix, *probe], capture_output=True, text=True, timeout=60, check=False
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if inside.returncode == 0 and inside.stdout.strip() == "0":
            return prefix
    return None


def d11_reported(output: str) -> dict[str, str]:
    """Every `D11-EVIDENCE` case printed, and its outcome."""
    reported: dict[str, str] = {}
    for line in output.splitlines():
        at = line.find(D11_EVIDENCE_PREFIX)
        if at < 0:
            continue
        try:
            record = json.loads(line[at + len(D11_EVIDENCE_PREFIX) :])
        except json.JSONDecodeError as exc:
            raise TaskError(f"unreadable evidence line: {line[:200]}") from exc
        reported[str(record.get("case"))] = str(record.get("outcome"))
    return reported


def d11_privileged_cases(test_binary: str, outputs: list[str]) -> list[str]:
    """The cases only root can set up, each undone whatever happens: a
    root-owned execute-only copy of the broker, and Yama at 0 for one run.
    Each runs whatever became of the other; what failed is returned, for the
    task to fail on once everything ran. `fs.suid_dumpable` and the core
    pattern are read and printed, never changed: they decide what the
    execute-only case can show."""
    failed: list[str] = []
    for name in ("fs/suid_dumpable", "kernel/core_pattern"):
        value = (_read(f"/proc/sys/{name}") or "unreadable").strip()
        print(f"{name.replace('/', '.')}: {value}  (read only)")
    broker = Path(test_binary).parent.parent / "dwkd-broker"
    # The fixed path the case reads (the broker's tests read nothing ambient).
    directory = Path(D11_XONLY_DIRECTORY)
    xonly = directory / "dwkd-broker"
    owned = ("-o", "root", "-g", "root")
    try:
        run("sudo", "-n", "install", "-d", *owned, "-m", "0755", str(directory))
        run("sudo", "-n", "install", *owned, "-m", "0711", str(broker), str(xonly))
        outputs.append(
            run_captured(
                test_binary,
                "--ignored",
                "--exact",
                "--nocapture",
                "--test-threads=1",
                HARDENING + "an_execute_only_binary_starts_its_worker_closed_to_its_uid",
            )
        )
    except TaskError as exc:
        failed.append(f"the execute-only binary: {exc}")
    finally:
        run("sudo", "-n", "rm", "-f", str(xonly))
        if directory.exists():
            run("sudo", "-n", "rmdir", str(directory))
    yama = Path("/proc/sys/kernel/yama/ptrace_scope")
    original = yama.read_text(encoding="utf-8").strip()
    try:
        run("sudo", "-n", "sysctl", "-q", "-w", "kernel.yama.ptrace_scope=0")
        outputs.append(
            run_captured(
                test_binary,
                "--exact",
                "--nocapture",
                "--test-threads=1",
                HARDENING + "a_same_uid_observer_cannot_reach_a_worker_whatever_yama_allows",
            )
        )
    except TaskError as exc:
        failed.append(f"the Yama-0 counterexample: {exc}")
    finally:
        run("sudo", "-n", "sysctl", "-q", "-w", f"kernel.yama.ptrace_scope={original}")
    return failed


def task_d11_hardening_evidence() -> None:
    """D11 hardening's evidence (ADR-0053 §18): the exchange worker's
    syscall filter, the broker's vouching from the kernel, the start-up
    window and the swap posture -- on real workers and real hosts.

    The broker's suites run first: the program evaluated for every syscall
    number and both other calling conventions; real workers proving their
    confinement before they are handed anything, as the kernel shows it; a
    same-uid observer refused; workers held at their first instruction --
    a readable image open to its own uid (the control), and one its uid
    cannot read closed to it, even to its parent; stand-ins lacking one
    property each, handed nothing; the host facts read before every hop.
    Then the host: a
    credential hop refused on this host's swap; one performed in a real
    cgroup that allows no swap, its worker in it; memory pressure there ending
    in the OOM killer, never in swap. Then, only with `DW_D11_PRIVILEGED=1`
    and passwordless sudo (the hosted job), a root-owned execute-only binary
    whose worker is closed to its uid from `execve` -- under the host's own
    `fs.suid_dumpable`, read and never changed -- and Yama at 0 for one run --
    the counterexample, restored at once; each runs whatever became of the
    other. What the host cannot provide is NOT EXERCISED, listed, and fails
    the task after everything else ran.
    Linux only.
    """
    if not sys.platform.startswith("linux"):
        raise TaskError(
            "NOT EXERCISED: D11 hardening is Linux's (seccomp, Yama, cgroup v2); "
            "use WSL2 on Windows"
        )
    run("cargo", "build", "--locked", "-p", "dwkd-broker")
    test_binary = broker_unit_binary()
    outputs: list[str] = []
    suites = run_captured(test_binary, "--test-threads=1", "--nocapture", *D11_SUITES)
    require_tests_ran(suites)
    outputs.append(suites)
    outputs.append(
        run_captured(
            test_binary,
            "--ignored",
            "--exact",
            "--nocapture",
            "--test-threads=1",
            HARDENING + "on_a_host_with_swap_the_production_policy_refuses_a_credential_hop",
        )
    )
    capped = no_swap_scope()
    if capped is not None:
        outputs.append(
            run_captured(
                *capped,
                test_binary,
                "--ignored",
                "--exact",
                "--nocapture",
                "--test-threads=1",
                HARDENING + "a_credential_hop_runs_under_a_real_no_swap_cap",
            )
        )
    # `OOMPolicy=continue`: the OOM killer ends the allocating process, and
    # the transient unit -- the test with it -- carries on to read what it did.
    pressured = no_swap_scope("MemoryMax=256M", "OOMPolicy=continue")
    if pressured is not None:
        outputs.append(
            run_captured(
                *pressured,
                test_binary,
                "--ignored",
                "--exact",
                "--nocapture",
                "--test-threads=1",
                HARDENING + "memory_pressure_under_the_cap_ends_in_the_oom_killer_never_in_swap",
            )
        )
    failed = d11_privileged_cases(test_binary, outputs) if d11_privileged() else []
    reported = d11_reported("\n".join(outputs))
    if failed:
        raise TaskError("privileged D11 case(s) FAILED: " + "; ".join(failed))
    missing = [case for case in D11_CASES if case not in reported]
    if missing:
        raise TaskError(f"{len(missing)} D11 case(s) did not report: " + ", ".join(missing))
    unexercised = [
        f"{case} ({needs})"
        for case, needs in D11_HOST_CASES
        if case not in reported or reported[case].startswith("NOT-EXERCISED")
    ]
    exercised = len(D11_CASES) + len(D11_HOST_CASES) - len(unexercised)
    print(
        f"{GREEN}D11 hardening: {exercised} of {len(D11_CASES) + len(D11_HOST_CASES)} "
        f"cases exercised{OFF}"
    )
    uvrun("dwcheck", "closure", "--report")
    if unexercised:
        raise TaskError("NOT EXERCISED on this host: " + "; ".join(unexercised))


def _read(path: str) -> str | None:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _syscall_available(number: int, *args: int) -> str:
    """Whether a syscall exists here, by calling it with harmless arguments
    (`memfd_secret(0)` makes a descriptor, closed at once;
    `landlock_create_ruleset(NULL, 0, VERSION)` only asks the ABI)."""
    import ctypes

    libc = ctypes.CDLL(None, use_errno=True)
    result = libc.syscall(number, *args)
    if result < 0:
        return f"unavailable ({os.strerror(ctypes.get_errno())})"
    if number == 447:
        os.close(result)
        return "available"
    return f"available, ABI {result}"


def task_d11_posture() -> None:
    """Report, read-only, what this host gives D11 hardening (ADR-0053 §13).

    Changes nothing: no sysctl, no cgroup, no service, no file. Prints Yama,
    the broker binary's owner and mode, swap devices and this shell's
    effective swap cap, page zeroing, hibernation, memory locking, whether
    `memfd_secret` and Landlock exist, and on WSL2 the `.wslconfig` swap
    setting -- and what each means for the broker's start-up and its
    credential hops. Linux only.
    """
    if not sys.platform.startswith("linux"):
        raise TaskError("the posture of a Linux host: run it in WSL2 on Windows")
    import resource

    yama = (_read("/proc/sys/kernel/yama/ptrace_scope") or "absent").strip()
    print(f"Yama ptrace_scope: {yama}  (1 or more closes the start-up window by itself)")
    for candidate in (
        os.environ.get("DW_BROKER_BINARY", ""),
        "/usr/libexec/direwolf/dwkd-broker",
        "/usr/local/libexec/direwolf/dwkd-broker",
        str(ROOT / "target" / "release" / "dwkd-broker"),
    ):
        if candidate and Path(candidate).exists():
            st = Path(candidate).stat()
            execute_only = st.st_uid == 0 and st.st_mode & 0o044 == 0
            print(
                f"broker binary {candidate}: owner uid {st.st_uid}, mode {st.st_mode & 0o7777:04o}"
                f" -> execute-only {execute_only}  (closes the window from execve where"
                " fs.suid_dumpable is 0 or 2)"
            )
    swaps = [line for line in (_read("/proc/swaps") or "").splitlines()[1:] if line.strip()]
    print(f"swap devices: {len(swaps)}" + "".join(f"\n  {line}" for line in swaps))
    cgroup = next(
        (
            line[3:]
            for line in (_read("/proc/self/cgroup") or "").splitlines()
            if line.startswith("0::")
        ),
        None,
    )
    capped_at = None
    if cgroup:
        at = cgroup.rstrip("/")
        while at:
            if (_read(f"/sys/fs/cgroup{at}/memory.swap.max") or "").strip() == "0":
                capped_at = at
                break
            at = at.rsplit("/", 1)[0]
    print(f"this shell's cgroup: {cgroup}; swap capped to 0 at: {capped_at or 'nowhere'}")
    if not swaps:
        print("  -> no swap device: credential hops are performed (re-checked every hop)")
    elif capped_at:
        print("  -> a broker started here may perform credential hops")
    else:
        print(
            "  -> a broker started here refuses credential hops unless --allow-swappable-workers "
            "(development only); run it under MemorySwapMax=0 instead"
        )
    zswap = (_read("/sys/module/zswap/parameters/enabled") or "absent").strip()
    print(f"zswap enabled: {zswap}")
    cmdline = (_read("/proc/cmdline") or "").split()
    zeroing = {
        k: v
        for k, _, v in (w.partition("=") for w in cmdline)
        if k in ("init_on_alloc", "init_on_free")
    }
    print(
        f"page zeroing on the kernel command line: {zeroing or 'none (the build default applies)'}"
    )
    print(f"hibernation (/sys/power/disk): {(_read('/sys/power/disk') or 'absent').strip()}")
    suid_dumpable = (_read("/proc/sys/fs/suid_dumpable") or "absent").strip()
    meaning = {
        "0": "an execute-only image starts not dumpable: closed to its uid",
        "1": "an execute-only image starts dumpable by its uid: it closes nothing",
        "2": "an execute-only image starts dumpable by root only: closed to its uid",
    }.get(suid_dumpable, "unknown: an execute-only binary closes nothing")
    print(f"suid_dumpable: {suid_dumpable}  ({meaning})")
    soft, hard = resource.getrlimit(resource.RLIMIT_MEMLOCK)
    print(f"RLIMIT_MEMLOCK: soft {soft}, hard {hard}")
    if platform.machine() == "x86_64":
        print(f"memfd_secret: {_syscall_available(447, 0)}")
        print(f"Landlock: {_syscall_available(444, 0, 0, 1)}")
    release = (_read("/proc/version") or "").lower()
    if "microsoft" in release:
        print(
            "WSL2: the guest's swap is the VM's; the Windows pagefile and the hypervisor "
            "are outside it"
        )
        configs = sorted(Path("/mnt/c/Users").glob("*/.wslconfig"))
        if not configs:
            print("  no %UserProfile%\\.wslconfig: WSL's defaults (a swap file of 25% of memory)")
        for config in configs:
            text = _read(str(config)) or ""
            settings = [
                line.strip()
                for line in text.splitlines()
                if line.strip().lower().startswith(("swap", "kernelcommandline"))
            ]
            print(f"  {config}: {settings or 'no swap setting (the default: 25% of memory)'}")


# The mutation review (ADR-0053 §18): each line weakens one D11 guard; each
# mutant must compile and must fail the broker's suites -- the program's
# evaluation, the vouching's tests, the real workers and the stand-ins, the
# host facts. Files are restored and checked byte for byte.
D11_MUTATIONS = (
    (
        "the worker installs no filter",
        "crates/dwkd-broker/src/http/confine.rs",
        "seccompiler::apply_filter_all_threads(&program)"
        '.map_err(|_| "the kernel refused the filter")',
        "{\n        let _ = program;\n        Ok(())\n    }",
    ),
    (
        "the program allows a new socket",
        "crates/dwkd-broker/src/http/confine.rs",
        '    ("read", libc::SYS_read),\n',
        '    ("read", libc::SYS_read),\n    ("socket", libc::SYS_socket),\n',
    ),
    (
        "the program allows execve",
        "crates/dwkd-broker/src/http/confine.rs",
        '    ("write", libc::SYS_write),\n',
        '    ("write", libc::SYS_write),\n    ("execve", libc::SYS_execve),\n',
    ),
    (
        "another architecture's table is allowed",
        "crates/dwkd-broker/src/http/confine.rs",
        "jump(JEQ_K, AUDIT_ARCH, To::Next, To::Kill)",
        "jump(JEQ_K, AUDIT_ARCH, To::Next, To::Next)",
    ),
    (
        "the x32 convention is allowed",
        "crates/dwkd-broker/src/http/confine.rs",
        "jump(JGE_K, X32_SYSCALL_BIT, To::Kill, To::Next)",
        "jump(JGE_K, X32_SYSCALL_BIT, To::Next, To::Next)",
    ),
    (
        "an executable mapping is allowed",
        "crates/dwkd-broker/src/http/confine.rs",
        '("mmap", libc::SYS_mmap, vec![Check::Clear(2, exec)])',
        '("mmap", libc::SYS_mmap, vec![Check::Clear(2, 0)])',
    ),
    (
        "fcntl may set another process as the signal owner",
        "crates/dwkd-broker/src/http/confine.rs",
        "        libc::F_DUPFD_CLOEXEC,\n    ]",
        "        libc::F_DUPFD_CLOEXEC,\n        libc::F_SETOWN,\n    ]",
    ),
    (
        "tgkill may signal any process",
        "crates/dwkd-broker/src/http/confine.rs",
        "vec![Check::AnyOf(0, vec![own_pid])]",
        "vec![Check::Clear(0, 0)]",
    ),
    (
        "the broker hands over whatever the worker said",
        "crates/dwkd-broker/src/http/worker.rs",
        "    match vouched(&ours, &child, authorisation.credential.is_some(), policy) {",
        "    match vouched(&ours, &child, authorisation.credential.is_some(), policy)\n"
        "        .or_else(|_| Ok::<Ready, String>(Ready { at_exec: 255, answers: Vec::new() }))\n"
        "    {",
    ),
    (
        "a worker without a filter is vouched for",
        "crates/dwkd-broker/src/http/vouch.rs",
        '    if field(status, "Seccomp") != Some(2) {',
        '    if false && field(status, "Seccomp") != Some(2) {',
    ),
    (
        "a worker without no_new_privs is vouched for",
        "crates/dwkd-broker/src/http/vouch.rs",
        '    if field(status, "NoNewPrivs") != Some(1) {',
        '    if false && field(status, "NoNewPrivs") != Some(1) {',
    ),
    (
        "a traced worker is vouched for",
        "crates/dwkd-broker/src/http/vouch.rs",
        '    if field(status, "TracerPid") != Some(0) {',
        '    if false && field(status, "TracerPid") != Some(0) {',
    ),
    (
        "a dumpable worker is vouched for",
        "crates/dwkd-broker/src/http/vouch.rs",
        "    if owner == worker_uid {",
        "    if false && owner == worker_uid {",
    ),
    (
        "an attempt the worker reports not refused is believed",
        "crates/dwkd-broker/src/http/vouch.rs",
        "    if answers.iter().any(|code| *code != 0) {",
        "    if false && answers.iter().any(|code| *code != 0) {",
    ),
    (
        "an execute-only image fs.suid_dumpable starts dumpable by its uid closes the window",
        "crates/dwkd-broker/src/posture.rs",
        "matches!(self.suid_dumpable, Some(0 | 2))",
        "matches!(self.suid_dumpable, Some(0 | 1 | 2))",
    ),
    (
        "an execute-only binary closes the window whatever fs.suid_dumpable says",
        "crates/dwkd-broker/src/posture.rs",
        "(self.execute_only && matches!(self.suid_dumpable, Some(0 | 2)))",
        "self.execute_only",
    ),
    (
        "an unreadable fs.suid_dumpable counts as 0",
        "crates/dwkd-broker/src/posture.rs",
        '        "2" => Some(2),\n        _ => None,\n    }\n}\n\n/// Whether `(owner, mode)`',
        '        "2" => Some(2),\n        _ => Some(0),\n    }\n}\n\n/// Whether `(owner, mode)`',
    ),
    (
        "a worker is started where no verified program confines it",
        "crates/dwkd-broker/src/http/mod.rs",
        "        if !self.architecture_verified {",
        "        if false && !self.architecture_verified {",
    ),
    (
        "an open start-up window is not read before a hop",
        "crates/dwkd-broker/src/http/mod.rs",
        "        if posture.startup_window_closed() {",
        "        if true || posture.startup_window_closed() {",
    ),
    (
        "an open start-up window counts as acknowledged",
        "crates/dwkd-broker/src/http/mod.rs",
        "        if self.traceable == TraceableWorkers::Permitted {",
        "        if true || self.traceable == TraceableWorkers::Permitted {",
    ),
    (
        "swappable memory does not stop a credential hop",
        "crates/dwkd-broker/src/http/mod.rs",
        "        if swap.protected() {",
        "        if true || swap.protected() {",
    ),
    (
        "swappable memory counts as acknowledged",
        "crates/dwkd-broker/src/http/mod.rs",
        "        if self.swappable == SwappableWorkers::Permitted {",
        "        if true || self.swappable == SwappableWorkers::Permitted {",
    ),
    (
        "the broker's own memory is not judged before it reads a credential",
        "crates/dwkd-broker/src/http/mod.rs",
        "                    self.policy.admits_credential(None)\n",
        "                    Ok(())\n",
    ),
    (
        "the worker's memory is not judged before it is handed a credential",
        "crates/dwkd-broker/src/http/worker.rs",
        "        policy.admits_credential(Some(child.id()))?;\n",
        "        let _ = policy;\n",
    ),
    (
        "a non-zero swap cap counts as none",
        "crates/dwkd-broker/src/posture.rs",
        '.find(|(_, limit)| limit.as_deref().map(str::trim) == Some("0"))',
        ".find(|(_, limit)| limit.is_some())",
    ),
    (
        "unreadable swap counts as no swap device",
        "crates/dwkd-broker/src/posture.rs",
        "    if total_kib == Some(0) {",
        "    if total_kib.is_none() || total_kib == Some(0) {",
    ),
)


def task_d11_hardening_mutations() -> None:
    """Weaken each D11 guard in turn; the broker's suites must catch every
    one. Every file is restored byte-identically whatever happens, and
    checked. Never run it beside another build."""
    killed: list[str] = []
    for what, rel, old, new in D11_MUTATIONS:
        path = ROOT / rel
        original = path.read_bytes()
        digest = hashlib.sha256(original).hexdigest()
        text = original.decode("utf-8")
        if text.count(old) != 1:
            raise TaskError(f"mutation `{what}`: its target is not in {rel} exactly once")
        print(f"{BOLD}mutant: {what}{OFF}")
        outcome = "survived"
        try:
            path.write_bytes(text.replace(old, new).encode("utf-8"))
            try:
                run("cargo", "build", "--locked", "-p", "dwkd-broker")
                test_binary = broker_unit_binary()
            except TaskError:
                outcome = "did not compile"
            else:
                try:
                    output = run_captured(
                        test_binary,
                        "--test-threads=1",
                        "http::",
                        "posture::",
                        "config::",
                        "tests::the_broker_serves_only",
                        "tests::swappable_memory",
                    )
                    require_tests_ran(output)
                except TaskError as exc:
                    outcome = f"killed by the broker's suites: {str(exc)[:160]}"
        finally:
            path.write_bytes(original)
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise TaskError(f"{rel} was not restored byte-identically")
        print(f"{DIM}restored {rel} (sha256 {digest[:16]}...){OFF}")
        if not outcome.startswith("killed"):
            raise TaskError(f"mutant `{what}` {outcome}: nothing guards it")
        killed.append(what)
        print(f"{GREEN}mutant {outcome[:60]}: {what}{OFF}")
    print(
        f"{GREEN}D11 hardening mutation review: {len(killed)} of {len(D11_MUTATIONS)} killed{OFF}"
    )
    # The binary the suites last built was a mutant's: rebuild the original.
    run("cargo", "build", "--locked", "-p", "dwkd-broker")


# --- M5c: kernel-performed net.http (ADR-0050) --------------------------------

NET_EVIDENCE_PREFIX = "NET-EVIDENCE "

# M5c's evidence (ADR-0050 §16). Each (suite, case) is printed by exactly one
# test, after its assertions held; a missing one -- or one whose outcome says it
# was not exercised -- fails the task. The suites, and what they are:
#   broker-http               the broker's HTTPS client against REAL TLS origins
#                             in its own process (rustls servers on loopback,
#                             this run's PKI): rendering, framing, bounds,
#                             certificates, deadlines, the credential's render,
#                             the broker's own guard;
#   authority-net-pipeline    the authority's per-hop state machine against a
#                             FAKE broker: order, grants, per-address policy,
#                             the guard again, redirects, budgets, taint,
#                             obligations, outcomes, crash windows N1-N4. Not
#                             transport evidence;
#   authority-net-credential  mode A's consumer against a FAKE broker and REAL
#                             keyring values: origin binding, a use per hop,
#                             never across origins, a secret in a request,
#                             echoes redacted;
#   net-http                  the REAL broker binary, REAL local HTTPS origins,
#                             the fixture resolver and the authority's library:
#                             SSRF and DNS, HTTP and redirects, TLS, secrets
#                             and residue, crashes, keys, budgets, the shipped
#                             packs and taint.
NET_HTTP_CASES = (
    ("authority-net-credential", "credential-cross-origin-redirect"),
    ("authority-net-credential", "credential-same-origin-redirect"),
    ("authority-net-credential", "echoed-credential"),
    ("authority-net-credential", "runtime-sets-credential-header"),
    ("authority-net-credential", "secret-in-request-body"),
    ("authority-net-credential", "secret-in-request-header"),
    ("authority-net-credential", "secret-in-request-url"),
    ("authority-net-pipeline", "broker-lost-after-send"),
    ("authority-net-pipeline", "broker-refusal-before-send"),
    ("authority-net-pipeline", "budget-bytes"),
    ("authority-net-pipeline", "budget-never-refilled"),
    ("authority-net-pipeline", "budget-origins"),
    ("authority-net-pipeline", "budget-requests"),
    ("authority-net-pipeline", "crash-N1-after-resolve"),
    ("authority-net-pipeline", "crash-N2-after-intent"),
    ("authority-net-pipeline", "crash-N3-after-exchange"),
    ("authority-net-pipeline", "crash-N4-after-outcome"),
    ("authority-net-pipeline", "final-denial-before-resolution"),
    ("authority-net-pipeline", "guard-loopback-answer"),
    ("authority-net-pipeline", "guard-metadata-ip-answer"),
    ("authority-net-pipeline", "guard-mixed-answer"),
    ("authority-net-pipeline", "idempotency-key-reused"),
    ("authority-net-pipeline", "idempotency-one-namespace"),
    ("authority-net-pipeline", "metadata-name-before-resolution"),
    ("authority-net-pipeline", "no-resolution-without-grant"),
    ("authority-net-pipeline", "obligation-max-output-bytes"),
    ("authority-net-pipeline", "obligation-unenforceable"),
    ("authority-net-pipeline", "order-guard-intent-exchange"),
    ("authority-net-pipeline", "per-hop-reauthorisation-max-requests"),
    ("authority-net-pipeline", "policy-per-pinned-address"),
    ("authority-net-pipeline", "preview-without-address"),
    ("authority-net-pipeline", "protocol-v4-net-http"),
    ("authority-net-pipeline", "redirect-303-to-get"),
    ("authority-net-pipeline", "redirect-307-with-body"),
    ("authority-net-pipeline", "redirect-blocked-target"),
    ("authority-net-pipeline", "redirect-cross-origin-headers"),
    ("authority-net-pipeline", "redirect-downgrade"),
    ("authority-net-pipeline", "redirect-loop"),
    ("authority-net-pipeline", "redirect-metadata-name"),
    ("authority-net-pipeline", "redirect-mixed-target"),
    ("authority-net-pipeline", "redirect-not-followed"),
    ("authority-net-pipeline", "redirect-policy-denied"),
    ("authority-net-pipeline", "redirect-same-origin-pinned"),
    ("authority-net-pipeline", "redirect-sixth-hop"),
    ("authority-net-pipeline", "redirect-ungranted-host"),
    ("authority-net-pipeline", "resolution-failed"),
    ("authority-net-pipeline", "resolution-timeout"),
    ("authority-net-pipeline", "runtime-credential-header"),
    ("authority-net-pipeline", "taint-novel-destination"),
    ("authority-net-pipeline", "taint-seen-destination"),
    ("authority-net-pipeline", "url-digest-only-in-audit"),
    ("authority-net-pipeline", "userinfo-and-literals"),
    ("authority-net-pipeline", "worker-failed-before-send"),
    ("authority-net-pipeline", "worker-unconfirmed-after-send"),
    ("broker-http", "bad-chunk-size"),
    ("broker-http", "body-past-bound-cut"),
    ("broker-http", "broker-rejudges-pinned-addresses"),
    ("broker-http", "close-delimited"),
    ("broker-http", "concurrent-workers"),
    ("broker-http", "credential-composed-in-broker"),
    ("broker-http", "credential-header-injection-refused"),
    ("broker-http", "echo-body-redacted-before-encoding"),
    ("broker-http", "echo-header-dropped-whole"),
    ("broker-http", "echo-in-a-broken-response"),
    ("broker-http", "echo-straddling-the-bound"),
    ("broker-http", "exchange-in-a-worker"),
    ("broker-http", "evidence-ca-under-production-trust"),
    ("broker-http", "expired"),
    ("broker-http", "gzip"),
    ("broker-http", "head-parser-mutation"),
    ("broker-http", "head-past-64-kib"),
    ("broker-http", "header-bomb"),
    ("broker-http", "http-1-0"),
    ("broker-http", "http2-only-server"),
    ("broker-http", "length-and-chunked"),
    ("broker-http", "other-transfer-coding"),
    ("broker-http", "pinned-request-rendered"),
    ("broker-http", "redirect-not-followed-by-broker"),
    ("broker-http", "response-parser-mutation"),
    ("broker-http", "resolution-judged-whole"),
    ("broker-http", "self-signed"),
    ("broker-http", "slow-head"),
    ("broker-http", "stalled-body"),
    ("broker-http", "status-past-599"),
    ("broker-http", "switching-protocols"),
    ("broker-http", "tls-handshake-timeout"),
    ("broker-http", "truncated-body"),
    ("broker-http", "two-lengths"),
    ("broker-http", "two-locations"),
    ("broker-http", "untrusted-authority"),
    ("broker-http", "worker-closed-to-its-uid"),
    ("broker-http", "worker-killed-after-sending"),
    ("broker-http", "worker-killed-before-sending"),
    ("broker-http", "worker-overrun-killed"),
    ("broker-http", "worker-refuses-a-stranger"),
    ("broker-http", "worker-refuses-an-unpromised-hand-over"),
    ("broker-http", "worker-unavailable"),
    ("broker-http", "wrong-name"),
    ("net-http", "broker-killed-takes-its-worker"),
    ("net-http", "budget-redirect-hop"),
    ("net-http", "budget-requests"),
    ("net-http", "crash-after-exchange"),
    ("net-http", "crash-after-intent"),
    ("net-http", "crash-after-resolve"),
    ("net-http", "credential-bound-origin"),
    ("net-http", "credential-broker-residue-after-send"),
    ("net-http", "credential-cross-origin-redirect"),
    ("net-http", "credential-durable-state"),
    ("net-http", "credential-echo-broker-residue"),
    ("net-http", "credential-echo-redacted"),
    ("net-http", "credential-port-confusion"),
    ("net-http", "credential-same-origin-redirect"),
    ("net-http", "credential-unbound-origin"),
    ("net-http", "credential-worker-killed"),
    ("net-http", "dns-rebinding-next-request"),
    ("net-http", "dns-rebinding-pinned-within-request"),
    ("net-http", "dns-resolution-failed"),
    ("net-http", "dns-resolution-timeout"),
    ("net-http", "https-get-pinned"),
    ("net-http", "idempotency-key-reused"),
    ("net-http", "origin-confusion-backslash"),
    ("net-http", "origin-confusion-encoded-dot-segment"),
    ("net-http", "origin-confusion-idna-label"),
    ("net-http", "origin-confusion-port"),
    ("net-http", "origin-confusion-trailing-dot"),
    ("net-http", "origin-confusion-uppercase"),
    ("net-http", "origin-confusion-userinfo"),
    ("net-http", "plaintext-refused"),
    ("net-http", "policy-balanced"),
    ("net-http", "policy-power-internal-range"),
    ("net-http", "policy-safe"),
    ("net-http", "redirect-303-to-get"),
    ("net-http", "redirect-307-with-body"),
    ("net-http", "redirect-blocked-address"),
    ("net-http", "redirect-cross-origin"),
    ("net-http", "redirect-downgrade"),
    ("net-http", "redirect-loop"),
    ("net-http", "redirect-metadata-name"),
    ("net-http", "redirect-mixed-address"),
    ("net-http", "redirect-not-followed"),
    ("net-http", "redirect-same-origin"),
    ("net-http", "redirect-sixth-hop"),
    ("net-http", "redirect-ungranted-origin"),
    ("net-http", "response-101"),
    ("net-http", "response-bad-chunk-size"),
    ("net-http", "response-close-delimited"),
    ("net-http", "response-encoded"),
    ("net-http", "response-header-bomb"),
    ("net-http", "response-length-and-chunked"),
    ("net-http", "response-malformed-status"),
    ("net-http", "response-never-answers"),
    ("net-http", "response-past-the-bound"),
    ("net-http", "response-set-cookie"),
    ("net-http", "runtime-authorization-header"),
    ("net-http", "runtime-cookie-header"),
    ("net-http", "secret-in-request"),
    ("net-http", "ssrf-6to4"),
    ("net-http", "ssrf-ip-literal-decimal"),
    ("net-http", "ssrf-ip-literal-dotted"),
    ("net-http", "ssrf-ip-literal-hex"),
    ("net-http", "ssrf-ip-literal-octal"),
    ("net-http", "ssrf-ip-literal-v6"),
    ("net-http", "ssrf-ipv4-mapped"),
    ("net-http", "ssrf-ipv6-loopback"),
    ("net-http", "ssrf-loopback-not-excepted"),
    ("net-http", "ssrf-metadata-address"),
    ("net-http", "ssrf-metadata-name"),
    ("net-http", "ssrf-mixed-answer"),
    ("net-http", "ssrf-nat64"),
    ("net-http", "ssrf-private-answer"),
    ("net-http", "ssrf-teredo"),
    ("net-http", "ssrf-ungranted-host-not-resolved"),
    ("net-http", "taint-novel-destination"),
    ("net-http", "taint-seen-destination"),
    ("net-http", "tls-expired"),
    ("net-http", "tls-self-signed"),
    ("net-http", "tls-test-authority-under-production-trust"),
    ("net-http", "tls-untrusted-root"),
    ("net-http", "tls-wrong-name"),
)


# What the real-daemon net.http and mode A evidence needs, each with the one
# command that shows it usable here: the tool's own version spelling.
# OpenSSL's is `openssl version` -- before 3.2 it refuses `--version` with
# "Invalid command" and status 1, as Ubuntu 24.04's OpenSSL 3.0 does, which is
# how hosted run 37855884386 lost every real-daemon case to NOT EXERCISED.
EVIDENCE_TOOLS: tuple[tuple[str, ...], ...] = (
    ("bash", "--version"),
    ("openssl", "version"),
    ("python3", "--version"),
)


def unusable_tool(probes: tuple[tuple[str, ...], ...] = EVIDENCE_TOOLS) -> str | None:
    """The first probe that does not run and succeed, as its command and why;
    None when every one does. A name on PATH is not enough: the tool must run."""
    for probe in probes:
        shown = " ".join(probe)
        try:
            done = subprocess.run(
                list(probe),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
                timeout=60,
            )
        except FileNotFoundError:
            return f"`{shown}`: not found"
        except (OSError, subprocess.TimeoutExpired) as exc:
            return f"`{shown}` could not run: {exc}"
        if done.returncode != 0:
            return f"`{shown}` exited {done.returncode}"
    return None


def require_net_evidence(output: str, cases: tuple[tuple[str, str], ...]) -> None:
    """Every (suite, case) must have printed its NET-EVIDENCE line, exercised."""
    if not cases:
        raise TaskError("net.http evidence: zero cases required")
    reported: set[tuple[str, str]] = set()
    for line in output.splitlines():
        at = line.find(NET_EVIDENCE_PREFIX)
        if at < 0:
            continue
        try:
            record = json.loads(line[at + len(NET_EVIDENCE_PREFIX) :])
        except json.JSONDecodeError as exc:
            raise TaskError(f"unreadable evidence line: {line[:200]}") from exc
        if not isinstance(record, dict) or not record.get("outcome") or not record.get("suite"):
            raise TaskError(f"malformed evidence line: {line[:200]}")
        if str(record["outcome"]).lower().startswith("not-exercised"):
            continue
        reported.add((str(record["suite"]), str(record.get("case"))))
    missing = [f"{suite}/{case}" for suite, case in cases if (suite, case) not in reported]
    if missing:
        raise TaskError(
            f"NOT EXERCISED: {len(missing)} net.http evidence case(s) did not report: "
            + ", ".join(missing[:40])
        )
    print(f"{GREEN}net.http evidence: {len(cases)} cases reported{OFF}")
    # Judged and passed: kept for the M5 gate, by its own verdict (G-Q1).
    keep_judged("net-http", cases, NET_EVIDENCE_PREFIX, output)


def busy_processes(count: int) -> list[subprocess.Popen[bytes]]:
    """`count` processes that do nothing but spin: CPU contention for an
    evidence run (DW_CPU_CONTENTION). The caller stops them."""
    return [
        subprocess.Popen(
            [sys.executable, "-c", "while True: pass"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        for _ in range(count)
    ]


def task_net_http_evidence() -> None:
    """M5c net.http (ADR-0050 §16) on real processes, no internet.

    The broker's HTTPS client against real TLS origins; the authority's
    per-hop pipeline and mode A's consumer against a fake broker; and the real
    broker binary with local HTTPS origins (tests/net_http/origin.py, a PKI
    made for the run), the fixture resolver and the authority's library. Every
    case of NET_HTTP_CASES is required. DW_CPU_CONTENTION=<n> runs it all
    beside n spinning processes. Linux only; needs openssl and python3.
    """
    if not sys.platform.startswith("linux"):
        raise TaskError(
            "NOT EXERCISED: the net.http evidence runs only on Linux (ADR-0050 §19); "
            "use WSL2 on Windows"
        )
    missing = unusable_tool()
    if missing is not None:
        raise TaskError(
            f"NOT EXERCISED: the net.http evidence needs bash, openssl and python3: {missing}"
        )
    contention = os.environ.get("DW_CPU_CONTENTION", "").strip()
    if contention and not contention.isdigit():
        raise TaskError(f"DW_CPU_CONTENTION={contention}: not a count of processes")
    run("cargo", "build", "--locked", "-p", "dwkd-broker")
    busy = busy_processes(int(contention or "0"))
    if busy:
        print(f"{BOLD}under CPU contention: {len(busy)} spinning process(es){OFF}")
    try:
        suites = [
            run_captured(
                "cargo",
                "test",
                "--locked",
                "-p",
                "dwkd-broker",
                "--bins",
                "http::",
                "--",
                "--nocapture",
            ),
            run_captured(
                "cargo",
                "test",
                "--locked",
                "-p",
                "dwkd-authority",
                "--lib",
                "state::net_http",
                "--",
                "--nocapture",
            ),
            run_captured(
                "cargo",
                "test",
                "--locked",
                "-p",
                "dwkd-authority",
                "--lib",
                "state::secret_use",
                "--",
                "--nocapture",
                fresh_keyring=True,
            ),
            run_captured(
                "cargo",
                "test",
                "--locked",
                "-p",
                "dwkd-authority",
                "--test",
                "net_http_evidence",
                "--",
                "--nocapture",
                "--test-threads=1",
                fresh_keyring=True,
            ),
        ]
    finally:
        for process in busy:
            process.kill()
            process.wait()
    for output in suites:
        require_tests_ran(output)
    require_net_evidence("\n".join(suites), NET_HTTP_CASES)
    uvrun("dwcheck", "closure", "--report")


# The mutation review (ADR-0050 §16): each line weakens one safeguard the
# evidence exists to prove, in the source, one at a time. Each mutant must
# compile and must fail `net-http-evidence`; the file is then restored, and
# its SHA-256 proves it byte-identical. A mutant that survives, or does not
# compile, fails the review.
NET_HTTP_MUTATIONS = (
    (
        "the shared IP guard blocks nothing",
        "crates/dwk-proto/src/wire/guard.rs",
        ".filter(|address| blocked(**address) && !exceptions.contains(address))",
        ".filter(|address| blocked(**address) && !exceptions.contains(address) && false)",
    ),
    (
        "a pinned host is resolved again on every hop",
        "crates/dwkd-authority/src/state/net_http/mod.rs",
        "if let Some(pinned) = chain.pins.get(hop.host()) {",
        "if let Some(pinned) = chain.pins.get(hop.host()).filter(|_| false) {",
    ),
    (
        "a redirect hop is sent whatever its gates decided",
        "crates/dwkd-authority/src/state/net_http/ledger.rs",
        "    if !plan.permits() {",
        "    if first && !plan.permits() {",
    ),
    (
        "the credential follows a redirect to another origin",
        "crates/dwkd-authority/src/state/net_http/mod.rs",
        "credential: home && canonical.credential.is_some(),",
        "credential: canonical.credential.is_some(),",
    ),
    (
        "the call's response bound is ignored",
        "crates/dwkd-authority/src/state/net_http/mod.rs",
        ".map_or(RESPONSE_LIMIT, |l| l.get().min(RESPONSE_LIMIT))",
        ".map_or(RESPONSE_LIMIT, |_| RESPONSE_LIMIT)",
    ),
    (
        "no hop is debited from the run's budget",
        "crates/dwkd-authority/src/state/net_http/ledger.rs",
        "count(DISTINCT host || ':' || port) FROM net_hop WHERE run_id = ?1\",",
        "count(DISTINCT host || ':' || port) FROM net_hop WHERE run_id = ?1 AND 0\",",
    ),
    # D11: the broker takes the hop's own credential out of what comes back.
    (
        "a response header holding the credential is copied into the answer",
        "crates/dwkd-broker/src/http/mod.rs",
        ".is_some_and(|needle| needle.found_in(value.as_bytes()))",
        ".is_some_and(|needle| needle.found_in(value.as_bytes()) && false)",
    ),
    (
        "an echo straddling the response bound is cut before it is redacted",
        "crates/dwkd-broker/src/http/mod.rs",
        "let past = self.needle.as_ref().map_or(0, |needle| needle.len());",
        "let past = self.needle.as_ref().map_or(0, |_| 0);",
    ),
    # D11's worker process: closed to its own uid, and handed only what it
    # was promised.
    (
        "the exchange worker stays dumpable while it holds a hop",
        "crates/dwkd-broker/src/hardening.rs",
        "&& set_dumpable_behavior(DumpableBehavior::NotDumpable).is_ok()",
        "&& true",
    ),
    # The count is the gate for one or two descriptors too many: the
    # ancillary buffer has room for four, so only five or more truncate.
    (
        "the exchange worker takes a hand-over with a descriptor too many",
        "crates/dwkd-broker/src/http/worker.rs",
        "let credential = if fds.len() == 2 { fds.pop() } else { None };",
        "fds.truncate(2);\n    let credential = if fds.len() == 2 { fds.pop() } else { None };",
    ),
)


def task_net_http_mutations() -> None:
    """Weaken each net.http safeguard in turn; the evidence must catch every one.

    Slow (the whole net-http-evidence per mutant). Every file is restored
    byte-identically whatever happens, and checked.
    """
    killed: list[str] = []
    for what, rel, old, new in NET_HTTP_MUTATIONS:
        path = ROOT / rel
        original = path.read_bytes()
        digest = hashlib.sha256(original).hexdigest()
        text = original.decode("utf-8")
        if text.count(old) != 1:
            raise TaskError(f"mutation `{what}`: its target is not in {rel} exactly once")
        print(f"{BOLD}mutant: {what}{OFF}")
        outcome = "survived"
        try:
            path.write_bytes(text.replace(old, new).encode("utf-8"))
            try:
                run(
                    "cargo",
                    "test",
                    "--locked",
                    "--no-run",
                    "-p",
                    "dwk-proto",
                    "-p",
                    "dwkd-broker",
                    "-p",
                    "dwkd-authority",
                )
            except TaskError:
                outcome = "did not compile"
            else:
                try:
                    task_net_http_evidence()
                except TaskError as exc:
                    outcome = f"killed: {str(exc)[:160]}"
        finally:
            path.write_bytes(original)
        if hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            raise TaskError(f"{rel} was not restored byte-identically")
        print(f"{DIM}restored {rel} (sha256 {digest[:16]}...){OFF}")
        if not outcome.startswith("killed"):
            raise TaskError(f"mutant `{what}` {outcome}: the evidence does not guard it")
        killed.append(what)
        print(f"{GREEN}mutant killed: {what}{OFF}")
    print(
        f"{GREEN}net.http mutation review: {len(killed)} of {len(NET_HTTP_MUTATIONS)} killed{OFF}"
    )


def require_sandbox_evidence(
    output: str, cases: tuple[tuple[str, str], ...]
) -> list[dict[str, object]]:
    """Every (suite, case) must have printed its SANDBOX-EVIDENCE line, exercised."""
    reported: set[tuple[str, str]] = set()
    records: list[dict[str, object]] = []
    for line in output.splitlines():
        at = line.find(SANDBOX_EVIDENCE_PREFIX)
        if at < 0:
            continue
        try:
            record = json.loads(line[at + len(SANDBOX_EVIDENCE_PREFIX) :])
        except json.JSONDecodeError as exc:
            raise TaskError(f"unreadable evidence line: {line[:200]}") from exc
        if not isinstance(record, dict) or not record.get("outcome") or not record.get("suite"):
            raise TaskError(f"malformed evidence line: {line[:200]}")
        if str(record["outcome"]).lower().startswith("not-exercised"):
            continue
        reported.add((str(record["suite"]), str(record.get("case"))))
        records.append(record)
    missing = [f"{suite}/{case}" for suite, case in cases if (suite, case) not in reported]
    if missing:
        raise TaskError(
            f"NOT EXERCISED: {len(missing)} sandbox evidence case(s) did not report: "
            + ", ".join(missing[:40])
        )
    print(f"{GREEN}sandbox evidence: {len(cases)} cases reported{OFF}")
    return records


def _proc_evidence(output: str) -> set[tuple[str, str]]:
    """Every (suite, case) a PROC-EVIDENCE line reported as exercised."""
    reported: set[tuple[str, str]] = set()
    for line in output.splitlines():
        at = line.find(PROC_EVIDENCE_PREFIX)
        if at < 0:
            continue
        try:
            record = json.loads(line[at + len(PROC_EVIDENCE_PREFIX) :])
        except json.JSONDecodeError as exc:
            raise TaskError(f"unreadable evidence line: {line[:200]}") from exc
        if not isinstance(record, dict) or not record.get("outcome") or not record.get("suite"):
            raise TaskError(f"malformed evidence line: {line[:200]}")
        if str(record["outcome"]).startswith("not-exercised"):
            continue
        reported.add((str(record["suite"]), str(record.get("case"))))
    return reported


def require_proc_evidence(output: str, cases: tuple[tuple[str, str], ...]) -> None:
    """Every (suite, case) must have printed its evidence line, exercised."""
    if not cases:
        raise TaskError("process-execution evidence: zero cases required")
    reported = _proc_evidence(output)
    missing = [f"{suite}/{case}" for suite, case in cases if (suite, case) not in reported]
    if missing:
        raise TaskError(
            "process-execution evidence incomplete, not reported: " + ", ".join(missing)
        )
    print(f"{GREEN}process-execution evidence: {len(cases)} cases reported{OFF}")


def require_proc_foreign_evidence(output: str) -> None:
    """The three-identity suite counts only if every test ran and every case reported."""
    summaries = [line for line in output.splitlines() if line.startswith("test result: ")]
    expected = f"test result: ok. {len(PROC_FOREIGN_TESTS)} passed; 0 failed; 0 ignored"
    if len(summaries) != 1 or not summaries[0].startswith(expected):
        raise TaskError(
            f"the three-identity suite did not run all of its tests: expected `{expected}`, "
            f"got {summaries or 'no summary'}"
        )
    require_proc_evidence(output, PROC_FOREIGN_CASES)


def task_authority_write_probe() -> None:
    """Attempt the runtime's forbidden writes as a SECOND operating-system user.

    Creates an authority state directory as the current user, then runs
    `tests/authority/runtime_write_probe.py` as the user named by
    DW_PROBE_AS through `sudo -n -u`. Every write must be refused.

    Needs two real identities. When DW_PROBE_AS is unset, or sudo cannot switch
    to it without a password, the probe is NOT EXERCISED and this task fails --
    it never reports a pass it did not earn. Mode bits alone are not the claim
    (ADR-0035): the claim is that the write was attempted and refused.
    """
    user = os.environ.get("DW_PROBE_AS")
    if not user:
        raise TaskError(
            "NOT EXERCISED: set DW_PROBE_AS to the runtime's user (e.g. `nobody`) and run "
            "where `sudo -n -u $DW_PROBE_AS` works"
        )
    import tempfile

    parent = Path(tempfile.mkdtemp(prefix="dw-probe-"))
    parent.chmod(0o755)  # the probe user may reach the state directory, not enter it
    state = parent / "state"
    env = {**os.environ, "DW_PROBE_STATE_DIR": str(state)}
    command = [
        "cargo",
        "test",
        "--locked",
        "-p",
        "dwkd-authority",
        "--test",
        "state_probe",
        "create_probe_state",
        "--",
        "--ignored",
        "--nocapture",
    ]
    print(f"{DIM}$ DW_PROBE_STATE_DIR={state} {' '.join(command)}{OFF}", flush=True)
    if subprocess.run(command, cwd=str(ROOT), env=env, check=False).returncode != 0:
        raise TaskError("the probe state could not be created")
    probe = ROOT / "tests" / "authority" / "runtime_write_probe.py"
    staged = parent / "runtime_write_probe.py"
    shutil.copyfile(probe, staged)
    staged.chmod(0o644)
    # The system interpreter, not this checkout's virtualenv: the probe is
    # standard-library only, and the second user may not be able to reach a
    # virtualenv under the first user's home directory.
    interpreter = "/usr/bin/python3" if Path("/usr/bin/python3").exists() else sys.executable
    result = subprocess.run(
        ["sudo", "-n", "-u", user, interpreter, str(staged), str(state)],
        check=False,
    )
    if result.returncode == 0:
        return
    if result.returncode == 1:
        raise TaskError(f"the runtime user {user!r} could write authority state")
    raise TaskError(
        f"NOT EXERCISED (exit {result.returncode}): the probe could not run as {user!r}"
    )


def task_fuzz() -> None:
    """Coverage-guided libFuzzer run of every target (nightly, cargo-fuzz).

    Two surfaces: the DWKP decoder and the M3c policy loader.
    """
    seconds = os.environ.get("DW_FUZZ_SECONDS", "60")
    if not seconds.isdigit() or int(seconds) < 1:
        raise TaskError("DW_FUZZ_SECONDS must be a positive whole number of seconds")
    if shutil.which("cargo-fuzz") is None:
        raise TaskError(
            "cargo-fuzz is not installed:\n"
            f"  rustup toolchain install {FUZZ_NIGHTLY} --profile minimal\n"
            f"  cargo install cargo-fuzz --version {CARGO_FUZZ_VERSION} --locked\n"
            "libFuzzer also needs a C++ compiler. `make fuzz-smoke` runs on stable without one."
        )
    by_surface = {
        **{t: _fuzz_seeds() for t in PROTO_FUZZ_TARGETS},
        **{t: _policy_fuzz_seeds() for t in POLICY_FUZZ_TARGETS},
    }
    for target in FUZZ_TARGETS:
        seeds = by_surface[target]
        corpus = ROOT / "fuzz" / "corpus" / target
        corpus.mkdir(parents=True, exist_ok=True)
        for seed in seeds:
            (corpus / f"vector-{hashlib.sha256(seed).hexdigest()[:16]}").write_bytes(seed)
        print(f"{DIM}seeded fuzz/corpus/{target} with {len(seeds)} vectors{OFF}")
        run(
            "cargo",
            f"+{FUZZ_NIGHTLY}",
            "fuzz",
            "run",
            target,
            "--",
            f"-max_total_time={seconds}",
        )


def task_security() -> None:
    """Dependency and supply-chain policy.

    Both halves run even if one is unavailable, and the failures are reported
    together: a missing cargo-deny must not be able to hide a pip-audit
    finding by aborting first.
    """
    failures = []

    if shutil.which("cargo-deny") is None:
        failures.append("cargo-deny is not installed; run `make tools`. The Rust half did not run.")
    else:
        for manifest, config in (
            (None, None),
            # The fuzz workspace has its own lockfile, so the root policy does
            # not see it, and its own policy, so fuzz-only crates never leak
            # into the product allowlist (fuzz/deny.toml explains the split).
            ("fuzz/Cargo.toml", "fuzz/deny.toml"),
        ):
            command = ["cargo", "deny", "--all-features"]
            if manifest is not None:
                command += ["--manifest-path", manifest, "--config", config or ""]
            try:
                run(*command, "check")
            except TaskError as exc:
                failures.append(str(exc))

    try:
        requirements = ROOT / "target" / "requirements-audit.txt"
        requirements.parent.mkdir(parents=True, exist_ok=True)
        uv(
            "export",
            "--frozen",
            "--all-packages",
            "--no-emit-workspace",
            "--format",
            "requirements-txt",
            "-o",
            str(requirements),
        )
        uvrun("pip_audit", "-r", str(requirements), "--strict", "--progress-spinner", "off")
    except TaskError as exc:
        failures.append(str(exc))

    if failures:
        joined = "\n  ".join(["supply-chain checks did not pass:", *failures])
        raise TaskError(joined)


def task_check() -> None:
    """Everything CI runs, in the order that fails fastest."""
    for name in (
        "fmt-check",
        "lint",
        "typecheck",
        "arch",
        "schema-check",
        "test",
        "eval-check",
        "security",
    ):
        print(f"\n{BOLD}=== {name} ==={OFF}")
        TASKS[name]()
    print(f"\n{GREEN}All checks passed.{OFF}")


def task_docs() -> None:
    """Check relative links and ADR citations across the docs."""
    uvrun("dwcheck", "--root", str(ROOT), "links")


def task_clean() -> None:
    """Remove build output, the virtualenv and tool caches."""
    for path in ("target", ".venv", ".mypy_cache", ".ruff_cache", ".pytest_cache"):
        target = ROOT / path
        if target.exists():
            print(f"{DIM}removing {path}{OFF}")
            shutil.rmtree(target, ignore_errors=True)


def task_hooks() -> None:
    """Install the optional pre-commit hook (fast checks only)."""
    hooks_dir = ROOT / ".git" / "hooks"
    if not hooks_dir.is_dir():
        raise TaskError("no .git/hooks directory; is this a git checkout?")
    source = ROOT / "scripts" / "hooks" / "pre-commit"
    destination = hooks_dir / "pre-commit"
    destination.write_text(source.read_text(encoding="utf-8"), encoding="utf-8", newline="\n")
    destination.chmod(0o755)
    print(f"installed {destination}")
    print(f"{DIM}It runs fmt-check and arch only. Remove it with: rm .git/hooks/pre-commit{OFF}")


# ---- M5e.6: the M5 gate ------------------------------------------------------
#
# The M5 gate (M5E6_PREPARATION_HANDOFF.md §§5-6) judges every M5 evidence
# task's own output again, in the run that produced it, and adds what no task
# can check alone: that every task ran in this run, on this commit, on a
# disposable GitHub-hosted runner, and that together they cover the whole
# attributed inventory.
#
# G1: each task of the gate, once all of its own checks have passed, keeps
# exactly what it judged -- each judging call's text, with the judge, its case
# table and its line prefix -- and its cleanup census, under
# `target/m5e-evidence/<task>/`. The task runner keeps it
# (`save_judged_evidence`), never the task's own code, so a task that fails
# keeps nothing; and before the task starts it forgets whatever an earlier
# process or a restored build cache left there (`forget_kept`). A later step
# of the same job, `make m5e-evidence-bundle`, checks it byte for byte and
# seals it with the run's provenance, on a disposable GitHub-hosted runner
# only; the job then uploads that task's directory and nothing else.
#
# G2: the `m5e-gate` job downloads this run's bundles, and `make
# m5e-gate-check` judges them (`m5e_gate_verdict`): every expected bundle
# once; each of this run and this commit, from a GitHub-hosted runner and the
# job that runs its task; each file at its digest; each output judged again by
# the very function that judged it, against the same table; the union of the
# attributed cases equal to the inventory, less the tables not yet required;
# a clean census from every task that makes containers. It then prints the M5e
# acceptance verdict, which the `m5e-gate` eval enforces once `M5e` is
# available (G3).

# Each task of the gate, and the CI job that runs it (`.github/workflows/ci.yml`;
# `tests/architecture/test_ci_m5e_gate.py` holds the two equal). The last four
# judge their own output in their own way, and join by that verdict (G-Q1).
M5E_GATE_TASKS: dict[str, str] = {
    "sandbox-foundation-evidence": "sandbox-foundation",
    "sandbox-egress-evidence": "sandbox-egress",
    "sandbox-workload-evidence": "sandbox-workload",
    "sandbox-secret-evidence": "sandbox-secret",
    "sandbox-workspace-evidence": "sandbox-workspace",
    "sandbox-restart-evidence": "sandbox-restart",
    "sandbox-capacity-evidence": "sandbox-capacity",
    "sandbox-registry-evidence": "sandbox-registry",
    "sandbox-proxy-weakened-evidence": "sandbox-proxy-weakened",
    "sandbox-agent-evidence": "sandbox-agent",
    "sandbox-release-evidence": "sandbox-release",
    "net-http-evidence": "net-http",
    "eval-check": "evals",
}
# What each task of the gate must have judged on its hosted run: (the judge,
# the case table), each once. The workspace task's hosted run judges both of
# its halves as one table; the agent task's, its three-identity half too.
M5E_GATE_JUDGEMENTS: dict[str, tuple[tuple[str, str], ...]] = {
    "sandbox-foundation-evidence": (
        ("attributed", "BROKER_ASSURANCE_CASES"),
        ("attributed", "SANDBOX_CASES"),
    ),
    "sandbox-egress-evidence": (
        ("attributed", "EGRESS_CASES"),
        ("attributed", "CAPTURED_ASSURANCE_CASES"),
    ),
    "sandbox-workload-evidence": (("attributed", "WORKLOAD_CASES"),),
    "sandbox-secret-evidence": (
        ("attributed", "SECRET_SANDBOX_UNIT_CASES"),
        ("attributed", "SECRET_SANDBOX_CASES"),
    ),
    "sandbox-workspace-evidence": (
        ("attributed", "WORKSPACE_UNIT_CASES"),
        ("attributed", "WORKSPACE_ALL_CASES"),
    ),
    "sandbox-restart-evidence": (("attributed", "RESTART_CASES"),),
    "sandbox-capacity-evidence": (("attributed", "CAPACITY_CASES"),),
    "sandbox-registry-evidence": (("attributed", "REGISTRY_CASES"),),
    "sandbox-proxy-weakened-evidence": (("attributed", "E6_CASES"),),
    "sandbox-agent-evidence": (("agent", "AGENT_CASES"), ("agent", "AGENT_IDENTITY_CASES")),
    "sandbox-release-evidence": (
        ("release", "RELEASE_UNIT_CASES"),
        ("release", "RELEASE_CASES"),
    ),
    "net-http-evidence": (("net-http", "NET_HTTP_CASES"),),
    "eval-check": (("eval", "M5_EVAL_CASES"),),
}
# The tasks of the gate that make no container, network or mount, and so
# report no census of their own.
M5E_CENSUS_FREE: dict[str, str] = {
    "net-http-evidence": "its origins, resolver and broker are the test's own processes",
    "eval-check": "its M5 suites run each evidence task as a child, which fails on its own census",
}
# The attributed tables no task of the gate requires yet: M5e.5's evidence
# runs only in its manual workflow until M5e.5's acceptance change makes
# `sandbox-hygiene` a required job.
M5E_NOT_YET_REQUIRED: tuple[str, ...] = ("HYGIENE_CASES",)
# The M5 eval suites' own verdicts, which the `evals` job keeps: one eval each.
M5_EVAL_CASES = (
    ("m5a-sandbox-foundation", "oci-strict-measured-assurance"),
    ("m5b-sandbox-egress", "proxy-only-egress"),
    ("m5c-net-http", "kernel-performed-net-http"),
    ("m5d-sandbox-exec", "sandboxed-exec-and-release-teardown"),
)
EVAL_RESULTS = ROOT / "target" / "evals" / "results.jsonl"
# The line prefix each judge reads; None: the prefix kept with the output.
M5E_JUDGE_PREFIX: dict[str, str | None] = {
    "attributed": None,
    "agent": SANDBOX_EVIDENCE_PREFIX,
    "release": SANDBOX_EVIDENCE_PREFIX,
    "net-http": NET_EVIDENCE_PREFIX,
    "eval": "",
}
# What makes `M5e` ready to join the available milestones (the handoff's
# §§6.4, 9), besides a complete inventory: each record's status, and the
# plan's records of each step's closure or acceptance.
M5E_ACCEPTANCE_ADRS = (
    ("0054", "Accepted"),
    ("0055", "Accepted"),
    ("0057", "Superseded"),
    ("0058", "Accepted"),
    ("0059", "Accepted"),
)
M5E_ACCEPTANCE_RECORDS = (
    "**M5e.2's closure (",
    "**M5e.4's acceptance (",
    "**M5e.5's acceptance (",
)
M5E_EVIDENCE_DIR = ROOT / "target" / "m5e-evidence"
M5E_GATE_DIR = ROOT / "target" / "m5e-gate"
M5E_GATE_JOB = "m5e-gate"
M5E_KEPT_SCHEMA = "direwolf.m5e.judged-evidence"
M5E_BUNDLE_SCHEMA = "direwolf.m5e.evidence-bundle"
# 2 (G2): each judged output names the function that judged it.
M5E_BUNDLE_VERSION = 2
# Each file the gate reads is at most this large, checked before it is read.
M5E_GATE_MAX_FILE = 32 * 1024 * 1024
# What this process judged and passed, and the census lines it reported.
_JUDGED: list[tuple[str, str | None, str, str]] = []
_CLEANUP: list[str] = []
_JUDGED_FILE = re.compile(r"judged-[0-9]{1,3}\.txt")
_CLEAN_CENSUS = re.compile(r"cleanup: no [^\n]{1,300}")
_COMMIT_SHA = re.compile(r"[0-9a-f]{40}")
_RUN_NUMBER = re.compile(r"[1-9][0-9]{0,19}")
_INVENTORY_VERDICT = "M5 gate: inventory verdict: COMPLETE"


def report_cleanup(text: str) -> None:
    """Print a task's cleanup census and keep it for the M5 gate."""
    print(f"{GREEN}{text}{OFF}")
    _CLEANUP.append(text)


def _table_name(cases: tuple[tuple[str, str], ...]) -> str | None:
    """The module-level name of a case table; None for one made elsewhere (a
    test's own), which nothing keeps."""
    names = [name for name, value in globals().items() if value is cases and name.isupper()]
    return names[0] if len(names) == 1 else None


def _case_table(name: object) -> tuple[tuple[str, str], ...] | None:
    """The module-level case table `name` names: a tuple of (suite, case)."""
    if not isinstance(name, str) or not name.isupper():
        return None
    value = globals().get(name)
    if not isinstance(value, tuple) or not value:
        return None
    pairs = all(
        isinstance(item, tuple) and len(item) == 2 and all(isinstance(s, str) for s in item)
        for item in value
    )
    return value if pairs else None


def keep_judged(judge: str, cases: tuple[tuple[str, str], ...], prefix: str, output: str) -> None:
    """Keep what `judge` judged and passed, for the M5 gate: the task runner
    writes it if this process's task is a task of the gate."""
    _JUDGED.append((judge, _table_name(cases), prefix, output))


def require_m5_eval_results(
    output: str, cases: tuple[tuple[str, str], ...]
) -> list[dict[str, object]]:
    """The M5 suites' own verdicts in the eval gate's results
    (`target/evals/results.jsonl`): every eval of `cases` reported, every one
    of its runs a pass at score 1.0. An unreadable line, an M5 suite's eval
    that `cases` does not list, a run reported twice or missing, or a result
    of another version fails. Other suites' lines are not this judge's."""
    if not cases:
        raise TaskError("M5 eval verdicts: zero evals required")
    suites = {suite for suite, _ in cases}
    runs: dict[tuple[str, str], list[dict[str, object]]] = {}
    problems: list[str] = []
    for line in output.splitlines():
        if not line.strip():
            continue
        try:
            record = _strict_json(line)
        except (ValueError, TaskError) as exc:
            raise TaskError(f"unreadable eval result: {line[:200]}") from exc
        if not isinstance(record, dict):
            raise TaskError(f"malformed eval result: {line[:200]}")
        suite, eval_id = record.get("suite"), record.get("eval_id")
        if suite not in suites:
            continue
        if not isinstance(eval_id, str) or not eval_id.startswith(f"{suite}/"):
            problems.append(f"{suite}: a result whose id {eval_id!r} is not its suite's")
            continue
        key = (str(suite), eval_id.removeprefix(f"{suite}/"))
        if key not in cases:
            problems.append(f"{eval_id}: an M5 eval the gate does not list")
            continue
        runs.setdefault(key, []).append(record)
    for key in cases:
        named = "/".join(key)
        got = runs.get(key, [])
        if not got:
            problems.append(f"{named}: no result")
            continue
        # Every run once: one count, said alike by each run, and each index of
        # it reported. Anything not an integer is no count and no index.
        said = [record.get("runs") for record in got]
        count = said[0]
        indices = sorted(
            index
            for index in (record.get("run_index") for record in got)
            if isinstance(index, int) and not isinstance(index, bool)
        )
        if (
            not isinstance(count, int)
            or isinstance(count, bool)
            or count < 1
            or any(other != count or isinstance(other, bool) for other in said)
            or indices != list(range(count))
        ):
            problems.append(f"{named}: its runs are not each reported once")
        for record in got:
            status, score = record.get("status"), record.get("score")
            if record.get("result_version") != 1:
                problems.append(f"{named}: a result of version {record.get('result_version')!r}")
            if status != "pass" or isinstance(score, bool) or score != 1.0:
                problems.append(f"{named}: {status!r} at score {score!r}, not a pass at 1.0")
    if problems:
        raise TaskError(
            f"{len(problems)} M5 eval verdict(s) not a pass: " + "; ".join(problems[:20])
        )
    print(f"{GREEN}M5 eval verdicts: {len(cases)} evals passed, every run at 1.0{OFF}")
    keep_judged("eval", cases, "", output)
    return [record for key in cases for record in runs[key]]


def _rejudge(judge: str, output: str, cases: tuple[tuple[str, str], ...], prefix: str) -> None:
    """Judge `output` again by the function that judged it."""
    if judge == "attributed":
        require_attributed_evidence(output, cases, prefix)
    elif judge == "agent":
        require_agent_evidence(output, cases)
    elif judge == "release":
        require_release_evidence(output, cases)
    elif judge == "net-http":
        require_net_evidence(output, cases)
    elif judge == "eval":
        require_m5_eval_results(output, cases)
    else:
        raise TaskError(f"{judge!r} is no judge of the M5 gate")


def m5e_keeps(task: str, environ: Mapping[str, str]) -> bool:
    """Whether the task runner keeps `task`'s judgement for the M5 gate: every
    task of the gate, but the eval gate only when it is strict. Lenient -- a
    contributor's machine -- its M5 suites may be NOT EXERCISED, and nothing
    reads what it would keep."""
    if task not in M5E_GATE_TASKS:
        return False
    return task != "eval-check" or eval_gate_is_strict(environ)


def forget_kept(task: str, root: Path = M5E_EVIDENCE_DIR) -> None:
    """Remove what was kept for `task`, before it runs: an earlier process's,
    or a restored build cache's (the setup action caches `target/`)."""
    directory = root / task
    if directory.exists():
        try:
            shutil.rmtree(directory)
        except OSError as exc:
            raise TaskError(f"what was kept for {task} cannot be removed: {exc}") from exc


def _strict_json(text: str) -> object:
    """JSON with no repeated key and no NaN or infinity."""

    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        keys = [key for key, _ in items]
        if len(keys) != len(set(keys)):
            raise TaskError(f"a repeated key among {keys}")
        return dict(items)

    def constant(name: str) -> object:
        raise TaskError(f"{name} is not JSON")

    return json.loads(text, object_pairs_hook=pairs, parse_constant=constant)


def _read_bounded_json(path: Path, what: str) -> object:
    """`path`'s strict JSON, refused before it is read if it is too large."""
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise TaskError(f"{what}: {path.name} is unreadable: {exc}") from exc
    if size > M5E_GATE_MAX_FILE:
        raise TaskError(f"{what}: {path.name} is {size} bytes, over {M5E_GATE_MAX_FILE}")
    try:
        return _strict_json(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, ValueError, TaskError) as exc:
        raise TaskError(f"{what}: {path.name} is unreadable: {exc}") from exc


def save_judged_evidence(
    task: str,
    root: Path = M5E_EVIDENCE_DIR,
    judged: Sequence[tuple[str, str | None, str, str]] | None = None,
    cleanup: Sequence[str] | None = None,
) -> Path:
    """Keep what `task` judged, after all of its checks passed: each judged
    output as `judged-<n>.txt`, its judge, case table, prefix, SHA-256 and
    size in `judged.json`, with its cleanup census. Refuses a task outside the
    gate, one that judged nothing, a table with no name, an unknown judge, and
    no census from a task that makes containers."""
    judged = list(_JUDGED if judged is None else judged)
    cleanup = list(_CLEANUP if cleanup is None else cleanup)
    if task not in M5E_GATE_TASKS:
        raise TaskError(f"{task} is not a task of the M5 gate")
    if not judged:
        raise TaskError(f"{task} judged no evidence: nothing to keep for the M5 gate")
    if not cleanup and task not in M5E_CENSUS_FREE:
        raise TaskError(f"{task} reported no cleanup census: nothing to keep for the M5 gate")
    if any(table is None for _, table, _, _ in judged):
        raise TaskError(f"{task} judged an output against a case table with no name")
    if any(judge not in M5E_JUDGE_PREFIX for judge, _, _, _ in judged):
        raise TaskError(f"{task} judged an output by no judge of the M5 gate")
    directory = root / task
    if directory.exists():
        shutil.rmtree(directory)
    directory.mkdir(parents=True)
    files: list[dict[str, object]] = []
    for number, (judge, table, prefix, output) in enumerate(judged):
        data = output.encode("utf-8")
        name = f"judged-{number}.txt"
        (directory / name).write_bytes(data)
        files.append(
            {
                "file": name,
                "judge": judge,
                "table": table,
                "prefix": prefix,
                "sha256": hashlib.sha256(data).hexdigest(),
                "bytes": len(data),
            }
        )
    record = {
        "schema": M5E_KEPT_SCHEMA,
        "version": M5E_BUNDLE_VERSION,
        "task": task,
        "judged": files,
        "cleanup": cleanup,
    }
    (directory / "judged.json").write_text(
        json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
    )
    print(
        f"{DIM}kept for the M5 gate: {len(files)} judged output(s) and {len(cleanup)} "
        f"census line(s) in {directory}{OFF}"
    )
    return directory


def _kept_judgements(
    directory: Path, task: str, kept: object, beside: frozenset[str] = frozenset()
) -> list[dict[str, object]]:
    """`task`'s kept record checked against its directory: its fields, its
    census, each judged output's judge, table, prefix and file at its digest,
    and no file but those, `judged.json` and `beside`."""
    fields = {"schema", "version", "task", "judged", "cleanup"}
    if not isinstance(kept, dict) or set(kept) != fields:
        raise TaskError(f"{task}'s judged.json does not have exactly {sorted(fields)}")
    if (kept["schema"], kept["version"], kept["task"]) != (
        M5E_KEPT_SCHEMA,
        M5E_BUNDLE_VERSION,
        task,
    ):
        raise TaskError(f"{task}'s judged.json is not its own, at this schema and version")
    judged, cleanup = kept["judged"], kept["cleanup"]
    if not isinstance(judged, list) or not judged:
        raise TaskError(f"{task} kept no judged output")
    if not isinstance(cleanup, list) or (not cleanup and task not in M5E_CENSUS_FREE):
        raise TaskError(f"{task} kept no cleanup census")
    if not all(isinstance(line, str) and _CLEAN_CENSUS.fullmatch(line) for line in cleanup):
        raise TaskError(f"{task}'s census is not its clean cleanup lines")
    names: set[str] = set()
    for entry in judged:
        entry_fields = {"file", "judge", "table", "prefix", "sha256", "bytes"}
        if not isinstance(entry, dict) or set(entry) != entry_fields:
            raise TaskError(f"{task}: a judged entry without exactly {sorted(entry_fields)}")
        name, judge, table, prefix = entry["file"], entry["judge"], entry["table"], entry["prefix"]
        if not isinstance(name, str) or not _JUDGED_FILE.fullmatch(name) or name in names:
            raise TaskError(f"{task}: {name!r} is not one judged output's file")
        names.add(name)
        if not isinstance(judge, str) or judge not in M5E_JUDGE_PREFIX:
            raise TaskError(f"{task}: {judge!r} is no judge of the M5 gate")
        if _case_table(table) is None:
            raise TaskError(f"{task}: {table!r} is not a case table")
        fixed = M5E_JUDGE_PREFIX[judge]
        if not isinstance(prefix, str) or (prefix != fixed if fixed is not None else not prefix):
            raise TaskError(f"{task}: {name} is not read at its judge's line prefix")
        path = directory / name
        try:
            size = path.stat().st_size
        except OSError as exc:
            raise TaskError(f"{task}: {name} is missing: {exc}") from exc
        if size > M5E_GATE_MAX_FILE:
            raise TaskError(f"{task}: {name} is {size} bytes, over {M5E_GATE_MAX_FILE}")
        data = path.read_bytes()
        if hashlib.sha256(data).hexdigest() != entry["sha256"] or len(data) != entry["bytes"]:
            raise TaskError(f"{task}: {name} is not the output the task judged")
    present = {path.name for path in directory.iterdir()}
    extra = sorted(present - names - {"judged.json"} - beside)
    if extra:
        raise TaskError(f"files beside {task}'s kept evidence: {extra}")
    return judged


def _hosted(environ: Mapping[str, str]) -> bool:
    return environ.get("GITHUB_ACTIONS") == "true" and (
        environ.get("RUNNER_ENVIRONMENT") == "github-hosted"
    )


def _run_identity(environ: Mapping[str, str]) -> tuple[str, str, str]:
    """This run's id, attempt and commit, each well formed."""
    run_id = environ.get("GITHUB_RUN_ID", "")
    attempt = environ.get("GITHUB_RUN_ATTEMPT", "")
    sha = environ.get("GITHUB_SHA", "")
    if not (_RUN_NUMBER.fullmatch(run_id) and _RUN_NUMBER.fullmatch(attempt)):
        raise TaskError("the run's id or attempt is missing or malformed")
    if not _COMMIT_SHA.fullmatch(sha):
        raise TaskError("the run's commit is missing or malformed")
    return run_id, attempt, sha


def m5e_bundle_record(
    environ: Mapping[str, str], root: Path = M5E_EVIDENCE_DIR
) -> dict[str, object]:
    """The bundle a job of the M5 gate uploads: what its own task kept,
    checked byte for byte, with this run's provenance. Only on a disposable
    GitHub-hosted runner (NOT EXERCISED anywhere else), and only for the task
    this job runs: whatever else lies under `root` is never sealed."""
    if not _hosted(environ):
        raise TaskError(
            "NOT EXERCISED: an M5 evidence bundle is sealed only on a disposable "
            "GitHub-hosted runner"
        )
    job = environ.get("GITHUB_JOB", "")
    tasks = [task for task, its_job in M5E_GATE_TASKS.items() if its_job == job]
    if len(tasks) != 1:
        raise TaskError(f"the {job!r} job runs no task of the M5 gate")
    task = tasks[0]
    directory = root / task
    if not directory.is_dir():
        raise TaskError(f"nothing kept under {directory}: {task} kept no evidence")
    kept = _read_bounded_json(directory / "judged.json", task)
    judged = _kept_judgements(directory, task, kept)
    run_id, attempt, sha = _run_identity(environ)
    cleanup = kept["cleanup"] if isinstance(kept, dict) else []
    return {
        "schema": M5E_BUNDLE_SCHEMA,
        "version": M5E_BUNDLE_VERSION,
        "task": task,
        "job": job,
        "run_id": run_id,
        "run_attempt": attempt,
        "sha": sha,
        "ref": environ.get("GITHUB_REF", ""),
        "runner": {
            "environment": "github-hosted",
            "os": environ.get("RUNNER_OS", ""),
            "image": environ.get("ImageOS", ""),
            "image_version": environ.get("ImageVersion", ""),
        },
        "judged": judged,
        "cleanup": cleanup,
        "exit": 0,
    }


def task_m5e_evidence_bundle() -> None:
    """M5e.6 (G1), HOSTED ONLY: seal what this job's M5 evidence task kept with
    the run's provenance, for the job to upload to the M5 gate."""
    record = m5e_bundle_record(os.environ)
    path = M5E_EVIDENCE_DIR / str(record["task"]) / "bundle.json"
    path.write_text(
        json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8", newline="\n"
    )
    judged = record["judged"]
    count = len(judged) if isinstance(judged, list) else 0
    print(
        f"{GREEN}M5 evidence bundle: {record['task']} ({record['job']}), run "
        f"{record['run_id']} attempt {record['run_attempt']} at {str(record['sha'])[:12]}, "
        f"{count} judged output(s){OFF}"
    )


def _gate_bundle(directory: Path, task: str, run: tuple[str, str, str]) -> list[dict[str, object]]:
    """One downloaded bundle, checked against this run before anything in it
    is judged: its record's fields and provenance, its kept record and files,
    and the judgements its task must have made."""
    job = M5E_GATE_TASKS[task]
    bundle = _read_bounded_json(directory / "bundle.json", task)
    fields = {
        "schema",
        "version",
        "task",
        "job",
        "run_id",
        "run_attempt",
        "sha",
        "ref",
        "runner",
        "judged",
        "cleanup",
        "exit",
    }
    if not isinstance(bundle, dict) or set(bundle) != fields:
        raise TaskError(f"its bundle.json does not have exactly {sorted(fields)}")
    if (bundle["schema"], bundle["version"], bundle["task"], bundle["job"]) != (
        M5E_BUNDLE_SCHEMA,
        M5E_BUNDLE_VERSION,
        task,
        job,
    ):
        raise TaskError(f"not {task}'s bundle from the {job!r} job, at this schema and version")
    run_id, attempt, sha = run
    said = (bundle["run_id"], bundle["run_attempt"], bundle["sha"])
    # The same run on the same commit: an earlier attempt's bundle is this
    # run's, from a job that passed and was not run again; a later one's, or
    # another run's or commit's, is not.
    if (
        said[0] != run_id
        or said[2] != sha
        or not isinstance(said[1], str)
        or not _RUN_NUMBER.fullmatch(said[1])
        or int(said[1]) > int(attempt)
    ):
        raise TaskError(f"from run {said[0]!r} attempt {said[1]!r} at {said[2]!r}: not this run's")
    runner = bundle["runner"]
    runner_fields = {"environment", "os", "image", "image_version"}
    if not isinstance(runner, dict) or set(runner) != runner_fields:
        raise TaskError(f"its runner is not exactly {sorted(runner_fields)}")
    if runner["environment"] != "github-hosted":
        raise TaskError(f"from a {runner['environment']!r} runner, not a GitHub-hosted one")
    if type(bundle["exit"]) is not int or bundle["exit"] != 0 or not isinstance(bundle["ref"], str):
        raise TaskError("its task's exit is not 0, or its ref is not a name")
    kept = _read_bounded_json(directory / "judged.json", task)
    judged = _kept_judgements(directory, task, kept, frozenset({"bundle.json"}))
    cleanup = kept["cleanup"] if isinstance(kept, dict) else None
    if bundle["judged"] != judged or bundle["cleanup"] != cleanup:
        raise TaskError("its bundle and its kept record disagree")
    made = sorted((str(entry["judge"]), str(entry["table"])) for entry in judged)
    if made != sorted(M5E_GATE_JUDGEMENTS[task]):
        raise TaskError(f"judged {made}, not exactly {sorted(M5E_GATE_JUDGEMENTS[task])}")
    return judged


def m5e_gate_verdict(
    environ: Mapping[str, str], root: Path = M5E_GATE_DIR, repo: Path = ROOT
) -> tuple[list[str], list[str]]:
    """The M5 gate, HOSTED ONLY, in the `m5e-gate` job: judge this run's
    bundles again. Raises on anything the inventory verdict refuses, every
    problem named; returns that verdict's lines and the M5e acceptance
    verdict's blockers (none: READY)."""
    if not _hosted(environ):
        raise TaskError(
            "NOT EXERCISED: the M5 gate judges only the bundles of a run on disposable "
            "GitHub-hosted runners, in its own job"
        )
    if environ.get("GITHUB_JOB") != M5E_GATE_JOB:
        raise TaskError(
            f"the M5 gate runs in the {M5E_GATE_JOB!r} job, not {environ.get('GITHUB_JOB')!r}"
        )
    run = _run_identity(environ)
    if not root.is_dir():
        raise TaskError(f"no bundle under {root}: nothing was downloaded")
    expected = {f"m5e-evidence-{job}": task for task, job in M5E_GATE_TASKS.items()}
    present = {entry.name for entry in root.iterdir()}
    problems: list[str] = []
    missing = sorted(set(expected) - present)
    unexpected = sorted(present - set(expected))
    if missing:
        problems.append(f"missing bundle(s): {missing}")
    if unexpected:
        problems.append(f"bundle(s) no task of the gate uploads: {unexpected}")
    attributed: set[tuple[str, str]] = set()
    rejudged: dict[str, int] = {}
    for artifact in sorted(set(expected) & present):
        task, directory = expected[artifact], root / artifact
        try:
            if not directory.is_dir():
                raise TaskError("not a directory")
            judged = _gate_bundle(directory, task, run)
        except TaskError as exc:
            problems.append(f"{artifact}: {exc}")
            continue
        for entry in judged:
            judge, table = str(entry["judge"]), str(entry["table"])
            cases = _case_table(table) or ()
            try:
                output = (directory / str(entry["file"])).read_text(encoding="utf-8")
                _rejudge(judge, output, cases, str(entry["prefix"]))
            except (OSError, UnicodeDecodeError, TaskError) as exc:
                problems.append(f"{task}: {judge} {table}: {exc}")
                continue
            if judge == "attributed":
                attributed.update(cases)
            rejudged[task] = rejudged.get(task, 0) + len(cases)
    not_yet = {case for table in M5E_NOT_YET_REQUIRED for case in (_case_table(table) or ())}
    required = set(ATTRIBUTED_CASES) - not_yet
    if not problems:
        lost = sorted(f"{suite}/{case}" for suite, case in required - attributed)
        extra = sorted(f"{suite}/{case}" for suite, case in attributed - required)
        if lost:
            problems.append(f"{len(lost)} attributed case(s) no bundle judged: {lost[:20]}")
        if extra:
            problems.append(f"{len(extra)} case(s) judged that are not yet required: {extra[:20]}")
    if problems:
        raise TaskError(f"M5 gate: {len(problems)} problem(s): " + "; ".join(problems[:30]))
    run_id, attempt, sha = run
    lines = [
        f"{_INVENTORY_VERDICT}: {len(expected)} bundles of run {run_id} attempt {attempt} at "
        f"{sha[:12]}, each from its job on a GitHub-hosted runner, judged again",
        f"  attributed inventory: {len(attributed)} of {len(ATTRIBUTED_CASES)} cases judged "
        f"again; not yet required: {', '.join(M5E_NOT_YET_REQUIRED)} ({len(not_yet)} cases)",
        *(f"  {task}: {rejudged[task]} case(s) judged again" for task in M5E_GATE_TASKS),
    ]
    return lines, m5e_acceptance_blockers(repo)


def adr_status(repo: Path, number: str) -> str:
    """The first word of ADR `number`'s status line ("missing" without one)."""
    found = sorted((repo / "docs" / "adr").glob(f"{number}-*.md"))
    if len(found) != 1:
        return "missing"
    for line in found[0].read_text(encoding="utf-8").splitlines():
        if line.startswith("**Status:** "):
            words = line.removeprefix("**Status:** ").lstrip("*").split()
            return words[0] if words else "missing"
    return "missing"


def m5e_acceptance_blockers(repo: Path = ROOT) -> list[str]:
    """What stops `M5e` joining the available milestones, besides the
    inventory verdict (the handoff's §§6.4, 9): M5e.5's evidence not yet
    required, a record not at its status, a step's closure or acceptance not
    recorded in the plan. None: READY."""
    blockers: list[str] = []
    if M5E_NOT_YET_REQUIRED or "sandbox-hygiene-evidence" not in M5E_GATE_TASKS:
        blockers.append(
            "M5e.5's evidence is not yet required: "
            + ", ".join(M5E_NOT_YET_REQUIRED or ("sandbox-hygiene-evidence",))
            + " (M5e.5's acceptance change)"
        )
    for number, wanted in M5E_ACCEPTANCE_ADRS:
        status = adr_status(repo, number)
        if status != wanted:
            blockers.append(f"ADR-{number} is {status}, not {wanted}")
    plan = (repo / "docs" / "M5E_ASSURANCE_PLAN.md").read_text(encoding="utf-8")
    for marker in M5E_ACCEPTANCE_RECORDS:
        if marker not in plan:
            blockers.append(f"the plan records no {marker.strip('*( ')}")
    return blockers


def task_m5e_gate_check() -> None:
    """M5e.6 (G2), HOSTED ONLY: the M5 gate. Judge again every M5 evidence
    task's bundle from this run (target/m5e-gate), and print the M5e
    acceptance verdict; NOT EXERCISED anywhere but its own hosted job."""
    lines, blockers = m5e_gate_verdict(os.environ)
    for line in lines:
        print(f"{GREEN}{line}{OFF}")
    if blockers:
        print(
            f"{BOLD}M5e acceptance verdict: NOT READY{OFF} ({len(blockers)} blocker(s); "
            "enforced by the m5e-gate eval once M5e is available)"
        )
        for blocker in blockers:
            print(f"  - {blocker}")
    else:
        print(f"{GREEN}M5e acceptance verdict: READY{OFF}")


TASKS = {
    "preflight": task_preflight,
    "tools": task_tools,
    "dev": task_dev,
    "fmt": task_fmt,
    "fmt-check": task_fmt_check,
    "lint": task_lint,
    "typecheck": task_typecheck,
    "test": task_test,
    "arch": task_arch,
    "adr-history": task_adr_history,
    "eval": task_eval,
    "eval-check": task_eval_check,
    "eval-one": task_eval_one,
    "schema": task_schema,
    "schema-check": task_schema_check,
    "capability-evidence": task_capability_evidence,
    "policy-benchmark": task_policy_benchmark,
    "authority-state-evidence": task_authority_state_evidence,
    "filesystem-canonicalization-evidence": task_filesystem_canonicalization_evidence,
    "authority-transport-evidence": task_authority_transport_evidence,
    "authority-write-probe": task_authority_write_probe,
    "broker-fs-read-evidence": task_broker_fs_read_evidence,
    "filesystem-operations-evidence": task_filesystem_operations_evidence,
    "process-broker-evidence": task_process_broker_evidence,
    "secret-broker-evidence": task_secret_broker_evidence,
    "sandbox-foundation-evidence": task_sandbox_foundation_evidence,
    "sandbox-egress-evidence": task_sandbox_egress_evidence,
    "sandbox-workload-evidence": task_sandbox_workload_evidence,
    "sandbox-restart-evidence": task_sandbox_restart_evidence,
    "sandbox-capacity-evidence": task_sandbox_capacity_evidence,
    "sandbox-proxy-weakened-evidence": task_sandbox_proxy_weakened_evidence,
    "sandbox-proxy-weakened-review": task_sandbox_proxy_weakened_review,
    "sandbox-registry-evidence": task_sandbox_registry_evidence,
    "sandbox-hygiene-evidence": task_sandbox_hygiene_evidence,
    "sandbox-registry-mutations": task_sandbox_registry_mutations,
    "m5e-evidence-bundle": task_m5e_evidence_bundle,
    "m5e-gate-check": task_m5e_gate_check,
    "net-http-evidence": task_net_http_evidence,
    "net-http-mutations": task_net_http_mutations,
    "sandbox-workload-mutations": task_sandbox_workload_mutations,
    "sandbox-neighbour-mutations": task_sandbox_neighbour_mutations,
    "sandbox-secret-evidence": task_sandbox_secret_evidence,
    "sandbox-secret-mutations": task_sandbox_secret_mutations,
    "sandbox-workspace-evidence": task_sandbox_workspace_evidence,
    "sandbox-workspace-mutations": task_sandbox_workspace_mutations,
    "sandbox-agent-evidence": task_sandbox_agent_evidence,
    "sandbox-agent-mutations": task_sandbox_agent_mutations,
    "sandbox-release-evidence": task_sandbox_release_evidence,
    "sandbox-release-mutations": task_sandbox_release_mutations,
    "d11-hardening-evidence": task_d11_hardening_evidence,
    "d11-hardening-mutations": task_d11_hardening_mutations,
    "d11-posture": task_d11_posture,
    "fuzz-smoke": task_fuzz_smoke,
    "fuzz": task_fuzz,
    "security": task_security,
    "check": task_check,
    "docs": task_docs,
    "clean": task_clean,
    "hooks": task_hooks,
}


# --- helpers ---------------------------------------------------------------


def _fuzz_seeds() -> list[bytes]:
    """Every input and frame in the shared golden vectors, as fuzzing seeds."""
    seeds = []
    for name in ("valid.json", "invalid.json"):
        path = ROOT / "tests" / "protocol" / "vectors" / name
        for vector in json.loads(path.read_text(encoding="utf-8"))["vectors"]:
            if "input" in vector:
                seeds.append(vector["input"].encode("utf-8"))
            else:
                seeds.append(bytes.fromhex(vector["input_hex"]))
            if "frame_hex" in vector:
                seeds.append(bytes.fromhex(vector["frame_hex"]))
    return seeds


def _policy_fuzz_seeds() -> list[bytes]:
    """The three shipped policy packs, as fuzzing seeds.

    A TOML parser started from an empty corpus spends its budget rediscovering
    that `[` opens a table. Started from `balanced.toml` it spends it on the
    schema walker, which is the part this repository wrote.
    """
    return [path.read_bytes() for path in sorted((ROOT / "policy").glob("*.toml"))]


def _version_of(tool: str) -> str:
    try:
        out = subprocess.run(
            [tool, "--version"], capture_output=True, text=True, check=False, timeout=30
        )
    except (OSError, subprocess.SubprocessError):
        return "?"
    return (out.stdout or out.stderr).strip().splitlines()[0] if out.stdout or out.stderr else "?"


def _platform_note() -> str:
    """State the support tier honestly. See docs/PRODUCT_SPEC.md section 9."""
    system = platform.system()
    if system == "Linux":
        try:
            version = Path("/proc/version").read_text(encoding="utf-8", errors="replace").lower()
        except OSError:
            version = ""
        return "WSL2, supported" if "microsoft" in version else "supported"
    if system == "Darwin":
        return "supported; the container sandbox runs in a Linux VM"
    if system == "Windows":
        return "development only; WSL2 is the supported Windows path"
    return "not evaluated"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="dw",
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("task", nargs="?", choices=sorted(TASKS), help="task to run")
    parser.add_argument("--list", action="store_true", help="list tasks and exit")
    args = parser.parse_args(argv)

    if args.list or not args.task:
        width = max(len(name) for name in TASKS)
        for name, fn in sorted(TASKS.items()):
            doc = (fn.__doc__ or "").strip().splitlines()
            print(f"  {name:<{width}}  {doc[0] if doc else ''}")
        return 0

    try:
        keeps = m5e_keeps(args.task, os.environ)
        if keeps:
            forget_kept(args.task)
        TASKS[args.task]()
        if keeps:
            save_judged_evidence(args.task)
    except TaskError as exc:
        print(f"\n{RED}dw: {exc}{OFF}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
