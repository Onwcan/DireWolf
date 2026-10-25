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
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from collections.abc import Callable, Mapping
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
    """
    args = ["check"]
    if eval_gate_is_strict(os.environ):
        args.append("--require-exercised")
    uvrun("direwolf_evals", *args)


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
    and the authority's real-container suites run, every case must report,
    no container the evidence made may remain, and every container that was
    there before must still be there.

    No reachable runtime, no container, no measurement: NOT EXERCISED, which
    fails. Linux only.
    """
    if not sys.platform.startswith("linux"):
        raise TaskError("NOT EXERCISED: the sandbox evidence needs Linux and an OCI runtime")
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
    print(f"{GREEN}cleanup: no evidence container remains; {len(before)} pre-existing kept{OFF}")
    records = require_sandbox_evidence("\n".join(outputs), SANDBOX_CASES)
    latency = [r for r in records if r.get("case") == "latency"]
    if latency:
        print(f"{BOLD}latency{OFF} {json.dumps(latency[0], sort_keys=True)}")
    uvrun("dwcheck", "closure", "--report")


# --- M5b: PROXY_ONLY and the CONNECT proxy (ADR-0048) -----------------------

SANDBOX_RELAY_PATH = "/usr/libexec/direwolf/sandbox-relay"
SANDBOX_FIXTURE_PATH = "/usr/libexec/direwolf/sandbox-fixture"

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

    Then every suite must run every test and every case must report; no
    container or network the evidence made may remain, and every one that was
    there before must still be there. No runtime: NOT EXERCISED, which fails.
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
    print(
        f"{GREEN}cleanup: no evidence container or network remains; {len(before_containers)} "
        f"container(s) and {len(before_networks)} network(s) pre-existing kept{OFF}"
    )
    require_sandbox_evidence("\n".join(outputs), EGRESS_CASES)
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
        )
    ),
)


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
            {SANDBOX_FIXTURE_PATH: fixture, "/usr/bin/true": fixture},
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
        **tool_variables,
    }
    return client, socket, variables, before, images


def task_sandbox_workload_evidence() -> None:
    """M5d.1's and M5d.2's real-container evidence (ADR-0052 §17): workloads
    in a real OCI environment -- the released broker running them through its
    real runtime client, the real authority deciding and recording them, and
    (M5d.2) a real DWKP client reaching them through the public route, the
    released `serve --sandbox-config` included.

    Every suite must run every test and every case must report; no container
    the evidence made may remain, and every container that was there before
    must still be there. No runtime: NOT EXERCISED, which fails. Linux only.
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
    print(f"{GREEN}cleanup: no evidence container remains; {len(before)} pre-existing kept{OFF}")
    require_sandbox_evidence("\n".join(outputs), WORKLOAD_CASES)
    uvrun("dwcheck", "closure", "--report")


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
    require_secret_evidence(unit, SECRET_SANDBOX_UNIT_CASES)
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
    print(f"{GREEN}cleanup: no evidence container remains; {len(before)} pre-existing kept{OFF}")
    require_sandbox_evidence("\n".join(outputs), SECRET_SANDBOX_CASES)
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
    print(f"{GREEN}cleanup: no workspace mount, loop device or directory remains{OFF}")


def require_workspace_unit_evidence(output: str) -> None:
    """Every in-process (suite, case) must have printed its
    WORKSPACE-EVIDENCE line."""
    reported: set[tuple[str, str]] = set()
    for line in output.splitlines():
        at = line.find(WORKSPACE_EVIDENCE_PREFIX)
        if at < 0:
            continue
        try:
            record = json.loads(line[at + len(WORKSPACE_EVIDENCE_PREFIX) :])
        except json.JSONDecodeError as exc:
            raise TaskError(f"unreadable evidence line: {line[:200]}") from exc
        if not isinstance(record, dict) or not record.get("outcome"):
            raise TaskError(f"malformed evidence line: {line[:200]}")
        reported.add((str(record.get("suite")), str(record.get("case"))))
    missing = [
        f"{suite}/{case}" for suite, case in WORKSPACE_UNIT_CASES if (suite, case) not in reported
    ]
    if missing:
        raise TaskError(
            f"NOT EXERCISED: {len(missing)} in-process workspace case(s) did not report: "
            + ", ".join(missing)
        )
    print(f"{GREEN}workspace in-process evidence: {len(WORKSPACE_UNIT_CASES)} cases reported{OFF}")


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

    Every case must report. Without the privileged half the task FAILS, NOT
    EXERCISED, after reporting the rest: the unverified-workspace waiver is
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
    require_workspace_unit_evidence(unit)
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
    print(f"{GREEN}cleanup: no evidence container remains; {len(before)} pre-existing kept{OFF}")
    require_sandbox_evidence("\n".join(outputs), WORKSPACE_CASES)
    if not privileged and not require_privileged:
        # A mutant's run: what could run here ran; the privileged half
        # is NOT EXERCISED, and never counted as a kill.
        print(
            f"NOT EXERCISED (not counted): {len(WORKSPACE_PRIVILEGED_CASES)} privileged "
            "workspace case(s)"
        )
        return
    if not privileged:
        raise TaskError(
            f"NOT EXERCISED: {len(WORKSPACE_PRIVILEGED_CASES)} case(s) need an "
            "operator-provisioned workspace -- the group 10001, filesystems of their own, "
            "sudo -- which only DW_WORKSPACE_PRIVILEGED=1 provisions (the hosted "
            "`sandbox-workspace` job). The unverified-workspace waiver is not evidence of "
            "the production guarantee: "
            + ", ".join(f"{suite}/{case}" for suite, case in WORKSPACE_PRIVILEGED_CASES)
        )
    require_sandbox_evidence("\n".join(outputs), WORKSPACE_PRIVILEGED_CASES)
    uvrun("dwcheck", "closure", "--report")


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
    print(
        f"{GREEN}cleanup: no evidence container, workspace mount or broker socket directory "
        f"remains; {len(before)} pre-existing container(s) kept{OFF}"
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
RELEASE_UNIT_TESTS = 8
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
    print(f"{GREEN}cleanup: no evidence container remains; {len(before)} pre-existing kept{OFF}")
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
    print(
        f"{GREEN}cleanup: no evidence container or broker socket directory remains; "
        f"{len(before)} pre-existing container(s) kept{OFF}"
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
        "                Reply::Done(true) => environment::begin_release(work, run)?,",
        "                Reply::Done(true) => Vec::new(),",
    ),
    (
        "the environment's destruction is recorded only after the release committed",
        "crates/dwkd-authority/src/state/mod.rs",
        "                Reply::Done(true) => environment::begin_release(work, run)?,\n"
        "                Reply::Done(false) | Reply::Refused(_) => Vec::new(),\n"
        "            };\n"
        "            let reply = match released {\n"
        "                Reply::Done(_) => Reply::Done(()),\n"
        "                Reply::Refused(reason) => Reply::Refused(reason),\n"
        "            };\n"
        "            Ok((reply, teardown))\n"
        "        })?;\n"
        "        if !teardown.is_empty() {\n"
        "            self.shared.crash(CrashPoint::ReleaseAfterIntent)?;\n"
        "        }\n",
        '                Reply::Done(true) => vec![environment::DestroyBegun::Refused("LATER")],\n'
        "                Reply::Done(false) | Reply::Refused(_) => Vec::new(),\n"
        "            };\n"
        "            let reply = match released {\n"
        "                Reply::Done(_) => Reply::Done(()),\n"
        "                Reply::Refused(reason) => Reply::Refused(reason),\n"
        "            };\n"
        "            Ok((reply, teardown))\n"
        "        })?;\n"
        "        if !teardown.is_empty() {\n"
        "            self.shared.crash(CrashPoint::ReleaseAfterIntent)?;\n"
        "        }\n"
        "        let teardown = if teardown.is_empty() {\n"
        "            teardown\n"
        "        } else {\n"
        "            self.transact(|work| environment::begin_release(work, run))?\n"
        "        };\n",
    ),
    (
        "a fenced release ends the run's environment",
        "crates/dwkd-authority/src/state/mod.rs",
        "                Reply::Done(false) | Reply::Refused(_) => Vec::new(),",
        "                Reply::Done(false) => Vec::new(),\n"
        "                Reply::Refused(_) => environment::begin_release(work, run)?,",
    ),
    (
        "a release acknowledged without effect ends the named run's environment",
        "crates/dwkd-authority/src/state/mod.rs",
        "                Reply::Done(false) | Reply::Refused(_) => Vec::new(),",
        "                Reply::Done(false) => environment::begin_release(work, run)?,\n"
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
    "net-http-evidence": task_net_http_evidence,
    "net-http-mutations": task_net_http_mutations,
    "sandbox-workload-mutations": task_sandbox_workload_mutations,
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
        TASKS[args.task]()
    except TaskError as exc:
        print(f"\n{RED}dw: {exc}{OFF}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
