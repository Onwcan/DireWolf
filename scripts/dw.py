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
import shutil
import subprocess
import sys
from collections.abc import Mapping
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
PROTO_FUZZ_TARGETS = ("frame_decoder", "dwkp_decode", "canonical_roundtrip", "envelope_version")
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
    root to a workspace, resolving for a run, and migrating an M3 store. Each
    case prints one `FS-EVIDENCE` line after its assertions held; this task
    requires every category, every race campaign with zero escapes, and lists
    what the machine could not exercise. Linux only: the resolver is openat2.
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
    for category, case, outcome in unexercised:
        if case not in FS_ENVIRONMENTAL:
            problems.append(f"{category}/{case} was not exercised ({outcome})")

    for category in FS_EVIDENCE_CATEGORIES:
        cases = exercised.get(category, [])
        total = sum(count for _, _, count in cases)
        print(f"  {category:<17} {len(cases):>3} cases  {total:>7} observations")
    raced = sum(count for _, count in races.values())
    print(f"  race campaigns: {len(races)}, {raced} raced resolutions, 0 escapes required")
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


def run_captured(*command: str) -> str:
    """`run`, also returning everything the command printed -- stdout and
    stderr, interleaved as it happened -- which is echoed as it arrives."""
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
