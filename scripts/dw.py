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
    "broker-fs-read-evidence": task_broker_fs_read_evidence,
    "filesystem-operations-evidence": task_filesystem_operations_evidence,
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
