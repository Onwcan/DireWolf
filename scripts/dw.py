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
    ("broker-http", "bad-chunk-size"),
    ("broker-http", "body-past-bound-cut"),
    ("broker-http", "broker-rejudges-pinned-addresses"),
    ("broker-http", "close-delimited"),
    ("broker-http", "credential-composed-in-broker"),
    ("broker-http", "credential-header-injection-refused"),
    ("broker-http", "echo-body-redacted-before-encoding"),
    ("broker-http", "echo-header-dropped-whole"),
    ("broker-http", "echo-in-a-broken-response"),
    ("broker-http", "echo-straddling-the-bound"),
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
    ("broker-http", "wrong-name"),
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
    for tool in ("bash", "openssl", "python3"):
        if shutil.which(tool) is None:
            raise TaskError(f"NOT EXERCISED: the net.http evidence needs {tool}")
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
    "net-http-evidence": task_net_http_evidence,
    "net-http-mutations": task_net_http_mutations,
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
