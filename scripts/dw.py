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
FUZZ_TARGETS = ("frame_decoder", "dwkp_decode", "canonical_roundtrip", "envelope_version")
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
    """Architecture boundary checks. Hygiene, not containment."""
    uvrun("dwcheck", "--root", str(ROOT), "all")


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
    """The eval merge gate: the deterministic subset, compared with the baseline."""
    uvrun("direwolf_evals", "check")


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
    run(
        "cargo",
        "test",
        "--release",
        "--locked",
        "-p",
        "dwk-proto",
        "--test",
        "fuzz_smoke",
        "--",
        "--nocapture",
    )


def task_fuzz() -> None:
    """Coverage-guided libFuzzer run of every dwk-proto target (nightly, cargo-fuzz)."""
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
    seeds = _fuzz_seeds()
    for target in FUZZ_TARGETS:
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
