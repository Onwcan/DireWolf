"""Prove the quality gates actually reject bad input.

A configured linter that has never rejected anything is a configured linter, not
a gate. Each test below runs the real tool against a fixture that is wrong in
exactly one way and asserts a non-zero exit -- the same exit code CI acts on.

What this does NOT prove: that CI runs these commands. That is asserted
separately by ``test_ci_runs_the_same_commands_as_make``.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
GATES = REPO_ROOT / "tests" / "architecture" / "fixtures" / "gates"


def _run(command: list[str], *, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        cwd=cwd or REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )


def _tool(name: str) -> str:
    """Resolve a dev tool, preferring the one in this interpreter's environment."""
    candidate = Path(sys.executable).parent / name
    for path in (candidate, candidate.with_suffix(".exe")):
        if path.is_file():
            return str(path)
    resolved = shutil.which(name)
    if resolved is None:
        pytest.skip(f"{name} is not installed")
    return resolved


# --- Python gates ----------------------------------------------------------


def test_ruff_format_rejects_badly_formatted_python() -> None:
    result = _run([_tool("ruff"), "format", "--check", "--no-cache", str(GATES / "bad_format.py")])
    assert result.returncode != 0, "ruff format accepted misformatted code"
    assert "would be reformatted" in result.stdout + result.stderr


def test_ruff_lint_rejects_a_lint_error() -> None:
    result = _run([_tool("ruff"), "check", "--no-cache", str(GATES / "lint_error.py")])
    assert result.returncode != 0, "ruff check accepted an undefined name"
    assert "F821" in result.stdout or "undefined" in result.stdout.lower()


def test_mypy_rejects_a_type_error() -> None:
    result = _run(
        [
            _tool("mypy"),
            "--strict",
            "--no-incremental",
            "--no-site-packages",
            str(GATES / "type_error.py"),
        ]
    )
    assert result.returncode != 0, "mypy accepted `str = add(1, 2)`"
    assert "Incompatible types" in result.stdout, f"expected a type error, got: {result.stdout}"


def test_pytest_fails_when_a_test_fails() -> None:
    """Obvious, and worth asserting: the test gate has to be able to go red."""
    result = _run(
        [
            sys.executable,
            "-m",
            "pytest",
            "-q",
            "-p",
            "no:cacheprovider",
            str(GATES / "failing_test.py"),
        ]
    )
    assert result.returncode != 0
    assert "1 failed" in result.stdout


# --- Rust gates ------------------------------------------------------------


def test_rustfmt_rejects_badly_formatted_rust() -> None:
    rustfmt = shutil.which("rustfmt")
    if rustfmt is None:
        pytest.skip("rustfmt is not installed")
    result = _run([rustfmt, "--edition", "2024", "--check", str(GATES / "bad_format.rs")])
    assert result.returncode != 0, "rustfmt accepted misformatted code"
    assert "Diff in" in result.stdout, f"expected a formatting diff, got: {result.stdout}"


@pytest.mark.slow
def test_clippy_denies_warnings(tmp_path: Path) -> None:
    """`cargo clippy -- -D warnings` must turn a clippy::all warning into a
    failure.

    Runs against a detached fixture crate carrying the same lint level as the
    workspace. It proves the mechanism -- lint table, clippy, `-D warnings` --
    rather than re-proving the workspace's own table, which is asserted by
    reading it in ``test_workspace_forbids_unsafe_code``.
    """
    cargo = shutil.which("cargo")
    if cargo is None:
        pytest.skip("cargo is not installed")
    crate = GATES / "clippy_crate"
    result = subprocess.run(
        [cargo, "clippy", "--quiet", "--", "-D", "warnings"],
        cwd=crate,
        capture_output=True,
        text=True,
        check=False,
        timeout=600,
        env={**os.environ, "CARGO_TARGET_DIR": str(tmp_path / "target")},
    )
    assert result.returncode != 0, "clippy accepted a clippy::all warning under -D warnings"
    # Assert on the diagnostic, not only the exit code: a non-zero exit because
    # cargo could not start would make this test pass for the wrong reason.
    assert "needless_range_loop" in result.stderr or "needless-range-loop" in result.stderr, (
        f"expected a clippy lint, got: {result.stderr}"
    )


# --- the gates are configured where they are claimed to be -----------------


def test_workspace_forbids_unsafe_code() -> None:
    """M1 contains no `unsafe`, and the workspace forbids it rather than
    relying on review to notice. See CONTRIBUTING.md "Unsafe Rust"."""
    manifest = tomllib.loads((REPO_ROOT / "Cargo.toml").read_text(encoding="utf-8"))
    lints = manifest["workspace"]["lints"]["rust"]
    assert lints["unsafe_code"] == "forbid"


def test_no_unsafe_block_exists_in_the_workspace() -> None:
    offenders = []
    for source in (REPO_ROOT / "crates").rglob("*.rs"):
        text = source.read_text(encoding="utf-8")
        if "unsafe " in text or "unsafe{" in text:
            offenders.append(source.relative_to(REPO_ROOT).as_posix())
    assert not offenders, f"unsafe Rust appeared in: {offenders}"


# --- supply-chain policy is declared where it is claimed to be -------------


def test_cargo_deny_policy_declares_the_sections_we_rely_on() -> None:
    """`cargo-deny` is the single Rust supply-chain gate, so its configuration
    is part of the claim rather than an implementation detail.

    This asserts the policy is present and says what CONTRIBUTING.md says it
    says. It does not execute cargo-deny -- the `supply-chain` CI job does
    that, and this test is what tells you the config was gutted before you get
    there.
    """
    policy = tomllib.loads((REPO_ROOT / "deny.toml").read_text(encoding="utf-8"))

    assert policy["advisories"]["yanked"] == "deny"
    assert policy["advisories"]["ignore"] == [], (
        "an advisory is being ignored; each entry needs a reviewer and a reason"
    )

    licences = set(policy["licenses"]["allow"])
    assert "Apache-2.0" in licences, "the project's own licence must be allowed"
    for copyleft in ("GPL-2.0", "GPL-3.0", "AGPL-3.0", "MPL-2.0"):
        assert copyleft not in licences, (
            f"{copyleft} is allowed; a copyleft dependency would change the licence "
            f"of the shipped kernel"
        )

    assert policy["bans"]["multiple-versions"] == "deny"
    assert policy["bans"]["wildcards"] == "deny"
    denied = {entry["crate"] for entry in policy["bans"]["deny"]}
    assert {"openssl", "native-tls"} <= denied, "the project standardises on rustls"

    assert policy["sources"]["unknown-registry"] == "deny"
    assert policy["sources"]["unknown-git"] == "deny"


def test_cargo_audit_is_not_also_installed_or_invoked() -> None:
    """One tool per signal. cargo-audit reads the same RustSec database as
    cargo-deny, and two tools means two places to suppress a finding, neither
    of whose reviewers knows about the other (ADR-0031).

    Asserted against what the tooling *runs*, not against the text: dw.py
    explains this choice in a comment, and a test that forbade the word would
    forbid the explanation.
    """
    sys.path.insert(0, str(REPO_ROOT / "scripts"))
    import dw

    assert "cargo-audit" not in dw.CARGO_TOOLS
    assert not (REPO_ROOT / "audit.toml").exists()

    workflow = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    invocations = [
        line
        for line in workflow.splitlines()
        if "cargo audit" in line and not line.strip().startswith("#")
    ]
    assert not invocations, f"cargo-audit is invoked in CI: {invocations}"
