"""The developer surface and the CI configuration hold their own invariants.

Two things are asserted here.

**CI runs what a contributor runs.** If CI spells its own version of the
commands, then "CI is green" and "`make check` passes" become different claims,
and the difference is discovered at the worst moment.

**CI is not sloppy.** This project argues that only OS-level boundaries are
real; a build pipeline with a write-scoped token, an unpinned third-party
action, or a `curl | sh` install would be a live contradiction of that in the
one place an attacker can reach without touching the product at all.

These are text assertions over the workflow files rather than YAML-semantic
ones: no YAML parser is a dependency here, and the properties that matter --
"pinned to a SHA", "no piped installer" -- are properties of the literal text.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
WORKFLOWS = sorted((REPO_ROOT / ".github" / "workflows").glob("*.yml"))
COMPOSITES = sorted((REPO_ROOT / ".github" / "actions").rglob("action.yml"))
ALL_ACTION_FILES = WORKFLOWS + COMPOSITES

sys.path.insert(0, str(REPO_ROOT / "scripts"))
import dw  # noqa: E402  - imported after the path is extended


def _without_comments(text: str) -> str:
    """Drop YAML comments.

    These files explain their own security posture in comments, which means the
    comments contain the very strings the checks below forbid. Checking the
    prose would make the test unmaintainable in exactly the direction that
    discourages writing the explanation.
    """
    lines = []
    for line in text.splitlines():
        stripped = line.lstrip()
        if stripped.startswith("#"):
            continue
        lines.append(re.split(r"\s+#", line, maxsplit=1)[0])
    return chr(10).join(lines)


def _makefile_targets() -> set[str]:
    text = (REPO_ROOT / "Makefile").read_text(encoding="utf-8")
    return set(re.findall(r"^([a-z][a-z-]*):\s", text, re.MULTILINE))


# --- the documented surface matches the implemented one --------------------


def test_every_make_target_is_a_real_task() -> None:
    """A documented command that does not exist is worse than an undocumented
    one: it sends a new contributor looking for their own mistake."""
    missing = _makefile_targets() - set(dw.TASKS) - {"help"}
    assert not missing, f"Makefile targets with no task behind them: {sorted(missing)}"


def test_every_task_is_reachable_from_make() -> None:
    missing = set(dw.TASKS) - _makefile_targets()
    assert not missing, f"tasks with no make target: {sorted(missing)}"


def test_check_runs_every_gate() -> None:
    """`make check` is the one command a contributor is told to trust."""
    source = (REPO_ROOT / "scripts" / "dw.py").read_text(encoding="utf-8")
    body = source[source.index("def task_check()") : source.index("def task_docs()")]
    for gate in ("fmt-check", "lint", "typecheck", "arch", "schema-check", "test", "security"):
        assert f'"{gate}"' in body, f"`make check` does not run {gate}"


def test_every_task_has_a_one_line_description() -> None:
    for name, fn in dw.TASKS.items():
        assert (fn.__doc__ or "").strip(), f"task {name} has no description for `make help`"


# --- CI invokes the same commands ------------------------------------------


@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda p: p.name)
def test_ci_runs_the_same_commands_as_make(workflow: Path) -> None:
    """Every job step that runs a gate does so through `make` or `dw.py`.

    `cargo build --release` and the fixture-rejection proof are the deliberate
    exceptions: neither is a gate a contributor runs in the inner loop, and
    both are asserted to be present by their own tests below.
    """
    text = workflow.read_text(encoding="utf-8")
    gates = {"cargo fmt", "cargo clippy", "cargo test", "cargo deny", "ruff", "mypy", "pytest"}
    for lineno, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip().lstrip("-").strip()
        if not stripped.startswith(("run:", "- run:")):
            continue
        command = stripped.split("run:", 1)[1].strip()
        for gate in gates:
            assert not command.startswith(gate), (
                f"{workflow.name}:{lineno} runs `{gate}` directly. "
                f"CI must invoke the same `make` target a contributor does, "
                f"or the two claims drift apart."
            )


def test_ci_proves_the_boundary_checker_rejects_the_fixture() -> None:
    """The M1 acceptance criterion is not "a checker is configured"."""
    text = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "tests/architecture/fixtures/violations" in text
    assert "accepted the deliberately-invalid fixture tree" in text


def test_ci_builds_the_release_profile() -> None:
    """LTO, one codegen unit and panic=abort can fail where debug does not."""
    text = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "cargo build --workspace --release" in text


def test_ci_fails_on_stale_generated_protocol_files() -> None:
    """ADR-0033: schemas/ and the Python bindings are generated. The gate is a
    CI job, and it is a required one."""
    text = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    assert "run: make schema-check" in text
    needs = re.search(r"needs:\s*\[([^\]]*)\]", text)
    assert needs is not None and "schema" in [n.strip() for n in needs.group(1).split(",")]


def test_the_fuzz_workflow_uses_the_task_runner_pins() -> None:
    """Two spellings of the nightly date or the cargo-fuzz version would mean a
    local `make fuzz` and the scheduled run fuzz with different engines."""
    text = (REPO_ROOT / ".github" / "workflows" / "fuzz.yml").read_text(encoding="utf-8")
    assert f"rustup toolchain install {dw.FUZZ_NIGHTLY} --profile minimal" in text
    assert f"cargo install cargo-fuzz --version {dw.CARGO_FUZZ_VERSION} --locked" in text
    assert "run: make fuzz-smoke" in text
    assert re.search(r"run: make fuzz$", text, re.MULTILINE)
    targets = sorted(p.stem for p in (REPO_ROOT / "fuzz" / "fuzz_targets").glob("*.rs"))
    assert targets == sorted(dw.FUZZ_TARGETS)
    # libFuzzer starts from real inputs, not from an empty corpus -- and from
    # the RIGHT real inputs: DWKP vectors would teach a TOML parser nothing.
    assert len(dw._fuzz_seeds()) > 100
    assert len(dw._policy_fuzz_seeds()) == 3, "one seed per shipped policy pack"
    assert set(dw.PROTO_FUZZ_TARGETS).isdisjoint(dw.POLICY_FUZZ_TARGETS)


def test_ci_tests_on_every_supported_platform() -> None:
    text = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text(encoding="utf-8")
    for runner in ("ubuntu-latest", "windows-latest", "macos-latest"):
        assert runner in text, f"{runner} is not in the test matrix"


# --- CI security -----------------------------------------------------------


@pytest.mark.parametrize("path", ALL_ACTION_FILES, ids=lambda p: str(p.relative_to(REPO_ROOT)))
def test_third_party_actions_are_pinned_to_a_commit_sha(path: Path) -> None:
    """A tag is mutable. `uses: foo/bar@v4` means whoever controls that tag can
    change what runs in our pipeline, retroactively."""
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        match = re.search(r"uses:\s*(\S+)", line)
        if not match:
            continue
        reference = match.group(1)
        if reference.startswith("./"):
            continue  # a composite action in this repository
        assert "@" in reference, f"{path.name}:{lineno}: `{reference}` has no version at all"
        pin = reference.split("@", 1)[1]
        assert re.fullmatch(r"[0-9a-f]{40}", pin), (
            f"{path.name}:{lineno}: `{reference}` is pinned to `{pin}`, not a 40-character "
            f"commit SHA. Tags are mutable."
        )


@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda p: p.name)
def test_workflows_declare_least_privilege(workflow: Path) -> None:
    text = workflow.read_text(encoding="utf-8")
    assert "permissions:" in text, f"{workflow.name} does not declare permissions"
    granted = re.findall(r"^\s+(\w[\w-]*):\s*(read|write|none)\s*$", text, re.MULTILINE)
    writes = [name for name, level in granted if level == "write"]
    assert not writes, (
        f"{workflow.name} grants write to {writes}. The first `permissions: write` is the "
        f"one nobody notices; add it deliberately, with a reviewer, or not at all."
    )


@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda p: p.name)
def test_no_workflow_uses_pull_request_target(workflow: Path) -> None:
    """`pull_request_target` runs fork code with the base repository's token."""
    assert "pull_request_target" not in _without_comments(workflow.read_text(encoding="utf-8"))


@pytest.mark.parametrize("path", ALL_ACTION_FILES, ids=lambda p: str(p.relative_to(REPO_ROOT)))
def test_nothing_is_installed_by_piping_a_url_into_a_shell(path: Path) -> None:
    """Piping a remote script into a shell in CI is the pattern this project's
    own threat model exists to argue against."""
    text = _without_comments(path.read_text(encoding="utf-8"))
    for pattern in (r"curl[^\n|]*\|\s*(sudo\s+)?(ba)?sh", r"wget[^\n|]*\|\s*(sudo\s+)?(ba)?sh"):
        match = re.search(pattern, text)
        if match is not None:
            pytest.fail(f"{path.name}: piped installer: {match.group(0)}")


@pytest.mark.parametrize("workflow", WORKFLOWS, ids=lambda p: p.name)
def test_no_secret_is_exposed_to_workflow_steps(workflow: Path) -> None:
    """No job needs one at M1, and a secret referenced by a workflow that runs
    on `pull_request` is a secret a fork can try to reach."""
    text = _without_comments(workflow.read_text(encoding="utf-8"))
    references = re.findall(r"\$\{\{\s*secrets\.(\w+)", text)
    # GITHUB_TOKEN is scoped by the `permissions:` block asserted above.
    assert [r for r in references if r != "GITHUB_TOKEN"] == []
