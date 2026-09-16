"""The fault-injection harness against its dummy process, and the inventory.

These are the tests that would fail if the harness could not actually control a
process — which is the difference between "we have a fault-injection design"
and "we have fault injection".
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

import pytest

from direwolf_evals.inventory import INVENTORY, available, pending
from direwolf_evals.process import POSIX, ChildTimeoutError, UnsupportedOnPlatformError, spawn
from direwolf_evals.test_environment import EvalTestEnvironment, SimulatedBehaviour

REPO_ROOT = Path(__file__).resolve().parents[2]


# --- the dummy child is controllable ---------------------------------------


def test_checkpoints_arrive_in_order() -> None:
    with spawn("checkpoint:a,emit:work,checkpoint:b,exit:0") as child:
        child.wait_for_checkpoint("a")
        child.wait_for_checkpoint("b")
        assert child.wait() == 0
        assert child.checkpoints() == ["a", "b"]
        assert "OUT work" in child.stdout


def test_a_child_waits_at_a_pause_and_continues_when_released() -> None:
    with spawn("pause:gate,checkpoint:after,exit:0") as child:
        child.wait_for_checkpoint("gate")
        assert child.process.poll() is None, "the child should still be blocked"
        with pytest.raises(ChildTimeoutError):
            child.wait_for_checkpoint("after", timeout=0.3)
        child.resume()
        child.wait_for_checkpoint("after")
        assert child.wait() == 0


def test_a_hang_is_detected_and_the_child_is_terminated() -> None:
    with spawn("checkpoint:ready,hang") as child:
        child.wait_for_checkpoint("ready")
        with pytest.raises(ChildTimeoutError):
            child.wait(timeout=0.3)
        child.terminate()
        code = child.wait(timeout=10)
    assert code != 0


def test_a_crash_keeps_its_exit_code_and_the_output_before_it() -> None:
    with spawn("emit:last-words,crash") as child:
        assert child.wait() == 70
        assert "OUT last-words" in child.stdout


def test_stderr_is_captured_separately() -> None:
    with spawn("warn:careful,exit:0") as child:
        assert child.wait() == 0
        assert "ERR careful" in child.stderr
        assert not any("careful" in line for line in child.stdout)


def test_an_unknown_step_is_an_error_not_a_silent_success() -> None:
    with spawn("teleport:somewhere") as child:
        assert child.wait() == 2


def test_closing_leaves_no_process_behind() -> None:
    child = spawn("hang")
    child.close()
    assert child.process.poll() is not None


@pytest.mark.skipif(not POSIX, reason="SIGSTOP/SIGCONT are POSIX-only")
def test_os_level_pause_stops_and_resumes_the_process() -> None:
    with spawn("checkpoint:ready,sleep:5,checkpoint:done,exit:0") as child:
        child.wait_for_checkpoint("ready")
        child.pause()
        child.unpause()
        assert child.process.poll() is None


@pytest.mark.skipif(POSIX, reason="the unsupported path only exists off POSIX")
def test_os_level_pause_is_reported_unsupported_rather_than_faked() -> None:
    with spawn("checkpoint:ready,exit:0") as child:
        child.wait_for_checkpoint("ready")
        with pytest.raises(UnsupportedOnPlatformError):
            child.pause()


def test_the_child_is_this_interpreter_and_never_a_shell() -> None:
    """The harness must not become a way to run arbitrary commands: argv is
    fixed, and the only variable part is the script this package parses."""
    source = (REPO_ROOT / "evals/src/direwolf_evals/process.py").read_text(encoding="utf-8")
    assert "shell=True" not in source
    assert "sys.executable" in source
    assert re.search(r'"-m",\s*"direwolf_evals\.dummy_child"', source)


# --- the test-only environment ----------------------------------------------


def test_the_test_environment_runs_nothing() -> None:
    """Checked over the parsed module, not its prose: the docstring explains
    what it must not do, and a grep would trip over the explanation."""
    tree = ast.parse(
        (REPO_ROOT / "evals/src/direwolf_evals/test_environment.py").read_text(encoding="utf-8")
    )
    imported: set[str] = set()
    called: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module.split(".")[0])
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            called.add(node.func.id)
    assert imported <= {"__future__", "dataclasses", "enum", "typing"}, imported
    assert not (called & {"open", "exec", "eval", "compile", "__import__"}), called


def test_the_test_environment_distinguishes_every_outcome_class() -> None:
    environment = EvalTestEnvironment()
    codes = {
        behaviour: environment.run("job", behaviour, output="abcdef").exit_code
        for behaviour in SimulatedBehaviour
    }
    assert codes[SimulatedBehaviour.SUCCESS] == 0
    assert codes[SimulatedBehaviour.TIMEOUT] == 124
    assert codes[SimulatedBehaviour.CRASH] == 70
    partial = environment.run("job", SimulatedBehaviour.PARTIAL, output="abcdef")
    assert partial.truncated and len(partial.output) < len("abcdef")


def test_no_daemon_or_runtime_module_imports_the_eval_harness() -> None:
    """PY003 in architecture.toml says so; this checks the text as well, because
    a test double that leaks into the product is how a second path starts."""
    for directory in ("runtime/src", "crates", "tools/dwcheck/src"):
        for path in sorted((REPO_ROOT / directory).rglob("*.py")):
            assert "direwolf_evals" not in path.read_text(encoding="utf-8"), path


# --- the inventory ----------------------------------------------------------


def test_every_inventory_entry_names_a_roadmap_milestone() -> None:
    roadmap = (REPO_ROOT / "docs/ROADMAP.md").read_text(encoding="utf-8")
    for item in INVENTORY:
        assert re.search(rf"##+ {re.escape(item.milestone)} ", roadmap), item.milestone


def test_pending_properties_have_no_suite_and_available_ones_do() -> None:
    assert pending(), "if nothing is pending, the inventory is not being kept"
    assert available()
    for item in pending():
        assert item.suite is None
        assert item.note.strip()
    for item in available():
        assert item.suite


def test_the_inventory_is_honest_about_what_m2_5_proves() -> None:
    """No entry may claim an authority property is measurable today."""
    words = ("policy", "capabilit", "approval", "sandbox", "secret", "egress", "peer")
    for item in available():
        assert not any(w in item.property.lower() for w in words), item.property


def test_python_version_supports_the_harness() -> None:
    assert sys.version_info >= (3, 12)
