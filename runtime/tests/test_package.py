"""Foundation tests for the `direwolf` package.

These assert that the package is real -- importable, versioned, typed -- and
that it has not quietly grown subsystems that belong to later milestones.
"""

from __future__ import annotations

import importlib.util
import pkgutil
import subprocess
import sys
from pathlib import Path

import direwolf


def test_package_imports_and_reports_a_version() -> None:
    assert isinstance(direwolf.__version__, str)
    assert direwolf.__version__


def test_version_matches_the_repository_version_file() -> None:
    """One version, one source of truth (see `dwcheck version`)."""
    repo_root = Path(__file__).resolve().parents[2]
    expected = (repo_root / "VERSION").read_text(encoding="utf-8").strip()
    assert direwolf.__version__ == expected


def test_package_ships_a_py_typed_marker() -> None:
    package_dir = Path(direwolf.__file__).parent
    assert (package_dir / "py.typed").is_file()


def test_no_subsystem_modules_exist_yet() -> None:
    """M1 is the foundation. A module here before its milestone is a stub.

    If you are landing one of these, delete its name from this list in the same
    commit -- that is the point of the test.
    """
    unimplemented = {
        "loop",
        "context",
        "providers",
        "routing",
        "memory",
        "tools",
        "mcp",
        "skills",
        "orchestration",
        "session",
        "store",
        "events",
        "kernelclient",
    }
    present = {m.name for m in pkgutil.iter_modules(direwolf.__path__)}
    assert not (present & unimplemented), (
        f"unimplemented subsystems present: {sorted(present & unimplemented)}"
    )


def test_importing_the_package_does_not_pull_in_a_network_module() -> None:
    """The runtime has no network route and no exec path by construction.

    A transitive import of a socket or HTTP module at package-import time would
    mean the constraint had been designed away rather than enforced.

    This is development hygiene, not containment: a prompt-injected ``exec()``
    can still call ``__import__("socket")`` and no static check will see it.
    The OS-level network restriction on the runtime identity is the actual
    control (docs/ARCHITECTURE.md §6).
    """
    probe = (
        "import sys, direwolf; "
        "banned = {'socket', 'ssl', 'http.client', 'urllib.request', 'requests', 'httpx'}; "
        "print(sorted(banned & set(sys.modules)))"
    )
    result = subprocess.run(
        [sys.executable, "-c", probe], capture_output=True, text=True, check=True
    )
    assert result.stdout.strip() == "[]", (
        f"imported at package-import time: {result.stdout.strip()}"
    )


def test_importlib_can_find_the_distribution() -> None:
    assert importlib.util.find_spec("direwolf") is not None
