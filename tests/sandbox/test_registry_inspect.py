"""M5e.4's inspection helper: what an install is held to, byte for byte.

`tests/sandbox/registry_inspect.py` is how the registry evidence sees what pip
left in an environment and compares it with the fixtures. A check that passed
something pip did not install exactly -- a member missing, a byte changed, a
file the wheel never held -- would let the evidence call any install the
fixture's. So each way an install can differ is shown to fail here, on every
platform `make test` runs on, against M5e.3's generated wheels; and the `.pth`
residual the evidence states is shown real: a site directory holding the
fixture's `.pth` runs it.

Nothing here runs pip, installs anything or opens a socket.
"""

from __future__ import annotations

import hashlib
import json
import sys
import zipfile
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import registry_fixtures as fx
import registry_inspect as ri

SEED = "direwolf-m5e4-inspect"


def _fixtures(tmp_path: Path, marker_dir: str = fx.MARKER_DIR) -> tuple[Path, dict[str, Any]]:
    out = tmp_path / "fixtures"
    manifest = fx.generate(
        SEED, out, marker_dir=marker_dir, granted_port=18443, ungranted_port=18444
    )
    return out, manifest


def _install(fixtures: Path, roles: list[str], target: Path) -> None:
    """What `pip install --target --no-compile` leaves for `roles`' wheels:
    each member, and `INSTALLER`, `REQUESTED` and a rewritten `RECORD` in each
    `.dist-info`."""
    manifest = json.loads((fixtures / "manifest.json").read_bytes())
    for role in roles:
        wheel = fixtures / "granted" / "files" / manifest["pip"]["projects"][role]["file"]
        with zipfile.ZipFile(wheel) as archive:
            archive.extractall(target)
            info = next(name.split("/")[0] for name in archive.namelist() if ".dist-info/" in name)
        (target / info / "INSTALLER").write_bytes(b"pip\n")
        (target / info / "REQUESTED").write_bytes(b"")
        (target / info / "RECORD").write_bytes(b"rewritten by pip\n")


def _tree_file(tmp_path: Path, target: Path) -> Path:
    path = tmp_path / "tree.json"
    path.write_text(json.dumps(ri.tree(str(target))), encoding="utf-8")
    return path


def test_the_plan_names_every_project_and_marker(tmp_path: Path) -> None:
    out, manifest = _fixtures(tmp_path)
    plan = ri.plan(out)
    assert plan["ports"] == {"granted": 18443, "ungranted": 18444}
    assert plan["markers"] == manifest["markers"]
    projects = plan["projects"]
    assert isinstance(projects, dict)
    assert set(projects) == {"base", "dependent", "sdist", "pth", "offsite", "redirected"}
    assert projects["sdist"]["file"].endswith(".tar.gz")


def test_the_plan_names_every_npm_package_the_hygiene_suite_asks_for(tmp_path: Path) -> None:
    """M5e.5's suite reads each npm package's name from the plan (run
    42846068083 failed both npm tests at their first line without it)."""
    out, manifest = _fixtures(tmp_path)
    packages = ri.plan(out)["npm"]["packages"]  # type: ignore[index]
    assert isinstance(packages, dict)
    assert set(packages) == set(manifest["npm"]["packages"])
    for role in ("plain", "offsite-parent", "redirected", "git-parent", "tampered"):
        published = manifest["npm"]["packages"][role]
        assert packages[role] == {
            "name": str(published["name"]),
            "version": str(published["version"]),
        }


def test_an_exact_install_passes_and_counts_its_files(tmp_path: Path) -> None:
    out, _ = _fixtures(tmp_path)
    target = tmp_path / "target"
    _install(out, ["dependent", "base"], target)
    verdict = ri.check(out, ["dependent", "base"], _tree_file(tmp_path, target))
    assert verdict["ok"] is True, verdict
    members = len(ri.wheel_members(out, "dependent")) + len(ri.wheel_members(out, "base"))
    # Each wheel's members, and INSTALLER and REQUESTED beside each RECORD.
    assert verdict["files"] == members + 4


@pytest.mark.parametrize(
    ("damage", "said"),
    [
        ("missing", "is not installed"),
        ("changed", "is not the fixture's bytes"),
        ("extra", "is no member of the fixture's wheels"),
        ("pycache", "is no member of the fixture's wheels"),
        ("installer", "does not name pip"),
        ("other-role", "is not installed"),
    ],
)
def test_an_install_that_differs_from_the_fixture_fails(
    tmp_path: Path, damage: str, said: str
) -> None:
    out, _ = _fixtures(tmp_path)
    target = tmp_path / "target"
    _install(out, ["base"], target)
    module = next(target.glob("dwfx_*_base/__init__.py"))
    info = next(target.glob("*.dist-info"))
    roles = ["base"]
    if damage == "missing":
        module.unlink()
    elif damage == "changed":
        module.write_bytes(module.read_bytes() + b"# changed\n")
    elif damage == "extra":
        (target / "evil.py").write_text("print('not the fixture')\n")
    elif damage == "pycache":
        (module.parent / "__pycache__").mkdir()
        (module.parent / "__pycache__" / "__init__.cpython-312.pyc").write_bytes(b"\0")
    elif damage == "installer":
        (info / "INSTALLER").write_bytes(b"not-pip\n")
    else:
        roles = ["base", "dependent"]
    verdict = ri.check(out, roles, _tree_file(tmp_path, target))
    assert verdict["ok"] is False and said in str(verdict["problem"]), verdict


def _compile_like_pip(target: Path) -> list[Path]:
    """What pip's default byte-compilation leaves: `__pycache__/M.cpython-NNN.pyc`
    beside each installed module `M.py` (its bytes are pip's, never checked)."""
    tag = f"cpython-{sys.version_info.major}{sys.version_info.minor}"
    written: list[Path] = []
    for module in sorted(target.rglob("*.py")):
        cache = module.parent / "__pycache__"
        cache.mkdir(exist_ok=True)
        compiled = cache / f"{module.stem}.{tag}.pyc"
        compiled.write_bytes(b"compiled")
        written.append(compiled)
    return written


def test_what_pip_compiles_passes_only_when_asked(tmp_path: Path) -> None:
    """Run 42846068083: under M5e.5's profile pip byte-compiles, as it does by
    default. `--compiled` admits exactly that; M5e.4's check stays as it was."""
    out, _ = _fixtures(tmp_path)
    target = tmp_path / "target"
    _install(out, ["dependent", "base"], target)
    written = _compile_like_pip(target)
    assert written
    tree = _tree_file(tmp_path, target)
    assert ri.check(out, ["dependent", "base"], tree)["ok"] is False
    verdict = ri.check(out, ["dependent", "base"], tree, compiled=True)
    assert verdict["ok"] is True, verdict
    members = len(ri.wheel_members(out, "dependent")) + len(ri.wheel_members(out, "base"))
    assert verdict["files"] == members + 4 + len(written)


@pytest.mark.parametrize(
    "stray",
    [
        "evil.cpython-312.pyc",  # no module of the wheels' beside it
        "__init__.cpython-312.opt-1.pyc",  # an optimisation level pip never asks for
        "__init__.pyc",  # no cache tag
        "__init__.pypy-312.pyc",  # another implementation's tag
    ],
)
def test_compiled_admits_nothing_but_pips_own_cache_files(tmp_path: Path, stray: str) -> None:
    out, _ = _fixtures(tmp_path)
    target = tmp_path / "target"
    _install(out, ["base"], target)
    module = next(target.glob("dwfx_*_base/__init__.py"))
    (module.parent / "__pycache__").mkdir()
    (module.parent / "__pycache__" / stray).write_bytes(b"\0")
    verdict = ri.check(out, ["base"], _tree_file(tmp_path, target), compiled=True)
    assert verdict["ok"] is False, verdict
    assert "is no member of the fixture's wheels" in str(verdict["problem"])


def test_compiled_never_stands_in_for_a_missing_module(tmp_path: Path) -> None:
    out, _ = _fixtures(tmp_path)
    target = tmp_path / "target"
    _install(out, ["base"], target)
    _compile_like_pip(target)
    next(target.glob("dwfx_*_base/__init__.py")).unlink()
    verdict = ri.check(out, ["base"], _tree_file(tmp_path, target), compiled=True)
    assert verdict["ok"] is False and "is not installed" in str(verdict["problem"])


def test_nothing_installed_is_never_an_install(tmp_path: Path) -> None:
    out, _ = _fixtures(tmp_path)
    absent = ri.tree(str(tmp_path / "absent"))
    assert absent == {"exists": False, "files": {}}
    path = tmp_path / "tree.json"
    path.write_text(json.dumps(absent), encoding="utf-8")
    verdict = ri.check(out, ["base"], path)
    assert verdict["ok"] is False and "is not installed" in str(verdict["problem"])
    assert ri.installed_problem({}, {}) == "no wheel is expected"


def test_a_source_distribution_is_no_wheel_to_hold_an_install_to(tmp_path: Path) -> None:
    out, _ = _fixtures(tmp_path)
    with pytest.raises(ValueError, match="not a wheel"):
        ri.wheel_members(out, "sdist")


def test_a_wheel_the_manifest_does_not_record_is_refused(tmp_path: Path) -> None:
    out, manifest = _fixtures(tmp_path)
    wheel = out / "granted" / "files" / manifest["pip"]["projects"]["base"]["file"]
    wheel.write_bytes(wheel.read_bytes() + b"\0")
    with pytest.raises(ValueError, match="not the bytes the manifest records"):
        ri.wheel_members(out, "base")


@pytest.mark.skipif(sys.platform == "win32", reason="symbolic links need privilege on Windows")
def test_a_link_is_recorded_and_never_followed(tmp_path: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    (tmp_path / "outside").write_text("outside")
    (target / "link").symlink_to(tmp_path / "outside")
    (target / "dir").mkdir()
    (target / "dir" / "up").symlink_to(tmp_path)
    files = ri.tree(str(target))["files"]
    assert files == {
        "dir/up": f"symlink:{tmp_path}",
        "link": f"symlink:{tmp_path / 'outside'}",
    }


def test_the_pth_the_install_leaves_runs_at_a_later_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The residual the evidence states: a site directory holding the
    fixture's `.pth` runs it -- `site` does, at any interpreter start whose
    site path holds the directory."""
    marks = tmp_path / "marks"
    marks.mkdir()
    out, manifest = _fixtures(tmp_path, marker_dir=str(marks))
    target = tmp_path / "target"
    _install(out, ["pth"], target)
    markers = manifest["markers"]
    assert isinstance(markers, dict)
    assert not any(marks.iterdir())
    monkeypatch.setattr(sys, "path", list(sys.path))
    added = ri.add_site(str(target))
    assert str(target) in added["added"]  # type: ignore[operator]
    assert sorted(p.name for p in marks.iterdir()) == [markers["pip-pth"]]


def test_the_versions_are_the_interpreters_and_pips(capsys: pytest.CaptureFixture[str]) -> None:
    pytest.importorskip("pip")
    assert ri.main(["versions"]) == 0
    found = json.loads(capsys.readouterr().out)
    assert found["python"] == sys.version.split()[0]
    assert found["executable"] == sys.executable


def test_the_command_line_says_one_json_line_or_its_usage(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out, _ = _fixtures(tmp_path)
    assert ri.main(["plan", str(out)]) == 0
    line = capsys.readouterr().out
    assert line.count("\n") == 1 and json.loads(line)["projects"]
    assert ri.main(["tree"]) == 2
    assert ri.main(["nothing"]) == 2
    target = tmp_path / "target"
    _install(out, ["base"], target)
    tree = str(_tree_file(tmp_path, target))
    assert ri.main(["check", str(out), "base", tree, "--compiled"]) == 0
    assert json.loads(capsys.readouterr().out)["ok"] is True
    assert ri.main(["check", str(out), "base", tree, "--other"]) == 2
    digest = hashlib.sha256(b"x").hexdigest()
    (tmp_path / "t").mkdir()
    (tmp_path / "t" / "x").write_bytes(b"x")
    assert ri.main(["tree", str(tmp_path / "t")]) == 0
    assert json.loads(capsys.readouterr().out.splitlines()[-1]) == {
        "exists": True,
        "files": {"x": digest},
    }
