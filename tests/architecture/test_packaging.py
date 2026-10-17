"""The Python packages build as a release would build them.

`uv sync` installs each workspace package editable, straight from the source
tree, so no ordinary gate builds one the way it would be published: a source
distribution first, then a wheel from that source distribution alone. A file
a package names from outside its own directory -- the runtime's readme was
`../README.md` -- is in the tree, so editable installs never notice; it is
missing from the sdist, so a wheel cannot be built from it.
"""

from __future__ import annotations

import shutil
import subprocess
import tarfile
import tomllib
import zipfile
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]

# Every Python package in the workspace, by directory: its distribution name.
PACKAGES = {
    "evals": "direwolf-evals",
    "runtime": "direwolf",
    "tools/dwcheck": "dwcheck",
}


def _project(directory: str) -> dict[str, object]:
    text = (REPO_ROOT / directory / "pyproject.toml").read_text(encoding="utf-8")
    project = tomllib.loads(text)["project"]
    assert isinstance(project, dict)
    return project


def _readme(directory: str) -> str | None:
    """The file a package's metadata names as its readme, if it names one."""
    readme = _project(directory).get("readme")
    if isinstance(readme, dict):
        readme = readme.get("file")
    assert readme is None or isinstance(readme, str), readme
    return readme


def test_the_listed_packages_are_the_workspace() -> None:
    root = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert sorted(root["tool"]["uv"]["workspace"]["members"]) == sorted(PACKAGES)
    for directory, name in PACKAGES.items():
        assert _project(directory)["name"] == name


@pytest.mark.parametrize("directory", sorted(PACKAGES))
def test_no_package_names_a_readme_outside_its_own_directory(directory: str) -> None:
    """What a package's metadata names must be inside the package: its sdist
    carries only that directory, and its wheel is built from the sdist."""
    readme = _readme(directory)
    if readme is None:
        return
    package = (REPO_ROOT / directory).resolve()
    path = (package / readme).resolve()
    assert path.is_relative_to(package), f"{directory}: readme {readme!r} is outside the package"
    assert path.is_file(), f"{directory}: readme {readme!r} does not exist"


def _uv(*args: str) -> None:
    uv = shutil.which("uv")
    if uv is None:
        pytest.skip("uv is not installed")
    result = subprocess.run(
        [uv, *args],
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        check=False,
        timeout=600,
    )
    assert result.returncode == 0, f"uv {' '.join(args)}:\n{result.stderr[-3000:]}"


@pytest.mark.slow
@pytest.mark.parametrize("directory", sorted(PACKAGES))
def test_each_package_builds_a_wheel_from_its_own_sdist(directory: str, tmp_path: Path) -> None:
    """The sdist first, then a wheel from that archive alone -- what a
    release does, and what an editable install never exercises."""
    name = PACKAGES[directory]
    _uv("build", "--package", name, "--sdist", "--out-dir", str(tmp_path / "sdist"))
    (sdist,) = sorted((tmp_path / "sdist").glob("*.tar.gz"))
    _uv("build", str(sdist), "--wheel", "--out-dir", str(tmp_path / "wheel"))
    (wheel,) = sorted((tmp_path / "wheel").glob("*.whl"))
    with tarfile.open(sdist) as archive:
        members = archive.getnames()
    assert all(".." not in Path(member).parts for member in members), members
    with zipfile.ZipFile(wheel) as archive:
        files = archive.namelist()
        (metadata,) = [f for f in files if f.endswith(".dist-info/METADATA")]
        text = archive.read(metadata).decode("utf-8")
    assert f"\nName: {name}\n" in text
    if _readme(directory) is not None:
        assert "Description-Content-Type: text/markdown" in text, "the readme reached the wheel"
    # A typed package stays typed when built: every `py.typed` in the source
    # tree is in the wheel.
    source = REPO_ROOT / directory / "src"
    for marker in source.rglob("py.typed"):
        assert marker.relative_to(source).as_posix() in files, (
            f"{name}: {marker} not in {wheel.name}"
        )
