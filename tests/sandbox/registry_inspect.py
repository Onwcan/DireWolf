"""M5e.4's registry evidence: what pip left, and what the fixtures say it must be.

Standard library only. It opens no socket and starts no process. Each command
prints one JSON line.

Inside the environment, run by the registry tools image's Python
(`crates/dwkd-authority/tests/sandbox_registry.rs`), because pip's files belong
to uid 10001 and the host cannot read them:

    registry_inspect.py versions       the interpreter's version and pip's, and
                                       where the interpreter is
    registry_inspect.py tree DIR       every file under DIR with its SHA-256, a
                                       link as `symlink:<target>`, never
                                       followed; `exists` false if DIR is absent
    registry_inspect.py site DIR       DIR added as a site directory, as a later
                                       interpreter start whose path holds it
                                       would: its `.pth` lines run

On the host, against the fixture set `registry_fixtures.generate` wrote:

    registry_inspect.py plan FIXTURES             every pip project's name,
                                                  version and file, every npm
                                                  package's name and version,
                                                  and every marker's name
    registry_inspect.py check FIXTURES ROLES TREE [--compiled]
                                                  the TREE file (`tree`'s line)
                                                  against the wheels of ROLES
                                                  (comma-separated)

`check` holds an install to the fixture byte for byte: every member of each
wheel present with the wheel's own SHA-256 -- the `RECORD` aside, which pip
rewrites -- and nothing else but what pip itself writes beside it in each
`.dist-info` (`INSTALLER`, `REQUESTED`, `RECORD`). No `__pycache__` unless
`--compiled`: M5e.4's evidence installs with `--no-compile`; M5e.5's runs pip
as its profile leaves it, which byte-compiles, so there a wheel's module
`D/M.py` may have pip's `D/__pycache__/M.cpython-NNN.pyc` beside it, and
nothing else may be. Nothing here is evidence by itself: the suite's lines
are.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import site
import sys
import zipfile
from pathlib import Path

# What pip writes into a `.dist-info` beside the wheel's own members.
PIP_WRITES = frozenset(("INSTALLER", "REQUESTED", "RECORD"))
INSTALLER = b"pip\n"
# What pip's byte-compilation writes for a module `M.py`: the interpreter's
# cache tag and no optimisation level (pip compiles at the default).
COMPILED = re.compile(r"(?P<dir>(?:.+/)?)__pycache__/(?P<stem>[^/]+)\.cpython-[0-9]+\.pyc")


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def versions() -> dict[str, object]:
    import pip

    return {
        "python": sys.version.split()[0],
        "pip": pip.__version__,
        "executable": sys.executable,
        "prefix": sys.prefix,
    }


def tree(directory: str) -> dict[str, object]:
    """Every file under `directory`, by its path relative to it."""
    root = Path(directory)
    if not root.is_dir():
        return {"exists": root.exists(), "files": {}}
    files: dict[str, str] = {}
    for parent, dirs, names in os.walk(root, followlinks=False):
        here = Path(parent)
        for name in sorted(dirs):
            path = here / name
            if path.is_symlink():
                files[path.relative_to(root).as_posix()] = f"symlink:{path.readlink()}"
        for name in sorted(names):
            path = here / name
            relative = path.relative_to(root).as_posix()
            if path.is_symlink():
                files[relative] = f"symlink:{path.readlink()}"
            else:
                files[relative] = _sha256(path.read_bytes())
    return {"exists": True, "files": dict(sorted(files.items()))}


def add_site(directory: str) -> dict[str, object]:
    """`directory` processed as a site directory: what `site` does at an
    interpreter's start for each directory on its site path."""
    before = set(sys.path)
    site.addsitedir(directory)
    return {"added": sorted(set(sys.path) - before)}


def _manifest(fixtures: Path) -> dict[str, object]:
    manifest = json.loads((fixtures / "manifest.json").read_text(encoding="utf-8"))
    if not isinstance(manifest, dict) or manifest.get("format") != 1:
        raise ValueError(f"{fixtures}: not a format-1 fixture manifest")
    return manifest


def _projects(manifest: dict[str, object]) -> dict[str, dict[str, str]]:
    pip = manifest["pip"]
    assert isinstance(pip, dict)
    projects = pip["projects"]
    assert isinstance(projects, dict)
    return projects


def _npm_packages(manifest: dict[str, object]) -> dict[str, dict[str, object]]:
    npm = manifest["npm"]
    assert isinstance(npm, dict)
    packages = npm["packages"]
    assert isinstance(packages, dict)
    return packages


def plan(fixtures: Path) -> dict[str, object]:
    manifest = _manifest(fixtures)
    return {
        "projects": {
            role: {key: str(project[key]) for key in ("name", "version", "file")}
            for role, project in sorted(_projects(manifest).items())
        },
        "npm": {
            "packages": {
                role: {key: str(package[key]) for key in ("name", "version")}
                for role, package in sorted(_npm_packages(manifest).items())
            }
        },
        "markers": manifest["markers"],
        "marker_dir": manifest["marker_dir"],
        "ports": manifest.get("ports"),
    }


def wheel_members(fixtures: Path, role: str) -> dict[str, str]:
    """Each member of `role`'s wheel, as the fixture set holds it, by SHA-256."""
    manifest = _manifest(fixtures)
    filename = _projects(manifest)[role]["file"]
    if not filename.endswith(".whl"):
        raise ValueError(f"{role}'s file {filename} is not a wheel")
    files = manifest["files"]
    assert isinstance(files, dict)
    sides = (f"granted/files/{filename}", f"ungranted/files/{filename}")
    path = next((p for p in sides if p in files), None)
    if path is None:
        raise ValueError(f"{filename} is served by neither origin")
    data = (fixtures / path).read_bytes()
    if _sha256(data) != files[path]:
        raise ValueError(f"{path} is not the bytes the manifest records")
    with zipfile.ZipFile(fixtures / path) as archive:
        return {
            info.filename: _sha256(archive.read(info))
            for info in archive.infolist()
            if not info.is_dir()
        }


def _compiled_by_pip(path: str, expected: dict[str, str]) -> bool:
    """Whether `path` is what pip's byte-compilation writes for one of the
    wheels' own modules."""
    found = COMPILED.fullmatch(path)
    return found is not None and f"{found['dir']}{found['stem']}.py" in expected


def installed_problem(
    expected: dict[str, str], installed: dict[str, str], *, compiled: bool = False
) -> str | None:
    """Why `installed` is not exactly `expected`'s wheels as pip installs
    them -- with what pip compiles from their modules when `compiled` -- or
    None."""
    tops = {path.split("/", 1)[0] for path in expected}
    infos = {top for top in tops if top.endswith(".dist-info")}
    for path, digest in sorted(expected.items()):
        if path.endswith(".dist-info/RECORD"):
            continue
        if path not in installed:
            return f"{path} is not installed"
        if installed[path] != digest:
            return f"{path} is not the fixture's bytes"
    for path, digest in sorted(installed.items()):
        if path in expected and not path.endswith(".dist-info/RECORD"):
            continue
        top, _, rest = path.partition("/")
        if top in infos and rest in PIP_WRITES:
            if rest == "INSTALLER" and digest != _sha256(INSTALLER):
                return f"{path} does not name pip"
            continue
        if compiled and _compiled_by_pip(path, expected):
            continue
        return f"{path} is installed but is no member of the fixture's wheels"
    if not expected:
        return "no wheel is expected"
    return None


def check(
    fixtures: Path, roles: list[str], tree_file: Path, *, compiled: bool = False
) -> dict[str, object]:
    measured = json.loads(tree_file.read_text(encoding="utf-8"))
    expected: dict[str, str] = {}
    for role in roles:
        for path, digest in wheel_members(fixtures, role).items():
            if path in expected and expected[path] != digest:
                return {"ok": False, "problem": f"{path} differs between the roles' wheels"}
            expected[path] = digest
    installed = measured.get("files", {}) if measured.get("exists") else {}
    problem = installed_problem(expected, installed, compiled=compiled)
    if problem is not None:
        return {"ok": False, "problem": problem}
    return {"ok": True, "files": len(installed), "roles": roles}


def main(argv: list[str]) -> int:
    if argv[:1] == ["versions"] and len(argv) == 1:
        result: dict[str, object] = versions()
    elif argv[:1] == ["tree"] and len(argv) == 2:
        result = tree(argv[1])
    elif argv[:1] == ["site"] and len(argv) == 2:
        result = add_site(argv[1])
    elif argv[:1] == ["plan"] and len(argv) == 2:
        result = plan(Path(argv[1]))
    elif argv[:1] == ["check"] and len(argv) == 4:
        result = check(Path(argv[1]), argv[2].split(","), Path(argv[3]))
    elif argv[:1] == ["check"] and len(argv) == 5 and argv[4] == "--compiled":
        result = check(Path(argv[1]), argv[2].split(","), Path(argv[3]), compiled=True)
    else:
        print(__doc__, file=sys.stderr)
        return 2
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
