"""M5e.3's registry fixture generator stays bytes (M5E_ASSURANCE_PLAN.md §7a, "Guards").

`tests/sandbox/registry_fixtures.py` is test data, generated. The plan holds
it to the standard library, no network module and no public host name, so
that nothing it makes was fetched, nothing it makes names a real registry, and
nothing it does reaches past the directory it writes. This module checks
that from its source and from what it generates:

* it imports only the standard library, and nothing that opens a route off
  the machine, starts a process, loads code by name or calls into C;
* it calls no builtin that runs code (`exec`, `eval`, `compile`,
  `__import__`);
* no string in it spells a host: every URL's host comes from its two
  constants, both under RFC 6761's reserved `.test`, and no public registry
  or forge is named;
* every URL in everything it generates -- archives included, which it stores
  rather than compresses -- names one of those two hosts;
* every package it makes, and every dependency it names, is one of its own;
* its default marker directory is the sandbox profile's workspace.

It reads source and generates into a temporary directory; it serves,
installs and runs nothing, and it is not evidence.
"""

from __future__ import annotations

import ast
import gzip
import io
import json
import re
import sys
import tarfile
import zipfile
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[2]
GENERATOR = REPO_ROOT / "tests" / "sandbox" / "registry_fixtures.py"
PROFILE = REPO_ROOT / "crates" / "dwk-sandbox-profile" / "src" / "lib.rs"
sys.path.insert(0, str(GENERATOR.parent))
import registry_fixtures as fx  # noqa: E402  - imported after the path is extended

# A route off the machine, a process, code loaded by name, or a call into C.
_BANNED_MODULES = frozenset(
    {
        "asyncio",
        "concurrent",
        "ctypes",
        "ftplib",
        "http",
        "imaplib",
        "importlib",
        "mmap",
        "multiprocessing",
        "nntplib",
        "os",
        "poplib",
        "pty",
        "runpy",
        "selectors",
        "shutil",
        "smtplib",
        "socket",
        "socketserver",
        "ssl",
        "subprocess",
        "urllib",
        "webbrowser",
        "xmlrpc",
    }
)
_BANNED_CALLS = frozenset({"exec", "eval", "compile", "__import__", "breakpoint"})
_PUBLIC = (
    "pypi.org",
    "pythonhosted.org",
    "npmjs.org",
    "npmjs.com",
    "yarnpkg.com",
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "localhost",
    "127.0.0.1",
)
_URL = re.compile(rb"[A-Za-z][A-Za-z0-9+.-]*://([^/\s\"'<>#]*)")


def _tree() -> ast.Module:
    return ast.parse(GENERATOR.read_text(encoding="utf-8"), filename=str(GENERATOR))


def test_it_imports_only_the_standard_library_and_nothing_that_leaves_the_directory() -> None:
    imported: set[str] = set()
    for node in ast.walk(_tree()):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom):
            assert node.level == 0 and node.module, ast.dump(node)
            imported.add(node.module.split(".")[0])
    imported.discard("__future__")
    assert imported, "the generator's imports were not read"
    foreign = sorted(imported - sys.stdlib_module_names)
    assert not foreign, f"the generator imports beyond the standard library: {foreign}"
    banned = sorted(imported & _BANNED_MODULES)
    assert not banned, f"the generator imports a way out of its directory: {banned}"


def test_it_calls_no_builtin_that_runs_code() -> None:
    called = {
        node.func.id
        for node in ast.walk(_tree())
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    assert called, "the generator's calls were not read"
    assert not called & _BANNED_CALLS, sorted(called & _BANNED_CALLS)


def test_no_string_in_it_spells_a_host() -> None:
    for node in ast.walk(_tree()):
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            for found in _URL.finditer(node.value.encode()):
                # A URL's host is always a formatted value: one of the two
                # constants, never a literal.
                assert found.group(1) == b"", f"a literal URL host: {node.value!r}"
    for host in (fx.GRANTED_HOST, fx.UNGRANTED_HOST):
        assert re.fullmatch(r"[a-z0-9-]+\.test", host), host
    assert fx.GRANTED_HOST != fx.UNGRANTED_HOST
    source = GENERATOR.read_text(encoding="utf-8").lower()
    named = [public for public in _PUBLIC if public in source]
    assert not named, f"the generator names a public host: {named}"


def _generated(tmp_path: Path) -> tuple[dict[str, bytes], dict[str, Any]]:
    out = tmp_path / "fixtures"
    fx.generate("architecture-guard", out)
    files = {
        path.relative_to(out).as_posix(): path.read_bytes()
        for path in sorted(out.rglob("*"))
        if path.is_file()
    }
    return files, json.loads(files["manifest.json"])


def test_everything_it_generates_names_only_its_two_hosts(tmp_path: Path) -> None:
    files, _ = _generated(tmp_path)
    hosts: set[bytes] = set()
    for path, data in files.items():
        hosts.update(found.group(1) for found in _URL.finditer(data))
        lowered = data.lower()
        named = [public for public in _PUBLIC if public.encode() in lowered]
        assert not named, f"{path} names a public host: {named}"
    assert hosts == {fx.GRANTED_HOST.encode(), fx.UNGRANTED_HOST.encode()}, hosts


def _npm_documents(files: dict[str, bytes]) -> dict[str, Any]:
    """Every npm document generated, a tarball's package.json included."""
    documents: dict[str, Any] = {}
    for path, data in files.items():
        if path.endswith(".tgz"):
            with tarfile.open(fileobj=io.BytesIO(gzip.decompress(data))) as archive:
                handle = archive.extractfile("package/package.json")
                assert handle is not None, path
                documents[f"{path}!package/package.json"] = json.loads(handle.read())
        elif path.endswith(".json") or path.startswith(("granted/npm/", "ungranted/npm/")):
            documents[path] = json.loads(data)
    return documents


def _named(document: object) -> set[str]:
    """Every package name a document's `dependencies` (anywhere in it) names."""
    names: set[str] = set()
    if isinstance(document, dict):
        for key, value in document.items():
            if key == "dependencies" and isinstance(value, dict):
                names.update(value)
            names |= _named(value)
    elif isinstance(document, list):
        for value in document:
            names |= _named(value)
    return names


def test_every_package_and_every_dependency_it_names_is_its_own(tmp_path: Path) -> None:
    files, manifest = _generated(tmp_path)
    own = f"dwfx-{manifest['tag']}-"
    names = [p["name"] for p in manifest["pip"]["projects"].values()]
    names += [p["name"] for p in manifest["npm"]["packages"].values()]
    assert names and all(name.startswith(own) for name in names), names
    required = 0
    for path, data in files.items():
        if path.endswith(".whl"):
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                for member in archive.namelist():
                    if member.endswith(".dist-info/METADATA"):
                        text = archive.read(member).decode()
                        for spec in re.findall(r"^Requires-Dist: (\S+)", text, re.M):
                            assert spec.startswith(own), (path, spec)
                            required += 1
    assert required >= 1, "no wheel's dependency was read"
    depended = set()
    for path, document in _npm_documents(files).items():
        for name in _named(document):
            assert name.startswith(own), (path, name)
            depended.add(name)
    assert len(depended) >= 3, depended


def test_its_markers_default_to_the_sandbox_profiles_workspace() -> None:
    target = re.search(
        r'pub const WORKSPACE_TARGET: &str = "([^"]+)";', PROFILE.read_text(encoding="utf-8")
    )
    assert target is not None
    assert target.group(1) == fx.MARKER_DIR
