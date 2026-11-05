"""M5e.3's registry fixtures: deterministic, self-consistent, and their markers live.

`tests/sandbox/registry_fixtures.py` generates the PEP 503 index and the npm
registry M5e.4's evidence will install from (M5E_ASSURANCE_PLAN.md §7a). These
tests hold §7a's "done when" for the generator, the index and the registry:

* the same seed gives byte-identical output, another seed differs, a fixed
  seed gives recorded bytes on every host, and no output names where it was
  written;
* every archive is sorted, stored, owned by no one and modified at 0;
* each wheel's RECORD matches its contents;
* the pages parse with the standard library's HTML parser, and each link's
  hash is its file's;
* every untampered tarball matches its packument's integrity and the tampered
  one does not;
* the lockfile names exactly the packuments' integrity;
* every route serves a file the manifest states, and every redirect leaves
  for the ungranted host;
* each marker a negative case will look for is written when its code runs --
  so its absence can only mean that the code did not run.

Nothing here serves, installs or runs a package manager; the one interpreter
started is this one, `-I`, over the fixture's own `.pth` and modules.
"""

from __future__ import annotations

import ast
import base64
import configparser
import csv
import gzip
import hashlib
import html.parser
import importlib.util
import io
import json
import os
import re
import shlex
import subprocess
import sys
import tarfile
import tomllib
import zipfile
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import registry_fixtures as fx

SEED = "direwolf-m5e3"
# manifest.json's SHA-256 for SEED. Every file's digest is in the manifest, so
# this one value pins every byte; a deliberate change to the fixtures changes
# it, and so does any host- or version-dependent byte.
GOLDEN = "61472c81a55e7f6d89162a6c62c6b4ecbe4b65d86db31a2b80bffab286cf4e51"


def _generate(
    tmp_path: Path, seed: str = SEED, name: str = "out", marker_dir: str = fx.MARKER_DIR
) -> tuple[Path, dict[str, Any]]:
    out = tmp_path / name
    fx.generate(seed, out, marker_dir=marker_dir)
    manifest: dict[str, Any] = json.loads((out / "manifest.json").read_bytes())
    return out, manifest


def _files(out: Path) -> dict[str, bytes]:
    return {
        path.relative_to(out).as_posix(): path.read_bytes()
        for path in sorted(out.rglob("*"))
        if path.is_file()
    }


def _served(out: Path, manifest: dict[str, Any], url: str) -> bytes:
    """What the origin `url` names serves at its path, by the manifest's routes."""
    parts = urlsplit(url)
    assert parts.hostname is not None, url
    side = {fx.GRANTED_HOST: "granted", fx.UNGRANTED_HOST: "ungranted"}[parts.hostname]
    route = manifest["routes"][side][parts.path]
    return (out / str(route["file"])).read_bytes()


def _archives(out: Path, *suffixes: str) -> list[Path]:
    return sorted(path for path in out.rglob("*") if path.name.endswith(suffixes))


class _Links(html.parser.HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.links: list[tuple[str, str]] = []
        self._href: str | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag == "a":
            href = dict(attrs).get("href")
            assert href, attrs
            self._href = href

    def handle_data(self, data: str) -> None:
        if self._href is not None:
            self.links.append((self._href, data))
            self._href = None


def _links(page: bytes) -> list[tuple[str, str]]:
    parser = _Links()
    parser.feed(page.decode("utf-8"))
    parser.close()
    return parser.links


def _packuments(out: Path, manifest: dict[str, Any]) -> dict[tuple[str, str], Any]:
    return {
        (side, path): json.loads((out / route["file"]).read_bytes())
        for side, routes in manifest["routes"].items()
        for path, route in routes.items()
        if route.get("type") == "application/json"
    }


def test_the_same_seed_gives_the_same_bytes_and_another_seed_differs(tmp_path: Path) -> None:
    a, first = _generate(tmp_path, name="a")
    b, _ = _generate(tmp_path, name="b")
    c, other = _generate(tmp_path, seed="another-seed", name="c")
    assert _files(a) == _files(b)
    # Package names and versions come from the seed.
    assert _files(a).keys() != _files(c).keys()
    assert _files(a)["manifest.json"] != _files(c)["manifest.json"]
    assert other["seed"] == "another-seed" and other["tag"] != first["tag"]

    def versions(manifest: dict[str, Any]) -> dict[str, str]:
        found = {f"pip-{r}": p["version"] for r, p in manifest["pip"]["projects"].items()}
        found |= {f"npm-{r}": p["version"] for r, p in manifest["npm"]["packages"].items()}
        return found

    assert versions(first).keys() == versions(other).keys()
    assert versions(first) != versions(other)
    for path, data in _files(a).items():
        assert str(tmp_path).encode() not in data, f"{path} names where it was written"


def test_a_fixed_seed_gives_the_recorded_bytes_on_every_host(tmp_path: Path) -> None:
    out, _ = _generate(tmp_path)
    digest = hashlib.sha256((out / "manifest.json").read_bytes()).hexdigest()
    assert digest == GOLDEN


def test_the_manifest_states_every_file_and_every_route_serves_one(tmp_path: Path) -> None:
    out, manifest = _generate(tmp_path)
    files = _files(out)
    del files["manifest.json"]
    assert manifest["files"] == {
        path: hashlib.sha256(data).hexdigest() for path, data in files.items()
    }
    routed = set()
    for side, routes in manifest["routes"].items():
        for path, route in routes.items():
            if "file" in route:
                assert (
                    route["file"] == f"{side}{path}" or route["file"] == f"{side}{path}index.html"
                )
                assert route["file"] in files, route
                routed.add(route["file"])
                continue
            # A redirect leaves the granted origin for the ungranted one,
            # which serves what it names.
            assert side == "granted" and route["status"] == 302, route
            target = urlsplit(route["redirect"])
            assert target.scheme == "https" and target.hostname == fx.UNGRANTED_HOST
            assert target.path in manifest["routes"]["ungranted"], route
    assert routed == {path for path in files if path.startswith(("granted/", "ungranted/"))}


def test_every_archive_is_sorted_stored_unowned_and_modified_at_zero(tmp_path: Path) -> None:
    out, _ = _generate(tmp_path)
    wheels = _archives(out, ".whl")
    tarballs = _archives(out, ".tgz", ".tar.gz")
    assert len(wheels) >= 6 and len(tarballs) >= 8
    for wheel in wheels:
        with zipfile.ZipFile(wheel) as archive:
            infos = archive.infolist()
            assert [i.filename for i in infos] == sorted(i.filename for i in infos)
            for info in infos:
                assert info.date_time == fx.ZIP_EPOCH, (wheel.name, info.filename)
                assert info.compress_type == zipfile.ZIP_STORED
                assert info.create_system == 3
                assert info.external_attr == 0o100644 << 16
    for tarball in tarballs:
        data = tarball.read_bytes()
        # gzip: deflate, no flags, modified at 0, no extra flags, OS unknown.
        assert data[:10] == b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x00\xff", tarball.name
        with tarfile.open(fileobj=io.BytesIO(gzip.decompress(data))) as archive:
            members = archive.getmembers()
            assert [m.name for m in members] == sorted(m.name for m in members)
            for m in members:
                assert m.isreg() and m.mode == 0o644 and m.mtime == 0, (tarball.name, m.name)
                assert (m.uid, m.gid, m.uname, m.gname) == (0, 0, "", "")


def test_the_stored_gzip_is_gzip_at_every_block_boundary() -> None:
    pattern = bytes(range(256)) * 1024
    for size in (0, 1, 0xFFFF - 1, 0xFFFF, 0xFFFF + 1, 3 * 0xFFFF + 7):
        data = pattern[:size]
        assert gzip.decompress(fx.stored_gzip(data)) == data, size


def test_each_wheels_record_matches_its_contents(tmp_path: Path) -> None:
    out, _ = _generate(tmp_path)
    for wheel in _archives(out, ".whl"):
        with zipfile.ZipFile(wheel) as archive:
            names = set(archive.namelist())
            (record,) = [n for n in names if n.endswith(".dist-info/RECORD")]
            rows = list(csv.reader(io.StringIO(archive.read(record).decode("utf-8"))))
            assert {row[0] for row in rows} == names, wheel.name
            for path, digest, size in rows:
                if path == record:
                    assert (digest, size) == ("", "")
                    continue
                data = archive.read(path)
                raw = hashlib.sha256(data).digest()
                assert digest == "sha256=" + base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
                assert size == str(len(data)), (wheel.name, path)
            metadata = archive.read(record.replace("RECORD", "METADATA")).decode()
            name = re.search(r"^Name: (.+)$", metadata, re.M)
            version = re.search(r"^Version: (.+)$", metadata, re.M)
            assert name and version
            dist = name.group(1).replace("-", "_")
            assert wheel.name == f"{dist}-{version.group(1)}-py3-none-any.whl"


def test_the_pages_parse_and_each_link_carries_its_files_hash(tmp_path: Path) -> None:
    out, manifest = _generate(tmp_path)
    pages = 0
    for side, routes in manifest["routes"].items():
        host = manifest["hosts"][side]
        for path, route in routes.items():
            if not path.startswith("/simple/") or "file" not in route:
                continue
            links = _links((out / route["file"]).read_bytes())
            assert links, path
            pages += 1
            for href, text in links:
                url = urlsplit(href)
                assert url.scheme == "https", href
                if path == "/simple/":
                    # The index lists projects of its own origin, each named
                    # as PEP 503 normalises it.
                    assert url.hostname == host and url.path == f"/simple/{text}/"
                    assert re.sub(r"[-_.]+", "-", text).lower() == text
                    assert url.path in routes
                    continue
                name, _, digest = url.fragment.partition("=")
                assert name == "sha256" and url.path == f"/files/{text}", href
                assert hashlib.sha256(_served(out, manifest, href)).hexdigest() == digest
    assert pages >= 9, pages
    offsite = manifest["pip"]["projects"]["offsite"]
    page = manifest["routes"]["granted"][f"/simple/{offsite['name']}/"]["file"]
    ((href, _),) = _links((out / page).read_bytes())
    assert urlsplit(href).hostname == fx.UNGRANTED_HOST, "the offsite file is on the ungranted host"


def test_every_untampered_tarball_matches_its_integrity_and_the_tampered_one_does_not(
    tmp_path: Path,
) -> None:
    out, manifest = _generate(tmp_path)
    tampered = {p["name"] for p in manifest["npm"]["packages"].values() if p["tampered"]}
    assert len(tampered) == 1
    checked = 0
    for packument in _packuments(out, manifest).values():
        for version, entry in packument["versions"].items():
            served = _served(out, manifest, entry["dist"]["tarball"])
            assert (entry["dist"]["integrity"] == _sri(served)) is (
                packument["name"] not in tampered
            ), packument["name"]
            members = _members(served)
            assert set(members) == {"package/package.json", "package/index.js"}
            package = json.loads(members["package/package.json"])
            assert package == {k: v for k, v in entry.items() if k != "dist"}
            assert package["version"] == version == packument["dist-tags"]["latest"]
            checked += 1
            if packument["name"] in tampered:
                # Tampered in content, not in framing: the bytes the integrity
                # states are the same package with its body restored.
                body = members["package/index.js"]
                assert b" tampered" in body
                members["package/index.js"] = body.replace(b" tampered", b"")
                assert entry["dist"]["integrity"] == _sri(fx.stored_gzip(fx.ustar(members)))
    assert checked >= 8, checked


def _sri(data: bytes) -> str:
    return "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()


def _members(tgz: bytes) -> dict[str, bytes]:
    with tarfile.open(fileobj=io.BytesIO(gzip.decompress(tgz))) as archive:
        members = {}
        for member in archive.getmembers():
            handle = archive.extractfile(member)
            assert handle is not None, member.name
            members[member.name] = handle.read()
        return members


def test_the_lockfile_names_exactly_the_packuments_integrity(tmp_path: Path) -> None:
    out, manifest = _generate(tmp_path)
    project = out / manifest["npm"]["project"]
    root = json.loads((project / "package.json").read_bytes())
    lock = json.loads((project / "package-lock.json").read_bytes())
    assert lock["lockfileVersion"] == 3 and lock["name"] == root["name"]
    assert lock["packages"][""]["dependencies"] == root["dependencies"]
    entries = {key: entry for key, entry in lock["packages"].items() if key}
    assert set(entries) == {f"node_modules/{name}" for name in root["dependencies"]}
    for key, entry in entries.items():
        name = key.removeprefix("node_modules/")
        packument = _packuments(out, manifest)[("granted", f"/npm/{name}")]
        dist = packument["versions"][entry["version"]]["dist"]
        assert (entry["resolved"], entry["integrity"]) == (dist["tarball"], dist["integrity"])
        assert root["dependencies"][name] == entry["version"]
        assert urlsplit(entry["resolved"]).hostname == fx.GRANTED_HOST


def test_every_lifecycle_script_writes_its_own_marker(tmp_path: Path) -> None:
    out, manifest = _generate(tmp_path)
    markers = manifest["markers"]
    packuments = _packuments(out, manifest)
    scripted = manifest["npm"]["packages"]["scripted"]
    (entry,) = packuments[("granted", f"/npm/{scripted['name']}")]["versions"].values()
    project = json.loads((out / manifest["npm"]["project"] / "package.json").read_bytes())
    source = out / manifest["npm"]["git_dependency"]["source"] / "package.json"
    for who, scripts in (("scripted", entry["scripts"]), ("project", project["scripts"])):
        assert set(scripts) == set(fx.NPM_SCRIPTS), who
        for phase, command in scripts.items():
            marker = markers[f"npm-{who}-{phase}"]
            assert command == fx.npm_marker_script(manifest["marker_dir"], marker)
            assert f"'{manifest['marker_dir']}/{marker}'" in command
    prepare = json.loads(source.read_bytes())["scripts"]
    assert prepare == {
        "prepare": fx.npm_marker_script(manifest["marker_dir"], markers["npm-git-dep-prepare"])
    }
    git = manifest["npm"]["git_dependency"]
    assert urlsplit(git["spec"].removeprefix("git+")).hostname == fx.UNGRANTED_HOST
    assert len(set(markers.values())) == len(markers) == 2 * 4 + 1 + 2


def _extract(wheels: list[Path], into: Path) -> None:
    """Unpack the wheels as an installer lays out a purelib wheel."""
    for wheel in wheels:
        with zipfile.ZipFile(wheel) as archive:
            for name in archive.namelist():
                (into / name).parent.mkdir(parents=True, exist_ok=True)
                (into / name).write_bytes(archive.read(name))


def _snapshot(root: Path) -> set[tuple[str, int]]:
    return {(p.as_posix(), p.stat().st_mtime_ns) for p in root.rglob("*")}


def test_the_pth_marks_when_python_starts_and_the_plain_wheels_import_writes_nothing(
    tmp_path: Path,
) -> None:
    marks = tmp_path / "marks"
    marks.mkdir()
    out, manifest = _generate(tmp_path, marker_dir=str(marks))
    projects = manifest["pip"]["projects"]

    def wheel(role: str) -> Path:
        return out / "granted" / "files" / str(projects[role]["file"])

    plain = tmp_path / "plain"
    _extract([wheel("base"), wheel("dependent")], plain)
    before = _snapshot(tmp_path)
    modules = ", ".join(projects[role]["name"].replace("-", "_") for role in ("base", "dependent"))
    subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            "-c",
            f"import sys; sys.path.insert(0, sys.argv[1]); import {modules}",
            str(plain),
        ],
        check=True,
        cwd=plain,
    )
    assert _snapshot(tmp_path) == before, "importing a plain fixture wheel wrote something"
    with_pth = tmp_path / "with-pth"
    _extract([wheel("pth")], with_pth)
    subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            "-c",
            "import site, sys; site.addsitedir(sys.argv[1])",
            str(with_pth),
        ],
        check=True,
        cwd=with_pth,
    )
    assert [p.name for p in marks.iterdir()] == [manifest["markers"]["pip-pth"]]


def test_the_sdists_build_backend_marks_on_every_hook(tmp_path: Path) -> None:
    marks = tmp_path / "marks"
    marks.mkdir()
    out, manifest = _generate(tmp_path, marker_dir=str(marks))
    sdist = manifest["pip"]["projects"]["sdist"]
    tree = tmp_path / "sdist"
    data = (out / "granted" / "files" / str(sdist["file"])).read_bytes()
    for name, content in _members(data).items():
        (tree / name).parent.mkdir(parents=True, exist_ok=True)
        (tree / name).write_bytes(content)
    (top,) = list(tree.iterdir())
    system = tomllib.loads((top / "pyproject.toml").read_text())["build-system"]
    assert system == {"requires": [], "build-backend": "backend", "backend-path": ["."]}
    spec = importlib.util.spec_from_file_location("dwfx_fixture_backend", top / "backend.py")
    assert spec is not None and spec.loader is not None
    backend = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(backend)
    marker = marks / manifest["markers"]["pip-build-backend"]
    scratch = str(tmp_path)
    for hook, arguments in (
        ("get_requires_for_build_wheel", ()),
        ("get_requires_for_build_sdist", ()),
        ("prepare_metadata_for_build_wheel", (scratch,)),
        ("build_wheel", (scratch,)),
        ("build_sdist", (scratch,)),
    ):
        marker.unlink(missing_ok=True)
        try:
            getattr(backend, hook)(*arguments)
        except RuntimeError as refused:
            assert "builds nothing" in str(refused)
        assert marker.exists(), hook


def test_the_workspace_npmrc_tries_every_undoing_and_pip_conf_names_the_ungranted_index(
    tmp_path: Path,
) -> None:
    out, manifest = _generate(tmp_path)
    lines = (out / manifest["npm"]["hostile_npmrc"]).read_text().splitlines()
    settings = dict(line.split("=", 1) for line in lines)
    assert settings["ignore-scripts"] == "false" and settings["strict-ssl"] == "false"
    assert {"cafile", "userconfig", "globalconfig"} <= settings.keys()
    config = configparser.ConfigParser()
    config.read_string((out / manifest["pip"]["image_configuration"]).read_text())
    index = config["global"]["index-url"]
    assert index == manifest["pip"]["ungranted_index"]
    assert urlsplit(index).hostname == fx.UNGRANTED_HOST
    assert urlsplit(index).path in manifest["routes"]["ungranted"]


def test_a_bad_seed_marker_directory_or_used_directory_is_refused(tmp_path: Path) -> None:
    for seed in ("", "a b", "x" * 65, "seed/../up"):
        with pytest.raises(ValueError):
            fx.generate(seed, tmp_path / "bad-seed")
    for marker_dir in ("workspace", "/work'space", '/work"space', "/work space"):
        with pytest.raises(ValueError):
            fx.generate(SEED, tmp_path / "bad-marker", marker_dir=marker_dir)
    used = tmp_path / "used"
    used.mkdir()
    (used / "left-over").write_text("")
    with pytest.raises(ValueError):
        fx.generate(SEED, used)
    assert [p.name for p in used.iterdir()] == ["left-over"]
    assert not (tmp_path / "bad-seed").exists() and not (tmp_path / "bad-marker").exists()


# Marker directories as either platform spells them, and the one form each is
# written with. The Windows ones are pytest's `tmp_path` on a hosted Windows
# runner (run 41720068934, `make test` on windows-latest) and on a host whose
# temporary directory has an 8.3 name.
ACCEPTED = (
    ("/workspace", "/workspace"),
    ("/workspace/", "/workspace"),
    ("/", "/"),
    (
        "/home/runner/work/_temp/pytest-0/test_x0/marks",
        "/home/runner/work/_temp/pytest-0/test_x0/marks",
    ),
    ("/private/var/folders/ab/c_d-1.2~3/T/marks", "/private/var/folders/ab/c_d-1.2~3/T/marks"),
    (
        r"C:\Users\runneradmin\AppData\Local\Temp\pytest-of-runneradmin\pytest-0\test_x0\marks",
        "C:/Users/runneradmin/AppData/Local/Temp/pytest-of-runneradmin/pytest-0/test_x0/marks",
    ),
    (r"C:\Users\KULLAN~1\AppData\Local\Temp\marks", "C:/Users/KULLAN~1/AppData/Local/Temp/marks"),
    ("C:/Users/runneradmin/marks/", "C:/Users/runneradmin/marks"),
    (r"D:\a/b\c", "D:/a/b/c"),
    ("d:\\", "d:/"),
)
# Not absolute, not plain, or holding a character some quoting acts on.
REFUSED = (
    "",
    "workspace",
    "./workspace",
    "~/workspace",
    "C:",
    "C:workspace",
    r"\workspace",
    r"\\server\share\marks",
    "//server/share",
    "/work space",
    r"C:\work space",
    "/work'space",
    '/work"space',
    "/work\\space",
    "/work$HOME",
    "/work`id`",
    "/work%TEMP%",
    "/work;rm",
    "/work&x",
    "/work|x",
    "/work<x",
    "/work>x",
    "/work!x",
    "/work^x",
    "/work\nspace",
    "/work\x00space",
    "/w\u00f6rk",
    "/workspace/../etc",
    "/workspace/./x",
    "/workspace/..",
    r"C:\Users\..\x",
    "C:/.",
)


def test_a_marker_directory_has_one_canonical_form_on_either_platform() -> None:
    for given, canonical in ACCEPTED:
        assert fx.marker_directory(given) == canonical, given
        assert fx.marker_directory(canonical) == canonical, canonical
    for given in REFUSED:
        with pytest.raises(ValueError):
            fx.marker_directory(given)
        with pytest.raises(ValueError):
            fx.npm_marker_script(given, "dwfx-mark")
        with pytest.raises(ValueError):
            fx.pth_line(given, "dwfx-mark")
    for name in ("", ".", "..", "a/b", "a\\b", "a b", "a'b", "a$b", "a\nb"):
        with pytest.raises(ValueError):
            fx.marker_path("/workspace", name)


def test_every_marker_command_carries_its_path_unquoted_and_unchanged() -> None:
    """For every accepted spelling: the npm command, the `.pth` line and the
    build backend name exactly the canonical marker path, in characters that
    no shell, cmd, Python or JavaScript quoting acts on -- so what runs writes
    that path and nothing else."""
    marker = "dwfx-0123abcd-marker-pip-pth"
    safe = re.compile(r"[A-Za-z0-9._~/:-]+")
    for given, canonical in ACCEPTED:
        path = fx.marker_path(given, marker)
        assert safe.fullmatch(path), path
        expected = f"{canonical}{marker}" if canonical.endswith("/") else f"{canonical}/{marker}"
        assert path == expected
        words = shlex.split(fx.npm_marker_script(given, marker))
        assert words == ["node", "-e", f"require('fs').writeFileSync('{path}', '')"], given
        assert re.findall(r"'([^']*)'", words[2]) == ["fs", path, ""]
        for source in (fx.pth_line(given, marker), fx._backend(given, marker).decode()):
            joins = [
                [ast.literal_eval(argument) for argument in node.args]
                for node in ast.walk(ast.parse(source))
                if isinstance(node, ast.Call) and ast.unparse(node.func) == "os.path.join"
            ]
            assert joins == [[canonical, marker]], source


def test_each_spelling_of_a_directory_gives_the_same_fixtures(tmp_path: Path) -> None:
    default, _ = _generate(tmp_path, name="default")
    trailing, _ = _generate(tmp_path, name="trailing", marker_dir="/workspace/")
    assert _files(trailing) == _files(default)
    back, manifest = _generate(tmp_path, name="back", marker_dir=r"C:\dw\marks")
    forward, _ = _generate(tmp_path, name="forward", marker_dir="C:/dw/marks/")
    assert _files(back) == _files(forward)
    assert manifest["marker_dir"] == "C:/dw/marks"
    texts = {
        path: data
        for path, data in _files(back).items()
        if not path.endswith((".whl", ".tgz", ".tar.gz"))
    }
    named = [path for path, data in texts.items() if b"C:/dw/marks" in data]
    assert len(named) >= 4, named
    # The backslash spelling never reaches a file, as written or JSON-escaped.
    spelled = [rb"C:\dw", rb"dw\marks", rb"C:\\dw", rb"dw\\marks"]
    assert not [path for path, data in texts.items() if any(s in data for s in spelled)]


def test_a_marker_lands_in_its_directory_however_this_host_spells_it(tmp_path: Path) -> None:
    """This host's own separator, and a trailing one -- `C:\\...\\marks\\` on
    Windows, `/.../marks/` elsewhere: the `.pth` and the build backend still
    write their markers in that directory."""
    marks = tmp_path / "marks"
    marks.mkdir()
    out, manifest = _generate(tmp_path, marker_dir=str(marks) + os.sep)
    files = out / "granted" / "files"
    projects = manifest["pip"]["projects"]
    site = tmp_path / "site"
    _extract([files / str(projects["pth"]["file"])], site)
    subprocess.run(
        [
            sys.executable,
            "-I",
            "-B",
            "-c",
            "import site, sys; site.addsitedir(sys.argv[1])",
            str(site),
        ],
        check=True,
        cwd=site,
    )
    tree = tmp_path / "sdist"
    for name, content in _members((files / str(projects["sdist"]["file"])).read_bytes()).items():
        (tree / name).parent.mkdir(parents=True, exist_ok=True)
        (tree / name).write_bytes(content)
    (top,) = list(tree.iterdir())
    spec = importlib.util.spec_from_file_location("dwfx_marker_backend", top / "backend.py")
    assert spec is not None and spec.loader is not None
    backend = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(backend)
    backend.get_requires_for_build_wheel()
    assert sorted(p.name for p in marks.iterdir()) == sorted(
        [manifest["markers"]["pip-pth"], manifest["markers"]["pip-build-backend"]]
    )


# --- M5e.4: the origins' fixed ports in every URL -----------------------------

PORTS = {"granted": 18443, "ungranted": 18444}
_URL = re.compile(rb"https://[A-Za-z0-9.:-]+[^\"'\s<>]*")


def _urls(out: Path) -> list[str]:
    """Every https URL any file of the set names, the manifest included."""
    return [url.decode() for data in _files(out).values() for url in _URL.findall(data)]


def test_a_run_with_fixed_ports_names_them_in_every_url_and_stays_deterministic(
    tmp_path: Path,
) -> None:
    out = tmp_path / "ported"
    fx.generate(SEED, out, granted_port=18443, ungranted_port=18444)
    manifest: dict[str, Any] = json.loads((out / "manifest.json").read_bytes())
    assert manifest["ports"] == PORTS
    urls = _urls(out)
    assert len(urls) > 20
    for url in urls:
        parts = urlsplit(url)
        side = {fx.GRANTED_HOST: "granted", fx.UNGRANTED_HOST: "ungranted"}[str(parts.hostname)]
        assert parts.port == PORTS[side], url
    name = manifest["pip"]["projects"]["redirected"]["name"]
    redirect = manifest["routes"]["granted"][f"/simple/{name}/"]["redirect"]
    assert redirect == f"https://{fx.UNGRANTED_HOST}:18444/simple/{name}/"
    # The same seed and ports give the same bytes; the default names no port
    # and keeps its recorded digest (`GOLDEN`); another port is other bytes.
    again = tmp_path / "again"
    fx.generate(SEED, again, granted_port=18443, ungranted_port=18444)
    assert _files(out) == _files(again)
    plain, plain_manifest = _generate(tmp_path, name="plain")
    assert "ports" not in plain_manifest
    assert all(urlsplit(url).port is None for url in _urls(plain))
    assert hashlib.sha256((plain / "manifest.json").read_bytes()).hexdigest() == GOLDEN
    other = tmp_path / "other"
    fx.generate(SEED, other, granted_port=18443, ungranted_port=18445)
    assert _files(other)["manifest.json"] != _files(out)["manifest.json"]
    # Only the URLs differ: the packages, markers and routes are the seed's.
    assert manifest["markers"] == plain_manifest["markers"]
    assert manifest["routes"]["granted"].keys() == plain_manifest["routes"]["granted"].keys()


def test_a_port_out_of_range_is_refused(tmp_path: Path) -> None:
    for at, port in enumerate((0, -1, 65536, True)):
        with pytest.raises(ValueError, match="port"):
            fx.generate(SEED, tmp_path / f"granted-{at}", granted_port=port)
        with pytest.raises(ValueError, match="port"):
            fx.generate(SEED, tmp_path / f"ungranted-{at}", ungranted_port=port)
    assert not any(tmp_path.iterdir()), "a refused run wrote something"


def test_the_command_line_takes_the_ports(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    out = tmp_path / "cli"
    assert fx.main([SEED, str(out), "--granted-port", "18443", "--ungranted-port", "18444"]) == 0
    assert json.loads((out / "manifest.json").read_bytes())["ports"] == PORTS
    assert json.loads(capsys.readouterr().out) == {"manifest": str(out / "manifest.json")}
