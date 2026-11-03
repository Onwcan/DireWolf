"""M5e.3's hermetic registry fixtures (M5E_ASSURANCE_PLAN.md §§7, 7a).

A PEP 503 index and an npm registry, each as a granted origin and an ungranted
one, generated from a seed. Standard library only, and nothing but bytes: it
opens no socket, starts no process, builds no environment and reads nothing of
the host's. Every byte comes from the seed -- package names and versions
included -- with fixed timestamps (a ZIP's 1980-01-01, tar and gzip at 0),
sorted entries, a fixed tar owner, group and mode, and no host path. The
archives are stored, not compressed, so no compressor's version can change a
byte, and the same seed gives the same bytes on any host.

    generate(seed, out) -> manifest

writes, under `out` (absent or empty):

    granted/, ungranted/          what each origin serves, and only through
                                  the manifest's `routes`
    image/pip.conf                an image configuration naming the ungranted
                                  index
    workspace/npm/                a project for `npm ci`: package.json and
                                  package-lock.json
    workspace/npm-hostile.npmrc   a workspace .npmrc that tries to undo the
                                  npm profile (ADR-0054 §3)
    source/                       the git dependency's tree, which no origin
                                  serves
    manifest.json                 the seed, the hosts, every package by role,
                                  every marker, the routes, every file's SHA-256

The content carries what ADR-0054 §8 and ADR-0055 §9 ask of the fixtures: two
pure wheels, one depending on the other, whose import writes nothing; a source
distribution whose build backend, and a wheel whose `.pth`, would write a
marker; packages whose four lifecycle scripts, the project's own included,
would each write one; a file and a tarball on the ungranted host; a page and a
packument redirected to it; a git dependency whose `prepare` would write a
marker; a tarball tampered against its integrity; and a lockfile naming
exactly the packuments' integrity. A marker is an empty file in `marker_dir`
(the workspace by default), so a marker's absence is evidence only because its
code is shown to write it when run (`tests/sandbox/test_registry_fixtures.py`).

Not here, and not M5e.3's generator: the per-run CA, which is made afresh for
every run and never committed (`tests/net_http/make-pki.sh`); the origins that
serve `routes`; and any pip or npm run (M5e.4). Nothing here is evidence, and
nothing here bears on R3 or E6.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import hashlib
import io
import json
import re
import struct
import sys
import tarfile
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

# RFC 6761 reserves `.test`: neither name can resolve to anything public.
# The broker's evidence-only resolver names them on loopback (plan §7).
GRANTED_HOST = "granted-registry.test"
UNGRANTED_HOST = "ungranted-registry.test"
# dwk-sandbox-profile's WORKSPACE_TARGET: writable in the environment and
# visible from the host.
MARKER_DIR = "/workspace"
ZIP_EPOCH = (1980, 1, 1, 0, 0, 0)
FORMAT = 1

_SEED = re.compile(r"[A-Za-z0-9._-]{1,64}")
_MARKER_PATH = re.compile(r"/[A-Za-z0-9._/-]*")
_HTML = "text/html; charset=utf-8"
_JSON = "application/json"
_BINARY = "application/octet-stream"
# The npm lifecycle scripts ADR-0054 §8 requires none of to run.
NPM_SCRIPTS = ("preinstall", "install", "postinstall", "prepare")


def _digest(seed: str, *parts: str) -> bytes:
    """SHA-256 over the seed and the parts, each length-prefixed."""
    hasher = hashlib.sha256()
    for part in (seed, *parts):
        data = part.encode("utf-8")
        hasher.update(len(data).to_bytes(4, "big"))
        hasher.update(data)
    return hasher.digest()


def _json(value: object) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _integrity(data: bytes) -> str:
    """npm's Subresource Integrity form of the tarball's SHA-512."""
    return "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode("ascii")


def _record_hash(data: bytes) -> str:
    """A wheel RECORD's hash field: urlsafe base64, unpadded (PEP 376, PEP 427)."""
    raw = hashlib.sha256(data).digest()
    return "sha256=" + base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def stored_zip(entries: dict[str, bytes]) -> bytes:
    """A ZIP of `entries`, sorted, stored, every entry a 0644 regular file of
    1980-01-01 written by a Unix system."""
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", compression=zipfile.ZIP_STORED) as archive:
        for name in sorted(entries):
            info = zipfile.ZipInfo(name, date_time=ZIP_EPOCH)
            info.compress_type = zipfile.ZIP_STORED
            info.create_system = 3
            info.external_attr = 0o100644 << 16
            archive.writestr(info, entries[name])
    return buffer.getvalue()


def ustar(entries: dict[str, bytes]) -> bytes:
    """A ustar archive of `entries`, sorted, every member a 0644 regular file of
    owner and group 0, no names, modified at 0."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name in sorted(entries):
            data = entries[name]
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mtime = 0
            info.mode = 0o644
            info.uid = info.gid = 0
            info.uname = info.gname = ""
            info.type = tarfile.REGTYPE
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


def stored_gzip(data: bytes) -> bytes:
    """RFC 1952 around RFC 1951 stored blocks: modified at 0, no name, OS
    unknown, and no compressor whose version could change a byte."""
    out = bytearray(b"\x1f\x8b\x08\x00" + bytes(4) + b"\x00\xff")
    blocks = [data[at : at + 0xFFFF] for at in range(0, len(data), 0xFFFF)] or [b""]
    for index, block in enumerate(blocks):
        out.append(1 if index == len(blocks) - 1 else 0)  # BFINAL; BTYPE 00, stored
        out += struct.pack("<HH", len(block), len(block) ^ 0xFFFF)
        out += block
    out += struct.pack("<II", binascii.crc32(data) & 0xFFFFFFFF, len(data) & 0xFFFFFFFF)
    return bytes(out)


def npm_marker_script(marker_dir: str, marker: str) -> str:
    """The one command every fixture lifecycle script runs: write its marker.
    `node` is the only program an npm run is sure to have; the path holds
    only `_MARKER_PATH`'s characters, so no quoting can change the command."""
    path = f"{marker_dir.rstrip('/')}/{marker}"
    assert _MARKER_PATH.fullmatch(path), path
    return f"node -e \"require('fs').writeFileSync('{path}', '')\""


def pth_line(marker_dir: str, marker: str) -> str:
    """A `.pth` line `site` executes at every interpreter start: write a marker."""
    return f'import os; open(os.path.join({marker_dir!r}, {marker!r}), "w").close()\n'


def _backend(marker_dir: str, marker: str) -> bytes:
    """A PEP 517 backend each of whose hooks writes its marker, then builds nothing."""
    return (
        '"""A DireWolf registry fixture: a build backend that marks it ran."""\n'
        "import os\n\n\n"
        "def _mark():\n"
        f'    open(os.path.join({marker_dir!r}, {marker!r}), "w").close()\n\n\n'
        "def get_requires_for_build_wheel(config_settings=None):\n"
        "    _mark()\n"
        "    return []\n\n\n"
        "def get_requires_for_build_sdist(config_settings=None):\n"
        "    _mark()\n"
        "    return []\n\n\n"
        "def prepare_metadata_for_build_wheel(metadata_directory, config_settings=None):\n"
        "    _mark()\n"
        '    raise RuntimeError("a DireWolf registry fixture builds nothing")\n\n\n'
        "def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):\n"
        "    _mark()\n"
        '    raise RuntimeError("a DireWolf registry fixture builds nothing")\n\n\n'
        "def build_sdist(sdist_directory, config_settings=None):\n"
        "    _mark()\n"
        '    raise RuntimeError("a DireWolf registry fixture builds nothing")\n'
    ).encode()


@dataclass
class _Tree:
    """Every file of the fixture set, by its path under `out`."""

    files: dict[str, bytes] = field(default_factory=dict)

    def put(self, path: str, data: bytes) -> str:
        assert path not in self.files, path
        self.files[path] = data
        return path


@dataclass
class _Origin:
    """One origin's routes: a path served from a file, or redirected."""

    host: str
    routes: dict[str, dict[str, object]] = field(default_factory=dict)

    def url(self, path: str) -> str:
        return f"https://{self.host}{path}"

    def serve(self, path: str, file: str, content_type: str) -> None:
        assert path not in self.routes, path
        self.routes[path] = {"file": file, "type": content_type}

    def redirect(self, path: str, to: str) -> None:
        assert path not in self.routes, path
        self.routes[path] = {"redirect": to, "status": 302}


class _Fixtures:
    def __init__(self, seed: str, marker_dir: str) -> None:
        self.seed = seed
        self.marker_dir = marker_dir
        self.tag = _digest(seed, "tag").hex()[:8]
        self.tree = _Tree()
        self.granted = _Origin(GRANTED_HOST)
        self.ungranted = _Origin(UNGRANTED_HOST)
        self.markers: dict[str, str] = {}

    def name(self, role: str) -> str:
        return f"dwfx-{self.tag}-{role}"

    def version(self, role: str) -> str:
        d = _digest(self.seed, "version", role)
        return f"{1 + d[0] % 9}.{d[1] % 20}.{d[2] % 50}"

    def value(self, role: str) -> str:
        return _digest(self.seed, "value", role).hex()[:16]

    def marker(self, what: str) -> str:
        name = f"dwfx-{self.tag}-marker-{what}"
        self.markers[what] = name
        return name

    # -- the PEP 503 index -------------------------------------------------

    def wheel(
        self, role: str, *, requires: tuple[str, ...] = (), pth: str | None = None
    ) -> tuple[str, bytes]:
        name, version = self.name(role), self.version(role)
        dist = name.replace("-", "_")
        info = f"{dist}-{version}.dist-info"
        entries = {
            f"{dist}/__init__.py": (
                '"""A DireWolf registry fixture: importing it writes nothing."""\n'
                f'VALUE = "{self.value(role)}"\n'
            ).encode(),
            f"{info}/METADATA": (
                "Metadata-Version: 2.1\n"
                f"Name: {name}\n"
                f"Version: {version}\n"
                "Summary: A DireWolf registry fixture, never published\n"
                + "".join(f"Requires-Dist: {spec}\n" for spec in requires)
            ).encode(),
            f"{info}/WHEEL": (
                b"Wheel-Version: 1.0\n"
                b"Generator: direwolf-registry-fixtures\n"
                b"Root-Is-Purelib: true\n"
                b"Tag: py3-none-any\n"
            ),
        }
        if pth is not None:
            entries[f"{dist}.pth"] = pth_line(self.marker_dir, pth).encode()
        record = [
            f"{path},{_record_hash(data)},{len(data)}" for path, data in sorted(entries.items())
        ]
        record.append(f"{info}/RECORD,,")
        entries[f"{info}/RECORD"] = ("\n".join(record) + "\n").encode()
        return f"{dist}-{version}-py3-none-any.whl", stored_zip(entries)

    def sdist(self, role: str, marker: str) -> tuple[str, bytes]:
        name, version = self.name(role), self.version(role)
        dist = name.replace("-", "_")
        top = f"{dist}-{version}"
        entries = {
            f"{top}/PKG-INFO": (
                f"Metadata-Version: 2.1\nName: {name}\nVersion: {version}\n"
            ).encode(),
            f"{top}/pyproject.toml": (
                "[build-system]\n"
                "requires = []\n"
                'build-backend = "backend"\n'
                'backend-path = ["."]\n\n'
                "[project]\n"
                f'name = "{name}"\n'
                f'version = "{version}"\n'
            ).encode(),
            f"{top}/backend.py": _backend(self.marker_dir, marker),
            f"{top}/{dist}/__init__.py": f'VALUE = "{self.value(role)}"\n'.encode(),
        }
        return f"{top}.tar.gz", stored_gzip(ustar(entries))

    def page(self, title: str, links: list[tuple[str, str]]) -> bytes:
        """A PEP 503 page (with PEP 629's version): one anchor per link."""
        anchors = "".join(f'<a href="{href}">{text}</a><br>\n' for href, text in links)
        return (
            "<!DOCTYPE html>\n<html>\n<head>\n"
            '<meta name="pypi:repository-version" content="1.0">\n'
            f"<title>{title}</title>\n</head>\n<body>\n{anchors}</body>\n</html>\n"
        ).encode()

    def file_on(self, origin: _Origin, filename: str, data: bytes) -> str:
        """Serve `data` at `/files/<filename>` of `origin`; its link, with its hash."""
        path = f"/files/{filename}"
        origin.serve(path, self.tree.put(f"{self.side(origin)}{path}", data), _BINARY)
        return f"{origin.url(path)}#sha256={_sha256(data)}"

    def project_page(self, origin: _Origin, name: str, links: list[tuple[str, str]]) -> None:
        path = f"/simple/{name}/"
        page = self.page(f"Links for {name}", links)
        origin.serve(path, self.tree.put(f"{self.side(origin)}{path}index.html", page), _HTML)

    def index_page(self, origin: _Origin, names: list[str]) -> None:
        links = [(origin.url(f"/simple/{n}/"), n) for n in sorted(names)]
        page = self.page("Simple index", links)
        origin.serve(
            "/simple/", self.tree.put(f"{self.side(origin)}/simple/index.html", page), _HTML
        )

    def pip(self) -> dict[str, object]:
        projects: dict[str, dict[str, object]] = {}

        def record(role: str, filename: str, served: str) -> None:
            projects[role] = {
                "name": self.name(role),
                "version": self.version(role),
                "file": filename,
                "served": served,
            }

        base_file, base = self.wheel("base")
        requires = (f"{self.name('base')}=={self.version('base')}",)
        dependent_file, dependent = self.wheel("dependent", requires=requires)
        sdist_file, sdist = self.sdist("sdist", self.marker("pip-build-backend"))
        pth_file, pth = self.wheel("pth", pth=self.marker("pip-pth"))
        offsite_file, offsite = self.wheel("offsite")
        redirected_file, redirected = self.wheel("redirected")

        granted = [
            ("base", base_file, base),
            ("dependent", dependent_file, dependent),
            ("sdist", sdist_file, sdist),
            ("pth", pth_file, pth),
        ]
        for role, filename, data in granted:
            link = self.file_on(self.granted, filename, data)
            self.project_page(self.granted, self.name(role), [(link, filename)])
            record(role, filename, "granted")
        # A granted page whose one file is on the ungranted host.
        link = self.file_on(self.ungranted, offsite_file, offsite)
        self.project_page(self.granted, self.name("offsite"), [(link, offsite_file)])
        record("offsite", offsite_file, "file on the ungranted host")
        # A granted page redirected to the ungranted host, which serves it.
        name = self.name("redirected")
        self.granted.redirect(f"/simple/{name}/", self.ungranted.url(f"/simple/{name}/"))
        link = self.file_on(self.ungranted, redirected_file, redirected)
        self.project_page(self.ungranted, name, [(link, redirected_file)])
        record("redirected", redirected_file, "redirected to the ungranted host")
        self.index_page(
            self.granted,
            [self.name(r) for r in ("base", "dependent", "sdist", "pth", "offsite", "redirected")],
        )
        # The ungranted index serves the base wheel too: pointed there, pip
        # would find what it asked for, so a refusal is the proxy's.
        link = self.file_on(self.ungranted, base_file, base)
        self.project_page(self.ungranted, self.name("base"), [(link, base_file)])
        self.index_page(self.ungranted, [self.name("base"), name])
        # An image configuration naming the ungranted index (ADR-0055 §9).
        self.tree.put(
            "image/pip.conf",
            f"[global]\nindex-url = {self.ungranted.url('/simple/')}\n".encode(),
        )
        return {
            "index": self.granted.url("/simple/"),
            "ungranted_index": self.ungranted.url("/simple/"),
            "image_configuration": "image/pip.conf",
            "projects": projects,
        }

    # -- the npm registry --------------------------------------------------

    def scripts(self, who: str) -> dict[str, str]:
        return {
            phase: npm_marker_script(self.marker_dir, self.marker(f"npm-{who}-{phase}"))
            for phase in NPM_SCRIPTS
        }

    def manifest_for(
        self,
        role: str,
        *,
        scripts: dict[str, str] | None = None,
        dependencies: dict[str, str] | None = None,
    ) -> dict[str, object]:
        package: dict[str, object] = {
            "name": self.name(role),
            "version": self.version(role),
            "description": "A DireWolf registry fixture, never published",
            "main": "index.js",
            "license": "UNLICENSED",
        }
        if scripts:
            package["scripts"] = scripts
        if dependencies:
            package["dependencies"] = dependencies
        return package

    def tarball(self, package: dict[str, object], body: str) -> bytes:
        return stored_gzip(
            ustar({"package/package.json": _json(package), "package/index.js": body.encode()})
        )

    def side(self, origin: _Origin) -> str:
        return "granted" if origin is self.granted else "ungranted"

    def publish(
        self,
        role: str,
        package: dict[str, object],
        *,
        origin: _Origin,
        tarball_on: _Origin,
        tamper: bool = False,
    ) -> dict[str, object]:
        """Serve `role`'s packument from `origin` and its tarball from
        `tarball_on`; tampered, the tarball served is not the one the
        packument's integrity states."""
        name, version = self.name(role), self.version(role)
        body = f'module.exports = "{self.value(role)}";\n'
        original = self.tarball(package, body)
        integrity = _integrity(original)
        data = self.tarball(package, body.replace('";', ' tampered";')) if tamper else original
        tgz = f"/npm/-/{name}-{version}.tgz"
        tarball_on.serve(tgz, self.tree.put(f"{self.side(tarball_on)}{tgz}", data), _BINARY)
        entry = dict(package)
        entry["dist"] = {"tarball": tarball_on.url(tgz), "integrity": integrity}
        packument = {
            "_id": name,
            "name": name,
            "dist-tags": {"latest": version},
            "versions": {version: entry},
        }
        path = f"/npm/{name}"
        origin.serve(path, self.tree.put(f"{self.side(origin)}{path}", _json(packument)), _JSON)
        return {
            "name": name,
            "version": version,
            "tarball": tarball_on.url(tgz),
            "integrity": integrity,
            "tampered": tamper,
        }

    def npm(self) -> dict[str, object]:
        granted, ungranted = self.granted, self.ungranted
        packages: dict[str, dict[str, object]] = {}
        packages["plain"] = self.publish(
            "plain", self.manifest_for("plain"), origin=granted, tarball_on=granted
        )
        packages["scripted"] = self.publish(
            "scripted",
            self.manifest_for("scripted", scripts=self.scripts("scripted")),
            origin=granted,
            tarball_on=granted,
        )
        # A dependency whose tarball is on the ungranted host, and its parent.
        packages["offsite"] = self.publish(
            "offsite", self.manifest_for("offsite"), origin=granted, tarball_on=ungranted
        )
        packages["offsite-parent"] = self.publish(
            "offsite-parent",
            self.manifest_for(
                "offsite-parent", dependencies={self.name("offsite"): self.version("offsite")}
            ),
            origin=granted,
            tarball_on=granted,
        )
        # A dependency named by a git URL, whose `prepare` would mark: no
        # origin speaks git, and the URL names the ungranted host.
        git_name = self.name("git-dep")
        git_url = f"git+{ungranted.url(f'/git/{git_name}.git')}"
        prepare = npm_marker_script(self.marker_dir, self.marker("npm-git-dep-prepare"))
        source = self.manifest_for("git-dep", scripts={"prepare": prepare})
        self.tree.put(f"source/{git_name}/package.json", _json(source))
        body = f'module.exports = "{self.value("git-dep")}";\n'
        self.tree.put(f"source/{git_name}/index.js", body.encode())
        packages["git-parent"] = self.publish(
            "git-parent",
            self.manifest_for("git-parent", dependencies={git_name: git_url}),
            origin=granted,
            tarball_on=granted,
        )
        # A packument redirected to the ungranted host, which serves it.
        redirected = self.name("redirected")
        granted.redirect(f"/npm/{redirected}", ungranted.url(f"/npm/{redirected}"))
        packages["redirected"] = self.publish(
            "redirected", self.manifest_for("redirected"), origin=ungranted, tarball_on=ungranted
        )
        # A tarball tampered against the integrity its packument states.
        packages["tampered"] = self.publish(
            "tampered",
            self.manifest_for("tampered"),
            origin=granted,
            tarball_on=granted,
            tamper=True,
        )
        # The ungranted registry serves the plain package too, from its own
        # tarball: pointed there, npm would find it, so a refusal is the proxy's.
        self.publish("plain", self.manifest_for("plain"), origin=ungranted, tarball_on=ungranted)
        project = self.project(packages)
        self.tree.put(
            "workspace/npm-hostile.npmrc",
            (
                "ignore-scripts=false\n"
                "strict-ssl=false\n"
                f"cafile={self.marker_dir}/dwfx-{self.tag}-hostile-ca.pem\n"
                f"userconfig={self.marker_dir}/dwfx-{self.tag}-hostile-userconfig\n"
                f"globalconfig={self.marker_dir}/dwfx-{self.tag}-hostile-globalconfig\n"
            ).encode(),
        )
        return {
            "registry": self.granted.url("/npm/"),
            "ungranted_registry": self.ungranted.url("/npm/"),
            "packages": packages,
            "git_dependency": {"name": git_name, "spec": git_url, "source": f"source/{git_name}"},
            "project": project,
            "hostile_npmrc": "workspace/npm-hostile.npmrc",
        }

    def project(self, packages: dict[str, dict[str, object]]) -> str:
        """A root project depending on the plain and the scripted package, its
        own four scripts marking too, and the lockfile `npm ci` installs."""
        name = self.name("project")
        dependencies = {
            str(packages[role]["name"]): str(packages[role]["version"])
            for role in ("plain", "scripted")
        }
        root = {
            "name": name,
            "version": "1.0.0",
            "private": True,
            "scripts": self.scripts("project"),
            "dependencies": dependencies,
        }
        locked: dict[str, object] = {
            "": {
                "name": name,
                "version": "1.0.0",
                "hasInstallScript": True,
                "dependencies": dependencies,
            }
        }
        for role in ("plain", "scripted"):
            entry: dict[str, object] = {
                "version": packages[role]["version"],
                "resolved": packages[role]["tarball"],
                "integrity": packages[role]["integrity"],
            }
            if role == "scripted":
                entry["hasInstallScript"] = True
            locked[f"node_modules/{packages[role]['name']}"] = entry
        lockfile = {
            "name": name,
            "version": "1.0.0",
            "lockfileVersion": 3,
            "requires": True,
            "packages": locked,
        }
        self.tree.put("workspace/npm/package.json", _json(root))
        self.tree.put("workspace/npm/package-lock.json", _json(lockfile))
        return "workspace/npm"


def generate(seed: str, out: Path, *, marker_dir: str = MARKER_DIR) -> dict[str, object]:
    """Write the fixture set for `seed` under `out` and return its manifest
    (also written as `out/manifest.json`). `out` must be absent or empty."""
    if not _SEED.fullmatch(seed):
        raise ValueError(f"a seed is 1 to 64 of [A-Za-z0-9._-], not {seed!r}")
    if not _MARKER_PATH.fullmatch(marker_dir):
        raise ValueError(f"the marker directory is an absolute plain path, not {marker_dir!r}")
    if out.exists() and any(out.iterdir()):
        raise ValueError(f"{out} is not empty")
    fixtures = _Fixtures(seed, marker_dir)
    pip = fixtures.pip()
    npm = fixtures.npm()
    files = fixtures.tree.files
    manifest: dict[str, object] = {
        "format": FORMAT,
        "seed": seed,
        "tag": fixtures.tag,
        "hosts": {"granted": GRANTED_HOST, "ungranted": UNGRANTED_HOST},
        "marker_dir": marker_dir,
        "markers": dict(sorted(fixtures.markers.items())),
        "pip": pip,
        "npm": npm,
        "routes": {
            "granted": dict(sorted(fixtures.granted.routes.items())),
            "ungranted": dict(sorted(fixtures.ungranted.routes.items())),
        },
        "files": {path: _sha256(files[path]) for path in sorted(files)},
    }
    for path in sorted(files):
        target = out / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(files[path])
    (out / "manifest.json").write_bytes(_json(manifest))
    return manifest


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0] if __doc__ else None)
    parser.add_argument("seed")
    parser.add_argument("out", type=Path)
    args = parser.parse_args(argv)
    generate(args.seed, args.out)
    print(json.dumps({"manifest": str(args.out / "manifest.json")}))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
