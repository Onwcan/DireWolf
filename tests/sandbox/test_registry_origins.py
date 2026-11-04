"""M5e.3's two registry origins: one name and one certificate each, from one
per-run authority, serving exactly their manifest's routes over verified TLS
(M5E_ASSURANCE_PLAN.md §7a, "Origins" and "Per-run CA").

The PKI is `tests/net_http/make-pki.sh`'s, made afresh in a temporary
directory for every run and never committed. The origins are
`tests/net_http/origin.py --routes`, one per side of a generated manifest, on
loopback. A stock verifying client -- the standard library's, the per-run
anchor its only trust, the origin's name its server name -- reaches every
route and gets exactly the bytes the manifest states. The ungranted origin
passes that same verification for its own name, so whatever refuses it in the
evidence is never TLS. That refusal is the proxy's: shown in process, over the
generator's two names, by the broker's egress tests
(`crates/dwkd-broker/src/egress/tests.rs`,
`a_registry_tunnel_reaches_the_granted_origin_and_never_the_ungranted_one`).

What a TLS failure looks like is held apart from it: the wrong name, an
untrusted issuer, and a certificate only an image's system store trusts
(ADR-0055 §9) each fail verification under the anchor.

Linux only: the PKI script and the evidence that uses these origins run there
(as `test_ci_authority_gate.py`'s Linux-only cases do). Nothing here installs,
fetches or reaches anything but loopback.
"""

from __future__ import annotations

import hashlib
import json
import socket
import ssl
import subprocess
import sys
import threading
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, cast
from urllib.parse import urlsplit

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent))
import registry_fixtures as fx

REPO_ROOT = Path(__file__).resolve().parents[2]
MAKE_PKI = REPO_ROOT / "tests" / "net_http" / "make-pki.sh"
ORIGIN = REPO_ROOT / "tests" / "net_http" / "origin.py"
LINUX = sys.platform.startswith("linux")
pytestmark = pytest.mark.skipif(
    not LINUX, reason="the per-run PKI and the evidence that uses these origins are Linux's"
)


@dataclass
class Origin:
    """One running origin: its process, its port and every request it saw."""

    process: subprocess.Popen[str]
    port: int
    requests: list[dict[str, object]] = field(default_factory=list)

    def stop(self) -> None:
        self.process.terminate()
        self.process.wait(timeout=10)


def _start(pki: Path, leaf: str, manifest: Path, side: str) -> Origin:
    process = subprocess.Popen(
        [
            sys.executable,
            str(ORIGIN),
            "--cert",
            str(pki / f"{leaf}.pem"),
            "--key",
            str(pki / f"{leaf}.key"),
            "--routes",
            str(manifest),
            "--side",
            side,
        ],
        stdout=subprocess.PIPE,
        text=True,
    )
    assert process.stdout is not None
    ready = process.stdout.readline()
    assert ready.startswith("ORIGIN-READY "), ready
    origin = Origin(process, int(json.loads(ready.removeprefix("ORIGIN-READY "))["port"]))
    stdout = process.stdout

    def drain() -> None:
        # Read every request line, so the origin never blocks on a full pipe.
        for line in stdout:
            if line.startswith("ORIGIN-REQUEST "):
                origin.requests.append(json.loads(line.removeprefix("ORIGIN-REQUEST ")))

    threading.Thread(target=drain, daemon=True).start()
    return origin


@dataclass
class Registry:
    pki: Path
    out: Path
    manifest: dict[str, Any]
    granted: Origin
    ungranted: Origin

    def host(self, side: str) -> str:
        return str(self.manifest["hosts"][side])

    def origin(self, side: str) -> Origin:
        return self.granted if side == "granted" else self.ungranted


def _make_pki(into: Path) -> Path:
    subprocess.run(["bash", str(MAKE_PKI), str(into)], check=True, capture_output=True)
    return into


@pytest.fixture(scope="module")
def registry(tmp_path_factory: pytest.TempPathFactory) -> Iterator[Registry]:
    base = tmp_path_factory.mktemp("registry")
    pki = _make_pki(base / "pki")
    out = base / "fixtures"
    manifest = fx.generate("direwolf-m5e3-origins", out)
    granted = _start(pki, "registry-granted", out / "manifest.json", "granted")
    ungranted = _start(pki, "registry-ungranted", out / "manifest.json", "ungranted")
    try:
        yield Registry(pki, out, manifest, granted, ungranted)
    finally:
        granted.stop()
        ungranted.stop()


def _verifying(cafile: Path) -> ssl.SSLContext:
    """The standard library's verifying client, trusting `cafile` alone."""
    context = ssl.create_default_context(cafile=str(cafile))
    assert context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname
    return context


def _get(
    port: int, name: str, path: str, cafile: Path, method: str = "GET"
) -> tuple[int, dict[str, str], bytes]:
    """One request over verified TLS, as `name`; its status, headers and body."""
    with (
        socket.create_connection(("127.0.0.1", port), timeout=10) as raw,
        _verifying(cafile).wrap_socket(raw, server_hostname=name) as tls,
    ):
        request = f"{method} {path} HTTP/1.1\r\nHost: {name}\r\nConnection: close\r\n\r\n"
        tls.sendall(request.encode("ascii"))
        data = b""
        while chunk := tls.recv(65536):
            data += chunk
    head, _, body = data.partition(b"\r\n\r\n")
    status_line, *lines = head.decode("latin-1").split("\r\n")
    headers = {k.strip().lower(): v.strip() for k, _, v in (line.partition(":") for line in lines)}
    return int(status_line.split(" ")[1]), headers, body


def test_each_origin_serves_exactly_its_routes_over_verified_tls(registry: Registry) -> None:
    files = registry.manifest["files"]
    served = 0
    for side in ("granted", "ungranted"):
        port, name = registry.origin(side).port, registry.host(side)
        for path, route in registry.manifest["routes"][side].items():
            status, headers, body = _get(port, name, path, registry.pki / "ca.pem")
            assert headers["connection"] == "close"
            if "redirect" in route:
                assert (status, headers["location"], body) == (302, route["redirect"], b"")
                target = urlsplit(route["redirect"])
                assert target.hostname == fx.UNGRANTED_HOST, route
            else:
                assert status == 200, (side, path)
                assert headers["content-type"] == route["type"]
                assert int(headers["content-length"]) == len(body)
                assert hashlib.sha256(body).hexdigest() == files[route["file"]], (side, path)
            served += 1
    assert served == sum(len(r) for r in registry.manifest["routes"].values()) >= 30


def test_an_origin_answers_nothing_but_its_own_routes(registry: Registry) -> None:
    cafile = registry.pki / "ca.pem"
    for side, other in (("granted", "ungranted"), ("ungranted", "granted")):
        port, name = registry.origin(side).port, registry.host(side)
        own = registry.manifest["routes"][side]
        for path in registry.manifest["routes"][other]:
            if path not in own:
                assert _get(port, name, path, cafile)[0] == 404, (side, path)
        for path in ("/", "/simple", "/files/", "/npm/", "/manifest.json", "/../manifest.json"):
            assert _get(port, name, path, cafile)[0] == 404, (side, path)
        some = next(iter(own))
        assert _get(port, name, some, cafile, method="POST")[0] == 405


def test_the_ungranted_origin_is_as_valid_as_the_granted_one(registry: Registry) -> None:
    """Both origins pass the same verification, each for its own name and only
    for it, under one per-run anchor -- so a refusal of the ungranted origin
    in the evidence cannot be a TLS failure."""
    cafile = registry.pki / "ca.pem"
    for side in ("granted", "ungranted"):
        with (
            socket.create_connection(("127.0.0.1", registry.origin(side).port), timeout=10) as raw,
            _verifying(cafile).wrap_socket(raw, server_hostname=registry.host(side)) as tls,
        ):
            certificate = tls.getpeercert()
            assert certificate is not None
            assert certificate["subjectAltName"] == (("DNS", registry.host(side)),)
            entries = cast("tuple[tuple[tuple[str, str], ...], ...]", certificate["issuer"])
            issuer = {key: value for entry in entries for key, value in entry}
            assert issuer["commonName"] == "DireWolf net.http evidence ca"
    assert registry.host("granted") != registry.host("ungranted")


def test_a_tls_failure_is_a_verification_error_and_nothing_else(registry: Registry) -> None:
    """What a TLS failure is, held apart from a proxy's refusal: the wrong
    name, an issuer the anchor does not know, and a certificate only an
    image's system store would trust each fail verification under the anchor;
    the last is accepted only by that other store."""
    pki, manifest = registry.pki, registry.out / "manifest.json"
    cafile = pki / "ca.pem"
    granted = registry.granted
    with pytest.raises(ssl.SSLCertVerificationError, match="match"):
        _get(granted.port, registry.host("ungranted"), "/simple/", cafile)
    for leaf in ("registry-rogue", "registry-system"):
        impostor = _start(pki, leaf, manifest, "granted")
        try:
            with pytest.raises(ssl.SSLCertVerificationError):
                _get(impostor.port, registry.host("granted"), "/simple/", cafile)
            if leaf == "registry-system":
                status, _, _ = _get(
                    impostor.port, registry.host("granted"), "/simple/", pki / "system.pem"
                )
                assert status == 200
        finally:
            impostor.stop()


def test_the_pki_is_made_per_run_and_the_origins_end_with_their_test(tmp_path: Path) -> None:
    first, second = _make_pki(tmp_path / "one"), _make_pki(tmp_path / "two")
    for name in ("ca.key", "registry-granted.key", "registry-ungranted.key"):
        assert (first / name).read_bytes() != (second / name).read_bytes(), name
    out = tmp_path / "fixtures"
    fx.generate("direwolf-m5e3-ending", out)
    origin = _start(first, "registry-granted", out / "manifest.json", "granted")
    assert _get(origin.port, fx.GRANTED_HOST, "/simple/", first / "ca.pem")[0] == 200
    origin.stop()
    assert origin.process.returncode is not None
    with pytest.raises(ConnectionRefusedError):
        socket.create_connection(("127.0.0.1", origin.port), timeout=5).close()


def test_an_origin_refuses_a_side_or_file_its_manifest_does_not_hold(tmp_path: Path) -> None:
    pki = _make_pki(tmp_path / "pki")
    out = tmp_path / "fixtures"
    fx.generate("direwolf-m5e3-refusals", out)
    manifest = json.loads((out / "manifest.json").read_text())
    escaping = dict(manifest)
    escaping["routes"] = {"granted": {"/x": {"file": "../outside", "type": "text/plain"}}}
    (tmp_path / "outside").write_text("not the fixtures'")
    (out / "escaping.json").write_text(json.dumps(escaping))
    no_side = dict(manifest)
    no_side["routes"] = {"ungranted": manifest["routes"]["ungranted"]}
    (out / "no-side.json").write_text(json.dumps(no_side))
    for name in ("escaping.json", "no-side.json"):
        done = subprocess.run(
            [
                sys.executable,
                str(ORIGIN),
                "--cert",
                str(pki / "registry-granted.pem"),
                "--key",
                str(pki / "registry-granted.key"),
                "--routes",
                str(out / name),
                "--side",
                "granted",
            ],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )
        assert done.returncode != 0 and "ORIGIN-READY" not in done.stdout, (name, done)
