"""M6.1 (ADR-0079, Proposed): an independent oracle for the approval binding's
golden vectors.

Each vector below is the canonical object ADR-0079 specifies, written out by
hand from the record -- not produced by the Rust implementation. This file
encodes it with RFC 8785 (every value is a string, null, array or object, so
Python's sorted, compact, non-ASCII-escaping encoding is JCS for it) and
hashes it with hashlib's SHA-256. `vectors/approval_binding_v1.json` must
hold exactly those bytes and digests; the Rust tests
(`crates/dwkd-authority/src/state/binding_tests.rs`) build the same bindings
from typed authority values and must produce the same bytes and digests.
Two implementations, one of them test-only, agree or a test fails.

Nothing here is a production binding: no Python code computes one.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

VECTORS_FILE = Path(__file__).parent / "vectors" / "approval_binding_v1.json"
SCHEMA = "direwolf.approval.binding.v1"
MEMBERS = {
    "schema",
    "verb",
    "resource_identity",
    "canonical_args",
    "workspace",
    "environment_profile",
    "credential_handles",
    "agent",
    "requester",
    "scope",
    "taint_level",
    "privacy_class",
    "obligations",
}


def canonical(value: object) -> str:
    """RFC 8785 for a value of strings, nulls, arrays and objects with ASCII
    keys: members sorted, no whitespace, no escaping beyond JSON's own."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def a_set(*members: object) -> list[object]:
    """ADR-0079 §2: a set is sorted by its members' canonical bytes."""
    return sorted(members, key=lambda m: canonical(m).encode("utf-8"))


WORKSPACE = {
    "id": "ws",
    "root": {
        "device": "2049",
        "inode": "2",
        "birth": {"seconds": "1700000000", "nanoseconds": "123456789"},
    },
}
AGENT = {"profile": "operator", "revision": "1"}
HOST = {"kind": "host"}
ADDRESSES = a_set("93.184.216.34", "2606:2800:0220:0001:0248:1893:25c8:1946")


def binding(**members: object) -> dict[str, object]:
    base: dict[str, object] = {
        "schema": SCHEMA,
        "workspace": WORKSPACE,
        "environment_profile": HOST,
        "credential_handles": [],
        "agent": AGENT,
        "requester": "uid:1000",
        "scope": {"kind": "exact_action"},
        "taint_level": "NONE",
        "privacy_class": None,
        "obligations": [],
    }
    base.update(members)
    assert set(base) == MEMBERS, set(base) ^ MEMBERS
    return base


# (name, the property it pins, the canonical object)
VECTORS: list[tuple[str, str, dict[str, object]]] = [
    (
        "fs-write-exact-action",
        "A write is bound to the file's identity (device, inode), never its "
        "path, and to its content by SHA-256 and length; an obligation is a "
        "tagged object with its parameter as a decimal string.",
        binding(
            verb="fs.write",
            resource_identity={"kind": "file", "device": "2049", "inode": "131074"},
            canonical_args={
                "kind": "fs_content",
                "byte_count": "6",
                "content_sha256": sha256("hello\n"),
            },
            obligations=[{"kind": "max_output_bytes", "bytes": "262144"}],
        ),
    ),
    (
        "process-exec-credentials-tainted",
        "An executable by canonical path and SHA-256; argv in its own order; "
        "credentials as a set sorted by canonical bytes, each with its "
        "revision and metadata digest; the run's taint at grant time.",
        binding(
            verb="process.exec",
            resource_identity={
                "kind": "executable",
                "path": "/usr/bin/git",
                "sha256": "07" * 32,
            },
            canonical_args={"kind": "argv", "argv": ["push", "--force", "origin"]},
            credential_handles=a_set(
                {"handle": "gh-token", "revision": "3", "metadata_sha256": "ab" * 32},
                {"handle": "ci-token", "revision": "1", "metadata_sha256": "cd" * 32},
            ),
            taint_level="EXTERNAL_UNTRUSTED",
            obligations=[{"kind": "network_deny"}],
        ),
    ),
    (
        "net-https-host-and-methods",
        "A host by decided name, port and every pinned address (IPv6 fully "
        "expanded); the request by method, URL digest and body digest -- never "
        "the URL's path or query; a host-and-methods scope with its own "
        "address and method sets.",
        binding(
            verb="network.https",
            resource_identity={
                "kind": "host",
                "host": "api.example.com",
                "port": "443",
                "addresses": ADDRESSES,
            },
            canonical_args={
                "kind": "http",
                "method": "POST",
                "url_sha256": sha256("https://api.example.com/v1/items"),
                "body_bytes": "7",
                "body_sha256": sha256('{"a":1}'),
            },
            scope={
                "kind": "host_and_methods",
                "host": "api.example.com",
                "port": "443",
                "addresses": ADDRESSES,
                "methods": a_set("POST", "GET"),
            },
            taint_level="LOCAL_UNVERIFIED",
            obligations=[{"kind": "max_output_bytes", "bytes": "16"}],
        ),
    ),
    (
        "sandbox-exec",
        "A sandboxed action binds the operator's runtime, socket, image, "
        "probe, topology and relay (null with no proxy) and the assurance the "
        "measurement earned -- never a profile name alone.",
        binding(
            verb="process.exec",
            resource_identity={
                "kind": "executable",
                "path": "/usr/bin/python3",
                "sha256": "09" * 32,
            },
            canonical_args={"kind": "argv", "argv": ["-c", "print(1)"]},
            environment_profile={
                "kind": "sandbox",
                "runtime": "/usr/bin/podman",
                "socket": "/run/podman/podman.sock",
                "image": "sha256:" + "aa" * 32,
                "probe_sha256": "bb" * 32,
                "topology": "NO_NETWORK",
                "relay_sha256": None,
                "assurance": "CONTAINER_ISOLATION",
            },
        ),
    ),
    (
        "fs-delete-path-set-past-2-53",
        "Integers past 2^53 - 1 are decimal strings and stay exact: devices, "
        "inodes and a revision at and beyond the double's exact range, u64 "
        "and u32 maxima; a path set sorted by canonical bytes.",
        binding(
            verb="fs.delete",
            resource_identity={
                "kind": "file",
                "device": "18446744073709551615",
                "inode": "9007199254740993",
            },
            canonical_args={"kind": "fs", "byte_count": "0"},
            workspace={
                "id": "ws-big",
                "root": {
                    "device": "9007199254740991",
                    "inode": "18446744073709551615",
                    "birth": None,
                },
            },
            agent={"profile": "operator", "revision": "9007199254740993"},
            requester="uid:4294967295",
            scope={
                "kind": "path_set",
                "verb": "fs.delete",
                "files": a_set(
                    {"device": "9007199254740991", "inode": "1"},
                    {"device": "18446744073709551615", "inode": "9007199254740993"},
                    {"device": "1", "inode": "9007199254740992"},
                ),
            },
        ),
    ),
    (
        "secret-use-credential-use",
        "A credential's use is bound to its handle as the resource and to its "
        "current revision; the credential-use scope names the upstream.",
        binding(
            verb="secret.use",
            resource_identity={"kind": "credential", "handle": "gh-token"},
            canonical_args={"kind": "none"},
            credential_handles=[
                {"handle": "gh-token", "revision": "2", "metadata_sha256": "ef" * 32}
            ],
            scope={
                "kind": "credential_use",
                "handle": "gh-token",
                "host": "api.github.com",
                "port": "443",
            },
        ),
    ),
]


def expected() -> list[dict[str, str]]:
    return [
        {
            "name": name,
            "property": prop,
            "canonical": canonical(obj),
            "sha256": sha256(canonical(obj)),
        }
        for name, prop, obj in VECTORS
    ]


def stored() -> list[dict[str, str]]:
    document = json.loads(VECTORS_FILE.read_text(encoding="utf-8"))
    assert document["schema"] == SCHEMA
    vectors: list[dict[str, str]] = document["vectors"]
    return vectors


def test_the_stored_vectors_are_the_oracles() -> None:
    assert stored() == expected()


def test_every_vector_is_canonical_and_its_digest_is_sha256() -> None:
    for vector in stored():
        text = vector["canonical"]
        assert canonical(json.loads(text)) == text, vector["name"]
        assert hashlib.sha256(text.encode("utf-8")).hexdigest() == vector["sha256"]


def scalars(value: object) -> list[object]:
    if isinstance(value, dict):
        return [s for v in value.values() for s in scalars(v)]
    if isinstance(value, list):
        return [s for v in value for s in scalars(v)]
    return [value]


def test_no_vector_holds_a_json_number_or_a_boolean() -> None:
    # ADR-0079 §2: every integer is a decimal string; nothing rounds.
    for vector in stored():
        for scalar in scalars(json.loads(vector["canonical"])):
            assert scalar is None or isinstance(scalar, str), (vector["name"], scalar)


def test_every_vector_names_exactly_the_thirteen_members() -> None:
    for vector in stored():
        assert set(json.loads(vector["canonical"])) == MEMBERS, vector["name"]


def test_distinct_vectors_have_distinct_digests() -> None:
    digests = [v["sha256"] for v in stored()]
    assert len(set(digests)) == len(digests)
