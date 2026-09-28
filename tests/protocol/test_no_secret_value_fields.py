"""No public protocol surface can carry a secret value (M4e, ADR-0046 §4).

A handle is an identifier and may appear; a value may not. This measures the
whole public corpus -- every emitted JSON Schema (DWKP, DWCP, events, common
definitions), every message in the shared test vectors, and every field of
the generated Python bindings -- for a member whose name says it carries
credential material, and proves the check itself catches one.

It is a static check over the contract, not the boundary: the boundary is that
no DWKP operation reads a value (ADR-0046 §4) and that the runtime's address
space is measured to hold none (`crates/dwkd-authority/tests/secret_evidence.rs`).
"""

from __future__ import annotations

import ast
import json
import re
from collections.abc import Iterator, Mapping
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]

# A member name that says it carries credential material. Matched against
# whole underscore-separated words, so `idempotency_key` -- a request key,
# not a credential -- and a future `credential_handle` are not findings.
_FORBIDDEN = re.compile(
    r"(^|_)(secret|secrets|password|passwd|passphrase|plaintext|credential|credentials|"
    r"api_key|apikey|private_key|access_key|bearer|cookie|authorization)(_|$)"
)

# Names that are identifiers, never values: a handle names a secret.
_ALLOWED = frozenset(
    {
        "credential_handle",
        "credential_handles",
        "secret_handle",
        "secret_handles",
    }
)


def forbidden(name: str) -> bool:
    lowered = name.lower()
    return lowered not in _ALLOWED and _FORBIDDEN.search(lowered) is not None


def _schema_members(node: object) -> Iterator[str]:
    if isinstance(node, dict):
        for key, value in node.items():
            if key in ("properties", "patternProperties") and isinstance(value, dict):
                yield from value.keys()
            yield from _schema_members(value)
    elif isinstance(node, list):
        for item in node:
            yield from _schema_members(item)


def _object_keys(node: object) -> Iterator[str]:
    if isinstance(node, dict):
        for key, value in node.items():
            yield key
            yield from _object_keys(value)
    elif isinstance(node, list):
        for item in node:
            yield from _object_keys(item)


def schema_members() -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    for path in sorted((ROOT / "schemas").rglob("*.json")):
        found[str(path.relative_to(ROOT))] = set(
            _schema_members(json.loads(path.read_text(encoding="utf-8")))
        )
    return found


def vector_names(vector: Mapping[str, object], *, invalid_file: bool) -> set[str]:
    """The member names one shared vector's JSON documents carry.

    Only intentionally invalid input may fail to parse: the ``input`` of a
    vector in ``invalid.json`` that declares the ``code`` it must be rejected
    with. Such input may be malformed, or nested past the depth this parser
    (and platform, and stack) can follow -- the corpus holds a depth bomb, and
    CPython raises ``RecursionError`` on it at a platform-dependent depth -- and
    either way it carries no member names. Every other document -- a valid
    vector's input, any ``canonical`` form -- must parse, and a failure,
    ``RecursionError`` included, propagates.
    """
    names: set[str] = set()
    for field in ("input", "canonical"):
        text = vector.get(field)
        if not isinstance(text, str):
            continue
        rejected = invalid_file and field == "input" and isinstance(vector.get("code"), str)
        try:
            document = json.loads(text)
        except (json.JSONDecodeError, RecursionError):
            if rejected:
                continue
            raise
        names.update(_object_keys(document))
    return names


def vector_members() -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    for path in sorted((ROOT / "tests" / "protocol" / "vectors").glob("*.json")):
        names: set[str] = set()
        for vector in json.loads(path.read_text(encoding="utf-8")).get("vectors", []):
            names.update(vector_names(vector, invalid_file=path.name == "invalid.json"))
        found[str(path.relative_to(ROOT))] = names
    return found


def binding_fields() -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    for path in sorted((ROOT / "runtime" / "src" / "direwolf" / "proto").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        names: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                for item in node.body:
                    if isinstance(item, ast.AnnAssign) and isinstance(item.target, ast.Name):
                        names.add(item.target.id)
        found[str(path.relative_to(ROOT))] = names
    return found


def findings(corpus: dict[str, set[str]]) -> list[str]:
    return sorted(
        f"{where}: {name}" for where, names in corpus.items() for name in names if forbidden(name)
    )


def test_the_corpus_is_not_empty() -> None:
    # A check over nothing proves nothing.
    assert sum(len(v) for v in schema_members().values()) > 50
    assert sum(len(v) for v in vector_members().values()) > 10
    assert sum(len(v) for v in binding_fields().values()) > 50


def test_no_emitted_schema_has_a_member_for_secret_material() -> None:
    assert findings(schema_members()) == []


def test_no_test_vector_carries_a_member_for_secret_material() -> None:
    assert findings(vector_members()) == []


def test_no_generated_binding_has_a_field_for_secret_material() -> None:
    assert findings(binding_fields()) == []


def test_the_check_catches_a_value_field_and_allows_a_handle() -> None:
    planted: dict[str, object] = {
        "properties": {
            "payload": {
                "properties": {
                    "credential_handle": {},
                    "secret_value": {},
                    "api_key": {},
                    "password": {},
                    "plaintext": {},
                    "authorization": {},
                    "idempotency_key": {},
                }
            }
        }
    }
    caught = sorted(name for name in _schema_members(planted) if forbidden(name))
    assert caught == ["api_key", "authorization", "password", "plaintext", "secret_value"]


# Deep enough that CPython's JSON parser gives up on every platform, stack and
# version (on Windows the corpus's own depth bomb already does); built here,
# never committed.
_TOO_DEEP = 1_000_000


def _too_deep(closed: bool) -> str:
    text = "[" * _TOO_DEEP + ("]" * _TOO_DEEP if closed else "")
    with pytest.raises(RecursionError):
        json.loads(text)  # the precondition: this really is a parser-depth failure
    return text


def test_an_over_deep_intentionally_invalid_input_carries_no_names() -> None:
    rejected = {"name": "depth bomb", "code": "PROTOCOL_MAX_DEPTH_EXCEEDED"}
    for text in (_too_deep(closed=False), _too_deep(closed=True)):
        assert vector_names({**rejected, "input": text}, invalid_file=True) == set()
    # Malformed invalid input, as before.
    assert vector_names({**rejected, "input": '{"a":'}, invalid_file=True) == set()


def test_a_parse_failure_anywhere_else_is_never_ignored() -> None:
    deep = _too_deep(closed=True)
    # A valid vector's input and a canonical form must parse, wherever they
    # are; so must invalid input that declares no rejection.
    for vector, invalid_file in (
        ({"name": "valid", "input": deep}, False),
        ({"name": "valid", "input": "{}", "canonical": deep}, False),
        ({"name": "invalid", "code": "X", "input": "{}", "canonical": deep}, True),
        ({"name": "undeclared", "input": deep}, True),
    ):
        with pytest.raises(RecursionError):
            vector_names(vector, invalid_file=invalid_file)
    with pytest.raises(json.JSONDecodeError):
        vector_names({"name": "valid", "input": '{"a":'}, invalid_file=False)


def test_the_vector_check_still_catches_a_value_field_and_allows_a_handle() -> None:
    planted = (
        '{"payload": {"credential_handle": "h", "secret_value": 1, "api_key": 2, "password": 3}}'
    )
    for vector, invalid_file in (
        ({"name": "valid", "input": planted}, False),
        ({"name": "invalid", "code": "X", "input": planted}, True),
        ({"name": "valid", "input": "{}", "canonical": planted}, False),
    ):
        names = vector_names(vector, invalid_file=invalid_file)
        caught = sorted(name for name in names if forbidden(name))
        assert caught == ["api_key", "password", "secret_value"]
        assert "credential_handle" in names and not forbidden("credential_handle")
