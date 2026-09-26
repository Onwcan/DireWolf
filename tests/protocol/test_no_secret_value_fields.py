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
from collections.abc import Iterator
from pathlib import Path

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


def vector_members() -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    for path in sorted((ROOT / "tests" / "protocol" / "vectors").glob("*.json")):
        names: set[str] = set()
        for vector in json.loads(path.read_text(encoding="utf-8")).get("vectors", []):
            for field in ("input", "canonical"):
                text = vector.get(field)
                if not isinstance(text, str):
                    continue
                try:
                    names.update(_object_keys(json.loads(text)))
                except json.JSONDecodeError:
                    # Invalid vectors are meant not to parse; their names are
                    # not a contract.
                    continue
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
