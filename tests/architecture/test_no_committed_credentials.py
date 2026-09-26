"""No credential-shaped string is committed (M4e, CONTRIBUTING.md "Secrets").

M4e brings secret-shaped test data -- redaction fixtures for every known token
shape, age identities for the age backend -- and the rule that none of it is
committed: every such fixture is assembled at run time from fragments, or
generated (`age::x25519::Identity::generate`), so no file in the tree holds a
whole token. This check makes the rule a gate. It walks the working tree -- no
network, no third-party scanner -- for the shapes a real credential of a kind
DireWolf handles would have, including the one push protection's provider
patterns do not know: an age identity, which is what unlocks every age store.

It is a tripwire for accidents, not a control: a credential with no shape
passes, and a test that assembles a token at run time is by design invisible
to it. The planted-leak test proves each rule fires on a synthetic value built
the same way the redaction fixtures build theirs.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]

# Directories that hold build output, caches or other people's code, never
# DireWolf's sources.
_SKIP_DIRS = frozenset(
    {
        ".git",
        ".venv",
        "target",
        "node_modules",
        "__pycache__",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        "corpus",
        "artifacts",
        "dist",
        "build",
    }
)
_MAX_FILE_BYTES = 4 * 1024 * 1024

# One rule per credential kind, each tight enough that documentation naming a
# prefix (`ghp_`, `AKIA`, `AGE-SECRET-KEY-1…`) is not a finding.
_RULES: dict[str, re.Pattern[bytes]] = {
    "github": re.compile(rb"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{22,})"),
    "openai": re.compile(rb"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}"),
    "slack": re.compile(rb"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    "aws": re.compile(rb"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"),
    "pem_private_key": re.compile(
        rb"-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----\s*[A-Za-z0-9+/=]{16,}"
    ),
    "jwt": re.compile(rb"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    # age: an X25519 identity is `AGE-SECRET-KEY-1` and 58 bech32 characters;
    # a post-quantum one carries `PQ-`.
    "age_identity": re.compile(rb"AGE-SECRET-KEY-(?:PQ-)?1[023456789ACDEFGHJKLMNPQRSTUVWXYZ]{40,}"),
}


def _plausible(rule: str, token: bytes) -> bool:
    # An `sk-` run of letters only is a kebab-case identifier, not a key.
    if rule == "openai":
        return any(chr(b).isdigit() for b in token) and any(chr(b).isalpha() for b in token[3:])
    return True


def _files(root: Path) -> Iterator[Path]:
    for path in sorted(root.iterdir()):
        if path.is_symlink():
            continue
        if path.is_dir():
            if path.name not in _SKIP_DIRS:
                yield from _files(path)
        elif path.is_file() and path.stat().st_size <= _MAX_FILE_BYTES:
            yield path


def scan(root: Path) -> tuple[int, list[str]]:
    """How many text files were read, and every finding as `path: rule`."""
    scanned = 0
    found: list[str] = []
    for path in _files(root):
        data = path.read_bytes()
        if b"\0" in data:
            continue
        scanned += 1
        for rule, pattern in _RULES.items():
            for match in pattern.finditer(data):
                if _plausible(rule, match.group(0)):
                    # The rule and the place, never the matched bytes.
                    found.append(f"{path.relative_to(root).as_posix()}: {rule}")
    return scanned, sorted(set(found))


def _synthetic(seed: int, length: int, alphabet: str) -> str:
    state = seed * 6364136223846793005 + 1442695040888963407
    out = []
    for _ in range(length):
        state = (state * 6364136223846793005 + 1442695040888963407) % (1 << 64)
        out.append(alphabet[(state >> 58) % len(alphabet)])
    return "".join(out)


_ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
_BECH32_UPPER = "023456789ACDEFGHJKLMNPQRSTUVWXYZ"


def _planted() -> dict[str, str]:
    """One synthetic leak per rule, assembled here so this file holds none."""
    return {
        "github": "gh" + "p_" + _synthetic(1, 36, _ALNUM),
        "openai": "s" + "k-proj-" + _synthetic(2, 30, _ALNUM) + "9",
        "slack": "xo" + "xb-" + _synthetic(3, 24, _ALNUM),
        "aws": "AK" + "IA" + _synthetic(4, 16, "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"),
        "pem_private_key": "-----BEGIN "
        + "OPENSSH PRIVATE "
        + "KEY-----\n"
        + _synthetic(5, 64, _ALNUM)
        + "\n-----END OPENSSH PRIVATE KEY-----",
        "jwt": "ey"
        + "J"
        + _synthetic(6, 20, _ALNUM)
        + "."
        + _synthetic(7, 30, _ALNUM)
        + "."
        + _synthetic(8, 25, _ALNUM),
        "age_identity": "AGE-SECRET-" + "KEY-1" + _synthetic(9, 58, _BECH32_UPPER),
    }


def test_the_scan_reads_the_tree() -> None:
    # A scan over nothing proves nothing.
    scanned, _ = scan(REPO_ROOT)
    assert scanned > 300, scanned


def test_no_credential_shaped_string_is_committed() -> None:
    _, found = scan(REPO_ROOT)
    assert found == [], (
        "credential-shaped content in the tree (build fixtures at run time):\n" + "\n".join(found)
    )


def test_every_rule_catches_a_planted_synthetic_leak(tmp_path: Path) -> None:
    planted = _planted()
    assert set(planted) == set(_RULES)
    for rule, token in planted.items():
        case = tmp_path / rule
        case.mkdir()
        (case / "leak.txt").write_text(f"config value: {token}\n", encoding="utf-8")
        _, found = scan(case)
        assert found == [f"leak.txt: {rule}"], (rule, found)


def test_names_and_near_misses_are_not_findings(tmp_path: Path) -> None:
    # Documentation names prefixes; a finding needs a whole token.
    (tmp_path / "doc.md").write_text(
        "\n".join(
            [
                "known shapes: `ghp_`, `github_pat_`, `sk-`, `xox[baprs]-`, `AKIA`, `ASIA`",
                "an X25519 identity is `AGE-SECRET-" + "KEY-1…`",
                "sk-learn-is-a-library-not-a-key-at-all",
                "AK" + "IA0123 is too short",
                "-----BEGIN PUBLIC KEY-----",
                "-----BEGIN " + "PRIVATE KEY----- (a heading, no body)",
                "Bearer <base64>",
            ]
        ),
        encoding="utf-8",
    )
    scanned, found = scan(tmp_path)
    assert scanned == 1
    assert found == []


def test_a_binary_file_and_a_skipped_directory_are_not_read(tmp_path: Path) -> None:
    token = _planted()["age_identity"]
    (tmp_path / "blob.bin").write_bytes(b"\0" + token.encode())
    (tmp_path / "target").mkdir()
    (tmp_path / "target" / "out.txt").write_text(token, encoding="utf-8")
    assert scan(tmp_path) == (0, [])
