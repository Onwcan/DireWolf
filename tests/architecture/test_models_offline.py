"""The operator's model library stays offline (ADR-0072, Proposed).

**No second egress path.** `direwolf models` links no HTTP or TLS crate
(TX044: only the broker's HTTPS client does), names no socket type, and its
manifests never call a model ready for inference: downloading is the
authority's decision, and inference is M7's.

**No pretend commands.** The dispatch holds the offline commands and nothing
that would need the network: no search, pull, pause or resume.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
CLI = REPO_ROOT / "crates" / "direwolf-cli"
MODELS = CLI / "src" / "models"
ADR = (
    REPO_ROOT
    / "docs"
    / "adr"
    / (
        "0072-the-operators-model-library-is-offline-and-a-download-is-egress-"
        "the-authority-decides.md"
    )
)

NETWORK_CRATES = {
    "rustls",
    "ureq",
    "ureq-proto",
    "reqwest",
    "hyper",
    "http",
    "native-tls",
    "openssl",
    "webpki-roots",
    "rustls-webpki",
    "curl",
}


def _read(path: Path) -> str:
    return path.read_bytes().decode("utf-8")


def test_the_cli_links_no_network_crate() -> None:
    manifest = tomllib.loads(_read(CLI / "Cargo.toml"))
    dependencies = set(manifest.get("dependencies", {}))
    assert dependencies == {"dwk-proto", "sha2"}, dependencies
    assert not dependencies & NETWORK_CRATES
    lock = _read(REPO_ROOT / "Cargo.lock")
    entry = lock[lock.index('name = "direwolf-cli"') :]
    entry = entry[: entry.index("\n\n")]
    for crate in NETWORK_CRATES:
        assert f'"{crate}' not in entry, crate


def test_no_source_of_the_library_opens_a_socket_or_names_a_url() -> None:
    for path in sorted(MODELS.glob("*.rs")):
        text = _read(path)
        for forbidden in (
            "std::net",
            "TcpStream",
            "UdpSocket",
            "UnixStream",
            "http://",
            "https://",
        ):
            assert forbidden not in text, (path.name, forbidden)
        assert "Command::new" not in text, path.name


def test_the_commands_are_the_offline_ones_and_none_pretends() -> None:
    dispatch = _read(MODELS / "mod.rs")
    arms = set(re.findall(r'^\s+"([a-z-]+)" => [a-z]+\(&o\)', dispatch, re.M))
    assert arms == {"status", "inspect", "import", "list", "verify", "remove", "recommend"}, arms
    for absent in ("search", "pull", "pause", "resume", "download", "providers"):
        assert f'"{absent}" =>' not in dispatch, absent
    library = _read(MODELS / "library.rs")
    assert '("ready_for_inference", Value::Bool(false))' in library
    assert '("verified", Value::String("LOCAL_DIGEST_ONLY".to_owned()))' in library
    assert '("publisher_authenticated", Value::Bool(false))' in library


def test_adr_0072_is_proposed_and_says_what_is_blocked() -> None:
    text = _read(ADR)
    assert text.startswith("# ADR-0072:")
    assert re.search(r"^\*\*Status:\*\* Proposed ", text, re.M)
    for said in ("TX044", "BLOCKED", "LOCAL_DIGEST_ONLY", "model_download", "OM-1", "M7"):
        assert said in text, said
    index = _read(REPO_ROOT / "docs" / "adr" / "README.md")
    assert f"[0072]({ADR.name})" in index
    assert "direwolf models" in _read(REPO_ROOT / "docs" / "MODELS.md")
