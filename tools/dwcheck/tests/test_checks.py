"""Unit tests for the checker's own logic.

``tests/architecture/`` proves the rules reject real violations. These tests
cover the edges where a checker is usually wrong: the false positive that gets
it switched off, and the false negative that makes it decorative.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

import pytest

from dwcheck import Finding, Report
from dwcheck.checks_links import check_links
from dwcheck.checks_manifests import (
    check_crates,
    check_lockfile_closure,
    check_python_dependencies,
)
from dwcheck.checks_python import check_python_imports, check_text
from dwcheck.config import ArchitectureConfig, ConfigError, load

RULES = Path(__file__).resolve().parents[3] / "architecture.toml"


def _tree(root: Path, files: dict[str, str]) -> None:
    for name, body in files.items():
        path = root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(textwrap.dedent(body).lstrip(), encoding="utf-8")


def _config(root: Path) -> ArchitectureConfig:
    return load(root, RULES)


# --- import detection ------------------------------------------------------


def test_a_banned_import_is_detected(tmp_path: Path) -> None:
    _tree(tmp_path, {"runtime/src/direwolf/x.py": "import socket\n"})
    findings = check_python_imports(_config(tmp_path))
    assert any(f.rule.startswith("PY001") for f in findings)


def test_a_banned_submodule_is_detected(tmp_path: Path) -> None:
    """`socket` is banned, so `socket.something` must be too."""
    _tree(tmp_path, {"runtime/src/direwolf/x.py": "import urllib.request.foo\n"})
    findings = check_python_imports(_config(tmp_path))
    assert findings


def test_a_banned_name_in_a_comment_or_string_is_not_a_finding(tmp_path: Path) -> None:
    """The check parses; it does not grep. A checker with false positives gets
    switched off, and then it protects nothing."""
    _tree(
        tmp_path,
        {
            "runtime/src/direwolf/x.py": '''
            """This module deliberately does not import socket or subprocess."""

            # import socket
            NOTE = "we never call os.system here"
            '''
        },
    )
    assert not [f for f in check_python_imports(_config(tmp_path)) if f.rule.startswith("PY001")]


def test_a_banned_attribute_call_is_detected(tmp_path: Path) -> None:
    _tree(tmp_path, {"runtime/src/direwolf/x.py": "import os\n\nos.system('ls')\n"})
    findings = check_python_imports(_config(tmp_path))
    assert any("os.system" in f.message for f in findings)


def test_from_import_of_a_banned_attribute_is_detected(tmp_path: Path) -> None:
    _tree(tmp_path, {"runtime/src/direwolf/x.py": "from os import system\n"})
    findings = check_python_imports(_config(tmp_path))
    assert any("os.system" in f.message for f in findings)


def test_the_exempt_module_may_do_what_others_may_not(tmp_path: Path) -> None:
    """`direwolf.kernelclient` opens the kernel socket; that is its whole job."""
    _tree(tmp_path, {"runtime/src/direwolf/kernelclient/transport.py": "import socket\n"})
    assert not [f for f in check_python_imports(_config(tmp_path)) if f.rule.startswith("PY001")]


def test_unparseable_python_is_reported_not_skipped(tmp_path: Path) -> None:
    """A file the checker cannot read is not a file the checker has cleared."""
    _tree(tmp_path, {"runtime/src/direwolf/x.py": "def broken(\n"})
    findings = check_python_imports(_config(tmp_path))
    assert any("could not parse" in f.message for f in findings)


# --- dependency names ------------------------------------------------------


@pytest.mark.parametrize("spelling", ["langchain-core", "langchain_core", "LangChain.Core"])
def test_dependency_names_are_normalised_per_pep_503(tmp_path: Path, spelling: str) -> None:
    _tree(
        tmp_path,
        {
            "pyproject.toml": f'[project]\nname = "x"\ndependencies = ["{spelling}>=0.1"]\n',
            "runtime/pyproject.toml": '[project]\nname = "direwolf"\ndependencies = []\n',
            "tools/dwcheck/pyproject.toml": '[project]\nname = "dwcheck"\ndependencies = []\n',
        },
    )
    findings = check_python_dependencies(_config(tmp_path))
    assert any(f.rule.startswith("DEP001") for f in findings)


def test_a_manifest_named_by_a_rule_but_absent_is_a_finding(tmp_path: Path) -> None:
    """Otherwise deleting a manifest silently deletes the rule that guards it."""
    _tree(tmp_path, {"pyproject.toml": '[project]\nname = "x"\ndependencies = []\n'})
    findings = check_python_dependencies(_config(tmp_path))
    assert any("does not exist" in f.message for f in findings)


# --- the TCB closure and the shared wire crate ---------------------------------

_WORKSPACE = """
[workspace]
members = ["crates/dwkd-authority", "crates/dwkd-broker", "crates/dwk-proto"]
"""
_DAEMONS = {
    "crates/dwkd-authority/Cargo.toml": '[package]\nname = "dwkd-authority"\n',
    "crates/dwkd-broker/Cargo.toml": '[package]\nname = "dwkd-broker"\n',
}
_LOCK = """
version = 4
[[package]]
name = "dwkd-authority"
version = "0.0.0"
[[package]]
name = "dwkd-broker"
version = "0.0.0"
[[package]]
name = "dwk-proto"
version = "0.0.0"
dependencies = ["serde_json", "unicode-normalization"]
[[package]]
name = "serde_json"
version = "1.0.0"
dependencies = ["itoa"]
[[package]]
name = "itoa"
version = "1.0.0"
[[package]]
name = "unicode-normalization"
version = "0.1.25"
dependencies = ["tinyvec"]
[[package]]
name = "tinyvec"
version = "1.0.0"
dependencies = ["tinyvec_macros"]
[[package]]
name = "tinyvec_macros"
version = "0.1.0"
"""


def _proto_tree(root: Path, section: str) -> ArchitectureConfig:
    """dwk-proto links unicode-normalization and declares serde_json in ``section``."""
    extra = "" if section == "dependencies" else f"\n[{section}]\n"
    manifest = (
        '[package]\nname = "dwk-proto"\n\n[dependencies]\n'
        "unicode-normalization = { workspace = true }\n"
        f"{extra}serde_json = {{ workspace = true }}\n"
    )
    _tree(
        root,
        {
            "Cargo.toml": _WORKSPACE,
            "Cargo.lock": _LOCK,
            **_DAEMONS,
            "crates/dwk-proto/Cargo.toml": manifest,
        },
    )
    return _config(root)


def test_a_dev_dependency_is_outside_the_tcb_closure(tmp_path: Path) -> None:
    """proptest and serde_json test dwk-proto; they are never linked into it."""
    config = _proto_tree(tmp_path, "dev-dependencies")
    assert not [f for f in check_crates(config) if f.rule.startswith("RS004")]
    assert not check_lockfile_closure(config)


def test_the_same_crate_as_a_normal_dependency_is_inside_it(tmp_path: Path) -> None:
    """The exclusion must be exactly dev-dependencies, not "whatever is noisy"."""
    config = _proto_tree(tmp_path, "dependencies")
    assert any(
        "serde_json" in f.message for f in check_crates(config) if f.rule.startswith("RS004")
    )
    closure = {f.message.split("`")[1] for f in check_lockfile_closure(config)}
    assert closure == {"serde_json", "itoa"}


def test_a_build_dependency_is_inside_it(tmp_path: Path) -> None:
    """A build script runs on the build machine and can write the crate's code."""
    config = _proto_tree(tmp_path, "build-dependencies")
    assert any(
        "serde_json" in f.message for f in check_crates(config) if f.rule.startswith("RS004")
    )
    assert check_lockfile_closure(config)


def test_a_renamed_dependency_is_checked_under_its_real_name(tmp_path: Path) -> None:
    config = _proto_tree(tmp_path, "dev-dependencies")
    manifest = tmp_path / "crates/dwk-proto/Cargo.toml"
    manifest.write_text(
        '[package]\nname = "dwk-proto"\n[dependencies]\n'
        'unicode = { workspace = true, package = "hyper" }\n',
        encoding="utf-8",
    )
    assert any("`hyper`" in f.message for f in check_crates(config) if f.rule.startswith("RS004"))


def test_only_the_named_shared_crate_may_be_linked_by_both_daemons(tmp_path: Path) -> None:
    _tree(
        tmp_path,
        {
            "Cargo.toml": '[workspace]\nmembers = ["crates/dwkd-authority", "crates/dwkd-broker", '
            '"crates/dwk-proto", "crates/dwk-util"]\n',
            "crates/dwk-proto/Cargo.toml": '[package]\nname = "dwk-proto"\n',
            "crates/dwk-util/Cargo.toml": '[package]\nname = "dwk-util"\n',
            "crates/dwkd-authority/Cargo.toml": '[package]\nname = "dwkd-authority"\n'
            '[dependencies]\ndwk-proto = { path = "../dwk-proto" }\n'
            'dwk-util = { path = "../dwk-util" }\n',
            "crates/dwkd-broker/Cargo.toml": '[package]\nname = "dwkd-broker"\n'
            '[dependencies]\ndwk-proto = { path = "../dwk-proto" }\n'
            '[dev-dependencies]\ndwk-util = { path = "../dwk-util" }\n',
        },
    )
    shared = [f for f in check_crates(_config(tmp_path)) if f.rule.startswith("RS008")]
    assert not shared, "a dev-dependency does not put code in the broker"
    broker = tmp_path / "crates/dwkd-broker/Cargo.toml"
    broker.write_text(broker.read_text().replace("[dev-dependencies]\n", ""), encoding="utf-8")
    shared = [f for f in check_crates(_config(tmp_path)) if f.rule.startswith("RS008")]
    assert [f.path for f in shared] == ["crates/dwk-util/Cargo.toml"]


def test_proto_source_rule_skips_comments_and_reads_only_rust(tmp_path: Path) -> None:
    _tree(
        tmp_path,
        {
            "crates/dwk-proto/src/lib.rs": """
            //! Never uses std::fs or std::process.
            // use std::net::TcpStream;
            #![forbid(unsafe_code)]
            pub fn f() {}
            """,
            "crates/dwk-proto/src/notes.py": "import std::net\n",
        },
    )
    assert not [f for f in check_text(_config(tmp_path)) if f.rule.startswith("TX002")]


@pytest.mark.parametrize(
    "line",
    [
        "use std::fs::File;",
        "    let _ = std :: process::Command::new(x);",
        "use std::{io, net};",
        "fn f() { unsafe { g() } }",
        "#![allow(unsafe_code)]",
        "let v = std::env::var(k);",
        "use std::os::unix::net::UnixStream;",
    ],
)
def test_proto_source_rule_fires(tmp_path: Path, line: str) -> None:
    _tree(tmp_path, {"crates/dwk-proto/src/wire/x.rs": line + "\n"})
    assert [f.rule for f in check_text(_config(tmp_path))] == ["TX002-proto-has-no-ambient-effects"]


# --- links -----------------------------------------------------------------


def test_a_link_inside_a_fenced_block_is_not_checked(tmp_path: Path) -> None:
    """Mermaid and shell transcripts contain bracket-paren shapes that are not
    links. Flagging them produces noise, and noise gets checks disabled."""
    (tmp_path / "docs" / "adr").mkdir(parents=True)
    _tree(
        tmp_path,
        {
            "a.md": """
            ```mermaid
            flowchart LR
              A["node"] --> B["other(node)"]
            ```
            """
        },
    )
    assert not check_links(tmp_path)


def test_a_broken_relative_link_is_detected(tmp_path: Path) -> None:
    (tmp_path / "docs" / "adr").mkdir(parents=True)
    _tree(tmp_path, {"a.md": "See [the thing](./missing.md).\n"})
    assert any(f.rule == "DOC001-broken-relative-link" for f in check_links(tmp_path))


def test_an_external_url_is_not_fetched_or_flagged(tmp_path: Path) -> None:
    (tmp_path / "docs" / "adr").mkdir(parents=True)
    _tree(tmp_path, {"a.md": "See [rustsec](https://rustsec.org/advisories/).\n"})
    assert not check_links(tmp_path)


def test_a_citation_of_a_nonexistent_adr_is_detected(tmp_path: Path) -> None:
    (tmp_path / "docs" / "adr").mkdir(parents=True)
    _tree(tmp_path, {"a.md": "As decided in ADR-4242.\n"})
    assert any(f.rule == "DOC002-missing-adr" for f in check_links(tmp_path))


def test_exempt_paths_are_not_link_checked(tmp_path: Path) -> None:
    (tmp_path / "docs" / "adr").mkdir(parents=True)
    _tree(tmp_path, {"fixtures/a.md": "A [dead link](./nope.md).\n"})
    assert not check_links(tmp_path, ("fixtures",))


# --- configuration ---------------------------------------------------------


def test_a_missing_rules_file_raises(tmp_path: Path) -> None:
    with pytest.raises(ConfigError):
        load(tmp_path, tmp_path / "absent.toml")


def test_a_text_rule_without_suffixes_raises(tmp_path: Path) -> None:
    """A text rule that reads no files reports success forever."""
    text = RULES.read_text(encoding="utf-8").replace('suffixes = [".rs"]', "suffixes = []")
    rules = tmp_path / "architecture.toml"
    rules.write_text(text, encoding="utf-8")
    with pytest.raises(ConfigError, match="suffixes"):
        load(tmp_path, rules)


def test_an_unknown_mirror_kind_raises(tmp_path: Path) -> None:
    rules = tmp_path / "architecture.toml"
    rules.write_text(
        'schema_version = 1\n[version]\nsource = "VERSION"\n'
        '[[version.mirrors]]\npath = "x"\nkind = "yaml"\nsection = ""\npattern = ""\n',
        encoding="utf-8",
    )
    with pytest.raises(ConfigError, match="kind"):
        load(tmp_path, rules)


# --- reporting -------------------------------------------------------------


def test_the_report_prints_the_reason_once_per_rule_not_once_per_finding() -> None:
    report = Report()
    reason = "because the boundary matters"
    for line in (1, 2, 3):
        report.add(Finding("a.py", line, "PY001-x", "nope", reason))
    rendered = report.render()
    assert rendered.count(reason) == 1
    assert rendered.count("a.py:") == 3


def test_an_empty_report_is_ok_and_renders_nothing() -> None:
    report = Report()
    assert report.ok
    assert report.render() == ""
