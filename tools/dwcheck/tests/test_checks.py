"""Unit tests for the checker's own logic.

``tests/architecture/`` proves the rules reject real violations. These tests
cover the edges where a checker is usually wrong: the false positive that gets
it switched off, and the false negative that makes it decorative.
"""

from __future__ import annotations

import shutil
import subprocess
import textwrap
from dataclasses import replace
from pathlib import Path

import pytest

from dwcheck import Finding, Report
from dwcheck.checks_adr import _digest, _load_manifest, check_adr, check_adr_history, record_adr
from dwcheck.checks_links import check_links
from dwcheck.checks_manifests import (
    check_crates,
    check_lockfile_closure,
    check_python_dependencies,
)
from dwcheck.checks_python import check_python_imports, check_text
from dwcheck.config import AdrException, ArchitectureConfig, ConfigError, load

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
dependencies = ["serde_json"]
[[package]]
name = "serde_json"
version = "1.0.0"
dependencies = ["itoa"]
[[package]]
name = "itoa"
version = "1.0.0"
"""


def _proto_tree(root: Path, section: str) -> ArchitectureConfig:
    """dwk-proto declares serde_json in ``section`` and nothing else.

    The authority allowlist is empty (ADR-0034), so any linked third-party
    crate is a finding and any dev-only one is not.
    """
    manifest = NEWLINE.join(
        [
            "[package]",
            'name = "dwk-proto"',
            "",
            f"[{section}]",
            "serde_json = { workspace = true }",
            "",
        ]
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


_OPTIONAL_LOCK = """
version = 4
[[package]]
name = "dwkd-authority"
version = "0.0.0"
dependencies = ["toml"]
[[package]]
name = "dwkd-broker"
version = "0.0.0"
[[package]]
name = "dwk-proto"
version = "0.0.0"
[[package]]
name = "toml"
version = "1.1.6"
dependencies = ["serde_spanned", "toml_datetime", "toml_parser", "winnow"]
[[package]]
name = "serde_spanned"
version = "1.1.1"
dependencies = ["serde_core"]
[[package]]
name = "toml_datetime"
version = "1.1.1"
dependencies = ["serde_core", "chrono"]
[[package]]
name = "toml_parser"
version = "1.1.3"
dependencies = ["winnow"]
[[package]]
name = "winnow"
version = "1.0.4"
[[package]]
name = "serde_core"
version = "1.0.229"
dependencies = ["serde_derive"]
[[package]]
name = "serde_derive"
version = "1.0.229"
dependencies = ["syn"]
[[package]]
name = "syn"
version = "3.0.5"
[[package]]
name = "chrono"
version = "0.4.0"
"""


def _optional_edge_tree(root: Path) -> ArchitectureConfig:
    """dwkd-authority links `toml`, whose lock entry records optional edges."""
    _tree(
        root,
        {
            "Cargo.toml": _WORKSPACE,
            "Cargo.lock": _OPTIONAL_LOCK,
            **_DAEMONS,
            "crates/dwkd-authority/Cargo.toml": NEWLINE.join(
                [
                    "[package]",
                    'name = "dwkd-authority"',
                    "",
                    "[dependencies]",
                    "toml = { workspace = true }",
                    "",
                ]
            ),
            "crates/dwk-proto/Cargo.toml": NEWLINE.join(["[package]", 'name = "dwk-proto"', ""]),
        },
    )
    return _config(root)


def test_a_reviewed_optional_edge_is_excluded_from_the_tcb_closure(tmp_path: Path) -> None:
    """Cargo.lock pins versions, not feature selections, so it records an
    optional dependency whether or not anything enables it.

    `serde_spanned -> serde_core` and `toml_datetime -> serde_core` are named
    in `[[authority.optional_edges]]` because the policy loader uses toml's
    `parse` feature and not its `serde` one. Without the exclusion the
    allowlist would have to claim serde_core, serde_derive and syn are in the
    trusted computing base, which `cargo tree --edges normal` says they are
    not.
    """
    findings = check_lockfile_closure(_optional_edge_tree(tmp_path))
    named = {f.message.split("`")[1] for f in findings}
    assert "serde_core" not in named, "a reviewed optional edge must not be followed"
    assert "serde_derive" not in named
    assert "syn" not in named


def test_an_unreviewed_optional_edge_is_still_a_finding(tmp_path: Path) -> None:
    """The exclusion is per EDGE, not per crate and not a wildcard.

    `toml_datetime -> chrono` is exactly as optional as the two edges beside
    it and is not named in architecture.toml, so it is still counted. That is
    what stops a feature change from quietly enlarging the TCB.
    """
    findings = check_lockfile_closure(_optional_edge_tree(tmp_path))
    named = {f.message.split("`")[1] for f in findings}
    assert "chrono" in named, "an optional edge nobody reviewed must still count"


def test_the_reviewed_edges_match_the_crates_they_name(tmp_path: Path) -> None:
    """An exclusion for an edge that does not exist is a stale exclusion, and a
    stale exclusion is a review nobody can check."""
    config = _config(tmp_path)
    assert config.authority_optional_edges, "the repository declares some"
    for edge in config.authority_optional_edges:
        assert edge.parent and edge.child
        assert edge.reason.strip(), f"{edge.parent} -> {edge.child} must say why"


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


# --- accepted ADRs are immutable -------------------------------------------

NEWLINE = chr(10)
CRLF = chr(13) + chr(10)


def _adr_tree(root: Path, body: str, *, status: str = "Accepted") -> ArchitectureConfig:
    text = NEWLINE.join(
        [
            "# ADR-0001: a decision",
            "",
            f"**Status:** {status} · **Date:** 2026-01-01",
            "",
            body,
            "",
        ]
    )
    _tree(root, {"docs/adr/0001-a-decision.md": text})
    return _config(root)


def test_recording_then_checking_passes(tmp_path: Path) -> None:
    config = _adr_tree(tmp_path, "The original text.")
    record_adr(config)
    assert check_adr(config) == []


def test_an_edited_accepted_adr_is_detected(tmp_path: Path) -> None:
    config = _adr_tree(tmp_path, "The original text.")
    record_adr(config)
    adr = tmp_path / "docs/adr/0001-a-decision.md"
    appended = NEWLINE.join(["", "## Notes", "", "Appended later.", ""])
    adr.write_text(adr.read_text(encoding="utf-8") + appended, encoding="utf-8")
    findings = check_adr(config)
    assert [f.rule for f in findings] == ["ADR001-accepted-adr-modified"]


def test_a_superseded_adr_is_immutable_too(tmp_path: Path) -> None:
    """Superseded records carry the emphasis markers the real ones use, and they
    are history: editing one rewrites what a reader is told was tried."""
    config = _adr_tree(tmp_path, "Old text.", status="**Superseded by [ADR-0019](0019-x.md)**")
    record_adr(config)
    assert len(_load_manifest(tmp_path / "docs/adr/accepted.sha256")) == 1
    adr = tmp_path / "docs/adr/0001-a-decision.md"
    adr.write_text(
        adr.read_text(encoding="utf-8").replace("Old text.", "New text."), encoding="utf-8"
    )
    assert [f.rule for f in check_adr(config)] == ["ADR001-accepted-adr-modified"]


def test_a_proposed_adr_may_still_change(tmp_path: Path) -> None:
    """Immutability starts at acceptance, not at creation."""
    config = _adr_tree(tmp_path, "Draft.", status="Proposed")
    record_adr(config)
    adr = tmp_path / "docs/adr/0001-a-decision.md"
    adr.write_text(
        adr.read_text(encoding="utf-8").replace("Draft.", "Second draft."), encoding="utf-8"
    )
    assert check_adr(config) == []


def test_line_endings_do_not_change_a_digest(tmp_path: Path) -> None:
    """A Windows checkout and a Linux one must agree; .gitattributes says LF,
    and a checkout that ignores it must not fail the gate."""
    config = _adr_tree(tmp_path, "Text.")
    adr = tmp_path / "docs/adr/0001-a-decision.md"
    lf = adr.read_bytes().replace(CRLF.encode(), NEWLINE.encode())
    adr.write_bytes(lf)
    record_adr(config)
    adr.write_bytes(lf.replace(NEWLINE.encode(), CRLF.encode()))
    assert check_adr(config) == []


def test_a_missing_manifest_is_a_finding_not_a_pass(tmp_path: Path) -> None:
    config = _adr_tree(tmp_path, "Text.")
    assert [f.rule for f in check_adr(config)] == ["ADR002-adr-not-recorded"]


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


# --- the ADR history anchor -------------------------------------------------
#
# The manifest above is a tripwire: whoever edits an accepted ADR can also run
# `dwcheck adr --record`, and the pair passes. These tests are about the anchor
# that the change cannot move -- the revision in which the ADR became Accepted.

HAS_GIT = shutil.which("git") is not None
needs_git = pytest.mark.skipif(not HAS_GIT, reason="the history anchor needs git")


def _git(root: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        capture_output=True,
    )


def _repo(root: Path) -> None:
    _git(root, "init", "-q", "-b", "main")
    _git(root, "config", "user.email", "test@example.invalid")
    _git(root, "config", "user.name", "dwcheck tests")
    _git(root, "config", "commit.gpgsign", "false")


def _commit(root: Path, message: str) -> None:
    _git(root, "add", "-A")
    _git(root, "commit", "-q", "-m", message)


def _adr_text(body: str, *, status: str = "Accepted", title: str = "ADR-0001: a decision") -> str:
    return NEWLINE.join(
        [f"# {title}", "", f"**Status:** {status} · **Date:** 2026-01-01", "", body, ""]
    )


def _history_config(
    root: Path, history_exceptions: tuple[AdrException, ...] = ()
) -> ArchitectureConfig:
    """The real rules, with this repository's own exceptions replaced.

    ``architecture.toml`` carries a live ``[[adr.history_exceptions]]`` entry;
    left in, it would authorise nothing in a fixture tree and every test here
    would trip ADR006 on it.
    """
    config = _config(root)
    return replace(config, adr=replace(config.adr, history_exceptions=history_exceptions))


def _accepted_repo(tmp_path: Path, body: str = "The original text.") -> ArchitectureConfig:
    _repo(tmp_path)
    _tree(tmp_path, {"docs/adr/0001-a-decision.md": _adr_text(body)})
    config = _history_config(tmp_path)
    record_adr(config)
    _commit(tmp_path, "accept ADR-0001")
    return config


@needs_git
def test_editing_an_accepted_adr_and_its_manifest_together_is_still_caught(tmp_path: Path) -> None:
    """The attack the digest manifest cannot see.

    A contributor edits an accepted ADR *and* re-records its digest in the same
    change. Every file in the tree is then self-consistent and the tripwire is
    silent, so the gate has to be anchored somewhere the change does not reach.
    It is: the commit in which the ADR became Accepted.
    """
    config = _accepted_repo(tmp_path)
    adr = tmp_path / "docs/adr/0001-a-decision.md"
    adr.write_text(
        adr.read_text(encoding="utf-8").replace("The original text.", "A different decision."),
        encoding="utf-8",
    )
    record_adr(config)  # <- the step that defeats the tripwire

    assert check_adr(config) == [], "precondition: the manifest is self-consistent again"
    assert [f.rule for f in check_adr_history(config)] == [
        "ADR004-accepted-adr-altered-since-acceptance"
    ]


@needs_git
def test_an_unchanged_accepted_adr_passes(tmp_path: Path) -> None:
    config = _accepted_repo(tmp_path)
    assert check_adr_history(config) == []


@needs_git
def test_adding_a_new_adr_is_allowed(tmp_path: Path) -> None:
    """Immutability is about the record, not about the directory."""
    config = _accepted_repo(tmp_path)
    _tree(
        tmp_path,
        {"docs/adr/0002-another.md": _adr_text("New decision.", title="ADR-0002: another")},
    )
    record_adr(config)
    assert check_adr_history(config) == []
    assert check_adr(config) == []


@needs_git
def test_superseding_marks_the_status_line_and_is_allowed(tmp_path: Path) -> None:
    """A superseding ADR has to be able to banner-mark what it supersedes, so
    the status line is writable. The decision below it is not."""
    config = _accepted_repo(tmp_path)
    adr = tmp_path / "docs/adr/0001-a-decision.md"
    adr.write_text(
        adr.read_text(encoding="utf-8").replace(
            "**Status:** Accepted", "**Status:** **Superseded by [ADR-0002](0002-another.md)**"
        ),
        encoding="utf-8",
    )
    record_adr(config)
    assert check_adr_history(config) == []


@needs_git
def test_an_accepted_adr_cannot_be_unaccepted(tmp_path: Path) -> None:
    config = _accepted_repo(tmp_path)
    adr = tmp_path / "docs/adr/0001-a-decision.md"
    adr.write_text(
        adr.read_text(encoding="utf-8").replace("**Status:** Accepted", "**Status:** Proposed"),
        encoding="utf-8",
    )
    record_adr(config)
    assert [f.rule for f in check_adr_history(config)] == ["ADR005-accepted-adr-withdrawn"]


@needs_git
def test_an_accepted_adr_cannot_be_deleted(tmp_path: Path) -> None:
    config = _accepted_repo(tmp_path)
    (tmp_path / "docs/adr/0001-a-decision.md").unlink()
    record_adr(config)
    assert [f.rule for f in check_adr_history(config)] == ["ADR005-accepted-adr-withdrawn"]


@needs_git
def test_an_exception_authorises_exactly_one_content(tmp_path: Path) -> None:
    """The escape hatch corrects one record. It does not make the file mutable:
    a second edit needs a second, equally visible, authorisation."""
    _accepted_repo(tmp_path)
    adr = tmp_path / "docs/adr/0001-a-decision.md"
    adr.write_text(
        adr.read_text(encoding="utf-8").replace("The original text.", "The corrected text."),
        encoding="utf-8",
    )
    allowed = _history_config(
        tmp_path,
        history_exceptions=(AdrException("0001-a-decision.md", _digest(adr), "reviewed"),),
    )
    assert check_adr_history(allowed) == []

    adr.write_text(
        adr.read_text(encoding="utf-8").replace("The corrected text.", "Something else again."),
        encoding="utf-8",
    )
    assert [f.rule for f in check_adr_history(allowed)] == [
        "ADR004-accepted-adr-altered-since-acceptance"
    ]


@needs_git
def test_an_exception_that_authorises_nothing_is_a_finding(tmp_path: Path) -> None:
    """An override nobody removed reads as "this was reviewed" for ever."""
    config = _accepted_repo(tmp_path)
    stale = _history_config(
        tmp_path,
        history_exceptions=(AdrException("0001-a-decision.md", "0" * 64, "obsolete"),),
    )
    assert check_adr(config) == []
    assert [f.rule for f in check_adr_history(stale)] == ["ADR006-stale-adr-history-exception"]


@needs_git
def test_an_adr_accepted_later_is_anchored_to_that_revision_not_its_draft(tmp_path: Path) -> None:
    """Immutability starts at acceptance, so the draft's text is not the anchor."""
    _repo(tmp_path)
    _tree(tmp_path, {"docs/adr/0001-a-decision.md": _adr_text("Draft.", status="Proposed")})
    _commit(tmp_path, "propose ADR-0001")

    adr = tmp_path / "docs/adr/0001-a-decision.md"
    adr.write_text(_adr_text("The decision, as accepted."), encoding="utf-8")
    config = _history_config(tmp_path)
    record_adr(config)
    _commit(tmp_path, "accept ADR-0001")
    assert check_adr_history(config) == []

    adr.write_text(_adr_text("Rewritten after the fact."), encoding="utf-8")
    record_adr(config)
    assert [f.rule for f in check_adr_history(config)] == [
        "ADR004-accepted-adr-altered-since-acceptance"
    ]


def test_no_history_is_a_finding_only_when_the_caller_requires_one(tmp_path: Path) -> None:
    """A release tarball has no history and must still be checkable; CI has one
    and must not quietly fall back to the tripwire alone."""
    _tree(tmp_path, {"docs/adr/0001-a-decision.md": _adr_text("Text.")})
    config = _history_config(tmp_path)
    assert check_adr_history(config, require_history=False) == []
    assert [f.rule for f in check_adr_history(config, require_history=True)] == [
        "ADR007-adr-history-unavailable"
    ]


@needs_git
def test_a_base_revision_cannot_smuggle_a_git_option(tmp_path: Path) -> None:
    """`--adr-base` reaches git as an argument; it must never reach it as a flag."""
    config = _accepted_repo(tmp_path)
    assert [f.rule for f in check_adr_history(config, "--upload-pack=touched")] == [
        "ADR007-adr-history-unavailable"
    ]
