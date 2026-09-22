"""The exact feature-resolved authority closure, and its fail-closed behaviour.

The property under test is the one the M3c closeout exists to establish:

    AN OPTIONAL EDGE MAY BE EXCLUDED ONLY WHILE IT IS PROVABLY INACTIVE.

A static exclusion list describes the truth at the moment it is written. These
tests pin the part that keeps it true afterwards: activation is *computed* from
Cargo's resolved graph, so a change that turns an excluded edge on makes the
gate red without anyone editing `architecture.toml`.

Cases A-G of the closeout brief, each against a synthetic resolved graph. They
are synthetic on purpose -- a weak feature reference, a legacy implicit one, a
dev-only edge and an activation arriving through a transitive dependency are
all tedious to produce by building real crates, and the point is to cover the
activation rules rather than to re-test Cargo.

The live graph is asserted separately, in `tests/architecture/`, where the real
repository and a real `cargo metadata` are available.
"""

from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest

from dwcheck.checks_cargo import check_authority_closure_exact, closure_from_metadata
from dwcheck.config import ArchitectureConfig, OptionalEdge, load

#: A fragment of a `cargo metadata` document.
Doc = dict[str, Any]

RULES = Path(__file__).resolve().parents[3] / "architecture.toml"
REPO_ROOT = Path(__file__).resolve().parents[3]


def _package(
    name: str,
    *,
    deps: list[tuple[str, bool, str | None]] | None = None,
    features: dict[str, list[str]] | None = None,
    third_party: bool = True,
) -> Doc:
    """A `packages[]` entry. `deps` is (name, optional, kind)."""
    return {
        "id": f"{name}@0.0.0",
        "name": name,
        "source": "registry+https://github.com/rust-lang/crates.io-index" if third_party else None,
        "features": features or {},
        "dependencies": [
            {"name": dep, "optional": optional, "kind": kind}
            for dep, optional, kind in (deps or [])
        ],
    }


def _node(
    name: str,
    *,
    deps: list[tuple[str, str | None]] | None = None,
    features: list[str] | None = None,
) -> Doc:
    """A `resolve.nodes[]` entry. `deps` is (name, kind).

    Cargo lists an optional dependency here whether or not a feature enables
    it, which is the whole reason this module cannot simply walk `deps`.
    """
    return {
        "id": f"{name}@0.0.0",
        "features": features or [],
        "deps": [
            {"pkg": f"{dep}@0.0.0", "dep_kinds": [{"kind": kind, "target": None}]}
            for dep, kind in (deps or [])
        ],
    }


def _metadata(packages: list[Doc], nodes: list[Doc]) -> Doc:
    return {"packages": packages, "resolve": {"nodes": nodes}}


def _toml_like(*, serde_on: bool) -> Doc:
    """The real shape, small enough to read.

    `dwkd-authority` -> `toml` -> {`serde_spanned`, `toml_datetime`, `winnow`},
    where the first two declare an OPTIONAL `serde_core` behind their own
    `serde` feature, and `toml`'s `serde` feature is what turns it on.
    """
    toml_features = {
        "parse": ["dep:winnow"],
        "serde": ["dep:serde_core", "serde_spanned/serde", "toml_datetime/serde"],
    }
    active = ["parse", "serde"] if serde_on else ["parse"]
    child_active = ["alloc", "serde"] if serde_on else ["alloc"]
    return _metadata(
        packages=[
            _package("dwkd-authority", deps=[("toml", False, None)], third_party=False),
            _package(
                "toml",
                deps=[
                    ("serde_spanned", False, None),
                    ("toml_datetime", False, None),
                    ("winnow", True, None),
                    ("serde_core", True, None),
                ],
                features=toml_features,
            ),
            _package(
                "serde_spanned",
                deps=[("serde_core", True, None)],
                # `serde_core?/alloc` is WEAK: it does not activate the dep.
                features={"alloc": ["serde_core?/alloc"], "serde": ["dep:serde_core"]},
            ),
            _package(
                "toml_datetime",
                deps=[("serde_core", True, None)],
                features={"alloc": ["serde_core?/alloc"], "serde": ["dep:serde_core"]},
            ),
            _package("winnow"),
            _package(
                "serde_core",
                deps=[("serde_derive", True, None)],
                features={"derive": ["dep:serde_derive"]},
            ),
            _package("serde_derive", deps=[("syn", False, None)]),
            _package("syn"),
        ],
        nodes=[
            _node("dwkd-authority", deps=[("toml", None)]),
            _node(
                "toml",
                deps=[
                    ("serde_spanned", None),
                    ("toml_datetime", None),
                    ("winnow", None),
                    ("serde_core", None),
                ],
                features=active,
            ),
            _node("serde_spanned", deps=[("serde_core", None)], features=child_active),
            _node("toml_datetime", deps=[("serde_core", None)], features=child_active),
            _node("winnow"),
            _node("serde_core", deps=[("serde_derive", None)], features=[]),
            _node("serde_derive", deps=[("syn", None)]),
            _node("syn"),
        ],
    )


def _config(
    *,
    crates: tuple[str, ...] = ("dwkd-authority",),
    allowed: tuple[str, ...] = (),
    build: tuple[str, ...] = (),
    edges: tuple[OptionalEdge, ...] = (),
) -> ArchitectureConfig:
    """The repository's real config with the four authority fields replaced.

    Explicit rather than `**overrides`, so the fields a test varies are the
    fields the signature names -- and so mypy checks them.
    """
    return replace(
        load(REPO_ROOT, RULES),
        authority_crates=crates,
        authority_allowed_third_party=allowed,
        authority_allowed_build_third_party=build,
        authority_optional_edges=edges,
    )


# --- A / B: the exclusion self-invalidates ---------------------------------


def test_an_inactive_optional_edge_is_not_in_the_linked_closure() -> None:
    """Case A. `toml` with `parse` only: serde_core is optional and off.

    The weak `serde_core?/alloc` reference in `alloc` must not be read as an
    activation -- reading `?` the wrong way is exactly what would put five
    crates in the inventory that are not in the binary.
    """
    exact = closure_from_metadata(_toml_like(serde_on=False), ["dwkd-authority"])
    assert exact.linked == {"toml", "serde_spanned", "toml_datetime", "winnow"}
    assert "serde_core" not in exact.linked
    assert ("serde_spanned", "serde_core") in exact.inactive_optional
    assert ("toml_datetime", "serde_core") in exact.inactive_optional
    assert not any(child == "serde_core" for _, child in exact.active_optional)


def test_activating_the_edge_puts_it_and_its_own_closure_back_in() -> None:
    """Case B, and the acceptance test of the whole closeout.

    Nobody edited the exclusion list. The feature moved, so the answer moved.
    """
    exact = closure_from_metadata(_toml_like(serde_on=True), ["dwkd-authority"])
    assert "serde_core" in exact.linked
    assert ("serde_spanned", "serde_core") in exact.active_optional
    assert ("toml_datetime", "serde_core") in exact.active_optional


def test_the_gate_turns_red_when_an_excluded_edge_becomes_active(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The same, through the finding-producing surface rather than the data.

    `architecture.toml` is untouched between the two halves: the exclusions
    are the repository's real ones and the allowlist is the repository's real
    allowlist. Only the resolved graph differs.
    """
    import dwcheck.checks_cargo as mod

    config = _config(
        allowed=("toml", "serde_spanned", "toml_datetime", "winnow"),
        edges=(
            OptionalEdge("serde_spanned", "serde_core", "not enabled"),
            OptionalEdge("toml_datetime", "serde_core", "not enabled"),
        ),
    )

    monkeypatch.setattr(mod, "_cargo_metadata", lambda _root: _toml_like(serde_on=False))
    assert check_authority_closure_exact(config) == [], "inactive: the gate is green"

    monkeypatch.setattr(mod, "_cargo_metadata", lambda _root: _toml_like(serde_on=True))
    findings = check_authority_closure_exact(config)
    rules = {f.rule for f in findings}
    assert "RS012-optional-edge-active" in rules, "the expired exclusion must be named"
    assert "RS010-authority-closure-exact" in rules, "the new crate must be named"
    named = {f.message.split("`")[1] for f in findings}
    assert "serde_core" in named, named
    # And `serde_derive` is NOT named, which is the checker being right rather
    # than lucky: in this graph `serde_core` arrives with no features, so its
    # own optional `derive` stays off. Activation is decided per package from
    # that package's activated features, not inherited from whatever pulled it
    # in. (On the real tree the derive stack DOES appear when toml's `serde`
    # feature is enabled, because something else activates `serde_core/derive`
    # -- a difference this model deliberately does not reproduce.)
    assert "serde_derive" not in named, named
    assert {("serde_spanned", "serde_core"), ("toml_datetime", "serde_core")} == {
        tuple(f.message.split("`")[1].split(" -> "))
        for f in findings
        if f.rule == "RS012-optional-edge-active"
    }


# --- C: an unlisted optional edge in the conservative closure ---------------


def test_the_offline_closure_still_counts_an_unreviewed_optional_edge() -> None:
    """Case C. The lockfile gate does not know about features, so it counts
    every recorded edge except the ones somebody reviewed. That is the
    conservative direction and it stays that way: the exact gate exists to
    stop the exclusions rotting, not to relax the offline one."""
    from dwcheck.checks_manifests import check_lockfile_closure

    config = load(REPO_ROOT, RULES)
    declared = {(e.parent, e.child) for e in config.authority_optional_edges}
    assert declared, "the repository declares exclusions for the offline gate"
    # An edge nobody declared is not excluded, so it would surface as RS006.
    assert ("toml", "serde_core") not in declared
    assert check_lockfile_closure(config) == [], "the real tree is clean"


# --- D / E: the allowlist must be exact, in both directions -----------------


def test_a_linked_crate_missing_from_the_allowlist_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """Case D."""
    import dwcheck.checks_cargo as mod

    monkeypatch.setattr(mod, "_cargo_metadata", lambda _root: _toml_like(serde_on=False))
    config = _config(allowed=("toml",))
    findings = check_authority_closure_exact(config)
    assert {f.rule for f in findings} == {"RS010-authority-closure-exact"}
    assert {f.message.split("`")[1] for f in findings} == {
        "serde_spanned",
        "toml_datetime",
        "winnow",
    }


def test_an_allowlist_entry_that_is_no_longer_linked_fails(monkeypatch: pytest.MonkeyPatch) -> None:
    """Case E. A stale entry is not harmless: it leaves the TCB inventory
    broader than the binary forever, which is how an allowlist stops being a
    review and becomes a list."""
    import dwcheck.checks_cargo as mod

    monkeypatch.setattr(mod, "_cargo_metadata", lambda _root: _toml_like(serde_on=False))
    config = _config(
        allowed=("toml", "serde_spanned", "toml_datetime", "winnow", "rusqlite"),
    )
    findings = check_authority_closure_exact(config)
    assert [f.rule for f in findings] == ["RS011-authority-allowlist-stale"]
    assert "rusqlite" in findings[0].message


def test_an_exclusion_for_an_edge_that_does_not_exist_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An exclusion applying to nothing cannot be reviewed, so it is a finding
    of its own rather than a quiet no-op."""
    import dwcheck.checks_cargo as mod

    monkeypatch.setattr(mod, "_cargo_metadata", lambda _root: _toml_like(serde_on=False))
    config = _config(
        allowed=("toml", "serde_spanned", "toml_datetime", "winnow"),
        edges=(OptionalEdge("winnow", "nonesuch", "invented"),),
    )
    findings = check_authority_closure_exact(config)
    assert [f.rule for f in findings] == ["RS013-optional-edge-absent"]


# --- F: activation arriving through a transitive dependency -----------------


def test_activation_through_a_transitive_dependency_is_detected() -> None:
    """Case F. Nothing in the authority's own manifest changed; a crate three
    levels down turned the feature on. The graph walk sees it because it reads
    each package's OWN activated features rather than the root's."""
    metadata = _metadata(
        packages=[
            _package("dwkd-authority", deps=[("mid", False, None)], third_party=False),
            _package("mid", deps=[("leaf", False, None)], features={"default": ["leaf/extra"]}),
            _package("leaf", deps=[("hidden", True, None)], features={"extra": ["dep:hidden"]}),
            _package("hidden"),
        ],
        nodes=[
            _node("dwkd-authority", deps=[("mid", None)]),
            _node("mid", deps=[("leaf", None)], features=["default"]),
            _node("leaf", deps=[("hidden", None)], features=["extra"]),
            _node("hidden"),
        ],
    )
    exact = closure_from_metadata(metadata, ["dwkd-authority"])
    assert exact.linked == {"mid", "leaf", "hidden"}
    assert ("leaf", "hidden") in exact.active_optional


def test_the_same_graph_without_the_transitive_activation_excludes_it() -> None:
    """The mirror, so the test above is not passing for an unrelated reason."""
    metadata = _metadata(
        packages=[
            _package("dwkd-authority", deps=[("mid", False, None)], third_party=False),
            _package("mid", deps=[("leaf", False, None)], features={"default": []}),
            _package("leaf", deps=[("hidden", True, None)], features={"extra": ["dep:hidden"]}),
            _package("hidden"),
        ],
        nodes=[
            _node("dwkd-authority", deps=[("mid", None)]),
            _node("mid", deps=[("leaf", None)], features=["default"]),
            _node("leaf", deps=[("hidden", None)], features=[]),
            _node("hidden"),
        ],
    )
    exact = closure_from_metadata(metadata, ["dwkd-authority"])
    assert exact.linked == {"mid", "leaf"}
    assert ("leaf", "hidden") in exact.inactive_optional


# --- G: dev-only must not be mistaken for a shipped dependency --------------


def test_a_dev_dependency_is_not_in_the_linked_closure() -> None:
    """Case G. `proptest` tests the authority; it is never linked into it."""
    metadata = _metadata(
        packages=[
            _package(
                "dwkd-authority",
                deps=[("toml", False, None), ("proptest", False, "dev")],
                third_party=False,
            ),
            _package("toml"),
            _package("proptest", deps=[("rand", False, None)]),
            _package("rand"),
        ],
        nodes=[
            _node("dwkd-authority", deps=[("toml", None), ("proptest", "dev")]),
            _node("toml"),
            _node("proptest", deps=[("rand", None)]),
            _node("rand"),
        ],
    )
    exact = closure_from_metadata(metadata, ["dwkd-authority"])
    assert exact.linked == {"toml"}
    assert "proptest" not in exact.linked and "rand" not in exact.linked


def test_a_build_dependency_is_reported_apart_from_what_is_linked() -> None:
    """A build script runs on the build machine and can write the crate's
    code, so it is inside the trust story -- and it is not in the shipped
    artifact, so conflating the two would flatter the inventory."""
    metadata = _metadata(
        packages=[
            _package("dwkd-authority", deps=[("toml", False, None)], third_party=False),
            _package("toml", deps=[("cc", False, "build")]),
            _package("cc"),
        ],
        nodes=[
            _node("dwkd-authority", deps=[("toml", None)]),
            _node("toml", deps=[("cc", "build")]),
            _node("cc"),
        ],
    )
    exact = closure_from_metadata(metadata, ["dwkd-authority"])
    assert exact.linked == {"toml"}
    assert exact.build_only == {"cc"}


# --- H: one dependency, declared twice (M3d) --------------------------------


def _rusqlite_like(*, wasm_feature_on: bool = False) -> Doc:
    """`rusqlite`'s real shape: `libsqlite3-sys` declared OPTIONAL for wasm and
    REQUIRED for every other target, and a build-only `cc` beneath it."""
    wasm = 'cfg(all(target_family = "wasm", target_os = "unknown"))'
    native = f"cfg(not({wasm[4:-1]}))"
    rusqlite = {
        "id": "rusqlite@0.0.0",
        "name": "rusqlite",
        "source": "registry+https://github.com/rust-lang/crates.io-index",
        "features": {"libsqlite3-sys": ["dep:libsqlite3-sys"], "bundled": []},
        "dependencies": [
            {"name": "libsqlite3-sys", "optional": True, "kind": None, "target": wasm},
            {"name": "libsqlite3-sys", "optional": False, "kind": None, "target": native},
        ],
    }
    sys_crate = _package(
        "libsqlite3-sys", deps=[("cc", True, "build")], features={"bundled": ["dep:cc"]}
    )
    sys_crate["links"] = "sqlite3"
    sys_crate["targets"] = [{"kind": ["lib"]}, {"kind": ["custom-build"]}]
    return _metadata(
        packages=[
            _package("dwkd-authority", deps=[("rusqlite", False, None)], third_party=False),
            rusqlite,
            sys_crate,
            _package("cc"),
        ],
        nodes=[
            _node("dwkd-authority", deps=[("rusqlite", None)]),
            {
                "id": "rusqlite@0.0.0",
                "features": ["bundled"] + (["libsqlite3-sys"] if wasm_feature_on else []),
                "deps": [
                    {
                        "pkg": "libsqlite3-sys@0.0.0",
                        "dep_kinds": [
                            {"kind": None, "target": native},
                            {"kind": None, "target": wasm},
                        ],
                    }
                ],
            },
            _node("libsqlite3-sys", deps=[("cc", "build")], features=["bundled"]),
            _node("cc"),
        ],
    )


def test_a_dependency_required_on_one_target_is_linked_whatever_its_optional_twin_says() -> None:
    """The M3c fail-open this closeout found by measurement.

    Optionality was decided by NAME, so `rusqlite`'s optional wasm declaration
    hid the required one and `libsqlite3-sys` -- the SQLite C -- fell out of the
    linked closure. Judged per declaration, it is linked.
    """
    exact = closure_from_metadata(_rusqlite_like(), ["dwkd-authority"])
    assert exact.linked == {"rusqlite", "libsqlite3-sys"}
    assert exact.build_only == {"cc"}
    assert exact.native == {"libsqlite3-sys"}
    assert exact.build_scripts == {"libsqlite3-sys"}


def test_an_edge_in_force_by_any_declaration_cannot_be_excluded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An exclusion naming `rusqlite -> libsqlite3-sys` would claim an edge the
    binary takes. It must expire (RS012), not be honoured."""
    import dwcheck.checks_cargo as mod

    exact = closure_from_metadata(_rusqlite_like(), ["dwkd-authority"])
    assert ("rusqlite", "libsqlite3-sys") in exact.active_optional
    assert ("rusqlite", "libsqlite3-sys") not in exact.inactive_optional

    monkeypatch.setattr(mod, "_cargo_metadata", lambda _root: _rusqlite_like())
    config = _config(
        allowed=("rusqlite", "libsqlite3-sys"),
        build=("cc",),
        edges=(OptionalEdge("rusqlite", "libsqlite3-sys", "wasm only"),),
    )
    assert [f.rule for f in check_authority_closure_exact(config)] == ["RS012-optional-edge-active"]


def test_a_build_only_crate_must_be_reviewed_in_its_own_list(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """RS014, RS015, and the rule against mixing the lists."""
    import dwcheck.checks_cargo as mod

    monkeypatch.setattr(mod, "_cargo_metadata", lambda _root: _rusqlite_like())
    runtime = ("rusqlite", "libsqlite3-sys")

    assert check_authority_closure_exact(_config(allowed=runtime, build=("cc",))) == []

    unreviewed = check_authority_closure_exact(_config(allowed=runtime))
    assert [f.rule for f in unreviewed] == ["RS014-authority-build-closure-exact"]
    assert "`cc`" in unreviewed[0].message

    stale = check_authority_closure_exact(_config(allowed=runtime, build=("cc", "bindgen")))
    assert [f.rule for f in stale] == ["RS015-authority-build-allowlist-stale"]

    # A build tool listed as linked overstates the binary: RS011 (stale runtime
    # entry) and RS014 (the build tool is still unreviewed as a build tool).
    mixed = check_authority_closure_exact(_config(allowed=(*runtime, "cc")))
    assert {f.rule for f in mixed} == {
        "RS011-authority-allowlist-stale",
        "RS014-authority-build-closure-exact",
    }

    # A linked crate listed as build-only is named for where it belongs.
    misfiled = check_authority_closure_exact(
        _config(allowed=("rusqlite",), build=("cc", "libsqlite3-sys"))
    )
    rules = {f.rule for f in misfiled}
    assert "RS010-authority-closure-exact" in rules
    assert any("belongs in allowed_third_party" in f.message for f in misfiled)


# --- the gate refuses to pass when it cannot run ---------------------------


def test_cargo_being_unavailable_is_a_finding_not_a_pass(monkeypatch: pytest.MonkeyPatch) -> None:
    """A gate that quietly passes when it cannot run is the fail-open shape
    this whole module exists to remove."""
    import dwcheck.checks_cargo as mod

    def unavailable(_root: Path) -> Doc:
        raise mod.CargoUnavailableError("cargo is not on PATH")

    monkeypatch.setattr(mod, "_cargo_metadata", unavailable)
    findings = check_authority_closure_exact(load(REPO_ROOT, RULES))
    assert [f.rule for f in findings] == ["RS010-authority-closure-exact"]
    assert "could not be computed" in findings[0].message


# --- the live graph --------------------------------------------------------


@pytest.mark.skipif(
    __import__("shutil").which("cargo") is None, reason="the exact gate needs cargo"
)
def test_the_real_repository_passes_the_exact_gate() -> None:
    """The live assertion. `make arch` runs the same check, so this is here to
    fail loudly in the unit suite too rather than only in the task runner."""
    assert check_authority_closure_exact(load(REPO_ROOT, RULES)) == []
