"""The EXACT, feature-resolved authority dependency closure.

`checks_manifests.check_lockfile_closure` (RS006) reads `Cargo.lock`. That is
deliberate -- it runs with no toolchain, no network and no registry index, so
it runs on every contributor's machine -- and it has a limit that only became
load-bearing at M3c:

    Cargo.lock pins VERSIONS, not FEATURE SELECTIONS.

A lockfile entry lists a package's dependencies whether or not any feature
activates them. `serde_spanned` declares `serde_core` as `optional = true`
behind its own `serde` feature; DireWolf links `toml` with `features =
["parse"]`, so that feature is off and `serde_core` is not in the binary. The
lockfile says otherwise.

M3c's first answer was a reviewed exclusion list, `[[authority.optional_edges]]`.
That describes the truth *at the moment it is written* and keeps describing it
afterwards, which is a fail-open gate: a later change that turns the `serde`
feature on would leave the exclusion in place and the crate silently outside
the trusted-computing-base inventory.

This module is the fix. It computes activation rather than being told it, from
Cargo's own resolved graph, and it is what makes an exclusion self-invalidating:
an edge that becomes active is a finding no matter what the exclusion list says.

# Why `cargo metadata`'s `deps` is not the answer on its own

`resolve.nodes[].deps` over-approximates in exactly the way the lockfile does:
it lists an optional dependency whether or not a feature enables it. Confirmed
by building `dwkd-authority` alone into an empty target directory, which
produces five third-party rlibs and no `serde_core`, while metadata's `deps`
lists six.

What metadata *does* give, and what this module uses, is
`resolve.nodes[].features` -- the features actually activated for that package
in this resolution -- plus `packages[].features`, the feature table. Expanding
one through the other yields the set of `dep:NAME` activations, and an optional
dependency is active exactly when its activation appears there.

# Optionality belongs to a DECLARATION, not to a name (M3d)

A package may declare the same dependency more than once: `rusqlite` declares
`libsqlite3-sys` as *optional* for `wasm32-unknown-unknown` and as *required*
for every other target. M3c's first version decided optionality by name, so the
optional wasm declaration hid the required one, the edge was dropped, and
`libsqlite3-sys` -- 269,376 lines of C -- vanished from the linked closure. A
gate that loses the largest crate in the TCB is the fail-open this module
exists to prevent, and it was found by measuring rather than by review.

So an edge is now judged per `dep_kinds` entry, against the declaration with
the same package, kind and target: active if that declaration is required, or
optional and activated. An edge whose declaration cannot be found is treated as
ACTIVE -- an unexplained edge is counted, never dropped.

Target conditions are not evaluated. The closure is the UNION over every target
Cargo resolved, which over-approximates for any one platform (`libc` enters
through `cpufeatures` on aarch64 and loongarch64 only) and never
under-approximates for a supported one. An allowlist that must hold on Linux,
macOS and Windows alike has to be the union.

# Build-only crates are reviewed too

Crates reachable only through build edges are not in the binary, but they
EXECUTE while the TCB is built: `cc` drives the C compiler over the SQLite
amalgamation. They are reviewed in their own allowlist
(`[authority].allowed_build_third_party`, RS014/RS015) and never mixed into the
runtime list -- listing a build tool as linked would overstate the binary, and
leaving it unlisted would hide code that runs with the builder's privileges.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from dwcheck import Finding
from dwcheck.config import ArchitectureConfig

#: A `cargo metadata --format-version 1` document. Deliberately loose: this
#: module reads four keys out of it and has no business asserting a shape for
#: the rest, which Cargo is free to extend.
Metadata = dict[str, Any]

__all__ = [
    "CargoUnavailableError",
    "ExactClosure",
    "check_authority_closure_exact",
    "closure_from_metadata",
    "render_closure",
    "resolve_exact_closure",
]

_REASON = (
    "The authority's trusted computing base is what the binary LINKS, which is not the "
    "same set as what Cargo.lock records: a lockfile pins versions, not feature "
    "selections, so it lists optional dependencies nothing activates. This gate "
    "computes activation from Cargo's resolved graph, so an allowlist cannot drift "
    "away from reality and an exclusion cannot outlive the fact that justified it."
)

_BUILD_REASON = (
    "Build-only dependencies are not linked into the authority, but they execute on the "
    "machine that builds it -- `cc` compiles the bundled SQLite amalgamation. They are "
    "reviewed in their own list so that 'runs during the build' is visible without "
    "overstating what the binary contains."
)


class CargoUnavailableError(RuntimeError):
    """Cargo could not produce a resolved graph.

    Raised rather than swallowed. A gate that quietly passes when it cannot run
    is the fail-open shape this module exists to remove, so the caller decides
    what to do and the decision is visible.
    """


@dataclass(frozen=True, slots=True)
class ExactClosure:
    """What the authority actually links, feature-resolved."""

    #: Third-party crates reachable through activated NORMAL dependency edges.
    linked: frozenset[str]
    #: Third-party crates reachable only through activated BUILD edges. These
    #: run on the build machine and are not in the shipped artifact; they are
    #: reported apart because "executes during the build" and "is in the binary"
    #: are different risks and conflating them flatters the inventory.
    build_only: frozenset[str]
    #: Optional edges (parent, child) that ARE activated in this resolution.
    #: An exclusion naming one of these has expired.
    active_optional: frozenset[tuple[str, str]]
    #: Optional edges present in the package graph but NOT activated.
    inactive_optional: frozenset[tuple[str, str]]
    #: Crates in either closure with a build script (a `custom-build` target):
    #: code that runs on the build machine, whatever the crate links.
    build_scripts: frozenset[str] = frozenset()
    #: Linked crates declaring `links` -- a native library. SQLite's C lives
    #: behind one of these, and `forbid(unsafe_code)` does not reach it.
    native: frozenset[str] = frozenset()


def _cargo_metadata(root: Path) -> Metadata:
    """Cargo's resolved graph for the workspace at ``root``."""
    if shutil.which("cargo") is None:
        raise CargoUnavailableError("cargo is not on PATH")
    try:
        # No `--all-features` and no `--features`: the resolution has to be the
        # one the build uses, which is the workspace members' own feature
        # selection. Asking for all features would report a graph nobody
        # builds, and would put crates in the inventory that are not linked.
        completed = subprocess.run(
            ["cargo", "metadata", "--locked", "--format-version", "1"],
            cwd=root,
            capture_output=True,
            text=True,
            check=False,
            timeout=300,
        )
    except OSError as exc:  # pragma: no cover - depends on the host
        raise CargoUnavailableError(f"cargo could not be run: {exc}") from exc
    except subprocess.TimeoutExpired as exc:  # pragma: no cover
        raise CargoUnavailableError("cargo metadata timed out") from exc
    if completed.returncode != 0:
        raise CargoUnavailableError(
            f"cargo metadata failed ({completed.returncode}): {completed.stderr.strip()[:500]}"
        )
    try:
        parsed: Metadata = json.loads(completed.stdout)
    except json.JSONDecodeError as exc:  # pragma: no cover
        raise CargoUnavailableError(f"cargo metadata produced no JSON: {exc}") from exc
    return parsed


def _activated_dep_names(feature_table: dict[str, list[str]], activated: Iterable[str]) -> set[str]:
    """Which optional dependencies the activated features turn on.

    Expands the feature table transitively and collects every activation of the
    form ``dep:NAME``, plus the legacy form where a feature's *name* is an
    optional dependency's name.

    The distinction that matters is the weak one. ``serde_core?/alloc`` enables
    a feature of ``serde_core`` **if something else already enabled it**, and
    enables the dependency itself never. ``dep:serde_core`` and plain
    ``serde_core`` do enable it. Reading `?` as an activation is precisely the
    mistake that would put five crates in the inventory that are not in the
    binary.
    """
    seen: set[str] = set()
    enabled: set[str] = set()
    stack = list(activated)
    while stack:
        feature = stack.pop()
        if feature in seen:
            continue
        seen.add(feature)
        # A feature whose name is an optional dependency enables it (pre-2021
        # implicit form). `dep:` names never appear in `resolve.nodes.features`.
        enabled.add(feature)
        for entry in feature_table.get(feature, []):
            if entry.startswith("dep:"):
                enabled.add(entry[len("dep:") :])
                continue
            if "?/" in entry:
                # Weak: does not activate the dependency. Ignore entirely.
                continue
            if "/" in entry:
                # `child/feature` activates `child` when `child` is an optional
                # dependency of this package (strong form).
                enabled.add(entry.split("/", 1)[0])
                continue
            stack.append(entry)
    return enabled


def resolve_exact_closure(config: ArchitectureConfig) -> ExactClosure:
    """Walk the activated dependency graph from the authority crates.

    # Errors

    :class:`CargoUnavailableError` when Cargo cannot produce a graph.
    """
    return closure_from_metadata(_cargo_metadata(config.root), config.authority_crates)


def closure_from_metadata(metadata: Metadata, authority_crates: Iterable[str]) -> ExactClosure:
    """The pure half: a resolved graph in, the activated closure out.

    Separated from the subprocess so the activation rules can be tested
    exhaustively offline, against graphs that would be tedious to produce by
    building real crates -- a weak feature reference, a legacy implicit one, a
    dev-only edge, an activation arriving through a transitive dependency, and
    one dependency declared twice with different optionality per target.
    """
    packages = {p["id"]: p for p in metadata.get("packages", [])}
    nodes = {n["id"]: n for n in metadata.get("resolve", {}).get("nodes", [])}
    in_tree = {p["name"] for p in packages.values() if p.get("source") is None}

    def name_of(package_id: str) -> str:
        package = packages.get(package_id)
        return str(package["name"]) if package else package_id

    # Which optional dependencies each package actually turns on, and every
    # declaration it makes: (package name, feature key, kind, target, optional).
    activated: dict[str, set[str]] = {}
    declarations: dict[str, list[tuple[str, str, str | None, str | None, bool]]] = {}
    for package_id, package in packages.items():
        table = {k: list(v) for k, v in (package.get("features") or {}).items()}
        node = nodes.get(package_id, {})
        activated[package_id] = _activated_dep_names(table, node.get("features") or [])
        declarations[package_id] = [
            (
                str(d["name"]),
                str(d.get("rename") or d["name"]),
                d.get("kind"),
                d.get("target"),
                bool(d.get("optional")),
            )
            for d in package.get("dependencies", [])
        ]

    def declaration_active(
        package_id: str, child: str, kind: str | None, target: str | None
    ) -> bool:
        """Whether the declaration behind one `dep_kinds` entry is in force.

        Unknown means active: an edge the resolver reports and the manifest does
        not explain is counted, never dropped.
        """
        matching = [
            (key, optional)
            for name, key, dkind, dtarget, optional in declarations.get(package_id, [])
            if name == child and dkind == kind and dtarget == target
        ]
        if not matching:
            return True
        return any(
            not optional or key in activated.get(package_id, set()) for key, optional in matching
        )

    def edges(package_id: str, kinds: set[str | None]) -> list[str]:
        """Activated dependency edges of the requested kinds."""
        out: list[str] = []
        for dep in nodes.get(package_id, {}).get("deps", []):
            child = name_of(dep["pkg"])
            if any(
                entry.get("kind") in kinds
                and declaration_active(package_id, child, entry.get("kind"), entry.get("target"))
                for entry in dep.get("dep_kinds", [])
            ):
                out.append(dep["pkg"])
        return out

    def closure(roots: list[str], kinds: set[str | None]) -> set[str]:
        seen: set[str] = set()
        stack = list(roots)
        while stack:
            current = stack.pop()
            if current in seen:
                continue
            seen.add(current)
            stack.extend(edges(current, kinds))
        return seen

    roots = [pid for pid, p in packages.items() if p["name"] in set(authority_crates)]
    # Normal edges only for `linked`; build edges reached from the linked set
    # are reported apart. `None` is cargo's spelling of a normal dependency.
    linked_ids = closure(roots, {None})
    build_ids: set[str] = set()
    for package_id in linked_ids:
        build_ids |= closure(edges(package_id, {"build"}), {None, "build"})

    linked = {name_of(i) for i in linked_ids} - in_tree
    build_only = {name_of(i) for i in build_ids} - in_tree - linked

    def has_build_script(package_id: str) -> bool:
        return any(
            "custom-build" in target.get("kind", [])
            for target in packages.get(package_id, {}).get("targets", [])
        )

    build_scripts = {name_of(i) for i in linked_ids | build_ids if has_build_script(i)} - in_tree
    native = {name_of(i) for i in linked_ids if packages.get(i, {}).get("links")} - in_tree

    # Every (parent, child) pair with an optional declaration, split by
    # whether the EDGE is in force -- by that declaration being activated, or by
    # any other declaration of the same child being required. `rusqlite` ->
    # `libsqlite3-sys` is optional for wasm and required everywhere else, so it
    # is active: an exclusion naming it would claim an edge the binary takes.
    active: set[tuple[str, str]] = set()
    inactive: set[tuple[str, str]] = set()
    for package_id, package in packages.items():
        parent = str(package["name"])
        by_child: dict[str, list[tuple[str, bool]]] = {}
        for name, key, _kind, _target, optional in declarations.get(package_id, []):
            by_child.setdefault(name, []).append((key, optional))
        for child, entries in by_child.items():
            if not any(optional for _, optional in entries):
                continue
            in_force = any(
                not optional or key in activated.get(package_id, set()) for key, optional in entries
            )
            (active if in_force else inactive).add((parent, child))

    return ExactClosure(
        linked=frozenset(linked),
        build_only=frozenset(build_only),
        active_optional=frozenset(active),
        inactive_optional=frozenset(inactive),
        build_scripts=frozenset(build_scripts),
        native=frozenset(native),
    )


def check_authority_closure_exact(config: ArchitectureConfig) -> list[Finding]:
    """Assert the reviewed allowlist is exactly what the authority links.

    Four separate findings, because they are four different mistakes:

    * **RS010** a crate is linked and not reviewed -- the TCB grew;
    * **RS011** a crate is reviewed and not linked -- the inventory is stale and
      overstates the TCB, which is how an allowlist stops being a review;
    * **RS012** an exclusion in `[[authority.optional_edges]]` names an edge
      that is now ACTIVE -- the fact that justified the exclusion has expired;
    * **RS013** an exclusion names an edge that is not optional, or does not
      exist at all -- the exclusion never applied to anything.
    """
    try:
        exact = resolve_exact_closure(config)
    except CargoUnavailableError as exc:
        return [
            Finding(
                path="Cargo.toml",
                line=0,
                rule="RS010-authority-closure-exact",
                message=(
                    f"the feature-resolved authority closure could not be computed: {exc}. "
                    f"This gate needs Cargo; the offline RS006 tripwire does not, and is "
                    f"weaker."
                ),
                reason=_REASON,
            )
        ]

    allowed = set(config.authority_allowed_third_party)
    findings: list[Finding] = []

    for crate in sorted(exact.linked - allowed):
        findings.append(
            Finding(
                path="architecture.toml",
                line=0,
                rule="RS010-authority-closure-exact",
                message=(
                    f"`{crate}` is LINKED into the authority but is not in "
                    f"[authority].allowed_third_party"
                ),
                reason=_REASON,
            )
        )
    for crate in sorted(allowed - exact.linked):
        findings.append(
            Finding(
                path="architecture.toml",
                line=0,
                rule="RS011-authority-allowlist-stale",
                message=(
                    f"`{crate}` is in [authority].allowed_third_party but is not linked into "
                    f"the authority; remove it, or the inventory overstates the TCB"
                ),
                reason=_REASON,
            )
        )

    allowed_build = set(config.authority_allowed_build_third_party)
    for crate in sorted(exact.build_only - allowed_build):
        findings.append(
            Finding(
                path="architecture.toml",
                line=0,
                rule="RS014-authority-build-closure-exact",
                message=(
                    f"`{crate}` EXECUTES while the authority is built (a build-only "
                    f"dependency) but is not in [authority].allowed_build_third_party"
                ),
                reason=_BUILD_REASON,
            )
        )
    for crate in sorted(allowed_build - exact.build_only):
        where = (
            "it is LINKED, so it belongs in allowed_third_party"
            if crate in exact.linked
            else "remove it"
        )
        findings.append(
            Finding(
                path="architecture.toml",
                line=0,
                rule="RS015-authority-build-allowlist-stale",
                message=(
                    f"`{crate}` is in [authority].allowed_build_third_party but is not a "
                    f"build-only dependency of the authority; {where}"
                ),
                reason=_BUILD_REASON,
            )
        )

    declared = {(e.parent, e.child) for e in config.authority_optional_edges}
    for parent, child in sorted(declared & exact.active_optional):
        findings.append(
            Finding(
                path="architecture.toml",
                line=0,
                rule="RS012-optional-edge-active",
                message=(
                    f"`{parent} -> {child}` is excluded from the offline closure as an "
                    f"inactive optional edge, but a feature now ACTIVATES it; the exclusion "
                    f"has expired and `{child}` is in the authority's linked closure"
                ),
                reason=_REASON,
            )
        )
    for parent, child in sorted(declared - exact.active_optional - exact.inactive_optional):
        findings.append(
            Finding(
                path="architecture.toml",
                line=0,
                rule="RS013-optional-edge-absent",
                message=(
                    f"`{parent} -> {child}` is excluded as an optional edge, but no such "
                    f"optional dependency exists in the resolved graph; the exclusion "
                    f"applies to nothing and cannot be reviewed"
                ),
                reason=_REASON,
            )
        )
    return findings


def render_closure(config: ArchitectureConfig) -> str:
    """The measured closure, for an evidence report.

    # Errors

    :class:`CargoUnavailableError` when Cargo cannot produce a graph.
    """
    exact = resolve_exact_closure(config)

    def line(label: str, crates: frozenset[str]) -> str:
        return f"{label:<28}{len(crates):>3}  {', '.join(sorted(crates)) or '-'}"

    edges = frozenset(f"{parent}->{child}" for parent, child in exact.inactive_optional)
    return "\n".join(
        [
            line("linked (runtime)", exact.linked),
            line("build-only (executes)", exact.build_only),
            line("with a build script", exact.build_scripts),
            line("native (`links`)", exact.native),
            line("optional edges, inactive", edges),
        ]
    )
