"""Manifest checks: declared Python dependencies and the Rust crate graph.

Two separate questions, both answered from manifests rather than from a
resolved lockfile:

* Python -- is a banned distribution declared anywhere it could reach a lock?
* Rust   -- does the crate dependency graph respect the authority/broker/CLI
  direction, and does the TCB's dependency set match what ADR-0019 claims?

Checking the manifest catches the mistake at the moment someone makes it,
which is when they still remember why.
"""

from __future__ import annotations

import re
import tomllib
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from dwcheck import Finding
from dwcheck.config import ArchitectureConfig

__all__ = ["check_crates", "check_lockfile_closure", "check_python_dependencies"]

# PEP 508: name is everything before a version specifier, extra, marker or URL.
_REQUIREMENT_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def check_python_dependencies(config: ArchitectureConfig) -> list[Finding]:
    findings: list[Finding] = []
    for rule in config.dependency_rules:
        banned = {_normalise(b) for b in rule.banned}
        for manifest in rule.manifests:
            path = config.root / manifest
            if not path.is_file():
                findings.append(
                    Finding(
                        path=manifest,
                        line=0,
                        rule=rule.id,
                        message="manifest named by this rule does not exist",
                        reason=rule.reason,
                    )
                )
                continue
            data = _load_toml(path)
            for requirement in _declared_requirements(data):
                name = _requirement_name(requirement)
                if name and _normalise(name) in banned:
                    findings.append(
                        Finding(
                            path=manifest,
                            line=_line_of(path, requirement),
                            rule=rule.id,
                            message=f"forbidden dependency `{requirement}`",
                            reason=rule.reason,
                        )
                    )
    return findings


def check_crates(config: ArchitectureConfig) -> list[Finding]:
    findings: list[Finding] = []
    workspace_path = config.root / config.crates.manifest
    if not workspace_path.is_file():
        return [
            Finding(
                path=config.crates.manifest,
                line=0,
                rule="RS000-workspace",
                message="workspace manifest not found",
            )
        ]

    workspace = _load_toml(workspace_path)
    ws_table = workspace.get("workspace")
    members: list[str] = []
    if isinstance(ws_table, dict):
        raw_members = ws_table.get("members", [])
        if isinstance(raw_members, list):
            members = [m for m in raw_members if isinstance(m, str)]

    manifests: dict[str, tuple[str, dict[str, Any]]] = {}
    for member in members:
        manifest_path = config.root / member / "Cargo.toml"
        rel = f"{member}/Cargo.toml"
        if not manifest_path.is_file():
            findings.append(
                Finding(
                    path=config.crates.manifest,
                    line=0,
                    rule="RS000-workspace",
                    message=f"workspace member `{member}` has no Cargo.toml",
                )
            )
            continue
        data = _load_toml(manifest_path)
        package = data.get("package")
        name = package.get("name") if isinstance(package, dict) else None
        if isinstance(name, str):
            manifests[name] = (rel, data)

    findings.extend(_check_orphan_crates(config, members))

    in_tree = set(manifests)
    for crate_name, (rel, data) in sorted(manifests.items()):
        for rule in config.crate_rules:
            if rule.crate != crate_name:
                continue
            for dep, _ in _dependencies(data):
                if dep in rule.forbidden_dependencies:
                    findings.append(
                        Finding(
                            path=rel,
                            line=_line_of(config.root / rel, dep),
                            rule=rule.id,
                            message=f"`{crate_name}` must not depend on `{dep}`",
                            reason=rule.reason,
                        )
                    )

        for dep, _ in _dependencies(data):
            if dep in config.crates.undependable and dep != crate_name:
                findings.append(
                    Finding(
                        path=rel,
                        line=_line_of(config.root / rel, dep),
                        rule="RS007-authority-plane-is-undependable",
                        message=f"`{crate_name}` must not depend on `{dep}`",
                        reason=(
                            "Nothing in the workspace may link an authority-plane crate. The "
                            "named direction rules cover the crates that exist; this covers the "
                            "one added later to share a little code between authority and "
                            "broker, which is how the ADR-0018 boundary would actually be lost. "
                            "Shared code goes in a narrow dwk-* crate that neither daemon's "
                            "decisions depend on."
                        ),
                    )
                )

        if config.crates.require_workspace_dependencies:
            findings.extend(_check_inheritance(rel, config.root, data, in_tree))

        if crate_name in config.authority_crates:
            allowed = set(config.authority_allowed_third_party)
            for dep, _ in _dependencies(data, include_dev=False):
                if dep not in in_tree and dep not in allowed:
                    findings.append(
                        Finding(
                            path=rel,
                            line=_line_of(config.root / rel, dep),
                            rule="RS004-authority-dependency-allowlist",
                            message=(
                                f"`{dep}` is not in the authority dependency allowlist "
                                f"(architecture.toml [authority].allowed_third_party)"
                            ),
                            reason=(
                                "The dependency set of dwkd-authority, and of dwk-proto which "
                                "it links from M3, is a load-bearing claim of ADR-0019: no HTTP "
                                "client, no TLS stack, no container client, no content parsers. "
                                "Adding one needs a note on that ADR and a reviewer other than "
                                "the author. Dev-dependencies are not linked and not counted."
                            ),
                        )
                    )

    findings.extend(_check_shared_crates(config, manifests))
    return findings


def _check_shared_crates(
    config: ArchitectureConfig, manifests: dict[str, tuple[str, dict[str, Any]]]
) -> Iterator[Finding]:
    """RS008 and RS009: the one sanctioned kind of code shared by both daemons.

    Both daemons will link ``dwk-proto``: they must agree on the wire. That
    makes a shared crate the obvious place for the ADR-0018 boundary to erode
    -- first a helper, then a type with a method, then a decision. So a crate
    linked by both daemons must be named in ``[crates].shared``, and a named
    crate must be a leaf: it links no in-tree crate, so it cannot become the
    route by which one daemon's code reaches the other.
    """
    in_tree = set(manifests)
    edges = {
        name: [d for d, _ in _dependencies(data, include_dev=False) if d in in_tree]
        for name, (_, data) in manifests.items()
    }
    daemons = [d for d in config.crates.undependable if d in in_tree]
    if len(daemons) >= 2:
        reached = [_closure(d, edges) - set(daemons) for d in daemons]
        common = set.intersection(*reached)
        for crate in sorted(common - set(config.crates.shared)):
            yield Finding(
                path=manifests[crate][0],
                line=0,
                rule="RS008-shared-crate-allowlist",
                message=(
                    f"`{crate}` is linked by both {' and '.join(daemons)} but is not in "
                    f"[crates].shared"
                ),
                reason=(
                    "Code linked into both authority and broker is code both sides of the "
                    "ADR-0018 split execute. The only sanctioned case is the wire contract, "
                    "dwk-proto. Sharing anything else is an architecture decision that needs an "
                    "ADR, not a Cargo.toml edit."
                ),
            )
    for crate in config.crates.shared:
        if crate not in manifests:
            continue
        rel, data = manifests[crate]
        for dep, _ in _dependencies(data, include_dev=False):
            if dep in in_tree:
                yield Finding(
                    path=rel,
                    line=_line_of(config.root / rel, dep),
                    rule="RS009-shared-crate-is-a-leaf",
                    message=f"shared crate `{crate}` must not depend on in-tree crate `{dep}`",
                    reason=(
                        "A crate both daemons link must not link anything else from the tree. "
                        "Otherwise it is a bridge: whatever it depends on is inside both "
                        "processes, and that set grows without anyone deciding it should."
                    ),
                )


def check_lockfile_closure(config: ArchitectureConfig) -> list[Finding]:
    """Assert the TCB's *transitive* dependency closure, from Cargo.lock.

    ADR-0019's claim about `dwkd-authority` -- "a genuinely small, enforceable
    dependency set: no HTTP client, no TLS stack, no container client, no
    content parsers" -- is about everything that ends up linked, not only the
    crates named in its manifest. A direct dependency on one innocuous crate
    that pulls in `hyper` breaks the claim just as thoroughly.

    Read from the lockfile rather than from `cargo metadata` so the check runs
    with no toolchain, no network and no registry index -- which means it runs
    on every contributor's machine and in every CI job, not only where a
    supply-chain tool happens to be installed.

    The cost of reading the lockfile is that it pins versions, not feature
    selections, so it records optional dependencies nothing enables. Those
    edges are named one at a time in `[[authority.optional_edges]]`, each with
    a reason -- see `OptionalEdge`. Without that, the allowlist would have to
    claim five crates are in the trusted computing base that are not in the
    binary.
    """
    lock_path = config.root / "Cargo.lock"
    if not lock_path.is_file():
        return [
            Finding(
                path="Cargo.lock",
                line=0,
                rule="RS006-authority-dependency-closure",
                message="Cargo.lock is absent; the dependency closure cannot be verified",
                reason=_CLOSURE_REASON,
            )
        ]

    lock = _load_toml(lock_path)
    packages = lock.get("package")
    if not isinstance(packages, list):
        return []

    edges: dict[str, list[str]] = {}
    for entry in packages:
        if not isinstance(entry, dict):
            continue
        name = entry.get("name")
        deps = entry.get("dependencies", [])
        if isinstance(name, str):
            edges[name] = [
                # Lock entries may be "name", "name version" or
                # "name version (source)"; the name is the first token.
                d.split(" ", 1)[0]
                for d in deps
                if isinstance(d, str)
            ]

    # Cargo.lock does not say which edges are dev-dependencies. For in-tree
    # crates, drop an edge only when the crate's manifest declares that name
    # *solely* as a dev-dependency; anything the manifest does not explain is
    # kept, so a missing manifest errs towards a finding. Registry packages'
    # lock entries never include their own dev-dependencies.
    for name, dev_only in _dev_only_dependencies(config).items():
        if name in edges:
            edges[name] = [d for d in edges[name] if d not in dev_only]

    # Optional edges this workspace does not enable. Each one is reviewed and
    # named in architecture.toml; an optional dependency that is NOT named
    # there is still counted, so a new one cannot arrive unnoticed.
    excluded = {(e.parent, e.child) for e in config.authority_optional_edges}
    if excluded:
        edges = {
            parent: [child for child in children if (parent, child) not in excluded]
            for parent, children in edges.items()
        }

    allowed = set(config.authority_allowed_third_party)
    findings: list[Finding] = []
    for crate in config.authority_crates:
        if crate not in edges:
            continue
        for dependency in sorted(_closure(crate, edges) - {crate}):
            if dependency in allowed:
                continue
            findings.append(
                Finding(
                    path="Cargo.lock",
                    line=_line_of(lock_path, dependency),
                    rule="RS006-authority-dependency-closure",
                    message=(
                        f"`{dependency}` is in the transitive closure of `{crate}` "
                        f"but not in [authority].allowed_third_party"
                    ),
                    reason=_CLOSURE_REASON,
                )
            )
    return findings


_CLOSURE_REASON = (
    "Everything reachable from dwkd-authority is inside the trusted computing base, whether it "
    "was chosen directly or arrived through another crate. Adding to the closure requires a note "
    "on ADR-0019 and a reviewer other than the author."
)


def _dev_only_dependencies(config: ArchitectureConfig) -> dict[str, set[str]]:
    """For each workspace member: names declared only under dev-dependencies."""
    workspace_path = config.root / config.crates.manifest
    if not workspace_path.is_file():
        return {}
    ws_table = _load_toml(workspace_path).get("workspace")
    members = ws_table.get("members", []) if isinstance(ws_table, dict) else []
    out: dict[str, set[str]] = {}
    for member in members if isinstance(members, list) else []:
        manifest = config.root / str(member) / "Cargo.toml"
        if not manifest.is_file():
            continue
        data = _load_toml(manifest)
        package = data.get("package")
        name = package.get("name") if isinstance(package, dict) else None
        if not isinstance(name, str):
            continue
        linked = {d for d, _ in _dependencies(data, include_dev=False)}
        out[name] = {d for d, _ in _dependencies(data)} - linked
    return out


def _closure(root: str, edges: dict[str, list[str]]) -> set[str]:
    seen: set[str] = set()
    stack = [root]
    while stack:
        current = stack.pop()
        if current in seen:
            continue
        seen.add(current)
        stack.extend(edges.get(current, []))
    return seen


def _check_orphan_crates(config: ArchitectureConfig, members: list[str]) -> Iterator[Finding]:
    """A crate directory that is not a workspace member is built by nobody."""
    crates_dir = config.root / config.crates.directory
    if not crates_dir.is_dir():
        return
    declared = {m.replace("\\", "/") for m in members}
    for child in sorted(crates_dir.iterdir()):
        if not (child / "Cargo.toml").is_file():
            continue
        rel = f"{config.crates.directory}/{child.name}"
        if rel not in declared:
            yield Finding(
                path=config.crates.manifest,
                line=0,
                rule="RS000-workspace",
                message=(
                    f"`{rel}` is a crate but not a workspace member: "
                    f"it is built, linted and audited by nothing"
                ),
            )


def _check_inheritance(
    rel: str, root: Path, data: dict[str, Any], in_tree: set[str]
) -> Iterator[Finding]:
    for dep, spec in _dependencies(data):
        if dep in in_tree:
            continue
        inherits = isinstance(spec, dict) and spec.get("workspace") is True
        if not inherits:
            yield Finding(
                path=rel,
                line=_line_of(root / rel, dep),
                rule="RS005-workspace-dependency-inheritance",
                message=(
                    f"`{dep}` must be declared in [workspace.dependencies] and inherited "
                    f"with `{{ workspace = true }}`"
                ),
                reason=(
                    "One table lists every third-party crate in the tree. A per-crate version "
                    "means a reviewer has to read every manifest to know what is linked, and "
                    "two crates can silently disagree on a version."
                ),
            )


def _dependencies(data: dict[str, Any], *, include_dev: bool = True) -> Iterator[tuple[str, Any]]:
    """Declared dependencies, under the package name Cargo.lock uses.

    ``include_dev=False`` yields only what is linked into the crate's own
    artifact or run while building it: normal and build dependencies. A renamed
    dependency (``alias = { package = "real" }``) is reported as ``real``.
    """
    sections: tuple[str, ...] = ("dependencies", "build-dependencies")
    if include_dev:
        sections = (*sections, "dev-dependencies")
    for section in sections:
        table = data.get(section)
        if isinstance(table, dict):
            for name, spec in table.items():
                real = spec.get("package") if isinstance(spec, dict) else None
                yield (real if isinstance(real, str) else str(name)), spec
    targets = data.get("target")
    if isinstance(targets, dict):
        for target in targets.values():
            if isinstance(target, dict):
                yield from _dependencies(target, include_dev=include_dev)


def _declared_requirements(data: dict[str, Any]) -> Iterator[str]:
    project = data.get("project")
    if isinstance(project, dict):
        deps = project.get("dependencies")
        if isinstance(deps, list):
            yield from (d for d in deps if isinstance(d, str))
        optional = project.get("optional-dependencies")
        if isinstance(optional, dict):
            for group in optional.values():
                if isinstance(group, list):
                    yield from (d for d in group if isinstance(d, str))
    groups = data.get("dependency-groups")
    if isinstance(groups, dict):
        for group in groups.values():
            if isinstance(group, list):
                yield from (d for d in group if isinstance(d, str))
    tool = data.get("tool")
    if isinstance(tool, dict):
        uv = tool.get("uv")
        if isinstance(uv, dict):
            dev = uv.get("dev-dependencies")
            if isinstance(dev, list):
                yield from (d for d in dev if isinstance(d, str))


def _requirement_name(requirement: str) -> str | None:
    match = _REQUIREMENT_NAME.match(requirement)
    return match.group(1) if match else None


def _normalise(name: str) -> str:
    """PEP 503 normalisation, so `Langchain_Core` and `langchain-core` match."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _load_toml(path: Path) -> dict[str, Any]:
    return tomllib.loads(path.read_text(encoding="utf-8"))


def _line_of(path: Path, needle: str) -> int:
    """Best-effort line number for a name inside a manifest.

    Returns 0 rather than guessing wrongly; a finding with no line is still
    actionable, a finding with the wrong line wastes someone's time.
    """
    try:
        text = path.read_text(encoding="utf-8")
    except OSError:
        return 0
    for lineno, line in enumerate(text.splitlines(), start=1):
        if needle in line:
            return lineno
    return 0
