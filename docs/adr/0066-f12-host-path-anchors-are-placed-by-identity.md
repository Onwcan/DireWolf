# ADR-0066: A policy path outside the workspace names a place on the host, and is decided by where that place lies relative to the run's pinned root -- found by identity, never by spelling; `~` stands for the homes the operator names and nothing else

**Status:** Proposed · **Date:** 2026-11-16 (designed, built and reviewed locally 2026-11-16 for finding F-12; hosted evidence observed on CI #201 (run 44818094052, `3998de2`), recorded in [PRE_M6_REMEDIATION.md](../PRE_M6_REMEDIATION.md); nothing here is accepted) · **Would amend (on acceptance):** [ADR-0042](0042-m4a-canonical-filesystem-resolution.md) §10 (the anchors other than `${WORKSPACE}` are resolved -- as host locations placed against the pinned root -- rather than left unresolved), [ADR-0038](0038-policy-evaluation-phases-and-composition.md) (a load rule: a `path_under` outside the workspace only in a `DENY` rule) · **Refines:** [ADR-0028](0028-policy-input-ownership.md) (a path anchor is operator configuration or a fact the authority holds, never a runtime or environment value), [ADR-0037](0037-capability-specifications-and-canonical-authority-identities.md) (a rule-side path is still never resolved into a capability) · **Leaves open:** `require_artifact_capture` stays unenforceable -- the capture store is M8's (F12_POLICY_PACK_USABILITY.md §8)

> **A rule-side path that is not `${WORKSPACE}`'s names a place on the
> host, and a live decision is made about it by where that place lies relative
> to the run's pinned workspace root -- found on the host, by `(device,
> inode)`, before the decision -- never by comparing its spelling with a
> `/workspace/...` path.** Disjoint: no path of the run is under it. The root
> inside it: every path is. It inside the root, or a place that cannot be
> examined: the rule is not evaluated, which denies. `~` stands for the homes
> the operator names (`serve --path-anchor home=`), and with none, every rule
> naming it stays unresolved.

Proposed. The change is built so that its evidence can run; the accepted
records' bodies are unchanged (README.md, rule 1).

## Context

Every path a live filesystem decision is about is a logical `/workspace/...`
path the resolver produced beneath the run's pinned root (ADR-0042). The
shipped packs' hard denials name host places: `~/.ssh` and its neighbours,
`/etc/shadow`, `/etc/sudoers`, the container sockets, and DireWolf's own
state, configuration and binaries. Finding F-12 recorded the consequence in
one line ("shipped policy packs deny every read (no home anchor) and
`balanced` cannot write (`require_artifact_capture`)"). Reproduced through the
authority's decision path at `ddf9601` (F12_POLICY_PACK_USABILITY.md §3), the
defects are:

1. **No anchor but `${WORKSPACE}` has a value** (ADR-0042 §10). The first
   filesystem rule of every pack names `~/.ssh` for `fs.read` and
   `${DIREWOLF_HOME}` for `fs.write`, `fs.create` and `fs.delete`; both are
   unresolved, so every read, write, creation and deletion in every pack is
   refused, `UNRESOLVED_POLICY_INPUT`. Only listings and stats pass. This is
   the intended fail-closed behaviour, and it makes the packs unusable.
2. **An absolute rule path is compared by spelling with a logical path, and
   never matches.** `/etc/shadow` is not a prefix of any `/workspace/...`
   path. A workspace root bound at `/etc` (or `/`) therefore exposed
   `/workspace/shadow` -- which *is* `/etc/shadow` -- to
   `allow-workspace-read`. Nothing reached it, but only because defect 1
   refused every read first. **Resolving `~` alone would have opened it.**

The textual model POLICY.md describes ("rule-side paths outside the workspace
match on the canonicalised candidate string") predates the logical namespace;
in it the candidate and the rule shared one namespace. They no longer do.

## Decision

### 1. A host path is a place, and a live decision is made about where it lies

`${WORKSPACE}` and an absolute path beginning `/workspace` are in the run's
logical namespace and compare by components, as before. **Every other
rule-side path names a place on the host:** `~/...`, `${DIREWOLF_HOME}`,
`${DIREWOLF_CONFIG}`, `${DIREWOLF_INSTALL}`, and every absolute path not
under `/workspace`.

Before each filesystem decision, with no transaction open and through the
same pinned root the targets were resolved beneath, the state layer walks
each host path of the active policy on the host and relates it to the root
(`resource::fs::PinnedRoot::relation_to`):

- both the root's recorded path and the place are walked from `/` the way the
  kernel resolves them -- symbolic links followed, at most 40, mount points
  crossed -- and every real directory is recorded by `(device, inode)`;
- the root's walk must end at the pinned root itself, or nothing is placed;
- the place's walk ends where it ends: found, absent (nothing below the last
  directory exists), or at a directory the authority cannot search.

| Placement | When | `path_under` is |
|---|---|---|
| `Disjoint` | neither lies inside the other | false |
| `Encloses` | the place is the root or one of the root's directories | true: every path of the run is under it |
| `InsideWorkspace` | the place's walk passes through the root (found or not) | not evaluated: denied |
| `Unexamined` | the root's path no longer names it; a link loop; a name the grammar refuses; an error; a search refused at one of the root's own directories | not evaluated: denied |

A place whose walk stops at a directory the authority cannot search is taken
to lie **beneath** that directory: the resolver runs as the authority and can
never reach below it either. The residual is a symbolic link inside such a
directory that leads elsewhere, which only that directory's owner can make.

`InsideWorkspace` is deliberately coarse: this build does not compute which
logical paths are under a place inside the root, so it refuses every action
the rule's verbs select rather than guess.

### 2. What each anchor stands for

| Anchor | Directories | Source |
|---|---|---|
| `~` | each `--path-anchor home=<dir>` | the operator, only. **No default:** no variable, no subject, no user database, not the authority's own uid. With none, every `~/...` rule stays unresolved and denies |
| `${DIREWOLF_HOME}` | the authority's resolved state directory; each `--path-anchor direwolf-home=` | the authority's own fact; the operator |
| `${DIREWOLF_CONFIG}` | the state directory (which holds the policy revision in force); the directory of every configuration file `serve` read (`--policy-file`, `--secrets-file`, `--sandbox-config`); each `--path-anchor direwolf-config=` | the authority; the operator |
| `${DIREWOLF_INSTALL}` | the directory of the authority's executable (`/proc/self/exe`); each `--path-anchor direwolf-install=` | the kernel; the operator |
| `/` (absolute) | the host root | -- |

Each directory is checked at start: absolute, not a symlink, a directory not
on procfs or sysfs, and searchable by the authority. A start that cannot
check one does not happen. `serve` logs what each anchor stands for, and
says so when `~` stands for nothing. An anchor with several directories is
placed through each, and the strictest answer wins (`Encloses`, then
`InsideWorkspace`, then `Unexamined`, then `Disjoint`).

### 3. A host path may be named only by a `DENY` rule

The loader refuses a `path_under` naming a host place in an `ALLOW` or
`REQUIRE_APPROVAL` rule (`ValueError::HostPathOutsideDenial`, "a path outside
the workspace may be named only by a DENY rule", reported at
`rule[n].when.path_under`). Placed, such a path could permit or offer for
approval whole workspaces by where their roots lie on the host, and would
match, first, actions a later rule denies. Before F-12 such a rule never
matched a live path, so refusing it turns a silently dead rule into an
error, never into a permission. Postconditions only narrow and are not
limited. With this rule, F-12 can only add refusals.

### 4. Where it lives

- **policy** (pure): `HostPlacement`, `HostPlacements`, `PathAnchors::host` --
  `Some` for the logical namespace (every live decision, and the default),
  `None` for the one-namespace model the engine's unit tests and benchmark
  build. `executable_in` still compares an executable's host path by
  components: only `path_under` over logical paths changes.
- **resource** (TX008 reviewed file): the host walk; the anchor check.
- **state**: `HostAnchors` (configuration), `anchors::place` (called from
  step 2 of a tool call), `query::policy_context_placed`.
- **server**: `--path-anchor <NAME>=<DIR>`; the configuration files'
  directories; the start-up log.

### 5. Unchanged

The shipped packs (byte for byte), every rule's effect, both gates and their
independence, the obligations and their enforcement --
`require_artifact_capture` is still unenforceable, and BALANCED's writes are
still refused (`OBLIGATION_UNENFORCEABLE`) -- the resolver, DWKP, the private
protocol (12), the store schema (14), the audit format. Policy `ALLOW` is
still not permission.

## Consequences

- With a home configured beside the workspace, SAFE, BALANCED and POWER read,
  list and stat the workspace. POWER also writes, creates and deletes.
  SAFE's mutations are refused by its ceiling, BALANCED's writes by the
  unenforceable obligation, and its deletions by the unattended
  postcondition (an admitted run's origin is unattended). A run without the
  grant is refused by the capability gate whatever the pack says.
- Without a configured home nothing changes: every read is refused, as
  before.
- A workspace overlapping a protected place -- the home itself, the state
  directory, `/etc`, `/` -- refuses what the overlapping rule's verbs
  select. A workspace inside one (or a protected name that is a link to the
  workspace) is denied by the rule's own reason.
- One host walk per host path per filesystem decision: twelve for a shipped
  pack, a few `openat` and `fstat` each, outside any transaction.
- An operator policy whose `ALLOW` or `REQUIRE_APPROVAL` rule named a host
  path no longer loads. Such a rule never matched a live path.

## Residuals and what is assigned elsewhere

- **`require_artifact_capture`**: unenforceable until the kernel-owned
  artifact store exists (ARTIFACTS.md; M8). Designed as a narrow subset in
  F12_POLICY_PACK_USABILITY.md §8, not built.
- **A root that is itself a bind mount of a directory inside a protected
  place** is not seen as inside it: a bind mount's root shows its own mount
  point's ancestors. Bind-mounting part of a protected place as a workspace
  is an administrator's act.
- **A symbolic link inside a directory the authority cannot search** that
  leads into a workspace is not seen (§1).
- **Path rules protect places, not objects:** a protected file moved into a
  workspace, or hard-linked there by its owner, is not under the rule's place.
  The workspace's own boundary, the resolver (which refuses to modify a
  multiply-linked file) and the operating system's permissions remain the
  primary controls. The rule is the backstop it always was.
- **Placement is a fact at decision time.** The objects the effect uses are
  the ones the resolver checked, but where a place lies can change after the
  decision (a rename by someone who can write both).
- **`InsideWorkspace` refuses more than it must** (§1). Computing which
  logical paths lie under a place inside the root -- by verified names, as
  the resolver does -- is a refinement, not built.
- **`${DIREWOLF_*}` stand for what the authority knows and the operator
  declares:** a runtime state directory elsewhere is protected by this
  backstop only once declared. `$DIREWOLF_HOME`'s layout is fixed at
  packaging (M17).
- **Off Linux** nothing is placed. Every host-path rule is unevaluated there,
  and neither daemon serves anyway. The anchors are not checked at start
  there either: with no resolver, no check could pass, and a start that
  failed on one would stop the in-process authority every test uses (CI #184,
  macOS).

## Alternatives considered

- **A. An operator-configured home, verified, placed by identity.**
  Chosen, for `~`.
- **B. A home from authenticated subject information** -- the DWKP peer's or
  the authority's uid, through the user database. Rejected. It names the
  wrong home in the deployment that matters: the runtime and the authority
  run as their own users, while the credentials the packs protect are the
  human operator's. A wrong anchor is a deny rule that silently protects
  another directory. It would also add the user database (NSS) to the
  authority's inputs.
- **C. A name-pattern protection** (deny any path with a `.ssh` component,
  anywhere). Rejected. It is a new predicate and a change to every pack. It
  is also both broader (a repository's `.ssh/` fixture) and narrower (it
  misses `~/.config/gh` spelled through a link) than the places the packs
  name.
- **D. Keep every host anchor unresolved until a later milestone.** Rejected
  as the whole answer: it leaves the packs unusable. It survives as the
  behaviour without a configured home.
- **Compare host paths by spelling, with `~` substituted** (the old textual
  model, made to resolve). Rejected: it is defect 2 made live. A spelling
  says nothing about where a logical path lies on the host.
- **Project each host place into the logical namespace** (compute exactly
  which `/workspace/...` paths lie under `~/.ssh` when the home is inside the
  root). Deferred. It needs names verified against their directories, as the
  resolver verifies them, or a case-insensitive filesystem could let a
  differently-spelled path past it.

## Evidence

Local, WSL Ubuntu 26.04 (hosted evidence since observed: [PRE_M6_REMEDIATION.md](../PRE_M6_REMEDIATION.md)):

- `crates/dwkd-authority/src/policy/fixtures.rs`: every pack names the same
  twelve host paths; a read is allowed once they are placed disjoint; an
  unplaced path denies and names its anchor; `Encloses` denies by name;
  `InsideWorkspace` and `Unexamined` are not evaluated; an absolute
  protection is placed, not spelled; a `/workspace` absolute path still
  compares by components; a host path only in a denial (load); an executable
  path still compared on the host; each pack keeps its ceiling.
- `crates/dwkd-authority/src/resource/fs/linux/tests.rs` (`host_placement`):
  beside and above; inside, existing or not; links followed (into the root,
  out of it, relative, through the root's own path), a loop unknown; a
  replaced root; an unsearchable directory beside the root or of its own;
  the anchor check.
- `crates/dwkd-authority/src/state/anchors.rs`: a root at `/` holds every
  absolute protection; several directories, the strictest; the logical
  root's name agrees with the resolver's.
- `crates/dwkd-authority/tests/policy_packs.rs`: the three shipped packs
  through the authority's decision path (preview and invocation) with a real
  workspace, the real resolver and a recording broker -- the matrix of
  F12_POLICY_PACK_USABILITY.md §4.
- `crates/dwkd-authority/tests/broker_fs_read.rs` (released binaries): a
  shipped pack reads through the real broker once a home is named; refuses
  when the home is the workspace; refuses every read without one (unchanged
  case); `serve` refuses a home it cannot examine.
- `crates/dwkd-authority/tests/policy_composition.rs`: a child permitting the
  parent's `~/.ssh` is refused at load.
- `tests/architecture/test_f12_policy_anchors.py`.
- `make policy-anchor-mutations`: 19 mutants, judged by C3's per-mutant
  judge.

## Revisit if

- M8's artifact store lands (`require_artifact_capture` becomes
  enforceable);
- packaging (M17) fixes `$DIREWOLF_HOME`'s layout (its directories become
  the authority's own facts);
- a home inside a workspace becomes a supported layout (project the place,
  §1);
- a filesystem predicate other than `path_under` comes to name host places.
