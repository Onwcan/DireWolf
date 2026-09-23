# ADR-0042: M4a — a declared path means the object found beneath a pinned root, by descriptor, or nothing

**Status:** Accepted · **Date:** 2026-09-23 · **Amends:** [ADR-0019](0019-language-rationale-v2.md) (the authority dependency set gains `unicode-normalization` and `tinyvec`, and `rustix` gains its `fs` feature), [ADR-0035](0035-m3-authority-dependency-set.md) (`rustix` has a second reviewed use), [ADR-0039](0039-durable-authority-state.md) (schema version 2 and two audit kinds) · **Refines:** [ADR-0018](0018-authority-broker-split.md) (the canonicaliser is the authority's; the checked object reaches the broker in M4b), [ADR-0028](0028-policy-input-ownership.md) (a workspace root is a policy input the runtime cannot supply), [ADR-0034](0034-protocol-depends-on-no-unicode-database.md) (a Unicode database enters the authority for filesystem names and stays off the wire), [ADR-0037](0037-capability-specifications-and-canonical-authority-identities.md) (the one production path from `DeclaredPath` to `CanonicalPath`), [ADR-0040](0040-m3d-reconciliation-admission-across-tenures-and-undecidable-proposals.md) (a resolved path does not make a proposal a canonical action)

> **A path spelling is not authority.** The object used later must be the
> object that was checked. The model may propose a path and the runtime may
> transmit one; neither defines what it means. The operating system supplies
> the object; the authority decides on the canonical result.

## Context

M3 left the filesystem half of the capability model deliberately unfinished.
[ADR-0037](0037-capability-specifications-and-canonical-authority-identities.md)
split a filesystem scope into two types: `ScopeSpec::DeclaredPath`, untrusted
text, and `Scope::Path(CanonicalPath)`, authority-comparable state — with **no
conversion between them**, and `CanonicalPath`'s constructors confined to
`crate::resource`, because the conversion needs filesystem truth and M3 had
none. Admission withholds every filesystem and process capability as
`UNRESOLVED_RESOURCE`; every policy path anchor is unresolved; `ToolInvoke` and
`CanonicalPreview` are reserved operations with no handler.

M4 is the milestone that makes those capabilities real: canonical filesystem
resolution, fd-relative operations, exec mediation, secrets. It is too large
to review as one change, and its first part — deciding what a path *means* —
is the part every later one depends on. A broker that reads the right bytes
through the wrong resolver is not a partial success.

This ADR records the canonical filesystem foundation (M4a): what a declared
path resolves to, beneath which root, by which mechanism, what it refuses, and
what it hands to the code that will later act on it. It performs no tool
effect.

## Decision

### 1. M4 is delivered in five parts; M4 is complete only when all are

| part | delivers |
|---|---|
| **M4a** (this ADR) | the canonical filesystem resource foundation: operator-bound roots pinned by identity, one resolver, canonical identities and checked handles, Linux high-assurance resolution, the portability contract, real-filesystem adversarial evidence |
| **M4b** | the private authority → broker channel; single-use, per-invocation authorisation; the first `ToolInvoke` and `CanonicalPreview` wire forms; admission resolving filesystem capabilities; `fs.read` end to end |
| **M4c** | the remaining filesystem broker operations and their retry and atomicity contracts |
| **M4d** | the process-execution broker: executable identity and hashing, argv normalisation, environment scrubbing, rlimits, descriptor hygiene |
| **M4e** | the secret broker: backends, injection modes A–C, the redaction index, residue and output evidence, and the final M4 security gate |

This is a planning distinction. The M4 acceptance criteria in
[ROADMAP.md](../ROADMAP.md) are unchanged, no M4 evaluation is activated by
any part before M4e, and the eval harness's available milestones stay M1, M2,
M2.5 and M3.

### 2. Four things, kept apart

| what | type | produced by | used for |
|---|---|---|---|
| a spelling | `DeclaredPath` (capability layer) | anyone | nothing but being resolved |
| the policy/capability name | `CanonicalPath` | **only** `crate::resource` | component-prefix containment, `path_under` |
| the operating-system object | `FileIdentity` — `(st_dev, st_ino)` from `fstat` of the **opened** descriptor | only `crate::resource::fs` | proving continuity: the object used is the object checked |
| the live checked object | `ResolvedResource`, holding an `O_PATH` descriptor and its parent's | only `PinnedRoot::resolve` | what M4b's broker acts on |

An inode is a point, not a subtree, so containment stays a component-prefix
relation over names — but over names that were **verified against the
directory holding them**, beneath a root proved to be the operator's, with no
symlink anywhere in the chain. The identity does not replace the name; it
proves the object behind the name did not change between the check and the
use.

None of these has a public constructor. `FileIdentity::new` and the
`CanonicalPath` constructors are `pub(in crate::resource)`; `PinnedRoot` is
produced only by `install` and `reopen`, which are `pub(crate)` and open a
real directory; `ResolvedResource` only by `PinnedRoot::resolve`. Each
carries `compile_fail` doctests proving an outside crate cannot build one
from numbers or strings, or by naming its fields. `RootFingerprint` is the
exception by design: it is the **expectation** the state layer stores, and
anyone may build one, because holding one grants nothing — a `PinnedRoot`
exists only when an opened directory turns out to *be* it.

`PinnedRoot` and `ResolvedResource` are not `Clone` (duplicating a descriptor
extends its authority's lifetime without a decision), their `Debug` renders
identities and canonical names but no descriptor, and no descriptor is
serialised anywhere. `Send`/`Sync` come from `OwnedFd`; no `unsafe impl` is
written.

### 3. The namespace and the grammar

A canonical `fs` path lives in DireWolf's **logical** namespace, not the
host's. `/workspace` is the run's pinned workspace root — the directory the
operator bound to the session's workspace — and every further component is a
name found beneath it. It is the path an agent sees inside its execution
environment ([SANDBOX.md](../SANDBOX.md) mounts the workspace there) and the
path capabilities and policy rules are written in (`fs.read:/workspace/src`).
**No other top-level name resolves in M4a.** A host-absolute spelling —
`/etc/hosts`, `/home/u/project`, `/` — is refused as `OUTSIDE_WORKSPACE`,
never looked up; so is `/workspaceX` and `/Workspace`. Host absolute paths,
sandbox paths and logical workspace paths are not conflated: the first is only
ever an operator's input (§8), the second is M5's, the third is this.

`DeclaredPath` already refuses an empty path, a relative one, NUL, `?` and
anything over 384 characters. The resolver's grammar, one pure function, is
the next layer, and it **refuses rather than rewrites**: there is exactly one
accepted spelling of each path, because a cleaned-up spelling is a second
spelling and a second spelling is how a deny rule is walked around.

| input | outcome |
|---|---|
| `/workspace` | the root itself |
| `/workspace/a/b` | components `a`, `b` |
| `/`, `/etc/hosts`, `/workspaceX` | `OUTSIDE_WORKSPACE` |
| `/workspace//a`, `/workspace/a/` | `EMPTY_COMPONENT` |
| `/workspace/./a`, `/workspace/a/../b`, `/../workspace` | `TRAVERSAL` |
| `/workspace/a\b` | `SEPARATOR` — a backslash is Windows's separator and never a name character |
| a C0/C1 control, DEL, a bidi override or isolate, a zero-width or format character, U+2028/2029, U+FEFF, U+061C | `UNSUPPORTED_CHARACTER` |
| a component that is not already NFC | `NOT_NORMALIZED` (§6) |
| a component over 255 bytes | `NAME_TOO_LONG` |
| more than 63 components below the anchor | `TOO_DEEP` |

`..` is refused three times: by the grammar, by `RESOLVE_BENEATH` (the kernel
refuses `..` above the starting descriptor, which the evidence shows by calling
the per-component open with `..` directly), and structurally, because each
component is opened relative to the previous one and never as a multi-component
string.

### 4. The Linux resolver

Linux is the only platform with a resolver. It uses `rustix` 1.1.5's safe
wrappers; DireWolf's own Rust remains `forbid(unsafe_code)`, and there is no
handwritten syscall and no FFI.

```text
pinned root descriptor ──┐
for each component, outermost first:
    fd   = openat2(parent, name,
                   O_PATH | O_NOFOLLOW | O_CLOEXEC [| O_DIRECTORY for intermediates],
                   RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS
                 | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV)
    st   = fstat(fd)                          -- identity and kind from the object itself
    kind = directory | regular file (leaf)    -- anything else refused
    list(parent): an entry spelled exactly `name`, and no other entry
                  canonically equivalent to it (§6)
then, leaf first:
    fstatat(parent, name, AT_SYMLINK_NOFOLLOW) == st, for every link   -- else RACE
then:
    judge(kind, link count, Access, Expect)   -- §7
```

* **Every open is relative to a held descriptor**: the pinned root, or the
  previous component. Nothing is reopened by name, the process working
  directory is never consulted, and nothing calls `chdir`.
* **`O_PATH` throughout.** Resolution opens nothing for reading: a FIFO cannot
  block it, a device cannot be triggered by it, and it needs no permission on
  the object beyond reaching it. Listing a directory to verify a name opens a
  separate read descriptor on `"."` relative to the held one, under the same
  `RESOLVE` flags.
* **The flags, verified against rustix 1.1.5** (`rustix::fs::ResolveFlags`):
  `BENEATH` — nothing resolves outside the starting descriptor, `..` above it
  and absolute paths included; `NO_SYMLINKS` — no symlink is followed at any
  position; `NO_MAGICLINKS` — implied by `NO_SYMLINKS` and named anyway, so the
  intent survives a reading of one line; `NO_XDEV` — no mount point, bind mounts
  included, is crossed. `O_NOFOLLOW` additionally makes a trailing symlink
  return the link itself, which classification then refuses.
* **Identity comes from the opened descriptor** (`fstat`), never from a stat of
  a path. `st_dev` and `st_ino` are widened to `u64` through `From`, never an
  `as` cast; `st_nlink` likewise, since it is `u32` on some targets.
* **The chain is re-verified after the walk**, leaf first: every name still
  binds, in its held parent, to the object opened for it. A rename, exchange
  or replacement anywhere in the chain while resolution was in progress is
  `RACE`. `openat2`'s own `EAGAIN` (a concurrent rename it could not rule out)
  is also `RACE`.
* **Directory listings are bounded** at 65,536 entries per directory per
  resolution; a larger directory is `DIRECTORY_TOO_LARGE`, not partially
  checked, because the entry after the cut could be the alias.

### 5. No fallback, and assurance is named

The documentation before M4a promised a component-wise fallback walker for
kernels without `openat2` (Linux before 5.6), macOS and Windows, "slower and
slightly weaker". **M4a implements no fallback.** A kernel that answers
`openat2` with `ENOSYS`, a seccomp filter that answers `EPERM`, or a kernel
that rejects one of the flags (`EINVAL`, `E2BIG`) gets `UNSUPPORTED_PLATFORM`
— not a quieter walk. Every successful resolution reports its mechanism as
`Assurance::LinuxOpenat2`, the only value, named so that a reduced mechanism
added later can never be mistaken for it. A reduced-assurance fallback needs
its own ADR, its own evidence, and a second `Assurance` value.

### 6. Unicode and non-UTF-8 names, precisely

"Normalise the path to NFC" is not the rule, because on a byte-exact
filesystem such as ext4 two canonically equivalent spellings can be two
different directory entries — two different objects — and normalising a
request can look up the one nobody asked for. The rules are:

1. **A requested component must already be NFC.** One that is not is
   `NOT_NORMALIZED`: refused, never normalised.
2. **Lookup is by the exact bytes requested,** and the resolver then proves,
   by listing the parent, that an entry with **exactly those bytes** exists.
   The canonical component is therefore the on-disk name. A filesystem that
   matched some other spelling — case folding, normalisation-insensitive
   lookup — is `NAME_MISMATCH`: refused, not believed.
3. **Another entry canonically equivalent to the requested one is an
   ambiguity**, and the request is `NORMALIZATION_AMBIGUITY`: `é` (U+00E9)
   beside `e` + U+0301, or `K` beside KELVIN SIGN U+212A. Two objects would
   share one canonical spelling; neither may be named through it.
4. **The descriptor, not the name, is the object.** The canonical name is for
   comparison and display; the handle is what M4b uses (§9). A name can never
   select a second object after the first was checked.

Equivalence is `NFC(sibling) == name` (the name is NFC by rule 1). An ASCII
sibling differs byte-wise and is never an alias, but a non-ASCII sibling can
alias an ASCII name (KELVIN SIGN normalises to `K`), so only ASCII siblings are
skipped. The work per sibling is bounded by `NAME_MAX`.

The implementation is `unicode-normalization` 0.1.25, pinned exactly, with
Unicode 17.0.0 tables (§13). A code point unassigned in 17.0.0 is judged by
those tables; a later Unicode version could decompose it, and upgrading the
crate is then a reviewed change to which names resolve, not a hidden one.

**Non-UTF-8 names.** DWKP text is UTF-8, so a declared path cannot spell a
name that is not; such an object cannot be named and never resolves. An
on-disk sibling that is not UTF-8 is ignored by the ambiguity check — it can
neither equal a UTF-8 request byte-for-byte nor be one of its canonical
equivalents — and nothing converts a name lossily. Support for names DWKP
cannot represent losslessly is not claimed.

### 7. Links, mounts, special files — each its own contract

| class | contract | evidence (§14) |
|---|---|---|
| **symlink** | never followed, at any position: `RESOLVE_NO_SYMLINKS` and `O_NOFOLLOW`; a trailing one is opened as itself and classified `SYMLINK` | leaf, intermediate, to a sibling, outside the root, a chain, dangling, created after an earlier check, and the exchange races |
| **procfs magic link** | never followed: `RESOLVE_NO_MAGICLINKS`; refused as `MAGIC_LINK` when the directory holding the link is procfs. A root on procfs or sysfs is refused outright (`ROOT_UNSUPPORTED_FILESYSTEM`, from `fstatfs`), and `/proc/self` as a root is a symlink (`ROOT_SYMLINK`) | `/proc/self/{cwd,root,exe,fd/0}` against a procfs directory opened by the test (the one place a test bypasses production root pinning, which is itself asserted to refuse procfs) |
| **mount crossing** | never crossed: `RESOLVE_NO_XDEV`; `MOUNT_CROSSING`. A workspace must be one mount: a bind mount, tmpfs or volume *inside* it makes the names beneath it unresolvable, which is the compatibility cost | real mount points `/proc`, `/sys`, `/dev` beneath a root pinned at `/`, each confirmed to be a mount point by `statx` mount ids before it counts; a bind mount inside a workspace needs privileges and is NOT EXERCISED |
| **hard link** | see below | an inside name for an outside inode, observed and modified; an inside twin; a single link; cross-device is impossible by construction |
| **FIFO, socket, device, unknown** | refused as a leaf (`SPECIAL_FILE`) or on the path (`NOT_A_DIRECTORY`) | FIFO and socket nodes, `/dev/null` |
| **wrong kind** | `Expect::Directory` refuses a file and `Expect::RegularFile` a directory (`WRONG_KIND`); an intermediate that is a file is `NOT_A_DIRECTORY` | each |

**Hard links are not symlinks, and `openat2` does not solve them.** A hard link
is a second *name* for the same inode; nothing is followed, so no `RESOLVE`
flag applies, and an inode whose other name is outside the workspace resolves
through its inside name like any other file. What DireWolf can truthfully
guarantee, and what it cannot:

* **Guaranteed:** the object resolved is the object found at a verified name
  beneath the pinned root, and it is the object M4b will act on.
* **Not guaranteed:** that the inode has no other name outside the workspace.
  `st_nlink` counts names, not where they are, and finding them would mean
  walking the host filesystem.

So the contract depends on what the caller will do (`Access`):

* **`Observe`** (read, list, inspect) **accepts a multiply-linked file.**
  Refusing `st_nlink > 1` would break ordinary workspaces: pnpm links
  `node_modules` into a store outside the project, `git clone --local` links
  object files, and build caches do the same. Reading through an inside name
  reads bytes whose creator could already read them: on Linux with
  `fs.protected_hardlinks = 1`, the default of the major distributions, a user
  can only link a file they own or can read and write, so planting a link
  grants nobody a read they did not have. An agent that can create a link to
  an outside file with a *process* could equally read that file with the same
  process; the escalation is the process (M4d, M5), not the read.
* **`Modify`** (write, create beneath, delete, rename, change) **refuses a
  regular file with more than one link** (`HARDLINK_ALIASED`), because the
  change would reach every other name for the inode — possibly outside the
  workspace — and no capability covered those names. Directories cannot be
  hard-linked.
* The link count is exposed on the result, and M4b must re-check it on the
  held descriptor immediately before a modification, since a link can be
  added after resolution.

### 8. Trusted roots: operator-bound, pinned by identity, immutable

**Provenance.** A runtime can only *name* a workspace (`WorkspaceId` stays a
name, not a path) and a session's workspace binding stays fixed for its life.
The root behind the name is the operator's: `OperatorBootstrap::
install_workspace_root(workspace, host_path)`, the in-process configuration API
M3 already uses for profiles, skills and workspaces. No DWKP operation reaches
it, the runtime-write probe of [ADR-0039](0039-durable-authority-state.md)
still covers the store it writes, and no environment variable — `PWD`, `HOME`,
`USERPROFILE`, `HOMEDRIVE`, `HOMEPATH`, `DIREWOLF_HOME` — is read to find or
interpret a root.

**Installation measures the directory.** The host path must be absolute (a
relative root would mean whatever the working directory makes it mean),
NUL-free and at most 4,096 bytes. It is opened with
`O_PATH | O_DIRECTORY | O_NOFOLLOW`: its final component may not be a symlink
(the intermediate components are the operator's own host layout and are
resolved normally), it must be a directory, and it may not be on procfs or
sysfs. The binding records the path and the **fingerprint of the opened
directory**: device, inode and, where the filesystem reports one (`statx`
`STATX_BTIME`), birth time — so a directory recreated at the same path and
handed a recycled inode number is still told apart where the filesystem
records birth.

**Schema version 2** adds one table, `workspace_root`: one row per bound
workspace, keyed by and referencing `workspace(workspace_id)`; the host path
(bounded, absolute by `CHECK`); device and inode as decimal text, so the whole
`u64` range survives SQLite's signed integers; birth seconds and nanoseconds
(both or neither); the installation time. Two triggers make a row immutable
and undeletable. Version 1 stores migrate to version 2 in the one migration
transaction [ADR-0039](0039-durable-authority-state.md) §4 defined, which now
also appends a `store.migrated` audit record carrying both versions. Tested:
a store brought to exactly the version-1 shape (the M3 schema, its data and
its audit chain) migrates on restart, verifies structurally, keeps a
verifiable audit chain and then takes a root binding; the exact version-2
schema is what the structural verifier accepts; and a failing migration step
leaves the version and the objects untouched.

**One root per workspace, forever.** Installing the same binding again is a
no-op; a different one is refused — *a different root is a different
workspace*. There is no update path, in code or in SQL. So the question "what
happens when the operator changes workspace X from root A to root B while a run
is live?" has the answer **the operator cannot**: they create workspace Y bound
to B, and new sessions bind to Y. A live run's `/workspace` can never be
re-pointed by configuration.

**Pinning.** Every resolution for a run opens the recorded path again and
proves the directory is the one installed (`PinnedRoot::reopen`: device, inode
and recorded birth time must match the opened descriptor's). The pinned
descriptor is then the only anchor for that resolution. If the directory at
the path has been replaced — renamed away with another put in its place,
recreated, or swapped — pinning fails with `ROOT_REPLACED` and nothing
resolves. A `PinnedRoot` already held keeps referring to the original
directory through its descriptor, whatever happens to the path.

This refines the earlier documentation's "pinned at run admission and held as
an open fd for the life of the run". An identity is pinned **before** any run,
by the operator, and every later pin must prove it; a run's state survives an
authority restart ([ADR-0040](0040-m3d-reconciliation-admission-across-tenures-and-undecidable-proposals.md))
and a descriptor would not. The unsafe answer — the next resolution follows
the new pathname — is impossible: the new directory is refused.

**Audit** ([ADR-0027](0027-audit-scope-boundary.md)). Installing a root is a
security-significant configuration change and is audited as
`config.workspace_root_installed`, with the workspace id, the host path (the
operator's, bounded by the schema), the device and inode, and whether a birth
time was recorded. Schema migration is audited as `store.migrated`. A
**resolution is not audited**: it is an internal step of a decision, not an
effect and not a decision, and a hostile client repeating one must not be able
to grow `audit.log`. The two kinds extend ADR-0039's inventory.

### 9. The checked object, its lifetime, and where it goes in M4b

A `ResolvedResource` holds the leaf's `O_PATH` descriptor and its parent's,
with the leaf's verified name. It offers the canonical path, the identity, the
kind, the link count, the root's identity, the assurance and one check —
`still_bound()`: the held leaf descriptor still has the checked identity, and
the name in the held parent still binds to it. It offers **no descriptor and
no host path**, and nothing in it is a path to reopen.

M4b's obligation, recorded here so it cannot be designed away later:

* The broker acts on the **checked object**: the descriptor the authority
  resolved, transferred over the private authority → broker channel, or a
  descriptor obtained relative to the retained parent and proved by identity
  to be the same object. It never opens the canonical name, or any host path,
  again.
* `still_bound()` (or its equivalent on the transferred descriptor) runs
  immediately before the effect; a failure is a refusal, never a re-resolve.
* An `O_PATH` descriptor grants no read or write by itself; turning it into
  one (for example `openat2(parent, name, O_RDONLY | O_NOFOLLOW, same RESOLVE
  flags)` plus identity comparison) is part of the effect, and happens in M4b
  under the single-use authorisation.
* Descriptors never appear in DWKP. The private channel is M4b's design.

**TOCTOU** is therefore handled by construction, not by timing: identities
come from descriptors, each open is relative to a descriptor, and the chain is
re-verified after the walk. The race evidence (§14) asserts the property the
design claims — the resolver returns the object it checked, or refuses — with
an attacker thread exchanging names throughout.

### 10. Integration: state orchestrates, the cores stay pure

* **State calls resource; resource never calls state.** The resolver does not
  read `kernel.db` (TX005). `state/resolution.rs` reads the run's workspace
  (from the policy input recorded at admission) and its root binding, and
  hands the resolver the recorded path and fingerprint. `Authority::
  pin_run_workspace` and `Authority::resolve_for_run` are the in-process entry
  points; a run that is unknown, not active, has no workspace, or whose
  workspace has no root is refused with a typed reason, never resolved against
  a default.
* **Capabilities.** The lattice compares `CanonicalPath`s and never obtains
  them (TX003). A resolved path's canonical name feeds containment exactly as
  M3's synthetic ones did, and the tests show containment over resolved
  paths.
* **Policy.** The engine stays a pure function (TX004). `PathAnchors.workspace`
  is filled with `/workspace` **only** when the run's workspace has a bound
  root — a kernel-owned fact — and stays unresolved otherwise, which remains
  fail-closed for every rule that names `${WORKSPACE}`. The other anchors
  (DireWolf home, config, install, the operator's home, absolute) stay
  unresolved: M4a has no kernel-owned identity for any of them.
* **Only the state layer may name the resolver** (TX011): a call to
  `resource::fs` from `policy`, `capability` or `server` is a static finding.
* **Admission is unchanged.** Filesystem and process capabilities are still
  withheld as `UNRESOLVED_RESOURCE`. Resolving a requested filesystem scope
  truthfully means resolving **every** term of the mint expression — profile,
  verified skills, parent grant, request, ceiling — through this resolver, and
  restoring recorded grants on replay; that is M4b's, with its first effect.
  Process capabilities stay withheld until M4d resolves executables.
* **`QueryAuthority`** still answers a proposal with `NO_CANONICAL_ACTION`
  ([ADR-0040](0040-m3d-reconciliation-admission-across-tenures-and-undecidable-proposals.md)):
  a resolved path is one fact of a canonical action, and the authority still
  lacks the rest (environment, byte counts, argv classes).
* **`ToolInvoke` and `CanonicalPreview`** remain reserved operations with no
  schema and no handler. The DWKP schema delta of M4a is zero.
* **The broker** remains a non-addressable stub.

### 11. Platforms: what is guaranteed where

| platform | resolver | assurance |
|---|---|---|
| **Linux ≥ 5.6** | `openat2`, §4 | high: `LinuxOpenat2` |
| **Linux < 5.6, or `openat2` filtered** | none | every resolution `UNSUPPORTED_PLATFORM` |
| **WSL2** | Linux semantics — it runs a Linux kernel | as Linux; the Windows host's own paths are not in scope |
| **macOS** | none | every root `UNSUPPORTED_PLATFORM` |
| **native Windows** | none | every root `UNSUPPORTED_PLATFORM` |

On every platform but Linux the resolver's descriptor type is uninhabited, so
no code path can hold a pinned root at all; the crate builds and its
platform-independent tests (grammar, names, judgement, bounds) run on the
three hosted CI platforms. There is no Windows path parsing to harden: a
backslash is refused by the grammar, and ADS, reserved names, trailing dots,
drive and UNC prefixes and 8.3 names cannot arise because no Windows path is
ever opened. The DWKP server was already Linux-only
([ADR-0041](0041-m3e-authenticated-dwkp-transport.md)).

### 12. Errors are bounded classes, not text

`ResolveError` and `RootError` are closed enums with stable codes
(`OUTSIDE_WORKSPACE`, `TRAVERSAL`, `SYMLINK`, `MAGIC_LINK`, `MOUNT_CROSSING`,
`NAME_MISMATCH`, `NORMALIZATION_AMBIGUITY`, `SPECIAL_FILE`, `WRONG_KIND`,
`HARDLINK_ALIASED`, `RACE`, `PERMISSION_DENIED`, `DIRECTORY_TOO_LARGE`,
`UNSUPPORTED_PLATFORM`, `IO`, `ROOT_REPLACED`, …). A variant carries at most a
component **depth**, a kind, a link count or an errno — never the text of a
name — so a hostile file name cannot reach a log, an audit record or a reason
through an error, and rendered error text is ASCII from a fixed alphabet (a
unit test renders the variants and checks every character). An `errno` is kept for diagnostics; it is not
authority semantics. Every failure narrows: a refusal is never "the predicate
did not match", never the original text, and never `*`.

Bounds on hostile input: 384 characters a declared path, 255 bytes a
component, 63 components, 4,096 bytes a root path, 65,536 entries a listing,
`NAME_MAX` of normalisation work per sibling.

### 13. The TCB change, measured

`dwcheck closure --report`, feature-resolved from `cargo metadata --locked`:

| | before M4a (M3e) | after M4a |
|---|---|---|
| linked (runtime) | 25 | **27**: + `unicode-normalization`, `tinyvec` |
| build-only | 5 (`cc`, `find-msvc-tools`, `pkg-config`, `shlex`, `vcpkg`) | 5, unchanged |
| with a build script | `libc`, `libsqlite3-sys`, `rustix` | unchanged |
| native (`links`) | `libsqlite3-sys` | unchanged |
| proc macro | none | none |

* **`rustix` 1.1.5**, `default-features = false`, features `std`, `net`,
  `time` and now **`fs`**. `fs = []` in rustix's manifest: it adds code and no
  crate, and requests no `linux-raw-sys` feature. The authority still declares
  rustix for `target_os = "linux"` only; on x86_64 and aarch64 it makes raw
  syscalls through `linux-raw-sys` (no C, no libc), and on powerpc64le and
  s390x through `libc` and `errno`, as ADR-0041 measured. What grew is the
  syscall surface — `openat2`, `openat`, `fstat`, `fstatat`, `statx`,
  `fstatfs`, `getdents64` — and that is the TCB change this ADR records.
  Licence: Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT.
* **`unicode-normalization` 0.1.25** (`=0.1.25`, `default-features = false`):
  `std` cannot answer "is this string NFC" or "are these canonically
  equivalent", and a home-grown table would be a second, unreviewed Unicode
  database. MIT OR Apache-2.0; no build script, no proc macro, no I/O.
  `#![deny(unsafe_code)]` with five local exceptions, all in Hangul
  composition and decomposition, all `char::from_u32_unchecked` on arithmetic
  bounded by the Hangul block constants — reviewed for this ADR.
* **`tinyvec` 1.13.3** (feature `alloc`, from unicode-normalization):
  unconditionally `#![forbid(unsafe_code)]`; Zlib OR Apache-2.0 OR MIT; no
  build script, no proc macro, no optional dependency enabled.

Nothing else moved: no existing dependency was upgraded, and `cargo update`
was not run.

**Static rules** ([ADR-0031](0031-repository-layout-and-boundary-enforcement.md);
hygiene, not containment), each with a deliberate-violation fixture:

* **TX008** becomes `TX008-rustix-only-at-reviewed-syscall-boundaries`: its
  exemption list grows from `server/peer.rs` to that file plus
  `resource/fs/linux/mod.rs` and its test module — named as **files**, so a new
  file dropped beside them is not exempt. The fixture names rustix in
  `resource/fs/mod.rs`, the portable half of the same resolver one directory
  up, and it is still a finding; a fixture use in `resource/fs/linux/mod.rs` is
  not.
* **TX011** (new): only `state/` and `resource/` may name `resource::fs` — the
  policy engine asking the resolver is a finding.
* **TX012** (new): `unicode_normalization` is named only in
  `resource/fs/names.rs` and the resolver's tests, across the authority and
  `dwk-proto`.
* **RS016** (new): `dwk-proto` may not depend on `unicode-normalization` or
  `tinyvec`. ADR-0034 holds for the wire: DWKP decoding still consults no
  Unicode database.

TX003, TX004, TX005, TX007, TX009 and TX010 are unchanged. One test that
created a socket node with a `UnixListener` was rewritten to use `mknodat`, so
TX009 needed no exception.

### 14. Evidence: the production resolver against real filesystems

`make filesystem-canonicalization-evidence` (Linux; a CI job the aggregate
requires) runs the resolver's real-filesystem tests and the state suite. Each
case prints one `FS-EVIDENCE` line after its assertions held. The task fails
when any of fourteen categories — normal, platform, traversal, symlink,
magic-link, mount-crossing, hardlink, unicode, resource-kind,
root-replacement, toctou, leak, performance, state — has no exercised case;
when any of the six race campaigns did not report or returned an escape or an
unexpected object; or when a case was not exercised other than the four that
need privileges or a special filesystem (a bind mount, a casefold filesystem, a
cross-device link, a recycled inode with the same birth time), which are listed
as NOT EXERCISED and never counted.

There is no test resolver: every case calls `PinnedRoot::install`/`resolve` or
the state layer's entry points. The race campaigns resolve 10,000 times each
while an attacker thread, released by a barrier, exchanges names with
`renameat2(RENAME_EXCHANGE)` or renames directories: a regular file with a
symlink to an outside file; a directory with a symlink to an outside directory
holding a same-named object; a parent renamed back and forth; a parent moved
out of the workspace and back; a leaf exchanged with an inside file and with a
symlink; and the workspace's own path exchanged with another directory after
pinning. **A returned object whose identity is outside the allowed set is an
escape; the required count is zero.** A refusal is success. No campaign uses a
sleep as its mechanism, and each asserts the attacker actually raced.

Identity alone cannot show the chain re-verification (§4) doing its job: when
a parent is renamed or moved out of the workspace mid-walk, the leaf returned
without the check would still be the leaf that was checked — under a name that
no longer binds. So the two parent campaigns must also show the check firing
(`RACE` refusals: tens to hundreds per 10,000 on the development machine, and
at least one is required), and
a deterministic test changes the tree underneath an opened chain and requires
`RACE` at the depth that changed. The mutation review found this gap: with the
call to the chain check removed from the walk, every other test still passed.

The root-replacement regression pins workspace A, renames it away, creates B
at its path, puts different markers in each, and shows the pinned root still
resolves A's marker while pinning again through the path is `ROOT_REPLACED`.
The leak test resolves 5,000 times, most of them refused, and requires **zero**
growth in the descriptors the process holds on the test's own fixture (read
from `/proc/self/fd`'s link targets, so that tests running concurrently cannot
move the count); it first shows the count rises by two while one result is
held, so that zero is a measurement and not a blind spot.

### 15. What M4a does not implement

No filesystem, exec or secret effect; no `fs.read` or any other tool; no
`ToolInvoke` or `CanonicalPreview` wire form; no authority → broker channel and
no per-invocation authorisation; no fallback resolver; no macOS or Windows
resolver; no admission of filesystem or process capabilities; no anchor but
the workspace's; no sandbox, approvals, budgets or providers. The
`path-traversal` evaluation stays pending until M4's filesystem broker
exercises it end to end.

## Consequences

### Security consequences

* "What object does this path mean?" has one production answer, in one
  module, relative to a root the operator pinned — and the runtime can choose
  neither the root nor the object.
* The object a later effect uses can be proved to be the object checked, and
  the types make reopening by name something code would have to go out of its
  way to do.
* A symlink, magic link or mount point anywhere in a path is a refusal, which
  makes some legitimate workspaces unresolvable (a symlinked `node_modules`, a
  bind-mounted cache). That is the price of a canonical path meaning one
  object; M4b's error codes let the operator see which component refused.

### TCB consequences

Two crates and one rustix feature, measured above. The authority now consults
a Unicode database — Unicode 17.0.0's — for filesystem names only; the wire
contract still does not.

### Portability consequences

Only Linux resolves. macOS and native Windows build and test everything
platform-independent and refuse every root. WSL2 is Linux.

### Operational consequences

`kernel.db` moves to schema version 2 on first start; an M3 store migrates in
one transaction and records it. Binding a workspace root is an operator step,
once per workspace; moving a project means binding a new workspace.

### Explicit limitations

* Hard links: an inside name for an outside inode can be **read** (§7).
* Casefold and normalisation-insensitive filesystems are refused per name
  (`NAME_MISMATCH`) rather than supported; not exercised on a real casefold
  filesystem.
* A bind mount inside a workspace is not exercised (it needs privileges); the
  kernel flag and the real mount points `/proc`, `/sys`, `/dev` are.
* On a filesystem without birth times, a directory recreated at the root's
  path with a recycled inode number and device would pass the fingerprint.
  Deleting and recreating a workspace root is an operator action on the
  operator's own directory.
* The resolver lists every directory on the path. Resolution cost grows with
  directory size, bounded at 65,536 entries a directory.

## Alternatives considered

* **`std::fs::canonicalize`, `realpath`, then open.** Check-then-open by
  string: the textbook TOCTOU, and it follows symlinks by definition.
* **Normalise requests to NFC.** Looks up a spelling nobody sent; on ext4 that
  can be a different object. Refusing non-NFC input costs a client nothing it
  could legitimately need.
* **Trust the kernel's lookup without listing.** A casefold or
  normalisation-insensitive directory would silently map one spelling to
  another object's name, and the canonical path would then describe a name
  that is not the object's.
* **Refuse every file with `st_nlink > 1`.** Breaks pnpm, `git clone --local`
  and build caches, and does not stop an agent with a process from reading
  the original anyway. Refusing only modification is the part that protects
  something.
* **Hold one descriptor per run.** Does not survive the authority restarts
  M3d made normal, and keeps operating on a directory the operator may have
  moved away on purpose. Pinning by recorded identity and refusing a replaced
  path gives the same guarantee — never redirected — across restarts.
* **A component-wise fallback walker now.** It would be the resolver most
  users on older kernels, macOS and Windows got, with weaker guarantees and
  none of this evidence behind it; it needs its own ADR.
* **Mutable root bindings with revisions.** Every revision scheme needs a rule
  for live runs; "a different root is a different workspace" needs none.

## Revisit if

* A supported platform needs resolution without `openat2` — a fallback needs
  its own ADR and a second `Assurance` value.
* Workspaces with nested mounts or symlinked directories become a common
  support request.
* A hard-link attack is found in which planting the link grants a read its
  creator did not already have.
* `unicode-normalization` needs an upgrade to a newer Unicode version.
* M4b's handle transfer cannot keep the checked descriptor, or an
  identity-proved reopen relative to the retained parent, as the only way to
  the object.
