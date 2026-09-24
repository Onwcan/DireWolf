# ADR-0044: M4c — the filesystem tools: a canonical plan, every gate of every action, and atomic changes checked against the authorised object on both sides of the system call

**Status:** Accepted · **Date:** 2026-09-24 · **Amends:** [ADR-0036](0036-m3-authority-operations-and-the-capability-wire-form.md) (`ToolInvoke` and `CanonicalPreview` get a version 2: a closed sum of eight tools, a plan of canonical actions, and a mandatory idempotency key on the invocation), [ADR-0039](0039-durable-authority-state.md) (schema version 4: eight tools, a persisted retry class, an `UNKNOWN` outcome, tool idempotency keys, tracked staging directories; two audit kinds), [ADR-0043](0043-m4b-private-broker-channel-and-brokered-fs-read.md) (private protocol version 2; the broker's blast radius grows by the write permission an operator grants; the retry decision of §9 is made) · **Refines:** [ADR-0005](0005-tool-system.md) (the M4c core tools and their retry classes), [ADR-0018](0018-authority-broker-split.md) (the broker still decides nothing), [ADR-0037](0037-capability-specifications-and-canonical-authority-identities.md) (a scope may name a vacant path, for the verbs that create), [ADR-0042](0042-m4a-canonical-filesystem-resolution.md) (a vacant name is a checked parent and a validated component, a second type)

> **The name that is created, replaced, moved or removed is checked —
> immediately before the system call that changes it, and again after — to be
> the name the authority authorised under the parent directory it checked;
> and a crash never turns an effect nobody can prove into a second one.** A
> call becomes a plan of canonical actions; both gates decide every action;
> the invocation proceeds only if all of them allow, its intent durable first.
> Linux has no compare-and-swap of a directory entry against an inode, so the
> instant between the broker's last check and its change is **not** closed by
> the kernel: it is closed by the permission model, under which only trusted
> writers may change names in a write-enabled workspace (§3, §5). A change that
> reaches anything else there is undone and the undo proved — or, if it cannot
> be proved, the invocation is `UNKNOWN`. An effect whose outcome is not proved
> is recorded `UNKNOWN` and never performed again by the authority.

## Context

M4b ([ADR-0043](0043-m4b-private-broker-channel-and-brokered-fs-read.md))
built the private channel and one effect, `fs.read`, and left the rest of the
filesystem inventory — and the question of effects that are not idempotent —
to M4c. [TOOL_SYSTEM.md](../TOOL_SYSTEM.md) §3 lists the core filesystem tools:
`fs.read`, `fs.list`, `fs.search`, `fs.stat`, `fs.write`, `fs.patch`,
`fs.move`, `fs.delete`. [CAPABILITIES.md](../CAPABILITIES.md) §2 defines the
`fs` verbs `read`, `list`, `stat`, `write`, `create`, `delete` and
`exec_bit`. The two vocabularies are not the same thing: a tool is what the
runtime asks for, a verb is what a capability and a policy rule name.

M4c is the third of M4's five parts (ADR-0042 §1). It is the first milestone
in which a decision of the authority changes a user's files.

## Decision

### 1. Scope: seven tools, and what is excluded

M4c implements `fs.list`, `fs.search`, `fs.stat`, `fs.write`, `fs.patch`,
`fs.move` and `fs.delete`; `fs.read` exists (M4b). `fs.create` is a
capability verb only — there is no `fs.create` tool, and no `fs.mkdir`,
`fs.copy`, `fs.rename`, `fs.append`, `fs.chmod`, `fs.touch`, `fs.glob` or
`fs.replace`. **Excluded, deliberately:** moving a directory; recursive
listing, search or deletion; overwriting on move; appending; a patch of more
than one file; unified diffs; a pattern language in search; `fs.exec_bit`
(M4d); execution, secrets, the sandbox (M4d, M4e, M5); approvals (M6);
artifacts (M8); `QueryInvocationStatus` (M9).

### 2. Public protocol: version 2 of the tool messages

Version 1 (ADR-0043) is kept **exactly**: one `fs.read`, its own types, its
own closed enumerations. Version 2 is new message versions of the same
schemas, registered side by side (`registry::message(type, schema,
version)`), each version its own Rust type:

* **A call is exactly one of eight typed members** (`ToolCall`: `fs_read`,
  `fs_list`, `fs_search`, `fs_stat`, `fs_write`, `fs_patch`, `fs_move`,
  `fs_delete`). No tool name, no argument map; a ninth member, or two, is a
  protocol error.
* **A decision is a plan** (`ToolPlan`): every canonical action, each with its
  role, verb, canonical path, object state (`EXISTING`/`VACANT`), byte count
  and both gates' decision; the plan's effect is `ALLOW` only if every action's
  is.
* **An invocation carries an idempotency key**, mandatory in the envelope; a
  preview carries none. Its meaning is §7.
* **Wider vocabularies in new enumerations** — `FsRefusalReason` (with
  `PATCH_TOO_LARGE`), `FsFailureReason` (with `SHARED_DIRECTORY`),
  `FsDecisionReason` (with `OBLIGATION_UNENFORCEABLE`) — so version 1's closed
  enumerations still mean what they meant.

**A request is answered in its own version.** The response envelope's
`schema_version` is the version the body type belongs to, never the highest
the registry knows. A version-1 `fs.read` and a version-2 `fs_read` decide on
the same plan through the same code; only the spelling of the answer
differs. The one M4c decision version 1 has no word for — a rule that allowed
with an obligation this build cannot enforce (§9) — is spelled as version 1
spells `REQUIRE_APPROVAL`: `DENY`, `DENIED_BY_RULE`, the policy gate not
satisfied, attributed to the rule. A runtime choosing the older version is not
a way round a condition.

Results carry no content the runtime did not ask for: `fs.list` names and
kinds, `fs.search` offsets, `fs.stat` kind/size/link count/executable, an
`fs.write` its length and SHA-256, an `fs.patch` whether it applied and the
post revision, a move or delete nothing. Every bound is proved against one
frame (§12).

### 3. The broker's write permission model — ambient authority, stated

**The experiment came first** (`crates/dwkd-broker/tests/permission_model.rs`,
the real kernel, before any mutation was written): a directory descriptor,
`O_PATH` or open for reading, confers **no** right to change the names in the
directory. `mkdirat`, `openat(O_CREAT)`, `renameat2` (plain, `NOREPLACE`,
`EXCHANGE`) and `unlinkat` relative to a held descriptor are each checked
against the *caller's* write and search permission on the directory, exactly
as by path — `EACCES` without it. Listing through an already-open directory
descriptor is not rechecked (`getdents` on the held descriptor; reopening
`"."` would be). On the hosted job the same is proven across uids: the
broker's own uid, holding the checked parent's descriptor, changes nothing
in a workspace that grants it nothing (`WRITE_DENIED`), while it still
stats, lists, searches and reads through the descriptors it is handed.

So there is no "descriptor capability" for mutation to be had, and M4c does
not pretend there is. **Option A, an explicit operator-owned permission
model**, is the decision:

* **A read-only workspace** is M4b's posture: the broker's uid has no access
  to it at all. Every read-family tool works through the authority's
  descriptors; every mutation fails `WRITE_DENIED` having changed nothing.
* **A write-enabled workspace** is one the operator grants the broker's uid
  directory write and search permission on — conventionally a group holding
  the broker's user and the workspace owner, directories group-writable and
  setgid (`2770`). The product never grants it: nothing in DireWolf changes a
  workspace's ownership or mode, and the hosted evidence's grant is applied
  by the **test harness** to its own fixture and printed exactly.
* **That grant is ambient authority, and it is stated as such.** The broker's
  uid can change names in a write-enabled directory by path, with no
  authorisation at all — the hosted suite demonstrates it (`grant-is-ambient`).
  A compromised broker process can therefore create, replace, rename and
  remove names in every write-enabled directory while it is compromised. What
  the authorisation protocol guarantees is narrower and still worth having: a
  *correct* broker changes only the one name in the one directory it was
  handed, only after checking the object immediately before, and leaves no
  persistent change to any object it did not prove (§5). Where that is not
  enough, the answer is not to grant the write permission — or to wait for
  M5's sandbox.

**The same model is the concurrency contract.** No Linux primitive changes a
name only if it still binds a given inode (§5), so M4c does not claim to
defend a write-enabled directory against an **untrusted** concurrent writer:
it excludes one. In a write-enabled workspace:

* **the runtime's uid — the hostile identity of ADR-0043 — has no directory
  write permission** anywhere in it: it is not in the grant group and owns
  none of its directories. The hosted suite proves the runtime uid cannot
  create, rename or remove a name there (`runtime-uid-outside-the-grant`);
* **the operator and any other writer the operator admits to the group are
  trusted**, outside the adversarial boundary. The broker's checks after each
  change are robustness against a *trusted* concurrent change — the change is
  undone and the undo proved — not proof that no transient effect occurred;
* **a directory writable by every user is refused**, `SHARED_DIRECTORY`,
  changing nothing: its mode says a writer outside the trusted set could race
  the change. ACLs that grant write to other identities are not inspected;
  keeping them out is the operator's side of the contract.

**Not done**, because each would move or hide the trust rather than bound
it: running the broker as root, as the authority's uid, or with
`CAP_DAC_OVERRIDE`; a setuid helper; the authority performing the rename
itself (TX010, and §11); `chmod`/`chown` of a user's workspace by the product.
The three-identity CI job is unchanged in shape and gains the group.

### 4. The canonical plan: every gate of every action

A tool name is not a capability verb. The plan is derived in one place
(`state::plan`) from the call's type and what the resolver found — never read
from the request:

| call | actions (role, verb, `byte_count`) |
|---|---|
| `fs.read` | TARGET `fs.read` (`max_bytes`) |
| `fs.search` | TARGET `fs.read` (`max_scan_bytes`) |
| `fs.stat` | TARGET `fs.stat` (0) |
| `fs.list` | TARGET `fs.list` (0) |
| `fs.write`, existing target | TARGET `fs.write` (content length) |
| `fs.write`, vacant target | TARGET `fs.write`, TARGET `fs.create` (content length each) |
| `fs.patch` | TARGET `fs.read` (base length), TARGET `fs.write` (post length) |
| `fs.move` | SOURCE `fs.delete` (0), DESTINATION `fs.create` (0) |
| `fs.delete` | TARGET `fs.delete` (0) |

`byte_count` is the content the action moves through the broker — read,
scanned or written; a name or metadata moves none, and a policy's
`when.max_bytes` sees 0 for them. Each action requires
`<verb>:<canonical path>?no_symlink_targets=true`, plus
`max_bytes=<byte_count>` for an action that moves content.

**Both gates run for every action, without short-circuit, and all must
allow.** A creating write whose `fs.write` is allowed and whose `fs.create`
is not creates nothing; a move whose destination may not be created leaves
the source where it is. A denial records every action's decision, contacts
the broker zero times, mints no id and binds no key.

**A preview is the same plan.** `CanonicalPreview` runs the same locate,
resolution and plan builder, and stops: no id, no key, no intent, no
effect-capable descriptor, no broker. The evidence runs every tool's preview
against a tree snapshot and then invokes it: the snapshot is unchanged and
each invocation decides the plan its preview named, byte for byte.

The order, per invocation: fence and run (and key) → resolve every target,
existing or vacant, `O_PATH` only → the plan → every capability gate → every
policy gate → mint the id, bind the key, record the intent **and where its one
staging directory may be made** (§10), commit, `fsync` the audit record →
**only then** make the effect-capable descriptors → the broker → the outcome
(completed, failed, or unknown), durably → the answer. No SQLite transaction
spans resolution, the handoff or the broker.

### 5. Object contracts per tool, and what Linux can guarantee

| tool | object | hard link | mechanism |
|---|---|---|---|
| `fs.stat` | existing regular file or directory | allowed | `fstat` of the object's own `O_PATH` descriptor; kind, size, link count, executable bit |
| `fs.list` | existing directory | — | `getdents` through the directory opened for reading; not recursive; entries never opened or followed; sorted by name bytes |
| `fs.search` | existing regular file | allowed | `pread` in 64 KiB windows up to the scan bound; KMP, linear whatever the needle |
| `fs.write` | regular file, existing or vacant | **refused** (`MULTIPLY_LINKED`) | new file in the broker's staging directory, `fsync`ed with its entry, its record made durable, the target checked, then `renameat2(RENAME_EXCHANGE)` (replace) or `renameat2(RENAME_NOREPLACE)` (create), then `fsync` **both** directories the rename changed (§10) |
| `fs.patch` | existing regular file | **refused** | base proved by SHA-256 through the authority's readable descriptor; the result must hash to the post revision; replaced as `fs.write` replaces; the base re-proved **immediately before** the exchange and again after it |
| `fs.move` | existing regular file → vacant name | allowed (moves one name) | one `renameat2(RENAME_NOREPLACE)`; the source checked immediately before; the object at the destination proved to be the source after; both directories `fsync`ed |
| `fs.delete` | regular file, or empty directory | allowed (removes one name) | the target checked immediately before; renamed (`NOREPLACE`) into the staging directory, proved there, both directories `fsync`ed, marked, then `unlinkat`; every step durable before the next (§10) |

**What Linux guarantees, and what it does not.** `RENAME_NOREPLACE` is an
atomic compare on the **destination**: the name is created or renamed into
only if absent, in one step — so a creation, a move's destination and a
delete's staging are never over anything. **Nothing in Linux compares a
source name, or an exchanged name, with an expected inode in the same step**:
there is no inode compare-and-swap on a directory entry. M4c invents none. It
does the strongest checks there are, where they can be made:

* **immediately before the system call that changes the name** — no system
  call of the broker's in between — the name binds the authorised object by
  `(st_dev, st_ino)`; a replacement's target is still a regular file, singly
  linked, without a special bit, with the permission bits and group the new
  file was given; a patch's target (through the authority's own readable
  descriptor) still holds the base revision; a move's destination is vacant; a
  directory to delete is empty. A substitution before this check is refused
  with **no namespace change attempted** — the broker's unit tests prove the
  change's code path was never reached;
* **after it**, the object the change reached is proved again: the displaced
  object is the target, singly linked, still holding the base; the object now
  at a move's destination is the source; the object taken for deletion is the
  target. Only then is anything removed, and only what is held in the broker's
  own staging directory.

**Persistent versus transient.** If a writer substitutes the object in the
microseconds between the check before and the change — possible only for a
writer the permission model admits (§3) — the change reaches the substitute:
it is exchanged into the staging directory, renamed to the destination, or
taken. The check after sees it and **undoes the change** — exchanged back,
renamed back (`NOREPLACE`), put back (`NOREPLACE`) — proves the undo, `fsync`s
both directories it changed and answers `refused` (`OBJECT_CHANGED`,
`CONFLICT`): **no persistent change**. The undo follows the change directly:
the change that reached the substitute is never made durable first. For that moment the namespace *was* changed, and a
process looking then could have seen the new file under the name, or the name
gone. M4c claims no more than that: no persistent effect on an object nobody
authorised, within the permission model.

**An undo that cannot be proved is never an ordinary failure.** A failed
exchange back, rename back or put back — or one whose result cannot be
re-proved — is `indeterminate` (`RESTORE_FAILED`), and the authority records
the invocation `UNKNOWN`, never `FAILED`, never retried; the displaced or taken
object stays in the staging directory, which is retained and recorded (§10).
The broker's unit tests make each undo fail at a chosen instant and require
exactly this.

* **Never in place.** A replacement is a new inode; the name holds the whole
  old or the whole new content at every instant. No shared `/tmp`: the
  temporary file lives in `.dwkd-<invocation id>`, a `0700` directory the
  broker makes beside the name, opens without following anything, and proves
  its own (owner, mode, kind) before using. Its lifecycle — a durable record,
  tracking from the intent, reclamation — is §10.
* **Modes.** A created file is `0660` exactly, whatever the umask, never
  executable; in a setgid directory it takes the directory's group. A replaced
  file keeps its permission bits and its group — or the write is refused
  `ATTRIBUTES_NOT_PRESERVED`, changing nothing. Its owner becomes the broker's
  uid, and ACLs and extended attributes are **not** preserved (stated, not
  hidden). A setuid, setgid or sticky file is refused: no implicit privilege is
  ever created or carried.
* **Directories, overwrite, recursion.** Only `fs.delete` touches a directory,
  and only an empty one; `fs.move` moves only regular files; nothing overwrites
  on move (`TARGET_OCCUPIED`/`DESTINATION_EXISTS`); nothing recurses.
* **Symlinks and mounts.** Every path is resolved beneath the pinned root with
  `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS |
  RESOLVE_NO_XDEV)` (ADR-0042): a symlink anywhere on any path, in any tool,
  is `SYMLINK`, and a symlink itself cannot be deleted or moved through the
  tools. Both parents of a move resolve within one mount; were a rename ever
  to cross one it would be `EXDEV` → `UNSUPPORTED`. **There is no copy-and-
  delete emulation** (TX019), and a filesystem without `RENAME_EXCHANGE` is
  `UNSUPPORTED`, not emulated with a window.
* **Shared directories.** A directory whose mode lets every user write is
  refused `SHARED_DIRECTORY` before anything is made in it (§3).

### 6. Targets and names: existing, vacant, and what a scope means

**Two types, never one.** `Target::Existing(ResolvedResource)` is M4a's
checked object. `Target::Vacant(VacantResource)` is a name that does not
exist: its parent resolved beneath the root as a directory like any other
object; the name is one canonical component (NFC, no control, bidi or
invisible character, ≤ 255 bytes, not `.`/`..`); nothing is at the name; **no
entry of the parent is canonically equivalent to it**; and the parent still
binds where it was found. Its canonical path is the checked parent's and the
validated name — derived, not the spelling. Vacancy is re-proved at the
handoff (an occupied name is `TARGET_OCCUPIED` before anything is sent), and
the broker creates with `NOREPLACE`, so an object that appears in the name
meanwhile is never replaced.

**Three paths from text to authority, kept apart** (ADR-0043 §8):

| path | how | touches the filesystem |
|---|---|---|
| a **new declaration** (a request, a profile, a skill, the ceiling) | the production resolver beneath the session's pinned root → a canonical path | yes — the filesystem supplies the meaning |
| a **stored grant**, re-read (a replay, a query, an invocation's plan) | its canonical text, as the authority stored it, read back by the grammar and required to render to exactly itself (`scopes::rehydrate`, the one module TX017 lets name the reader) | **no** — never resolved, never re-minted |
| a **tool's target**, at invocation | the production resolver again → the object checked *now*, compared by canonical path against the frozen grant | yes |

So a stored grant neither gains nor loses authority when the filesystem
changes: after its object is deleted it re-reads identically; a new admission
of the deleted path is withheld; an invocation on it fails resolution
(`NOT_FOUND`), nothing recorded; another object created at the same path is
resolved afresh by the next invocation — the order names the new inode —
under the same grant, nothing re-minted. An admission replay under its active
key is answered from the record **before any lookup**. The evidence measures
lookups directly — a per-thread count of every root pinning and resolution:
zero for a replay and for a re-read grant, before and after the deletion, and
some for a new declaration and for a tool target. The count is **test
observation, not an interface**: it is compiled only into the authority
crate's own unit tests (`#[cfg(test)]`), where the proof runs
(`src/state/lookup_tests.rs`); no build a user runs contains it.

**Admission resolves six verbs** — `fs.read`, `fs.list`, `fs.stat`,
`fs.write`, `fs.create`, `fs.delete` — through the same resolver; a new
declaration never means its spelling (TX017). `fs.exec_bit` stays
`UNRESOLVED_RESOURCE` (M4d).

| verb | a concrete scope path must |
|---|---|
| `fs.read`, `fs.list`, `fs.stat`, `fs.delete` | exist: a scope naming nothing covers nothing |
| `fs.write`, `fs.create` | exist, **or** be vacant beneath an existing directory |

A path is probed for vacancy only if some declaration naming it is for a verb
that may name a vacant one; otherwise it resolves exactly as M4b resolved it,
and a missing object is `NOT_FOUND` in the admission record. A scope covers
its path and every descendant, compared component by component: the evidence
shows `fs.create:/workspace/out.txt` covering exactly that name,
`fs.create:/workspace/src` covering `src/new.rs`, neither covering `out.txtX`
or `srcX`, a scope with a missing parent withheld, and `/workspaceX` not a
workspace path at all. A scope whose meaning is unstable covers nothing.

**`fs.list` names.** The broker returns the first `max_entries` names in byte
order, as bytes (hexadecimal on the private channel); the authority applies
the canonical grammar to each and to the set: a name a canonical path can name
is emitted, one it cannot — not UTF-8, not NFC, a control/bidi/invisible
character, or canonically equivalent to another entry — is **counted**
(`unaddressable`) and never rewritten or emitted lossily. `complete` says
whether every entry was examined. A directory with more than 65 536 entries is
refused, not listed in an order the directory chose.

### 7. Durable state: retry classes, keys, and `UNKNOWN` (schema 4)

**Retry classes are fixed per tool** (RELIABILITY.md §1): `fs.move` and
`fs.delete` are `NON_RETRYABLE`; every other tool is `RETRY_SAFE` — the read
family has no effect, a whole-content write converges, and a patch recognises
its own post revision (`ALREADY_APPLIED`). A `CHECK` ties the class to the
tool in the store.

**A key names one invocation, for ever.** A version-2 invocation's key is
bound, scoped to the caller and session, in the transaction that records its
intent; a second invocation with it is refused `IDEMPOTENCY_KEY_REUSED`
before anything is resolved or sent — whatever it asks for. A refused or
denied request binds nothing (nothing was performed). The binding stores a
digest of the run and the canonical call, for M9's `QueryInvocationStatus`,
which M4c does not implement: a runtime's retry of a retry-safe tool uses a
new key.

**Schema version 4** rebuilds `tool_invocation` in one migration transaction
(renamed aside, created, every row copied, the old table dropped with its
triggers — a version-3 row is a completed or ended `fs.read`) and adds
`tool_idempotency` and `tool_staging`:

* eight tools; the retry class; the target's object state and identity (a
  vacant target's parent's); a move's destination path and parent identity;
  the largest content bound of the plan;
* states `INTENT`, `COMPLETED` (with a per-tool completion class —
  `CREATED`/`REPLACED`, `APPLIED`/`ALREADY_APPLIED`, … — and the content bytes
  moved, never above the bound), `FAILED` (a failure code), `INTERRUPTED`
  (only a tool without effect: the process ended between intent and outcome),
  and **`UNKNOWN`** (only a tool with effect: something may have changed and
  nothing proves what);
* `tool_staging`: for a write, a patch or a delete, the one staging directory
  it may make — recorded **with the intent**, settled once (§10);
* the intent immutable, the ending written once, a staging record's location
  immutable and its settlement written once, nothing deleted — by trigger,
  verified by the exact-schema check. `UNKNOWN` is a state, not a failure
  code, and is never rewritten.

The audit gains two kinds: `tool.outcome_unknown` (live, with the broker's
detail, or `cause: restart`) and `tool.staging_settled` (§10).

**Reads keep M4b's durable intent.** A tool without effect could skip the
`fsync`ed intent — a crash can lose nothing but a result nobody received —
but the read family keeps it: one order for every invocation, so that no
effect-capable descriptor, readable or writable, ever exists before its
intent is durable, and so that an interrupted read is recorded rather than
silent. The cost is one transaction with `fsync` per read, stated.

### 8. Private protocol version 2

`PROTOCOL = 2`; a version-1 peer is refused by its hello. One strict message
type per operation, decoded by its `kind`, the descriptor count fixed by the
kind, every descriptor's role and open mode fixed:

| kind | descriptors, in order |
|---|---|
| `broker.fs_read`, `broker.fs_search` | the file, open for reading |
| `broker.fs_stat` | the object, `O_PATH` |
| `broker.fs_list` | the directory, open for reading |
| `broker.fs_write`, `broker.fs_delete` | the parent directory, open for reading |
| `broker.fs_patch` | the parent directory; the file, open for reading |
| `broker.fs_move` | the source's parent directory; the destination's |
| `broker.fs_reclaim` | the directory holding the staging directory, open for reading |

Authorisations carry only what the broker must enforce: identities to
re-prove, bounds, and — for a name-changing operation — **one validated leaf
name** relative to a transferred directory (`LeafName`: no `/`, no NUL, not
`.`/`..`, ≤ 255 bytes, re-validated on decode). Never a path, a root, a policy
or a capability. At most two descriptors are ever held while the count is
judged; any mismatch closes all of them unused (`DESCRIPTOR_COUNT`). An
authorisation is at most one DWKP frame (it carries a write's content); a
patch authorisation inserting more than the inline bound (§12) does not
decode.

**Three answers.** `done` (the operation's own result, exactly one member);
`refused` — **no persistent change**: refused before acting, or the change
undone and the undo proved (§5); `indeterminate` — something may have changed
and the broker cannot prove the final state (`RESTORE_FAILED`,
`DURABILITY_UNCONFIRMED`, `EFFECT_UNCONFIRMED`). The authority treats a
failure as provably without effect only if the authorisation never left or the
broker said `refused`; anything else after sending is ambiguous (§10).

TX015 is refined narrowly: `exchange/mutate.rs` and `exchange/staging.rs` may
call `openat`, and only TX019's rules bind them — no `std::fs`, no path type,
no `CWD`, no `openat2` resolution, no plain `open`, no copy/splice/link
fallback. TX018 confines the `sha2` digest to `mutate.rs`. TX016 forbids the
cognition side from naming any `broker.fs_*` kind.

### 9. Obligations, and what the audit record holds

**An obligation this build cannot enforce is not a permission.** The authority
enforces two, where they hold by construction: `read_only_workspace` on an
action that changes nothing, and `max_output_bytes=N` on an `fs.read` bounded
at most `N`. Any other obligation denies the action, `OBLIGATION_UNENFORCEABLE`,
attributed to the rule. The shipped `balanced` pack attaches
`require_artifact_capture` to `fs.write`/`fs.create` (M8), so under it no
write is performed; `REQUIRE_APPROVAL` still denies (M6). Deployments that
want writes supply an operator policy — as M4b's did for reads.

The audit records the plan — every action's capability, gates, rule and
obligations — the identities, the key, the request digest, the staging
directory's name and parent, and the outcome's counts and digests: a write's
length and SHA-256, a patch's post revision, a listing's counts, a search's
match count. **Never content**: not the written bytes, not the patch's
insertions, not names listed, not search matches. The evidence scans
`audit.log` for the content and its hexadecimal and finds neither.

### 10. Crash windows, staging, races, and restart

| window | the authority's record | the workspace | the staging directory |
|---|---|---|---|
| A — intent durable, nothing handed over | `UNKNOWN` (effect tool) / `INTERRUPTED` (read family) on restart | unchanged | none; its record settles `CLEARED` |
| B — descriptors made, nothing sent | as A | unchanged | none |
| C — the broker acted, the outcome not recorded | as A | changed | cleaned by the broker; `CLEARED` |
| D — outcome durable | `COMPLETED`/`FAILED`, kept | as recorded | `CLEARED` |
| the broker aborts before its record is durable | `UNKNOWN` (live) | unchanged | the broker's new file only: **removed** |
| … after the record, before the change | `UNKNOWN` | unchanged | record and the new file: **removed** |
| … a replacement after its exchange | `UNKNOWN` | new content | the displaced file: **retained** `DISPLACED` |
| … a creation after its rename | `UNKNOWN` | created | the record alone: **retained** `EVIDENCE` |
| … a move after its rename | `UNKNOWN` | moved | none (a move stages nothing) |
| … a delete after staging | `UNKNOWN` | the name gone | the object: **retained** `TAKEN` |
| … a delete after unlink | `UNKNOWN` | removed | the mark: **retained** `EVIDENCE` |

**Restart performs nothing.** The next incarnation ends every open intent in
its start-up transaction — `INTERRUPTED` for a tool without effect, `UNKNOWN`
for one with — and sends the broker no invocation (measured: a counting
channel sees zero). A live ambiguous answer is `UNKNOWN` on the wire
(`OUTCOME_UNKNOWN`). **The authority never retries anything.** The evidence
shows the runtime's retry, with a new key, converging for every retry-safe
window (`fs.write` rewrites the same content; `fs.patch` answers
`ALREADY_APPLIED`) and, for a move or delete, finding its effect already done
(`NOT_FOUND`) and performing nothing.

**The staging lifecycle.** A write, a patch or a delete makes at most one
staging directory, `.dwkd-<invocation id>`, beside the one name it changes:

* **tracked from the intent** — `tool_staging` records where it will be (the
  checked parent's canonical path and identity), the name, the operation and
  the object authorised, in the intent's transaction, before any descriptor
  that could create it exists. So no staging directory is ever untracked;
* **a durable record before any effect** — the broker writes `record` (the
  invocation, operation, name, target and the new file's identity) into the
  staging directory and makes it durable — its content, its entry in the
  staging directory, and the staging directory's own entry in the workspace
  parent — **before any workspace name changes**; a delete also durably marks
  `taken` before it unlinks what it proved. The record is removed only after
  the effect, if any, is durable and everything the operation took from the
  workspace is durably gone. A staging directory without a complete record
  therefore holds nothing of the workspace's (at most the broker's own new
  file); with one, what else it holds says how far the operation got.
  Clean-up removes entries in the order that keeps every intermediate state
  truthful, each removal durable before the next;
* **every namespace change durable before the next** — a file's `fsync` makes
  its content durable, not the entry that names it. After every system call
  that creates, removes, renames or exchanges a name, the broker `fsync`s
  **every directory whose entries changed** before its next namespace change
  and before it answers:

  | transition | directories changed | made durable |
  |---|---|---|
  | A. make `.dwkd-<invocation>` | the parent | the staging directory (its mode), then the parent |
  | B. write `record` | the staging directory | the record, then the staging directory |
  | C. write the new file | the staging directory | the file, then the staging directory |
  | D. the exchange or rename that is the effect | the parent and the staging directory — a move: both parents | both, once the check after it passes |
  | E. an undo (exchange back, rename back, put back) | the same two | both, before the record is removed |
  | F. a delete's object taken into staging | the parent and the staging directory | both, before `taken` is written |
  | G. removing an entry of the staging directory (clean-up, reclamation) | the staging directory | it, after each removal |
  | H. removing the staging directory | the parent | the parent |

  A change is never made durable before the check that follows it, and an
  undo follows the change it undoes directly, so a change that reached an
  object nobody authorised is never persisted first. A directory that cannot
  be made durable after an effect is `indeterminate` (`UNKNOWN`); anywhere else
  the operation stops and leaves the staging directory to be reclaimed. **What
  is proved, and what is not:** this order of system calls is implemented,
  traced on every operation the broker's unit tests run, and mutation-tested;
  recovery from a **process** crash at every point is exercised on the real
  channel; recovery from a **physical power loss** is not exercised — whether
  the device beneath the filesystem honours `fsync` is outside what DireWolf
  can prove. The broker holds no SQLite transaction (it has none), and the
  authority holds none while the broker works;
* **settled once** — `CLEARED` when the broker's answer proves nothing is left
  (`done` without debris) or nothing was sent; otherwise it stays `EXPECTED`
  and the authority asks the broker to **reclaim** it (`broker.fs_reclaim`):
  after the invocation's outcome is recorded, after later effect invocations
  of the same run (at most four), and at start-up (at most 64), **only for
  invocations whose outcome is recorded** — never a live one's. **The
  authority re-pins, it never trusts a path**: `tool_staging` holds the
  parent's *logical* canonical path and identity, not a host path; the
  authority reopens the workspace's root binding — immutable, a different root
  is a different workspace — and proves it by its M4a fingerprint (device,
  inode, birth time), refusing a symlink at the recorded path; resolves the
  recorded parent beneath that pinned root one component at a time; and
  requires it to be the directory recorded, by identity. A root renamed away,
  replaced, or redirected by a symlink — even to the original — or a parent
  replaced beneath it, hands the broker nothing: the record stays `EXPECTED`,
  and whatever is found at the old path is never touched. No pinned root
  outlives a call, so an original root renamed elsewhere is out of reach until
  the operator puts it back at its recorded path; then it is recognised by its
  fingerprint and reclaimed. The broker opens `.dwkd-<id>` relative to the one
  directory it is handed, without following anything — it has no path to
  reopen — and requires it to be its own (owner, mode `0700`) and its record
  to name exactly that invocation, operation, name and target; then:
  * **removed** (`REMOVED`) if it provably holds only its own uncommitted data
    — no complete record, or a record and the new file it names, or a delete's
    record with nothing taken;
  * **retained** (`RETAINED`), untouched, if it holds a workspace object (a
    displaced file, `DISPLACED`; a taken object, `TAKEN`), the evidence that
    the effect happened (`EVIDENCE`), or anything it cannot account for
    (`UNEXPECTED`). The record gets what it holds and the held object's
    `(device, inode)`, and a `tool.staging_settled` audit record says the same:
    the operator — and M9's reconciliation — find the retained object by the
    invocation, and the invocation stays `UNKNOWN`;
  * `CLEARED` if absent; `FOREIGN` — untouched — if the name is not the
    broker's (a file, a symlink, another owner or mode).
* **never by spelling** — a reclamation names exactly one invocation's
  directory; an unrelated `.dwkd-*` directory, or one spelled for an
  invocation the authority never minted, is never looked at;
* **bounded** — at most one per invocation, every one on disk tracked; the
  evidence injects six crashes in a row and finds exactly as many directories
  as tracked records, the pre-effect ones removed by the next sweep and the
  retained ones still named by theirs. A normal success or refusal leaves none.

**Races.** Between the authority's handoff and the broker's action — the
widest window a concurrent writer of the workspace has, were the permission
model to admit one — a swapped target, an occupied vacant name, an occupied
destination, a swapped move source, a swapped deletion target, an empty
directory swapped for a full one, an in-place rewrite of a patch target, a
target swapped for a symlink, and a parent directory renamed away: in every
case the broker's check immediately before its change refuses it, the
substitute survives exactly as left, and the invocation is `FAILED` with no
change — except the last, where the broker changes the checked directory,
wherever it now is, and not the new one. **At chosen instants of the broker's
own sequence**, its unit tests substitute through a test-only race point and
record which points were reached: a substitution before the last check is
refused with the change never attempted; a substitution after it — the window
Linux cannot close — is changed and then undone, proved, `refused`, with the
transient change recorded as such; a creation or a move destination taken
after the check is refused by `NOREPLACE` with no transient change at all;
and an undo made to fail is `indeterminate`, its object kept.

### 11. Result trust, and the broker's blast radius restated

Read-family results — bytes, names, offsets, metadata — raise the run's taint
to `LOCAL_UNVERIFIED` before they reach cognition; acknowledgements of changes
do not (a patch's outcome is a comparison against digests the runtime itself
stated). **The authority performs no filesystem effect**: it resolves, opens
for the handoff, and records; every change — every reclamation included — is
the broker's.

This amends ADR-0043 §11 for M4c: a compromised broker has, besides M4b's, (i)
the write permission the operator granted its uid — ambient over every
write-enabled directory (§3); (ii) the parent-directory descriptors it is
handed while compromised, which grant nothing its uid lacks; (iii) the
ability to lie about what it did, bounded by the authority's checks (a
delivery of the wrong shape is a protocol failure for a read, and `UNKNOWN`
for a change; a reclamation's answer must agree with itself); (iv) the ability
to leave, or remove, staging directories — nothing its ambient grant does not
already allow. It still has no policy, grant, audit log, `kernel.db`, DWKP
endpoint or runtime reach.

### 12. Bounds, dependencies and the TCB

Content inline, one frame, no spill (artifacts are M8):

| bound | value | why |
|---|---|---|
| DWKP frame body | 1 048 576 bytes | ADR-0032 — **unchanged** |
| `fs.write` content | 262 144 bytes | 524 288 hex characters, half the frame |
| `fs.patch` file, before and after | 1 048 576 bytes | the file never crosses DWKP |
| `fs.patch` edits | 64 | |
| `fs.patch` inserted bytes, **all edits together** | 262 144 bytes (`MAX_PATCH_INSERT_BYTES_TOTAL`) | 524 288 hex characters; one byte more is `PATCH_TOO_LARGE`, refused before anything is resolved or recorded |
| `fs.patch` deleted bytes | not separately bounded | a range of a ≤ 1 MiB base, crossing as two integers |
| `fs.patch` path | 384 characters; ≤ 2 306 bytes encoded | six bytes a character at worst, with quotes |
| `fs.patch` request, everything but inserts | ≤ 16 384 bytes (`MAX_PATCH_REQUEST_OVERHEAD_BYTES`) | envelope, path, revisions, 64 edits' numbers and punctuation |
| `fs.patch` request, encoded | ≤ 540 672 bytes (`MAX_PATCH_REQUEST_ENCODED_BYTES`) | leaves ≥ 507 904 bytes of the frame (`PATCH_FRAME_MARGIN_BYTES`) |
| a listing | ≤ 512 entries of ≤ 255 characters | the worst listing the wire admits is proved to fit |
| a search | ≤ 16 MiB scanned, ≤ 1024 offsets, needle ≤ 1024 bytes | |
| a plan | ≤ 4 actions | |

The patch bound replaces an earlier, unproved one: 64 edits each carrying a
full-width insertion could not have fitted one frame. `tests/dwkp_v2.rs`
builds the largest patch request any decoder accepts — every field at its
widest, the whole insertion bound — and the largest a patch the authority
accepts can be, and encodes each **whole envelope**: each fits under the
derived bound, and so under the frame with the stated margin. The smallest
request past the bound decodes and is refused `PATCH_TOO_LARGE` end to end,
nothing recorded, the broker never contacted. The frame was not enlarged to
make anything fit. Private messages are bounded by one frame, read from the
header before a body byte is buffered.

**The authority's closure is unchanged** — no dependency, no feature; the
`rustix` it already uses provides `renameat_with`, `mkdirat`, `unlinkat`,
`fchmod`, `fchown`, `fsync`, `Dir`. ADR-0019 is not amended. **The broker
gains `sha2`**, the same pinned pure-Rust crate and features the authority
already links, for patch revisions only (TX018). Zero `unsafe` anywhere: every
syscall is `rustix`'s safe API; no FFI, no `CMSG` arithmetic, no external
command (TX010 in the authority, TX013 in the broker).

### 13. Evidence

`make filesystem-operations-evidence` (Linux; a mandatory hosted CI job,
required by the aggregate check) runs, and requires every case of:

* **the released daemons, end to end** — every tool; previews against a tree
  snapshot and the preview/invoke differential; compound denials (a creating
  write where creation is denied, a move to such a destination, a rule's
  denial, an approval rule, an unenforceable obligation, a missing
  capability — zero broker contact, no key bound); idempotency keys; hard
  links per operation; symlinks on every path of every tool; listing names;
  search bounds; `fs.create` scope semantics; version 1 answered in version 1;
  no audit content; every staging record settled; the inline patch bound, one
  byte over and exactly at it; descriptors of both daemons stable over 150
  operations;
* **in process, on the real channel** — the race campaigns R1–R9; the crash
  campaigns A–K (authority crash points; debug-broker crash points,
  `DWKD_BROKER_CRASH_AT`, compiled only into debug builds), each with its
  staging directory's settlement; the staging campaigns (four pre-effect
  crashes removed, six repeated crashes bounded and tracked, directories
  spelled like the broker's never touched, and reclamation against a root
  renamed and replaced, a symlink at the root's path, a lookalike in a
  replacement root, the original root restored, and a parent replaced beneath
  the root); and the stored-grant paths of §6;
* **inside the authority crate** — the lookups of §6 counted, by a counter
  that exists only in its unit tests;
* **at chosen instants of the broker's own sequence** — substitutions before
  and after the last check of every operation, undos made to fail, a shared
  directory, and reclamation of every staging state (§10);
* **the durability order** — the exact sequence of namespace changes and
  `fsync`s for each transition A–H of §10, and, on every operation the
  broker's unit tests run, a check that no change follows one not yet durable
  and no answer but `indeterminate` leaves one; the checker is itself tested
  against broken sequences. The order of system calls — not a power cut;
* **the patch frame** — the largest decodable and the largest valid patch
  request, each encoded whole, with its size and margin;
* **the broker against a hostile authority-side peer** — every M4b case, and
  for version 2 a file where a directory must be, an `O_PATH` directory, the
  wrong directory, two descriptors for one, one for two, a readable descriptor
  where `O_PATH` must be, a patch's descriptors reversed, a deletion naming
  another object, a reclamation given a file, two directories or the wrong
  one: each refused, nothing changed, nothing staged;
* **the permission experiment**, locally on the real kernel, and on **three
  identities** — the runner as the authority, a broker user and a write group
  the job creates, `nobody` as the runtime: no grant → `WRITE_DENIED` and
  observation through descriptors; the harness's grant → every operation,
  owner and mode and group as §5 says, only where granted, the grant ambient,
  the runtime's uid outside it.

Without the identities the three-identity half is **NOT EXERCISED** and the
command fails after running everything else.

### 14. Platforms

**Linux only**, as M4b: the resolver is `openat2`, the channel needs
`SO_PEERCRED` and `SCM_RIGHTS`, and the operations need `renameat2` with
`RENAME_EXCHANGE`/`RENAME_NOREPLACE`. Elsewhere every tool is refused
`UNSUPPORTED_PLATFORM` or fails `BROKER_UNAVAILABLE`; both daemons still build
and test on macOS and Windows.

### 15. What M4c does not do

The exclusions of §1; no `QueryInvocationStatus` (a key is bound and never
answered until M9); no approvals, so `REQUIRE_APPROVAL` denies; no artifacts,
so `require_artifact_capture` denies; no sandbox — every action is `HOST`; no
home anchor; no copy-and-delete, no in-place write, no recursion; no inode
compare-and-swap, because Linux has none; no automatic removal of a retained
staging directory. No M4 evaluation is activated. **M4 is incomplete.**

## Consequences

**Security.** Mutation exists, and only behind: the fence, the resolver for
every target, a plan whose every action passed both gates, enforced
obligations, a durable intent and a bound key, re-proved handoffs, a
kernel-identified broker that checks the object immediately before and after
its change, atomic renames, durable directories, and a durable outcome — or an
honest `UNKNOWN` that nothing retries. Against a writer the permission model
excludes, no persistent change reaches an object nobody authorised; against a
trusted writer that races the change, it is undone and the undo proved, or the
invocation is `UNKNOWN` — and the transient change is stated, not denied.

**Negative.** A write-enabled workspace gives the broker's uid ambient write
authority there (§3), and replaced files change owner and lose ACLs and
extended attributes. The concurrency guarantee rests on the operator keeping
untrusted writers out of the group and the ACLs. `balanced` performs no write
until M8. A retry of a retry-safe tool is the runtime's decision, with a new
key, until M9 answers status by key. Every mutation costs a staging directory,
about ten `fsync`s — every directory it changes, after every change — and two
transactions; a refusal or an ambiguous outcome costs a reclamation. An inline patch inserts at most 256 KiB. Resolution
precedes the gates, so a run still learns whether a path resolves (ADR-0043
§7), now for vacant names too.

**Operational.** Operators who want writes create the group, grant it on the
directories that may change, keep the runtime's uid and every untrusted
identity out of it, and supply a policy that allows the verbs without
obligations this build cannot meet. A `.dwkd-*` directory a crash leaves is
tracked in `tool_staging` from the moment its invocation was authorised;
disposable ones are removed by the next sweep; a retained one is named, with
what it holds and the held object's identity, by its record and its
`tool.staging_settled` audit record.

## Alternatives considered

* **The authority performs the rename.** It holds the descriptors and has the
  permission. It would make the authority an executor of effects, the one
  thing ADR-0018 exists to prevent, and put the user's files in the
  authority's blast radius. Rejected.
* **Run the broker as root, or with `CAP_DAC_OVERRIDE`, or a setuid helper.**
  Every file on the machine in the broker's blast radius, to save an operator
  a group. Rejected.
* **Descriptor-only mutation.** Does not exist on Linux (§3); claiming it would
  be false.
* **Claim an inode compare-and-swap.** Linux has none: `RENAME_EXCHANGE` swaps
  whatever the names bind, and nothing conditions a rename on a source inode.
  A check-then-exchange presented as atomic would be a false guarantee that a
  passing race test could not make true. Rejected for the checks before and
  after, the undo, and the permission model's exclusion of untrusted writers.
* **Delete every `.dwkd-*` directory at start-up.** Deletes by spelling, and
  deletes the only copy of a displaced or taken object. Rejected for tracked,
  judged reclamation.
* **`fsync` the record alone, and one directory per change.** A file's `fsync`
  does not make its name durable, and an exchange changes two directories: a
  power cut could keep the effect and lose the record or the staging
  directory's entry, or keep a later removal and lose an earlier one, and the
  table of §10 would lie. Rejected for every changed directory, after every
  change. Its cost is stated above.
* **Reclaim by the stored host path.** Reopening where the workspace *was*
  follows whatever is there now. Rejected: the root is re-pinned by its
  fingerprint and the parent resolved beneath it by identity.
* **In-place write with `O_TRUNC`.** Not atomic, and writes through every hard
  link. Rejected; hard-linked targets are refused besides.
* **Unified diffs as the patch format.** A parser in the authority or the
  broker, and fuzzy context. Rejected for typed edits against a stated base.
* **Multi-file patch.** A sequence of renames is not a transaction; claiming
  atomicity would be false. Rejected.
* **Enlarge the frame to fit larger patches.** Changes every peer's bound for
  one tool. Rejected: the inline patch bound is derived from the frame.
* **Retry ambiguous changes automatically.** Turns one uncertain effect into
  two for a move or delete. Rejected: `UNKNOWN`, never repeated.
* **Widen version 1's enumerations.** Changes what a version-1 message means
  under a client that never asked. Rejected for version 2.
* **Ignore obligations** (as M4b did, harmlessly, for reads). A condition
  ignored is a permission broadened. Rejected; version 1 too.

## Revisit if

M5's sandbox can hold the broker's write authority to a per-invocation mount
(the ambient grant of §3 would end); Linux gains a rename conditioned on the
source inode; M8 lands (`require_artifact_capture` becomes enforceable and
content can spill); M9 answers status by key and reconciles retained staging;
a filesystem without `RENAME_EXCHANGE` must be supported; or directory moves
or recursive operations are needed.
