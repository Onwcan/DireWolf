# ADR-0039: Durable authority state — `kernel.db`, epoch fencing, admission, kernel-owned policy inputs, and an audit chain behind a transactional outbox

**Status:** Accepted · §8, §9 and §12 amended by [ADR-0040](0040-m3d-reconciliation-admission-across-tenures-and-undecidable-proposals.md) · **Date:** 2026-09-21 · **Amends:** [ADR-0019](0019-language-rationale-v2.md) (the authority now links SQLite's C and a SHA-256 implementation), [ADR-0035](0035-m3-authority-dependency-set.md) (the measured M3d closure, a corrected amalgamation size, and a build-only closure reviewed separately) · **Refines:** [ADR-0009](0009-storage-strategy.md) (the kernel's state gets a directory of its own), [ADR-0010](0010-event-model.md) and [ADR-0017](0017-observability-vs-audit.md) (the audit record format and hash chain), [ADR-0011](0011-session-concurrency.md) (lease holder versus subject; restart invalidation), [ADR-0028](0028-policy-input-ownership.md) (which producers of each policy input exist yet), [ADR-0036](0036-m3-authority-operations-and-the-capability-wire-form.md) (the four idempotency cases made durable, and two things the M3 wire cannot say)

> **Authority state must survive a crash without becoming ambiguous.**
>
> M3b made authority unable to widen and M3c made policy deterministic and
> fail-closed. Both are pure functions: they decide, and remember nothing. M3d
> is where the authority starts to *remember* — which epoch is current, who
> holds a session, which runs were admitted and with what, which policy was in
> force — and where every one of those memories has to survive a crash, a
> replay and a stale writer without turning into authority nobody granted.

## Context

[ADR-0009](0009-storage-strategy.md) specifies `kernel.db` as SQLite in WAL
mode, separate from `runtime.db`, quarantined on structural corruption, with no
abstraction layer. [ADR-0011](0011-session-concurrency.md) makes the kernel the
epoch authority. [ADR-0036](0036-m3-authority-operations-and-the-capability-wire-form.md)
§8 fixes the `AdmitRun` idempotency contract and assigns its durability to M3d.
[ADR-0028](0028-policy-input-ownership.md) requires every policy input to be
derived and stored kernel-side. [ADR-0010](0010-event-model.md) and
[ADR-0017](0017-observability-vs-audit.md) require a hash-chained, kernel-written
audit log that is a separate durable artifact from the database.

Two durable objects — `kernel.db` and `audit.log` — with no transaction spanning
them, a single-writer lease that must not be shared by a process that merely
has the same uid, and an idempotency key that must never be a way past the
fence: those are the three problems that decide the design.

M3d does **not** listen on a socket, authenticate a peer, execute anything,
resolve a filesystem resource or grant an approval. Those remain M3e, M4 and M6.

## Decision

### 1. One module owns the state; the pure cores never learn it exists

`crates/dwkd-authority/src/state/` owns `kernel.db`, `audit.log` and every
transaction. It calls M3b's lattice and M3c's evaluator; neither calls it, and
neither imports `rusqlite`. That direction is enforced as hygiene by two new
rules: **TX005** (no `rusqlite` and no `crate::state` in `capability/`,
`policy/` or `resource/`) and **TX006** (no SQL built with `format!`, and no
`std::net`, `std::process` or `std::env`, in `state/`). Both have violation
fixtures. Both are tripwires, not proofs.

The state layer uses `rusqlite` directly. There is no repository framework, no
ORM, no query builder and no portability layer; every statement is static text
in the module that runs it, and every value is a bound parameter.

### 2. The kernel's state lives in a directory of its own

`$DIREWOLF_HOME` is shared with the runtime, which writes `runtime.db` there.
A process that cannot write `kernel.db` but can write the directory holding it
can replace it by renaming another file over it. So the authority's state is a
**private directory** (`0700`, owned by the authority user) containing:

| file | role |
|---|---|
| `kernel.db` (+ `-wal`, `-shm`) | durable authority state, created `0600` by the authority before SQLite sees it |
| `audit.log` | the authoritative hash chain, `0600` |
| `authority.lock` | an exclusive OS file lock held for the life of the process: one authority per directory |
| `kernel.quarantined` | written **beside** the store, never in it, after structural damage |

Startup refuses a symlinked directory or file, a directory or file with any
group or other permission bit, a directory owned by another uid (found without
`libc` by creating an `O_EXCL` probe file and reading its owner), and a
quarantine marker. On Windows no ownership check is made: native Windows is a
reduced-assurance target ([ADR-0029](0029-packaging-runtime-first-decoupled-authority.md))
and emulating Unix ownership there would prove nothing.

**Nothing is ever recreated around a missing piece.** A new store is created
only when the directory holds no state at all. `kernel.db` missing beside a
surviving `audit.log` or WAL, `audit.log` missing beside a `kernel.db`, or an
emptied `kernel.db` beside a non-empty `audit.log`: each is refused, because
creating an empty store there would erase the state that constrains the runtime
— a fail-open.

Mode bits are necessary and not sufficient. The deployment claim is verified by
**attempting the writes as the runtime user** (`make authority-write-probe`,
§14).

### 3. SQLite, configured and read back

Every connection is opened without `SQLITE_OPEN_URI` (no query parameter in a
path can change how it opens), with `SQLITE_OPEN_NOFOLLOW` (a symlinked
`kernel.db` is refused), and with extended result codes. Each setting is set
**and read back**; a mismatch refuses the connection.

| setting | value | rationale |
|---|---|---|
| `journal_mode` | `WAL` | ADR-0009. |
| `synchronous` | `FULL` | an acknowledged transaction survives power loss as far as the storage stack honours `fsync`; under WAL the WAL is synced on every commit. |
| `fullfsync` | `ON` | macOS `fsync` does not flush the drive cache; `F_FULLFSYNC` does. No-op elsewhere. |
| `foreign_keys` | `ON` | security history uses `ON DELETE RESTRICT`. |
| `busy_timeout` | 5 s | handles contend through `BEGIN IMMEDIATE`; past the timeout, `Busy`, nothing done. |
| `trusted_schema` | `OFF` | a schema object may not call an unsafe-flagged function. |
| `mmap_size` | 0 | I/O errors arrive as error codes the store can classify, not as signals. |
| `DEFENSIVE` | on | refuses deliberately corrupting SQL (`writable_schema` and the like). |
| `NO_CKPT_ON_CLOSE` | on | closing never checkpoints; see §5. |

Left at SQLite's defaults and stated: `wal_autocheckpoint` (1000 pages),
`auto_vacuum` (`NONE`), cache and temp-store sizes.

Every table is `STRICT`: a column accepts only its declared type, the database
half of M3c's no-coercion rule.

### 4. One schema version, migrated in one transaction, verified exactly

`PRAGMA user_version` is the version; `PRAGMA application_id` (`0x4457_4B44`,
`DWKD`) marks the file as a kernel store. Both are written in the same
transaction as the schema they describe.

| found | outcome |
|---|---|
| empty database | create the current schema and the genesis state in one transaction |
| kernel id, older version | apply every later migration in **one** transaction; a failure rolls back completely |
| kernel id, current version | verify |
| kernel id, **newer** version | **refuse** (`FutureSchema`); nothing is written |
| kernel id with version 0, or objects with no id | **refuse** (malformed, or someone else's database) |

A store claiming the current version must contain **exactly** the objects this
build's DDL creates — every table, index and trigger, byte-identical SQL — and
nothing else. The expected set is read back from a scratch in-memory database
built from the same DDL, so it cannot drift from it. A dropped trigger, a
missing table, or an extra object refuses the store; a missing table is never
recreated. Startup also runs `quick_check` and `foreign_key_check`, requires
the three singleton rows (`store_meta`, `audit_head`, `audit_state`), and
recomputes every stored policy revision from its stored sources (§11).

**Append-only is enforced by the database.** Security history — the audit
chain's local copy, policy revisions and their sources, activations and
ceilings, agent-profile and skill revisions, admissions, grants, withheld
requests, run skills, idempotency records — has `BEFORE UPDATE` and
`BEFORE DELETE` triggers that abort. Current state changes, and its triggers
constrain how: a session's epoch row is never deleted and its epoch never
decreases; **a new lease tenure without a new epoch is refused**; a run that has
ended never becomes active; a run's taint never falls; origin, privacy and
workspace are fixed at admission; a workspace's sensitivity only rises; the
audit head advances one record at a time and each chained record must extend
it. These restate, independently, properties the Rust maintains.

Version 1 is the only version. The migration list exists so that version 2 is
an append to it, and a unit test shows a failing migration step leaves version,
id and schema exactly as they were.

### 5. Structural corruption poisons, quarantines, and never checkpoints

SQLite's extended result code decides — never its message. `SQLITE_CORRUPT` and
`SQLITE_NOTADB` are structural: the store is **poisoned** in memory for every
handle at once, a quarantine marker is written beside it, and every later
operation fails before touching a file. An `SQLITE_IOERR`, and any failure to
write or `fsync` `audit.log`, also poisons (a later `fsync` can succeed without
the earlier data being durable, so no retry is believed), without the marker:
the next start re-verifies everything from the files.

Closing a connection normally checkpoints the WAL into the main file — the
behaviour [ADR-0009](0009-storage-strategy.md) point 4 forbids after
corruption. Every connection therefore sets `NO_CKPT_ON_CLOSE`: dropping a
poisoned authority leaves `kernel.db` byte-identical, which a test checks.
While the store is healthy, SQLite's automatic checkpoint still runs during
commits. No WAL file is ever deleted by hand.

A quarantined store is refused on every start until an operator removes the
marker. The authority never removes it, never renames the store away, and
never creates a replacement.

### 6. Two identities: the subject that authenticated, and the connection that holds

**`AuthenticatedSubject`** is the stable identity of a peer — a Unix uid. It
scopes idempotency: a subject that reconnects must find the admission it made.

**`LeaseHolder`** is one live connection to one authority **incarnation**: a
counter in `kernel.db` every start increments, and a per-incarnation connection
number. It has no public constructor; the only way to obtain one is
`Authority::connect`, which mints a new one every call.

They differ because a new process with the same uid is **not** evidence that it
is the same single writer — the old one may be paused, or about to wake.
Handing it the live lease would put two writers behind one fencing token. So a
lease is held by a holder, and a new connection from the same subject waits for
release, expiry or a restart.

Neither is ever read from a DWKP message. **M3d authenticates nobody**: the
subject is whatever the in-process caller asserts, and in M3d the callers are
tests standing in for M3e's peer-credential bridge.

### 7. Leases and epochs

One row per session, never deleted, holding the current epoch and — while a
lease is live — its holder, subject and absolute expiry.

| `AcquireLease` finds | outcome |
|---|---|
| no row | epoch 1, held by the caller |
| held, unexpired, by another holder (including the same subject on another connection) | `LEASE_HELD` |
| held, unexpired, by **this** holder | re-issued at `epoch + 1`, fencing its own old epoch |
| held but expired, released, or invalidated by a restart | `epoch + 1`, held by the caller |

The epoch never decreases, never resets and never wraps. At `2^53 − 1` — the
wire's maximum — acquisition fails closed (`EpochExhausted`) and the session can
no longer be leased.

**The fence** — for `Heartbeat`, `ReleaseLease`, `AdmitRun`, `ReleaseRun` and
`QueryAuthority` — requires a live lease, the presented epoch equal to the
current one, the caller's holder and subject equal to the lease's, and an
expiry in the future. Any failure is `STALE_EPOCH`: one answer for all four,
carrying no current epoch, checked before anything else the operation does.

`ReleaseLease` of a lease the same holder already released at that epoch is
acknowledged (a retry indistinguishable from success, [ADR-0036](0036-m3-authority-operations-and-the-capability-wire-form.md)
§10); from anyone else it is `STALE_EPOCH`. A successful `Heartbeat` extends by
one TTL (default 60 s, bounded 1 s–10 min) and is not audited; a fenced one is.

**Authority restart invalidates every live holder.** The previous process's
connections no longer exist, so at startup every held lease becomes
`INVALIDATED` and every active run is reaped; epochs are untouched, and the next
acquisition of each session moves strictly past them. Whenever a lease ends —
released, expired and re-acquired, or invalidated — every active run admitted
under it is **reaped** (`REAPED`, audited): a run is fenced to the epoch it was
admitted under, and resuming means a new admission
([RELIABILITY.md](../RELIABILITY.md) §7).

**Clock.** Lease time is the authority's, through an injectable `Clock`. Expiry
is persisted as an absolute wall-clock millisecond so it means the same after a
restart. A backwards jump prolongs a lease; a forwards jump expires one early,
and the next holder gets a new epoch while the old is fenced — availability
lost, never exclusivity. Neither can make two holders current, because currency
is the epoch comparison inside one transaction. M3d does not resist an attacker
who controls the host clock.

### 8. `AdmitRun`: the fence, then the record, all in one transaction

In one `BEGIN IMMEDIATE` transaction:

1. **The fence.** A zombie with a valid old key gets `STALE_EPOCH`, never a
   replayed grant.
2. **The record**, keyed by `(subject, session_id, idempotency_key)` — a
   primary key, so SQLite enforces the scope. Same digest: the **recorded**
   `RunGrant`, reconstructed from immutable rows and checked against a grant
   digest recorded with it; no policy re-read, nothing re-minted, no row but
   the replay's audit record. Different digest: `IDEMPOTENCY_CONFLICT`,
   original untouched. A different subject is a different scope.
3. The profile (`UNKNOWN_AGENT_PROFILE` if the kernel holds none), the active
   skills, minting (§9), the kernel-derived policy inputs (§10).
4. Ids, then every row: run, run skills, grants, withheld requests, policy
   inputs, the idempotency record with the grant digest, and the audit record.
5. Commit; append and `fsync` the audit record; **only then** answer.

The bound request is the RFC 8785 encoding of the **decoded** request with
exactly `id`, `ts`, `correlation_id` and `causation_id` removed, hashed as
`SHA-256("direwolf.dwkp.admit_run.request.v1" || 0x00 || u64be(len) || JCS)`.
`schema_version`, `session_id`, `epoch`, `idempotency_key` and the payload are
bound.

**Retention: none.** Idempotency records are never garbage-collected in M3d.
A finite window reopens duplicate admission for a retry slower than it, and no
evidence yet says how slow a retry can be. Storage is recoverable; a duplicate
admission is not.

**Across an authority restart, a replay is unreachable — by the contract.** The
restart invalidates every lease, so the retry meets the fence; after
re-acquiring, the epoch is part of the bound request, so the same key with the
new epoch is a *different* request and is refused `IDEMPOTENCY_CONFLICT`. What
survives the restart is the record: the key can never admit a second run, and
the original admission — reaped, not deleted — remains exactly as it was. That
is the safe reading of [ADR-0036](0036-m3-authority-operations-and-the-capability-wire-form.md)
and [RELIABILITY.md](../RELIABILITY.md) §7 together, and M3d does not change
either. A caller that lost the response to a crash re-admits under a new key.

**A released run replayed** returns the same recorded `RunGrant` (ADR-0036 case
3) and stays released: a trigger forbids reactivation, `QueryAuthority` answers
`UNKNOWN_RUN`, and no row changes. The replay is a record of the past, not a
re-issue.

### 9. Minting: exactly as requested, or withheld with the term that refused it

For each distinct requested capability, in order:

```text
granted(r)  iff  r parses and resolves             -- else see below
            ∧   agent profile's declared set covers r    -- else NOT_IN_AGENT_PROFILE
            ∧   every active skill's declared set covers r -- else NOT_IN_SKILL_SET
            ∧   the mode ceiling covers r                  -- else ABOVE_PROFILE_CEILING
```

"Covers" is M3b's `CapabilitySet::covers`: one declared member contains `r`
whole, so no grant is assembled from two declarations. A granted capability is
`r` itself, canonicalised — never narrowed into something the runtime did not
ask for, never widened. Nothing unrequested is granted because a profile
contains it.

* A capability outside the kernel's vocabulary is `NOT_IN_AGENT_PROFILE`: no
  profile can declare it, so the first term refuses it.
* An `fs` or `process` capability names a resource only M4's canonicaliser can
  identify. It is withheld as **`NeedsCanonicalization`** — not
  `NOT_IN_AGENT_PROFILE`, which would be false when the profile declares exactly
  that, and not "malformed", which it is not. It has no wire reason (§12).
* **Parent grant**: `AdmitRun` has no parent field and every M3 admission is a
  root; the term is absent. `NOT_IN_PARENT_GRANT` is never produced.
* **No policy preflight.** A capability is authority to *attempt* a class of
  action; `AdmitRun` carries no action for policy to decide, and fabricating one
  would be deciding something nobody asked to do. `DENIED_BY_POLICY` is never
  produced. Policy decides at `QueryAuthority` (and, from M4, `ToolInvoke`).

**Active skills cannot be used to widen** ([ADR-0028](0028-policy-input-ownership.md)'s
finding). An agent profile carries **baseline skills** the kernel activates for
every run, named or not; the runtime's `skills[]` can only add to them. A named
skill the kernel holds no record of, or holds as `QUARANTINED`, contributes the
**empty** set — so everything is withheld `NOT_IN_SKILL_SET` — and is never read
as "no constraint". Skill *verification* (manifests, content hashes, trust assignment) is
M11a's; in M3d a skill record and its trust level come from the operator.

Agent profiles, skills and workspaces are kernel records installed through
`OperatorBootstrap`, an in-process API for the operator's tooling and for tests.
**No DWKP operation reaches it.** Profiles and skills are append-only revisions;
an admission records which revision it used.

The **mode** (`SAFE`/`BALANCED`/`POWER`) is kernel-wide operator configuration
— one per authority incarnation, with its capability ceiling — and is what
`RunGrant.profile` reports. An agent profile does not choose it.

### 10. Every policy input the kernel decides on, and where it comes from

`PolicyContext` for a live decision is built in exactly one place, from the
run's `run_policy_input` row and the active configuration flags. There is no
constructor from a request or from JSON, and no DWKP message carries any of
these fields — the decoder rejects each as an unknown member, which a test
drives through the real decoder.

| input | durable source | derivation in M3d | updated by | trusted producer |
|---|---|---|---|---|
| origin | `run_policy_input.origin` | `api` for every run: the only admission path is programmatic DWKP, and no attended channel exists — so every run is unattended, the restrictive direction | nobody (fixed by trigger) | the producer that tells interactive, scheduled and channel runs apart (gateway, scheduler, M6's approval channel): **deferred** |
| taint | `run_policy_input.taint` | `NONE` at admission — the kernel has delivered nothing to the run yet | `raise_taint` only: monotonic (`max`), audited, trigger-enforced; no clear, reset or set | tool results (M4), artifacts (M12), memory retrieval (M13): **deferred**; the interface exists and nothing calls it |
| privacy class | `run_policy_input.privacy` | `min(profile default, workspace ceiling)`; a session with no kernel-recorded workspace has unknown sensitivity, read as the strictest (`LOCAL_ONLY`) | nobody (fixed by trigger) | profile and workspace records: operator; workspace pinning by `(dev, ino)`: **M4** |
| workspace sensitivity | `workspace`, `session_workspace` | operator configuration: `PUBLIC`→`ANY`, `PRIVATE`→`VENDOR_OK`, `SECRET`→`LOCAL_ONLY`; only ever made stricter | operator bootstrap | operator: **exists**; binding sessions on the runtime path: deferred (M4/M8) |
| active skills and trust | `run_skill` | baseline ∪ named, trust from the registry record, unknown recorded as unknown | nobody (append-only) | registry records: operator; verification: **M11a** |
| configuration flags | `activation.allow_host_execution` | operator startup configuration | a new activation | **exists** |
| standing grant | none | always `Unavailable` | — | **M6** |
| path anchors | none | all unresolved — only `crate::resource` may build a canonical path ([ADR-0037](0037-capability-specifications-and-canonical-authority-identities.md)) | — | **M4** |
| artifact and memory trust/provenance | not persisted | not M3-relevant | — | M12, M13 |
| lease epochs | `session_lease` | kernel-issued | the kernel | **exists** |

[ADR-0028](0028-policy-input-ownership.md) is therefore **structurally** met —
nothing the runtime sends is a policy input, and every input has a kernel-owned
row — and **not end-to-end proven** for origin, taint and workspace binding,
whose real producers are later milestones. Where a producer is missing, the
derivation is the restrictive one.

### 11. Policy revision: content, stored, recomputed

```text
policy_revision = SHA-256( "direwolf.policy.revision.v1" || 0x00
                           || u64be(policy SCHEMA_VERSION)
                           || field(selected profile name)
                           || u64be(source count)
                           || for each source, in composition order:
                                field(logical source name) || field(source bytes) )
field(x) = u64be(len(x)) || x
```

Composition order is the chain `compose` resolves, extending profile first. A
source that is not part of the composition is refused. Logical names must be
representable as a wire `RuleSource`. No mtime, inode, absolute path or
installation time enters the revision.

The revision and its exact source snapshot are stored, immutable, and **every
start recomputes every stored revision from its stored sources**; a mismatch
quarantines the store. Activation — `(revision, mode, flags, ceiling)` — is an
append-only row; the latest is in force, an identical configuration reuses it,
and a changed one appends a new one, audited.

**Startup only.** The configured policy is loaded through M3c's strict loader
before anything touches the disk; if it does not load, **the authority does not
start** — no fallback to a shipped pack, a stored revision or an embedded
default. There is no file watcher and no in-process reload, so no decision can
see a half-installed composition. Because a restart reaps every active run, a
live run and the active revision always agree.

### 12. `QueryAuthority`, both gates, and what the M3 wire cannot say

After the fence and the run check (it must exist, be **active**, and belong to
this caller's subject, session and epoch — otherwise `UNKNOWN_RUN`, one answer
for never-existed, released, reaped and someone else's), both gates run,
independently, always:

| capability gate | policy | wire `effect` | wire `reason` | rule reported |
|---|---|---|---|---|
| covered | `ALLOW` | `ALLOW` | `ALLOWED_BY_RULE` | the allowing rule |
| not covered | `ALLOW` | `DENY` | `NO_CAPABILITY` | the allowing rule |
| either | `DENY` by a rule or postcondition | `DENY` | `DENIED_BY_RULE` | that rule |
| either | `DENY` by `default` | `DENY` | `DEFAULT_DENY` | `default` |
| either | `REQUIRE_APPROVAL` | `DENY` | `DENIED_BY_RULE` | the rule that required approval |
| — | outside the vocabulary | `DENY` | `CAPABILITY_MALFORMED` | `default` |

Both gate results are always reported. Internally the three-valued effect is
kept and audited; `REQUIRE_APPROVAL` fails the policy gate because nothing in
this build can obtain an approval, and on the wire it is `DENY` with the
approving rule's id and source ([ADR-0036](0036-m3-authority-operations-and-the-capability-wire-form.md)
§9). In practice every M3d run is `api`, so the shipped packs' unattended
postcondition narrows it to `DENY` first, and that postcondition is the rule
reported. `CAPABILITY_MALFORMED` cites the mandatory `default` rule because the
wire requires a rule and an unrepresentable action is refused by deny-by-default;
no rule predicate was evaluated against it.

**Two protocol gaps**, reported rather than papered over. The internal outcome
exists; the committed M3 wire has no truthful value for it, so the mapping
returns a `WireGap` instead of choosing an inaccurate reason:

1. **An `fs` or `process` resource M4 has not identified** — as a withheld
   capability in a `RunGrant`, or as a proposed action. None of the five
   `WithheldReason`s and none of the five `DecisionReason`s says "the kernel
   cannot identify this resource yet".
2. **A policy rule needing a value the action does not carry** — a rule with
   `when.ip_in` asked about a network action with no destination address, or a
   rule-side path whose anchor is unresolved. The policy decision is `DENY`
   with `UNRESOLVED_CANONICAL_INPUT`; `DENIED_BY_RULE` would claim the rule
   matched and said deny.

Both are reachable only by requests the runtime cannot yet usefully make: M3 is
not activated on the wire, and M4's canonicaliser is what makes both inputs
resolvable. **No schema is changed here.** M4 decides whether a remaining case
needs a new reason, with a `schema_version` bump, as ADR-0036 §10 provides.

A decision about a proposed action with a destination address records that
address in the audit record. That is the evidence M4 needs to hold the
connection to the address that was decided; **M3d binds nothing**, and makes no
DNS-rebinding claim.

### 13. The audit log and the outbox

**Format.** One record per line: the RFC 8785 canonical JSON of an object with
`v` (format 1), `seq`, `prev`, `ts_ms` (the authority's clock), `event`, the
event's fields, and `hash`. Integers only; every field set fixed by the code
that emits it; no secret, prompt, tool output or credential in any record.

**Chain.**

```text
C_n = JCS(record_n without "hash")
H_n = SHA-256( "direwolf.audit.record.v1" || 0x00
               || u64be(32) || H_{n-1}
               || u64be(len(C_n)) || C_n )
H_0 = 32 zero bytes; seq starts at 1 and is gapless
```

**Inventory.** Audited: `store.created` (always record 1), `store.opened`
(incarnation, leases invalidated, runs reaped, recovery counts),
`policy.installed`, `authority.activated`, the four operator configuration
events, `lease.acquired`, `lease.released`, `lease.refused` (`LEASE_HELD`,
`STALE_EPOCH`), `run.admitted`, `run.admit_replayed`, `run.admit_refused`,
`run.released`, `run.release_refused`, `run.reaped`, `authority.decision`,
`authority.query_refused`, `run.taint_raised`. **Not** audited: a successful
heartbeat (it grants nothing new; one record per renewal is telemetry) and a
`QueryAuthority` without a proposal (it decides nothing).

**Transactional outbox.** In the same SQLite transaction as the mutation, the
next sequence is allocated from `audit_head`, the record is built, chained and
inserted into `audit_chain`, and the head advances. After commit, every record
past `audit_state.flushed_seq` is appended to `audit.log` in order by the one
process-wide writer, the file is `fsync`ed, the in-memory durable mark moves,
and only then is the flush recorded in `kernel.db`. **Authority is returned
only after the `fsync`.** If the append or the `fsync` fails, the operation
fails closed and the store is poisoned; nothing is "logged later".

**Recovery** makes `audit.log` hold exactly `kernel.db`'s chain, or refuses:

| on disk after a crash | recovery |
|---|---|
| committed record not in the log (window C; E after power loss) | append from the outbox, `fsync` |
| a partial final record that is a strict prefix of the pending record (window D) | truncate only those bytes, append the record whole |
| complete records above the flushed mark (windows E, F) | **reconcile**: verify and match byte for byte; never append twice |
| trailing bytes that are not a prefix of the pending record, or with nothing pending | **refuse** |
| a complete record that differs from `kernel.db`'s, or fails verification | **refuse** |
| fewer complete records than the flushed mark | **refuse**: acknowledged records are missing |
| more complete records than the head | **refuse**: records nobody committed |

A refusal writes the quarantine marker.

**Verifier.** `verify_audit_log` checks syntax, canonical form, sequence
continuity, `prev` linkage and every hash, recomputed; it reports a torn tail as
a fault because on its own it cannot tell a crash from damage.
`verify_audit_against_store` adds the byte-for-byte comparison with
`kernel.db`'s copy and flushed mark, and accepts a torn tail only as a prefix of
the pending record. Both are read-only (`kernel.db` is opened read-only).
`dwkd-authority verify-audit <state-dir>` runs both.

**Tamper-evident, not tamper-proof.** The chain detects modification,
interior deletion, reordering, duplication, a wrong `prev`, a wrong hash and —
against the store — removal of acknowledged records and records nobody
committed. It does **not** detect an attacker who rewrites `audit.log` and every
copy of the head this host keeps (`audit_chain`, `audit_head`, `audit_state`)
together and consistently; a test demonstrates exactly that. Anchoring the head
off-host remains future operational work.

### 14. Ids, and the runtime-user probe

`run_id` and `cap_id` are UUIDv7 in the wire's own types: 48 bits of authority
time, then a 42-bit counter incremented in `kernel.db` **inside the transaction
that writes the row the id names**, then a 32-bit store instance fixed at
creation. [RFC 9562](https://www.rfc-editor.org/rfc/rfc9562) §6.2 permits a
counter in the random fields. No `uuid`, `rand` or `getrandom`: ids are
identifiers, not secrets and not capabilities — a `cap_id` proves nothing on its
own, and an unknown or foreign `run_id` is `UNKNOWN_RUN`. Uniqueness is
guaranteed by the counter and enforced by `UNIQUE` constraints; a collision
fails the whole transaction (tested by planting the next id). Counter
exhaustion fails closed.

`make authority-write-probe` creates a real state directory as the current user
and runs `tests/authority/runtime_write_probe.py` as `DW_PROBE_AS` through
`sudo -n -u`: open `kernel.db` and its WAL for writing, create a file in the
state directory, rename a file over `kernel.db`, truncate and append
`audit.log`, delete `kernel.db`, chmod the directory. Every one must be refused.
Where there is no second identity it reports **NOT EXERCISED** and fails; it
never reports a pass it did not earn. It lives outside the authority's decision
path and the authority never calls it.

### 15. The trusted computing base, measured

Measured on 2026-09-21 with rustc 1.98.1, from the workspace's own resolution
(`cargo tree -p dwkd-authority --edges normal`, `cargo metadata --locked`, and
`dwcheck closure --report`), not predicted.

**Linked (runtime): 20 third-party crates**, 15 of them new in M3d.

| crate | version | licence | for |
|---|---|---|---|
| `rusqlite` | 0.40.2 | MIT | kernel.db |
| `libsqlite3-sys` | 0.38.2 | MIT | **SQLite 3.53.2** (`3053002`), bundled C |
| `bitflags` | 2.13.2 | MIT OR Apache-2.0 | rusqlite |
| `fallible-iterator` | 0.3.0 | MIT/Apache-2.0 | rusqlite |
| `fallible-streaming-iterator` | 0.1.9 | MIT/Apache-2.0 | rusqlite |
| `smallvec` | 1.16.1 | MIT OR Apache-2.0 | rusqlite |
| `sha2` | 0.11.0 | MIT OR Apache-2.0 | SHA-256 |
| `digest` | 0.11.3 | MIT OR Apache-2.0 | sha2 |
| `block-buffer` | 0.12.1 | MIT OR Apache-2.0 | digest |
| `crypto-common` | 0.2.2 | MIT OR Apache-2.0 | digest |
| `hybrid-array` | 0.4.15 | MIT OR Apache-2.0 | digest |
| `typenum` | 1.20.1 | MIT OR Apache-2.0 | hybrid-array |
| `cpufeatures` | 0.3.1 | MIT OR Apache-2.0 | sha2 |
| `cfg-if` | 1.0.4 | MIT OR Apache-2.0 | sha2 |
| `libc` | 0.2.189 | MIT OR Apache-2.0 | cpufeatures, **aarch64 and loongarch64 only** |

plus M3c's five (`toml`, `toml_parser`, `toml_datetime`, `serde_spanned`,
`winnow`). `serde_core` is still not linked; `rustix` and `linux-raw-sys` enter
with M3e. No proc-macro crate.

**Build-only (executes while the TCB is built, not linked): 5**, reviewed in a
separate list, `[authority].allowed_build_third_party`:

| crate | version | licence | why |
|---|---|---|---|
| `cc` | 1.4.7 | MIT OR Apache-2.0 | compiles the amalgamation |
| `find-msvc-tools` | 0.1.13 | MIT OR Apache-2.0 | `cc` on Windows |
| `shlex` | 2.0.1 | MIT OR Apache-2.0 | `cc` |
| `pkg-config` | 0.3.34 | MIT OR Apache-2.0 | libsqlite3-sys default feature |
| `vcpkg` | 0.2.15 | MIT/Apache-2.0 | libsqlite3-sys default feature |

`pkg-config` and `vcpkg` come from `libsqlite3-sys`'s default
`min_sqlite_version_3_34_1` feature, which `rusqlite` does not let a dependent
turn off. With `bundled`, the build script takes the bundled path and consults
neither, but both are compiled into it, so both are listed. Build scripts also
run for two **linked** crates: `libsqlite3-sys` (drives the C compiler) and
`libc`.

**Native code.** The amalgamation is `sqlite3/sqlite3.c`: **269,376 lines,
9,507,037 bytes of C**, compiled into the authority's address space.
`#![forbid(unsafe_code)]` governs DireWolf's Rust — which has **zero** `unsafe`
blocks — and does not reach it. "DireWolf unsafe = 0" must never be read as
"the authority contains no unsafe or native code": it contains SQLite.

**Corrections to ADR-0035's measurement**, recorded here rather than edited
there:

* ADR-0035's table gives the amalgamation as 271,671 lines / 9,616,148 bytes.
  Those are the figures for `sqlcipher/sqlite3.c`, a second amalgamation the same
  crate ships for its SQLCipher feature. The file `bundled` compiles is
  `sqlite3/sqlite3.c`, measured above. The version, 3.53.2, is unchanged.
* ADR-0035 lists `cfg-if` 1.0.5; the workspace resolves 1.0.4, which was already
  locked and satisfies `sha2`.
* ADR-0035's build-time note named `cc` and three build scripts. The measured
  build-only closure is the five crates above.

**The gate had a fail-open, found by this measurement.** M3c's exact-closure
checker decided a dependency's optionality **by name**. `rusqlite` declares
`libsqlite3-sys` twice — optional for `wasm32-unknown-unknown`, required
everywhere else — so the optional declaration hid the required one and the
checker dropped `libsqlite3-sys`, and with it all of SQLite's C, from the linked
closure. It is now judged **per declaration** (package, kind and target), an
edge whose declaration cannot be found counts as active, and an optional pair
whose edge is in force by any declaration counts as active for exclusion
purposes (RS012). A regression test reproduces `rusqlite`'s exact shape. The
closure is the union over every target Cargo resolved, which is why `libc` is
listed.

`dwcheck closure` now enforces both lists: RS010/RS011 for the linked set as
before, **RS014** for a build-only crate not reviewed and **RS015** for a stale
build entry, which also names a linked crate filed in the wrong list. The
offline RS006 cannot tell the lists apart from a lockfile and accepts a crate
reviewed in either; it now also treats the in-tree `dwk-proto` as part of the
TCB rather than as a third-party dependency of it.

## Consequences

### Security consequences

- An epoch is issued, fenced and never reused, across restarts, by one row per
  session that SQLite refuses to delete or lower; a new tenure without a new
  epoch is refused by the database itself.
- A process with the same uid does not inherit a live lease, and a restart
  invalidates every holder the previous process had.
- An idempotency key is never a way past the fence, cannot reach another
  subject's admission, and can never admit a second run — before or after a
  restart.
- A released or reaped run never becomes active again; replaying its admission
  returns a record and authorises nothing.
- A runtime cannot state origin, taint, privacy, workspace sensitivity, active
  skills, a standing grant, a mode or a policy revision: no field exists, and
  the decoder refuses each. Omitting a skill cannot remove a baseline one, and
  an unknown or quarantined skill withholds everything.
- Capability and policy are decided independently for every proposed action;
  neither substitutes for the other.
- Authority is returned only after its audit record is `fsync`ed; a crash in any
  window between commit and flush is recovered without duplicating, losing or
  inventing a record, and a log that disagrees with the store in a way no crash
  explains stops the authority.
- A structurally corrupt store is poisoned for every handle at once, never
  checkpointed, never reopened automatically and never recreated.
- The methodology check: twenty deliberate single-point bugs — the key checked
  before the fence, the holder ignored, the same subject sharing a lease,
  baseline skills dropped, an unknown skill read as no constraint, no restart
  invalidation, capability alone deciding, a garbage tail accepted, a
  reconciled record appended again, missing records accepted, corruption not
  poisoned, runs not reaped, authority returned before its audit, a released
  run queryable, an epoch not bumped, taint lowered, the digest ignoring the
  payload, a quarantined skill believed, the subject dropped from the scope, an
  expired lease accepted — were each applied to a copy of the tree, and every
  one turned the suite red.

### TCB consequences

§15: fifteen new linked crates including 269,376 lines of C, five build-only
crates that execute during the build, two build scripts among the linked crates.
SQLite parses `kernel.db`, which is authority-owned; the TOML chain still parses
operator policy. Those are where review effort goes.

### Portability consequences

- Linux is where assurance is claimed. WSL2 is the Windows development path.
- macOS: `fullfsync` makes `synchronous = FULL` mean what it says there. `libc`
  is linked on Apple silicon through `cpufeatures`.
- Windows native: the store works; no ownership or ACL check is made, and the
  runtime-user probe does not run there. Reduced assurance, as ADR-0029 says.
- The bundled amalgamation needs a C compiler on every build host.

### Operational consequences

- Every audited operation costs a SQLite commit with `synchronous = FULL`, an
  `fsync` of `audit.log`, and a second commit recording the flush.
  `make authority-state-evidence` reports the diagnostic latency; it is not a
  gate, because `fsync` latency is a property of the disk.
- `audit.log` and `audit_chain` grow without bound, as do idempotency records.
  Retention is future work with evidence.
- A quarantined store needs an operator: `dwkd-authority verify-audit`, the
  marker's reason, and a restore from a backup taken with SQLite's backup API
  ([STORAGE.md](../STORAGE.md) §5, not M3d's).
- One authority process per state directory; a second start is refused.

### Explicit limitations

- **No authentication.** `AuthenticatedSubject` is asserted by the in-process
  caller. M3e derives it from the peer's credentials.
- **No transport.** `Authority::dispatch` maps decoded messages to response
  bodies; nothing sends them.
- **Two protocol gaps** (§12) have no truthful M3 wire form; M4 owns them.
- **Producers deferred** (§10): origin beyond `api`, taint rises, workspace
  binding on the runtime path, skill verification, standing grants.
- **No DNS binding.** A decision records the destination address it evaluated;
  nothing holds a connection to it.
- **Tamper-evident only** (§13), with no off-host head anchor.
- **Power loss** is not simulated. Crash tests kill processes, which keeps the
  page cache; the power-loss forms of the audit windows are the same on-disk
  states as windows C and D, which are tested directly.
- **The runtime-user probe** needs two real identities and is exercised only
  where it is run with them. Hosted CI does not run it.
- **SQLite is C.** Nothing in this ADR makes it memory-safe.

## Alternatives considered

**A single transaction across `kernel.db` and `audit.log`.** Does not exist, and
simulating it — two-phase commit over a file — would be a second, worse database.
The outbox closes the same windows with one real transaction and a recovery
rule for each crash state.

**Audit only in SQLite.** One durable object, no reconciliation. Rejected by
ADR-0009 and ADR-0010: `audit.log` is the separate, append-only artifact, and a
chain that lives only in the database it audits is one file an attacker must
rewrite. The copy in `kernel.db` is kept for recovery and comparison, not as the
record.

**Write the audit record after answering.** Faster, and it is the "queue
silently dropped records" failure ADR-0017 rejects.

**Lease scoped to the subject.** Simpler, and it hands one fencing token to two
processes with the same uid. Rejected (§6).

**A finite idempotency window.** Conventional, and it reopens duplicate
admission for a slow retry with no evidence of how slow is safe (§8).

**Treat an unknown skill as no constraint, or refuse the admission.** The first
widens; the second needs `UNKNOWN_SKILL`, which ADR-0036 deliberately left to
the skill-registry milestone. The empty set is truthful on the committed wire and fails closed.

**Call an unresolved `fs` request `NOT_IN_AGENT_PROFILE` or
`CAPABILITY_MALFORMED`.** Wire-representable and false. Rejected; the gap is
reported instead (§12).

**`uuid` with random v7 ids.** A new dependency and a new source of randomness
in the TCB, to buy unguessability nothing relies on.

**Recreate a corrupt or missing store, or fall back to a previous policy.**
Availability bought by erasing the state that constrains the runtime, or by
deciding on rules nobody configured. Rejected outright.

## Revisit if

- M4 finds the two protocol gaps need wire reasons, or that `ToolInvoke` needs
  state this schema does not have.
- Evidence about retry latency makes a finite idempotency retention safe to
  state.
- `fsync` cost on the audit path becomes the measured bottleneck, which would
  argue for group commit — never for answering first.
- A SQLite advisory lands that a version bump cannot close.
- `libsqlite3-sys` exposes its default features, which would remove
  `pkg-config` and `vcpkg` from the build closure.
- An off-host head anchor becomes available, which would upgrade §13 from
  tamper-evident to tamper-evident against a local rewrite.
