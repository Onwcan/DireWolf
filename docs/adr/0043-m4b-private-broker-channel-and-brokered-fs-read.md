# ADR-0043: M4b — the broker reads the object the authority checked, over a private channel only the authority can speak on

**Status:** Accepted · **Date:** 2026-09-23 · **Amends:** [ADR-0018](0018-authority-broker-split.md) (the per-invocation authorisation is bound to the kernel's peer identity and a broker-issued channel, not MACed; the broker's blast radius is stated precisely), [ADR-0036](0036-m3-authority-operations-and-the-capability-wire-form.md) (`ToolInvoke` and `CanonicalPreview` get their first wire forms, with exactly one tool), [ADR-0039](0039-durable-authority-state.md) (schema version 3, seven audit kinds, one crash-window family) · **Refines:** [ADR-0028](0028-policy-input-ownership.md) (the byte bound and the environment are kernel-derived policy inputs), [ADR-0032](0032-wire-contract-framing-strict-json-and-jcs.md) (the private protocol reuses DWKP's framing and strict JSON profile and nothing else), [ADR-0037](0037-capability-specifications-and-canonical-authority-identities.md) (a new `fs.read` declaration becomes a `CanonicalPath` only through the M4a resolver; the grammar alone re-reads a grant the authority stored), [ADR-0040](0040-m3d-reconciliation-admission-across-tenures-and-undecidable-proposals.md) (a proposal in `AuthorityQuery` is still not a canonical action), [ADR-0041](0041-m3e-authenticated-dwkp-transport.md) (the authority's one worker also carries the broker exchange), [ADR-0042](0042-m4a-canonical-filesystem-resolution.md) (§9: how the checked object reaches the broker)

> **The object the broker reads is the object the authority authorised, and
> the runtime has no path to the broker.** The authority decides, records its
> intent, and hands the broker one descriptor for one checked file; the broker
> proves the descriptor is that file, reads at most the authorised bound, and
> reports back; the authority records the outcome and the taint it brings, and
> only then answers. Nothing on the channel is trusted because of what it says
> — only because of who the kernel says sent it.

## Context

M4a ([ADR-0042](0042-m4a-canonical-filesystem-resolution.md)) decided what a
declared path means: the object found beneath an operator-bound root pinned
by identity, by `openat2` relative to held descriptors, or nothing. It
performed no effect. `ToolInvoke` and `CanonicalPreview` were reserved
([ADR-0036](0036-m3-authority-operations-and-the-capability-wire-form.md));
admission withheld every filesystem capability as `UNRESOLVED_RESOURCE`; the
broker was a binary that printed its milestones and exited.

[ADR-0018](0018-authority-broker-split.md) split deciding from doing and left
the hop between them undesigned. It stated two things about that hop that this
ADR must honour or change explicitly: per-invocation authorisations "must be
unforgeable to the broker's own peers (they are MACed by authority and
single-use)", and "compromising the broker gives an attacker the current
invocation". It also stated, as rule 1, that the runtime speaks only to the
authority.

M4b is the second of M4's five parts (ADR-0042 §1): the private channel, the
first tool's wire forms, admission that resolves filesystem capabilities, and
one real effect — `fs.read` — end to end. It is the first milestone in which a
decision of the authority causes a process to touch a user's file.

## Decision

### 1. Three processes, three identities, one direction of trust

| process | identity | listens | connects to |
|---|---|---|---|
| runtime (cognition) | the runtime's user | nothing | the authority's DWKP socket |
| `dwkd-authority` | the authority's user | the DWKP socket (M3e) | the broker's private socket |
| `dwkd-broker` | **its own** user | the private socket, and nothing else | nothing |

* **The broker binds; the authority connects.** The broker owns its socket's
  directory with the same rules the authority applies to its own
  (ADR-0041 §2): owned by the broker's uid, not writable by group or other,
  ancestors root's or the broker's unless sticky, a lock per name, a stale
  socket removed only if it is provably the broker's own and dead, `0666` on
  the socket because the mode is not the access control.
* **The authority does not start the broker.** It executes nothing (TX010);
  both daemons are started by the operator's service manager, and the broker
  is told the authority's uid and the authority the broker's socket and uid
  (`--broker-socket`, `--broker-uid`; `--authority-uid`). Nothing on the wire
  names or changes either.
* **Peer authentication both ways, by the kernel.** The broker asks
  `SO_PEERCRED` of every accepted connection and closes it **before reading a
  byte** unless the uid is the configured authority's. The authority asks
  `SO_PEERCRED` of the connection it made and **sends nothing** — not a byte,
  not a descriptor — unless the uid is the configured broker's. Neither trusts
  the socket path.
* **The broker's uid must be its own.** The authority refuses to start with a
  broker uid equal to its own or to an allowed DWKP peer's, and the broker
  refuses an authority uid equal to its own, unless the operator passes
  `--allow-shared-broker-uid` / `--allow-shared-authority-uid`, which log
  `REDUCED ASSURANCE` at start-up. The broker refuses to run as root: a root
  broker would hold every file on the machine instead of the ones it is
  handed. Development machines use the shared flags; the hosted evidence job
  uses three real users (§13).
* **Exactly one private listener.** TX009 becomes
  `TX009-one-listener-per-daemon`: the authority's `server/` directory and the
  broker's `listener.rs` file, and nothing else in either daemon, the CLI or
  the wire crate, may name a listener. Negative fixtures prove a second
  authority listener, a second broker listener, a broker TCP listener and a CLI
  helper daemon are each findings, and the reviewed broker listener is not.

The runtime can reach the broker's socket file — it is `0666` in a traversable
directory — and that is all it can do: the broker reads nothing from it and
writes nothing to it. An operator who wants the filesystem to narrow even that
pre-creates the broker's directory `0710` with the authority's group, which
the broker accepts.

### 2. The private protocol is not DWKP

`dwk_proto::brokerp` defines three messages, each a strict `reject` type in
DWKP's framing and JSON profile ([ADR-0032](0032-wire-contract-framing-strict-json-and-jcs.md))
with a `kind` checked on decode so no message reads as another:

| message | from | fields |
|---|---|---|
| `broker.hello` | broker | `kind`, `protocol` (= 1), `channel` |
| `broker.fs_read` | authority | `kind`, `protocol`, `channel`, `invocation_id`, `device`, `inode`, `max_bytes`, `descriptors` (= 1) |
| `broker.outcome` | broker | `kind`, `protocol`, `channel`, `invocation_id`, exactly one of `done{content, eof_observed}` / `refused` |

It has no envelope, no registry entry, no emitted schema, no Python binding
and no operation inventory row. TX016 makes the runtime, the CLI, the binding
generator and the task runner unable to name it; TX013 makes the broker unable
to name DWKP dispatch, DWCP or events. `device` and `inode` are decimal text
because JSON integers are exact only to 2^53. There is no path in any message:
the broker is never told a name.

Bounds are read from the header before a body byte is buffered: an
authorisation is at most 16 KiB, a hello 1 KiB, an outcome one DWKP frame.

### 3. The authorisation: no MAC, no token, no table — and still unforgeable to the broker's peers

**This amends ADR-0018's parenthesis "(they are MACed by authority and
single-use)".** The requirement it served is kept: *a broker peer cannot forge
an authority authorisation*. The mechanism is replaced:

* **Unforgeable to peers** because the broker reads authorisations only from a
  connection the kernel attributes to the authority's uid. A process that is
  not that uid is closed unread. A process that *is* that uid can read
  `kernel.db` and everything else the authority holds — including any MAC key
  one would have given it — so a MAC adds nothing against it and a key
  somewhere to hold, rotate and leak.
* **Single-use** because each connection carries at most one. The broker
  issues a fresh `channel` in its hello — 64 random bits drawn once per
  process from the standard library's OS-keyed hasher, then a 64-bit counter,
  so no two connections of one broker process ever share one, and a restarted
  broker's differ from its predecessor's except with probability 2^-64 — and
  executes an authorisation only if it names that channel. After one outcome
  it closes the connection; a second frame on it is never read.
* **Bound to the object**: the authorisation names `(device, inode)` and the
  broker re-proves the descriptor against it (§5).

Replay is therefore structurally refused: the same bytes on another connection,
with a changed byte in the channel, with another descriptor, on the same
connection after the first, or against a restarted broker, are each refused
before a byte of any file is read — each is a test against the real broker
(`crates/dwkd-broker/tests/private_protocol.rs`). No key exists on either side,
so **the broker holds no long-lived secret key**, and no spent-authorisation
table exists, so none grows. TX013 bans key and store libraries from the broker
crate so that stays true.

Stated, not hidden: in the shared-uid development mode the runtime runs as the
authority's uid, so the kernel cannot tell them apart and the runtime could
speak to the broker. That is what `REDUCED ASSURANCE` means, and why neither
daemon accepts it without the flag.

### 4. The descriptor: one, read-only, checked, and never a path

The authority's M4a handle is **consumed**, never exposed and never reopened
by name:

1. `PinnedRoot::resolve` (Observe, `RegularFile`) gives the `ResolvedResource`
   — `O_PATH` leaf and parent, which cannot read — and its canonical path is
   the one the gates decide on (§7). Nothing is open for reading yet.
2. **Only after the intent is durable** (§9), `ResolvedResource::into_read_handoff`
   consumes it. `open_for_read` opens the leaf **relative to the held parent
   descriptor** with
   `openat2(O_RDONLY|O_NOFOLLOW|O_NOCTTY|O_NONBLOCK|O_CLOEXEC, RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS|RESOLVE_NO_MAGICLINKS|RESOLVE_NO_XDEV)`,
   after re-checking the name is still bound, and `fstat`s the result:
   identity equal to the resolved one and a regular file, or the invocation
   ends `FAILED` (§10). The `O_PATH` descriptors close.
3. `ReadHandoff` has private fields, no `Clone`, and one crate-private method,
   `into_transfer_descriptor`, called from exactly one place — the broker link
   (TX014, with a negative fixture).
4. The link sends it with `sendmsg`, `SCM_RIGHTS`, **exactly one descriptor
   attached to the authorisation's first byte**, then closes its own copy.

The broker receives with `recvmsg(MSG_CMSG_CLOEXEC)` and **requires exactly
one descriptor**. None is `DESCRIPTOR_COUNT`. More than one is
`DESCRIPTOR_COUNT` too — every received descriptor is closed and not one byte
of content is read; the broker never takes the first and discards the rest,
because which descriptor is "first" is the sender's choice. Control-data
truncation is a count failure. Only the first descriptor is ever held while
the frame is read (later ones are closed as they arrive), so a peer cannot make
the broker hold descriptors by sending many.

The descriptor is exactly one regular file opened for reading — not its
directory, not the workspace root, not an `O_PATH` handle. The broker needs no
filesystem permission at all; in the three-identity evidence the broker's own
uid is refused (`EACCES`) when it tries to open the same file by path, and
reads it through the descriptor. TX015 bans path-based opens from the broker
outside its listener's own lock file.

### 5. The broker re-verifies before it reads, and reads only what was bounded

In order, each a refusal **before any byte of the file is read**:

| check | refusal |
|---|---|
| the frame decodes strictly as `broker.fs_read` | none: closed unanswered (`malformed`) |
| `channel` is this connection's | `CHANNEL_MISMATCH` |
| exactly the declared one descriptor, control data not truncated | `DESCRIPTOR_COUNT` |
| `fcntl(F_GETFL)`: read-only, not `O_PATH` | `DESCRIPTOR_NOT_READABLE` |
| `fstat`: a regular file | `DESCRIPTOR_NOT_REGULAR` |
| `(st_dev, st_ino)` is the authorised object's | `IDENTITY_MISMATCH` |

Then `pread` from offset zero into a buffer sized from `max_bytes`, which the
strict decoder has already bounded to 256 KiB — nothing is allocated before
the bound is known to hold. **Never a byte past the bound**: every `pread` asks
for at most what is left of `max_bytes`, and a read that claims more than it was
asked for is not trusted. There is no probe for the end of the file, so the
outcome reports `eof_observed` conservatively: `true` when a read returned
fewer bytes than the bound (the end was seen), `false` when exactly `max_bytes`
were read (the end was not proven, because nothing past the bound is read to
prove it). The broker never canonicalises, resolves, evaluates policy or
records anything, and writes only event lines — ids and counts, never content
— to its stderr.

### 6. The wire forms: one typed tool, and a preview that performs nothing

`ToolInvoke` is **defined** (effect-bearing) and `CanonicalPreview` is defined
(not effect-bearing), both `REQUEST_RUN` envelopes (session, run, epoch
required; **no** idempotency key), with one member each:
`fs_read{path, max_bytes}`. There is no `tool` name and no argument map: a
second tool is an undeclared member and a protocol error, never a dispatch.
There is no `cap_id` and no `environment`: the authority finds the covering
grant and decides where the action runs. `path` is the runtime's spelling —
any absolute text without NUL up to 384 characters — which only the authority
judges; `max_bytes` is `1..=262144`.

Responses: `direwolf.tool.result{invocation_id, action, decision, fs_read}`,
`.denied{action, decision}`, `.previewed{action, decision}`,
`.refused{operation, reason}` and `.failed{invocation_id, reason}`. The action
reports the canonical path, the byte bound and the environment; the decision
reports both gates, the rule and its source, and a reason from
`ALLOWED_BY_RULE`, `DENIED_BY_RULE`, `DEFAULT_DENY`, `NO_CAPABILITY`,
`UNRESOLVED_POLICY_INPUT`. It carries no capability text, because a canonical
path may be non-ASCII and `CapabilityText` is ASCII; the audit record carries
the required capability. Content is lowercase hexadecimal — lossless for every
byte value, one spelling each. `fs_read.eof_observed` is the broker's
conservative end-of-file report (§5).

**Output and frame bound, proven.** `MAX_FS_READ_BYTES` = 262 144 is derived
from the frame: hex doubles it to 524 288 characters, leaving 524 288 bytes of
the 1 MiB frame for everything else, which is under 8 KiB even with a
384-character path of six-byte escapes. `tests/dwkp.rs` encodes the largest
result every field allows and asserts it fits; one byte more does not decode.
There is no artifact spill in M4b.

**`CanonicalPreview` causes zero effect.** It runs the same steps 1–3 as an
invocation (§7) — the same resolution, the same action, the same gates, so the
action and the decision are identical by construction, and a preview/invoke
differential test asserts it on the real processes — and stops there. A path
that does not resolve is refused (`NOT_FOUND`, `SYMLINK`, …) exactly as an
invocation's is. It opens nothing for reading (the resolver's handles are
`O_PATH` and close unread), mints no invocation id, records no intent, contacts
no broker and reserves nothing; twenty previews move the broker's connection
count by zero. **A preview is not a promise:** it is information, stale the
moment it is sent, and a later `ToolInvoke` fences, resolves and decides from
scratch.

**Versioning.** The new schemas are version 1 of new operations. DWKP's
envelope version is unchanged: a peer that does not know them answers
`PROTOCOL_UNKNOWN_OPERATION`, which is the truth. The private protocol has its
own version, 1, checked on every message.

### 7. One decision path, and the gates see the bound before the effect

`state::tool`, for both operations, in this order:

1. **Locate** (one transaction) — the fence and the run (lease, holder, epoch;
   the run active, the caller's, the session's, at this epoch, under the
   activation in force: otherwise `STALE_EPOCH` / `UNKNOWN_RUN`); the path is
   text a path can be; the run's workspace has a bound root (otherwise
   `WORKSPACE_UNBOUND`).
2. **Resolve** (no transaction) — the M4a resolver beneath the pinned root,
   `O_PATH` only. Its grammar refuses a spelling before any lookup
   (`PATH_OUTSIDE_WORKSPACE`, `PATH_TRAVERSAL`, `PATH_NOT_CANONICAL`); then the
   filesystem answers (`NOT_FOUND`, `SYMLINK`, `ROOT_REPLACED`, …). **The
   canonical path is the resolver's**, never the request's spelling.
3. **Decide** (one transaction) — the fence and the run again; then:
   * **the required capability, derived and never read from the request**:
     `fs.read:<canonical path>?max_bytes=<bound>&no_symlink_targets=true`.
     `no_symlink_targets` is true of every object the resolver can return;
   * **the canonical action**: that capability, `environment = HOST`,
     `byte_count = max_bytes`. `HOST` is the truth until M5: the broker reads
     on the host with its own privileges. Policy therefore decides on the most
     that could be read, before anything is, never on what a file held;
   * **both gates, independently** (`query::decide`): a held grant covering
     the action, and a policy `ALLOW`. `REQUIRE_APPROVAL` fails the policy
     gate (no approvals in M4b); the first unevaluable rule denies;
   * a preview records its answer; a denial is recorded; an allowed invocation
     mints its id and records its intent (§9) — all before this transaction
     commits.

Every refusal and denial is recorded and answered there. **The broker is
contacted for none of them** — nor for a stale epoch, an ended or unknown run,
a path that does not resolve, or a workspace without a root; the real-process
suite asserts the broker saw zero connections across all of them.

**What resolving first costs, stated.** Because resolution precedes the gates,
a run can learn whether a path in its workspace resolves — and the class of
refusal if it does not — even where policy would deny reading it: a denial
means "it resolved", `NOT_FOUND` means it did not. It never learns content,
and never anything outside the operator-bound root, whose spellings the grammar
refuses before any lookup. The order is deliberate: the action the gates decide
on must name what the filesystem found, not a spelling the filesystem had not
yet confirmed.

**The shipped packs deny every read**, and say why. Their first filesystem
rule names `~/.ssh`, and no run has a home anchor (ADR-0042); that rule cannot
be evaluated, so the pack denies with `UNRESOLVED_POLICY_INPUT` rather than
guess. That is fail-closed and stays so until the home anchor is designed; an
operator policy is how a deployment reads files in M4b, and the end-to-end
tests use one.

### 8. Admission resolves `fs.read` through the M4a resolver, in every term

**A new declaration means what the filesystem says it means.** Every concrete
`fs.read` path any term of an admission names — the request, the agent
profile, every active skill, the mode ceiling — is resolved by the production
M4a resolver beneath the session's operator-bound, pinned workspace root
(`Observe`, any kind), and becomes comparable only through the resolver's
answer (`state::scopes::declared`). A path that does not exist, crosses a
symlink, a magic link or a mount, is ambiguous under normalisation, is not one
canonical spelling (non-NFC, traversal, an empty component), lies beneath a
root that was replaced, or belongs to a session with no bound root, covers
nothing: a member of a term that did not resolve covers nothing, and a request
that did not resolve is withheld `UNRESOLVED_RESOURCE` before any term is
consulted. `fs.read:*` names no object and needs no resolution. Every other
filesystem verb and `process` stay `UNRESOLVED_RESOURCE` until M4c and M4d
define what their targets mean.

**No SQLite transaction is open across the resolution.** An admission that names
a concrete path runs in passes: the first decides everything up to minting
(fence, idempotency record, profile, skills), writes nothing, and returns the
paths; they are resolved with no transaction open; the next pass decides again
from the start and mints from those answers — provided they were resolved
beneath the binding in force and cover every path it now names. At most three
passes; the last never asks to resolve, and a path it has no current answer for
covers nothing. The admission's audit record lists every concrete path with the
resolver's answer: the identity of the object it found, or the refusal class.

**A trusted stored grant is not a declaration** (`state::scopes::rehydrate`).
A grant the authority resolved, minted and stored is re-read by its canonical
text — the grammar alone, no filesystem — and must render to exactly its stored
text. So a replay under the same idempotency key is answered from the record
before any path is looked at: it never resolves or mints again, and a grant
whose object has since gone still reads back as what was granted. The
grammar-only reader is named for that purpose, and one module may name it
(TX017, with a negative fixture). A proposal in `AuthorityQuery` is not a
declaration either: it resolves nothing, and a concrete `fs.read` proposal is
`UNRESOLVED_RESOURCE` as in M3.

### 9. Durable intent before the effect; durable outcome and taint before the answer

Schema version 3 adds `tool_invocation`: one row per authorised invocation,
written in the transaction that records the intent, with what was authorised
(run, canonical path, byte bound, object device and inode, incarnation) fixed
by trigger and the ending written exactly once. The invocation id is minted by
the authority (`inv_`, UUIDv7). New audit kinds: `tool.denied`,
`tool.refused`, `tool.previewed`, `tool.intent_recorded`, `tool.completed`,
`tool.failed`, `tool.interrupted`.

```text
1 (transaction)  locate: fence, run, the run's root binding
2 (none)         resolve beneath the pinned root: O_PATH only
3 (transaction)  fence and run again; capability, action, both gates; mint
                 the id; INSERT the INTENT row; audit tool.intent_recorded;
                 COMMIT and fsync
4 (none)         ONLY NOW open the checked file for reading, relative to its
                 retained parent, and prove its identity -- or end the row
                 FAILED (OBJECT_CHANGED / OBJECT_UNREADABLE) in a transaction
5 (none)         the broker exchange: one authorisation, one descriptor
6 (transaction)  for a result: raise taint to LOCAL_UNVERIFIED; end the row
                 COMPLETED or FAILED; audit; COMMIT and fsync
  then, and only then, the runtime is answered
```

**No readable descriptor exists before the intent is durable.** Step 2 holds
only `O_PATH` handles; step 4 is the first `O_RDONLY` open. A test inspects the
process's own `/proc/self/fd` and `fdinfo` at every crash point an invocation
crosses: zero readable descriptors on the file up to and including the point
after the intent commits (with the intent row present and its audit record
written), exactly one at the next point, and none after the broker answers.

No SQLite transaction is open across resolution, the open or the broker. The
broker writes no audit: it returns an outcome, and the authority writes it.
Workspace content is `LOCAL_UNVERIFIED`, never lower; the taint is raised in
the outcome's transaction, before the bytes can reach cognition. A delivery
longer than the authorised bound is not a result — it is recorded as a
protocol failure and taints nothing — whichever broker produced it.

**Crash windows.** Every crash point one invocation crosses — each step
boundary and every point of each of its transactions — was swept with the
crash hook: stop there, start a new incarnation, assert the record. There is
no hook *inside* the broker exchange; a death there (window D) leaves the
record windows C and E leave, which the sweep covers, and the broker's side of
it is the early-close case of the hostile-peer suites.

| window | where the process dies | what the record says after restart |
|---|---|---|
| A | before the intent commits | nothing; no effect, no broker contact |
| B | intent durable, nothing open for reading, broker not contacted | row `INTERRUPTED`, `tool.interrupted`; no effect |
| C | the checked file open for reading, broker not contacted | row `INTERRUPTED`; no effect |
| D | during the exchange (the authority dies) | row `INTERRUPTED`; a read may have happened; nothing delivered, no taint |
| — | the broker dies mid-exchange (the authority lives) | `FAILED` (`BROKER_PROTOCOL_ERROR` or `BROKER_UNAVAILABLE`) |
| E | outcome read, not yet durable | row `INTERRUPTED`, no taint raised, nothing delivered |
| F | outcome and taint durable, runtime not answered | row `COMPLETED`, taint raised; the runtime got nothing |

The next incarnation ends every `INTENT` row `INTERRUPTED` in its start-up
transaction, before it serves anything, exactly once. So an effect is never
silent and a durable intent is never left open.

**Retry.** `ToolInvoke` carries no idempotency key and is not replayed: a
retry is a new invocation, decided from scratch, with a new id. A read has no
external side effect, so a retry after window F reads again, and the audit
chain shows both. M4c, whose effects are not idempotent, must design this
again.

### 10. Failure classes are distinct

| class | wire | when |
|---|---|---|
| denied | `tool.denied` | the path resolved and a gate refused; nothing opened for reading |
| refused | `tool.refused` + reason | before any effect was authorised: fence, run, root, grammar, resolution |
| `OBJECT_CHANGED` | `tool.failed` | after the intent: the name no longer binds to the checked object, or the file opened is another; nothing sent |
| `OBJECT_UNREADABLE` | `tool.failed` | after the intent: the checked file cannot be opened for reading (permission, I/O); nothing sent |
| `BROKER_UNAVAILABLE` | `tool.failed` | none configured, connect failed, the peer's uid is not the broker's, timeout |
| `BROKER_PROTOCOL_ERROR` | `tool.failed` | the broker's frames did not decode, named another channel or invocation, carried both or neither result, or more bytes than authorised |
| `BROKER_EXECUTION_ERROR` | `tool.failed` | the broker refused (`IDENTITY_MISMATCH`, …) or could not read |

The audit record keeps the finer class (`not_configured`, `peer_refused` with
the uid the kernel observed, `protocol` with its detail, `refused` with the
broker's reason). A scripted hostile broker on the real channel — wrong
channel, wrong invocation, too many bytes, both results, garbage, an oversized
header, early close, a stall, no hello, a refusal — produces exactly these,
records `FAILED`, and taints nothing.

### 11. The broker's blast radius, stated precisely

**This amends ADR-0018's "compromising the broker gives an attacker the
current invocation".** That sentence is too generous in one direction and too
vague in another. In M4b a compromised broker process has:

* **everything its own uid can do on the host** — which is why the broker must
  be its own least-privileged user, with no write access to workspaces and no
  access to the authority's state (the three-identity evidence proves the
  broker's uid can neither list the state directory, read `kernel.db` or
  `audit.log`, append to the log, create a file there, nor speak DWKP);
* **the descriptors it is handed while it is compromised** — each read-only,
  to one regular file the authority authorised. A descriptor is not a
  capability boundary against its holder's own uid: through
  `/proc/self/fd/N` the holder can reopen the file with *its own* permissions,
  so a broker uid that could write the file anyway could write it. Hence,
  again, a broker uid with no write access;
* **the ability to lie about what it read** — up to the authorised bound. The
  authority records the digest of what it was given and taints it
  `LOCAL_UNVERIFIED` like any workspace content; it cannot verify the bytes;
* **the ability to refuse or stall** — bounded by the 10-second exchange
  deadline, after which the invocation fails `BROKER_UNAVAILABLE`.

It does not have: any capability, any policy decision, any grant, any
approval, the audit log, `kernel.db`, a DWKP endpoint, a descriptor for an
object the authority did not authorise, or a way to make the authority send
one. It cannot forge an authorisation *to itself* in any sense that matters,
and it cannot reach the runtime.

### 12. Liveness costs, stated

The authority's single worker ([ADR-0041](0041-m3e-authenticated-dwkp-transport.md) §10)
carries the broker exchange, so a slow broker holds every other authority
operation for up to the 10-second deadline per invocation. Heartbeats queue
behind it; the default lease lifetime (60 s) absorbs that. The broker serves
one connection at a time, which bounds its memory and descriptors to one
exchange and lets the authority's own deadline end a stall. A local process
can flood the broker's socket with connections, each costing one `accept` and
one `getsockopt`; the operator's `0710` directory removes even that.

### 13. Evidence

`make broker-fs-read-evidence` (Linux; a mandatory hosted CI job, required by
the aggregate check):

* **same identity, real processes** — the released authority and broker,
  end to end with exact and lossless bytes; `max_bytes` enforced by both gates
  before the effect; zero broker contact for every denial, refusal and dead
  run; the preview/invoke differential; broker down, restart and absence;
  authority restart; the largest result through one frame; the decoder
  refusing hostile tool requests; a cross-process TOCTOU campaign (a thread
  swapping names for symlinks to outside files while the runtime reads — every
  answer is the checked object's bytes or a refusal, never the outside file);
* **in process, on the real channel** — the crash-point sweep (§9); no
  readable descriptor before the durable intent, measured from `/proc` (§9);
  the name swapped, or the file made unreadable, between the intent and the
  open — `FAILED`, no broker, no taint; a scripted hostile broker; the tree
  changed *after* the authority opened the file and
  before the real broker reads (rename-over and symlink-swap: the checked
  object is read; an in-place rewrite of that same object is read too, because
  the authorisation names an object, not its bytes);
* **the broker binary against a hostile authority-side peer** — non-authority
  peers closed unread; single use (replay on another connection, a changed
  byte, another descriptor, after restart, a second on one connection);
  descriptor count and kind — zero, two and three descriptors each refused
  `DESCRIPTOR_COUNT` with every descriptor closed, zero content bytes read
  (the kernel's `rchar` for the broker process) and the next valid invocation
  served; the read bound — for N of 1, 8, 4096 and 262 144 on a larger file
  the broker reads exactly N bytes, never N+1; twelve malformed frames closed unanswered with no
  descriptor outliving its exchange; descriptor pressure; a stalled peer cut
  off at the deadline; untrusted configurations refused;
* **admission through the resolver** (`make filesystem-canonicalization-evidence`)
  — every granted concrete path's identity recorded from the resolver;
  missing, symlinked, normalisation-ambiguous, non-canonical and non-NFC
  paths, a replaced root and an unbound session each withheld; a
  failing profile, skill or ceiling term covering nothing; a stored grant
  re-read after its object is gone while a new declaration of it is withheld;
* **three identities** — the runner as the authority, a broker user the job
  creates, and `nobody` as the hostile runtime, each proven by its numeric uid
  (distinct, none root) before anything runs: the broker's uid cannot open the
  file by path and reads it through the descriptor; the runtime's uid is
  closed unread by the broker whatever it sends; a real broker running as the
  runtime's uid at the configured socket is sent nothing; the broker's uid
  reaches no authority state and no DWKP.

Without the identities the three-identity half is **NOT EXERCISED** and the
command fails after running everything else. The harness switches users
through `sudo -n -u`; the authority never does (TX010).

### 14. Platforms and dependencies

**Linux only.** The channel needs `SO_PEERCRED`, `SCM_RIGHTS` and the M4a
resolver; elsewhere the broker refuses to serve and the authority's link
answers `BROKER_UNAVAILABLE` (`unsupported`). Both still build and test on
macOS and Windows.

**No dependency change for the authority**: the link uses `rustix`'s `net`
feature, already enabled for peer credentials (ADR-0041); the exact
feature-resolved closure (`dwcheck closure`) is unchanged, so
[ADR-0019](0019-language-rationale-v2.md) is not amended. TX008 gains one file,
`broker/link.rs`. **The broker** gains `dwk-proto` and, on Linux, `rustix` with
the authority's features exactly, so a workspace build adds no feature to the
authority's `rustix`. Zero `unsafe` in either: every syscall goes through
`rustix`'s safe API (`sendmsg`/`recvmsg` with `SendAncillaryBuffer` /
`RecvAncillaryBuffer`, `socket_peercred`, `fcntl_getfl`, `fstat`, `pread`,
`openat2`) — no FFI and no `CMSG` arithmetic by hand.

### 15. What M4b does not do

No other tool (`fs.write`, `fs.list`, `fs.stat` … — M4c); no execution (M4d);
no secrets (M4e); no sandbox — every action is `HOST` (M5); no approvals; no
artifact spill; no home anchor; no Windows or macOS channel; no parser of
file content anywhere in the authority. No M4 evaluation is activated, and the
eval harness's available milestones are unchanged. **M4 is incomplete.**

## Consequences

**Security.** The first effect exists, and exists only behind: the fence, the
resolver, a derived capability, both gates with the bound, a durable intent, a
kernel-identified broker, a checked descriptor re-proven by the broker, a
bounded read, a durable outcome with taint. The runtime has no path to the
broker, and the broker no path to the authority's state.

**Negative.** A third process to deploy, with its own user. Resolution
precedes the gates, so a run learns whether a workspace path resolves even
where it may not read it (§7). An admission naming a concrete path costs a
second transaction and a resolution per path. An allowed read
costs two transactions with `fsync` more than a denial and one IPC exchange.
The authority's worker waits on the broker. A compromised broker can lie about
bytes up to the bound.

**Operational.** Shipped policy packs deny every read (§7); deployments
supply an operator policy. The broker must run as its own user; the shared-uid
flags are for development and say so.

## Alternatives considered

* **A MAC over each authorisation** (ADR-0018's sketch). Adds a key to hold and
  protect, and protects against no one the peer check does not already stop: a
  process with the authority's uid can read the key. Rejected, and ADR-0018
  amended accordingly.
* **Send the path; let the broker open it.** A second canonicaliser outside the
  authority, reading whatever the name means by then. Rejected; TX015 bans it.
* **Send the `O_PATH` handle, or the parent directory.** More authority than
  one read needs, and an `O_PATH` descriptor re-opened by the broker is the path
  problem again. Rejected: one read-only regular file.
* **Bearer tokens or a spent-authorisation table.** State the broker must keep
  and a restart must reconcile. The per-connection channel gives single use
  with neither.
* **The authority spawns the broker.** Would make the authority an executor
  (TX010) and couple their lifetimes. Rejected.
* **Return content as a UTF-8 string.** Lossy for arbitrary files. Rejected for
  hexadecimal.
* **Probe one byte past the bound to report the end of file exactly.** Reads
  `max_bytes + 1` bytes of a file the authority authorised `max_bytes` of.
  Rejected: `eof_observed` is conservative instead.
* **Resolve only after the gates allow**, so that no refusal reveals whether a
  path exists. The gates would then decide on a spelling the filesystem had
  not confirmed. Rejected; the cost is stated in §7.
* **Canonicalise admission scopes by the grammar alone.** A declaration would
  mean its spelling, not an object: a grant could be minted for a path that
  does not exist or crosses a symlink. Rejected (§8); the grammar re-reads
  only grants the authority itself resolved.

## Revisit if

A second tool is added (the typed-call shape must stay closed); an effect that
is not idempotent is added (the retry decision in §9 does not carry over); the
broker needs concurrency (the one-at-a-time bound in §12 changes); approvals
arrive (`REQUIRE_APPROVAL` stops meaning deny); or the broker's liveness shows
up as authority latency in practice.
