# ADR-0080: The approval registry -- durable requests and approvals, each use spent in its effect's own transaction

**Status:** Proposed · **Date:** 2026-11-26 (proposed for M6.2; built and reviewed locally 2026-11-26; committed as `b8414fd`, CI #227 green; M6.2.1's evidence built locally 2026-11-27, its hosted run pending; nothing here is accepted) · **Builds on:** [ADR-0079](0079-the-approval-binding-v1-what-it-binds-and-how-it-is-encoded.md) (the binding, and its §8 registry obligations), [ADR-0078](0078-approval-assurance-which-classes-need-a2-and-the-presence-factor.md) (A1 and A2), [ADR-0077](0077-the-approval-channel-is-the-approver-endpoint-and-an-approver-uid-is-a-principal-not-a-person.md) (the channel), [ADR-0067](0067-f18-approver-endpoint-identity-boundary.md) §7 (`approval.*` audit kinds), [ADR-0064](0064-f02-authority-endings-serialised-with-decided-effects.md) (the gate, Proposed), [ADR-0063](0063-principal-ownership-of-sessions-workspaces-and-profiles.md) (principals), [ADR-0062](0062-taint-follows-delivered-content.md) (taint), [ADR-0052](0052-m5d-sandboxed-process-exec.md) (the sandboxed launch and its intent) · **Would amend (on acceptance):** [ADR-0039](0039-durable-authority-state.md) (store schema version 15: the registry) · **Leaves unchanged:** DWKP, the private broker protocol, the approver endpoint (TX065), the shipped packs, the binding (TX066), every accepted decision

> **An approval is a record the authority keeps, and a use is spent only in
> the transaction that records the effect it allows.** A launch denied
> `REQUIRE_APPROVAL` records a durable request naming its binding; an
> approver's decision on it records an approval with a life and a use count;
> a launch whose binding matches an open approval, and passes every guard,
> spends one use after its intent and in its intent's transaction, so neither
> commits without the other. The database refuses what no guard would write.
> No path outside the authority can decide an approval in M6.2, and the
> shipped build attaches no approver, so nothing is approvable before M6.3.

## Context

M6.1 built the binding: thirteen members that name exactly what an approval
would cover, stored nowhere. Its §8 left the registry the guards the hash
does not carry -- the run, TTL, `max_uses`, the policy revision, the
approver, the assurance -- and [M6_IMPLEMENTATION_PLAN.md](../M6_IMPLEMENTATION_PLAN.md)
§5 gives M6.2 durable requests and approvals, an atomic burn, revocation and
restart, with no approver operation yet. ADR-0078 as written makes every
`fs` and `net.http` action, and every host launch, an A2 class (each is
decided in `Environment::Host`), and no presence factor exists in M6: the
one route with A1 actions is the sandboxed `process.exec` without a
credential. This record decides the registry as built in
`crates/dwkd-authority/src/state/approvals.rs`, its schema in
`state/schema.rs` (version 15) and its one route in `state/workload.rs`.

## Decision

### 1. Scope

The registry serves one route: the public sandboxed `process.exec`
(ADR-0052), at A1, under an `exact_action` rule. Every other
`REQUIRE_APPROVAL` -- an `fs` operation, a `net.http` hop, a host launch, a
launch that injects a credential, `secret.use`, `fs.delete`, any scope but
`exact_action` -- is decided exactly as before M6.2: `DENY`, with no request
recorded. The in-process API's launches are never approvable: only the
public route carries a tenure (§5).

### 2. The store: schema 15

Four tables, created empty by the migration from 14; nothing is inherited
from history, so no store becomes approvable by upgrading.

| table | holds | the database refuses |
|---|---|---|
| `approval_clock` | one row: the highest instant any registry transaction has recorded | a delete; a fall |
| `approval_request` | a request: its run, session, requester, epoch, holder incarnation, idempotency key, binding schema, hash and canonical bytes, scope, TTL, `max_uses`, the assurance it needs, policy revision, rule, when asked and its window's end; `PENDING`, `GRANTED`, `DENIED` or `EXPIRED` | a delete; any change but its one decision; a second pending request for one run and binding; an insert that is not `PENDING` or whose run is not `ACTIVE` under the same subject, session and epoch |
| `approval` | an approval of one request: its approver, the channel (`APPROVER_ENDPOINT`), assurance, life, `max_uses`, `uses`; `OPEN`, `EXHAUSTED`, `EXPIRED` or `REVOKED`, ended once | a delete; a change to anything fixed; a second approval of a request; one not decided on a pending, unexpired request of a run still `ACTIVE`, within its TTL and use limit; an A2 request at A1; its requester as approver; `uses` that are not its use records |
| `approval_use` | one use: its approval and sequence, its invocation, run and action hash, when | any update or delete; a use that is not the next of an `OPEN`, unexpired approval of its own run and binding, on a workload intent of that run still `LAUNCHING` |

A use's insert raises `uses` and, at `max_uses`, ends the approval
`EXHAUSTED`, in the database (`approval_use_counts`).

### 3. Requests

A launch denied only for want of an approval, on a run whose environment is
`READY` (the binding names it as measured), records a request in the
transaction that denies it: id `DomainHash("direwolf.approval.request.v1",
run, binding hash, n)`, the canonical binding stored on the row. A run that
already waits on the same binding records nothing new. A run holds at most
16 waiting requests and a store 1024 -- waiting meaning `PENDING` and inside
its window; past either bound the launch is denied as before and records
nothing. A request waits `min(TTL, 10 minutes)` (APPROVALS.md §8: no
decision is no execution); a request past its window ends `EXPIRED` when its
run next records one, or when a decision finds it. History is kept: the
bounds limit waiting requests, not the store's size, whose retention is the
storage work's (M8).

### 4. Decisions

`Authority::decide_approval` is the state machine M6.3's approver operations
will call. It records a decision once, on a pending request inside its
window whose run still holds its authority, by an approver in the
operator's set who is not the requester. A request whose run has ended is
refused (`RunEnded`) and ended `EXPIRED` (cause `RUN_ENDED`), and the database
refuses an approval of it: no approval is recorded for authority that has
ended. A denial ends the request `DENIED`; a grant at A1 of a request needing A1
records an approval -- id `DomainHash("direwolf.approval.v1", request)`, its
life the rule's TTL from the grant, its use limit the rule's -- and ends the
request `GRANTED`. An A2 decision is refused (`AssuranceUnavailable`): no
presence factor exists. **In M6.2 nothing calls it outside tests**: no DWKP,
approver-endpoint, broker or CLI path names it (TX068), and the approver set
it checks is attached by `Authority::attach_approvers`, which exists in test
builds only -- Linux test builds, where the route tests that call it run.
In the shipped build the set is empty: no approval can be decided, and none
spent.

### 5. Spend-time guards

A launch is approved only if, inside its own transaction and the effect
section ADR-0064 gives it, one open approval passes every guard:

| guard | where |
|---|---|
| the exact action: verb, executable by path and digest, argv in order, workspace and root, the measured environment, credentials (none), agent profile and revision, requester, scope, taint, privacy, kept obligations | the binding's bytes equal the request's, byte for byte (ADR-0079) |
| the same run | the approval's request is of this run (the query, and the use's trigger) |
| the same requester, session, lease epoch and holder incarnation | the request's tenure equals the caller's (`passes`) |
| the same policy revision | the request's revision is the active one |
| open, unexpired, a use left | `OPEN`, `now < not_after` on the registry's clock (§7), `uses < max_uses`; the use's trigger again |
| decided by an approver still in the operator's set, never the requester | the approver set at the spend; `approver != requester`; the trigger at the decision |
| A1, for an A1 class | the approval's and the request's assurance; the class (`required`) |
| the route's own fences, unchanged | the lease fence, the run held and `ACTIVE`, the idempotency key, the capability, the kept obligations, the image, the `READY` environment, egress (F-17) |

A replayed key is answered from its recorded workload before anything is
decided: it spends nothing. Anything that fails a guard is denied as before
M6.2 and records a request for the world as it now is; an open approval of
the same run and key under another binding is recorded as a drift
(`approval.drift_detected`).

### 6. The burn

The use is spent after the workload's intent and its audit record, in the
same transaction (`workload::intent_recorded`); its trigger requires that
intent. A crash before the commit leaves neither; after it, both -- and the
restart settles the workload `UNKNOWN` (or, past its outcome, `COMPLETED`),
never run again, its use spent and never given back. This is exactly-once
*consumption*, a property of one transaction; it is not exactly-once
execution: an effect interrupted after its start is `UNKNOWN` under the
existing effect-recovery contract, never retried and never refunded. A
crash while a request is recorded leaves it whole or absent, and one while
revoking leaves the approval `REVOKED` or `OPEN`, each audited exactly as
the store holds it; a schema-15 migration that fails midway rolls back
whole. Concurrent contenders on separate handles serialise on
SQLite's single writer (`BEGIN IMMEDIATE`): of a hundred launching one
single-use approval, one spends it; contenders for a K-use approval never
spend more than K.

### 7. Expiry and the clock

The registry's clock is the authority's, never below `approval_clock`'s
high-water mark, which every registry transaction raises. An approval is
spendable while `now < not_after` and expired at the instant; an expired
approval found by a launch is ended `EXPIRED`, durably, so a host clock moved
back -- or moved back before the approval was ever looked at -- never makes a
passed instant current again.

### 8. Revocation and the other ends

`Authority::revoke_approval` ends an open approval `REVOKED`, inside an
ADR-0064 ending section: it waits for every effect already decided, whose
committed use stands and whose effect goes on, and no use begins after it.
A run's end, an ownership revocation, a lease taken over or released and a
restart each fence the run before the registry is asked (its run is no
longer held, or its tenure no longer the caller's), so its approvals are
never spent; their rows stay `OPEN` until they expire or are revoked. Each
of those ends is already an ADR-0064 ending: one that arrives while a spend
stands decided waits for it -- the use and its intent commit first and the
effect reaches the broker while its run still holds authority -- and nothing
is spent after it. The linearisation point is the gate: a spend inside its
effect section before the ending is admitted has won; one that reaches the
gate while an ending waits or stands is decided after it, and refused.

### 9. Audit

Seven kinds: `approval.requested`, `approval.granted`, `approval.denied`,
`approval.expired` (`kind` request or approval), `approval.used`,
`approval.revoked`, `approval.drift_detected`. A use names its approval,
request, invocation -- the intent's own record -- run, binding hash,
approver, assurance, policy revision and its sequence. No registry record
carries the binding's members or the command: the canonical binding is on
the request row, digests only, and the command is the intent's record
(SANDBOX.md §4).

### 10. What does not change

DWKP and its operations: an approved launch is planned `ALLOW` with the
reason `ALLOWED_BY_RULE` and its rule's id; the approval is the audit log's
(OD-5). The private protocol, the approver endpoint, which still holds no
operation (TX065), the binding module, which still grants nothing (TX066),
and the shipped packs. TX062 keeps every other state and server file from
recording an approval; its exemption names the registry, its schema and its
tests, and TX068 keeps every other path from writing the registry or naming
its decision seam.

## Consequences

- M6.3 has one seam to call (`decide_approval`), one revocation, and a
  durable record to show an approver.
- The run's taint is bound: an approval granted before a launch's output
  raised it is never spent after (a K-use approval asked for on a clean run
  spends one use); asked for at the plateau, the same launch binds the same
  bytes every time.
- A store at schema 15 cannot be opened by an earlier build; ADR-0064's
  per-tunnel design, which needed "a schema 15", needs the next version.

## Alternatives considered

- **A use spent before the intent, or in a transaction of its own.**
  Rejected: a crash between them is a use with no effect or an effect with no
  use.
- **The approval checked at the decision only.** Rejected: an approval
  outlives the world it was granted in; every guard is read again inside the
  spend.
- **A request for every `REQUIRE_APPROVAL`.** Rejected: an A2 class or a
  scope M6.2 cannot spend would be a request no approval can ever answer.
- **A wall clock without a high-water mark.** Rejected: a clock set back
  would revive an expired approval.
- **Ending a run's approvals in the run's own ending transaction.** Rejected
  for M6.2: every end already fences the run before the registry is asked;
  touching each ending transaction would widen M6.2 into every lifecycle
  path for no change in what can be spent.

## Residuals

- A launch denied before its environment is `READY` records no request: the
  environment is prepared only for a permitted launch, and the binding names
  it as measured.
- An ended run's approvals stay `OPEN` -- unspendable -- until they expire
  or are revoked; its pending requests end `EXPIRED` when a later
  transaction finds them (a decision, or its run's next request).
- The store-wide bound counts waiting requests by query; its arithmetic is
  unit-tested, a thousand requests are not. History is retained.
- Only `exact_action` is spent; `executable_and_argv` needs its allowlist's
  source (M6.4).
- The clock's floor is the highest instant a registry transaction has
  committed: a host clock that leaps forward and back with no registry
  transaction between is not seen.
- The concurrency evidence is SQLite contention between handles and a fake
  broker, its handles waiting longer than production's five seconds; the
  server never runs two writers, and a production handle past its wait is
  refused `Busy`, spending nothing.
- The crash evidence was, in M6.2, the in-process crash hooks on a
  reopened store; real process termination was not exercised for the
  registry (TX010 keeps process starts out of the authority's source, and
  an integration test, where the real-process harness lives, cannot hold an
  approval). Since M6.2.1 it is: an external supervisor kills the library's
  unit-test executable's child with SIGKILL at each of 34 windows and
  another process recovers its files
  ([M6_2_1_SECURITY_EVIDENCE.md](../M6_2_1_SECURITY_EVIDENCE.md)). A process
  kill is not a power loss: written but unsynced bytes survive it.

## Owner decisions

- **OD-1** M6.2's scope: the sandboxed `process.exec` at A1 under
  `exact_action`; every other class unchanged, `DENY`, no request.
- **OD-2** Schema 15 as §2, every invariant also a trigger, nothing
  inherited.
- **OD-3** The bounds: 16 waiting requests per run, 1024 per store, a ten
  minute window.
- **OD-4** Revocation as an ADR-0064 ending; the other ends fence instead of
  ending rows.
- **OD-5** An approved launch's wire plan unchanged (`ALLOW`,
  `ALLOWED_BY_RULE`), the approval in the audit log.
- **OD-6** No production approver set and no production decision before
  M6.3; TX062's exemption and TX068 as §10.

## Evidence

Local, 2026-11-26 (WSL2, Linux): the registry's unit tests, the Linux
real-authority route tests (`state/approval_route_tests.rs`, each case's
`APPROVAL-EVIDENCE` line after its assertions), the A2 credential case and
schema 15's migration test; `make approval-registry-evidence`; the mutation
review `make approval-registry-mutations`; TX062 and TX068 on their fixtures.
Its results and hosted evidence are recorded in
[M6_2_IMPLEMENTATION.md](../M6_2_IMPLEMENTATION.md); hosted CI is the
acceptance gate, and this record stays Proposed until accepted. M6.2.1
(2026-11-27, local): `make approval-registry-crash-evidence` (34 windows,
real process termination), `make approval-registry-separation`, seven more
route cases and mutants A50 to A54 -- recorded in
[M6_2_1_SECURITY_EVIDENCE.md](../M6_2_1_SECURITY_EVIDENCE.md).

## Revisit if

M6.3's approver operations need a decision this state machine does not
make; a presence factor makes A2 approvable; a route other than the
sandboxed launch becomes A1; standing grants (M6.4) share the registry; or
the server gains a second writer.
