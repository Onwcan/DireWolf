# ADR-0064: An end of authority waits for every effect already decided -- one gate per store orders a revocation, a lease taken over or released and a run released after each effect standing between its decision and its outcome

**Status:** Proposed · **Date:** 2026-11-15 (designed, built and reviewed locally 2026-11-15 for finding F-02; its hosted evidence is pending and nothing here is accepted) · **Would amend (on acceptance):** [ADR-0011](0011-session-concurrency.md) point 5 (an epoch fences the effects a request has decided as well as the request: no tenure begins while one of them stands between its decision and its outcome), [ADR-0039](0039-durable-authority-state.md) (the handles onto one store share an in-memory gate beside SQLite's transactions) · **Refines (Proposed):** [ADR-0063](0063-principal-ownership-of-sessions-workspaces-and-profiles.md)'s concurrency residual ("F-02 must keep a revocation serialised with intents already recorded") · **Leaves open:** the F-02 residuals of [ADR-0061](0061-workload-egress-decided-by-policy-novelty-and-exposure.md) and [ADR-0062](0062-taint-follows-delivered-content.md) -- per-tunnel mediation and concurrency within a run -- designed in [F02_AUTHORITY_CONCURRENCY.md](../F02_AUTHORITY_CONCURRENCY.md) §9 and not built

> **From the commit of an end of authority -- a revocation's first phase, a
> lease acquired over another tenure, a lease released, a run released --
> nothing it ended reaches the broker.** Every effect the authority decides
> is decided, handed to the broker and recorded inside an *effect section*;
> every end of authority commits inside an *ending section*; the two kinds
> exclude each other on every handle onto a store. An effect decided before
> an end is performed and recorded before the end commits, and is reported
> as what it is: authorised history. An effect decided after it is decided by
> what the end left -- and refused.

Proposed. The change is built so that its evidence can run; the accepted
records' bodies are unchanged (README.md, rule 1).

## Context

**What is serial today.** The production server gives the authority one
worker thread (`server/worker.rs`): one request at a time, except a sandboxed
launch, which is parked once the broker has started it and collected between
other requests (ADR-0052 §8). Within one request, an effect follows a fixed
order: one transaction decides it -- the fence, the run, the subject's
standing, the key, both gates -- and records its intent; the broker is handed
it with no transaction open; another transaction records its outcome
(ADR-0039, ADR-0044 §10). The worker never lets another request in between.

**What is not.** The store does not depend on the worker. `Authority::handle`
opens another handle onto the same state directory -- the same process lock,
poison state and audit writer -- "so several threads can contend for the
store through SQLite's own locking", and the release route tests already use
it for "the interleaving one worker never makes, which the store does not
forbid". Each step is one `BEGIN IMMEDIATE` transaction, so every decision
is serialised; the steps of one effect are not.

**Finding F-02** (reproduced 2026-11-15, before any change). A second handle
ended an effect's authority after its intent and before its hand-off; the
broker performed the effect anyway. With the effect stopped at the crash
point after its intent (`ToolAfterIntent`, `WorkloadAfterIntent`) and the
fake broker recording how many runs were `ACTIVE` when each order arrived:

| interleaving | what happened |
|---|---|
| a delegate's `fs.write` decided; the operator revokes the delegate | the revocation reported `COMPLETE`; the write then reached the broker with its run `REAPED` (`active_runs: 0`), and the revoked delegate was answered with a successful result |
| the old holder's `fs.write` decided; its lease expires and the same subject's new connection takes the session over | the write reached the broker after the new tenure had reaped the run: two tenures' effects in one session, which ADR-0011 point 5 exists to prevent |
| a delegate's sandboxed launch decided; the operator revokes the delegate | the workload's start reached the broker after its run was reaped and its environment destroyed |

No production path reaches these today: one worker serialises requests, and
ownership changes are offline (ADR-0063 §5). They are reachable through the
store's own interface, and from the first change that gives the authority a
second writer -- which ADR-0061, ADR-0062 and ADR-0063 each defer to F-02.

## Decision

### 1. One gate per store

The handles onto one store share a gate (`state/gate.rs`). It is in memory,
like the poison state they already share: the state directory's lock keeps
one process, so one gate sees every handle.

### 2. Effect sections

| effect | the section begins | it ends |
|---|---|---|
| a file operation (`tool_invoke`) | before the transaction that decides it and records its intent | after the transaction that records its outcome |
| a host launch, status or kill (`process_invoke`) | likewise | likewise |
| a `net.http` hop | before the hop's intent (the fence, the run, both gates, in one transaction) | after the hop's outcome; each hop is a section of its own |
| a sandboxed launch | before the transaction that records the workload's intent (the route decided after a preparation is decided again, in a section of its own) | when the broker has started it -- or, if it ended at once, when it is settled |

Effect sections do not exclude each other: two effects contend through
SQLite, as before.

### 3. Ending sections

`acquire_lease` (a new tenure reaps the old one's runs), `release_lease`,
`release_run`, and a revocation's first phase each hold an ending section for
their one transaction. An ending begins only when no effect section is open;
while it waits, no effect section begins. Endings do not exclude each other:
two acquirers still contend through SQLite (`tests/state_concurrency.rs`).
What an ending leaves to the broker -- the destruction of its runs'
environments, a revocation's second phase -- is performed after the section.

### 4. What is not a section, and why

- **A started workload.** What it does after its start is its environment's
  (ADR-0052 §8). An end of its run's authority marks the environment
  `DESTROYING` and the broker removes it -- ADR-0063's two phases, unchanged:
  the report says `REVOKED` until the workload is settled, and a revoked run
  is told nothing its workload produced.
- **An environment's preparation, destruction and listing, a staging
  reclamation, a workload's collection.** Each is undone if its run ends
  meanwhile (`environment::end_with_its_run`), is itself a clean-up, or reads.
  Holding the gate across a preparation (up to the environment deadline)
  would make every end of authority wait for one; the release route tests
  that end a run during a preparation keep passing unchanged.
- **An admission, a heartbeat, a query, a preview.** No broker effect;
  SQLite's serialisation decides their order against an ending (a profile
  revocation racing admissions leaves no run of the revoked principal
  `ACTIVE`: `tests/state_concurrency.rs`).

### 5. Lock order and bounded waiting

The gate is taken before any SQLite transaction and never inside one; a
section is never entered from inside another (debug builds assert it), and
its guard is not `Send`. An effect section holds at most one broker exchange,
each within its own deadline (an environment's is the longest, 120 s); an
ending section holds one transaction and no broker exchange. Every wait ends
at five minutes: past it the operation is refused `Busy` with nothing written
-- fail closed, as a transaction past SQLite's busy timeout is. One server
worker never waits at the gate.

### 6. Unchanged

Store schema 14, the private broker protocol (12) and public DWKP. The
server's single worker and the parked launch. Idempotency (a key names one
invocation for ever), the epoch fence, ownership, taint and egress decisions,
every pending state and its reconciliation at start-up. No new concurrency
is enabled: within a run, a second sandboxed launch is still `ENVIRONMENT_BUSY`
and a brokered change still waits while a workload may run on its root.

## Consequences

- An end of authority means what its record says: after a revocation's
  report says `COMPLETE`, nothing the revoked subject was granted is still to
  be performed; after a new tenure begins, no effect of the old one reaches
  the broker.
- An effect decided before an end is still performed and answered: the end
  is ordered after it, not the other way round. This is the linearisation the
  single worker already gave.
- An ending may wait for the longest effect section open on another handle --
  in the worst case one `net.http` hop or one sandboxed start, each bounded by
  its broker deadline. A flood of effects cannot starve an ending: once one
  waits, no new effect begins.
- A store used from several handles can now answer `Busy` from the gate after
  five minutes; the server, with one worker, cannot.

## Residuals and what is assigned elsewhere

- **Per-tunnel mediation** (ADR-0061's option B) and **concurrency within a
  run** (ADR-0062) are not built: they need a durable per-tunnel intent, a
  private protocol 13 and a schema 15. The design is in
  [F02_AUTHORITY_CONCURRENCY.md](../F02_AUTHORITY_CONCURRENCY.md) §9; until it
  is decided, a run's workloads stay one at a time and its egress tripwire
  stays the backstop.
- **A running workload keeps its egress until its environment is removed**
  (ADR-0063 OD-12): an immediate broker-side stop is a protocol change.
- **The gate is not durable.** A crash ends every section; start-up settles
  what an interrupted effect left `UNKNOWN`, never performed again.
- **Not real-process concurrency.** The evidence is the authority's own
  ordering against a fake broker and SQLite contention between handles; the
  server never runs two writers.

## Alternatives considered

- **A. Keep one worker and change nothing in the store.** The production
  ordering stays right, but the store's interface keeps permitting the
  window, and the first second writer -- an online operator endpoint, a
  second worker, a test harness -- reopens F-02. Rejected: the invariant
  belongs where the decisions are.
- **B. A durable claim before each hand-off** -- a transaction that re-checks
  the fence and the run and marks the intent "handed over", which a
  revocation marks "cancelled" first. It linearises at the claim, but an end
  can still commit between the claim and the hand-off, so the report must
  count claimed effects, and it needs schema 15. A larger change for the same
  guarantee; kept as the basis of per-tunnel mediation (§9 of the report).
- **C. Per-tunnel authority mediation now.** The broker asks the authority
  for every CONNECT. It needs a durable per-tunnel intent, protocol 13 and
  the authority answering while a workload's start is in flight -- the
  concurrency this record does not enable. Deferred, designed.
- **D (chosen). Refuse the unsafe interleaving and enable nothing new:** an
  in-memory gate between effects and ends of authority, taken at the entry
  points, with no protocol or schema change.

## Evidence

Built and run locally on 2026-11-15; **hosted evidence is pending**:

- reproduction before the change: the three interleavings above, each
  failing its assertion (`active_runs: 0` at the broker);
- `state/gate.rs`'s unit tests: effects share the gate and endings share it;
  an ending waits for every effect inside and holds back new ones; every wait
  is bounded and a refused ending lets effects in; a section ends however its
  holder leaves; sections do not nest;
- `state/concurrency_route_tests.rs` (fake broker, a second handle at the
  crash point after each intent): a delegate's revocation, a takeover after
  expiry, a run release and a lease release against a decided write or
  start, each held at the gate, each effect reaching the broker while its run
  was `ACTIVE`, each end committed after the effect's outcome; and the other
  direction, each kind of end stopped inside its section before its
  transaction while a write is asked for -- the write waits at the gate, is
  decided after the end and refused, and nothing reaches the broker; racing
  invocations under one key on two handles are one effect;
- `state/net_http/tests.rs` and `state/process/tests.rs`: a run release
  against a decided hop and a decided host launch;
- `tests/state_concurrency.rs`: admissions racing a profile revocation leave
  no active run of the revoked principal; racing writers leave one audit
  chain that a restart replays without reconciling anything;
- `make authority-concurrency-mutations`: every guard weakened in turn
  (G1-G5, E1-E8, C1-C7), each required to fail the authority's unit or
  contention suites;
- `tests/architecture/test_f02_concurrency.py`: every broker hand-off in the
  state layer accounted for; each entry point takes its section before it
  decides; the mutation table matches the source.

Hosted CI is the acceptance gate; this record stays Proposed until accepted.

## Revisit if

The authority gains a second writer (a second worker, an online operator
endpoint); per-tunnel mediation or concurrency within a run is decided; a
broker exchange inside an effect section gains a deadline longer than the
gate's wait; or a new kind of end of authority is introduced (it must take an
ending section).
