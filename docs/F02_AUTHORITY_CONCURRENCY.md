# F-02: authority concurrency and durable pending operations

Phase 3.1's implementation and evidence report. The decision is
[ADR-0064](adr/0064-f02-authority-endings-serialised-with-decided-effects.md)
(**Proposed**); this document holds the map it rests on, the per-operation
contracts, the design left for a later decision, and the evidence. Baseline:
`main` at `1c0224b`, CI #178 green (33/33).

## 1. The concurrency model as built

| layer | what runs at once | what serialises it |
|---|---|---|
| process | one authority per state directory | the state directory's lock (`state/files.rs`) |
| server | one acceptor; one thread per connection, each with at most one request in flight | **one authority worker** (`server/worker.rs`): a bounded queue of 64 jobs, served one at a time |
| sandboxed launch | up to `MAX_PARKED` launches the broker supervises, each **parked** after its start and collected between other jobs | the worker; each collection is one short broker exchange |
| store | any number of `Authority` handles onto one store (`Authority::handle`), each with its own SQLite connection | `BEGIN IMMEDIATE` per step; the busy timeout (5 s) ends a wait as `Busy`; **since F-02, the authority gate** between effects and ends of authority (`state/gate.rs`) |
| broker | many requests, one per connection | the broker's own tables (`MAX_SUPERVISED_WORKLOADS`) |

The worker is the only production caller. The in-process API is used by the
evidence harness (`Served::operate`, on the worker between jobs), by
operator tooling (offline: the lock admits one process), and by the tests --
which is where a second handle interleaves.

### Request path and linearisation points

| step | where | linearisation point |
|---|---|---|
| peer authenticated | `server/peer.rs`: `SO_PEERCRED` | the subject is the kernel's uid (ADR-0041, ADR-0063 §8) |
| caller context | `Authority::connect`: a fresh holder per connection | -- |
| lease | `lease::acquire`, one conditional `UPDATE` | its commit; the epoch is the store's counter (ADR-0011 point 5) |
| ownership | `ownership::standing` inside each lease and admission transaction | that transaction's commit |
| admission | `admission::admit`, one transaction per pass | the pass that records the run |
| an effect's decision | fence, run, standing, key, both gates, intent: one transaction | **its commit** -- and, since F-02, every end of authority is ordered after the effect's outcome |
| broker hand-off | no transaction open | inside the effect section |
| outcome | one transaction (outcome, taint, audit) | its commit; the answer follows it |
| an end of authority | one transaction (lease, run, revocation's first phase) | its commit, inside an ending section |
| audit | appended in the transaction, flushed by the committing handle after its commit | the record's sequence number, allocated in the transaction |
| recovery | `begin_incarnation`, one transaction at start-up | leases invalidated, runs reaped, every open intent settled |

## 2. The finding

**F-02 (verified).** An end of authority committed on one handle between an
effect's intent and its broker hand-off on another; the broker performed the
effect for a run already ended. Reproduced before any change with three
interleavings, each stopping the effect at the crash point after its intent:

| interleaving | observed |
|---|---|
| revocation of a delegate vs its `fs.write` | revocation report `COMPLETE`; write reached the broker with `active_runs: 0`; the revoked delegate answered with `ToolResultV2` |
| lease expiry and takeover vs the old holder's `fs.write` | write reached the broker after the new tenure reaped its run |
| revocation of a delegate vs its sandboxed launch | `workload.start` reached the broker with its run reaped and its environment destroyed |

**Root cause.** The decision and the hand-off are two steps; SQLite
serialises each step, not the pair, and nothing ordered an end of authority
against the pair. The worker made the window unreachable in production, so
the store's own interface carried an assumption it did not enforce.

**Reachability.** None in production today. Every later change that gives the
authority a second writer -- the concurrency ADR-0061, ADR-0062 and ADR-0063
assign to F-02 -- would have made it reachable.

## 3. The remediation

[ADR-0064](adr/0064-f02-authority-endings-serialised-with-decided-effects.md):
one in-memory gate per store, two kinds of section.

- **Effect sections**: `tool_invoke`, `process_invoke`, each `net.http` hop,
  and a sandboxed launch from its intent's transaction to the broker's start.
- **Ending sections**: `acquire_lease`, `release_lease`, `release_run`, and a
  revocation's first phase.

The kinds exclude each other; neither excludes itself. A waiting ending holds
back new effects. Every wait is bounded (300 s) and fails closed as `Busy`.

**Lock order.** Gate, then SQLite; never the gate inside a transaction; never
one section inside another (asserted in debug builds); guards are not `Send`.
An effect section holds at most one broker exchange; an ending section holds
one transaction and no broker exchange.

### Architectures compared

| | A: one worker, store unchanged | B: bounded internal concurrency, serialised decisions | C: per-tunnel mediation | D: refuse the unsafe interleaving (**chosen**) |
|---|---|---|---|---|
| closes F-02 at the store | no | yes | not by itself | yes |
| new concurrency | none | yes: a worker pool | yes: CONNECT round trips during a workload | none |
| schema / protocol | none | none | schema 15, protocol 13 | none |
| deadlock risk | none | lock order across workers | the authority answering the broker while a start is in flight | one lock, fixed order, bounded waits |
| review cost | -- | high | high | one module and seven call sites |
| throughput | one worker | higher | lower per tunnel | unchanged (no waits in production) |

## 4. Pending operations, per operation

Each row is the operation's contract as the source implements it. "Cancel"
is the client going away: no DWKP operation cancels a decided effect, and a
connection that disappears is simply not answered.

| operation | intent durable | broker may act | outcome recorded | client gone | broker gone | authority crash | retry |
|---|---|---|---|---|---|---|---|
| file operation (`tool.rs`, `plan.rs`, `staging.rs`) | the deciding transaction, with its staging `EXPECTED` | after the intent, with descriptors proved to be the objects decided | `COMPLETED`, `FAILED` or `UNKNOWN` | outcome still recorded; answer dropped | not sent: `FAILED`; sent, no answer: `UNKNOWN` | `reconcile_open`: interrupted / `UNKNOWN`; staging judged by `reclaim_staging` | the key is bound for ever (`IDEMPOTENCY_KEY_REUSED`); a retry-safe tool is retried with a new key (ADR-0044 `RetryClass`) |
| host process (`process.rs`) | intent + `tool_process LAUNCHING` | after both | `RUNNING`, `EXITED`, `FAILED`, `UNKNOWN` | as above | as above | an open launch or kill `UNKNOWN`, an open status `INTERRUPTED`; never re-launched or re-signalled | as above; the production floor refuses every host launch before M6 |
| `net.http` hop (`net_http/`) | the hop's intent, per hop | after it, with the pinned addresses | per hop, then the request | as above | `FAILED` or `UNKNOWN` | `reconcile_open`: `UNKNOWN`, never re-sent | key bound for ever |
| credential use (`secret_use/`) | the use's intent before any backend read | after the value is read, as a one-shot pipe | with the hop's or the launch's outcome | as above | the pipe's value is never re-read | `UNKNOWN` | key bound for ever |
| sandbox preparation (`environment_ops.rs`) | `PREPARING` | after it | `READY`, `REFUSED`, `FAILED`; a run ended meanwhile: destroyed at the outcome | -- (the authority's own) | `UNKNOWN`, destroyed by labels later | `UNKNOWN`; reconciliation by labels | never prepared again; the next launch prepares anew |
| workload launch (`workload.rs`, `workload_ops.rs`) | `LAUNCHING`, egress authorisation, taint marks | after it | at settlement: `COMPLETED`, `FAILED`, `UNKNOWN`; egress `REPORTED`, `NOTHING_RAN`, `UNCERTAIN` | collected and settled; answer dropped | `UNKNOWN`; environment destroyed | `UNKNOWN`, environment destroyed, run raised as interrupted (ADR-0062 R5) | key bound for ever |
| environment destruction (`environment.rs`) | `DESTROYING` | after it | `DESTROYED`; unconfirmed stays `DESTROYING` | -- | stays `DESTROYING` | completed by the next preparation, start or start-up | retried by label, never a different container |
| run release / lease release / takeover (`admission.rs`, `lease.rs`) | the release or acquisition, with runs reaped and environments `DESTROYING`, in one transaction (an ending section) | destruction after the commit | -- | the release is durable; the answer may be lost | destruction pending | the lease and runs are already ended | a repeated release is acknowledged without effect |
| ownership revocation (`ownership.rs`) | phase A in one transaction (an ending section) | phase B: destruction after it | `revocation_status`: `REVOKED`, then `COMPLETE` | -- (operator) | stays `REVOKED` | phase A is durable; phase B completes later | an absent grant is refused, nothing written |

Every open intent is settled at start-up in one transaction
(`Authority::begin_incarnation`): leases invalidated, active runs reaped, and
file, process, credential, `net.http`, workload and environment intents
interrupted or `UNKNOWN` -- never performed again. No transaction is held
across a broker exchange, and none across the network.

## 5. Lease and revocation races

| race | handled by | evidence |
|---|---|---|
| two acquisitions | one conditional `UPDATE`; endings do not exclude each other | `exactly_one_of_many_racing_acquirers_wins` |
| old holder after expiry, after reacquisition | the gate orders the takeover after the old holder's decided effect; afterwards the fence refuses it | `f02_a_takeover_after_expiry_waits_for_the_old_holders_decided_write` |
| release and an effect | gate | `f02_a_run_release_waits_for_a_decided_write`, `_hop`, `_host_launch`; `f02_a_lease_release_waits_for_a_decided_workload_start` |
| release and admission | SQLite: an admission after the release is refused | existing admission suites |
| revocation and admission | SQLite: admitted-then-reaped or refused | `racing_admissions_and_a_profile_revocation_leave_the_revoked_subject_no_active_run` |
| revocation and an executing tool | gate: phase A waits for the tool's outcome | `f02_a_revocation_waits_for_a_decided_write_and_nothing_it_ended_follows` |
| revocation and a launch | gate up to the start; phase A/B after it; output withheld | `f02_a_revocation_waits_for_a_decided_start_and_withholds_what_it_produced` |
| revocation and a parked workload | ADR-0063's phases | `f18_a_revocation_ends_a_parked_workloads_environment_and_answers_nothing_it_produced` |
| broker teardown and a restart | `DESTROYING` durable first; completed later | F-18 and M5d.6 route tests |
| workspace-principal revocation and a shared root | phase A reaps the subject's runs on every bound session; exposure and taint are the root's | `state_ownership.rs`, `taint_route_tests.rs` |

An effect that reached the broker before an end is authorised history: its
outcome precedes the end in the audit log (the tests assert the order). One
decided after it is refused at its decision -- `STALE_EPOCH`, `UNKNOWN_RUN`,
`LEASE_HELD` or `UNKNOWN_AGENT_PROFILE`, as before.

## 6. Concurrent taint and egress

Answered against the implementation:

- **Inputs that may change while an operation is pending:** a run's taint
  (monotonic), novelty (grows), a root's exposure (grows), ownership and
  leases (ended only by endings, now ordered). Policy is fixed for an
  incarnation.
- **One workload consuming another's authorisation:** no. An authorisation
  is per workload, held by the broker for its environment; one environment per
  run and one workload per environment (`ENVIRONMENT_BUSY`).
- **A policy decision going stale between intent and effect:** for a file
  operation, a host launch and a hop the effect follows within one effect
  section, and only taint, novelty and exposure can grow meanwhile -- each
  from another run's operation, which T-9 (ADR-0062) keeps out of this run's
  context. For a workload, the decision is held for its life and checked at
  each collection by the egress tripwire (ADR-0061 §5), which destroys the
  environment on drift.
- **A network response raising taint while another operation decides:** the
  rise and the decision are transactions; whichever commits first is seen by
  the other. Within a run the server answers one request at a time; across
  handles, `f02_racing_invocations_under_one_key_are_one_effect` and the
  existing route suites show the order holds.
- **A workspace exposure update observed before a concurrent effect:** a
  `LAUNCHING` workload that may reach an origin already counts as exposure
  (ADR-0062 §2, `IN_FLIGHT`), and a brokered change waits while any workload
  may run on its root (M5d.4).
- **A broker using an authorisation after revocation:** until the
  environment is removed, yes -- the documented residual (ADR-0063 OD-12).
  No new effect is decided under the revoked grant.
- **A tunnel outliving its workload's authorisation:** no: a workload's
  tunnels are halted when it ends (`WORKLOAD_ENDED`, ADR-0061 §4), and its
  report is taken then (ADR-0062 §7).
- **A broker restart losing an enforcement fact:** the broker's per-root
  state is in memory; the authority's durable exposure decides the next
  launch (ADR-0061, Consequences).

Nothing here enables concurrency within a run; the tripwire stays the
backstop until per-tunnel mediation is decided.

## 7. Tests

| file | tests | kind |
|---|---|---|
| `crates/dwkd-authority/src/state/gate.rs` | 5 | the gate's rules, threads and channels, no sleeps on guesses |
| `crates/dwkd-authority/src/state/concurrency_route_tests.rs` | 10 | a second handle at the crash point after each intent (6); each kind of end stopped before its transaction while a write is asked for (4); fake broker |
| `crates/dwkd-authority/src/state/net_http/tests.rs` | +1 | a hop |
| `crates/dwkd-authority/src/state/process/tests.rs` | +1 | a host launch |
| `crates/dwkd-authority/tests/state_concurrency.rs` | +2 | SQLite contention between handles; audit replay |
| `tests/architecture/test_f02_concurrency.py` | 8 (12 cases) | hand-off inventory, entry points, mutation table, ADR status, the review's judge driven with a stand-in for cargo |
| `tests/architecture/test_ci_supply_chain.py` | +3 | Dependabot covers each Cargo workspace (separate change) |

`crates/dwkd-authority/src/state/interleave.rs` holds the shared test
helpers. `Meantime` starts the other handle's work at the chosen crash point
and waits until that work has either finished -- the window F-02 closed -- or
is held at the gate; each test asserts it was held, and with a guard
weakened the work finishes first and the broker-side assertion fails. `Hold`
stops one chosen thread at one crash point: an end of authority inside its
section, before its transaction, while a write is asked for on another
handle -- the write must wait at the gate, not even decided, and is refused
once the end has committed. The first direction alone could not tell an end
that enters the gate and leaves it before its transaction from one that
holds it (§8).

These are unit-level orderings against a fake broker and SQLite contention
between handles. They do not show real-process concurrency, which the
production server does not have.

## 8. Mutation review

`make authority-concurrency-mutations` (local; record in
`target/f02-evidence/record.json`): 20 mutants -- the gate's rules G1-G5;
each end of authority's section, missing (E1-E4) or left before its
transaction (E5-E8); each effect's section, missing, cut short or taken
after the decision (C1-C7). Each
must build the two stages' test targets and fail one of them; a build
failure, a timeout or a selection that ran nothing is not a kill; every file
is restored byte-identically.

**The first run found a gap in the tests.** Its table had 15 mutants, the
four ending mutants written as an end that enters the gate and leaves it at
once, before its transaction. G1-G5 were killed; E1-E4 **survived**: such an
end still waits for every effect already inside, which is all the first six
route tests looked at, while a new effect may begin and be decided in the gap
before the end commits -- the F-02 window again. The four `Hold` tests were
added for exactly that gap, the table grew to 20 (E1-E4 "takes no ending
section", E5-E8 the forms that survived, C7 a file operation's section taken
after its decision), and the run was stopped and repeated from the start.
Restoring the file it was mutating when stopped was checked against the
digest it recorded. Results of the second run are in §11.

Three weakenings are held by the architecture test, not by the review: a
host launch's or a `net.http` hop's section taken after its decision, and a
sandboxed launch's taken after its route's transaction. The `Hold` tests ask
for a file write only; the same test for a launch, a hop and a sandboxed
start is not written, so those orders are checked in the source
(`test_each_end_of_authority_and_each_effect_takes_its_section_before_deciding`
fails if one is reversed) rather than by a mutant.

## 9. Per-tunnel mediation: design, not built

What concurrency within a run would require, for a later decision:

1. **Durable per-tunnel intent.** Schema 15: `workload_tunnel(invocation,
   tunnel, destination, cell, state INTENT|OPEN|CLOSED|UNKNOWN, ...)`, its
   intent written before the broker dials.
2. **Protocol 13.** The broker asks the authority per CONNECT
   (`tunnel.authorise`), naming the workload's invocation and the destination;
   the authority answers from the run's context *now*, so taint or exposure
   that rose since the launch decides the tunnel.
3. **Ordering.** A tunnel decision is an effect section; an end of authority
   waits for it as for any other. The authority must answer while a start is
   in flight: the worker cannot block on its own broker exchange, so this
   needs either a second worker with the gate as its only shared ordering, or
   a broker-side queue the authority drains between jobs.
4. **Recovery.** `INTENT` and `OPEN` tunnels at start-up are `UNKNOWN`, and
   their destinations uncertain reach, as ADR-0061 §6 settles a workload.
5. **Evidence.** A real-OCI case where taint rises during a workload and its
   next CONNECT is refused; the tripwire's destroy no longer needed for it.

Until then: one workload per run at a time, its egress decided at launch and
held, the tripwire destroying the environment on drift.

## 10. Hosted evidence

The change needs no new workflow and no manual dispatch: every new test runs
in the existing jobs (`make test` on Linux, Windows and macOS for the Python
architecture tests; the authority's Rust suites on Linux). The mutation
review is local, like the other `*-mutations` reviews outside C3. Hosted
status: **pending** until a pushed run passes.

## 11. Results

Filled from the local runs of 2026-11-15:

- Reproduction before the change: 3 of 3 interleavings failed their
  assertion (`active_runs: 0` at the broker; revocation report `COMPLETE`).
- After the change: the authority's unit suite (all of it) and
  `state_concurrency` pass; the F-02 tests, 17 unit and 2 integration, pass.
- Mutation review, first run (15 mutants, stopped): G1-G5 killed, E1-E4 in
  their enter-and-leave form survived (§8).
- Mutation review, second run (20 mutants, 13:50-14:16 UTC, local, not
  hosted): baseline passed (497 unit tests, 5 contention tests); **20 of 20
  killed**, each by the authority's unit suite, each applied and restored
  byte-identically. The forms that survived the first run are killed by the
  `Hold` tests that were added for them; C6 is killed by the existing
  preparation tests, whose nested section the debug build refuses.

## 12. Remaining limits

- No parallel execution within a run or across a run's workloads is
  supported; none is claimed.
- **Head-of-line blocking** (the review's original F-02 note) is unchanged:
  with one worker, a `net.http` hop (its exchange deadline is 45 s, a
  request's 300 s) or an environment preparation (120 s) delays every other
  request; only a sandboxed launch is parked. Removing it means a second
  writer -- a worker pool or §9's mediation -- which ADR-0064's gate makes
  safe for ends of authority but which needs its own decision and evidence.
- A running workload keeps its egress until its environment is removed
  (ADR-0063 OD-12).
- The gate is in memory; a crash is handled by start-up reconciliation.
- An ending may wait up to one broker exchange; the server never waits.
- Per-tunnel mediation (§9) needs its own decision.
