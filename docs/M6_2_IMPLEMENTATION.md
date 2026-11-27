# M6.2 implementation report: the kernel-owned approval registry

**As of 2026-11-26.** M6.2 of [M6_IMPLEMENTATION_PLAN.md](M6_IMPLEMENTATION_PLAN.md):
durable requests and approvals, each use spent in its effect's own
transaction, revocation and restart. Its record is
[ADR-0080](adr/0080-the-approval-registry-durable-requests-and-atomic-consumption.md),
Proposed. **Built and validated locally (WSL2, Linux); not committed; hosted
evidence pending.** No path outside the authority can decide an approval,
and the shipped build attaches no approver: every `REQUIRE_APPROVAL` still
denies in production, and nothing is approvable before M6.3.

## 1. Baseline

| | |
|---|---|
| Revision | `4d18030` on `main` (`4d18030af74ce1db9997d65e94c4464e9d63ee16`), equal to `origin/main`; the working tree clean, nothing staged, no stash, one worktree; byte-identical to M6.1's closeout as delivered |
| CI | #226, [run 45711333755](https://github.com/Onwcan/DireWolf/actions/runs/45711333755): 33 of 33 jobs |
| Push workflow (CodeQL) | #42, [run 45711334711](https://github.com/Onwcan/DireWolf/actions/runs/45711334711): 4 of 4 |
| M6.1's formal closeout | verified: ADR-0062, ADR-0076 and ADR-0079 Accepted, each digest in `docs/adr/accepted.sha256` |
| Decisions in force | ADR-0062, ADR-0063, ADR-0067, ADR-0076, ADR-0077 (OD-1), ADR-0078 and ADR-0079 accepted; ADR-0064 Proposed |
| Rust dependencies | unchanged; Dependabot's grouped Rust update (PR #33) is not part of this change |

## 2. The record

[ADR-0080](adr/0080-the-approval-registry-durable-requests-and-atomic-consumption.md)
(Proposed) fixes the registry's scope, store schema 15, the request
lifecycle and its bounds, the decision state machine M6.3 will call, every
spend-time guard, the burn's place in the intent's transaction, expiry on a
clock that never falls, revocation as an ADR-0064 ending, and the seven
`approval.*` audit kinds. It would amend ADR-0039 (schema 15) on
acceptance; DWKP, the private protocol, the approver endpoint (TX065) and
the binding module (TX066) are unchanged. Its owner decisions are §20.

## 3. Store schema 15 and its migration

Four tables, created empty by one migration step from 14, inside the start-up
migration's one `IMMEDIATE` transaction:

| table | holds | the database refuses |
|---|---|---|
| `approval_clock` | one row: the highest instant a registry transaction has committed | a delete; a fall |
| `approval_request` | the run, session, requester, epoch, holder incarnation, idempotency key; the binding's schema, hash and canonical bytes; scope, TTL, `max_uses`, the assurance needed; policy revision, rule; when asked, its window's end; `PENDING`/`GRANTED`/`DENIED`/`EXPIRED` | a delete; a change to anything but its one decision; a second pending request for one run and binding; an insert that is not `PENDING` or whose run is not `ACTIVE` under the same subject, session and epoch |
| `approval` | the request it decides, approver, channel, assurance, life, `max_uses`, `uses`; `OPEN`/`EXHAUSTED`/`EXPIRED`/`REVOKED`, ended once | a delete; a change to a fixed column; a second approval of a request; one not decided on a pending, unexpired request of a run still `ACTIVE`, within its TTL and use limit; an A2 request at A1; the requester as approver; `uses` that are not its use records |
| `approval_use` | approval and sequence, invocation, run, action hash, when | an update or delete; a use that is not the next of an `OPEN`, unexpired approval of its own run and binding, on a workload intent of that run still `LAUNCHING` |

A use's insert raises `uses`, and at `max_uses` ends the approval
`EXHAUSTED`, in the database (`approval_use_counts`). Migration evidence:
`version_15_adds_an_empty_registry_and_grants_nothing` (14 to 15 in memory:
nothing inherited, the clock at zero, rising only, kept, an approval with no
request refused, `verify_exact` passing),
`a_version_15_migration_that_fails_midway_leaves_none_of_it` (a store holding
an object named like the last table: the step fails, the version stays 14,
no registry table remains), the integration tests that downgrade a real store
to 14 and reopen it through `Authority::start`
(`tests/resource_workspace.rs`, `tests/state_ownership.rs`), and every route
test's store created at 15.

## 4. The registry's state machine

| record | from | to | by |
|---|---|---|---|
| request | -- | `PENDING` | a sandboxed launch denied only `REQUIRE_APPROVAL` (`request`) |
| request | `PENDING` | `GRANTED` / `DENIED` | a decision (`decide`): once |
| request | `PENDING` | `EXPIRED` | its window passed (cause `WINDOW`), or its run ended before a decision (cause `RUN_ENDED`) |
| approval | -- | `OPEN` | a grant |
| approval | `OPEN` | `EXHAUSTED` | the use that reaches `max_uses` (the database) |
| approval | `OPEN` | `EXPIRED` | a launch that finds it past its instant (`settle`) |
| approval | `OPEN` | `REVOKED` | `revoke_approval` |
| use | -- | recorded | `consume`, in the intent's transaction |

No other transition exists; each terminal state is final (triggers
`approval_request_decided_once`, `approval_ends_once`, `approval_use_no_update`).

## 5. The request and approval lifecycle

| step | behaviour | test |
|---|---|---|
| asked | a launch denied only `REQUIRE_APPROVAL`, A1, `exact_action`, on a `READY` run, records one request; nothing runs | `m6_2_a_launch_needing_approval_is_requested_once_denied_and_nothing_runs` |
| deduplicated | the same binding again records nothing and extends no window; another binding is another request | the same; `m6_2_a_replayed_key_spends_nothing_and_another_runs_binding_is_not_this_runs_approval` |
| bounded | 16 waiting per run, 1024 per store -- waiting meaning `PENDING` and inside its window; past either, denied as before, nothing recorded | `m6_2_a_run_holds_at_most_sixteen_pending_requests`, `the_pending_bounds_are_the_runs_and_the_stores` |
| windowed | `min(TTL, 10 min)`; at its end a decision is refused `Expired` and the request ends `EXPIRED`; the same call later records a new one | `m6_2_a_request_waits_ten_minutes_at_most_and_then_ends_expired` |
| decided | once, by an approver in the set, never the requester, at A1 only, on a run still `ACTIVE`; a denial spends nothing | `m6_2_a_decision_is_an_approvers_once_never_the_requesters_and_never_a2`, `m6_2_a_request_whose_run_has_ended_is_never_decided` |
| not asked | no capability; another scope; an A2 class | `m6_2_a_launch_without_its_capability_or_under_another_scope_asks_for_nothing`, `m6_2_a_launch_injecting_a_credential_is_a2_and_asks_for_nothing` |
| no approver set | nothing decided: the shipped build | `m6_2_without_an_attached_approver_set_nothing_is_decided_or_spent` |

History is kept: no registry row is ever deleted. The bounds limit
*waiting* requests, not the store's size; retention of decided and expired
rows is left to the storage work that owns retention (M8), as for every other
durable record.

## 6. Trusted producers

| value | from |
|---|---|
| the binding and its canonical bytes | ADR-0079's builder, from the decided action, the run's record, the resolved executable, the operator's sandbox and its measured level (`RunContext::load`, `BoundEnvironment::sandbox`) |
| requester, session, epoch, incarnation | the caller as the public route authenticated it (the kernel-reported uid, the lease) -- `Binding::tenure`; never a field of the request |
| policy revision, rule, TTL, `max_uses`, scope | the active policy's decision (`ApprovalSpec`) |
| the assurance a class needs | `approvals::required` (ADR-0078 §1, literal: `Environment::Host` of any verb, `secret.use`, `fs.delete`, an injected credential) |
| an approver and its assurance | the decision seam's caller; in M6.2, tests alone (§15) |
| the registry's clock | the authority's clock, never below `approval_clock` |

## 7. Spend-time guards

The assignment's 25 spend-time checks, each with where it is enforced and what
tests it:

| # | guard | enforced by | tested by |
|---|---|---|---|
| 1 | the request and approval exist | the lookup joins them; the use's trigger | every spend test |
| 2 | the record is consistent | the query by hash, then the stored bytes against the freshly built ones; the tables' checks | `every_spend_guard_refuses_on_its_own` (binding) |
| 3 | not revoked | `OPEN` only | `m6_2_a_revoked_approval_is_never_spent` |
| 4 | the request not denied or invalidated | an approval exists only for a request decided `GRANTED` | `m6_2_a_decision_is_an_approvers_once_never_the_requesters_and_never_a2` |
| 5 | not expired | `now < not_after` on the registry's clock; the use's trigger | `m6_2_an_approval_is_spent_before_its_instant_never_at_it_and_never_again`, `m6_2_a_clock_moved_back_never_revives_a_passed_instant` |
| 6 | a use left | `uses < max_uses`; the trigger's sequence; `uses <= max_uses` | `m6_2_a_k_use_approval_is_spent_k_times_and_no_more`, both concurrency tests |
| 7 | the requester | the request's requester is the caller's subject; the binding's `requester` | `every_spend_guard_refuses_on_its_own` |
| 8 | agent profile and revision | the binding's `agent` | M6.1's binding tests |
| 9 | the run | the approval's request is this run's (lookup and trigger) | `m6_2_a_replayed_key_spends_nothing_and_another_runs_binding_is_not_this_runs_approval` |
| 10 | the run active | the route's `run_is_held` before the registry is asked | `m6_2_a_run_or_lease_ended_beside_a_decided_spend_waits_for_it_and_nothing_is_spent_after` |
| 11 | ownership | the route's fence (F-18) and `run_is_held` | the route's own tests (F-18) |
| 12 | lease tenure | the request's epoch and holder incarnation are the caller's; the lease fence | `every_spend_guard_refuses_on_its_own`, `m6_2_a_restart_leaves_no_approval_spendable` |
| 13 | the epoch | likewise | likewise |
| 14 | policy revision | the request's is the active one | `every_spend_guard_refuses_on_its_own` |
| 15 | the decision still asks an approval | `consider` runs only on `REQUIRE_APPROVAL` with its spec | `m6_2_a_launch_without_its_capability_or_under_another_scope_asks_for_nothing` |
| 16 | the resource identity | the binding's `resource_identity` (path and SHA-256) | M6.1's binding tests |
| 17 | the action matches | the canonical bytes, byte for byte | `m6_2_a_call_asked_again_under_another_binding_is_drift_and_spends_nothing` |
| 18 | the environment | the binding's `environment_profile` (configuration and measured level) | M6.1's binding tests |
| 19 | credential revisions | the binding's `credential_handles`; an injected credential is A2 | `m6_2_a_launch_injecting_a_credential_is_a2_and_asks_for_nothing` |
| 20 | taint | the binding's `taint_level` | `m6_2_a_run_whose_taint_rose_spends_nothing_granted_below_it` |
| 21 | privacy | the binding's `privacy_class` | M6.1's binding tests |
| 22 | obligations enforceable | kept obligations only (`consider`; the binding refuses; the route's permit) | M6.1's binding tests; equivalent mutant E2 |
| 23 | approver provenance | the approver still in the operator's set at the spend; the channel | `m6_2_an_approval_by_an_approver_outside_the_set_is_never_spent` |
| 24 | approver is not the requester | at the spend, at the decision, and by trigger | `every_spend_guard_refuses_on_its_own`, `m6_2_the_registry_tables_refuse_what_no_guard_would_write` |
| 25 | the assurance floor | the approval and the request both A1; the class | `every_spend_guard_refuses_on_its_own`, `the_a2_classes_are_the_host_a_credential_and_a_deletion` |

## 8. Scopes

Only `exact_action` is spent: the binding names the executable by path and
digest and the argv in order. A rule under any other scope is decided as
before M6.2 -- `DENY`, no request -- because the binding refuses a scope it
is not given and `executable_and_argv`'s allowlist has no source until M6.4.
`path_set`, `path_subtree`, `host_and_methods` and `credential_use` belong to
routes that are A2 under ADR-0078 as written (§14); their substitution and
widening refusals are M6.1's binding tests, not end-to-end registry tests.

## 9. The atomic transaction

```
ADR-0064 effect section (workload_route::routed)
  BEGIN IMMEDIATE
    fence; run held; key unbound
    decide: policy, capability, obligations, environment
      consider: binding built; every guard of §7 read      (read-only)
    settle: high-water raised; stale approvals EXPIRED; drift audited
    denied  -> request recorded, workload.denied audited      -> COMMIT
    allowed -> workload intent (LAUNCHING), idempotency row, egress, taint
               workload.intent_recorded audited
               approval_use inserted (trigger: OPEN, next, unexpired, own
               run and binding, this intent LAUNCHING); uses raised
               approval.used audited
  COMMIT
  broker start   (only after the commit)
end of section
```

If the intent cannot be recorded, nothing is spent; if the use is refused,
the intent rolls back with it. A committed use is never given back: an effect
that fails or is interrupted is settled by the existing effect-recovery
contract (`UNKNOWN`, never retried). A replayed key is answered from its
record before anything is decided, and spends nothing. TX068 keeps every
other path from writing a registry table.

## 10. Revocation and the other ends

`revoke_approval` is an ADR-0064 ending section around one transaction. Every
other end of a run's authority -- a run release, a lease released, taken over
or expired, an ownership revocation, a restart -- is already one, and each
fences the run before the registry is asked. The linearisation point is the
gate: a spend inside its effect section before an ending is admitted has
won -- its use and intent commit, its start reaches the broker while its run
holds authority, and the ending follows; a spend that reaches the gate while
an ending waits or stands is decided after it and refused. Nothing that has
already started is cancelled by an approval's revocation.

| race | test |
|---|---|
| revocation against a decided spend | `m6_2_a_revocation_waits_for_a_decided_spend_and_wins_against_a_later_one` |
| run release, lease release against a decided spend | `m6_2_a_run_or_lease_ended_beside_a_decided_spend_waits_for_it_and_nothing_is_spent_after` |
| restart | `m6_2_a_restart_leaves_no_approval_spendable` |
| a decision after the run ended | `m6_2_a_request_whose_run_has_ended_is_never_decided` |

Lease takeover and ownership revocation take the same ending sections; their
ordering against decided effects is F-02's own tests
(`concurrency_route_tests.rs`), unchanged.

## 11. Lifetime and the clock

An approval lives the rule's TTL (policy-bounded, at most 24 hours by the
table's check) from its grant; a request waits at most ten minutes. Each
deadline is computed with checked arithmetic and refused, never wrapped, past
the clock's range (`a_deadline_past_the_clocks_range_is_refused_never_wrapped`).
An approval is spendable a millisecond before its instant, expired at it and
after, ended `EXPIRED` durably; expiry is not a denial (`approval.expired`,
never `approval.denied`).

The registry's clock is the authority's, never below `approval_clock`'s
high-water mark, which every registry transaction raises in the same
transaction as what it observed. So an expiry and the instant that showed it
commit together or roll back together: a refused launch's transaction
commits both; a crash or error rolls both back, leaving nothing observed. Its
limit is stated: the floor is the highest instant a registry transaction has
committed -- a host clock that leaps forward and back with no registry
transaction between is not seen. There is no runtime-controlled time source.

## 12. Crash recovery

Each case reopens the actual store (a new authority on the same files) and
checks the use count, the intent, the approval's state, the audit chain and
the count of `approval.*` records against the store, and that the run is
fenced.

| window (the assignment's list) | M6.2 point | how exercised | after recovery |
|---|---|---|---|
| 1 before request persistence | `ApprovalBeforeRequest` | in-process hook | no request, nothing audited |
| 2 during request persistence | `BeforeCommit`; after commit, mid-record, synced not marked | in-process hook | absent before commit; whole and audited once after |
| 3 before the burn transaction | -- | not separately: window 5's points are later in the same transaction and leave nothing | -- |
| 4 after the counter changes, before the intent | not reachable: the intent is inserted first and the use (which raises the counter) after | -- | -- |
| 5 after the intent, before commit | `ApprovalBeforeUse`; `BeforeCommit` | in-process hook | neither use nor intent; the approval open; nothing at the broker |
| 6 immediately after commit | `AfterCommitBeforeAudit`, `MidAuditRecord`, `AfterAuditWriteBeforeSync`, `AfterAuditSyncBeforeMark`, `AfterAuditMark` | in-process hook | both; the workload `UNKNOWN`, never run; the use audited once |
| 7 before broker dispatch | `WorkloadAfterIntent` | in-process hook | both; `UNKNOWN` |
| 8 after dispatch, before settlement | `WorkloadAfterStart`, `WorkloadAfterBroker`; after it, `WorkloadAfterOutcome` | in-process hook | both; `UNKNOWN`, or `COMPLETED` |
| 9 during revocation | `BeforeCommit`; `AfterCommitBeforeAudit`, `MidAuditRecord` | in-process hook | `OPEN` and nothing audited, or `REVOKED` and audited once |
| 10 during schema migration | a migration step failing midway | ordinary rollback (in-memory) | version 14, no registry table |

Tests: `m6_2_a_crash_in_every_window_of_a_spend_leaves_both_or_neither_and_spends_once`
(eleven windows), `m6_2_a_crash_while_a_request_is_recorded_leaves_it_whole_or_absent`,
`m6_2_a_crash_while_revoking_leaves_the_approval_revoked_or_open`,
`a_version_15_migration_that_fails_midway_leaves_none_of_it`.

**Real process termination: not exercised for the registry.** The
repository's real-process harness (`tests/state_crash.rs`) re-executes an
integration test binary that calls `std::process::abort()` at the window.
Neither place can host a registry spend: TX010 forbids starting a process
anywhere in the authority's `src/` (its unit tests included) and TX006 keeps
`std::process` and `std::env` out of `state/`; and an integration test
builds the library without `cfg(test)`, where no approver set can be attached
and no decision seam exists -- so no approval can be granted or spent there,
which is the property M6.2 must keep. Building it would mean an
approval-minting seam in a non-test build, or weakening TX010 or TX006;
neither was done. What the real-process harness does show, unchanged, is the
transaction and audit-outbox mechanism every registry transaction uses:
`a_real_process_killed_in_each_audit_window_recovers` (an admission aborted
in windows B to F). A power loss is not simulated by either.

**Follow-up (2026-11-27, M6.2.1).** Real process termination is now
exercised for the registry, from outside the authority: an external
supervisor (`make approval-registry-crash-evidence`) runs the library's
unit-test executable as a child, kills it with SIGKILL at each of 34
windows -- this table's, the decisions', the expiry's, and a migrating
start's -- and recovers the files it left in another process. TX010, TX006
and the shipped build's lack of an approver set are unchanged. The design,
the matrix and its results are [M6_2_1_SECURITY_EVIDENCE.md](M6_2_1_SECURITY_EVIDENCE.md) §§3-7; the
paragraph above is kept as M6.2 found it.

This is exactly-once *consumption* -- a property of one database transaction.
It is not exactly-once execution: a workload interrupted after its start is
`UNKNOWN` under the existing contract, never retried and never refunded.

## 13. Audit and privacy

Seven kinds: `approval.requested`, `approval.granted`, `approval.denied`,
`approval.expired` (`kind` request or approval; a request's `cause` `WINDOW`
or `RUN_ENDED`), `approval.used`, `approval.revoked`,
`approval.drift_detected`. A use names its approval, request, invocation --
the intent's own `workload.intent_recorded` -- run, binding hash, approver,
assurance, policy revision and sequence. No registry record carries a
binding member, the command's arguments or the executable's path
(`m6_2_the_registrys_audit_links_each_use_and_holds_no_binding_text`); a
rolled-back use leaves no `approval.used` (§12's windows 1 and 5).

## 14. Route integration

The public sandboxed `process.exec` (ADR-0052) is the one route. Every other
route decides in `Environment::Host` -- `fs.*`, the kernel-performed
`net.http` hop, host process execution -- and ADR-0078 §1 as accepted makes
`Environment::Host` of any verb A2, as it makes `secret.use`, `fs.delete`, an
injected credential and a standing grant's creation. No presence factor
exists, so each keeps its `DENY` and records no request. The in-process API's
launches carry no tenure and are never approvable. An approved launch is
planned `ALLOW` with the reason `ALLOWED_BY_RULE` on the unchanged wire.

## 15. The M6.2/M6.3 boundary

| seam | caller in M6.2 | compiled |
|---|---|---|
| `Authority::decide_approval` | the Linux route tests | always; `expect(dead_code)` outside Linux test builds |
| `Authority::revoke_approval` | the Linux route tests | likewise |
| `Authority::attach_approvers` | the Linux route tests | Linux test builds only |
| `Attachments::approvers` | read by the registry; set by `attach_approvers` alone | always; empty unless attached |

No DWKP, approver-endpoint, broker or CLI path names any of them (TX068);
the approver endpoint still holds no operation (TX065). In the shipped build
the approver set is empty: no approval can be decided, and none spent.

## 16. Architecture rules

- **TX062** keeps both patterns; its exemption names `approvals.rs`,
  `schema.rs` and `approval_route_tests.rs`, nothing in the server, and
  `test_f18_approver_identity.py` pins the list.
- **TX068** (new): only the registry, its schema and its route tests write a
  registry table; nothing else names `decide_approval`, `revoke_approval`,
  `attach_approvers` or the approver set. Its fixtures -- the CLI deciding,
  attaching and reaching the set; the runtime resetting a spent approval and
  forging a use -- are five findings; the comments none.
- **TX061, TX065, TX066, TX067** unchanged. `test_m6_2_approval_registry.py`
  pins the seams' compilation conditions and `dead_code` reasons, the use's
  place after the intent, the mutation table, the evidence inventory and the
  CI step.

## 17. Tests

M6.2's own tests (33 Rust, 8 Python), and the existing tests it changed:

| where | tests | platforms |
|---|---|---|
| `state/approval_route_tests.rs` (new) | 26 real-authority route tests (a real store, policy, binding, transactions and audit; the route tests' fake broker), each printing its `APPROVAL-EVIDENCE` line after its assertions | Linux |
| `state/workload_secret_tests.rs` | `m6_2_a_launch_injecting_a_credential_is_a2_and_asks_for_nothing`, in the kernel keyring | Linux |
| `state/approvals.rs` | 4: the A2 classes; every spend guard flipped on its own (12 records, the binding and the revision arguments, 4 tenures); deadline arithmetic; the pending bounds | Linux, macOS, Windows |
| `state/schema.rs` | 2: the 14-to-15 migration; a migration failing midway | Linux, macOS, Windows |
| `tests/architecture/test_m6_2_approval_registry.py` (new) | 8: the record, the mutation table, a mutant per spend guard, the evidence inventory and its parser's refusals, the seams' compilation, the use after the intent, the CI step | every platform's pytest |
| `test_boundaries.py`, `test_f18_approver_identity.py`, `test_m6_1_approval_binding.py` | TX068 on its fixtures and in the required list; TX062's exemption pinned; the binding's one production caller | every platform's pytest |
| `state/binding_route_tests.rs`, `tests/state_crash.rs`, `tests/resource_workspace.rs`, `tests/state_ownership.rs`, `state/workload_route_tests.rs` | the registry's tables exist and hold no row after a binding is built; the new crash points in the exhaustive match; the downgrades to 14 drop the registry; the route tests include the registry's | as before |

No property-based (proptest) test is added; the binding's property tests are
M6.1's, unchanged. Concurrency, as asserted:

| case | contenders | started | uses | intents | the rest |
|---|---|---|---|---|---|
| one single-use approval | 100 handles, one barrier | 1 | 1 | 1 | 99 denied or refused (the split is timing's; each asserted to be one of the two, none run) |
| one 5-use approval | rounds of 8 handles until 5 uses | 5 | 5 | 5 (and the warm-up's) | never more than 5 uses after any round |
| revocation against a decided spend | 2 handles | 1 | 1 | 1 | the revocation waits at the gate, then wins: the next launch denied |
| run release, lease release against a decided spend | 2 handles, each | 1 | 1 | 1 | the end waits at the gate; the start reaches the broker while the run is `ACTIVE`; nothing after |


**Binding drift, by where it is proved:**

| drift | the sandboxed route, end to end | the registry's unit tests | M6.1's binding tests | not reachable in M6.2 |
|---|---|---|---|---|
| argv changed | yes (drift) | | yes | |
| taint risen | yes | | yes | |
| another run, identical bytes | yes (refused) | | | |
| requester, session, epoch, incarnation | through the fences (restart, run and lease ends) | each flipped | requester | a new requester within a run |
| policy revision | through the restart | flipped | | a revision change within an incarnation |
| a credential injected | yes (A2, no request) | classifier | revision | |
| executable digest, environment measurement, profile revision, workspace root, privacy, obligations | | binding bytes | each member | fixed within an incarnation |
| file identity, network identity, path sets, subtrees, hosts and methods | | | each | the routes are A2 (§14) |

## 18. Mutation review

`make approval-registry-mutations` (the repository's `_finding_review`), local,
WSL2, in a filesystem copy of the checkout (`~/p53`), against the frozen tree:
**49 mutants, 49 killed, 0 survived, 0 invalid**, in 1,173 s (started
2026-11-26T15:08:15Z, finished 2026-11-26T15:27:48Z). The unmutated baseline
passed first; each mutant was applied (its anchor matched exactly once),
built, and failed at least one named test of the detector -- the registry's
unit tests, its Linux route tests, the A2 credential case and schema 15's
migration tests; no kill is a compilation failure, a missing anchor or an
unexecuted test. Every file was restored and checked: after the campaign
`approvals.rs`, `workload.rs` and `schema.rs` matched their recorded digests
and the reviewed tree byte for byte. The record is
`target/m6-2-evidence/record.json` in the copy.

| id | file | mutation | invariant | killed by (first of n) | seconds |
|---|---|---|---|---|---|
| A01 | `approvals.rs` | the host environment not A2 | ADR-0078: host is A2 | `the_a2_classes_are_the_host_a_credential_and_a_deletion` (1) | 21.0 |
| A02 | `approvals.rs` | a credential injection not A2 | an injected credential is A2 | `the_a2_classes_are_the_host_a_credential_and_a_deletion` (2) | 20.0 |
| A03 | `approvals.rs` | secret.use not A2 | secret.use is A2 | `the_a2_classes_are_the_host_a_credential_and_a_deletion` (1) | 20.9 |
| A04 | `approvals.rs` | fs.delete not A2 | fs.delete is A2 | `the_a2_classes_are_the_host_a_credential_and_a_deletion` (1) | 20.4 |
| A05 | `approvals.rs` | an A2 launch considered | no request for an A2 launch | `m6_2_a_launch_injecting_a_credential_is_a2_and_asks_for_nothing` (1) | 21.1 |
| A06 | `approvals.rs` | a launch without its capability considered | no request without the capability | `m6_2_a_launch_without_its_capability_or_under_another_scope_asks_for_nothing` (1) | 20.6 |
| A07 | `approvals.rs` | an approval spendable at its instant | expired at the instant | `m6_2_an_approval_is_spent_before_its_instant_never_at_it_and_never_again` (1) | 21.1 |
| A08 | `approvals.rs` | an expired approval left open | an expired approval ends EXPIRED | `m6_2_a_clock_moved_back_never_revives_a_passed_instant` (2) | 21.5 |
| A09 | `approvals.rs` | the clock's high-water mark ignored | the clock never below its high-water mark | `m6_2_a_clock_moved_back_never_revives_a_passed_instant` (1) | 20.7 |
| A10 | `approvals.rs` | the clock's high-water mark never recorded | the high-water mark recorded | `m6_2_a_clock_moved_back_never_revives_a_passed_instant` (2) | 21.5 |
| A11 | `approvals.rs` | the requester not checked | requester | `every_spend_guard_refuses_on_its_own` (1) | 20.6 |
| A12 | `approvals.rs` | the session not checked | session | `every_spend_guard_refuses_on_its_own` (1) | 21.1 |
| A13 | `approvals.rs` | the epoch not checked | epoch | `every_spend_guard_refuses_on_its_own` (1) | 21.6 |
| A14 | `approvals.rs` | the incarnation not checked | holder incarnation | `every_spend_guard_refuses_on_its_own` (1) | 20.0 |
| A15 | `approvals.rs` | the policy revision not checked | policy revision | `every_spend_guard_refuses_on_its_own` (1) | 21.3 |
| A16 | `approvals.rs` | the binding's bytes not compared | binding byte equality | `every_spend_guard_refuses_on_its_own` (1) | 20.6 |
| A17 | `approvals.rs` | a self-approval spendable | no self-approval at spend | `every_spend_guard_refuses_on_its_own` (1) | 20.7 |
| A18 | `approvals.rs` | an approval's assurance not checked | approval assurance A1 | `every_spend_guard_refuses_on_its_own` (1) | 21.3 |
| A19 | `approvals.rs` | a request's required assurance not checked | request assurance A1 | `every_spend_guard_refuses_on_its_own` (1) | 20.3 |
| A20 | `approvals.rs` | a use past the limit | a use left | `every_spend_guard_refuses_on_its_own` (1) | 20.6 |
| A21 | `approvals.rs` | the approver set not checked at the spend | approver still in the set | `m6_2_an_approval_by_an_approver_outside_the_set_is_never_spent` (1) | 21.3 |
| A22 | `approvals.rs` | a drift not detected | drift recorded | `m6_2_a_call_asked_again_under_another_binding_is_drift_and_spends_nothing` (1) | 21.2 |
| A23 | `approvals.rs` | a request recorded twice | one pending request per binding | `m6_2_a_launch_needing_approval_is_requested_once_denied_and_nothing_runs` (5) | 15.2 |
| A24 | `approvals.rs` | the run's pending bound removed | run bound (16) | `the_pending_bounds_are_the_runs_and_the_stores` (2) | 21.4 |
| A25 | `approvals.rs` | the store's pending bound removed | store bound (1024) | `the_pending_bounds_are_the_runs_and_the_stores` (1) | 20.6 |
| A26 | `approvals.rs` | a request's window not bounded | ten-minute window | `a_deadline_past_the_clocks_range_is_refused_never_wrapped` (2) | 21.2 |
| A27 | `approvals.rs` | a request past its window left pending | a passed window ends the request | `m6_2_a_request_waits_ten_minutes_at_most_and_then_ends_expired` (1) | 22.2 |
| A28 | `approvals.rs` | a request decided at its window's end | no decision at the window's end | `m6_2_a_request_waits_ten_minutes_at_most_and_then_ends_expired` (1) | 21.6 |
| A29 | `approvals.rs` | a decision by an approver outside the set | decision by an approver in the set | `m6_2_a_decision_is_an_approvers_once_never_the_requesters_and_never_a2` (2) | 21.1 |
| A30 | `approvals.rs` | a decision by the requester | no decision by the requester | `m6_2_a_decision_is_an_approvers_once_never_the_requesters_and_never_a2` (1) | 21.1 |
| A31 | `approvals.rs` | an A2 decision recorded | no A2 decision | `m6_2_a_decision_is_an_approvers_once_never_the_requesters_and_never_a2` (1) | 21.0 |
| A32 | `approvals.rs` | a request decided twice | decided once | `m6_2_a_decision_is_an_approvers_once_never_the_requesters_and_never_a2` (1) | 21.1 |
| A33 | `approvals.rs` | a revocation not serialised with decided effects | revocation inside ADR-0064's gate | `m6_2_a_revocation_waits_for_a_decided_spend_and_wins_against_a_later_one` (1) | 67.0 |
| A34 | `approvals.rs` | a revocation that ends nothing | revocation ends the approval | `m6_2_a_revoked_approval_is_never_spent` (3) | 19.6 |
| A35 | `workload.rs` | an approval permits nothing | an approval permits its launch | `m6_2_a_crash_in_every_window_of_a_spend_leaves_both_or_neither_and_spends_once` (13) | 68.8 |
| A36 | `workload.rs` | an approved launch spends no use | the use is spent | `m6_2_a_run_whose_taint_rose_spends_nothing_granted_below_it` (12) | 69.6 |
| A37 | `workload.rs` | a denied launch records no request | a denial records its request | `m6_2_a_clock_moved_back_never_revives_a_passed_instant` (26) | 9.1 |
| A38 | `workload.rs` | a decided launch's expiries and drift never recorded | expiries and drift recorded | `m6_2_a_call_asked_again_under_another_binding_is_drift_and_spends_nothing` (3) | 22.5 |
| A39 | `schema.rs` | the clock may fall (schema) | the clock never falls (DB) | `version_15_adds_an_empty_registry_and_grants_nothing` (2) | 21.1 |
| A40 | `schema.rs` | a decided request reopened (schema) | a request decided once (DB) | `m6_2_the_registry_tables_refuse_what_no_guard_would_write` (1) | 22.0 |
| A41 | `schema.rs` | a self-approval recorded (schema) | no self-approval (DB) | `m6_2_the_registry_tables_refuse_what_no_guard_would_write` (1) | 20.8 |
| A42 | `schema.rs` | an approval's uses not its records (schema) | uses are use records (DB) | `m6_2_the_registry_tables_refuse_what_no_guard_would_write` (1) | 21.2 |
| A43 | `schema.rs` | a use with no intent (schema) | a use needs its LAUNCHING intent (DB) | `m6_2_the_registry_tables_refuse_what_no_guard_would_write` (1) | 22.0 |
| A44 | `schema.rs` | the database's use count not raised (schema) | the DB counts each use | `m6_2_a_granted_approval_is_spent_once_with_its_intent_and_never_again` (13) | 15.7 |
| A45 | `workload.rs` | a refused use swallowed, its intent kept | a refused use rolls its intent back | `m6_2_a_crash_in_every_window_of_a_spend_leaves_both_or_neither_and_spends_once` (1) | 20.5 |
| A46 | `approvals.rs` | a request's deadline wrapped | request deadline never wraps | `a_deadline_past_the_clocks_range_is_refused_never_wrapped` (1) | 21.0 |
| A47 | `approvals.rs` | an approval's deadline wrapped | approval deadline never wraps | `a_deadline_past_the_clocks_range_is_refused_never_wrapped` (1) | 21.5 |
| A48 | `approvals.rs` | a request whose run has ended decided | no decision for an ended run | `m6_2_a_request_whose_run_has_ended_is_never_decided` (1) | 21.8 |
| A49 | `schema.rs` | an approval of an ended run's request recorded (schema) | no approval of an ended run's request (DB) | `m6_2_a_request_whose_run_has_ended_is_never_decided` (1) | 22.7 |

Three mutants are equivalent and not in the table
(`APPROVAL_REGISTRY_EQUIVALENT`), each verified in the code: consider's
`REQUIRE_APPROVAL` check (a decision carries an approval shape only when its
effect is `REQUIRE_APPROVAL`, `policy/eval.rs`), its kept-obligations check
(the binding refuses, `ObligationUnenforceable`) and its `exact_action` check
(the binding refuses a scope it is not given, `ScopeMismatch`).

On the way here: a first campaign (43 mutants) left A43 alive -- its raw
insert was refused by a foreign key before the trigger clause under test, so
the test proved nothing about that clause; the test now inserts a use on a
real, settled intent of the run, which only the clause refuses, and A43 is
killed by it. A second attempt stopped at A35, which made one test wait for
an interleaving that could not happen; the wait is now bounded. Neither
attempt's results are counted above.

## 19. Local and hosted evidence

Everything above is local: WSL2 (Linux 6.18.58.1-microsoft-standard-WSL2),
rustc and cargo 1.98.1, Python 3.12.14, in a filesystem copy of the checkout
at `4d18030` with this change applied. None of it is native Windows or macOS
evidence.

| command | result |
|---|---|
| `make fmt-check`, `make lint` (clippy `-D warnings`, ruff), `make typecheck` | exit 0 |
| `make schema-check`, `make docs`, `make arch`, `make adr-history`, `make security` | exit 0 |
| `make eval-check` | exit 0 (788 s) |
| `make test` | exit 0: cargo 1,783 passed, 0 failed, 126 ignored; pytest 2,207 passed, 18 skipped |
| `make approval-registry-evidence` | exit 0: 27 cases, each once |
| `make approval-registry-mutations` | 49 of 49 killed (§18) |
| `cargo build --workspace --release` | exit 0 |
| `dwcheck adr --record` | `accepted.sha256` unchanged |

The ignored and skipped tests are the repository's own: evidence-only tests
run by their tasks, and platform guards. NOT EXERCISED: real process
termination for the registry (§12), and every hosted run. `Cargo.lock`,
dependency pins, deny rules and the authority's allowlists are unchanged.

**Follow-up (2026-11-27).** M6.2 was committed as `b8414fd`; CI #227
([run 45859307449](https://github.com/Onwcan/DireWolf/actions/runs/45859307449)) passed 33 of 33 job records, its `authority boundary`
job printing each of the 27 cases once. M6.2.1's evidence -- the
real-process crash matrix, the release build's separation scan, seven more
route cases -- is [M6_2_1_SECURITY_EVIDENCE.md](M6_2_1_SECURITY_EVIDENCE.md); its hosted run is pending.
What follows is the paragraph as written before that commit.

Hosted: none yet -- this change is not committed. Its first hosted run carries `make test` (the route tests on
Linux; the unit and schema tests on Linux, macOS and Windows) and the new
`make approval-registry-evidence` step in the `authority-transport` job,
which requires each of the registry's evidence cases once.

## 20. Owner decisions

**ADR-0080** (each Proposed; a recommendation, not a decision):

| | decision | recommendation |
|---|---|---|
| OD-1 | the scope: the sandboxed `process.exec` at A1 under `exact_action`; every other class `DENY`, no request | accept: it is ADR-0078 as accepted, read literally |
| OD-2 | schema 15 as §3, every invariant also a trigger, nothing inherited | accept |
| OD-3 | bounds: 16 waiting per run, 1024 per store, a ten-minute window | accept; revisit with M6.3's prompt fatigue |
| OD-4 | revocation as an ADR-0064 ending; the other ends fence rather than end rows | accept |
| OD-5 | an approved launch's wire plan unchanged (`ALLOW`, `ALLOWED_BY_RULE`), the approval in the audit log | accept for M6.2; M6.3 may surface the approval to the trusted client |
| OD-6 | no production approver set and no production decision before M6.3; TX062's exemption and TX068 | accept |

Acceptance needs M6.2's commits on `main` with a green hosted run, then a
status line, its digest (`dwcheck adr --record`), the index row, the README
count and the plan's state, in one change.

**ADR-0064's acceptance package.**
[ADR-0064](adr/0064-f02-authority-endings-serialised-with-decided-effects.md)
(F-02) is Proposed; the M6 plan offers it for acceptance with M6.2's
closeout. It is **not** accepted here.

- *Why the gate is sufficient.* Every effect the registry can authorise is a
  sandboxed start, already an effect section from before its decision
  transaction to its start; the burn is inside that transaction; and every
  end of authority -- the new revocation included -- is an ending section.
  No registry-local lock exists or is needed, and no amendment is.
- *Consumption against an ending.* The gate orders them: an ending waits for
  every effect section open when it arrives and holds back new ones.
- *When consumption wins.* Its use and intent commit, its start reaches the
  broker while its run is `ACTIVE`, then the ending commits; a started
  workload is its environment's (ADR-0052 §8) and ends with its run's
  environment.
- *When revocation wins.* A launch that reaches the gate while the ending
  waits or stands is decided after it: the approval is `REVOKED` or the run
  fenced, and the launch is denied or refused with nothing spent.
- *In-flight effects.* Settled by the existing contract: an interrupted start
  `UNKNOWN`, never run again.
- *Restart.* A new incarnation invalidates every lease and reaps every run;
  the requests carry the old epoch and incarnation; nothing of the old tenure
  is spent.
- *Its mutation review.* `make authority-concurrency-mutations`: 20 mutants
  (G1-G5, E1-E8, C1-C7), each killed, local.
- *What M6.2 adds.* A new end of authority taking an ending section, as its
  "Revisit if" requires; the revocation and run- and lease-end races of §10;
  mutant A33 (the revocation outside the gate) killed.
- *What stays true.* Its residuals: the gate is not durable; the evidence is
  the authority's ordering against a fake broker and SQLite contention, not
  real-process concurrency; per-tunnel mediation and concurrency within a run
  are not built. Its §6 "store schema 14" describes its own change; its
  per-tunnel residual's "a schema 15" is now the next free version.
- *Recommendation.* Accept as written once M6.2's commits have a green hosted
  run, which carries §10's tests.

Acceptance, when authorised, is one change: ADR-0064's status line (and
"Would amend (on acceptance)" read as "Amends"); `dwcheck adr --record` (one
added line in `accepted.sha256`); its index row, and ADR-0011's and
ADR-0039's rows naming what it amends; the README count; the ledger's F-02
row and acceptance paragraph; `tests/architecture/test_f02_concurrency.py`'s
`test_adr_0064_is_proposed_and_records_its_evidence`, which pins Proposed and
changes with it; and the documents that say Proposed
(`F02_AUTHORITY_CONCURRENCY.md`, the M6 plan, this report).

## 21. M6.3 entry prerequisites

(2026-11-27: item 1 is met for M6.2 at `b8414fd`, CI #227; M6.2.1's own
commits and hosted run join it -- [M6_2_1_SECURITY_EVIDENCE.md](M6_2_1_SECURITY_EVIDENCE.md) §17.)

1. M6.2's commits on `main`, and their hosted run green -- the route tests
   and `make approval-registry-evidence` among it.
2. ADR-0080 decided, and ADR-0064 accepted, each its own change.
3. M6.3's own record: the approver endpoint's operations calling
   `decide_approval` and `revoke_approval`; the approver set attached from
   the operator's configuration; the request rendered from canonical data to
   the trusted client; TX065 replaced under that decision.
