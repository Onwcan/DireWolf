# M6.2.1 security evidence: real-process crash recovery, binding drift and scope

**As of 2026-11-27.** M6.2.1 hardens M6.2's evidence
([M6_2_IMPLEMENTATION.md](M6_2_IMPLEMENTATION.md)) and adds no authority:
built and verified locally, not committed, hosted evidence pending.
[ADR-0080](adr/0080-the-approval-registry-durable-requests-and-atomic-consumption.md)
and [ADR-0064](adr/0064-f02-authority-endings-serialised-with-decided-effects.md)
stay Proposed. The shipped build still attaches no approver set and has no
decision path: nothing is approvable before M6.3. The milestone order stays
M6 → M3.5 → M7 → M8 → M9; M6.3 has not started.

**Hosted-verified and closed (2026-11-27):** committed as `f81b898`, CI
#228 green, both records accepted -- §20. The sections before it say
what held when this report was written.

M6.2 left three evidence lines open: crash recovery PARTIAL, scope and
binding drift PARTIAL, and real process termination NOT EXERCISED for the
registry. This report records how each was closed, case by case, within
M6.2's supported scope -- the sandboxed `process.exec` at A1 under
`exact_action` -- and what stays outside it.

## 1. Baseline

| | |
|---|---|
| Revision | `b8414fd` on `main` (`b8414fde37c2c497ec6ad4fa22c3956f93d3cdcb`), equal to `origin/main`; M6.2 as reported |
| CI | #227, [run 45859307449](https://github.com/Onwcan/DireWolf/actions/runs/45859307449): 33 of 33 job records, attempt 1 |
| Push workflow (CodeQL) | #43, [run 45859308380](https://github.com/Onwcan/DireWolf/actions/runs/45859308380): success |
| Registry evidence | `authority boundary`: 27 `APPROVAL-EVIDENCE` lines and `approval registry evidence: 27 cases, each once` |
| Store schema | 15, unchanged by M6.2.1 |
| Records | ADR-0080 Proposed; ADR-0064 Proposed |

M6.2's baseline hosted evidence is verified: the registry's route tests ran
on a hosted Linux runner and each of its 27 cases reported once.

## 2. What M6.2 could not run, and why

M6.2's crash windows were in-process hooks on a reopened store. The
repository's real-process harness (`tests/state_crash.rs`) is an integration
test that re-executes itself and aborts at a window. It cannot host a
registry spend: an integration test builds the library without `cfg(test)`,
where no approver set can be attached, so no approval can exist there --
which is the property the shipped build must keep. Moving the harness into
the authority's source would have needed a process start inside it (TX010
forbids one) or the environment read inside `state/` (TX006 forbids it).
M6.2.1 keeps all three properties and runs the processes from outside.

## 3. The real-process harness

### 3.1 The design

```
scripts/dw.py (supervisor, outside the authority)
  cargo test -p dwkd-authority --lib --no-run --message-format=json
    -> exactly one library unit-test executable (cfg(test), Linux)
  for each of 34 cases:
    crash child:  <exe> --ignored --exact ...::approval::m6_2_1_crash_child
                  DW_M621_CRASH_CASE, DW_M621_DIR, DW_M621_READY
      builds its authority in DW_M621_DIR, arms its crash hook;
      at the case's window: writes "case point" to ready.partial,
      renames it to ready, and parks -- it never ends by itself
    supervisor:   sees ready; os.kill(child.pid, SIGKILL); waits;
                  requires the exit to be that SIGKILL
    recovery:     <exe> --ignored --exact ...::approval::m6_2_1_recovery_child
                  DW_M621_RECOVER_CASE, DW_M621_DIR  (a new process)
      reads the dead process's files raw, then starts a new incarnation
      on them; asserts every invariant; prints one APPROVAL-CRASH-EVIDENCE
      line after the assertions
    supervisor:   requires exit 0, one test run, one line whose every
                  field is the case's expectation
```

- **The children** are two `#[ignore]`d unit tests of the Linux route tests
  (`state/approval_route_tests.rs`). Without an assignment in their
  environment they return at once -- a vacuous pass the supervisor never
  counts, since it requires the handshake and the evidence line.
- **The assignment and the handshake** are `src/crash_child.rs`, compiled
  only into Linux unit-test builds (`#[cfg(all(test, target_os = "linux"))]`
  in `lib.rs`). It lives outside `state/` for TX006's reason, as
  `scratch.rs` does, and it starts, signals and waits for no process
  (TX010): at its window it writes the handshake and stands still in
  `std::thread::park()`.
- **The supervisor** is `make approval-registry-crash-evidence`
  (`scripts/dw.py`), outside the authority's trusted computing base. It
  selects the executable from cargo's own JSON messages -- exactly one
  compiler artifact of the library target `dwkd_authority`, with the test
  profile and an executable; zero or two fail the task -- and requires
  `--list --ignored` to name each child exactly once.
- **Termination** is `os.kill(pid, SIGKILL)` of the one child the
  supervisor started, in a new session of its own; no name-based kill, no
  process group signal, no global setting. Core dumps are disabled for the
  children only (`RLIMIT_CORE` 0, set in the child before it runs). SIGKILL
  runs no unwinding, destructor, rollback or flush: what the store and the
  audit log hold is what the dead process left.
- **The recovery** is a separate process on the same directory. The
  supervisor removes every `DW_M621_*` variable of its own environment
  before setting a child's, so no stale assignment is inherited.
- **A migrating start** gained four crash points
  (`CrashPoint::MIGRATION`: before the migration's transaction, after its
  schema, after its `store.migrated` record, after its commit), crossed by
  `migrate_store` through the start's existing crash hook (§4).

### 3.2 What counts, and what does not

A case is evidence only when the supervisor saw the child's handshake for
that case's window, its own SIGKILL ended the child, and the recovery passed
with exactly one evidence line matching the case on every field. Every other
ending fails the task:

| ending | judged as |
|---|---|
| the handshake for the case's window, then the supervisor's SIGKILL | the crash half of a case |
| the child exits 0 before any handshake (an early exit, or a filtered or renamed test) | `ended (exit 0) before its window` |
| a panic (exit 101), an abort (SIGABRT) | `ended ... before its window` |
| a handshake naming another case or point | `stood at another window` |
| no handshake within 120 s (a deadlock, a missed window) | `never reached its window`; the child is killed |
| a handshake, then any ending other than the supervisor's SIGKILL | `not the supervisor's SIGKILL` |
| the recovery fails, runs no test, or runs two | `recovery child failed` / `ran no test` |
| no evidence line, two, or an unreadable one | `expected one recovery evidence line` / `unreadable` |
| any field other than the expectation | `found <field>=..., expected ...` |

Each is tested: `judge_crash_child` and `judge_crash_recovery` on every
platform, and the supervisor itself on Linux against a stand-in child that
exits early, panics, aborts, stands at another window, hangs, fails its
recovery, runs no test, or reports a wrong count
(`tests/architecture/test_m6_2_1_crash_evidence.py`). No sleep is evidence:
the supervisor's poll only notices the handshake file.

### 3.3 What it is not

A process kill is not a power loss: bytes written but not synced survive it
in the page cache, so the `written, not synced` windows show the outbox's
ordering under a process crash, not under a power cut. Nothing here is
exactly-once execution: a workload interrupted after its start is `UNKNOWN`
under the existing contract, never retried and never refunded.

## 4. Production test-seam separation

The registry's test-only seams, and how each is kept out of every
non-test build:

| seam | compiled only into | pinned by |
|---|---|---|
| the approver set's attachment (`Authority::attach_approvers`) | Linux unit-test builds | the record test `test_the_seams_have_no_production_caller`; mutant A50 |
| the crash children's module (`crash_child`), their variables and entry points | Linux unit-test builds | `test_the_crash_children_are_compiled_into_linux_unit_test_builds_only`; mutant A51 |
| `Scratch::kept` | Linux unit-test builds | the same test |
| the pre-M6 host-launch test approval (`with_test_approval`, `TEST_APPROVAL`) | unit-test builds; `approved()` answers `false` in every other build | the same test |
| the decision and revocation (`decide_approval`, `revoke_approval`) | every build, with no production caller | `test_the_seams_have_no_production_caller`, TX065 |

Complementary checks:

1. **Compilation conditions** in the source, pinned by the record tests
   above.
2. **No environment activation.** Only `src/crash_child.rs` names a
   `DW_M621_*` variable; no production code reads one (record test).
3. **No Cargo feature.** `dwkd-authority`'s manifest declares no
   `[features]`: nothing can switch a seam on (record test).
4. **The release artifacts.** `make approval-registry-separation` builds the
   workspace for release and reads every release executable and the
   authority's release library for twelve traces: six identifiers as both
   Rust manglings spell a compiled symbol (`16attach_approvers`,
   `18with_test_approval`, `13TEST_APPROVAL`, `11crash_child`,
   `18m6_2_1_crash_child`, `21m6_2_1_recovery_child`) and six string
   literals (the four `DW_M621_*` variables and both children's test
   paths). Before it may pass it finds every trace in the unit-test
   executable, a compiled authority symbol in the release library and the
   registry's binding schema literal in the release daemon -- so a stripped
   or wrong file cannot pass for a clean one (the release executables are
   stripped of symbols; the library is not). Local result: 7 release
   artifacts, none of the 12 traces.
5. **The crash hook.** The migration's points are crossed through
   `StartOptions::crash_hook`, the crash hook every store transaction has
   had since M3d. Its default is `None`, the daemon never sets one, and a
   hook can only continue or stop: a stop fails the start closed. It cannot
   create, decide or spend anything.

A finding of the scan's first version: the release library's metadata holds
the *names* of items a `cfg` removed -- observed for `with_test_approval`
and `crash_child`, beside other test modules' names, which rustc keeps for
its diagnostics about configured-out items -- and none of their code. A
bare-name match therefore proves nothing either way; the scan matches the
compiled and literal forms only, and its tests show a bare name is not a
trace.

**PRODUCTION TEST-SEAM SEPARATION: PASS.**

## 5. The crash matrix

Each row is one real process killed at its window and one recovery process.
"Left" is what the recovery read raw, before anything wrote: the store's
version, then its requests, approvals, uses and workload intents.

| case | window | point | durable | left (v; req, appr, use, intent) |
|---|---|---|---|---|
| `spend-before-transaction` | before the spend's transaction | A | no | 15; 1, 1, 0, 0 |
| `spend-after-intent-before-use` | the intent written, the use not | w | no | 15; 1, 1, 0, 0 |
| `spend-use-before-commit` | the use written, not committed | B | no | 15; 1, 1, 0, 0 |
| `spend-after-commit` | committed, audit not written | C | yes | 15; 1, 1, 1, 1 |
| `spend-mid-audit-record` | half an audit record | D | yes | 15; 1, 1, 1, 1 |
| `spend-audit-written-not-synced` | the record written, not synced | E | yes | 15; 1, 1, 1, 1 |
| `spend-audit-synced-not-marked` | synced, the outbox not marked | F | yes | 15; 1, 1, 1, 1 |
| `spend-audit-marked` | marked | G | yes | 15; 1, 1, 1, 1 |
| `spend-before-dispatch` | committed, before the broker | q | yes | 15; 1, 1, 1, 1 |
| `spend-after-start` | the broker started it | t | yes | 15; 1, 1, 1, 1 |
| `spend-after-collect` | its outcome collected | r | yes | 15; 1, 1, 1, 1 |
| `spend-after-outcome` | its outcome recorded | s | yes | 15; 1, 1, 1, 1 |
| `request-before-insert` | the denied launch's request not written | x | no | 15; 0, 0, 0, 0 |
| `request-before-commit` | written, not committed | B | no | 15; 0, 0, 0, 0 |
| `request-after-commit` | committed, audit not written | C | yes | 15; 1, 0, 0, 0 |
| `request-mid-audit-record` | half an audit record | D | yes | 15; 1, 0, 0, 0 |
| `request-audit-synced-not-marked` | synced, not marked | F | yes | 15; 1, 0, 0, 0 |
| `grant-before-transaction` | before the decision's transaction | A | no | 15; 1, 0, 0, 0 |
| `grant-before-commit` | the grant written, not committed | B | no | 15; 1, 0, 0, 0 |
| `grant-after-commit` | committed | C | yes | 15; 1, 1, 0, 0 |
| `grant-mid-audit-record` | half its audit record | D | yes | 15; 1, 1, 0, 0 |
| `deny-before-commit` | the denial written, not committed | B | no | 15; 1, 0, 0, 0 |
| `deny-after-commit` | committed | C | yes | 15; 1, 0, 0, 0 |
| `ended-run-decision-before-commit` | a decision after the run ended, not committed | B | no | 15; 1, 0, 0, 0 |
| `ended-run-decision-after-commit` | committed (the request `EXPIRED`) | C | yes | 15; 1, 0, 0, 0 |
| `revoke-before-commit` | the revocation written, not committed | B | no | 15; 1, 1, 0, 0 |
| `revoke-after-commit` | committed | C | yes | 15; 1, 1, 0, 0 |
| `revoke-mid-audit-record` | half its audit record | D | yes | 15; 1, 1, 0, 0 |
| `expiry-before-commit` | the expiry observed, not committed | B | no | 15; 1, 1, 0, 0 |
| `expiry-after-commit` | the expiry committed (its run's next request with it) | C | yes | 15; 2, 1, 0, 0 |
| `migration-before-transaction` | a v14 store, before the migration's transaction | y | no | 14; no registry table |
| `migration-after-schema` | every step's schema written, not committed | z | no | 14; no registry table |
| `migration-before-commit` | `store.migrated` written, not committed | H | no | 14; no registry table |
| `migration-after-commit` | committed | I | yes | 15; 0, 0, 0, 0 |

The migration cases start from a real file-backed store of schema 14: a
store with a run on it whose registry -- all that version 15 adds -- a raw
connection dropped, setting its version back to 14, before the migrating
start. The raw read shows the whole of schema 14 or the whole of 15 -- the
version and the registry's objects together -- never between.

## 6. What every recovery checks

Before anything writes, on a raw connection to the dead process's
`kernel.db`: `PRAGMA integrity_check` is `ok`, `PRAGMA foreign_key_check`
is empty, the version and the registry's objects are as above, and the
counts are the case's. Then a new incarnation starts on the same files and:

- **the audit chain** verifies end to end (`verify_audit_log`), and against
  the store: no record pending, the log's records equal to the store's head
  and its flushed head -- every outbox window recovered exactly once;
- **linkage**: a durable use's `approval.used` names exactly one
  `workload.intent_recorded`; no `GRANTED` request lacks its approval; the
  approval's `uses` equals its use rows; each decision event is recorded
  once when durable, never when not;
- **terminal states**: the spent approval `EXHAUSTED` (single use) or still
  `OPEN`; a crashed workload `UNKNOWN`, or `COMPLETED` after its outcome --
  never run again; a request `PENDING`, `GRANTED`, `DENIED` or `EXPIRED`
  exactly as committed; a revoked approval `REVOKED`; an expired one
  `EXPIRED`, never revived;
- **restart fencing**: the dead incarnation's run is refused `UnknownRun`;
  a new run's launch of the same command spends nothing and reaches no
  broker (no `workload.start` at the new incarnation's fake broker); a
  decided request is refused `NotPending`, an undecided one of the ended
  run `RunEnded`;
- **the migration**: one run, one `store.migrated`, no approval.

## 7. Results by window

Local, seven complete runs of the crash evidence -- one first, three
repeated for flakiness, one in the full gate, and one in each mutation
campaign's baseline: 34 of 34 each, 238 real-process cases, each killed at
its window by the supervisor and recovered by another process; about 16 s a
run. No run failed.

| | |
|---|---|
| REQUEST CRASH RECOVERY | PASS -- x, B, C, D, F |
| DECISION CRASH RECOVERY | PASS -- grant A, B, C, D; deny B, C; a decision after the run ended B, C |
| PRE-COMMIT ATOMIC ROLLBACK | PASS -- every non-durable case left nothing of its transaction: no use without its intent, no intent without its use |
| POST-COMMIT DURABILITY | PASS -- every durable case kept its whole transaction |
| CONSUMPTION AND INTENT RECOVERY | PASS -- A, w, B, C, q: use and intent both or neither, the approval spent once |
| AUDIT OUTBOX RECOVERY | PASS -- C, D, E, F, G of a spend; C, D, F of a request; C, D of a grant and a revocation |
| DISPATCH AND SETTLEMENT RECOVERY | PASS -- q, t, r `UNKNOWN`; s `COMPLETED`; none run again |
| REVOCATION CRASH RECOVERY | PASS -- B, C, D |
| MIGRATION CRASH RECOVERY | PASS -- y, z, H at 14; I at 15 |
| FRESH-PROCESS RESTART FENCING | PASS -- every case |
| CLOCK ROLLBACK AFTER CRASH | PASS -- below |

**The clock after a crash.** The recovery's clock starts at two seconds
after the fixture's start -- for the expiry cases, about 58 seconds *behind*
the instant the dead process observed. A committed expiry stays `EXPIRED` and
the registry's high-water mark stays at or past the approval's instant; an
expiry observed but not committed rolls back with its high-water mark --
ADR-0080's stated floor, the highest instant a registry transaction
committed -- and the approval it would have ended is unspendable anyway,
its run fenced by the restart.

**CRASH RECOVERY: PASS. REAL-PROCESS CRASH EVIDENCE: PASS** (local; hosted
pending, §15).

## 8. The thirteen members of the binding

ADR-0079's binding has thirteen members, each inside the hash. For each, the
drift a launch can present and the evidence that it spends nothing:

| member | the drift | evidence | classification |
|---|---|---|---|
| `schema` | another binding schema | the table refuses any but `direwolf.approval.binding.v1`; a forged request of the same hash and other bytes, granted by a raw connection, is never spent (`m6_2_1_a_matching_hash_alone_is_never_authority_and_the_schema_is_fixed`; mutant A53) | PASS -- END TO END + STRUCTURAL INVARIANT |
| `verb` | another verb on the same resource | M6.1: `changing_any_one_member_changes_the_binding`; every other verb is A2 or decided without the registry, which only the sandboxed launch asks (§11) | PASS -- COMPONENT + FAIL-CLOSED REFUSAL |
| `resource_identity` | another executable, a rewritten binary | M6.1: `changing_any_one_member_changes_the_binding`, `identities_that_share_digits_never_alias`; within an incarnation the image's executable identity is the operator manifest's, fixed until a restart, which fences every run | PASS -- COMPONENT + STRUCTURAL INVARIANT |
| `canonical_args` | any argv change | five forms -- an argument changed, added, removed, reordered, and the empty argv -- each denied with a request of its own distinct hash, the approval unspent, then the approved command spent once (`m6_2_1_an_approved_command_never_widens_to_another_argv`); `m6_2_a_call_asked_again_under_another_binding_is_drift_and_spends_nothing` | PASS -- END TO END |
| `workspace` | a replaced root | M6.1: `a_replaced_workspace_root_is_another_workspace`; a run's root is bound once at admission and read from that record, and its identity is measured when the environment is prepared (`HostWorkspaceIdentity`; the real-OCI workspace evidence is the `sandbox workspace` job's) | PASS -- COMPONENT + STRUCTURAL INVARIANT |
| `environment_profile` | another image, runtime, probe or level; host for sandbox | M6.1: `changing_any_one_member_changes_the_binding`, `a_sandbox_binding_is_never_a_host_binding`; a `READY` environment's measured level equals its declared one or it is not ready, and the sandbox configuration is attached once per incarnation | PASS -- COMPONENT + STRUCTURAL INVARIANT |
| `credential_handles` | a credential added or replaced | a launch injecting a credential is A2 and asks for nothing (`m6_2_a_launch_injecting_a_credential_is_a2_and_asks_for_nothing`); no credential-bearing approval can exist in M6.2's scope | PASS -- FAIL-CLOSED REFUSAL; revision drift NOT APPLICABLE -- CURRENT SCOPE |
| `agent` | another profile or revision | M6.1: `changing_any_one_member_changes_the_binding`; a run's profile and revision are recorded at its admission and never change | PASS -- COMPONENT + STRUCTURAL INVARIANT |
| `requester` | another principal | `every_spend_guard_refuses_on_its_own` (mutant A11); another principal cannot hold the run (F-18's fence, ADR-0063's ownership) | PASS -- COMPONENT + STRUCTURAL INVARIANT |
| `scope` | another scope | every other scope creates no authority (§10); the binding refuses a scope it is not given (`BindingError::ScopeMismatch`) | PASS -- END TO END + FAIL-CLOSED REFUSAL |
| `taint_level` | the run's taint rose after the grant | `m6_2_a_run_whose_taint_rose_spends_nothing_granted_below_it` | PASS -- END TO END |
| `privacy_class` | a wider class | M6.1: `privacy_class_is_bound_and_each_class_is_its_own`; the class is the matched rule's capability's, which changes only with the policy (its revision, §9) | PASS -- COMPONENT + STRUCTURAL INVARIANT |
| `obligations` | an obligation the launch cannot keep; another kept set | an unkeepable obligation (`max_output_bytes=1`) asks for nothing; a kept one (`max_output_bytes=64`) is bound and spent (`m6_2_1_an_obligation_the_launch_cannot_keep_asks_for_nothing_and_a_kept_one_is_bound`; mutant A54) | PASS -- END TO END |

| | |
|---|---|
| THIRTEEN-MEMBER BINDING COVERAGE | PASS -- every member hashed and each drift refused; five end to end, the rest component and structural |
| RESOURCE IDENTITY DRIFT | PASS -- COMPONENT + STRUCTURAL INVARIANT |
| CANONICAL ARGUMENT DRIFT | PASS -- END TO END |
| WORKSPACE IDENTITY DRIFT | PASS -- COMPONENT + STRUCTURAL INVARIANT |
| ENVIRONMENT DRIFT | PASS -- COMPONENT + STRUCTURAL INVARIANT |
| PROFILE AND PRINCIPAL DRIFT | PASS -- COMPONENT + STRUCTURAL INVARIANT |
| TAINT AND OBLIGATION DRIFT | PASS -- END TO END |

Within M6.2's scope a run's executable identity, workspace root,
environment and profile cannot change while its approval is open without a
restart, which fences the run; so those drifts are shown by the binding's
own tests and by the invariant, not by a route test that would have to break
the invariant first.

## 9. Guards outside the hash

| guard | drift | evidence | classification |
|---|---|---|---|
| the run | another run of the same principal binds alike (M6.1) | the lookup and the use's trigger are the run's own (`m6_2_a_replayed_key_spends_nothing_and_another_runs_binding_is_not_this_runs_approval`) | PASS -- END TO END |
| the session | the same binding through another connection of the principal | refused `StaleEpoch`, nothing spent (`m6_2_1_the_same_binding_through_another_connection_of_the_principal_spends_nothing`) | PASS -- END TO END |
| the lease epoch | the lease expired and taken over | the old holder refused `StaleEpoch`, then the run `UnknownRun`, the approval unspent (`m6_2_1_a_lease_taken_over_after_it_expired_leaves_the_approval_unspent`) | PASS -- END TO END |
| the incarnation | a restart | `m6_2_a_restart_leaves_no_approval_spendable`; every real-process recovery (§6) | PASS -- END TO END, real process |
| the policy revision | the policy changed between grant and use | `every_spend_guard_refuses_on_its_own` (A15); the active policy changes only at a start, which fences | PASS -- COMPONENT + STRUCTURAL INVARIANT |
| the instant | at or after `not_after`; the clock moved back | `m6_2_an_approval_is_spent_before_its_instant_never_at_it_and_never_again`, `m6_2_a_clock_moved_back_never_revives_a_passed_instant`; §7 | PASS -- END TO END |
| the uses | past `max_uses`, concurrently | `m6_2_a_k_use_approval_is_spent_k_times_and_no_more`, both contention tests | PASS -- END TO END |
| the approval's state | revoked, expired | `m6_2_a_revoked_approval_is_never_spent`; §5 | PASS -- END TO END |
| the request key | a replayed idempotency key | answered from its record, spends nothing (as above) | PASS -- END TO END |
| the approver | outside the set at the spend; the requester | `m6_2_an_approval_by_an_approver_outside_the_set_is_never_spent`; the trigger and the guard (A17, A30, A41) | PASS -- END TO END |
| the assurance | A1 for an A2 class | §11 | PASS -- FAIL-CLOSED REFUSAL |
| the hash alone | a forged row of the same hash | §8 `schema` | PASS -- END TO END |

**POLICY, LEASE AND EPOCH DRIFT: PASS.**

## 10. Unsupported scopes

A rule under each scope, a launch it matches, and what the registry holds
afterwards (`m6_2_1_no_scope_but_exact_action_creates_any_authority`, and
M6.2's `m6_2_a_launch_without_its_capability_or_under_another_scope_asks_for_nothing`):

| scope | decision | request | approval | use | broker |
|---|---|---|---|---|---|
| `exact_action` | `REQUIRE_APPROVAL`, requested; spendable once granted | 1 | per decision | per spend | only after a spend |
| `executable_and_argv` | `DENY` | 0 | 0 | 0 | not called |
| `path_set` | `DENY` | 0 | 0 | 0 | not called |
| `path_subtree` | `DENY` | 0 | 0 | 0 | not called |
| `host_and_methods` | `DENY` | 0 | 0 | 0 | not called |
| `credential_use` | `DENY` | 0 | 0 | 0 | not called |

The registry's `consider` asks only under `exact_action` (equivalent mutant
E3 records why), and the binding refuses any other (`ScopeMismatch`).
**UNSUPPORTED SCOPE REFUSAL: PASS. EXACT-ACTION SCOPE COVERAGE: PASS.
POSITIVE BROAD-SCOPE SUPPORT: NOT ENABLED** -- `executable_and_argv`'s
allowlist has no source until M6.4, and the other four scopes belong to
classes that are A2 under ADR-0078.

## 11. A2 classes on the real routes

ADR-0078 as accepted, read literally: `Environment::Host` of any verb, a
credential injection, `secret.use` and `fs.delete` are A2. On each route that
can meet one under `REQUIRE_APPROVAL`, the action is denied, no request is
recorded and no broker is asked:

| class | route | test | classification |
|---|---|---|---|
| host `process.exec` | the process route | `the_host_floor_refuses_every_launch_without_an_approval_whatever_policy_allows` (now also: no request) | PASS -- END TO END |
| host `net.http` | the `net.http` route | `a_tainted_run_reaches_no_new_origin_and_obligations_narrow_or_deny` (now also: no request) | PASS -- END TO END |
| host `fs.write`, `fs.delete` | the filesystem route | `m6_2_1_a_file_operation_needing_an_approval_is_a2_and_asks_for_nothing`: denied, no request, no broker call, the file untouched | PASS -- END TO END |
| a credential injected into a sandboxed launch | the workload route | `m6_2_a_launch_injecting_a_credential_is_a2_and_asks_for_nothing` | PASS -- END TO END |
| `secret.use` | -- | `the_a2_classes_are_the_host_a_credential_and_a_deletion`; only the workload route consults the registry (TX068) | PASS -- COMPONENT + STRUCTURAL INVARIANT |

**A2 CLASS REFUSAL: PASS.** No A2 class is approvable: there is no
presence factor (ADR-0078 OD-3).

## 12. The twenty-five spend-time guards

M6.2's report §7 lists the guards. Their classification after M6.2.1:

| # | guard | classification |
|---|---|---|
| 1 | the request and approval exist | PASS -- END TO END |
| 2 | the record is consistent (the stored bytes, not the hash) | PASS -- END TO END (`hash-is-not-authority`) |
| 3 | not revoked | PASS -- END TO END |
| 4 | the request not denied or invalidated | PASS -- END TO END |
| 5 | not expired | PASS -- END TO END |
| 6 | a use left | PASS -- END TO END |
| 7 | the requester | PASS -- COMPONENT + STRUCTURAL INVARIANT |
| 8 | agent profile and revision | PASS -- COMPONENT + STRUCTURAL INVARIANT |
| 9 | the run | PASS -- END TO END |
| 10 | the run active | PASS -- END TO END |
| 11 | ownership | PASS -- END TO END (F-18's route tests) |
| 12 | lease tenure | PASS -- END TO END (`lease-takeover-refused`, `another-connection-refused`) |
| 13 | the epoch | PASS -- END TO END |
| 14 | policy revision | PASS -- COMPONENT + STRUCTURAL INVARIANT |
| 15 | the decision still asks an approval | PASS -- END TO END |
| 16 | the resource identity | PASS -- COMPONENT + STRUCTURAL INVARIANT |
| 17 | the action matches | PASS -- END TO END (`argv-drift-each-form`) |
| 18 | the environment | PASS -- COMPONENT + STRUCTURAL INVARIANT |
| 19 | credential revisions | PASS -- FAIL-CLOSED REFUSAL (a credential is A2); NOT APPLICABLE -- CURRENT SCOPE for a revision change |
| 20 | taint | PASS -- END TO END |
| 21 | privacy | PASS -- COMPONENT + STRUCTURAL INVARIANT |
| 22 | obligations enforceable | PASS -- END TO END (`obligations-unkept-refused-kept-bound`; mutant A54, the route's kept flag forced true; E2 stays equivalent) |
| 23 | approver provenance | PASS -- END TO END |
| 24 | approver is not the requester | PASS -- END TO END + STRUCTURAL INVARIANT (trigger) |
| 25 | the assurance floor | PASS -- FAIL-CLOSED REFUSAL (§11) |

No guard is NOT EXERCISED, DEFERRED or FAIL. **TWENTY-FIVE SPEND-TIME
GUARDS: PASS. SCOPE AND BINDING DRIFT: PASS.**

## 13. Security review

A focused review of the registry's recovery, the new seams and the
evidence's own trustworthiness. No production flaw was found, so M6.2.1
changes no guard: its production-file changes are the migration's crash
points (crossed only with a hook, which no production start has) and
test-only, `cfg`-gated modules.

| # | examined | finding |
|---|---|---|
| R1 | a use without its intent, or an intent without its use, after any crash | none: windows A, w, B leave neither; C onwards both (§5) |
| R2 | a spent approval spendable again after a restart | none: the run is fenced, the new run spends nothing and reaches no broker |
| R3 | a workload redispatched after a crash | none: `UNKNOWN` or `COMPLETED`, never started again |
| R4 | an audit record lost or doubled across a crash | none: every outbox window recovers exactly once, checked against the store's head and flushed head |
| R5 | a half-migrated store | none: 14 or 15, the version and the tables together |
| R6 | a crash that revives an expired approval, or a clock moved back after one | none (§7); the floor's stated limit is unchanged |
| R7 | a test seam reachable in a release build | none (§4); the release library keeps the names of removed items, not their code |
| R8 | the crash hook as an authority | it can only stop, and no production start passes one |
| R9 | the evidence judged by what it claims | the supervisor requires its own SIGKILL and the case's window; a child's success alone counts for nothing |
| R10 | an inherited assignment | the supervisor strips `DW_M621_*` before it sets a child's (tested) |
| R11 | a stale or release executable used as the children | the executable is cargo's own report of this build's test artifact, exactly one |

Residuals, unchanged by this review: the crash evidence is process
termination, not power loss; the concurrency evidence is SQLite contention
against a fake broker; the gate is not durable (ADR-0064); a host clock that
leaps forward and back between registry transactions is not seen.

## 14. Mutation campaign

`make approval-registry-mutations` keeps M6.2's 49 mutants (A01-A49) with
their anchors unchanged, and adds five:

| mutant | file | killed by |
|---|---|---|
| A50 the approver set attachable in every build | `state/approvals.rs` | the record stage (`test_the_seams_have_no_production_caller`) |
| A51 the crash children compiled into every build | `lib.rs` | the record stage (`test_the_crash_children_are_compiled_into_linux_unit_test_builds_only`) |
| A52 a migrating start reaches none of its schema point | `state/mod.rs` | the real-process crash stage: `migration-after-schema` never reaches its window |
| A53 a request of another binding schema recorded (schema) | `state/schema.rs` | the registry's tests (`hash-is-not-authority`) |
| A54 the route reports every obligation kept to the registry | `state/workload.rs` | the registry's tests (`obligations-unkept-refused-kept-bound`) |

The detector gained two stages after M6.2's, each run only for a mutant
every earlier stage let through: the **record stage**, four named record
tests that read a compilation condition, an ordering or a case table --
never the mutation table's own test, which every mutant fails by
construction (pinned by
`test_the_record_stage_never_runs_a_test_a_source_edit_alone_fails`); and
the **crash stage**, the whole real-process crash evidence. A stage that
cannot run is BLOCKED, never KILLED.

A first campaign killed 53 of 54. Its survivor, A54 as first written --
`consider`'s kept-obligations check removed -- was M6.2's equivalent mutant
E2 again: the binding refuses on the same flag
(`BindingError::ObligationUnenforceable`), so no test can tell them apart.
It was replaced by the flag's source, the route's
`obligations_kept: plan.obligations_enforced` forced `true`, which records a
request for an unkeepable obligation and is killed; E2 stays recorded as
equivalent.

The campaign of record (2026-11-27, 1,456 s): the unmutated baseline passed
every stage -- 39 registry tests, the four record tests, all 34 crash
cases -- then **54 of 54 killed**: 51 by the registry's tests, A50 and A51
by the record stage, A52 by the crash stage. None survived, timed out, was
blocked or failed to compile. E1-E3 stay recorded as equivalent, with their
reasons. **MUTATION CAMPAIGN: PASS.**

**MUTATION RESTORATION: VERIFIED.** Before the campaign each of the five
mutable files was copied read-only and its digest recorded; after it, each
file's digest matches, and each is byte-identical to its clean copy and to
the delivered source.

## 15. Hosted evidence

The first hosted run of this change carries:

- `make approval-registry-evidence` (the `authority boundary` job): 34
  cases, each once -- M6.2's 27 and M6.2.1's seven -- with each case's
  evidence category printed (`end-to-end` 17, `end-to-end-drift` 6,
  `fail-closed` 5, `in-process-hook` 3, `structural` 2, `component` 1;
  never `real-process`, which only the crash evidence is);
- `make approval-registry-crash-evidence` (the same job, after it): each of
  the 34 cases as one `APPROVAL-CRASH` line with its handshake, its
  termination `SIGKILL (9)` and its category `real-process`, then
  `approval registry crash evidence: 34 cases, each a real process killed at
  its window by this supervisor and recovered by another`; its record
  `target/m6-2-1-evidence/record.json`;
- `make approval-registry-separation` (the `release build` job, after the
  release build): one line per release artifact and
  `approval registry separation: 7 release artifacts, no test-only seam`;
- `make test` on Linux, macOS and Windows, with the record tests of
  `test_m6_2_1_crash_evidence.py` (the stand-in supervisor tests on Linux).

The evidence lines are canonical JSON (`to_canonical_string`), each printed
after its test's assertions. **M6.2.1 HOSTED EVIDENCE: PENDING.**
(2026-11-27: verified on CI #228 -- §20.)

## 16. Validation

Local, 2026-11-27: WSL2 (Linux 6.18.58.1-microsoft-standard-WSL2), rustc
and cargo 1.98.1, Python 3.12.14, in a filesystem copy of the checkout at
`b8414fd` with this change applied. None of it is native Windows or macOS
evidence; hosted `make test` runs those.

| command | result |
|---|---|
| `make fmt-check`, `make lint` (clippy `-D warnings`, ruff), `make typecheck` | exit 0 |
| `make schema-check`, `make docs`, `make arch`, `make adr-history`, `make security` | exit 0 |
| `make eval-check` | exit 0 (789 s) |
| `make test` | exit 0: cargo 1,790 passed, 0 failed, 128 ignored; pytest 2,230 passed, 18 skipped |
| `make approval-registry-evidence` | exit 0: 34 cases, each once, by category |
| `make approval-registry-crash-evidence` | exit 0: 34 of 34 in each of seven complete runs (§7) |
| `make approval-registry-mutations` | 54 of 54 killed; every file restored (§14) |
| `cargo build --workspace --release`, then `make approval-registry-separation` | exit 0: 7 release artifacts, none of 12 traces |
| `dwcheck adr --record` | `accepted.sha256` unchanged |

The first gate pass found one clippy `doc_markdown` lint in a new test's
doc comment and two mypy annotations in the new record test file; both were
fixed, and `fmt-check`, `lint`, `typecheck`, `arch`, `docs`, the
registry's evidence and 211 record and boundary tests passed again after.
The ignored and skipped tests are the repository's own -- evidence-only
tests run by their tasks (the two crash children among them), and platform
guards. `Cargo.lock`, dependency pins, deny rules and the authority's
allowlists are unchanged; TX006, TX010, TX061, TX062 and TX065 to TX068
pass unchanged.

## 17. ADR-0080 and ADR-0064: the decision package

Neither is accepted here. M6.2.1 changes neither record's decisions; it
supplies evidence each one's acceptance asked for.

**ADR-0080** (Proposed). Its residual "real process termination is not
exercised for the registry" is now answered by §5 -- the record's residual
is updated to say so, with the process-kill limit kept. Its OD-1 to OD-6
recommendations stand as M6.2's report §20 gives them. Acceptance needs this
change's commits on `main` with a green hosted run carrying §15, then a
status line, its digest (`dwcheck adr --record`), the index row, the README
count and the plan's state, in one change.

**ADR-0064** (Proposed). M6.2's report §20 is its package. M6.2.1 adds:
the revocation's crash windows with real process termination (§5, B, C, D);
the lease takeover against an open approval, end to end
(`lease-takeover-refused`); and a restart's fencing of every run in a fresh
process, 34 times. The recommendation is unchanged: accept as written once
M6.2's and M6.2.1's commits have a green hosted run. (2026-11-27: both
accepted as written, each its own change -- §20.)

## 18. Not changed

`Cargo.lock`, dependency pins and deny rules; store schema 15; DWKP and the
private protocol; the approver endpoint (TX065); TX006, TX010, TX061, TX062,
TX065, TX066, TX067 and TX068; every accepted ADR; ADR-0078 as accepted
(`Environment::Host` of any verb is A2). No production approval-minting
seam, Cargo feature, environment switch or command was added. M5e.2's
status, F-05's limitation and the casefold classification are unchanged.

## 19. Status

```
M6.2 BASELINE HOSTED EVIDENCE: VERIFIED
REAL-PROCESS TEST HARNESS: PASS
PRODUCTION TEST-SEAM SEPARATION: PASS
CRASH RECOVERY: PASS
REAL-PROCESS CRASH EVIDENCE: PASS (local; hosted pending)
SCOPE AND BINDING DRIFT: PASS
POSITIVE BROAD-SCOPE SUPPORT: NOT ENABLED
ADR-0064: PROPOSED
ADR-0080: PROPOSED
M6.2.1 HOSTED EVIDENCE: PENDING
M6.2 FORMAL CLOSEOUT: PENDING
READY FOR M6.3: NO
```

(As delivered for commit; §20 records the hosted verification and the
closeout.)

## 20. Hosted verification and closeout (2026-11-27)

M6.2.1 was committed as `f81b898`. Its hosted run, CI #228 ([run
45985130343](https://github.com/Onwcan/DireWolf/actions/runs/45985130343)),
attempt 1, passed 33 of 33 jobs, and the Push workflow (CodeQL, [run
45985130381](https://github.com/Onwcan/DireWolf/actions/runs/45985130381)) 4 of
4, both at `f81b898`. Its job logs, read line by line against this report's
tables:

| | hosted result |
|---|---|
| `make approval-registry-evidence` (`authority boundary`) | 34 `APPROVAL-EVIDENCE` lines, 34 distinct cases, each required case once -- M6.2's 27 and the seven of §15; the categories printed as §15 says (end-to-end 17, end-to-end-drift 6, fail-closed 5, in-process-hook 3, structural 2, component 1) |
| `make approval-registry-crash-evidence` (the same job) | 34 `APPROVAL-CRASH` records, 34 distinct cases; every one `SIGKILL (9)`, its handshake naming its case and window, `audit` verified, `category` real-process; every non-migration case fenced `refused`, every migration case `migrated`; every field equal to the case's expectation (§5) |
| consumption | before the transaction (A), after the intent before the use (w), the use before commit (B): 0 uses and 0 intents; after commit (C) and every later audit and dispatch window (D-G, q, t, r, s): 1 use and its 1 intent |
| migration | before the transaction, after the schema, before the commit: version 14; after the commit: 15; nothing between |
| requests, decisions, revocation, expiry | as §5's table, each case's counts exactly |
| `make approval-registry-separation` (`release build`) | each of the 7 release artifacts "none of 12 test-only traces"; `approval registry separation: 7 release artifacts, no test-only seam` |
| `make test` | Linux: cargo 1,790 passed, 0 failed, 128 ignored; pytest 2,228 passed, 20 skipped (the stand-in supervisor tests among them). Windows: cargo 1,039 / 0 / 8; pytest 2,166 passed, 82 skipped. macOS: cargo 1,079 / 0 / 8; pytest 2,182 passed, 66 skipped |

The local totals of §16 are WSL2's and stay local; the mutation campaigns
(§14) are local, not hosted. The real-process supervisor runs on Linux: no
native Windows or macOS SIGKILL crash evidence is claimed. The separation
scan is one check among the source pins, compilation conditions,
architecture rules and negative tests of §4, not by itself proof that no
bypass can exist.

**A precision note on §8** (2026-11-27). Its closing sentence says a run's
workspace root "cannot change" while its approval is open. What holds is
narrower: the binding's `workspace` member is the run's recorded root
identity, which no operation changes; the directory at that path can still
be replaced in the world, and a later pin or environment preparation then
refuses it (`RootError::Replaced`; `HOST_WORKSPACE_IDENTITY` fails at the
broker), while an environment already prepared keeps the directory it was
given. The member's classification -- COMPONENT + STRUCTURAL INVARIANT --
is unchanged, and the real-OCI workspace guarantees are `sandbox
workspace`'s.

**Closeout.** On this evidence ADR-0080 (OD-1 to OD-6) and ADR-0064 were
accepted on 2026-11-27, as written, each its own change
([M6_2_IMPLEMENTATION.md](M6_2_IMPLEMENTATION.md) §22).

```
M6.2.1 HOSTED EVIDENCE: VERIFIED (CI #228)
CRASH RECOVERY: PASS
REAL-PROCESS CRASH EVIDENCE: PASS (local; hosted on Linux, CI #228)
SCOPE AND BINDING DRIFT: PASS -- M6.2 SUPPORTED SCOPE
POSITIVE BROAD-SCOPE SUPPORT: NOT ENABLED
ADR-0064: ACCEPTED 2026-11-27
ADR-0080: ACCEPTED 2026-11-27 (OD-1 to OD-6)
M6.3: NOT STARTED
```
