# C3: hosted evidence for Phase 1's remediations

Phase 1 changed four security boundaries:

- **F-19**: a constrained `network.https` grant is never a `PROXY_ONLY`
  destination ([ADR-0060](adr/0060-a-constrained-network-grant-gives-no-proxy-only-destination.md)).
- **F-17**: each workload's egress is decided by policy, the run's novelty and its
  workspace's exposure ([ADR-0061](adr/0061-workload-egress-decided-by-policy-novelty-and-exposure.md)).
- **F-01**: taint follows delivered content ([ADR-0062](adr/0062-taint-follows-delivered-content.md)).
- **F-18**: sessions, workspaces and profiles belong to principals
  ([ADR-0063](adr/0063-principal-ownership-of-sessions-workspaces-and-profiles.md)).

All four ADRs are **Proposed**. This document records, property by property,
what hosted CI has shown about their guarantees, run by run. The
machine-readable form is [c3-evidence-matrix.json](c3-evidence-matrix.json),
which `tests/architecture/test_c3_evidence.py` checks against the real producer
of each row.

Status as of 2026-11-15: every row of the matrix is VERIFIED from a hosted run.

## 1. Where each finding stands

Five milestones are kept apart. A green CI run is not an exercised property, an
exercised property is not a killed mutant, and none of them is an accepted ADR.

| Finding | Implemented | Ordinary hosted CI | Property exercised (hosted) | Mutation control (hosted) | ADR |
|---|---|---|---|---|---|
| F-19 | `9837ddc` | #161 onward | VERIFIED: both real-OCI cases; the derivation's tests by name | VERIFIED: 12 of 12 killed | Proposed |
| F-17 | `2f5721b`, `d58d622` | #163 onward | VERIFIED: every real-OCI case; the unit tests by name; the M5e.5 manual workflow on its code | VERIFIED: 26 of 26 killed | Proposed |
| F-01 | `c2353e8` | #164 onward | VERIFIED: every real-OCI case; the unit tests by name | VERIFIED: 20 of 20 killed | Proposed |
| F-18 | `d8eb736`, `e62c597` | #166 onward | VERIFIED: `i09` on three identities; the cross-uid cases with both uids; the descriptor test and the unit tests by name; TX061–TX064 | VERIFIED: 27 of 27 killed | Proposed |

**IMPLEMENTATION COMPLETE.** All four remediations and C3's mechanism are
committed: C3's mechanism is `6aa9245`, its archive fix `8a64a9f`.

**HOSTED EVIDENCE VERIFIED.** All 50 rows, from the runs in §2.

**HOSTED EVIDENCE PENDING.** No row. What the matrix does not claim is in §8.

**ADR ACCEPTANCE PENDING.** ADR-0060 to ADR-0062 stay Proposed. Hosted evidence
is a necessary input to their acceptance, not the acceptance itself: that is
the owner's separate decision, recorded in the ADRs. ADR-0063 (F-18) was
accepted on 2026-11-24, on this evidence and every hosted run since (CI #216
among them), as its status line records.

## 2. The runs, and how each was read

| Run | Commit | What it gives | How it was read |
|---|---|---|---|
| CI #172, 43640168802 | `4aee637` | each real-OCI case's own line; the three-identity agent cases; the foreign-uid eval verdict | the fourteen M5 bundles, archived at GitHub's digests and verified offline; the run's own M5 gate replayed over them: 675 of 675 cases |
| CI #173, 43648487347 | `299686c` | ADR-0060's job contract | GitHub's jobs API: 33 of 33 jobs green |
| C3 hosted evidence (manual) #1, 43658092468 | `6aa9245` | the four mutation reviews; the cross-uid record; the unit tests by name | its gate: `C3 gate: COMPLETE: 12 record(s)`; the shards' logs, each baseline read before its first mutant |
| M5e.5 evidence (manual) #5, 43658104419 | `6aa9245` | hygiene and the profile mutation review on F-17's code | the two jobs' logs |
| CI #176, 43656395503 | `6aa9245` | TX061–TX064 firing on their violations | the boundaries job's log (the run failed only in D11 hardening, on a runner with no swap device) |

**Same source.** None of these commits differ in exercised source.
`git diff 4aee637 6aa9245` changes no file under `crates/`, `policy/`,
`schemas/`, `fuzz/`, `evals/`, `runtime/` or `tools/`.

**What counts as VERIFIED.** One of:

- a case's own line, judged in its run;
- an eval's result over named cases;
- a replayed gate;
- a test passed by name in an unmutated baseline that the C3 gate accepted;
- a mutation review's record that the C3 gate accepted;
- a job contract an ADR states in those words.

A green job alone never counts. An archived run is historical: it shows what
the property did on that commit, and never stands in for a current run's gate.

## 3. The matrix

The table names each row's evidence. For each row, the JSON also gives:

- the positive and negative controls;
- the provenance;
- the artifact and its digest;
- the mutants that guard it;
- anything left open.

| Row | Invariant | Evidence | Level | Run | Observed | Status |
|---|---|---|---|---|---|---|
| `F-19-1` | ADR-0060 decision; EG-1 | `sandbox-authority-egress/grant-constrained-https-not-destinations` | real-oci | 43640168802 (#172, `4aee637`) | granted-and-absent [enforcement authority-grant-derivation] | **VERIFIED** |
| `F-19-2` | ADR-0060 decision; EG-1 | `sandbox-authority-egress/constrained-grant-name-not-granted` | real-oci | 43640168802 (#172, `4aee637`) | target-not-granted [enforcement connect-proxy:grant] | **VERIFIED** |
| `F-19-3` | ADR-0060 decision | 5 test(s) in `crates/dwkd-authority/src/sandbox.rs` | in-process | 43658092468 (#1, `6aa9245`) | each named test passed in the unmutated baseline of both agent-mutations shards, before any mutant | **VERIFIED** |
| `F-19-4` | ADR-0060 Evidence: acceptance contract | 6 CI jobs | hosted-job | 43648487347 (#173, `299686c`) | all six jobs: success (33 of 33 jobs of the run) | **VERIFIED** |
| `F-19-5` | mutation review | campaign `agent-mutations` | hosted-mutation | 43658092468 (#1, `6aa9245`) | 12 of 12 killed in 2 shards; the F-19 mutant (a constrained network.https grant becomes a proxy destination) by the authority-guards selection's na... | **VERIFIED** |
| `F-17-1` | EG-4 | `sandbox-egress/authorisation-none-outside-a-workload` | real-oci | 43640168802 (#172, `4aee637`) | 403-NOT_AUTHORISED-before-resolution [enforcement connect-proxy:workload-authorisation] | **VERIFIED** |
| `F-17-2` | EG-2 | `sandbox-egress/authorisation-allowed-and-denied-same-workload` | real-oci | 43640168802 (#172, `4aee637`) | 200-reached+403-POLICY_DENIED-before-resolution [enforcement connect-proxy:workload-authorisation] | **VERIFIED** |
| `F-17-3` | EG-6 | `sandbox-egress/authorisation-address-range-denied` | real-oci | 43640168802 (#172, `4aee637`) | status='HTTP/1.1 403 Forbidden' decision=POLICY_ADDRESS_DENIED sent=0 received=0 [enforcement connect-proxy:workload-authorisation-address] | **VERIFIED** |
| `F-17-4` | EG-6 | `sandbox-authority-egress/power-internal-ranges-refused-at-the-address` | real-oci | 43640168802 (#172, `4aee637`) | status="HTTP/1.1 403 Forbidden" decision=POLICY_ADDRESS_DENIED sent=0 received=0 [enforcement connect-proxy:workload-authorisation-address] | **VERIFIED** |
| `F-17-5` | EG-4 | `sandbox-egress/authorisation-ends-with-the-workload` | real-oci | 43640168802 (#172, `4aee637`) | WORKLOAD_ENDED=1;bytes-back-0;not-reached [enforcement connect-proxy:workload-lifetime] | **VERIFIED** |
| `F-17-6` | EG-4 | `sandbox-egress/authorisation-none-after-the-workload` | real-oci | 43640168802 (#172, `4aee637`) | status='HTTP/1.1 403 Forbidden' decision=NOT_AUTHORISED sent=0 received=0 [enforcement connect-proxy:workload-authorisation] | **VERIFIED** |
| `F-17-7` | EG-9 | `sandbox-egress/authorisation-tunnel-output-bounded` | real-oci | 43640168802 (#172, `4aee637`) | status='HTTP/1.1 200 Connection Established' decision=- sent=87 received=100 end=eof [enforcement connect-proxy:tunnel-output-bound] | **VERIFIED** |
| `F-17-8` | EG-12 | `sandbox-egress/authorisation-report-per-destination` | real-oci | 43640168802 (#172, `4aee637`) | reached-1+0+0+1;POLICY_DENIED;POLICY_ADDRESS_DENIED;TUNNEL_OUTPUT_LIMIT [enforcement workload-supervisor-report] | **VERIFIED** |
| `F-17-9` | EG-8 | `sandbox-egress/exposure-revokes-an-open-tunnel` | real-oci | 43640168802 (#172, `4aee637`) | status='HTTP/1.1 200 Connection Established' decision=- sent=87 received=0 end=eof [enforcement connect-proxy:workspace-exposure] | **VERIFIED** |
| `F-17-10` | EG-8 | `sandbox-egress/exposure-novel-refused-after-first-origin-byte` | real-oci | 43640168802 (#172, `4aee637`) | status='HTTP/1.1 403 Forbidden' decision=POLICY_DENIED sent=0 received=0 [enforcement connect-proxy:workspace-exposure] | **VERIFIED** |
| `F-17-11` | EG-8 | `sandbox-egress/exposure-sibling-on-the-shared-root` | real-oci | 43640168802 (#172, `4aee637`) | status='HTTP/1.1 403 Forbidden' decision=POLICY_DENIED sent=0 received=0 [enforcement connect-proxy:workspace-exposure] | **VERIFIED** |
| `F-17-12` | EG-8 | `sandbox-egress/exposure-other-root-untouched` | real-oci | 43640168802 (#172, `4aee637`) | status='HTTP/1.1 200 Connection Established' decision=- sent=87 received=5 end=eof [enforcement connect-proxy:workspace-exposure] | **VERIFIED** |
| `F-17-13` | EG-8 | `sandbox-authority-egress/exposure-durable-before-the-next-launch` | real-oci | 43640168802 (#172, `4aee637`) | exposure-row+certain-reach+exposed-at-start [enforcement authority-ledger] | **VERIFIED** |
| `F-17-14` | EG-8 | `sandbox-authority-egress/exposure-from-a-sibling-run-on-the-shared-root` | real-oci | 43640168802 (#172, `4aee637`) | status="HTTP/1.1 403 Forbidden" decision=POLICY_DENIED sent=0 received=0 [enforcement authority-egress-decision] | **VERIFIED** |
| `F-17-15` | EG-2; EG-10; EG-13 | `sandbox-authority-egress/policy-denied-before-resolution` | real-oci | 43640168802 (#172, `4aee637`) | 403-POLICY_DENIED-no-resolution-no-origin [enforcement connect-proxy:workload-authorisation] | **VERIFIED** |
| `F-17-16` | EG-3; EG-12 | `sandbox-authority-egress/decision-recorded-with-the-intent` | real-oci | 43640168802 (#172, `4aee637`) | 4-destinations-4-cells-digests [enforcement authority-audit] | **VERIFIED** |
| `F-17-17` | EG-2 | `sandbox-authority-egress/approval-needed-refused-unattended` | real-oci | 43640168802 (#172, `4aee637`) | review.example.com:34559 NOVEL np=0/2[deny-approval-needed-when-unattended] ne=0/2[deny-approval-needed-when-unattended] sp=0/2[deny-approval-neede... | **VERIFIED** |
| `F-17-18` | EG-7 | `sandbox-authority-egress/tainted-novel-refused-seen-reached` | real-oci | 43640168802 (#172, `4aee637`) | seen-200+novel-POLICY_DENIED [enforcement authority-egress-decision] | **VERIFIED** |
| `F-17-19` | EG-4; EG-11 | 4 test(s) in `crates/dwkd-broker/src/egress/tests.rs` | in-process | 43658092468 (#1, `6aa9245`) | each named test passed in the unmutated baseline of all four egress-policy shards, before any mutant | **VERIFIED** |
| `F-17-20` | EG-5; EG-7; EG-8 | 9 test(s) in `crates/dwkd-authority/src/state/workload_route_tests.rs` | in-process | 43658092468 (#1, `6aa9245`) | each named test passed in the unmutated baseline of all four egress-policy shards, before any mutant | **VERIFIED** |
| `F-17-21` | EG-3; EG-8 | `sandbox-authority-egress/restart-never-restores-a-pristine-root` | real-oci | 43640168802 (#172, `4aee637`) | exposed-at-start-after-restart [enforcement authority-reconciliation] | **VERIFIED** |
| `F-17-22` | EG-7; EG-8; EG-10 | `sandbox-authority-egress/restart-settles-an-interrupted-workload-uncertain` | real-oci | 43640168802 (#172, `4aee637`) | UNCERTAIN+exposed+uncertain-reach [enforcement authority-reconciliation] | **VERIFIED** |
| `F-17-23` | EG-2 (registry production path) | `sandbox-registry/registry-pip-granted-index-denied-by-policy` | dwkp-end-to-end | 43640168802 (#172, `4aee637`) | refused:nothing-installed;connect-403;POLICY_DENIED=1 [enforcement connect-proxy:workload-authorisation] | **VERIFIED** |
| `F-17-24` | EG-14 Only narrows; EG-13 fixed rules first | pinned `tests/architecture/m5e_cases_before_f17.txt` | hosted-gate | 43640168802 (#172, `4aee637`) | the archived bundles replayed through the M5 gate: inventory COMPLETE, 675 of 675 attributed cases judged again | **VERIFIED** |
| `F-17-25` | multi-identity production path | 26 `sandbox-agent-identity` cases | hosted-three-identity | 43640168802 (#172, `4aee637`) | 26 cases at hosted-three-identity; i01: authority=1001 broker=999 runtime=997 outsider=65534 | **VERIFIED** |
| `F-17-26` | ADR-0061 Evidence: hosted only (M5e.5) | `.github/workflows/m5e5-evidence.yml` | hosted-mutation | 43658104419 (#5, `6aa9245`) | success on 6aa9245, F-17's code: sandbox-hygiene-evidence 44 cases at dwkp-end-to-end with a clean census; the profile mutation review 36 of 36 kil... | **VERIFIED** |
| `F-17-27` | mutation review | campaign `egress-policy-mutations` | hosted-mutation | 43658092468 (#1, `6aa9245`) | 26 of 26 killed in 4 shards; each by a named failing test: 17 in the authority's partition and workload suites, 9 in the broker's egress suite; non... | **VERIFIED** |
| `F-01-1` | T-11 | `sandbox-authority-egress/taint-permission-refusal-failed-dial-not-external` | real-oci | 43640168802 (#172, `4aee637`) | none+POLICY_DENIED+dial-failed:local-only [enforcement authority-taint] | **VERIFIED** |
| `F-01-2` | T-6 | `sandbox-authority-egress/taint-download-no-output-external` | real-oci | 43640168802 (#172, `4aee637`) | stdout-0+external:workload_reached:ORIGIN_BYTES [enforcement authority-taint] | **VERIFIED** |
| `F-01-3` | T-7 | `sandbox-authority-egress/taint-partial-transfer-external` | real-oci | 43640168802 (#172, `4aee637`) | 3-of-5-bytes+external [enforcement authority-taint] | **VERIFIED** |
| `F-01-4` | T-4; T-5 | `sandbox-authority-egress/taint-downloaded-file-read-by-another-run` | real-oci | 43640168802 (#172, `4aee637`) | external:root_exposed:ORIGIN_BYTES [enforcement authority-taint] | **VERIFIED** |
| `F-01-5` | T-3 (R3) | `sandbox-authority-egress/taint-tainted-writer-marks-root` | real-oci | 43640168802 (#172, `4aee637`) | workspace_taint+external-read [enforcement authority-taint] | **VERIFIED** |
| `F-01-6` | T-9 (with ADR-0061) | `sandbox-authority-egress/taint-fresh-run-decided-by-the-exposed-cell` | real-oci | 43640168802 (#172, `4aee637`) | second.example.com:34559 NOVEL np=2/2[https-to-the-evidence-origins] ne=0/2[deny-approval-needed-when-unattended] sp=2/2[https-to-the-evidence-orig... | **VERIFIED** |
| `F-01-7` | T-3; T-7 | `sandbox-authority-egress/taint-interrupted-workload-on-restart` | real-oci | 43640168802 (#172, `4aee637`) | reaped-run-uncertain+next-run-uncertain [enforcement authority-taint] | **VERIFIED** |
| `F-01-8` | T-1; T-2; T-8; T-10; T-12 | 15 test(s) in `crates/dwkd-authority/src/state/taint_route_tests.rs` | in-process | 43658092468 (#1, `6aa9245`) | each named test passed in the unmutated baseline of all three taint shards, before any mutant | **VERIFIED** |
| `F-01-9` | Every earlier evidence case kept | pinned `tests/architecture/m5e_cases_before_f01.txt` | hosted-gate | 43640168802 (#172, `4aee637`) | replayed M5 gate: 675 of 675 attributed cases; tainted-novel-refused-seen-reached observed as seen-200+novel-POLICY_DENIED | **VERIFIED** |
| `F-01-10` | mutation review | campaign `taint-mutations` | hosted-mutation | 43658092468 (#1, `6aa9245`) | 20 of 20 killed in 3 shards; each by a named failing test of the authority's unit suite; none needed sandbox-egress-evidence | **VERIFIED** |
| `F-18-1` | §1 the principal is the kernel's uid; §3; §4 | `i09-runtime-holds-only-what-the-operator-declared`, `i01-three-distinct-host-identities` | hosted-three-identity | 43640168802 (#172, `4aee637`) | LEASE_HELD,UNKNOWN_AGENT_PROFILE [authority-ownership]; uids authority=1001 broker=999 runtime=997 outsider=65534 | **VERIFIED** |
| `F-18-2` | §3 a foreign uid takes over nothing; §4 | eval `authority-security/peer-credential-check` (7 cases) | real-process-second-identity | 43640168802 (#172, `4aee637`) | pass, score 1.0: 7 of 7 expected cases contained, layers peer-gate=3 state-fence=3 filesystem=1, against the real dwkd-authority binary; the cases'... | **VERIFIED** |
| `F-18-3` | §3; §5; §6; §7 | 18 test(s) in `crates/dwkd-authority/tests/state_ownership.rs` | in-process | 43658092468 (#1, `6aa9245`) | each named test passed in the unmutated baseline of both ownership shards, before any mutant | **VERIFIED** |
| `F-18-4` | §5 two-phase revocation; settlement | 5 test(s) in `crates/dwkd-authority/src/state/ownership_route_tests.rs` | in-process | 43658092468 (#1, `6aa9245`) | each named test passed in the unmutated baseline of both ownership shards, before any mutant | **VERIFIED** |
| `F-18-5` | §1 (TX061): runtime-provided descriptors never become authority | 1 test(s) in `crates/dwkd-authority/tests/transport_hostile.rs` | real-process | 43658092468 (#1, `6aa9245`) | transport_hostile: 11 of 11 passed, this test among them by name | **VERIFIED** |
| `F-18-6` | boundary rules TX061-TX064 | TX061, TX062, TX063, TX064 | static | 43656395503 (#176, `6aa9245`) | the boundaries job succeeded (CI #176 failed only in D11 hardening): dwcheck ok on the tree, and on the deliberately invalid fixture tree each of T... | **VERIFIED** |
| `F-18-7` | mutation review | campaign `ownership-mutations` | hosted-mutation | 43658092468 (#1, `6aa9245`) | 27 of 27 killed in 2 shards; each by a named failing test: 22 by the ownership suites, 5 by the authority's unit suite | **VERIFIED** |
| `F-18-8` | §3 a foreign uid takes over nothing (case lines and uids kept) | campaign `cross-uid-ownership` | real-process-second-identity | 43658092468 (#1, `6aa9245`) | the second identity proven by number (this job uid 1001, DW_PEER_AS=nobody uid 65534); the cross-uid suite 3 of 3 tests, 7 of 7 cases contained, it... | **VERIFIED** |

## 4. By finding

### F-19 (ADR-0060)

**The real-OCI cases** were observed in CI #172:

- `grant-constrained-https-not-destinations`: three constrained grants, all
  granted, are absent from the destinations.
- `constrained-grant-name-not-granted`: a CONNECT to the constrained-only name
  is refused `TARGET_NOT_GRANTED`.

**The derivation's five tests** passed by name in both agent shards' baselines.
They cover `methods`, `max_requests`, both together, alternative ports,
mixtures, duplicates, and the destination bound.

**ADR-0060's acceptance contract** is now met as written:

- the `sandbox-egress`, three-platform tests, `boundaries` and `m5e-gate`
  jobs are green on the committed revision (CI #173);
- the mutation review's hosted result is recorded: 12 of 12 killed. The F-19
  mutant was killed by the authority's guard tests.

### F-17 (ADR-0061)

**EG-1 to EG-14 each have a VERIFIED row:**

- all 21 cases F-17 added, observed in CI #172;
- the broker's egress tests and the authority's `f17_` route tests by name.
  These cover EG-5's drift tripwire and EG-11's typed facts;
- the M5e.5 manual workflow on F-17's code: hygiene 44 cases; the profile
  mutation review 36 of 36 killed, 1 equivalent;
- 26 of 26 mutants killed, each by a named failing test.

**Earlier evidence is kept.** The 647 cases pinned before F-17 are judged again
by the replayed gate.

**One gap stays open:** no real-OCI case puts two concurrent workloads against
each other's authorisation. The broker's unit test covers it (`F-17-6`,
`F-17-19`).

### F-01 (ADR-0062)

**T-1 to T-12 each have a VERIFIED row:**

- the seven real-OCI cases F-01 added;
- the fifteen `f01_` route tests by name. These cover monotonicity, ordering,
  evidence rows and replay;
- 20 of 20 mutants killed, each by a named failing test of the authority's
  unit suite.

**Earlier evidence is kept and replayed:** the 668 cases pinned before F-01.

### F-18 (ADR-0063)

**Verified:**

- **`i09` on three real host identities.** Observed beside `i01`'s measured
  uids: authority 1001, broker 999, runtime 997, outsider 65534.
- **The cross-uid cases**, kept with both uids: this job ran as uid 1001, and
  `nobody` as 65534. All 3 tests passed and all 7 cases were contained.
- **The runtime-passed-descriptor test, by name**, in `transport_hostile`
  (11 of 11 passed).
- **The `state_ownership` and route suites, by name.**
- **TX061–TX064**, each firing on its planted violation in hosted CI. These
  are static hygiene, not containment.
- **The mutation review:** 27 of 27 killed, each by a named failing test.

## 5. The mutation reviews

| Campaign | Finding | Mutants | Hosted result (run 43658092468) | Killed by |
|---|---|---|---|---|
| `agent-mutations` | F-19 (and M5d.5) | 12 | 12 of 12 killed, 2 shards | named failing tests 10 (the authority's guards 5, the broker's unit tests 4, its private channel 1); the one-identity agent evidence's refusal 2 |
| `egress-policy-mutations` | F-17 | 26 | 26 of 26 killed, 4 shards | named failing tests: the authority's partition and workload 17, the broker's egress 9 |
| `taint-mutations` | F-01 | 20 | 20 of 20 killed, 3 shards | named failing tests of the authority's unit suite |
| `ownership-mutations` | F-18 | 27 | 27 of 27 killed, 2 shards | named failing tests: the ownership suites 22, the authority's unit suite 5 |

`mutation_review` in `scripts/dw.py` runs all four. Before any mutant is judged,
an unmutated baseline must pass, and each test selection must run at least one
test. Then:

- **A mutant is KILLED only** by a test that failed by name, or by an evidence
  task's refusal.
- **None of these counts as a kill:**
  - COMPILE_ERROR;
  - ERROR: a command failed with no failing test;
  - NO_TESTS: a selection ran nothing;
  - TIMEOUT;
  - BLOCKED: the evidence task said NOT EXERCISED.
- **Every file** is restored and checked.
- **A record** is kept even when the review fails. The C3 gate judges every
  record again.

**Baselines.** In the hosted run they ran 542 tests for the agent review, 157
for the egress-policy review, 480 for the taint review and 551 for the
ownership review.

## 6. The hand-dispatched workflow

`.github/workflows/c3-evidence.yml` (**C3 hosted evidence (manual)**) runs only
when dispatched.

- **Rights:** a read-only token, no secrets, the same SHA-pinned actions as
  `ci.yml`.
- **Jobs:**
  - 11 mutation shards;
  - the cross-uid job;
  - `c3-gate`, which judges this run's records only. Records of any other run,
    archived ones included, fail it.
- **First dispatch:** run 43658092468. All 13 jobs succeeded within 19 minutes,
  every shard well inside its 300-minute limit.
- **It is not a required check.** `ci.yml`, its `CI` aggregate and its M5 gate
  are unchanged.

Dispatch it again after any change to the code these reviews guard: the
remediations, the mutation tables, or their detectors.

## 7. Keeping C3's evidence

The F-10 archive (`docs/EVIDENCE_ARCHIVE.md`) covers `ci.yml` and `fuzz.yml` runs
only. Its contracts are frozen, and C3 does not change them. For a C3 run:

1. Download its twelve `c3-evidence-*` ZIPs and its log archive within 7 days.
   For run 43658092468, that is by 2026-11-22.
2. Put them in `<archive root>/c3/<run id>/`, outside the repository.
3. Compare each ZIP's SHA-256 with the `digest` GitHub's API lists for it
   (`GET /repos/Onwcan/DireWolf/actions/runs/<run id>/artifacts`).
4. Record the run id, the commit, and the gate job's result beside them.

Never copy a C3 record where a run's gate reads it. The C3 gate refuses every
record of another run, and so does the M5 gate.

## 8. Residual risks

- **Two kills named no test.** Two of the agent review's kills came from the
  evidence task's refusal. A kill like that does not say which test caught the
  mutant, and an infrastructure failure during that run would look the same.
  The same runner's passing baseline narrows that, but does not remove it.
- **A flaky test can kill a mutant falsely.** A passing baseline shows the
  detectors pass unmutated once, not that they never flake.
- **Each review weakens only the guards it lists.** Mutation testing shows those
  guards are watched, not that no other guard is missing.
- **Two concurrent workloads against each other's authorisation** have no
  real-OCI case, only the broker's unit test.
- **Some hosted runners have no swap device.** Since 2026-11-15, the D11 job
  then adds a temporary swap file for its swap cases (`docs/BROKER_HARDENING.md`).
  That path runs only when the job lands on such a runner.
- **Records and archives are hashed, not signed** (see `EVIDENCE_ARCHIVE.md`).
- **A C3 archive class** for `scripts/evidence_archive.py` (a frozen contract of
  campaigns and shards, judged by the same gate) is a bounded follow-up. It is
  not built.
