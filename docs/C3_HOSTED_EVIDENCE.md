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
which of their guarantees hosted CI has actually shown, and which it has not.
It also describes the hand-dispatched workflow that produces the missing
evidence. The machine-readable form is
[c3-evidence-matrix.json](c3-evidence-matrix.json), which
`tests/architecture/test_c3_evidence.py` checks against the real producers of
each row.

Status as of 2026-11-15, with the baseline at commit `299686c` (CI #173, run
43648487347, 33 of 33 jobs green).

## 1. Where each finding stands

Five milestones are kept apart. A green CI run is not an exercised property, an
exercised property is not a killed mutant, and none of them is an accepted ADR.

| Finding | Implemented | Ordinary hosted CI | Property exercised (hosted) | Mutation control (hosted) | ADR |
|---|---|---|---|---|---|
| F-19 | `9837ddc` | #161 onward, latest #173 | VERIFIED: both real-OCI cases | NOT VERIFIED: local only | Proposed |
| F-17 | `2f5721b`, `d58d622` | #163 onward, latest #173 | VERIFIED: every real-OCI case. NOT VERIFIED: the M5e.5 manual workflow on F-17's code, and unit tests by name | NOT VERIFIED: local only | Proposed |
| F-01 | `c2353e8` | #164 onward, latest #173 | VERIFIED: every real-OCI case. NOT VERIFIED: unit tests by name | NOT VERIFIED: local only | Proposed |
| F-18 | `d8eb736`, `e62c597` | #166 onward, latest #173 | VERIFIED: `i09` on three identities; the foreign-uid cases by the eval's verdict. NOT VERIFIED: unit tests by name | NOT VERIFIED: local only | Proposed |

**IMPLEMENTATION COMPLETE.** All four remediations are committed. So is C3's own
mechanism: the hardened mutation harness, the C3 records and gate, and
`.github/workflows/c3-evidence.yml`.

**HOSTED EVIDENCE VERIFIED.** 36 of the matrix's 50 rows. Each is the case's own
line in a hosted bundle, an eval's verdict over named cases, the replayed M5
gate, or a job contract an ADR states in those words.

**HOSTED EVIDENCE PENDING.** The other 14 rows:

- **The four mutation reviews.** None has ever run on a hosted runner.
- **The cross-uid case lines and their uids.** Not kept today.
- **Unit-level properties, test by test.** The jobs that ran them are green,
  but no per-test result is kept.
- **The M5e.5 manual workflow on F-17's code.** Its last run, 42994561934, was
  on `523dc9a`, before F-19 and F-17.
- **The boundary rules TX061–TX064.** Static checks: the boundaries job is
  green, but no per-rule output is kept, and C3's workflow does not add one.

C3's workflow closes every pending row except the last two: M5e.5 needs its
own workflow dispatched, and the boundary rules stay checked only by the
`boundaries` job.

**ADR ACCEPTANCE PENDING.** ADR-0060 to ADR-0063 stay Proposed. Hosted evidence
is a necessary input to their acceptance, not the acceptance itself: that is
the owner's separate decision, recorded in the ADRs.

## 2. How the evidence was read

- **CI #172** (run 43640168802, commit `4aee637`): the per-case evidence comes
  from this run's fourteen M5 bundles.
  - The bundles were archived with `scripts/evidence_archive.py`. Every ZIP is
    at the SHA-256 digest GitHub's artifact API reports.
  - The archive verifies offline.
  - Replaying the run's own M5 gate over it judges **675 of 675** attributed
    cases again.
  - Each row cites the bundle and its digest.
- **The same source as the baseline.** `git diff 4aee637 299686c` changes only
  `CONTRIBUTING.md`, `docs/EVIDENCE_ARCHIVE.md`, `scripts/evidence_archive.py`
  and that script's test. No exercised source changed.
- **CI #173** (run 43648487347, `299686c`): the job conclusions were read from
  GitHub's jobs API. All 33 succeeded, every one on a GitHub-hosted runner.
- **What counts as VERIFIED.** A case's own line, judged in the run; an eval's
  result over named cases; the replayed gate; or a job contract an ADR states
  as such. A green job alone never counts. An archived run is historical: it
  shows what the property did on that commit, and it never stands in for a
  current run's gate.
- **Statuses.** VERIFIED, FAILED, NOT EXERCISED, NOT VERIFIED and BLOCKED, with
  the matrix's meanings. Today no row is FAILED, NOT EXERCISED or BLOCKED.

## 3. The matrix

The table names each row's evidence. For each row, the JSON also gives:

- the positive and negative controls;
- the provenance;
- the artifact and its digest;
- the mutants that guard it;
- the remaining gap.

| Row | Invariant | Evidence | Level | Run | Observed | Status |
|---|---|---|---|---|---|---|
| `F-19-1` | ADR-0060 decision; EG-1 | `sandbox-authority-egress/grant-constrained-https-not-destinations` | real-oci | 43640168802 (#172, `4aee637`) | granted-and-absent [enforcement authority-grant-derivation] | **VERIFIED** |
| `F-19-2` | ADR-0060 decision; EG-1 | `sandbox-authority-egress/constrained-grant-name-not-granted` | real-oci | 43640168802 (#172, `4aee637`) | target-not-granted [enforcement connect-proxy:grant] | **VERIFIED** |
| `F-19-3` | ADR-0060 decision | 5 test(s) in `crates/dwkd-authority/src/sandbox.rs` | in-process | 43648487347 (#173, `299686c`) | the job succeeded; no per-test result of it is retained | **NOT VERIFIED** |
| `F-19-4` | ADR-0060 Evidence: acceptance contract | 6 CI jobs | hosted-job | 43648487347 (#173, `299686c`) | all six jobs: success (33 of 33 jobs of the run) | **VERIFIED** |
| `F-19-5` | mutation review | campaign `agent-mutations` | hosted-mutation | none | local, 2026-11-12: 12 of 12 killed, the F-19 mutant by the authority's unit suite | **NOT VERIFIED** |
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
| `F-17-19` | EG-4; EG-11 | 4 test(s) in `crates/dwkd-broker/src/egress/tests.rs` | in-process | 43648487347 (#173, `299686c`) | the job succeeded; no per-test result of it is retained | **NOT VERIFIED** |
| `F-17-20` | EG-5; EG-7; EG-8 | 9 test(s) in `crates/dwkd-authority/src/state/workload_route_tests.rs` | in-process | 43648487347 (#173, `299686c`) | the job succeeded; no per-test result of it is retained | **NOT VERIFIED** |
| `F-17-21` | EG-3; EG-8 | `sandbox-authority-egress/restart-never-restores-a-pristine-root` | real-oci | 43640168802 (#172, `4aee637`) | exposed-at-start-after-restart [enforcement authority-reconciliation] | **VERIFIED** |
| `F-17-22` | EG-7; EG-8; EG-10 | `sandbox-authority-egress/restart-settles-an-interrupted-workload-uncertain` | real-oci | 43640168802 (#172, `4aee637`) | UNCERTAIN+exposed+uncertain-reach [enforcement authority-reconciliation] | **VERIFIED** |
| `F-17-23` | EG-2 (registry production path) | `sandbox-registry/registry-pip-granted-index-denied-by-policy` | dwkp-end-to-end | 43640168802 (#172, `4aee637`) | refused:nothing-installed;connect-403;POLICY_DENIED=1 [enforcement connect-proxy:workload-authorisation] | **VERIFIED** |
| `F-17-24` | EG-14 Only narrows; EG-13 fixed rules first | pinned `tests/architecture/m5e_cases_before_f17.txt` | hosted-gate | 43640168802 (#172, `4aee637`) | the archived bundles replayed through the M5 gate: inventory COMPLETE, 675 of 675 attributed cases judged again | **VERIFIED** |
| `F-17-25` | multi-identity production path | 26 `sandbox-agent-identity` cases | hosted-three-identity | 43640168802 (#172, `4aee637`) | 26 cases at hosted-three-identity; i01: authority=1001 broker=999 runtime=997 outsider=65534 | **VERIFIED** |
| `F-17-26` | ADR-0061 Evidence: hosted only (M5e.5) | `.github/workflows/m5e5-evidence.yml` | hosted-mutation | 42994561934 (#4, `523dc9a`) | success, but on 523dc9a (2026-11-11), before F-19 (9837ddc) and F-17 (2f5721b) | **NOT VERIFIED** |
| `F-17-27` | mutation review | campaign `egress-policy-mutations` | hosted-mutation | none | local, 2026-11-13: 26 of 26 killed | **NOT VERIFIED** |
| `F-01-1` | T-11 | `sandbox-authority-egress/taint-permission-refusal-failed-dial-not-external` | real-oci | 43640168802 (#172, `4aee637`) | none+POLICY_DENIED+dial-failed:local-only [enforcement authority-taint] | **VERIFIED** |
| `F-01-2` | T-6 | `sandbox-authority-egress/taint-download-no-output-external` | real-oci | 43640168802 (#172, `4aee637`) | stdout-0+external:workload_reached:ORIGIN_BYTES [enforcement authority-taint] | **VERIFIED** |
| `F-01-3` | T-7 | `sandbox-authority-egress/taint-partial-transfer-external` | real-oci | 43640168802 (#172, `4aee637`) | 3-of-5-bytes+external [enforcement authority-taint] | **VERIFIED** |
| `F-01-4` | T-4; T-5 | `sandbox-authority-egress/taint-downloaded-file-read-by-another-run` | real-oci | 43640168802 (#172, `4aee637`) | external:root_exposed:ORIGIN_BYTES [enforcement authority-taint] | **VERIFIED** |
| `F-01-5` | T-3 (R3) | `sandbox-authority-egress/taint-tainted-writer-marks-root` | real-oci | 43640168802 (#172, `4aee637`) | workspace_taint+external-read [enforcement authority-taint] | **VERIFIED** |
| `F-01-6` | T-9 (with ADR-0061) | `sandbox-authority-egress/taint-fresh-run-decided-by-the-exposed-cell` | real-oci | 43640168802 (#172, `4aee637`) | second.example.com:34559 NOVEL np=2/2[https-to-the-evidence-origins] ne=0/2[deny-approval-needed-when-unattended] sp=2/2[https-to-the-evidence-orig... | **VERIFIED** |
| `F-01-7` | T-3; T-7 | `sandbox-authority-egress/taint-interrupted-workload-on-restart` | real-oci | 43640168802 (#172, `4aee637`) | reaped-run-uncertain+next-run-uncertain [enforcement authority-taint] | **VERIFIED** |
| `F-01-8` | T-1; T-2; T-8; T-10; T-12 | 15 test(s) in `crates/dwkd-authority/src/state/taint_route_tests.rs` | in-process | 43648487347 (#173, `299686c`) | the job succeeded; no per-test result of it is retained | **NOT VERIFIED** |
| `F-01-9` | Every earlier evidence case kept | pinned `tests/architecture/m5e_cases_before_f01.txt` | hosted-gate | 43640168802 (#172, `4aee637`) | replayed M5 gate: 675 of 675 attributed cases; tainted-novel-refused-seen-reached observed as seen-200+novel-POLICY_DENIED | **VERIFIED** |
| `F-01-10` | mutation review | campaign `taint-mutations` | hosted-mutation | none | local, 2026-11-13: 20 of 20 killed | **NOT VERIFIED** |
| `F-18-1` | §1 the principal is the kernel's uid; §3; §4 | `i09-runtime-holds-only-what-the-operator-declared`, `i01-three-distinct-host-identities` | hosted-three-identity | 43640168802 (#172, `4aee637`) | LEASE_HELD,UNKNOWN_AGENT_PROFILE [authority-ownership]; uids authority=1001 broker=999 runtime=997 outsider=65534 | **VERIFIED** |
| `F-18-2` | §3 a foreign uid takes over nothing; §4 | eval `authority-security/peer-credential-check` (7 cases) | real-process-second-identity | 43640168802 (#172, `4aee637`) | pass, score 1.0: 7 of 7 expected cases contained, layers peer-gate=3 state-fence=3 filesystem=1, against the real dwkd-authority binary | **VERIFIED** |
| `F-18-3` | §3; §5; §6; §7 | 18 test(s) in `crates/dwkd-authority/tests/state_ownership.rs` | in-process | 43648487347 (#173, `299686c`) | the job succeeded; no per-test result of it is retained | **NOT VERIFIED** |
| `F-18-4` | §5 two-phase revocation; settlement | 5 test(s) in `crates/dwkd-authority/src/state/ownership_route_tests.rs` | in-process | 43648487347 (#173, `299686c`) | the job succeeded; no per-test result of it is retained | **NOT VERIFIED** |
| `F-18-5` | §1 (TX061): runtime-provided descriptors never become authority | 1 test(s) in `crates/dwkd-authority/tests/transport_hostile.rs` | real-process | 43648487347 (#173, `299686c`) | the job succeeded; no per-test result of it is retained | **NOT VERIFIED** |
| `F-18-6` | boundary rules TX061-TX064 | TX061, TX062, TX063, TX064 | static | 43648487347 (#173, `299686c`) | the job succeeded; locally `make arch`: dwcheck ok | **NOT VERIFIED** |
| `F-18-7` | mutation review | campaign `ownership-mutations` | hosted-mutation | none | local, 2026-11-14: 27 of 27 killed | **NOT VERIFIED** |
| `F-18-8` | §3 a foreign uid takes over nothing (case lines and uids kept) | campaign `cross-uid-ownership` | real-process-second-identity | none | never run (new in C3) | **NOT VERIFIED** |

## 4. By finding

### F-19 (ADR-0060)

**Verified.** Both required real-OCI cases were observed in run 43640168802:

- `grant-constrained-https-not-destinations`: three constrained grants, all
  granted, are absent from the destinations.
- `constrained-grant-name-not-granted`: a CONNECT to the constrained-only name
  is refused `TARGET_NOT_GRANTED`.

**The derivation's details** are covered by the unit tests of `sandbox.rs`:
`methods`, `max_requests`, both together, alternative ports, mixtures,
duplicates, and the destination bound.

**ADR-0060's acceptance contract** names four sets of jobs: `sandbox-egress`,
the three-platform tests, `boundaries` and `m5e-gate`. All are green on the
committed revision. Its last item, the mutation review's result, has only ever
run locally: 12 of 12 killed on 2026-11-12.

### F-17 (ADR-0061)

**EG-1 to EG-14 each have a contract row.** All 21 cases F-17 added are
observed, 20 at `real-oci` and one at `dwkp-end-to-end` in the registry suite.
Together they show:

- no authority outside a supervised workload (EG-4);
- both gates, per destination, in one workload (EG-2);
- the name and the resolved addresses each judged (EG-6);
- refusal before resolution (EG-10, EG-13);
- the authorisation ending with the workload (EG-4);
- the per-tunnel bound (EG-9) and the per-destination report (EG-12);
- exposure on the first origin byte, per root, revoking open tunnels, and
  durable across launches and restarts (EG-8);
- novelty (EG-7);
- the intent's digests (EG-3).

**Earlier M5 evidence is intact.** The 647 cases pinned before F-17 are all
judged again by the replayed gate (EG-14).

**The production paths still hold.** The three-identity agent half (26 cases,
on uids 1001, 999, 997 and 65534) and the registry suite still exercise them.

**Gaps:**

- No hosted case puts two concurrent workloads against each other's
  authorisation. The broker's unit test covers it (`F-17-19`).
- The drift tripwire (EG-5) and the typed broker facts (EG-11) are unit-level
  only.
- ADR-0061 names the M5e.5 manual workflow as hosted-only evidence, and it has
  not run on F-17's code. It needs a fresh dispatch. Its `sandbox-hygiene`
  half also runs in every CI run, but its hosted registry mutants run only
  there.

### F-01 (ADR-0062)

**T-1 to T-12 each have a contract row.** All seven real-OCI cases F-01 added
are observed:

- permission, a refusal and a failed dial are not external (T-11);
- an output-less download is external (T-6);
- a partial transfer is external (T-7);
- another run reads the download as external (T-4, T-5);
- a tainted writer marks the root (R3);
- a fresh run is decided by the exposed cell;
- an interrupted workload is settled uncertain on restart (T-3, T-7).

**Earlier evidence is kept and replayed.** The 668 cases pinned before F-01 are
judged again, and `tainted-novel-refused-seen-reached` is observed at its
stricter re-baselined outcome.

**Unit-level only:** monotonicity, ordering, evidence rows and replay (T-1, T-2,
T-8, T-10, T-12).

### F-18 (ADR-0063)

**Verified:**

- **`i09`, on three real host identities.** Observed as
  `LEASE_HELD,UNKNOWN_AGENT_PROFILE`, beside `i01`'s measured uids (authority
  1001, broker 999, runtime 997, outsider 65534).
- **The three foreign-uid ownership cases.** Session takeover, profile
  escalation and an owned session held are among the seven named cases of the
  hosted `authority-security/peer-credential-check` eval. That eval passed: 7
  of 7 contained, against the real binary, with a second identity. It fails
  unless every named case is reported.

**Gaps:**

- The cases' own lines and the two uids are not kept. C3's `cross-uid` job
  keeps both.
- The `state_ownership` and route suites, and the runtime-passed-descriptor
  test, are unit or same-uid real-process tests. Their jobs are green, but no
  per-test result is kept.
- TX061–TX064 are static hygiene.

## 5. The mutation reviews

| Campaign | Finding | `make` task | Mutants | Detectors, in order | Last result |
|---|---|---|---|---|---|
| `agent-mutations` | F-19 (and M5d.5) | `sandbox-agent-mutations` | 12 | the authority's guards; the broker's unit tests, then its private channel; the probe; the one-identity agent evidence | local, 2026-11-12: 12 of 12 |
| `egress-policy-mutations` | F-17 | `sandbox-egress-policy-mutations` | 26 | `dwk-proto`'s egress; the authority's partition and workload; the broker's egress; `sandbox-egress-evidence` | local, 2026-11-13: 26 of 26 |
| `taint-mutations` | F-01 | `sandbox-taint-mutations` | 20 | the authority's unit suite; `sandbox-egress-evidence` | local, 2026-11-13: 20 of 20 |
| `ownership-mutations` | F-18 | `authority-ownership-mutations` | 27 | the five ownership suites; the authority's unit suite | local, 2026-11-14: 27 of 27 |

**The audit.** The runners checked each mutation's target, refused a mutant that
did not build, and restored each file, checked by SHA-256. All three are kept.
But they also:

- ran **no unmutated baseline**, so a detector that already failed killed every
  mutant;
- counted **any** failing command as a kill. That included a test command that
  failed with no failing test (a test target that does not exist, for
  example), and an evidence task's NOT EXERCISED when no runtime answers;
- had no check that a test selection ran anything;
- had no time limit per stage;
- kept no record;
- stopped at the first survivor.

None of this shows a past result was wrong. It shows the past results could not
have shown otherwise.

**`mutation_review` in `scripts/dw.py` now runs all four:**

- It checks every target first, then runs the baseline: the same build and
  stages, unmutated. Each stage must pass, and each test selection must run at
  least one test, or the review is BLOCKED and judges no mutant.
- It applies each mutant and reads its bytes back. A mutant is KILLED only by a
  test that failed **by name**, or by an evidence task's refusal.
- None of these counts as a kill: COMPILE_ERROR; ERROR (failed with no failing
  test); NO_TESTS; TIMEOUT (45 minutes a command); BLOCKED (NOT EXERCISED).
- It restores and checks every file whatever happens.
- It writes `target/c3-evidence/<campaign>-<k>of<n>/record.json` before the
  first mutant and after each one. A failed review keeps its diagnostics and
  says FAIL.
- `DW_MUTATION_SHARD=k/n` runs one shard.

**What a kill names:**

- **By a test selection:** the failing tests.
- **By an evidence task:** the first line of its refusal. That attribution is
  weaker, and the same runner's passing baseline is what stands behind it.

## 6. The hand-dispatched workflow

`.github/workflows/c3-evidence.yml` (**C3 hosted evidence (manual)**) runs only
when dispatched:

- **Rights:** a read-only token, no secrets, the same SHA-pinned actions as
  `ci.yml`, nothing as root.
- **`mutations`:** the four reviews in 11 independent shards (`fail-fast:
  false`, 300 minutes each). Each shard keeps its record whatever happens.
- **`cross-uid`:** `make c3-cross-uid-evidence` with `DW_PEER_AS=nobody`. It
  proves the second identity by number, keeps the cross-uid suite's output and
  both uids, judges the output with the same function as
  `authority-transport-evidence`, and keeps the hostile-client suite's
  descriptor test by name.
- **`c3-gate`:** `make c3-gate-check` over the records of **this** run only.
  There is no `run-id`, so an archived or earlier record cannot be read. It
  requires:
  - every shard of every campaign;
  - this run, attempt and commit, from a GitHub-hosted runner;
  - each inventory exactly its table, across the shards;
  - a passed baseline that ran tests;
  - every mutant applied, killed and restored;
  - for the cross-uid record, two distinct non-root uids.

  Anything else fails it.

The workflow is not a required check. `ci.yml`, its `CI` aggregate and its M5
gate are unchanged.

**What the owner does:**

1. After this change is committed and pushed, open **Actions → C3 hosted
   evidence (manual) → Run workflow**, choose `main`, and run it.
2. Also dispatch **Actions → M5e.5 evidence (manual)** on `main` (row
   `F-17-26`).
3. When both finish, send the two run ids. Within 7 days, download the C3 run's
   twelve `c3-evidence-*` artifacts and its log archive (§7).

The matrix rows move to VERIFIED only from the C3 gate's own passed run.

## 7. Keeping C3's evidence

The F-10 archive (`docs/EVIDENCE_ARCHIVE.md`) covers `ci.yml` and `fuzz.yml` runs
only. Its contracts are frozen, and C3 does not change them. Until a C3 class is
added (§8):

1. Download the twelve `c3-evidence-*` ZIPs and the log archive from the run's
   page within 7 days.
2. Put them in `<archive root>/c3/<run id>/`, beside the F-10 archives and never
   inside the repository.
3. Compare each ZIP's SHA-256 with the `digest` GitHub's API lists for it
   (`GET /repos/Onwcan/DireWolf/actions/runs/<run id>/artifacts`). For
   example, `sha256sum *.zip`, or on Windows `certutil -hashfile <zip> SHA256`.
4. Record the run id, the commit and the gate job's result next to them.

Never copy a C3 record where a run's gate reads it. The C3 gate refuses every
record of another run, and so does the M5 gate.

## 8. Residual risks

- **A kill by an evidence task names no test.** An infrastructure failure during
  a mutant's evidence run would be counted as a kill. The same runner's passing
  baseline narrows that, but does not remove it.
- **A flaky test can kill a mutant falsely.** The baseline shows the detectors
  pass unmutated once, not that they never flake.
- **Each review weakens only the guards it lists.** Mutation testing shows those
  guards are watched, not that no other guard is missing.
- **CI #173's own artifacts were not inspected.** Its evidence is the same
  source as #172's, which was. Its artifacts expire on 2026-11-21.
- **Some properties remain unit-level only** until the C3 run records their
  tests by name: EG-5, EG-11, T-1, T-2, T-8, T-10, T-12, and F-18's revocation
  and adoption rules. Two concurrent workloads against each other's
  authorisation have no real-OCI case.
- **Records and archives are hashed, not signed** (see `EVIDENCE_ARCHIVE.md`).
- **A C3 archive class** for `scripts/evidence_archive.py` (a frozen contract of
  campaigns and shards, judged by the same gate) is a bounded follow-up. It is
  not built here.
