# M6 preparation handoff

**As of 2026-11-23.** The end of the pre-M6 security remediation and the
entry contract for M6, Approvals and budgets ([ROADMAP.md](ROADMAP.md)). It
records what is closed, by what evidence, what stays open, which decisions
are the owner's before M6.0, and a proposed order of work inside M6. **No M6
functionality is built, and nothing here starts it.** The build order stays
M6 → M3.5 → M7 → M8 → M9.

> **Since (2026-11-24).** The three decisions §C lists as blocking M6.0 have
> moved: ADR-0063, ADR-0067 and ADR-0077's OD-1 are accepted, and OD-2 is a
> record of its own, [ADR-0078](adr/0078-approval-assurance-which-classes-need-a2-and-the-presence-factor.md),
> accepted the same day. The plan this page proposed in §E is carried, bounded and
> corrected against the code, in [M6_IMPLEMENTATION_PLAN.md](M6_IMPLEMENTATION_PLAN.md),
> with its decisions in [M6_0_DECISION_PACKAGE.md](M6_0_DECISION_PACKAGE.md).
> The rest of this page is as it was on 2026-11-23.

The finding-by-finding ledger is [PRE_M6_REMEDIATION.md](PRE_M6_REMEDIATION.md);
the two security reviews are
[INDEPENDENT_SECURITY_REVIEW_2026-11-22.md](INDEPENDENT_SECURITY_REVIEW_2026-11-22.md)
(SR-01 to SR-09, at `d0fbb24`) and
[INDEPENDENT_SECURITY_REREVIEW_2026-11-22.md](INDEPENDENT_SECURITY_REREVIEW_2026-11-22.md)
(ISR2-01 to ISR2-09, at `f7f5aae`). This page repeats from them only what
the handoff needs.

## A. Baseline

| | |
|---|---|
| Starting revision | `8b771a7` on `main` (`8b771a7399882823c8299655843322427a06ce9a`), equal to `origin/main` |
| Hosted CI at it | CI #213, [run 45250010413](https://github.com/Onwcan/DireWolf/actions/runs/45250010413): 33 of 33 job records succeeded |
| Push workflow (CodeQL) at it | #31, [run 45250010312](https://github.com/Onwcan/DireWolf/actions/runs/45250010312): 4 of 4 jobs succeeded |
| Namespace evidence at it | `sandbox-egress`: `namespace evidence: 4 tests, 9 markers, each exercised` -- F-16's six cases, F-05's two, the hidden-pid peer reader's one |
| `net.http` evidence at it | 193 cases, `obligation-unenforceable` (ISR2-01) among them |
| Approver evidence at it | `authority boundary`: `approver evidence: 1 test, 6 cases contained, three identities` |
| First review's baseline | `d0fbb24`, CI #205 (run 45027301654) |
| Second review's baseline | `f7f5aae`, CI #209 (run 45056220111), 33 of 33 |
| Earlier reference | `02bb256`, CI #212 (run 45240438449), 33 of 33; CI #211 at `85ddb7d` shows failed only because its macOS job was cancelled by the next push (`cancel-in-progress`) |

The work below is a change to that tree, not yet committed: everything it
adds is **local evidence** until the owner commits it and a hosted run
reports. The hosted facts above are of `8b771a7` as it is.

## B. Pre-M6 security closure

Status words: **CLOSED** (built, and its hosted evidence observed),
**CLOSED LOCALLY** (built and mutation-proved here; its hosted run follows
the commit), **OPEN**, **NOT EXERCISED**, **ACCEPTED RESIDUAL**.

| Finding | Problem | Enforcement now | Regression tests | Mutation evidence | Hosted | Residual | Status |
|---|---|---|---|---|---|---|---|
| SR-01 / ADR-0075 | policy files read without the trusted walk | `PolicySet::from_files` → `read_operator_file` → `trusted_file::read`; the policy loads after `socket::prepare` gives the authority's uid and before anything is served | `transport_server.rs`: the loader's refusals; the released binary refuses to start, naming `--policy-file` | SR-01a killed (first review) | CI #209 → CI #213: both tests in `make test` (ubuntu) and `authority boundary` | ISR2-04: a write descriptor opened before `chmod go-w` survives it -- migration replaces the file ([OPERATIONS.md](OPERATIONS.md) §4) | **CLOSED**; ADR-0075 **accepted** |
| ISR2-01 / ADR-0076 | `audit_level=full` counted as kept on a `net.http` hop whose record holds the URL only as a digest | `net_http/plan.rs` `obligations`: a hop keeps `max_output_bytes` only; `audit_level=full` denies `OBLIGATION_UNENFORCEABLE` before any exchange | `a_tainted_run_reaches_no_new_origin_and_obligations_narrow_or_deny`: denied, no `http.exchange`, `max_output_bytes` still narrows | the old behaviour restored fails the test (the fix's author) | CI #212, CI #213: the case line among 193 | the case line is shared with `network_deny`'s; it prints after both assertions | **CLOSED** by evidence; open for a verification pass by someone other than the fix's author |
| ISR2-02 | the model import's in-loop length bound held by no test | `copy_hashing`: refuses once more than the checked length is read; the import removes what it staged | `a_source_extended_after_its_check_is_never_copied_past_its_checked_length` (in CI #213); `an_import_whose_source_grows_after_its_check_publishes_nothing` (new) | SR-04b 5/5 runs, SR-04bc, SR-04d: each killed | the first test in CI #213 (ubuntu, macOS); the second follows the commit | non-Unix identity is length and modification time (first review) | **CLOSED LOCALLY** |
| ISR2-03 | the walk's directory no-follow and set-id refusal held by no test | `trusted_file::read`: `O_NOFOLLOW` on every directory component, `0o6000` refused | `the_operator_file_walk_refuses_a_symlinked_directory_and_a_set_id_file`, now with the sticky-directory cases | TF-1, TF-2, TF-3: each killed by this test alone | in CI #213 (ubuntu) without the sticky cases; with them after the commit | Linux only, as the walk is | **CLOSED LOCALLY** |
| ISR2-05 / ADR-0077 | Accepted ADR-0022 still prescribes the terminal-over-DWKP and DWKP `direwolf approve` paths | built: no descriptor received on either endpoint (TX061), no approval operation (TX065), every `REQUIRE_APPROVAL` denies | ADR-0067's suites | `make approver-identity-mutations` 13/13 (re-run by the second review) | CI #213: three identities | -- | **OWNER-DECISION-PENDING** (ADR-0077 OD-1) |
| ISR2-06 / ADR-0077 | an approver uid is a principal, not a person | the endpoint authenticates a uid; nothing claims a person | -- | -- | -- | A1 proves the principal; A2 needs a presence factor not built | **OWNER-DECISION-PENDING** (ADR-0077 OD-2) |
| SR-02 / F-16 | the namespace tests passed as NOT EXERCISED in every hosted job | `make namespace-evidence` in `sandbox-egress` after the runner's restriction is lifted | the task's checker tests | `make resolver-mutations` 3/3 | CI #209 → CI #213: 4 tests, 9 markers | -- | **CLOSED** |
| SR-06 bind mount | no real-kernel bind mount inside a workspace | `RESOLVE_NO_XDEV` on every `openat2` | `a_bind_mount_inside_a_workspace_is_never_crossed` (new), required by `make namespace-evidence` (5 tests, 10 markers) | BM-1 (`NO_XDEV` dropped): killed | after the commit, in `sandbox-egress` | -- | **CLOSED LOCALLY** |
| SR-06 casefold | no casefold filesystem | `verify_entry`'s exact-name check (a case-sensitive filesystem's evidence only) | the exact-name check's unit case | -- | -- | no kernel tested here has Unicode casefolding | **NOT EXERCISED** (plan in §G) |
| ISR2-08 | records stale after CI #209 | -- | `test_docs_truth.py` | -- | -- | -- | reconciled in this change |

The rest of F-01 to F-19 is as the ledger states; nothing here changes their
code or their hosted state.

## C. ADR decision register

### Already decided

- **ADR-0075** -- policy files through the trusted walk. OD-1 accepted
  2026-11-22, recorded Accepted 2026-11-23 with its hosted evidence; its
  Decision unchanged from the reviewed text. Its digest is in
  `docs/adr/accepted.sha256` (`dwcheck adr --record`); from the commit on,
  Git history anchors it.
- **ADR-0022** -- Accepted, immutable. Its remote channel stands; its two
  local paths would be withdrawn by ADR-0077 on acceptance. Neither is built.

### Prepared, waiting for the owner

| Record | What it decides | Why it matters to M6 | Recommendation |
|---|---|---|---|
| ADR-0062 (F-01) | a run's taint follows the content it receives | `require_untainted_run` and taint in the binding stand on it | accept: hosted-observed |
| ADR-0063 (F-18) | sessions, workspaces and profiles belong to principals; the runtime is never its own approver | approvals bind to principals, and the store refuses self-approval | accept, **before M6.0** |
| ADR-0064 (F-02) | an end of authority waits for every effect already decided | an approval's consumption and a revocation must serialise the same way | accept: hosted-observed, 20/20 mutants |
| ADR-0067 (F-18) | the approver endpoint, identity boundary only | the one door M6's channel is built on | accept, **before M6.0** |
| ADR-0076 (ISR2-01) | `audit_level=full` is not kept on a hop | M6 shows obligations to the approver; one must never read "kept" where it is not | accept (package below) |
| ADR-0077 (ISR2-05, ISR2-06) | one approval channel; an approver uid is a principal; A1 and A2 | without it, ADR-0022's paths are still the formal design | accept OD-1 **before M6.0**; decide OD-2 |

**ADR-0076 acceptance package.**

- *Decision:* a `net.http` hop keeps `max_output_bytes` only; `audit_level=full`
  denies it `OBLIGATION_UNENFORCEABLE` before any exchange.
- *Operator-visible:* a network rule carrying `audit_level=full` stops
  allowing the hops it matches; workload tunnels it decides are unaffected;
  no shipped pack uses it.
- *Migration:* drop `audit_level=full` from network rules, or accept the
  denial.
- *Evidence:* the test above; CI #212 (run 45240438449) and CI #213 (run
  45250010413) print its case.
- *Records on acceptance:* its Status line to Accepted with the date and
  evidence; its index row bold, "amends 0050 §5 step 6"; ADR-0050's row
  "§5 step 6 amended by 0076"; `dwcheck adr --record` in the same commit; the
  README count (57 accepted, 17 Proposed); the ledger's sentence.

### Owner decisions that block M6.0

1. Accept ADR-0063 and ADR-0067 (the principal model and the approver
   endpoint).
2. Accept ADR-0077 OD-1: one approval channel, ADR-0022's local paths
   withdrawn.
3. Decide ADR-0077 OD-2: which classes need A2, and whether M6 builds a
   presence factor or leaves those classes denied.

ADR-0062, ADR-0064 and ADR-0076 are recommended but do not block M6.0.

## D. M6 security entry contract

Every M6 phase preserves these; a change to one is a new ADR.

1. **No runtime self-approval.** Approvals arrive only on the approver
   endpoint; the DWKP endpoint receives no descriptor and decodes no
   approval-shaped member; the store refuses an approval whose approver is
   its requester.
2. **Kernel-authenticated approver identity.** The kernel's report of the
   peer's uid, disjoint from every runtime's, the broker's and the
   authority's, with no override; recorded with the assurance level (A1, A2)
   actually provided.
3. **A trusted approver client** renders the authority's request from data
   on its own terminal, as an approver uid; agent-authored text is
   quarantined and labelled; nothing in the authoritative region is
   model-authored.
4. **Canonical action binding.** The approval binds the canonical action,
   taint, privacy class, obligations, environment profile, the requester's
   principal and the agent ([ADR-0021](adr/0021-approval-binding-v2.md),
   [APPROVALS.md](APPROVALS.md) §1).
5. **JCS binding hash** ([ADR-0032](adr/0032-wire-contract-framing-strict-json-and-jcs.md)):
   one canonical encoding, the same bytes hashed at request and at use.
6. **Atomic single-use consumption.** Burned in the same transaction that
   records the effect's intent; a second use, a concurrent use or a use after
   restart finds it burned.
7. **Re-canonicalisation before the effect.** The action is resolved again
   at use -- file identity, executable hash, pinned address set,
   environment -- and a drift denies (`approval.drift_detected`).
8. **Taint-sensitive matching.** A tainted run does not match an approval or
   grant made for an untainted one; `require_untainted_run` is the default.
9. **Principal-bound standing grants**, listed, capped at 90 days, never
   created from a prompt's "approve".
10. **Hierarchical subtractive budgets.** A child's budget is carved from its
    parent's; nothing is created by fan-out.
11. **No amplification** of authority or budget from parent to child, or
    across a restart.
12. **Unattended `DENY`.** No approver, no decision before expiry, no
    endpoint: `REQUIRE_APPROVAL` denies; expiry is not denial.
13. **No host-local execution** without a per-invocation approval and the
    operator's `--allow-host-execution` ([ADR-0045](adr/0045-m4d-process-execution-broker.md)
    host floor); Landlock with it is ADR-0070 OD-D's.
14. **Revocation and restart.** A decision does not outlive the authority
    that made it: an approval is bound to the incarnation's epoch and the
    policy revision, and ADR-0064's gate serialises an ending with every
    decided effect.

## E. M6 implementation sequence (proposed)

These labels are proposals, not approved sub-milestones. Each phase is
independently verifiable and ends with its hosted evidence.

| Phase | Depends on | Builds | Security-critical operations | Tests | Hosted evidence | Exit |
|---|---|---|---|---|---|---|
| **M6.0** decisions | -- | nothing | -- | -- | -- | ADR-0063, ADR-0067, ADR-0077 OD-1 accepted; OD-2 decided; an M6 ADR for the registry's schema proposed |
| **M6.1** binding and hash | M6.0 | the binding type from canonical inputs; its JCS hash (`dwk-proto`, `crates/dwkd-authority/src/policy`) | canonicalisation; the hash | property tests: every bound field changes the hash; vectors; no field from the runtime | `make test`; protocol vectors | every APPROVALS.md §10 binding property passes |
| **M6.2** registry and burn | M6.1 | the next store schema: requests, approvals, grants, burns; audit kinds (`crates/dwkd-authority/src/state`) | the atomic burn with the intent; epoch fencing | concurrency: N consumers, one wins; crash windows around the burn; restart finds it burned; revocation races | `make authority-state-evidence`, a hosted crash campaign | a use after burn, revoke or restart denies |
| **M6.3** endpoint and client | M6.2 | approver-endpoint operations (fetch, decide), the trusted client (`direwolf approve`) | request nonce; binding re-verified on decide; the assurance level recorded | three identities: a runtime uid cannot fetch, decide or replay; the agent claims of ADR-0067 §4 | `authority boundary` three-identity suite | `REQUIRE_APPROVAL` approvable at A1 for the classes OD-2 allows |
| **M6.4** standing grants | M6.3 | grant creation, listing, revocation; 90-day cap; `require_untainted_run` | principal binding; taint match | widening: a grant never covers more than its scope; taint; expiry | `make test`, state evidence | no grant from a prompt; every grant listed and revocable |
| **M6.5** budgets | M6.2 | the subtractive ledger, parent/child carving | underflow, overflow, fan-out | property tests for no amplification; concurrency on one parent | `make test` | APPROVALS.md §10's budget properties |
| **M6.6** gated host execution | M6.3, M6.5 | host launches behind a per-invocation approval and `--allow-host-execution` | re-canonicalised executable identity at use | drift: binary swapped after approval; environment swap | `process-broker` evidence | no host launch without both; Landlock per OD-D |
| **M6.7** adversarial acceptance | all | -- | -- | replay, substitution, drift, laundering, environment swap, fatigue, amplification, agent self-approval | every M6 job hosted | the roadmap's M6 acceptance list passes |
| **M6 closeout** | M6.7 | records | -- | -- | one green hosted run | M6's ADRs accepted; the roadmap's M6 marked complete |

Forbidden until the phase that builds it is accepted: any approval
operation on any endpoint; any insert into an approval table on the runtime
path (TX062); a descriptor on either endpoint (TX061); a host launch.

## F. Critical path

Before M6.0: the three owner decisions in §C. Nothing else blocks it.

Not blockers, and not to be treated as such: SR-06's casefold evidence,
ISR2-07 (branch protection), ISR2-09 (model-library hardening), SR-09's
local-only campaigns, the acceptance of ADR-0062, ADR-0064 and ADR-0076,
and the hosted runs of this change's new tests -- each is tracked in §G.

## G. Remaining risks

| Item | Owner | Priority | Closed when |
|---|---|---|---|
| ISR2-01's separate verification | a reviewer other than the fix's author | medium | someone else confirms the fix, the test and the hosted case |
| ISR2-02/03 strengthened tests, SR-06's bind mount | the owner (commit) | medium | the first hosted run after the commit shows the tests passing and `namespace evidence: 5 tests, 10 markers, each exercised` |
| SR-06 casefold | engineering | low | a hosted job makes a casefold filesystem and the resolver refuses its alias (plan below) |
| ISR2-07 branch protection | the owner | low | a ruleset requiring `CI` on `main`, or a recorded decision to accept post-push CI |
| ISR2-09 model-library hardening | engineering | low | the second review's hardening items done or declined |
| SR-09 local-only campaigns | engineering | low | capability and authority-state campaigns run hosted |
| F-05 per-environment user namespace | upstream runtimes | -- | a supported runtime offers one per container |
| Protocol 13 / D6, Landlock (OD-D), F-06 OF-3, model downloads, F-12 artifact capture | as deferred | -- | their milestones |
| SR-07 domain fronting, the shared kernel | accepted residuals | -- | not closed; stated in [THREAT_MODEL.md](THREAT_MODEL.md) |
| M5e.2 | -- | -- | **partially completed**, tracked by its existing issue |

**SR-06 casefold, the hosted plan.** In the `sandbox-egress` job, after the
step that lifts the namespace restriction: if
`/sys/fs/tmpfs/features/casefold` exists (Linux 6.13 and later with Unicode
support), the test mounts `tmpfs -o casefold` in its own user and mount
namespace; otherwise, where `/sys/fs/ext4/features/casefold` exists and the
runner allows `sudo`, a 16 MiB file is made `mkfs.ext4 -O casefold`,
loop-mounted, and a directory in it given `chattr +F`. The test then shows the
alias exists -- `stat` of `README` finds `readme` -- and that the resolver
refuses `/workspace/case/README` as `NAME_MISMATCH` and resolves
`/workspace/case/readme`; it reports the case exercised only after both held,
and NOT EXERCISED with the reason where neither feature is present. The
evidence task would require it only once a hosted run has shown the feature
present, so that no required check fails for want of a kernel feature.

## H. Verdict

**CONDITIONALLY READY -- OWNER DECISIONS REQUIRED.** No security blocker is
open: every confirmed vulnerability of both reviews is fixed with hosted
evidence, the remaining test gaps are closed locally and mutation-proved,
and the approval boundary that M6 builds on is built and three-identity
tested. M6.0 cannot start until the owner accepts the principal model and
the approver endpoint (ADR-0063, ADR-0067) and the single approval channel
(ADR-0077 OD-1), and decides the assurance levels (OD-2). The first safe
engineering task after those decisions is M6.1: the binding and its hash,
with no registry and no endpoint operation.
