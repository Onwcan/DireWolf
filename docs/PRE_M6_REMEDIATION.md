# Pre-M6 security remediation: state and hosted evidence

**As of 2026-11-21; F-16's row and the sections after "What is open" brought
to CI #213 (run 45250010413, `8b771a7`) on 2026-11-23.** Between M5 and M6, the findings of the security review
of 2026-11-11/12 (F-01 to F-19) were remediated one by one. This is not a
milestone and does not change the build order ([ROADMAP.md](ROADMAP.md): M6
is next). This page is the one place that says, for each finding, which
record holds its decision and what a hosted run actually exercised.

**Sources.** CI #201 (run 44818094052, `3998de2`, 2026-11-20) and CI #202
(run 44902937921, `6a0acea`, 2026-11-21; documentation only): every job
succeeded in both (33 job records each, the aggregate among them). The
evidence below is read from CI #201's job logs: a line names the case that
ran, its level and its outcome. **A green run is not evidence for a property
its jobs did not exercise**, and a test that reports NOT EXERCISED and
passes is listed as not exercised.

**Reading the Hosted column.** `OBSERVED`: the cases that carry the property
ran in a hosted job and held. `NOT EXERCISED`: the hosted job ran the test,
and the test could not exercise the property there. `n/a`: no hosted case
applies. Every decision record named in the table is **Proposed** but
F-18's two, ADR-0063 and ADR-0067, accepted 2026-11-24; none is accepted
by this page, by a green run or by a commit. Of the records below, ADR-0075
(accepted 2026-11-22, recorded 2026-11-23), ADR-0077 (OD-1, accepted
2026-11-24) and ADR-0078 (ADR-0077's OD-2, accepted 2026-11-24) are
accepted.

## Findings

| Finding | What changed | Record | Hosted | Hosted evidence (CI #201 unless stated) | Not shown by a hosted run |
|---|---|---|---|---|---|
| F-01 | a run's taint follows the content it receives | [ADR-0062](adr/0062-taint-follows-delivered-content.md) | OBSERVED | `sandbox-egress`, real OCI: the `taint-*` cases, `taint-fresh-run-decided-by-the-exposed-cell` among them | -- |
| F-02 | an end of authority waits for every effect already decided | [ADR-0064](adr/0064-f02-authority-endings-serialised-with-decided-effects.md) | OBSERVED | `make test` on Linux, macOS and Windows: the gate's unit tests and `tests/state_concurrency.rs` | the mutation review is local |
| F-03 | each daemon reports its effective posture, control by control | [ADR-0065](adr/0065-f03-effective-posture-is-reported-and-recorded.md) | OBSERVED | `authority-transport`: `each_incarnation_records_its_effective_posture_and_a_restart_records_the_change` against the real binary; the broker's posture tests in `make test` | the broker's posture in the authority's record (D6, protocol 13): deferred |
| F-04 | the CONNECT proxy admits only the relay's kernel uid | [ADR-0068](adr/0068-f04-connect-proxy-peers-are-authenticated-by-kernel-uid.md) | OBSERVED | `sandbox-egress`, `make proxy-peer-evidence` with a real foreign uid (`DW_PEER_AS=nobody`, uid 65534): `foreign-uid-refused-through-a-loosened-directory`, `foreign-uid-served-only-when-it-is-the-relay` | -- (the hidden-pid case, `kernel-hidden-pid`, ran here too: the job lifts the runner's restriction on unprivileged user namespaces first; corrected 2026-11-22) |
| F-05 | an environment's user namespace and security module measured; a module required on request | [ADR-0069](adr/0069-f05-user-namespace-and-lsm-assurance-are-measured-not-assumed.md), [ADR-0070](adr/0070-adr-0069-decisions-host-vantage-required-lsm-and-what-stays-deferred.md) | OBSERVED | CI #198 (run 44706359028): the `required-apparmor-*` cases; on CI #198 and again on CI #201, `sandbox-foundation` reports `userns=UNSUPPORTED:both:shared apparmor=ENFORCED:both:docker-default` | **partially completed**: a user namespace per environment is not built -- no supported runtime offers one per container ([F05_USERNS_LSM.md](F05_USERNS_LSM.md) §13) |
| F-06 | the operator's egress allowlist: every shipped rule requires it (OF-1), and it is a ceiling over every policy (OF-2) | [ADR-0071](adr/0071-f06-an-operator-egress-allowlist-every-shipped-network-rule-requires.md), [ADR-0073](adr/0073-f06-of2-the-operators-egress-allowlist-is-a-ceiling-every-policy-is-under.md) | OBSERVED | OF-1 on CI #198; OF-2: `net.http`, 193 cases, the seven `of2-operator-policy-*` among them; `sandbox-registry` (20 cases) and `sandbox-hygiene` (44) under `--egress-allowlist` | OF-3, a `model_download` path and per-entry quotas: partially decided, not built |
| F-07 | one coverage-guided fuzz job per target | -- | OBSERVED | the Fuzz workflow, run 43602590762 (2026-11-14): 8 of 8 targets PASS | -- |
| F-08 | repository governance | -- | n/a | handled in repository settings, not in the repository's files | not verifiable from the repository |
| F-09 | private vulnerability reporting | [SECURITY.md](../SECURITY.md) | OBSERVED | `GET https://api.github.com/repos/Onwcan/DireWolf/private-vulnerability-reporting` answers `{"enabled":true}` (read 2026-11-21) | whether administrators are notified is a personal setting |
| F-10 | a CI evidence archive | [EVIDENCE_ARCHIVE.md](EVIDENCE_ARCHIVE.md) | n/a | an operator's tool; nothing hosted to exercise | -- |
| F-11 | every GitHub Actions pin checked | `tests/architecture/test_ci_supply_chain.py` | OBSERVED | `dependencies` (`make security`, which runs `make action-pins`) and the architecture tests in `make test` | -- |
| F-12 | host path anchors placed by identity | [ADR-0066](adr/0066-f12-host-path-anchors-are-placed-by-identity.md) | OBSERVED | `broker-fs-read`: `shipped-pack-reads-with-a-trusted-home`, `shipped-pack-refuses-an-overlapping-home`, `shipped-pack-denies-unevaluable`; `make test` on three platforms | artifact capture: M8 |
| F-13 | the product specification against the deployment as built | this page's change: [OPERATIONS.md](OPERATIONS.md), [PRODUCT_SPEC.md](PRODUCT_SPEC.md) | n/a | documentation; `tests/architecture/test_docs_truth.py` | hosted run of the new checks: pending |
| F-14 | the competitive analysis since M4 | [COMPETITIVE_ANALYSIS.md](COMPETITIVE_ANALYSIS.md) §22 | n/a | documentation | -- |
| F-15 | roadmap and records against each other | this page; [ROADMAP.md](ROADMAP.md) | n/a | documentation; `tests/architecture/test_docs_truth.py` | hosted run of the new checks: pending |
| F-16 | the broker resolves the decided name and no other | [ADR-0074](adr/0074-f16-the-broker-resolves-the-decided-name-and-no-other.md) | OBSERVED | CI #209 (run 45056220111, `f7f5aae`) and every run since, latest CI #213 (run 45250010413, `8b771a7`): `sandbox-egress`, `make namespace-evidence` after the job lifts Ubuntu's restriction on unprivileged user namespaces -- all six `F16-EVIDENCE` cases, no NOT EXERCISED. On CI #201 the test ran only in the broker unit run, which has no such namespaces, and passed as NOT EXERCISED | the mutation review (`make resolver-mutations`, 3 of 3 killed) is local |
| F-17 | each workload's egress decided by policy | [ADR-0061](adr/0061-workload-egress-decided-by-policy-novelty-and-exposure.md) | OBSERVED | `sandbox-egress`, real OCI: `a_workloads_egress_authorisation_holds_in_the_real_topology`; `sandbox-registry`, 20 cases; the agent suite's three-identity half | -- |
| F-18 | sessions, workspaces and profiles owned by principals; the approver's own endpoint | [ADR-0063](adr/0063-principal-ownership-of-sessions-workspaces-and-profiles.md), [ADR-0067](adr/0067-f18-approver-endpoint-identity-boundary.md) | OBSERVED | `authority-transport`, three identities (uid 1001, `DW_PEER_AS`, `DW_APPROVER_AS` uid 999): `transport_foreign`'s cross-uid test and six `cross-uid-*` approver cases; `sandbox-agent`: `i09-runtime-holds-only-what-the-operator-declared` at `hosted-three-identity` | approvals themselves: M6 |
| F-19 | a constrained network grant gives a `PROXY_ONLY` environment no destination | [ADR-0060](adr/0060-a-constrained-network-grant-gives-no-proxy-only-destination.md) | OBSERVED | `sandbox-egress`, real OCI: `grant-constrained-https-not-destinations`, `constrained-grant-name-not-granted` | -- |

**Code scanning #10 to #13** (`py/insecure-protocol`): the TLS 1.2 floor in two
evidence clients; GitHub's code scanning closed all four as fixed on
2026-11-20, and `tests/sandbox/test_tls_floor.py` passed on Linux, macOS and
Windows.

**Also since M5, not a finding:** the operator's offline model library
([ADR-0072](adr/0072-the-operators-model-library-is-offline-and-a-download-is-egress-the-authority-decides.md),
Proposed; [MODELS.md](MODELS.md)), whose tests run in `make test` on three
platforms.

## What is open

- **F-05**, partially completed: every environment runs as one host uid until
  a runtime offers a user namespace per container.
- **F-16** is no longer open: `make namespace-evidence`, added 2026-11-22 to
  the `sandbox-egress` job after the step that lifts Ubuntu's restriction,
  reported its six cases from CI #209 on, with F-05's two real-kernel-map
  cases and the hidden-pid peer reader (ADR-0049), which also printed NOT
  EXERCISED in every hosted job before.
- **SR-06**, the filesystem resolver's two environmental cases: a bind mount
  inside a workspace is exercised since 2026-11-23 on WSL2 and, once
  committed, in `sandbox-egress` (below); a casefold filesystem stays NOT
  EXERCISED -- the development kernel (WSL2) has no Unicode casefolding, and
  no hosted job makes such a filesystem.
- **Deferred by decision:** protocol 13 with F-03's D6 (ADR-0070 OD-C),
  Landlock with M6's host execution (OD-D), F-06's OF-3, model downloads after
  M7 (ADR-0072 OM-2), F-12's artifact capture (M8).
- **Acceptance:** every other record in the table stays Proposed until it
  is accepted. The approval channel -- ADR-0063, ADR-0067 and ADR-0077's
  OD-1 -- was accepted on 2026-11-24, M6.0's first gate
  ([M6_PREPARATION_HANDOFF.md](M6_PREPARATION_HANDOFF.md)); which classes
  need A2 is [ADR-0078](adr/0078-approval-assurance-which-classes-need-a2-and-the-presence-factor.md), accepted the same day.

## Since the security review of 2026-11-22

That review (its report is `docs/INDEPENDENT_SECURITY_REVIEW_2026-11-22.md`)
found that operator policy files were read without the contract the other
operator files keep (SR-01): the fix is
[ADR-0075](adr/0075-sr01-operator-policy-files-are-read-as-the-other-operator-files-are.md),
built 2026-11-22, its two regression tests hosted from CI #209 (run
45056220111, `f7f5aae`) on; **accepted** (OD-1, 2026-11-22; recorded
2026-11-23). Making a file that another uid could once write trusted means
replacing it, not re-moding it ([OPERATIONS.md](OPERATIONS.md) §4).

## Since the second security review of 2026-11-22

That review (its report is `docs/INDEPENDENT_SECURITY_REREVIEW_2026-11-22.md`)
found that `audit_level=full` was counted as kept on a `net.http` hop whose
record holds the URL only as its digest (ISR2-01): the fix is
[ADR-0076](adr/0076-isr2-01-audit-level-full-is-not-kept-on-a-net-http-hop.md),
Proposed, built 2026-11-23, hosted evidence observed on CI #212 and CI #213
(`net-http-evidence`'s `obligation-unenforceable` case). The finding stays
open until a verification pass separate from the fix confirms it.

The same review found three guards that no repository test held (ISR2-02,
ISR2-03): the model import's bound inside its copy loop, and the trusted
file walk's refusal of a symlinked directory and of a set-id file. Since
2026-11-23 each has a test that fails when its guard is removed --
`a_source_extended_after_its_check_is_never_copied_past_its_checked_length`
(`direwolf-cli`) and
`the_operator_file_walk_refuses_a_symlinked_directory_and_a_set_id_file`
(the secret backend) -- and both ran and passed in CI #213's `make test`
(the walk's on Linux only, as the walk is). Later the same day the walk's
test gained the sticky-directory cases, and the import gained a test of the
whole import (`an_import_whose_source_grows_after_its_check_publishes_nothing`:
no manifest, no object, nothing in `tmp/`), entered through a hook compiled
into tests only; their mutants (TF-1, TF-2, TF-3, SR-04b, SR-04bc, SR-04d)
are each killed locally, and their hosted run follows the commit.

It also found ADR-0022's local approval paths still prescribed by an
Accepted record (ISR2-05) and that an approver uid is a principal, not a
person (ISR2-06):
[ADR-0077](adr/0077-the-approval-channel-is-the-approver-endpoint-and-an-approver-uid-is-a-principal-not-a-person.md),
a decision record with nothing built, withdraws those paths and states the
assurance levels; its OD-1 was accepted on 2026-11-24, and its OD-2 -- which
classes need A2 -- moved to [ADR-0078](adr/0078-approval-assurance-which-classes-need-a2-and-the-presence-factor.md), accepted the same day.

**SR-06's bind mount.** `a_bind_mount_inside_a_workspace_is_never_crossed`
(`crates/dwkd-authority/tests/resource_workspace.rs`) starts itself in a
user and mount namespace of its own, bind-mounts a directory from outside a
workspace onto one inside it on the same filesystem, and requires
`MOUNT_CROSSING` at the mount point and beneath it from the production
resolution path; `make namespace-evidence` now requires its case line
beside the broker's nine markers (5 tests, 10 markers). Exercised on WSL2
on 2026-11-23, with the mutant that drops `RESOLVE_NO_XDEV` killed; hosted
from the first `sandbox-egress` run after the commit. The casefold case
stays NOT EXERCISED: WSL2's kernel has no Unicode casefolding, and no
hosted job makes a casefold filesystem
([M6_PREPARATION_HANDOFF.md](M6_PREPARATION_HANDOFF.md) §G has the plan).
