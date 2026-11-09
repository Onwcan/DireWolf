# M5e.2 closure assessment and independent review handoff

> **Superseded as a status (2026-11-09).** This review is a snapshot of
> 2026-11-03 and is kept as written; its verdict below — E6 BLOCKED, 0 of 15,
> M5e.2 in progress — was true then and is not now. Since: E6 was authorised
> (2026-11-08), built ([ADR-0058](adr/0058-m5e-proxy-only-hard-rules-weakened-in-a-real-environment.md)),
> run hosted, its finding F-E6-HOSTNET fixed
> ([ADR-0059](adr/0059-m5e-proxy-only-peer-joins-only-its-own-network-namespace.md)),
> and passed at `14405ab` in hosted run
> [42525106398](https://github.com/Onwcan/DireWolf/actions/runs/42525106398):
> all fifteen rows, sixteen weakened cases and the control, at `real-oci`.
> ADR-0059 and ADR-0058 were accepted on 2026-11-09, ADR-0057 superseded by
> ADR-0058 and never accepted, and R3 and M5e.2 closed: **M5e.2 is
> COMPLETE**. Where M5e stands now is the
> [M5e plan](M5E_ASSURANCE_PLAN.md)'s latest status and the
> [ROADMAP](ROADMAP.md)'s M5e section.

Initial review and external-source snapshot: 2026-11-02. Final reconciliation:
2026-11-03. This assesses an uncommitted working tree; it is not an acceptance
decision or real-container E6 evidence.

## Verdict and baseline

**PARTIALLY COMPLETE**. The two independently reproduced defects found in
this review are fixed locally, and both ordinary test halves subsequently
passed. The first broad run's HTTP worker test timeout still lacks a causal
explanation; full evaluation/hosted validation remains limited as recorded
below. E6 remains **BLOCKED**: required 15, implemented 0,
exercised 0, passed 0, blocked 15. M5e.2 remains **IN PROGRESS**;
M5e.3–M5e.6 remain **NOT STARTED**.

The authoritative repository started clean on `main`, HEAD
`4101ce554e9df27a35b2cdd2010815fd85a287f2`, tracking `origin/main` with
zero ahead/behind. No initial staged, unstaged or untracked files were
reported. HEAD, branch and index are preserved. Changes in this review are
unstaged and uncommitted; the owner controls publication and acceptance.
Final status: six tracked files modified, two new files untracked, no staged
changes. The complete eight-file inventory is below. Logs and the final
SHA-256 manifest remain ignored under `target/m5e2-final-review/`.

The contract read for this review comprises README, CONTRIBUTING, ROADMAP,
M5E_ASSURANCE_PLAN (including §3b), SANDBOX, SECURITY, THREAT_MODEL,
ARCHITECTURE, COMPETITIVE_ANALYSIS, ADR-0047/0048/0052/0056/0057, the R3
closure and attribution architecture tests, and the relevant production and
evidence paths in `scripts/dw.py` and the Rust suites. Accepted ADRs, their
digest, evaluation baselines, CI requirements and evidence levels are unchanged.

## Issue #19: what is still missing

[Issue #19](https://github.com/Onwcan/DireWolf/issues/19) was read in full:
OPEN, zero comments. Its body still cites hosted run #121; the actual newer
baseline is [run #122](https://github.com/Onwcan/DireWolf/actions/runs/41477576755),
independently read as completed/success, attempt 1, `main`, the exact HEAD
above, 29/29 jobs successful. This review did not publish an issue update.
Historical hosted success applies to that committed baseline, not these fixes.
Read-only reconciliation on 2026-11-03 again found Issue #19 OPEN with zero
comments and run #122 still the latest run, successful at the same SHA.

Every unchecked acceptance and closure item in the issue remains unchecked:

| Requirement | Actual status |
|---|---|
| Written authorization within the existing safety control; isolated disposable environment | No qualifying plan or laboratory engagement supplied/found |
| Exact revision, probe/relay hashes, runtime/API/OS/architecture/client identity | Available for supporting runs; no qualifying E6 run |
| Unedited broker-used runtime records and original probe observations with SHA-256 | No E6 bundle found |
| Required host/container vantage attribution | Supporting E1–E5 only; missing under each real hard-rule weakening in `PROXY_ONLY` |
| Genuine `PROXY_ONLY`, including topology-specific invariants and interactions | Clean/topology cases exist; missing in E6's arrangement |
| Exactly one targeted hard rule per record; all expected and additional failed invariants | No qualifying record for any of 15 rows |
| Production measurement and refusal; never retained READY | No E6 observation; a startup error or edited-record judgement cannot qualify |
| Exact ownership cleanup; complete before/after resource census | Supporting runs have their own cleanup; no E6 census |
| All 15 records complete, readable and exercised | 0/15 |
| Digested raw evidence/logs and reproducible execution provenance | No E6 manifest or run reference |
| Owner evidence review, accepted successor ADR superseding ADR-0057 | Not performed; ADR-0057 remains Proposed, outside accepted digest |
| Applicable hosted validation on the relevant committed revision | #122 verifies the baseline; these uncommitted fixes need later hosted verification |
| Explicit owner decision on R3 and milestone completion | Not made; R-B remains binding |

The governing sources are [assurance plan §3a–§3b](M5E_ASSURANCE_PLAN.md#3b-what-genuine-e6-evidence-must-carry-an-acceptance-specification-not-a-procedure)
and [ADR-0057 §8](adr/0057-m5e-proxy-only-real-container-evidence-residual.md).
No acceptance wording is amended by this assessment.

## Evidence search and qualification

The parent project directory was inspected read-only. The search covered
visible and hidden nondependency files, historical worktree owner handoffs,
log/JSONL/text/digest/archive candidates, and relevant record/census/evidence
names in the authoritative repository's `target`. Git object stores,
virtual environments and ordinary compiled binary contents were excluded.
No qualifying bundle was found in this scope; this is not a claim about
every arbitrary byte on the machine. Nothing from the parent was imported,
overwritten, removed or relocated.

The historical `owner-handoff/r3-e6` patch represents `e746aeeb09282b7757e7c606c57355ed99055ebf`'s
attribution/governance work. Its message explicitly says no weakened real
`PROXY_ONLY` container was built, planned or run. The suggestive directory
name is not evidence. Reviewed byte identifiers:

| Historical file | SHA-256 |
|---|---|
| `r3-e6/r3-e6.patch` | `6b3b8f3f0da61ffc8109410ad479632e1971d427d6bcddddd17d898ce7225bc` |
| `r3-e6/msg.txt` | `a0bf251c4961d46c7c28310b3489725b29d299b60c762b3922c6f2371ce9913a` |

Timestamps and hashes identify local bytes, not an authenticated execution.
Other handoffs describe already known F-RELAY/F-EVICT/F-TEARDOWN/F-ABSENT/G2
or documentation work. Existing eval JSONL and dependency exports are not
E6 runtime/probe records.

GitHub artifact listings for runs
[#114](https://github.com/Onwcan/DireWolf/actions/runs/41242001763),
[#116](https://github.com/Onwcan/DireWolf/actions/runs/41323258812) and
[#122](https://github.com/Onwcan/DireWolf/actions/runs/41477576755) returned
empty artifact arrays. This establishes no retained downloads at those
endpoints; it does not establish that their tests never ran. No archive was
downloaded. Actual #122 job logs were read through the GitHub connector:

| Job | Observed attributed records |
|---|---|
| [Foundation](https://github.com/Onwcan/DireWolf/actions/runs/41477576755/job/125387103261) | 109 `real-oci` (92 broker, 17 authority); 20 `in-process` broker judgements |
| [Egress](https://github.com/Onwcan/DireWolf/actions/runs/41477576755/job/125387103193) | 104 `real-oci` (96 broker, 8 authority); 19 `in-process` captured-record judgements |

Foundation's `detected-15-of-15` concerns `NO_NETWORK`. Captured hard-rule
changes explicitly remain `in-process`. Foundation records no remaining
evidence container; egress records no remaining evidence container/network,
with its three pre-existing networks preserved. Supporting runtime: Docker
29.4.2, API 1.54, linux/amd64. Supporting probe SHA-256:
`97ec0339188866f3e145afdd7ef9d89829fffc3e7c158f72b3f4ceb4aa28d1c1`;
relay SHA-256:
`6af8e50f6f5a463eb8eb51547aec12e2728de55d61b6403b112a021c7b39df87`.
These are hosted supporting-run identifiers, not pins or evidence for a new E6 run.

## Alternative paths: decision matrix

The two tables share candidate IDs; together they cover observation,
requirements, authority, safety, provenance, complexity, privilege,
executability, qualification and recommendation. A conditional possibility is
not present authorization. No experimental procedure or bypass is provided.

| ID / candidate | Actual observation; possible E6 coverage | Still missing | Required authorization / safety compatibility | Executable now / qualifies now |
|---|---|---|---|---|
| A: Existing local/hosted records | Historical code and E1–E5/U4 results; authentic previously overlooked E6 could in principle be qualified | No qualifying E6 records found | Read-only qualification already authorized and completed | Review yes; E6 no |
| B: Strict-production measurements and historical E1/E2 | Clean real `PROXY_ONLY`, relay and topology observations | Individual real hard-rule failures, U1–U3, all 15 refusal bundles | Read existing records; any new execution must exclude real weakening/mutation cases under this prompt's blanket restriction | Read-only review and clean permitted checks yes; full E2 mutation target no; E6 no |
| C: Deterministic/differential/metamorphic validation | Production judgement of bounded record changes; plan/measurement consistency, fail-closed negative controls | Actual runtime/kernel behaviour and inside vantage under each weakening | Safe in-process work authorized; no forged live evidence | Yes; E6 no |
| D: Independently authorized security laboratory | Could produce all 15 authentic observation/refusal/cleanup bundles | Approved compatible engagement, resources, original records and review | Owner-approved engagement within the existing control plus laboratory's approved scope; isolation alone grants no permission | No dependent experiment now; potentially qualifies after authorization and full qualification |
| E: Separately authorized disposable CI/lab | Could produce the same complete observation set on an exact revision | Compatible authorization, dedicated runner and evidence implementation, records, applicable hosted gates | Explicit approval within existing stop before dependent work; never ordinary developer daemon | No now; potentially qualifies later |
| F: Previously occurring natural runtime drift | Only the particular authentic observation actually preserved | No qualifying artifact found; typically missing one-rule isolation, disposable scope, raw probe/census and never-READY proof | Lawful authorized original scope and owner review mandatory; do not induce drift | Retrospective read only; none qualifies now |
| G: Alternate runtime/client/plugin or pre-seeded weakened container to reach the broker | Would recreate the stopped experiment under another entry path | Authorization; cannot substitute a different arrangement or fake runtime | Prohibited as a workaround under present control; no implementation | No; invalid now |
| H: Relabel E3/E4/E5, change profile/contract, accept ADR-0057's residual | Changes a label or claim, not observation | Original E6 contract still unmet | Conflicts with R-B; rejected | No; never qualifies under current R-B |

| ID | Provenance / reproducibility | Engineering complexity | Privileged-resource dependence | Recommendation and justification |
|---|---|---|---|---|
| A | Pins/logs can be checked; hashes alone cannot prove a run | Low for qualification | None for read-only review | Completed; retain actual evidence levels |
| B | Existing exact-source harness and runtime/probe attribution | Existing harness; carefully inspect transitive task selection | Real OCI socket is root-equivalent; obey the user's restrictions and each suite's limits | Retain actual supporting evidence; do not infer that an existing mutation suite is authorized merely because CI ran it |
| C | Deterministic existing harness, exact fail-before/after and same inputs | Low for focused defects; a full model would be larger | None; temporary Unix sockets only for new lifecycle regression | Completed focused fixes below; broader formal work cannot waive E6 |
| D | Exact committed source/build pins, raw originals, custody manifest, lab reference and independent replay review | Medium/high, contingent on scope approval | Laboratory-controlled isolated OCI privileges | Preferred evidence candidate: independently attributable qualification and dedicated isolation; no claimed lab selected or accredited |
| E | Exact committed source, pinned environment, retained raw observations and run URL | High; evidence work remains unbuilt | Dedicated disposable runner; privileges only in approved scope | Viable alternative after authorization; do not edit CI now |
| F | Only preserved originals count; incident summaries insufficient | Unpredictable qualification effort | Read-only review needs none; original execution scope must qualify | Assess any later supplied bundle strictly; no assumption of complete coverage |
| G | A wrapper/fake/edited record is weaker evidence; a genuine alternate arrangement still requires approval | High and unjustified now | Same root-equivalent privileges; relocation does not remove risk | Reject present workaround; an independently approved future design must meet every unchanged criterion |
| H | No authentic observation to reproduce | Irrelevant | Irrelevant | Reject; changing language cannot resolve U1–U3 |

### Architecture conclusion

The production plan contains typed constants, no caller-provided weakening
flags. Docker inspection supplies the trusted runtime's record; the pinned
probe supplies kernel observations from inside. The relay adds a shared
network namespace, setup lifecycle, exact helper ownership and a separately
protected proxy socket. `oci::clean` requires all required invariants, and
the broker refuses/removes a non-clean preparation before the authority can
retain READY. Reconciliation and exact labels bound cleanup; they do not
make a historical record a new measurement.

Shared validation code proves a useful relationship between topologies but
does not observe the missing runtime behaviour. ADR-0057's **U1** (real
weakened runtime record), **U2** (inside vantage under that weakening), and
**U3** (interaction with relay/topology invariants) remain unresolved. U4 is
closed only in process. No existing authorized architecture path was found
that produces all required E6 observations while avoiding the stopped
experiment. Changing the client, using another OCI implementation, observing
a deliberately pre-seeded container, or moving to a disposable runner does
not itself authorize that experiment.

### Independent laboratory qualification, before any dependent experiment

The owner must identify the authority governing the stop and approve a
compatible engagement within it. The laboratory needs demonstrated OCI,
namespace, network and evidence-handling competence; the contract mandates
no named accreditation. Its own approved scope must cover the unchanged
15-row contract and dedicated isolated disposable resources, with no
unrelated workload or credential exposure.

The engagement must require exact committed revision/build provenance,
runtime/API/client identification, agreement between built and measured
probe/relay digests, raw immutable originals and SHA-256 manifest, actual
production measurement/refusal and never-READY proof, all changed
invariants, exact ownership cleanup and complete pre/post census. A signature
can strengthen custody but cannot authenticate synthetic observations by
itself. Independently qualify every §3b field; reject incomplete rows
without partial E6 credit. Keep confidential originals private and use only
owner-approved safe review copies; redaction cannot silently replace the
original evidence the reviewer must authenticate.

External results require owner review and an accepted successor ADR
superseding ADR-0057; they are never silently imported into mandatory CI.
No laboratory has been engaged, and no E6 procedure or harness is built here.

## Competitor source research: ideas, limitations, independent design

Research used individual public files through GitHub only. No competitor
repository was cloned, forked, mirrored, archived, vendored or downloaded;
no implementation, fixture, test body, comment or configuration was copied
into DireWolf. Existing COMPETITIVE_ANALYSIS was read for taxonomy, method,
containment evidence and design lessons. Relevant heads were re-resolved on
the review date; conclusions below concern these specific pinned files,
not an exhaustive audit or another project's test results.

| Project / pinned SHA | Specific primary source | Observed behaviour | Applicability, limits and independent DireWolf approach |
|---|---|---|---|
| IronSecCo/ironclaw `843b0e37ca49a31c36cb6af83bd912bd12ca2f39` | [containment workflow](https://github.com/IronSecCo/ironclaw/blob/843b0e37ca49a31c36cb6af83bd912bd12ca2f39/.github/workflows/sandbox-containment.yml) | Paired containment and deliberate network-negative-control phases; missing Docker self-skips; comments describe additive non-required status | A negative control must fail for its intended defect. DireWolf keeps NOT EXERCISED failing required gates; any nonzero infrastructure failure is insufficient proof of the target regression. This is no authorization to reproduce their experiment |
| IronSecCo/ironclaw, same SHA | [escape harness](https://github.com/IronSecCo/ironclaw/blob/843b0e37ca49a31c36cb6af83bd912bd12ca2f39/examples/red-team-escape/run.sh) | Observations taken inside a live sandbox; optional versioned report includes runtime/image/commit metadata before final verdict | Useful distinction between observation, metadata and verdict. An independent DireWolf bundle must additionally retain the actual broker-used record, pinned probe bytes, all 15 row failures, refusal/never-READY and census; a report alone is insufficient |
| jersonboydmilan/Capgate `df8d1929b4ad7d75a505bd43385557f57ec5ff3b` | [network boundary tests](https://github.com/jersonboydmilan/Capgate/blob/df8d1929b4ad7d75a505bd43385557f57ec5ff3b/tests/adversarial/isolation/test_network_boundary.py) | Combines agent-side observations with tool ledger/audit ground truth; requires selected check groups to be nonempty | Independent observation channels and non-vacuity are useful. DireWolf's distinct host/probe/production-decision/census records must agree; the new lifecycle test independently checks socket path, neighbour identity, response and proxy registry |
| Capgate, same SHA | [runtime tests](https://github.com/jersonboydmilan/Capgate/blob/df8d1929b4ad7d75a505bd43385557f57ec5ff3b/tests/adversarial/isolation/test_gvisor_runtime.py), [CI](https://github.com/jersonboydmilan/Capgate/blob/df8d1929b4ad7d75a505bd43385557f57ec5ff3b/.github/workflows/ci.yml) | Runtime test checks guest kernel identity and repeats boundary checks; skips if Docker/runsc absent; heavy CI paths are dispatch/schedule conditional | Do not infer runtime identity from a desired setting. Different isolation mechanisms are not equivalent evidence. DireWolf would verify exact runtime/probe pins and fail absent required evidence; adopting gVisor would neither supply current E6 nor be an authorized dependency change |
| nearai/ironclaw `b0b999d96781516ee05e6ba961d6f3ead900da96` | [network allowlist source](https://github.com/nearai/ironclaw/blob/b0b999d96781516ee05e6ba961d6f3ead900da96/crates/lanes/ironclaw_sandbox/src/sandbox_process/network_allowlist.rs) | Defaults and operator additions use the same hostname validator; malformed configuration fails construction; source rejects a retired byte-ceiling setting its opaque path cannot guarantee | Preserve agreement between requested controls and observed guarantees. DireWolf independently checks its own exact grants and actual tunnel budgets; its evidence must never advertise a guarantee or evidence level the observation does not earn |

The last NEAR AI SHA equals the older documented snapshot; it was actually
re-resolved, not assumed current. IronSecCo and Capgate heads differ from
the old snapshot. No project supplies DireWolf evidence. Research on the
remaining listed products was limited to the existing comparison because
their unrelated features offer no identified way to resolve R3's missing
observation without the same authorization.

## Engineering changes and adversarial reproductions

Complete review-file inventory (all unstaged; new files untracked):

| File | Change |
|---|---|
| `architecture.toml` | Register the new `cfg(test)` fixture module's exact path under TX015, consistent with existing fixture exemptions; no production pattern or exemption changed |
| `crates/dwkd-broker/src/sandbox/inspect.rs` | Two relay propagation comparisons |
| `crates/dwkd-broker/src/sandbox/inspect_tests.rs` | Independent requested/effective propagation regression |
| `crates/dwkd-broker/src/sandbox/mod.rs` | Unconditional authorized proxy closure and test-module registration |
| `crates/dwkd-broker/src/sandbox/destroy_tests.rs` (new) | Early-refusal proxy lifecycle regression |
| `docs/M5E_ASSURANCE_PLAN.md` | Record the new local findings and link this assessment, preserving E6 status |
| `docs/M5E2_FINAL_CLOSURE_REVIEW.md` (new) | This review and handoff |
| `tests/architecture/test_m5e_r3_closure.py` | Include this new status document in the existing guard against false milestone-completion claims |

The review traced `inspect`, `plan`, `relay_plan`, `oci`, `mod`, `supervisor`,
workload preparation/execution/collection, authority environment reconciliation,
the probe reports and required evidence-task attribution/census paths. This
was a source and focused regression review, not an exhaustive proof of every
possible runtime failure. No new reproducible failure was established in the
previously fixed F-R8/F-RELAY/F-EVICT/F-TEARDOWN/F-ABSENT/G2 findings.

### F-RELPROP: relay bind propagation was not measured

The relay plan explicitly requests `bind-propagation=rprivate`. Its host
validation checked mount source, target, type and read-only status but
ignored both effective `Mounts[].Propagation` and requested
`HostConfig.Mounts[].BindOptions.Propagation`. A record with either side
changed to shared/slave propagation, or missing/malformed, still passed
the relay's exactness check. This is distinct from the previously fixed
relay cgroup/UTS/swap findings.

The fix adds two exact `rprivate` comparisons in `inspect::relay_exact`.
Every mismatch/missing/malformed value now refuses that relay check. The
regression varies each requested/effective propagation field independently, retaining
the other conforming side: 20 formerly accepted invalid cases and two
conforming controls. This is host-record validation **in process**, not
a live mount propagation experiment or E6. It reconciles measurement with
the existing private mount plan; it adds no profile parameter or new invariant.

### F-PROXY-CLOSE: early runtime refusal left the proxy open

`Sandbox::destroy` previously closed the proxy only inside `with_oci`'s
callback. Runtime re-proof can refuse before invoking that callback, leaving
the environment's proxy/listener usable although destruction was requested.
ADR-0048 §10 requires closing the listener regardless of what runtime
removal accomplished. The authority's correct retention of DESTROYING did
not itself close the broker's listener.

The fix closes the authorized environment's proxy outside the callback,
after the attempted destruction, preserving the original Refused or
Indeterminate result and attaching counters only to a Done answer. It does
not claim the container is gone, clear pending destruction, or touch another
environment. The Linux in-process regression uses actual temporary proxy
sockets and empty grants: identity mismatch, digest mismatch and unsupported
profile-path refusal occur before any runtime client launches. It checks
target closure, original refusal, exact remaining registry, unchanged
neighbour socket identity and a working neighbour rejection response.

Accounting limitation: Refused/Indeterminate destruction responses cannot
carry the closed proxy's counter snapshot. Closing removes that proxy, so a
later successful retry has no snapshot to return. Late runtime-error paths
already had this limitation; this fix prioritizes the required immediate
egress closure on early refusal too. The new regression uses empty grants
and proves no traffic-counter recovery or final audit-accounting completeness.
No wire-contract expansion or counter-persistence mechanism is introduced.

| Change review question | Answer |
|---|---|
| Requirement / insufficiency | Exact relay mount plan must be measured; destruction must end its egress even when runtime verification fails |
| Concrete reproduction | Original relay validator accepts 20 invalid records; original destroy leaves its real test proxy open on early refusal |
| Why correct | Compare both actual/requested propagation with the existing plan; move proxy close beyond the fallible callback admission |
| Regression / negative control | New regressions fail with original production behavior and pass with fixes; no synthetic result is represented as OCI evidence |
| Accepted security contract changed? | No; implementation conforms more closely to the existing plan/lifecycle contract |
| E6 level or 15-row matrix changed? | No |
| Necessary for closure? | Sound relay measurement and unconditional egress teardown are prerequisites to trustworthy refusal/cleanup. Neither fix suffices for closure |
| New dependency / abstraction / authority route? | None |

## E6 coverage: every required hard rule

In this table E3 means real `NO_NETWORK` observations; E4 means edited
captured `PROXY_ONLY` records judged in process; E5 means handwritten records
judged in process. `…` abbreviates `proxy-only-weakened-`; E4 uses its
`captured-` counterpart. E1 clean `PROXY_ONLY` supports every row without
exercising its weakening. The actual evidence levels are E3 `real-oci` and
E4/E5 `in-process`, never E6. Every row lacks the complete authorized raw
runtime/probe/production-refusal/never-READY/cleanup/provenance bundle.

| Requirement | Required vantage | Actual supporting sources | Genuine E6 | Result / missing |
|---|---|---|---|---|
| Read-only root | Both | E3 `weakened-writable-root`; E4/E5 `…writable-root-refused` | No | BLOCKED / bundle absent |
| Non-root user | Both | E3 `weakened-root-user`; E4/E5 `…root-user-refused` | No | BLOCKED / bundle absent |
| Not privileged | Both | E3 `weakened-privileged`; E4/E5 `…privileged-refused` | No | BLOCKED / bundle absent |
| No runtime socket | Both | E3 `weakened-runtime-socket-mounted`; E4/E5 corresponding refusal | No | BLOCKED / bundle absent |
| Capabilities dropped | Both | E3 `weakened-capability-added`; E4/E5 corresponding refusal | No | BLOCKED / bundle absent |
| No-new-privileges | Both | E3 `weakened-no-new-privileges-disabled`; E4/E5 corresponding refusal | No | BLOCKED / bundle absent |
| Pinned seccomp, not unconfined | Both | E3 `weakened-seccomp-unconfined`; E4/E5 corresponding refusal | No | BLOCKED / bundle absent |
| Pinned seccomp, not runtime default | Both | E3 `weakened-seccomp-default-profile`; E4/E5 U4 refusal | No | BLOCKED / bundle absent |
| Private PID namespace | Both | E3 `weakened-host-pid`; E4/E5 corresponding refusal | No | BLOCKED / bundle absent |
| Private IPC namespace | Host | E3 `weakened-host-ipc`; E4/E5 corresponding refusal | No | BLOCKED / bundle absent |
| Private UTS namespace | Host | E3 `weakened-host-uts`; E4/E5 corresponding refusal | No | BLOCKED / bundle absent |
| Isolated network | Both | E3 `weakened-host-network`; E4/E5 corresponding refusal; real E1/E2 network cases | No | BLOCKED / bundle and weakening/topology interaction absent |
| Digest-pinned image | Host | E3 `weakened-mutable-image-tag`; E4/E5 corresponding refusal | No | BLOCKED / bundle absent |
| No additional devices | Both | E3 `weakened-extra-device`; E4/E5 corresponding refusal | No | BLOCKED / bundle absent |
| Resource limits, including 8,192 task backstop | Both | E3 dropped limits/pids drift; E4/E5 pids, swap and combined U4 refusals; E4 task-backstop-at-256 | No | BLOCKED / bundle and required limit failures absent |

Exact required failing invariants remain those in ADR-0057 §1a and assurance
plan §3a. Extra topology changes must also be reported, not hidden to force
an exact-looking result. Totals remain **15 / 0 / 0 / 0 / 15**.

## Verification report

No privileged or hosted-only result is inferred from a unit-test pass.

Environment: existing Ubuntu WSL tooling, repository-pinned Rust 1.98.1,
locked Python 3.12 virtual environment and uv 0.12.5. Commands used
`CARGO_NET_OFFLINE=true`, `UV_OFFLINE=1`, `UV_NO_SYNC=1`, with existing Cargo/uv
on PATH; no developer dependency synchronization or tool installation ran.
Canonical tasks were invoked through `make`; after diagnosing the launch
prerequisites, its two unchanged test commands were also run separately.
No test semantics were reimplemented by the local entry-process wrappers.

| Canonical check | Actual result |
|---|---|
| `make fmt-check` | PASS |
| `make lint` | PASS |
| `make typecheck` | PASS: 92 source files |
| `make arch` | Initial FAIL: new test fixture not registered for TX015; final PASS including exact dependency closure |
| `make schema-check` | PASS: 61 generated files and 5 generated Python modules match |
| `make docs` | PASS; final reconciliation checked again in `docs-final.log` |
| `make test` | Initial FAIL in existing HTTP credential worker-crash observation; second FAIL in the existing execute-only-image hardening test; both stopped before the Python phase |
| Canonical Rust half, `cargo test --workspace`, fresh native target and clean entry descriptors | PASS, exit 0: 1,417 passed, 0 failed, 110 ignored across 75 result summaries, including doctests |
| Canonical Python half, `uv run --frozen python -m pytest` | PASS: 1,325 passed, 1 platform-specific skip; 3,557.71 seconds |
| `make eval-check` | NOT COMPLETED: intentionally terminated (143) after inspection showed real sandbox campaigns are transitively selected; no overall PASS claimed |
| Official eval CLI, `check --suite protocol-security --suite protocol-compat --suite harness-selftest` | PASS: 12 passed, 0 failed/error/pending/skipped/not-exercised; original baseline unchanged |
| `make security` | PASS: root/fuzz cargo-deny checks and pip-audit, no known vulnerabilities reported |
| `make sandbox-egress-evidence` | PASS technically: 104 real-OCI + 19 in-process records; execution scope error described below; not E6 |
| R3 closure/attribution pytest subset | PASS: 52 tests, including the new report's status guard |

The egress task used Docker 29.9.2, API 1.56, linux/amd64; its static probe
SHA-256 was `83abb3e37780a061dfb20bb695b1fd2acb61d58d9973999647ba31e5e13defe9`,
relay SHA-256 `dcf56eac8dc30f557ad14c4e5ef9e8027fe6bb49c902464265d6c1a5fa54512c`.
The actual dirty-tree broker accepted conforming relay records with the added
checks. Existing successful-destruction closure/counter cases passed too.
The task's complete census retained four pre-existing containers and three
networks, leaving no evidence container/network. This is supporting
integration evidence on the uncommitted diff, not evidence on a future commit.

The original `make test` failure was
`linux::a_credential_hop_whose_worker_dies_is_unknown_and_leaves_the_broker_clean`:
its observer timed out after 30 seconds (`a worker holds the hop`). The test
joins that observer before examining the request outcome, so the saved
failure lacks the diagnostic needed to distinguish a missing worker from
a pre-worker refusal. Read-only tracing establishes that this HTTP dispatch
does not call the changed sandbox lifecycle/measurement functions.

One isolated diagnostic run of that same test passed all its original
assertions (1 passed, 6 filtered; 4.37 seconds). A private observer recorded
only process IDs/parent IDs/states, command-line readability and boolean
argument presence, with no raw command lines, credentials or payloads. The
worker remained observable after hardening, refuting the initial hypothesis
that nondumpability hid its command line. Possible pre-worker failures
include credential lookup, worker-policy admission, framing/dialing and
worker spawn/vouching; none can be selected as the original cause from
the retained failure. Concurrent load is not established as causal.
The original FAIL remains a review finding even if later validation passes.

The second full `make test` run passed that HTTP credential-worker case but
failed `http::tests::hardening::an_image_its_uid_cannot_read_starts_its_worker_closed_to_that_uid`
at `hardening_tests.rs:367`: a fixture chmodded to 0111 remained readable.
That test places its copy next to the broker binary in `target/debug`,
which here is on a 9p/DrvFS mount without Linux metadata permission
semantics. Its broker unit binary reported 233 passed, 1 failed, 6 ignored.
A task-owned plain-file probe confirmed requested 0111 becomes readable
0555 there, whereas the identical `/tmp` fixture stays 0111 and returns
EACCES. An existing ext4 Cargo cache was used to rebuild the current broker,
without moving or changing the working tree.

The first native exact check reached the correct kernel memory denials but
the worker refused self-hardening (exit 3). Its WSL entry process inherited
nonstandard terminal descriptors 7 and 10, which the worker correctly
refuses (`process/fdcheck.rs` explicitly documents this prerequisite).
Launching the existing Cargo command with Python's `subprocess.run` and
`close_fds=True`, retaining standard streams, corrected the test entry
environment. The unchanged exact test then **passed** (1 passed, 239
filtered), including its original ready/at-exec/exit and kernel-denial
assertions. No test or worker assertion was removed, bypassed or weakened.
This is a test-launch correction, not a container experiment or alternate
authority path. The original HTTP timeout lacks a retained descriptor
census, so these findings do not establish its cause.

A first full Rust attempt in the existing native cache failed because a
reused protocol test artifact had a historical, missing checkout path baked
into `CARGO_MANIFEST_DIR` (five canonical tests passed, one could not read
its fixture). That result was rejected as validation of the present source.
No cache or source was deleted to make it pass.

The final Rust run used a verified absent, freshly created native target
directory, seeded with **no compiled artifacts**, offline locked dependencies,
and `close_fds=True`. It first built the current broker, then executed the
exact canonical Rust command `cargo test --workspace`. Its exit code is 0:
**1,417 passed, 0 failed, 110 ignored**, across 75 result summaries. The
broker unit binary passed 234 tests with 6 ignored; the authority unit binary
passed 419 with 1 ignored. Both earlier failing tests passed unchanged in
this full run. The retained summary names every binary and result.

The 110 ignored tests are ordinary-run exclusions, not 110 newly missing
acceptance rows. They include separately invoked OCI/identity/privileged,
benchmark/evidence cases, auxiliary child entrypoints and a documentation
example; passing parent tests explicitly invoke some child entrypoints with
`--ignored`. Only an actual dedicated campaign can establish its own
evidence coverage.

The full Python command completed independently: **1,325 passed, 1 skipped**.
Its sole skip is `evals/tests/test_process_and_inventory.py:90`, which tests
the unsupported path available only off POSIX. The hour-long run was retained
without excluding slow architecture tests or relaxing assertions.

These are successful executions of both canonical test halves under their
stated prerequisites. The two earlier `make test` invocations remain FAIL;
no successful combined `make test` invocation or full CI result is invented.

NOT EXERCISED in this session: genuine E6 (compatible authorization and all
raw records missing); hosted restart/capacity campaigns (disposable authorized
runner required); privileged workspace/agent halves (separate identities,
provisioned filesystem and hosted authorization required); other sandbox
hard-rule or source-mutation campaigns (outside the safe selection made
after the scope error); strict full hosted eval/CI on a committed revision.
No skipped unit test is promoted to an exercised containment result.

Focused checks already executed:

| Check | Actual result |
|---|---|
| Propagation regression against original production validator | Expected FAIL: one test failed, 20 independently listed false acceptances; both conforming controls matched |
| Inspection suite after fix | PASS: 14 passed, 1 pre-existing captured-record test ignored pending real egress setup |
| Proxy-close regression against original destroy behavior | Expected FAIL: one test failed on `IdentityMismatch: destruction left its proxy open` |
| Proxy-close regression after fix | PASS: one test, all three early-refusal variants and neighbour checks |
| Broker sandbox unit subset | PASS: 53 passed, 1 pre-existing captured-record test ignored |
| Broker all-target Clippy with warnings denied | PASS after correcting the new test's initial function-length/format findings |
| Owned-file rustfmt; `git diff --check` | PASS |

The initial canonical architecture check failed on five TX015 matches in the
new fixture file, whose test-only filesystem setup had not been registered.
The exact-file fixture registration above addresses that finding without
changing the production rule. The initial log is retained separately.

One exploratory lifecycle test command selected zero tests because `--exact`
was paired with an unqualified name; it is not evidence. The corrected
command actually ran and failed the regression. The propagation before-run
wrapper had a subsequent exit-value parsing error; the saved Rust panic and
one-failed-test summary, not that wrapper's status, establish the reproduction.

Focused commands, under the existing pinned WSL toolchain:

```text
cargo test --locked -p dwkd-broker --bin dwkd-broker sandbox::inspect::tests::the_relays_requested_and_effective_mount_propagation_must_be_recursive_private -- --exact --nocapture
cargo test --locked -p dwkd-broker --bin dwkd-broker sandbox::inspect::tests -- --nocapture
cargo test --locked -p dwkd-broker --bin dwkd-broker sandbox::destroy_tests::destruction_closes_only_its_proxy_even_when_the_runtime_cannot_be_reproved -- --exact --nocapture
cargo test --locked -p dwkd-broker --bin dwkd-broker sandbox::
cargo clippy --locked -p dwkd-broker --all-targets -- -D warnings
```

Local logs remain ignored under `target/m5e2-final-review/`, including the
two before-run logs. SHA-256 identifiers for those before-run bytes:

| Log | SHA-256 |
|---|---|
| `relay-propagation-before.log` | `36bfb906bd3164a3c3f30818b35ef6449d72a5e2fb2499766c93a9c97a229a1d` |
| `proxy-close-before.log` | `67e8d2f3f55b3c66bf24c264496d99af6d7103268a0c41841a7e034deaf861d7` |

These identify session regression logs; they are not signed attestations or
E6 authenticity claims. The report/manifest identifies the final dirty-tree
revision; HEAD alone does not identify these uncommitted fixes.
`review-manifest.sha256` covers the eight review files, tracked diff and
retained local logs/diagnostics. A separate baseline/status record identifies
HEAD and the unchanged index. The manifest is local review integrity data,
not a laboratory attestation or E6 qualification.

## Safety, governance and owner decisions

**Execution-scope error:** the full existing `sandbox-egress-evidence` target
was selected for runtime-serialization compatibility. It also executes E2's
real weakened/drifted topology cases (including bridge networking, missing
relay/proxy variables and topology drift). The user's blanket restriction on
weakened real `PROXY_ONLY` experiments called for a narrower selection.
This was acknowledged to the owner during the session. No further real
container mutation tests are to run under this authorization. The recorded
task passed its census: no evidence container/network remained and all four
pre-existing containers and three networks were retained. The scope error
is not erased by passing cleanup or by E2's historical CI status.

The stopped 15-row E6 hard-rule experiment, a bypass and an alternate
authorization route were not implemented. No E2 result counts as E6.
The full `eval-check` wrapper was intentionally stopped after source review
showed it transitively selects the real sandbox campaigns too; it is not a
passing gate. No developer daemon was restarted. No competitor code or
unapproved dependency was installed. No branch, index, commit, ref, PR or
issue was changed. Accepted ADRs/digests, CI requirements, evaluation
baselines and the 15-row E6 count are preserved.

R-B remains binding; R-A and R-C remain unselected. ADR-0057 must not be
accepted to waive the gap. A successor can be prepared only after authentic
qualifying evidence exists; acceptance and milestone closure are the owner's.

Ordered owner actions:

1. Independently review/falsify the unstaged fixes and their negative controls;
   investigate the unexplained broad-suite HTTP timeout and review the
   recorded validation scope error.
2. Decide whether to commit/publish the reviewed changes and obtain the full
   applicable hosted validation on that exact committed revision.
3. Identify the authority governing the stop and approve a compatible,
   non-operational laboratory engagement/scope or dedicated disposable
   evidence path. Preserve all 15 rows and §3b; do not treat this assessment
   as experimental authorization.
4. Only after those prerequisites, commission the separately authorized
   evidence work and retain authentic original observations with custody
   and digests. Qualify all 15 rows independently.
5. If the complete contract is actually satisfied, prepare and owner-review
   an evidence-backed successor ADR superseding ADR-0057, preserve applicable
   hosted obligations, then decide R3, M5e.2 and Issue #19 explicitly.
6. Until then keep Issue #19 OPEN, R3/E6 BLOCKED and M5e.2 IN PROGRESS.
   Do not start later dependent milestones.

### Copy-ready owner update (not published; not a closure comment)

> CI #122 independently verifies the baseline at
> `4101ce554e9df27a35b2cdd2010815fd85a287f2`, 29/29 jobs. Review found and
> locally fixed missing relay mount-propagation checks and proxy closure
> skipped by early runtime-verification refusal; deterministic regressions
> distinguish those fixes from containment evidence. These changes remain
> uncommitted and need independent review and later hosted verification.
> Both ordinary test halves passed with a fresh native build and correct
> entry descriptors. Initial failures and the overbroad E2 validation
> selection remain disclosed in the review; the original HTTP timeout's
> cause is unresolved.
> No qualifying E6 bundle was found in the inspected local/hosted sources.
> All 15 rows remain BLOCKED. The next dependency is written authorization
> for an isolated evidence path within the existing safety control, followed
> by complete §3b qualification and owner ADR/milestone decisions. Issue #19
> remains OPEN; M5e.2 remains IN PROGRESS.

## Independent review handoff

Claude Opus 5.5 Extra High UltraCode should begin from the exact baseline
above and the unstaged diff, including untracked new files. Attempt to
disprove the following claims:

1. Every non-`rprivate`, missing or malformed requested/effective relay
   propagation field is rejected independently; conforming runtime records
   still pass. Check actual runtime serialization compatibility.
2. Every early runtime-verification refusal closes exactly its authorized
   proxy; neighbour sockets/grants remain usable and unchanged. Inspect
   errors, absent proxies, counters and Indeterminate teardown responses.
3. The fixes preserve authority ownership, pending-destruction state,
   original failure reasons, fail-closed handling and all accepted contracts.
4. The regressions fail for original defective behavior rather than a test
   environment failure, timeout or zero-test selection. Inspect raw logs.
5. All hosted evidence cited really uses the stated topology, source,
   level and cleanup; no local unit result is being promoted to E6.
6. No qualifying E6 source was overlooked within the stated search scope;
   any later artifact must meet every §3b criterion, not merely a digest.

Unresolved uncertainties: the initial HTTP worker test timeout's cause and
test reliability; full evaluation/hosted validation under the applicable
authorization; U1–U3; authentic all-15 E6 records; the compatible
authorization path and lab operator; hosted results for this new revision;
the pre-existing absence of a real-runtime mid-operation communication-loss
campaign (not reproduced by any hosted job). No claim of deployment-scale
assurance is made. The runtime's truthful record and applicable deployment
identity/ownership prerequisites remain trusted assumptions. Passing these
local tests cannot guarantee the independent audit will pass.

## Suggested commit message (owner action only)

Subject:

```text
fix(sandbox): verify relay propagation and close refused teardown proxies
```

Body:

```text
Require recursive-private propagation in both requested and effective
relay bind-mount records. Reject missing and malformed propagation data.

Close an environment's proxy even when runtime re-verification refuses
before teardown starts, preserving the refusal and other environments.

Add deterministic fail-before regressions for both defects and record
the evidence search, alternative-path assessment and independent-review
handoff. Preserve the accepted contracts and existing evidence levels.

Record validation prerequisites, initial failures and the overbroad E2
validation selection without promoting supporting results to E6.

E6 remains blocked across all 15 required rows. M5e.2 remains in progress;
no ADR acceptance, hosted verification or issue closure is implied.
```
