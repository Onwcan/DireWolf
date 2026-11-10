# M5e.6 — the integrated M5 assurance gate: preparation handoff

**Project:** [DireWolf](https://github.com/Onwcan/DireWolf)\
**Prepared:** 2026-11-07, on `main` at `6a702d710a1750be656c698722825c3f89ad5304`\
**Status:** **PREPARATION ONLY.** The owner authorised preparing M5e.6 on 2026-11-07:
research, design, dependency analysis, test planning and this handoff. Implementation is not
authorised. No code, CI job, eval, baseline or milestone list changes with this document, and
it starts no step of M5e.6.\
**Status (2026-11-09):** **IN PROGRESS.** Implementation is authorised on §12's recommendations (G-D1 a separate `m5e-gate` job; G-D2 7 days; G-Q1 the four self-judging tasks by their own verdict; G-D3 neither M4 task in the gate) — [M5E_ASSURANCE_PLAN.md](M5E_ASSURANCE_PLAN.md) §10, "M5e.6's implementation". G1 is built for the nine attributed tasks: `save_judged_evidence`, `make m5e-evidence-bundle` and an upload in each job, held by `tests/architecture/test_ci_m5e_gate.py`; the four self-judging tasks follow, then G2–G4. G5 and G6 stay decisions of their own.\
**Status (2026-11-10):** G1's first hosted run, [42619476453](https://github.com/Onwcan/DireWolf/actions/runs/42619476453) at `f50286c`, uploaded eight of the nine bundles. The ninth, `sandbox-workspace`'s, was refused by the task runner: the task judged a table built at the call, with no name to keep it by. Named (`WORKSPACE_ALL_CASES`) and guarded; hosted run pending.\
**Authority of this document:** a technical handoff, not an ADR. It approves nothing, and every
choice in it is a recommendation for the owner.

## 1. Baseline

| Item | State on 2026-11-07 |
|---|---|
| `main` | `6a702d7`. Runs [42390237238](https://github.com/Onwcan/DireWolf/actions/runs/42390237238), [42392419869](https://github.com/Onwcan/DireWolf/actions/runs/42392419869), [42394667883](https://github.com/Onwcan/DireWolf/actions/runs/42394667883) and [42397671369](https://github.com/Onwcan/DireWolf/actions/runs/42397671369) (nos. 134–137) passed 30 of 30 jobs each |
| Required jobs | 29, plus the `ci` aggregate that needs them all. The M5 evidence among them: `sandbox-foundation`, `sandbox-egress`, `sandbox-workload`, `sandbox-secret`, `sandbox-workspace`, `sandbox-agent`, `sandbox-release`, `sandbox-restart`, `sandbox-capacity`, `sandbox-registry`, `net-http` and `evals` (the `m5a`–`m5d` suites) |
| Manual workflow | `M5e.5 evidence (manual)`: `sandbox-hygiene` and the mutation review. Required by nothing, and never run |
| `AVAILABLE_MILESTONES` | `M1`, `M2`, `M2.5`, `M3`, `M4`, `M5a`, `M5b`, `M5c`, `M5d` (`evals/src/direwolf_evals/runner.py`). Neither `M5e` nor `M5` is in it |
| Pending M5 property | `pending-kernel/sandbox-egress`, which requires `M5` and has no runner, deliberately |
| The attributed inventory | 627 distinct `(suite, case)` pairs in `scripts/dw.py`'s `ATTRIBUTED_CASES`, 634 rows across the tables below; seven cases are required by two tasks |

## 2. Where each step stands

| Step | State | What closes it |
|---|---|---|
| M5e.1 attribution | COMPLETE (run 40774766063) | — |
| M5e.2 closure | COMPLETE (2026-11-09). R3's E6, required by R-B, built 2026-11-08 ([ADR-0058](adr/0058-m5e-proxy-only-hard-rules-weakened-in-a-real-environment.md)) in the required `sandbox-proxy-weakened` job, passed hosted at `14405ab` (run 42525106398) after [ADR-0059](adr/0059-m5e-proxy-only-peer-joins-only-its-own-network-namespace.md)'s fix: 15 of 15 rows; both records accepted, ADR-0057 superseded, R3 and M5e.2 closed ([M5E_ASSURANCE_PLAN.md](M5E_ASSURANCE_PLAN.md) §10, "M5e.2's closure"; [issue #19](https://github.com/Onwcan/DireWolf/issues/19), closed 2026-11-09) | — |
| M5e.3 fixtures | COMPLETE (runs 41916040076, 41920008027) | — |
| M5e.4 pip, npm refused | COMPLETE (runs 134–137; accepted 2026-11-09, OD-E4's mechanism as built: [M5E_ASSURANCE_PLAN.md](M5E_ASSURANCE_PLAN.md) §10, "M5e.4's acceptance") | — |
| M5e.5 npm and pip profiles | IMPLEMENTATION COMPLETE / HOSTED EVIDENCE PENDING | the manual run; ADR-0055's trust revision; acceptance of both ADRs; the acceptance change ([M5E5_IMPLEMENTATION_HANDOFF.md](M5E5_IMPLEMENTATION_HANDOFF.md) §§7–10) |
| M5e.6 the gate | IN PROGRESS (2026-11-09): G1 built for the nine attributed tasks, hosted run pending | G1's hosted run; the four self-judging tasks' bundles; G2–G4; then G5 and G6, each a decision of its own |

## 3. What M5e.6 is, and what it is not

The plan's §6 row: an eval suite requiring `M5e` that runs the M5 evidence tasks and requires
every case at its level with its attribution; architecture tests for each new job; committed
negative controls; the owner's decisions; npm's profile enabled on ADR-0054's acceptance; then
`M5` joins the available milestones and `pending-kernel/sandbox-egress` gets its runner. The
ROADMAP's M5e acceptance is the M5 contract in full, except `local` (OD-E5).

M5e.6 is **the gate over evidence that already exists**. It adds no package-manager feature,
no new boundary and no new kind of evidence. It must not replace any task's own judgement. It
re-judges each task's real output, and it adds what no single task can check: that every task
ran, in this run, on this commit, on a disposable runner, and that together they cover the
whole inventory.

## 4. Dependency graph

```text
issue #19: E6 evidence (DONE) ──► M5e.2 closed (2026-11-09) ────────────────────────┐
M5e.4 acceptance, OD-E4 included (DONE, 2026-11-09) ────────────────────────────────┤
M5e.5 manual run ──► ADR-0055 trust revision ──► rerun ──► ADR-0054/0055 accepted ──► │
      acceptance change (option removed, `sandbox-hygiene` required) ──────────────┤
                                                                                    ▼
M5e.6 G1–G4 (bundles, gate job, pending eval) ── may be built before ───►  "M5e" joins
                                                  the blockers clear     AVAILABLE_MILESTONES
                                                                                    │
                                     the owner accepts M5 against its contract ◄───┘
                                                                                    ▼
                                "M5" joins; `pending-kernel/sandbox-egress` gets its runner
```

G1–G4 (§10) depend on nothing blocked. Built, they run in required CI and gate the inventory
from their first commit. Only the switch that makes `M5e` available waits for everything above
it.

## 5. The evidence the gate must cover

| Task | Required job | Case tables | Rows |
|---|---|---|---|
| `sandbox-foundation-evidence` | `sandbox-foundation` | `SANDBOX_CASES`, `BROKER_ASSURANCE_CASES` | 109 + 20 |
| `sandbox-egress-evidence` | `sandbox-egress` | `EGRESS_CASES`, `CAPTURED_ASSURANCE_CASES` | 104 + 19 |
| `sandbox-workload-evidence` | `sandbox-workload` | `WORKLOAD_CASES` | 152 |
| `sandbox-secret-evidence` | `sandbox-secret` | `SECRET_SANDBOX_UNIT_CASES`, `SECRET_SANDBOX_CASES` | 40 + 52 |
| `sandbox-workspace-evidence` | `sandbox-workspace` | `WORKSPACE_UNIT_CASES`, `WORKSPACE_CASES`, `WORKSPACE_PRIVILEGED_CASES` | 17 + 20 + 27 |
| `sandbox-restart-evidence` | `sandbox-restart` | `RESTART_CASES` | 7 |
| `sandbox-capacity-evidence` | `sandbox-capacity` | `CAPACITY_CASES` | 4 |
| `sandbox-registry-evidence` | `sandbox-registry` | `REGISTRY_CASES` | 19 |
| `sandbox-hygiene-evidence` | none yet: the manual job, until M5e.5's acceptance change | `HYGIENE_CASES` | 44 |
| `sandbox-proxy-weakened-evidence` | `sandbox-proxy-weakened` (since 2026-11-08; ADR-0058, accepted 2026-11-09; passed hosted in run 42525106398) | `E6_CASES` | 18 |

Four tasks judge their own output in their own way and are not in `ATTRIBUTED_CASES`:
`sandbox-agent-evidence`, `sandbox-release-evidence` (the `m5d-sandbox-exec` eval's runner),
`net-http-evidence` and the `evals` job's `m5a`–`m5d` suites. **Implementation question G-Q1:**
whether each joins the gate through a bundle of its own verdict, or through attribution first,
an M5e.1-style change. The recommendation is a bundle of the task's own verdict now, and
attribution as a later, separate step.

## 6. The gate's design (recommended)

**6.1 Shape.** A new required job, `m5e-gate`, that `needs` every job in §5. It runs no
evidence and starts no container. It reads what those jobs recorded in **this** run and judges
it again. Its eval half is a suite `m5e-gate.toml` that requires `M5e`, with the runner
`m5e.gate`. Until `M5e` is available the suite is pending, as `pending-kernel`'s evals are, and
the job's check is the gate.

**6.2 The evidence bundle.** Each evidence task writes a bundle after its own checks pass, and
only then. The job uploads it with `actions/upload-artifact`, pinned by commit SHA, and a short
retention. A bundle has two files: the task's whole output, and a JSON record that carries:

| Field | Value |
|---|---|
| `schema`, `version` | `direwolf.m5e.evidence-bundle`, `1` |
| `task`, `job` | the `dw.py` task, and the job's id in `ci.yml` |
| `run_id`, `run_attempt`, `sha`, `ref` | `GITHUB_RUN_ID`, `GITHUB_RUN_ATTEMPT`, `GITHUB_SHA`, `GITHUB_REF` |
| `runner` | `RUNNER_ENVIRONMENT` (must be `github-hosted`), `RUNNER_OS`, `ImageOS` |
| `output_sha256`, `output_bytes` | of the raw output file |
| `exit` | `0`; a failed task writes no bundle |
| `cleanup` | the task's census line, verbatim (`cleanup: no evidence container or network remains; …`) |

The bundle is written by `dw.py`'s own task runner, never by the gate and never by a workflow
step's shell. Its record holds no secret and no credential header, and the output it points
to has already passed the task's bounded-output rules.

**6.3 What the gate checks, failing closed on each:**

1. **Every expected bundle, once.** One per task in §5's required set; a missing, extra or
   repeated one fails the gate. The expected set is a table in `dw.py`, held to `ci.yml`'s
   `needs` by an architecture test.
2. **Provenance.** Each record's `run_id`, `run_attempt` and `sha` equal the gate's own. Its
   `runner` is `github-hosted`, and its `job` is the job that uploaded it. The output's SHA-256
   and size match the record. Nothing is downloaded from another run: no `run-id` input, and
   no `github-token`.
3. **The task's judgement, again.** For each attributed task, `require_attributed_evidence`
   runs over the raw output against that task's own tables. That is the same function, levels,
   `ATTRIBUTION` and `outcome_problem` as the task used, so a record cannot claim what its
   lines do not show. For the four tasks of §5's note, their own judging function does the
   same.
4. **The whole inventory.** The union of the cases re-judged equals `ATTRIBUTED_CASES`, minus
   the tables that are not yet required (`HYGIENE_CASES` until M5e.5's acceptance change). Any
   case two tasks share comes from a declared table, not from a guess. No case is unknown, and
   none is NOT EXERCISED.
5. **Cleanup.** Every bundle carries its task's census line, and no task's census reported a
   container or network left behind or lost.
6. **Bounds.** Each file is size-bounded before it is read, and the JSON is parsed strictly
   (duplicate keys, unknown fields and non-UTF-8 are refused). The gate executes nothing from a
   bundle.

**6.4 Two verdicts, kept apart.** The job prints and enforces **the inventory verdict**:
complete, authentic, every present case passing. It must pass from G2's first commit. The
**M5e acceptance verdict** is computed and printed every run. It is READY only when E6's 15
rows pass, M5e.5's cases are required and passing, and the plan records the owner's
acceptances. The verdict is enforced only by the `m5e-gate` eval, so it binds from the day
`M5e` joins `AVAILABLE_MILESTONES`. Making `M5e` available too early fails CI loudly: it never
passes quietly.

**6.5 Hosted-only stays hosted-only.** Every hosted-only task keeps its own job, flag and
refusal. The gate job only reads files, and locally `make m5e-gate-check` with no bundles says
NOT EXERCISED, never a pass.

## 7. Files and ownership (implementation, when authorised)

| Area | File | Change |
|---|---|---|
| Bundles | `scripts/dw.py` | `write_evidence_bundle()`, called by each §5 task after its checks; `M5E_GATE_TASKS`; the gate task `m5e-gate-check`; the acceptance verdict |
| Bundles | `.github/workflows/ci.yml` | an upload step in each §5 job, pinned by SHA; a new job `m5e-gate` that `needs` them; `m5e-gate` added to the `ci` aggregate's `needs` |
| Make | `Makefile` | `m5e-gate-check` |
| Eval | `evals/suites/m5e-gate.toml` (new), `evals/src/direwolf_evals/runners/m5e.py` (new), `evals/baselines/main.json` (re-recorded by the established procedure) | the suite requiring `M5e`; a runner that reimplements nothing and calls `dw.py`'s judging |
| Guards | `tests/architecture/test_ci_m5e_gate.py` (new) | the job's shape, its `needs`, the upload steps, the expected-task table, and a negative control for each |
| Guards | `tests/architecture/test_m5e_r3_closure.py` | unchanged by G1–G4; G5 changes it with the owner's acceptance (§9) |
| Docs | `docs/M5E_ASSURANCE_PLAN.md` §§6, 8, 9; `docs/EVALS.md`; `docs/SANDBOX.md` §6a | the gate, as built |

## 8. Architecture tests and negative controls

| Invariant | Test | Negative controls (each must fail it) |
|---|---|---|
| The gate job is required and unconditional | `test_ci_m5e_gate.py` | dropped from `ci.needs`; `continue-on-error`; an `if:`; a matrix; a second copy |
| It needs every evidence job | same | one job missing from its `needs`; a renamed job |
| Each evidence job uploads its bundle, pinned | same | the step missing; an unpinned action; `if: always()` on the upload, so a failed task would ship a bundle |
| The gate downloads only this run's artifacts | same | a `run-id` or `github-token` input; a wildcard naming another workflow |
| The expected-task table equals `ci.yml` | same | an extra task; a missing task |
| Bundles are judged, not trusted | unit tests of the gate task | a fabricated record with no lines; a wrong `sha`, run or attempt; a self-hosted runner; an output digest mismatch; a duplicate case; an unknown case; a level downgraded; an enforcement swapped; a NOT EXERCISED line; a missing census line; an oversized file; malformed or duplicate-key JSON |
| The acceptance verdict cannot be READY early | unit tests | E6 rows absent; `HYGIENE_CASES` not required; ADR-0054 or ADR-0055 Proposed; ADR-0057 not superseded |
| `M5e` and `M5` stay unavailable until the milestone decision (§9) — while ADR-0057 stood and, since 2026-11-09, after it was superseded | existing `test_m5e_r3_closure.py` | existing controls |

## 9. Milestone availability

`M5e` joins `AVAILABLE_MILESTONES` in a separate change, which needs all of these:

- the owner closed M5e.2 on accepted E6 evidence (ADR-0057 superseded, as its §8 requires);
- the owner accepted M5e.4 and M5e.5;
- ADR-0054 and ADR-0055 are accepted, and `sandbox-hygiene` is required;
- the `m5e-gate` acceptance verdict is READY on that commit's hosted run.

The same change updates `test_m5e_r3_closure.py`, which refuses `M5e` or `M5` as available
whether or not ADR-0057 stands (since 2026-11-09), and records the decision in the plan's §10.

`M5` joins later and separately, when the owner accepts M5 against its contract. That change
gives `pending-kernel/sandbox-egress` a runner: the `m5e-gate` verdict over `sandbox-egress`'s
and `sandbox-agent`'s bundles, which already measure a real `PROXY_ONLY` workload end to end.
Neither change may lower a requirement, move a case to "pending" or edit a baseline to pass.

## 10. Proposed commit slices

| Slice | What | Needs |
|---|---|---|
| G1 | Bundles: `write_evidence_bundle()`, the upload steps, their unit and architecture tests | authorisation |
| G2 | The gate task and the `m5e-gate` job, required by `ci`; its inventory verdict | G1 hosted green |
| G3 | The `m5e-gate` eval suite and runner, pending on `M5e` | G2 |
| G4 | Docs: the plan's §§6, 8, 9; `EVALS.md`; `SANDBOX.md` §6a | G3 |
| G5 | `M5e` joins `AVAILABLE_MILESTONES` | §9's list, and the owner |
| G6 | `M5` joins; `pending-kernel/sandbox-egress` gets its runner | the owner's M5 acceptance |

Each slice is its own commit and hosted run. G5 and G6 are the owner's decisions, not
engineering steps.

## 11. Hosted verification, per slice

1. After G1: every §5 job shows its upload step. Each artifact's record names that run, that
   commit and `github-hosted`.
2. After G2: `m5e-gate` passes, printing the inventory verdict (`627` minus the not-yet-required
   tables, every one re-judged) and the acceptance verdict `NOT READY`, with its blockers
   listed: M5e.5 not required, ADR-0054 and ADR-0055 Proposed (E6, ADR-0058 and M5e.4 were cleared on 2026-11-09).
3. Then one deliberate check per negative control, in unit tests, never by breaking `main`.

## 12. The owner's checklist, before G1

- [ ] Authorise M5e.6's implementation (G1–G4), or not yet.
- [ ] G-D1: a separate `m5e-gate` job (recommended), or making the `evals` job need every
      evidence job (simpler, but every CI run waits for the slowest job before evals start).
- [ ] G-D2: the bundle's artifact retention (recommended: 7 days; the gate reads it in the
      same run).
- [ ] G-Q1: the four self-judging tasks join by their own verdict (recommended) or after
      attribution.
- [ ] G-D3: whether `d11-hardening` and `process-broker` (M4's) belong to the M5 gate
      (recommended: no; M5's contract names neither).

## 13. External prerequisites

- **E6** ([issue #19](https://github.com/Onwcan/DireWolf/issues/19)). Met: hosted run 42525106398,
  ADR-0058 accepted and ADR-0057 superseded on 2026-11-09, and the issue closed.
- **Acceptances.** M5e.4 (with OD-E4): 2026-11-09. Still needed: D1–D4,
  ADR-0054 and ADR-0055.
- **GitHub Actions.** `actions/upload-artifact` and `actions/download-artifact` at commits the
  repository pins, as `actions/checkout` is pinned today.

## 14. Technical acceptance criteria for M5e.6's implementation

- `m5e-gate` is required by `ci`, needs every §5 job, and passes on a hosted run of `main`.
- Every attributed case of every required task is re-judged from that run's own output, at its
  level, with its attribution and outcome. Any missing, duplicated, unknown, NOT EXERCISED,
  mis-levelled or mis-attributed line fails it.
- A bundle from another run, commit or runner kind, or with a wrong digest or no census,
  fails it.
- Each invariant of §8 has a committed negative control that fails.
- The acceptance verdict prints its blockers, and nothing makes `M5e` or `M5` available.
- No task's own check, level, case, outcome, gate or job is weakened, and no hosted-only
  evidence runs anywhere else.
