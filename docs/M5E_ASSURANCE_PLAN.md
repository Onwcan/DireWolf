# M5e — The M5 defensive assurance gate: gap analysis and implementation plan

**Project:** [DireWolf](https://github.com/Onwcan/DireWolf)\
**Baseline:** `f8aeef97ec0bcc356d8a2421be709496fe275d70` (`main`, verified 2026-10-26)\
**Verified hosted CI of the baseline:** [run 40331005080](https://github.com/Onwcan/DireWolf/actions/runs/40331005080), 27 of 27 jobs successful\
**Status (as written, 2026-10-26):** Planning only. M5e is NOT STARTED: no M5e code, evidence or CI job exists, and no M5e evidence has run. M5 stays IN PROGRESS.\
**Status (2026-10-26, later):** the owner decided the plan's eight open points, OD-E1 to OD-E8 (§10). M5e is still NOT STARTED.\
**Status (2026-10-27):** the sibling pip ADR the owner decided on (OD-E2) is drafted, [ADR-0055](adr/0055-m5e-pip-hygiene-profile.md), **Proposed**; SANDBOX.md §6 says what a contained attempt's evidence is (OD-E1); and a test now holds every evidence case §3 cites to the task that requires it. That is M5e.1's groundwork, not M5e.1: no evidence line has changed. M5e is still NOT STARTED.\
**Status (2026-10-27, later):** after the groundwork's hosted run ([40497912001](https://github.com/Onwcan/DireWolf/actions/runs/40497912001), `a0d6ade`, 27 of 27), **M5e.1 is built**: every line of the five suites' evidence says its level and enforcement, and each task refuses one that does not as the contract says ([SANDBOX.md](SANDBOX.md) §6a; R16 below). It passed locally on a real runtime; it is complete when a hosted run of the owner's commit passes. M5e is IN PROGRESS; M5e.2–M5e.6 are not complete.\
**Status (2026-10-29):** **M5e.1 is COMPLETE** — committed as `f42f44a` and verified, with the CI recovery after it (`9175307`, `bbedd06`) and PR #17 (`6fd0bc7`), by hosted [run 40774766063](https://github.com/Onwcan/DireWolf/actions/runs/40774766063) on `6fd0bc7`, 27 of 27 jobs. **M5e.2 is BUILT in part, hosted verification pending:** R2 and R3 are evidenced in process by the broker's own host judgement and decision, R9 on a real runtime (§3). **R8 FAILS**: its neighbour case found that environments are coupled through the one host uid they share — finding **F-R8** (§5a), the owner's to decide; nothing was changed to make it pass. The real weakened `PROXY_ONLY` containers and R11's runtime restart are not built (§3, §6). M5e is IN PROGRESS; M5 stays IN PROGRESS.\
**Status (2026-10-30):** the partial M5e.2 commit `3c16bfb` ran as hosted [run 40954372045](https://github.com/Onwcan/DireWolf/actions/runs/40954372045) (CI #106): **FAILURE**, 23 of 27 jobs successful — `sandbox-foundation` (R2, R3 in process) and `sandbox-workload` (R9) among them, so those cases are hosted-verified — and three privileged jobs failed with their hosted-only halves NOT EXERCISED (`filesystem-operations`, `sandbox-workspace`, `sandbox-agent`), the aggregate with them. Cause: each crossed `sudo --user "$USER"` with a bare `--preserve-env`, which carried none of the step's `DW_*` configuration under the Ubuntu 26.04 image's sudo-rs (its `env_reset` cannot be disabled); the tasks correctly failed. Repaired, unverified until the owner's next hosted run: `scripts/ci_handoff.py` hands each value across by name and proves it arrived (§8). The same change adds R2's real-container host-UTS case, R11's hosted runtime restart as a required job of its own (never executed yet: only a disposable hosted runner may run it), and [ADR-0056](adr/0056-m5e-cross-run-task-limit-isolation.md) (**Proposed**) for F-R8. R8 still FAILS; F-R8 stays OPEN until the owner accepts a remedy and its evidence passes. M5e.2 stays IN PROGRESS.\
**Status (2026-10-31):** the owner committed that change as `e696c25` and `466b106`; hosted [run 41130431929](https://github.com/Onwcan/DireWolf/actions/runs/41130431929) (run no. 113, `466b106`): **SUCCESS**, 28 of 28 jobs. So the CI #106 repair is hosted-verified (`filesystem-operations`, `sandbox-workspace`, `sandbox-agent`), R2's `weakened-host-uts` and R9's cross-run cases passed hosted, and **R11's `sandbox-restart` ran for the first time and passed** — its seven cases, the runner's Docker Engine restarted under a running authority. The owner then **selected ADR-0056's Option B and authorised its implementation** (2026-10-31; not acceptance — the ADR stays **Proposed**). Built since, unstaged, hosted verification pending (§3, §5a): `RLIMIT_NPROC` derived as `PIDS_LIMIT × MAX_LIVE_ENVIRONMENTS × 2` = 8 192; R8's neighbour test restored as required evidence, at the broker and through the authority, with its cap case hosted-only in a new required job (`sandbox-capacity`) and its negative control (`make sandbox-neighbour-mutations`); and R3 over a real runtime's own `PROXY_ONLY` record, judged in process. Real weakened `PROXY_ONLY` containers stay NOT EXERCISED, so **M5e.2 stays IN PROGRESS (partial)**: R8 needs the owner's hosted run, R3's real-container level is not met, and ADR-0056 needs its formal acceptance.\
**Status (2026-11-01):** the owner committed that change as `615e77e`; hosted [run 41242001763](https://github.com/Onwcan/DireWolf/actions/runs/41242001763) (run no. 114, `615e77e`): **SUCCESS**, 29 of 29 jobs, the new required `sandbox-capacity` among them. So **R8 is hosted-verified** — the neighbour at the broker and through the authority, and the live-environment cap (§3, §5a) — and R3's captured-record cases passed hosted, at their level, `in-process`. On that record the owner **formally accepted [ADR-0056](adr/0056-m5e-cross-run-task-limit-isolation.md)** on 2026-11-01: Option B as built — each environment's pids cgroup (256) its task bound, `RLIMIT_NPROC` the host-wide backstop of 8 192 — with its deployment contract and its shared-uid residuals stated, not narrowed. **F-R8 is closed.** Real weakened `PROXY_ONLY` containers stay NOT EXERCISED, so R3's real-container level is still open, for a separate decision of the owner's, and **M5e.2 stays IN PROGRESS** until it is decided. M5e.3 is NOT STARTED.\
**Status (2026-11-01, later):** for that decision the owner chose to record the gap as a residual: [ADR-0057](adr/0057-m5e-proxy-only-real-container-evidence-residual.md), **Proposed**, states what R3's evidence shows at each level, what stays unverified without real weakened `PROXY_ONLY` containers, and the owner's choice — accept the residual with a limited claim, require the real-container level, or defer it. It accepts nothing, adds no evidence and changes no acceptance wording; M5e.2 stays IN PROGRESS.\
**Status (2026-11-01, R-B):** the owner committed that record and ADR-0056's acceptance as `576b249`; hosted [run 41304247232](https://github.com/Onwcan/DireWolf/actions/runs/41304247232) (run no. 115, `576b249`): **SUCCESS**, 29 of 29 jobs. The owner then **selected R-B** on ADR-0057: R3's real-container level stays required, the residual is not accepted, its limited claim is not approved, and M5's contract stands as written. Built since, unstaged, hosted run pending: ADR-0057's U4 closed in process — the runtime's default seccomp profile and the swap limit, alone and with the pids limit as the real `NO_NETWORK` case lifts both, refused under `PROXY_ONLY` over the hand-written record and the real runtime's own, each `in-process` and required by name (§3, R3). Real `PROXY_ONLY` containers weakened one hard rule at a time — ADR-0057's E6 — are **BLOCKED**: not built and not planned, the earlier safety control standing. **M5e.2 is IN PROGRESS, R3 E6 BLOCKED**; M5e.3 is NOT STARTED.\
**Status (2026-11-01, U4 hosted):** the owner committed U4 and the R-B record as `b25c3e6`; hosted [run 41323258812](https://github.com/Onwcan/DireWolf/actions/runs/41323258812) (run no. 116, `b25c3e6`): **SUCCESS**, 29 of 29 jobs. So **U4 is hosted-verified, at its level, `in-process`**: `sandbox-foundation` required the three hand-written-record cases among its 20 `broker-assurance` lines and `sandbox-egress` the three captured-record ones among its 19 (beside the egress suite's 104 `real-oci` cases), every line at its level. That run carries **no E6 case**, so it proves nothing about E6, which stays **BLOCKED**. Reviewed since, against every existing source, for whether E6 can be met without the blocked experiment (§3a): it cannot — no authorised test observes a real `PROXY_ONLY` environment with a hard rule weakened, so all 15 rows are BLOCKED; §3b specifies, without any procedure, what genuine E6 evidence would have to carry. Built, unstaged, hosted run pending: the evidence gate now also holds what each R2/R3 line says it showed — a weakening refused by the invariants that failed, the in-process judgement naming the host's vantage only, a real weakening naming what caught it from the vantage it claims — and an architecture test holds the owner's R-B (ADR-0057 never accepted; no document claiming E6 or M5e.2 complete while it stands). **M5e.2 is IN PROGRESS, R3 E6 BLOCKED**; M5e.3 is NOT STARTED.\
**Status (2026-11-02):** the owner committed that gate and guard as `e746aee`, F-RELAY's fix as `f3ae200`, and F-EVICT's and F-TEARDOWN's as `df4fa24`; hosted runs [41349869654](https://github.com/Onwcan/DireWolf/actions/runs/41349869654) (run no. 117, `e746aee`), [41358634372](https://github.com/Onwcan/DireWolf/actions/runs/41358634372) (no. 118, `f3ae200`) and [41430527997](https://github.com/Onwcan/DireWolf/actions/runs/41430527997) (no. 119, `df4fa24`): **SUCCESS**, 29 of 29 jobs each, by their conclusions. So the outcome checks and the R-B guard are hosted-verified (R17), and so are the three findings' fixes (§5a), each at the level its tests have: unit tests in `make test`, beside the real-runtime suites that already ran; none of it is E6. Found since, built, unstaged, hosted run pending: F-ABSENT (§5a), a runtime the client could not ask read as a container gone. **M5e.2 is IN PROGRESS, R3 E6 BLOCKED**; M5e.3 is NOT STARTED.\
**Status (2026-11-02, F-ABSENT hosted):** the owner committed F-ABSENT's fix as `f0f237f`; hosted [run 41446389484](https://github.com/Onwcan/DireWolf/actions/runs/41446389484) (run no. 120, `f0f237f`): **SUCCESS**, 29 of 29 jobs, by their conclusions. So F-ABSENT's fix is hosted-verified at its tests' levels — its unit tests, and every required real-runtime case over the changed removal, destruction and listing — while the interruption itself, a runtime that stops answering between two of the broker's steps, is reproduced by no local or hosted job (§5a). Built since, unstaged, hosted run pending: the evidence's side of the same weakness — every real-runtime suite's `exists` believes a container gone only from a listing the runtime answered (§5a). None of it is E6. **M5e.2 is IN PROGRESS, R3 E6 BLOCKED**; M5e.3 is NOT STARTED.\
**Status (2026-11-02, evidence side hosted):** the owner committed F-ABSENT's evidence side as `b6a8a1e`; hosted [run 41471750928](https://github.com/Onwcan/DireWolf/actions/runs/41471750928) (run no. 121, `b6a8a1e`): **SUCCESS**, 29 of 29 jobs, by their conclusions. So the engineering hardening M5e.2's reviews found — F-RELAY, F-EVICT, F-TEARDOWN, F-ABSENT and F-ABSENT's evidence side (§5a) — is fixed and hosted-verified, each at its tests' levels; a runtime that stops answering between two of the broker's steps is still reproduced by no job. That is not M5e.2's acceptance: R3's E6 has no qualifying evidence, all 15 of its rows are **BLOCKED** (§3a), and [issue #19](https://github.com/Onwcan/DireWolf/issues/19) is the tracker for it; ADR-0057 stays **Proposed**, the owner's R-B binding. **M5e.2 is IN PROGRESS, R3 E6 BLOCKED**; M5e.3–M5e.6 are NOT STARTED.\
**Status (2026-11-03, M5e.3 sequencing):** the owner committed F-RELPROP's and F-PROXY-CLOSE's fixes (§5a) as `396d87b`; hosted [run 41535101815](https://github.com/Onwcan/DireWolf/actions/runs/41535101815) (run no. 123, `396d87b`): **SUCCESS**, 29 of 29 jobs, by their conclusions — both fixes hosted-verified at their tests' levels, unit tests in `make test`; neither is E6. The owner then made one narrow exception to §6's order (§10, "M5e.3's sequencing"): M5e.3's fixture work may proceed while M5e.2 stays open. It changes when M5e.3 may start and nothing else — the owner's R-B, E6's 15 rows and §3b's criteria, every evidence level, production control, architecture guard and CI requirement, and M5's acceptance stand as written. **M5e.2 is IN PROGRESS, R3 E6 BLOCKED** (required 15, passed 0, blocked 15), and [issue #19](https://github.com/Onwcan/DireWolf/issues/19) stays OPEN; M5e.3 is NOT STARTED, its start authorised ahead of M5e.2's close; M5e.4–M5e.6 are NOT STARTED and still follow M5e.2.\
**Status (2026-11-03, M5e.3's offline fixtures):** under that exception M5e.3 started, in §7a's order. Built, unstaged, hosted run pending: §7a's generator, PEP 503 index and npm registry — `tests/sandbox/registry_fixtures.py`, standard library only, every byte from a seed, a fixed seed's bytes pinned by a recorded digest — with their unit tests (`tests/sandbox/test_registry_fixtures.py`) and §7a's guard (`tests/architecture/test_m5e_registry_fixtures.py`), all in `make test`. Not built: the per-run CA and the origins (§7a). No production line, evidence case or level, CI job or eval changes; none of it is evidence, and none bears on R3 or E6. **M5e.2 is IN PROGRESS, R3 E6 BLOCKED** (required 15, passed 0, blocked 15), and [issue #19](https://github.com/Onwcan/DireWolf/issues/19) stays OPEN; M5e.3 is IN PROGRESS, out of sequence; M5e.4–M5e.6 are NOT STARTED and still follow M5e.2.\
**Status (2026-11-04, M5e.3 built; M5e.2 partially implemented):** the owner committed the sequencing exception, M5e.3's offline fixtures and the closed-port fix as `6be8c41`; hosted [run 41720068934](https://github.com/Onwcan/DireWolf/actions/runs/41720068934) (run no. 126, `6be8c41`): **FAILURE**, 27 of 29 jobs. `make test` on windows-latest failed, and the `ci` aggregate with it: two fixture tests gave pytest's Windows `tmp_path` as a marker directory, which the generator refused. On Linux and macOS every fixture test passed, the recorded digest included, as did the sequencing guard and the closed-port fix. Fixed since, unstaged, hosted run pending: a marker directory is an absolute POSIX or Windows path of plain segments, in one canonical form, the default's bytes unchanged (§7a). Built since, unstaged, hosted run pending: the rest of M5e.3 — the per-run CA's registry certificates and the two registry origins, with the proxy's side shown in process (§7a). **M5e.2 — PARTIALLY IMPLEMENTED / ASSURANCE BLOCKED (R3/E6, [issue #19](https://github.com/Onwcan/DireWolf/issues/19))**: its engineering hardening is hosted-verified; R3's real-container E6, required by the owner's R-B, is BLOCKED (required 15, passed 0, blocked 15); M5e.2 stays IN PROGRESS. M5e.3's implementation is complete under the owner's sequencing exception (§10), its hosted validation pending; M5e.4–M5e.6 are NOT STARTED and still follow M5e.2, and M5's acceptance waits for E6.\
**Authority of this document:** a technical plan, not an ADR. It approves nothing itself; the owner's decisions are recorded in §10 as given. [ADR-0054](adr/0054-m5e-npm-hygiene-profile.md) stays **Proposed**.

## 1. Scope, sources and the owner's directions

M5e is the milestone that turns M5's slices into one gate: the complete escape,
SSRF and persistence suites as merge gates, the weakened-profile closure for
`PROXY_ONLY`, and package-manager acceptance — a real `pip install` and
`npm install` succeeding against an allowlisted registry and failing against a
non-allowlisted one ([ROADMAP.md](ROADMAP.md), M5e and "The M5 contract").

Read for this plan, at the baseline: [ROADMAP.md](ROADMAP.md) (M5a–M5e and the
M5 contract), [SANDBOX.md](SANDBOX.md) (§§2, 4, 4a, 6),
[NETWORK_SECURITY.md](NETWORK_SECURITY.md) (§§1–3, 8, 9),
[EVALS.md](EVALS.md) (§§3, 8), [ADR-0052](adr/0052-m5d-sandboxed-process-exec.md)
(§§1, 5a, 8, 17, 19), `crates/dwkd-authority/src/resource/exec/hygiene.rs`,
`crates/dwk-sandbox-profile/src/lib.rs` (`HYGIENE_ENVIRONMENT`,
`PROXY_VARIABLES`), the broker's and the authority's real-container suites
(`sandbox_foundation.rs`, `sandbox_egress.rs`, `sandbox_workload.rs`,
`sandbox_agent.rs`), `scripts/dw.py` (every evidence task, its case lists and
its image builders), `Makefile`, `.github/workflows/ci.yml`, and the eval
suites, runners, inventory and baseline under `evals/`.

The owner's directions of 2026-10-26, for design and planning — **not** an
acceptance of anything:

1. Draft [ADR-0054](adr/0054-m5e-npm-hygiene-profile.md) as **Proposed**: a
   narrowly scoped, evidence-backed npm execution profile. npm stays
   fail-closed (`HYGIENE_NOT_EVIDENCED`) until the profile is validated and
   the owner accepts it.
2. Host-local execution (`local`) stays deferred to M6, as the accepted
   ADR-0052's OD-7 decided.
3. pip and npm registry verification is hermetic and **hosted** (CI): no new
   tooling is installed on the developer's WSL host.
4. The audit model stays as it is: each case is attributed to an existing
   authority or broker event, or to measured environment evidence — no new
   per-attempt audit event inside the sandbox.

Out of scope here: implementing anything, running uncontrolled exhaustion,
reaching any third-party system, and weakening a production control to make a
test pass.

## 2. The requirements M5e must meet

| ID | Requirement | Source |
|---|---|---|
| R1 | Every hard rule of `oci-strict` verified at runtime by the measured-assurance probe, not merely configured | M5 contract; SANDBOX.md §2 |
| R2 | A weakened-profile meta-test for each hard rule makes the gate fail | M5 contract; SANDBOX.md §6 |
| R3 | Weakened-profile closure for `PROXY_ONLY`: the weakenings also hold, and are caught, in a `PROXY_ONLY` environment | M5e deliverables |
| R4 | From `PROXY_ONLY`, no route to any address but the proxy endpoint (direct TCP, UDP, DNS, raw sockets) | M5 contract; NETWORK_SECURITY.md §9 |
| R5 | Network destination authorization: only the run's exact grants are tunnelled; CONNECT form, host and SNI agree | NETWORK_SECURITY.md §2; ADR-0048 |
| R6 | TLS verification: the client verifies the origin; the kernel's own requests verify every hop | NETWORK_SECURITY.md §§2, 4 |
| R7 | The full SSRF suite (blocked ranges, metadata by IP and name, rebinding, mixed answers, IPv4-mapped, NAT64, redirects, credential leakage) | M5 contract; NETWORK_SECURITY.md §9 |
| R8 | Resource exhaustion bounded: fork, memory, disk, descriptors, file size, wall clock — without uncontrolled experiments | M5 contract; SANDBOX.md §6 |
| R9 | Cross-run isolation and persistence: nothing of one run reaches or survives into another | M5 contract; SANDBOX.md §§2, 6 |
| R10 | Environment lifecycle and cleanup: orphans reaped exactly; a run's and a lease's end end its environment | M5 contract; ADR-0052 §8 |
| R11 | Re-attach by run-id label after a container-runtime restart | M5 contract; RELIABILITY.md (container runtime restart) |
| R12 | A tampered or substituted assurance probe, and a configuration that looks hardened while the running environment differs, are caught | M5 contract (adversarial) |
| R13 | A fronted request through an allowlisted shared host stays within its byte budget and connection count | M5 contract (adversarial); NETWORK_SECURITY.md |
| R14 | A real `pip install` succeeds against an allowlisted registry and fails against a non-allowlisted one | M5 contract |
| R15 | A real `npm install` succeeds against an allowlisted registry and fails against a non-allowlisted one | M5 contract |
| R16 | Every containment is attributed to what enforced it | SANDBOX.md §6; owner direction 4 |
| R17 | CI and eval evidence cannot turn a missing or weakened case into a green check | EVALS.md §§3, 8; every `test_ci_*` |
| R18 | `local` behind opt-in | M5 contract — **deferred to M6** (ADR-0052 OD-7, accepted; owner direction 2) |

## 3. Requirements-to-evidence matrix

"Hosted" means the named cases are required by a task that is a required job
of the `ci` aggregate and passed in hosted CI at the baseline (run
40331005080). A case named here is a case the task requires by name; nothing is
listed as verified on any other basis.

| ID | Existing evidence (task: cases) | Status | Gap, and the M5e work |
|---|---|---|---|
| R1 | `sandbox-foundation-evidence`: the probe's measured invariants on a real runtime; `host-pid-private`, `host-ipc-private`, `host-uts-private`, `container-pid-private`; the strict profile measured from the runtime's record and from inside | Hosted | None for the rules M5a measures. Restate the rule-to-invariant map in the gate (M5e.6). |
| R2 | `sandbox-foundation-evidence`: `every_weakened_profile_is_detected` — `weakened-writable-root`, `-root-user`, `-privileged`, `-runtime-socket-mounted`, `-capability-added`, `-seccomp-unconfined`, `-seccomp-default-profile`, `-host-network`, `-host-pid`, `-host-ipc`, `-no-new-privileges-disabled`, `-resource-limits-dropped`, `-extra-device`, `-mutable-image-tag`, `weakened-count`; `drift-pids-limit-raised`. Since M5e.2, in process (the broker's own host judgement and its decision, `oci::clean`, given one record at a time): `no-network-weakened-host-uts-refused`, `proxy-only-weakened-host-uts-refused`; on a real runtime (2026-10-30), `weakened-host-uts` — a `NO_NETWORK` container sharing the host's UTS namespace, caught by the broker's measurement of the runtime's record (HOST_UTS_NAMESPACE_PRIVATE, measured from the host) | Hosted (the in-process cases passed in run 40954372045; `weakened-host-uts` in run 41130431929) | Host UTS is refused by the production judgement under both topologies in process, and measured on a real `NO_NETWORK` container — the existing weakened-profile suite, one entry more; the container holds no `CAP_SYS_ADMIN`, so it cannot change the hostname it shares. The gate's own failure is shown per task (a missed case fails it); an M5-level meta-test is M5e.6's. |
| R3 | `sandbox-egress-evidence`: `weakened_topologies_are_detected` — `weakened-bridge-network`, `weakened-missing-relay`, `weakened-relay-tampered`, `weakened-proxy-variables-removed`, `drift-extra-peer-listening`, `drift-fake-resolver-in-namespace`, `drift-egress-directory-opened`, `drift-setup-left-running`, `drift-relay-stopped`, `weakened-topology-count`. Since M5e.2, in process, every hard rule judged under a `PROXY_ONLY` spec: `proxy-only-conforming-kept`, `no-network-conforming-kept`, `proxy-only-weakened-writable-root-refused`, `proxy-only-weakened-root-user-refused`, `proxy-only-weakened-privileged-refused`, `proxy-only-weakened-capability-added-refused`, `proxy-only-weakened-no-new-privileges-disabled-refused`, `proxy-only-weakened-seccomp-unconfined-refused`, `proxy-only-weakened-seccomp-default-profile-refused`, `proxy-only-weakened-host-pid-refused`, `proxy-only-weakened-host-ipc-refused`, `proxy-only-weakened-host-network-refused`, `proxy-only-weakened-mutable-image-tag-refused`, `proxy-only-weakened-runtime-socket-mounted-refused`, `proxy-only-weakened-extra-device-refused`, `proxy-only-weakened-resource-limits-dropped-refused`, `proxy-only-weakened-swap-limit-lifted-refused`, `proxy-only-weakened-pids-and-swap-limits-lifted-refused` (the default profile and the two swap cases since 2026-11-01: ADR-0057's U4). Since 2026-10-31, the same judgement over **a real runtime's own record** of a real `PROXY_ONLY` environment the broker prepared and measured clean (captured by `sandbox-egress-evidence`, then judged in process): `captured-proxy-only-conforming-kept`, `captured-proxy-only-weakened-host-uts-refused`, `captured-proxy-only-weakened-writable-root-refused`, `captured-proxy-only-weakened-root-user-refused`, `captured-proxy-only-weakened-privileged-refused`, `captured-proxy-only-weakened-capability-added-refused`, `captured-proxy-only-weakened-no-new-privileges-disabled-refused`, `captured-proxy-only-weakened-seccomp-unconfined-refused`, `captured-proxy-only-weakened-seccomp-default-profile-refused`, `captured-proxy-only-weakened-host-pid-refused`, `captured-proxy-only-weakened-host-ipc-refused`, `captured-proxy-only-weakened-host-network-refused`, `captured-proxy-only-weakened-mutable-image-tag-refused`, `captured-proxy-only-weakened-runtime-socket-mounted-refused`, `captured-proxy-only-weakened-extra-device-refused`, `captured-proxy-only-weakened-resource-limits-dropped-refused`, `captured-proxy-only-weakened-swap-limit-lifted-refused`, `captured-proxy-only-weakened-pids-and-swap-limits-lifted-refused`, `captured-proxy-only-weakened-task-backstop-at-256-refused` (U4's three since 2026-11-01) | Partial; in process hosted-verified (run 40954372045), the captured-record cases too (run 41242001763), each `in-process`; U4's three over both records too (run 41323258812); real weakened containers **NOT EXERCISED — BLOCKED** (E6) | Each nonconforming record changes exactly the invariants it states and the production decision refuses it under `PROXY_ONLY` — over a hand-written record of the runtime's shape and, since 2026-10-31, over the runtime's own record of a real environment, so the judgement is shown on the runtime's real field names, defaults and ordering. Every one of those lines is `in-process`: the runtime never ran a weakened record; the inside vantage under `PROXY_ONLY` stays the egress suite's (`proxy-only-container-capabilities-empty`, `proxy-only-container-raw-sockets-refused`), and the weakened *topologies* are real containers already. **Not built, deliberately:** real `PROXY_ONLY` containers weakened one hard rule at a time — an earlier session's work on exactly that was stopped by a safety control, and the owner directed it not be worked around; in-process evidence is the judgement's, never a container's, and is not relabelled as one. R3 stays open at the real-container level, its gate preserved: [ADR-0057](adr/0057-m5e-proxy-only-real-container-evidence-residual.md) (Proposed) records the residual, E1–E6 and U1–U4, and the owner selected **R-B** on it (2026-11-01) — the real-container level is required and the residual not accepted. U4 is closed in process (2026-11-01) and hosted-verified (run 41323258812); E6 is **BLOCKED**: not built and not planned while the safety control stands, and no existing source observes it (§3a); [issue #19](https://github.com/Onwcan/DireWolf/issues/19) tracks it. |
| R4 | `sandbox-egress-evidence`: `bypass-raw-ipv4`, `-raw-ipv6`, `-icmp`, `-vsock`, `-udp-external`, `-udp-ipv6-external`, `-dns-external`, `-dns-ipv6-external`, `-dns-local-stub`, `-dns-desktop-host`, `-dns-embedded-runtime-resolver`, `-tcp-external-dns`, `-tcp-private-lan`, `-tcp-host-loopback-origin`, `-tcp-cloud-metadata`, `-tcp-nat64-metadata`, `-tcp-ipv4-mapped`, `-tcp-link-local-neighbour`, `bypass-proxy-variable-redirected`; `sandbox-agent-evidence`: `a06-*`, `a07-*` | Hosted | None for the topology. For package managers: M5e.4 repeats direct-route attempts from the pip and npm invocations themselves. |
| R5 | `sandbox-egress-evidence` (strict CONNECT parse, exact grants, tunnel limit); `sandbox-agent-evidence`: `a05-connect-absolute-form-refused`, `a05-connect-address-literal-refused`, `a05-connect-another-method-refused`, `a05-connect-host-header-disagrees-refused`, `a05-connect-host-not-canonical-refused`, `a05-connect-smuggled-body-refused`, `a05-tls-sni-mismatch-closed`, `a05-tls-sni-missing-closed` | Hosted | **Missing for registries:** an ungranted registry, a tarball or wheel on an ungranted host, and a redirect to one. M5e.4. |
| R6 | Sandbox egress is an opaque tunnel, so TLS is the client's: `a03-https-granted-origin-tls-verified`, `a05-tls-untrusted-issuer-refused-by-the-client`, `a05-tls-certificate-for-another-name-refused-by-the-client`. The kernel's own path: `net-http-evidence` (verified per hop) | Hosted | **Missing for pip and npm:** each verifies the fixture registry under a per-run CA, refuses an untrusted issuer, and its verification is not turned off by an argument (ADR-0054 for npm; [ADR-0055](adr/0055-m5e-pip-hygiene-profile.md) for pip, both Proposed). M5e.4–M5e.5. |
| R7 | Kernel path, `net-http-evidence`: `ssrf-*` (IP literals, `ssrf-ipv4-mapped`, `ssrf-6to4`, `ssrf-mixed-answer`, …), `dns-rebinding-pinned-within-request`, `dns-rebinding-next-request`, `redirect-*` (`-blocked-address`, `-metadata-name`, `-mixed-address`, `-ungranted-host`, `-sixth-hop`, `-downgrade`, …), `credential-cross-origin-redirect`, `origin-confusion-idna-label`, and the authority's own pipeline: `guard-loopback-answer`, `guard-metadata-ip-answer`, `guard-mixed-answer`, `metadata-name-before-resolution`. Proxy path, `sandbox-egress-evidence`: `resolver-metadata-blocked`, `resolver-rebinding-pinned`, `resolver-mixed-refused-outright`, `bypass-tcp-cloud-metadata`, `bypass-tcp-nat64-metadata`, `bypass-tcp-ipv4-mapped` | Hosted | The suite is spread over two tasks and has no single gate. M5e.6's gate requires both, by name. Out of M5's scope and stated so: link-preview and markdown-image exfiltration (channels, M10+) and a `LOCAL_ONLY` model call (M7). |
| R8 | `sandbox-foundation-evidence`: `resource-pids-bounded`, `resource-memory-oom-killed`, `resource-file-size-bounded`; `sandbox-workload-evidence`: `workload-fork-loop-reaped`, `workload-daemon-reaped`, `workload-wall-clock-timed-out`; `sandbox-workspace-evidence`: `workload-fills-to-enospc`; the 16-environment and workload budgets (`public-exec-budget-exhausted-refused`). Since 2026-10-31 (ADR-0056, Option B), the neighbour at the broker — `neighbour-holds-its-own-task-bound`, `neighbour-workload-served-beside-a-bound-environment`, `neighbour-measured-clean-beside-a-bound-environment`, `neighbour-broker-answers-beside-a-bound-environment`, `neighbour-both-kept-then-destroyed-exactly` — and through the authority's `process.exec`, a real DWKP client per run — `neighbour-run-holds-its-own-task-bound`, `neighbour-authority-answers-beside-a-bound-run`, `neighbour-environment-judged-clean-beside-a-bound-run`, `neighbour-process-exec-completed-beside-a-bound-run`, `neighbour-environments-kept-ready`; at the live-environment cap, hosted only (`sandbox-capacity-evidence`) — `capacity-environments-at-their-own-bound`, `capacity-last-environment-prepared-and-measured-clean`, `capacity-last-workload-served`, `capacity-all-destroyed-exactly` | Hosted, each limit alone. The neighbour, at the broker and through the authority, and the cap: **Hosted — PASS** (run 41242001763's `sandbox-workload` and `sandbox-capacity`) | Each limit holds for the environment it bounds. F-R8 (§5a) is remedied by ADR-0056's Option B (owner-approved for implementation, 2026-10-31; **accepted** 2026-11-01): the neighbour test — once the finding's reproducer, required by no task — is required again, and still says F-R8 by name, measured, if the coupling returns. A holds at least `PIDS_LIMIT − 8` threads by its own count, its cgroup full by the runtime's (`docker stats`), so A's own bound stopped it; B is then served, measured clean, never drifted; both are destroyed by their exact labels. The negative control, `make sandbox-neighbour-mutations`, puts the backstop back at 256 and requires both neighbour tests to fail as F-R8 (run by hand, locally; not hosted). Hosted (run 41242001763): the ten `neighbour-*` and the four `capacity-*` cases passed — at the cap, by the job's log as the owner read it, 15 environments each at its own 256-task bound, 3 840 tasks of uid 10001, the 16th prepared, measured clean and served as uid 10001, all 16 destroyed by their labels. **Not shown:** memory or disk pressure beside a neighbour — each limit is shown alone (`resource-memory-oom-killed`, `workload-fills-to-enospc`); and isolation from uid-10001 processes DireWolf did not start, or from more than one full set of uncounted environments (ADR-0056 §5). |
| R9 | `persistence-tmp-marker-not-inherited`, `workload-nothing-persists`, `release-spares-another-runs-environment`, `release-other-run-still-runs`, `release-spares-another-runs-proxy-only-environment`, one environment per run (schema, ADR-0052 §4). Since M5e.2, on a real runtime: `cross-run-processes-not-visible`, `cross-run-other-environment-refused`, `cross-run-destroy-spares-the-other`, `cross-run-next-environment-holds-nothing-of-the-last` | Hosted (the cross-run cases passed in runs 40954372045 and 41130431929) | Run A sees none of run B's processes (process isolation), cannot name B's environment (environment ownership: `FOREIGN_ENVIRONMENT`), and destroying it leaves B's workload running (persistence and cleanup); the next environment is a fresh container holding nothing of A's. Run-scoped authority — a capability, a grant or a lease of one run never acting for another — is the authority's and its existing evidence's (M3, M5d.6's `release-*` cases), not these four; network-grant isolation between runs is per-environment by construction (each relay serves its own environment's grants) and **not separately attacked**. **Not shown:** A reaching B's relay (each relay listens in its own environment's namespace — `proxy-only-relay-shares-the-namespace-unprivileged` — but no cross-relay attempt is made). **By design and stated:** runs bound to one workspace directory share it (ADR-0052 §6) — a documented residual, not a gap. |
| R10 | `orphan-ended-record-reaped`, `reconcile-helper-orphan-reaped`, `broker-restart-orphans`, `foreign-*`; the release and lease teardown (`sandbox-release-evidence`, 62 + 45 cases) | Hosted | None for the cases. F-ABSENT (§5a, 2026-11-02): a removal, and a reconciliation's listing, are believed only from an answer the runtime gave — fixed as `f0f237f`, hosted-verified at its tests' levels by run 41446389484 (no. 120); a runtime that stops answering mid-operation is reproduced by no job. Its evidence side — each suite's `exists` — committed as `b6a8a1e`, hosted-verified by run 41471750928 (no. 121). |
| R11 | Reconciliation at an **authority** start: stopped environments destroyed, missing ones `LOST`, twins untouched. What a runtime restart leaves, each shown alone on a real runtime: a stopped environment refused before any workload (`workload-stopped-environment-refused`), a removed one never reported clean (`workload-environment-removed-mid-run-not-clean`), an unreachable runtime refused (`exit-runtime-unavailable`), an uncertain ending settled `UNKNOWN` and its environment destroyed (`unknown-ending-environment-destroyed`) | **Hosted — PASS** (run 41130431929's `sandbox-restart`, its first execution: all seven cases; passed again in run 41242001763) | Exercised hosted on 2026-10-30 (run no. 113): the interrupted workload was not believed, reconciliation settled within the bound (about 10.5 s, as the owner read the job's log; this checkout cannot read hosted logs, only the job's success), the stopped environments were reconciled, nothing was rerun, the foreign container was kept, and a new workload was served. It is never run locally: no developer's daemon is restarted. Since 2026-10-30, `sandbox-restart-evidence` in a required job of its own (`sandbox-restart`): the runner's Docker Engine restarted (`systemctl restart docker`) while run A's workload is in flight and run B's environment is idle, on the **same** authority incarnation — `restart-in-flight-not-believed`, `restart-reconciled-within-bound` (the engine answering again and reconciliation settling within the 120 s environment deadline), `restart-interrupted-environment-not-believed`, `restart-idle-environment-reconciled` (stopped: destroyed by its labels; still running under `live-restore`: measured again), `restart-in-flight-never-rerun`, `restart-foreign-untouched`, `restart-new-workload-served`, all `privileged-oci`. The task and the test each refuse before anything unless `DW_RUNTIME_RESTART=1` on a GitHub-hosted runner whose engine is a local systemd unit — never Docker Desktop, never a developer's daemon. What it holds is the accepted contract (no re-attach: `--restart no`, `UNKNOWN` never rerun, reconciliation by exact label), not a new one. |
| R12 | `tamper-substituted-probe`, `tamper-changed-byte`, `tamper-extra-field`, `tamper-truncated-output`, `tamper-malformed-output`, `tamper-flood-output`, `tamper-hang-timeout`; `drift-*`; `mount-substitution-destroys-before-the-workload` (the workspace's privileged half) | Hosted | None. |
| R13 | `fronting-residual-carried-and-bounded`, `budget-*`, `a08-tunnel-limit`, `a08-download-budget`, `a08-upload-budget` | Hosted | None; the residual stays stated (NETWORK_SECURITY.md). |
| R14 | — | **Missing** | No pip in any evidence image (the tools image copies the standard library only, `ensurepip` excluded), no registry fixture, no case. `pip` falls under the obligation's "anything else" row and is kept with **no** pip-specific neutralisation — reachable only under an operator policy without `argv_safe`, since the shipped packs deny `pip install` (R3) (§4, G3). [ADR-0055](adr/0055-m5e-pip-hygiene-profile.md) proposes the profile. M5e.3–M5e.5. |
| R15 | — | **Missing, and refused by design** | npm is `HYGIENE_NOT_EVIDENCED` (ADR-0052 §5a), although `npm_config_ignore_scripts=true` is already among the launcher's variables. ADR-0054 (Proposed) defines the profile and the evidence it needs. M5e.3–M5e.5. |
| R16 | `sandbox-agent-evidence` and `sandbox-release-evidence` lines carry `level` and `enforcement`; `environment.refused` and `environment.drifted` records; the broker's egress counted by disposition; since M5e.1 (complete: hosted run 40774766063 on `6fd0bc7`), every line of `sandbox-foundation-evidence`, `sandbox-egress-evidence`, `sandbox-workload-evidence`, `sandbox-secret-evidence` and `sandbox-workspace-evidence` too, each case held to its level and mechanisms (`scripts/dw.py`, `ATTRIBUTION`; SANDBOX.md §6a); M5e.2's in-process and real-runtime cases join the same contract | Hosted (M5e.1 complete) | Was: M5a, M5b and M5d.1–M5d.4 lines carried only `suite`, `case`, `outcome`. M5e.1 added attribution to every line, from existing events and measurements only (owner direction 4), and §6 says so (OD-E1, decided). No per-attempt audit event was added. |
| R17 | `tests/architecture/test_ci_*` (each job present, unconditional, required by `ci`, exact command; the task's and the eval's case lists equal); the strict eval gate under GitHub Actions; the reviewed baseline (`evals/baselines/main.json`, never rewritten by a run); mutation campaigns; the ADR history anchor | Hosted | Each new job, task and eval gets the same treatment (M5e.6). The negative controls run by hand for M5d.6 become committed tests. Built 2026-11-01 (ADR-0057, R-B), hosted-verified by run 41349869654 (no. 117, `e746aee`): the attributed gate also holds each line's outcome to what it claims (`outcome_problem` in `scripts/dw.py`) — an R2/R3 judgement shows the production decision's refusal by the host invariants that failed and a conforming record kept; a real weakened profile or topology says what caught it, its invariants of the vantage its enforcement claims — with a committed negative control for each (`tests/architecture/test_m5e_attribution.py`), and `tests/architecture/test_m5e_r3_closure.py` fails ADR-0057 accepted, or E6 or M5e.2 claimed, while R-B stands. |
| R18 | — | Deferred | `local` is M6's (ADR-0052 OD-7). The ROADMAP's M5 contract and M5e section say so, and M5's acceptance excludes it (OD-E5, decided). |

## 3a. R3's E6: coverage and feasibility (reviewed 2026-11-01, after run 41323258812)

A defensive review, not evidence: it reads the existing suites, tasks and hosted
results, builds and runs nothing new, and plans no container. Its question:
can any existing, authorised source stand for E6 — a real `PROXY_ONLY`
environment with one hard rule weakened, measured from the vantages
[ADR-0057](adr/0057-m5e-proxy-only-real-container-evidence-residual.md) §1a
names, and refused — without the experiment the safety control stopped?

**Each candidate source, against R-B.**

| Source | The target configuration (a real `PROXY_ONLY` environment, one hard rule weakened) exercised? | The runtime's own state measured? | The production decision invoked? | Meets R-B? |
|---|---|---|---|---|
| M5a's real weakened profiles (E3, `sandbox-foundation`) | No: each is `NO_NETWORK` — no relay, no proxy variables, no setup address in its namespace | Yes, both vantages (three host-only by design) | Yes: the broker's measurement fails exactly the invariants stated | No — the runtime's and the kernel's behaviour under `PROXY_ONLY`'s arrangement is what E6 asks (ADR-0057 §3, U1–U3) |
| M5b's real `PROXY_ONLY` topology (E1, E2, `sandbox-egress`) | No: every hard rule kept; only the topology's own invariants weakened or drifted | Yes, both vantages | Yes: clean environments kept, weakened topologies caught | No — no hard rule is weakened in them |
| The judgement over hand-written records (E5, `broker-assurance`) | No: a record, never a container | No: a record of the runtime's shape | Yes: `oci::clean` refuses, exactly the stated invariants failing | No — `in-process`; the host's vantage only |
| The judgement over a real runtime's own `PROXY_ONLY` record (E4, `captured-*`) | No: the record is real and conforming; the weakening is made in the test process | Yes for the conforming record; no for any weakened one — the runtime never ran it | Yes, as E5 | No — `in-process`; the host's vantage only |
| The broker's refusal and drift tests (`refusals-create-nothing`, `drift-*`, `workload-drifted-environment-refused`) | No: none weakens a hard rule under `PROXY_ONLY` | Yes | Yes | No |
| The probe's reports (digest-pinned, `tamper-*`) | No: every inside report under `PROXY_ONLY` is of a conforming environment | Yes | — | No (ADR-0057 §3, U2) |
| Runtime inspection and reconciliation (`foreign-*`, `crash-*`, `restart-*`) | No | Yes | Yes, for ownership and endings | No — not about the hard rules |
| An independent security laboratory's records | None exist, and none were provided | — | — | Not until genuine records meet §3b and the owner accepts them |

**By hard rule** (ADR-0057 §1a's rows; the seccomp rule twice). The same for
every row, so stated once: no authorised test exercises E6's observation,
none has occurred, the production refusal of a weakened real `PROXY_ONLY`
environment has never been exercised, and it is not permitted here while the
safety control stands — so each row is **BLOCKED**.

| Hard rule | The vantage(s) E6 needs | Real (`real-oci`): `NO_NETWORK` weakened (E3); `PROXY_ONLY` clean (E1) | In process (`in-process`): E5; E4 as `captured-` | E6 |
|---|---|---|---|---|
| Read-only root | both | `weakened-writable-root`; `proxy-only-prepare-clean` | `proxy-only-weakened-writable-root-refused` | BLOCKED |
| Non-root user | both | `weakened-root-user`; `proxy-only-prepare-clean` | `proxy-only-weakened-root-user-refused` | BLOCKED |
| Not privileged | both | `weakened-privileged`; `proxy-only-prepare-clean` | `proxy-only-weakened-privileged-refused` | BLOCKED |
| No runtime socket | both | `weakened-runtime-socket-mounted`; `proxy-only-prepare-clean` | `proxy-only-weakened-runtime-socket-mounted-refused` | BLOCKED |
| Capabilities dropped | both | `weakened-capability-added`; `proxy-only-host-capabilities-dropped`, `proxy-only-container-capabilities-empty` | `proxy-only-weakened-capability-added-refused` | BLOCKED |
| `no-new-privileges` | both | `weakened-no-new-privileges-disabled`; `proxy-only-prepare-clean` | `proxy-only-weakened-no-new-privileges-disabled-refused` | BLOCKED |
| Pinned seccomp, not unconfined | both | `weakened-seccomp-unconfined`; `proxy-only-prepare-clean` | `proxy-only-weakened-seccomp-unconfined-refused` | BLOCKED |
| Pinned seccomp, not the runtime's default | both | `weakened-seccomp-default-profile`; `proxy-only-prepare-clean` | `proxy-only-weakened-seccomp-default-profile-refused` (U4) | BLOCKED |
| Private PID namespace | both | `weakened-host-pid`; `proxy-only-prepare-clean` | `proxy-only-weakened-host-pid-refused` | BLOCKED |
| Private IPC namespace | host | `weakened-host-ipc`; `proxy-only-prepare-clean` | `proxy-only-weakened-host-ipc-refused` | BLOCKED |
| Private UTS namespace | host | `weakened-host-uts`; `proxy-only-prepare-clean` | `proxy-only-weakened-host-uts-refused` | BLOCKED |
| Isolated network | both | `weakened-host-network`; `proxy-only-host-network-isolated`, `proxy-only-container-network-isolated`, `proxy-only-container-direct-egress-refused`, `proxy-only-container-direct-dns-refused` | `proxy-only-weakened-host-network-refused` | BLOCKED |
| Image pinned by digest | host | `weakened-mutable-image-tag`; `proxy-only-prepare-clean` | `proxy-only-weakened-mutable-image-tag-refused` | BLOCKED |
| No devices | both | `weakened-extra-device`; `proxy-only-prepare-clean` | `proxy-only-weakened-extra-device-refused` | BLOCKED |
| Resource limits, the 8 192 backstop included | both | `weakened-resource-limits-dropped`, `drift-pids-limit-raised`; `proxy-only-prepare-clean` | `proxy-only-weakened-resource-limits-dropped-refused`, `proxy-only-weakened-swap-limit-lifted-refused`, `proxy-only-weakened-pids-and-swap-limits-lifted-refused` (U4); `captured-proxy-only-weakened-task-backstop-at-256-refused` | BLOCKED |

So: **implemented 0, exercised 0, passed 0, blocked 15, missing 15**. What
*can* be done safely was done in the gate rather than in containers (§3, R17):
every line R-B does count as supporting evidence now has to show what it
claims — and no line, document or record can count as E6.

## 3b. What genuine E6 evidence must carry (an acceptance specification, not a procedure)

Criteria for judging E6 evidence wherever it comes from — the owner-approved
plan ADR-0057 §8 requires, or an authorised independent security laboratory.
They say nothing about how such an environment is built, and approve nothing:
producing E6 needs the owner's plan within the safety control first. A record
is **rejected** — never a partial pass — when any criterion is missing.

1. **Authorisation.** The owner's written approval of the plan or engagement
   that produced it, given within the safety control, cited by date; and the
   environment it ran in, stated as isolated and disposable.
2. **Provenance.** The exact DireWolf commit (40 hex digits); the SHA-256 of
   the probe and relay that commit builds, equal to what the record's
   measurement pinned; the runtime's server and API versions, its OS and
   architecture, and the runtime client's identity — as
   `make sandbox-egress-evidence` prints them for E1 today.
3. **Authentic observations.** For each row of §3a: the runtime's own record of
   the environment as the broker read it, unedited, and the digest-pinned
   probe's own report from inside — the raw bytes, each with its SHA-256. A
   summary, a screenshot or a re-typed value is not an observation.
4. **Vantage attribution.** Each failing invariant attributed to the vantage
   that measured it — `HOST_*` from the record, `CONTAINER_*` from the probe —
   and both present wherever §3a says "both"; every line at `real-oci` (or
   `privileged-oci`, if that is what ran it), passing `require_attributed_evidence`
   with its outcome checks.
5. **`PROXY_ONLY`, really.** The broker measured the environment against a
   `PROXY_ONLY` specification, so the measurement reports every invariant that
   topology requires — its own (`HOST_PROXY_ENVIRONMENT`, `HOST_PROXY_RELAY`,
   `HOST_RELAY_DIGEST`, `CONTAINER_PROXY_REACHABLE`) included — and how the
   weakening and the topology interact is observed, not assumed (ADR-0057
   §3, U3).
6. **One hard rule at a time.** Each record weakens one row's hard rule; every
   invariant ADR-0057 §1a names for that row fails, from the vantage(s) it
   names; any other invariant that moves is reported, never hidden.
7. **The production refusal.** The production decision over that measurement
   refused the environment — never kept, never `READY` — through the broker's
   own measurement and decision, not a harness's re-implementation of either.
   A container that failed to start, or a judgement over an edited record, is
   not a refusal of a measured environment.
8. **Cleanup and ownership.** Every container, network and egress directory the
   evidence made removed by its exact labels, and every resource that predated
   it kept — the before-and-after census the egress task already takes.
9. **Completeness.** One record per row of §3a; a missing, unreadable or
   NOT EXERCISED row fails E6 as a whole.
10. **Integrity and reproducibility.** Every record and log digested (SHA-256),
    the run identified (a hosted run's URL, or the laboratory's run reference),
    and enough recorded to repeat it at the same commit.

**Rejected outright:** a result at another commit or runtime than stated; any
line relabelled from `in-process` or `NO_NETWORK`; a record edited after
capture; an external summary without its observations. External evidence is
never imported into a mandatory CI gate: the owner reviews it, and only an
accepted ADR that supersedes ADR-0057 can record it as closing E6 (ADR-0057
§8). Until then E6 is **BLOCKED**, R3 is not met and M5e.2 stays IN PROGRESS. The blocker is
tracked in [issue #19](https://github.com/Onwcan/DireWolf/issues/19); the issue records it and
approves nothing, and these criteria and the owner's R-B govern what can close it.

## 4. Gap analysis

- **G1 — Package-manager acceptance does not exist (R14, R15).** No pip or npm
  is in any evidence image; no registry fixture exists; no case runs either
  tool. The tools image (`scripts/dw.py`, `_tools_image`) is built offline
  `FROM scratch` from the host's own bytes — the host's git, Python's standard
  library without `ensurepip`, and the locked pytest.
- **G2 — npm is fail-closed (R15).** `npm`, `npx`, `pnpm`, `yarn`, `bun`,
  `cargo` and their wrappers are `HYGIENE_NOT_EVIDENCED`
  (`hygiene.rs`, `UNEVIDENCED`). The accepted ADR-0052 §5a lifts that only on
  real-tool evidence; a profile changes an accepted decision, so it needs its
  own ADR: ADR-0054.
- **G3 — pip is kept with nothing pip-specific (R14, R6).** Under the shipped
  packs `pip install` never reaches the obligation: they require `argv_safe`,
  and ADR-0045 §8's R3 names `install`, `download` and `wheel` as `pip`'s
  exec-style words (`python -m pip` is R1). Under an operator policy without
  `argv_safe`, a `pip` executable matches no family in `hygiene()` and is
  `Kept` with an empty prefix ("it reads none of them"), and `python -m pip`
  is the Python family (the variables, `-E` refused). pip reads its own configuration from the image
  (the operator's) and options from a requirements file in the workspace, can
  disable TLS verification for a host (`--trusted-host`), and runs a source
  distribution's build backend — package code, the same class of risk as an
  npm lifecycle script, which the obligation does neutralise for npm. The owner
  decided (OD-E2): a sibling ADR, [ADR-0055](adr/0055-m5e-pip-hygiene-profile.md) (Proposed), gives pip a profile; until
  it is accepted, pip's behaviour does not change.
- **G4 — Attribution is incomplete (R16).** See R16. Closed by M5e.1 once its hosted run
  passes.
- **G5 — Weakened-profile closure for `PROXY_ONLY` is not shown (R3).** See R3;
  plus `weakened-host-uts` (R2). Since 2026-10-31 shown in process over a real
  runtime's own record; still open at the real-container level, its residual
  proposed in [ADR-0057](adr/0057-m5e-proxy-only-real-container-evidence-residual.md) (Proposed) — not accepted: the owner
  selected R-B (2026-11-01), so E6 is required, and it is BLOCKED. U4 is
  closed in process (2026-11-01).
- **G6 — Runtime restart is not evidenced (R11).** Closed: hosted run
  41130431929's `sandbox-restart`.
- **G7 — Cross-run isolation is evidenced in parts, not as a suite (R9).**
- **G8 — No bounded neighbour case for exhaustion (R8).** Built in M5e.2, and it
  failed: finding F-R8 (§5a). Since 2026-10-31 remedied by ADR-0056's Option B
  and required again. Closed: hosted run 41242001763 passed it, and the owner
  accepted ADR-0056 on 2026-11-01.
- **G9 — `M5` is not an available milestone.** `AVAILABLE_MILESTONES` ends at
  `M5d` (`evals/src/direwolf_evals/runner.py`); the pending
  `pending-kernel/sandbox-egress` eval requires `M5` and has no runner. That
  runner's docstring still calls ADR-0052 Proposed — a stale comment, to be
  corrected with the runner's next change.
- **G10 — The M5 contract still lists `local` (R18).** Deferred to M6; the
  ROADMAP says so beside the contract, and M5's acceptance excludes it (OD-E5).

## 5. Architectural decisions

| Decision | Where | State |
|---|---|---|
| An evidence-backed npm profile for `workspace_exec_hygiene`, narrowly scoped (`npm ci` and `npm install` of registry packages only) | [ADR-0054](adr/0054-m5e-npm-hygiene-profile.md) | **Proposed** — would amend ADR-0052 §5a on acceptance |
| npm stays `HYGIENE_NOT_EVIDENCED` until ADR-0054 is accepted | ADR-0052 §5a (accepted) | In force |
| `local` is M6's | ADR-0052 OD-7 (accepted) | In force; recorded in ROADMAP M5e and the M5 contract |
| Package-manager tools for the evidence come from the hosted runner, at pinned versions verified by checksum | owner direction 3; OD-E4; this plan §8 | Decided |
| Attribution from existing events and measurements; no new per-attempt audit event; SANDBOX.md §6 reworded | owner direction 4; OD-E1; this plan M5e.1 | Decided |
| An unaccepted profile is reached only through an evidence-only start-up option | ADR-0054 §7; OD-E3 | Decided; the ADR stays Proposed |
| npm trusts only an operator trust file in the image; `--cafile`/`--ca` refused | ADR-0054 §§2–4; OD-E6 | Decided; the ADR stays Proposed |
| pip gets its own profile in a sibling ADR | [ADR-0055](adr/0055-m5e-pip-hygiene-profile.md); OD-E2 | Decided; drafted 2026-10-27, **Proposed** |
| M5's acceptance excludes `local`; `npm install` and `npm ci` both meet its npm scenario | ROADMAP M5e and M5 contract; OD-E5 | Decided |
| A container-runtime restart under a running authority is an M5e case, hosted-only | ROADMAP M5e; OD-E8 | Decided |
| F-R8's remedy: each environment's pids cgroup is its task bound, `RLIMIT_NPROC` a host-wide backstop of `PIDS_LIMIT × MAX_LIVE_ENVIRONMENTS × 2` | [ADR-0056](adr/0056-m5e-cross-run-task-limit-isolation.md) (Option B) | Owner-approved for implementation 2026-10-31; built (`615e77e`); its §6 evidence passed hosted (run 41242001763); **Accepted** by the owner 2026-11-01 — amends ADR-0047 §5 and ADR-0052 §10 |
| R3's real-container level: real `PROXY_ONLY` containers weakened one hard rule at a time were not built; the closure is shown by real topologies, real `NO_NETWORK` weakenings and the production judgement over a real runtime's own record | [ADR-0057](adr/0057-m5e-proxy-only-real-container-evidence-residual.md) | **Proposed**, 2026-11-01 — the owner **selected R-B** (2026-11-01): the real-container level is required; the residual is not accepted and its limited claim not approved; the record stays Proposed, outside the accepted digest |

## 5a. Findings

**F-R8 — environments share one host uid's task count (M5e.2, 2026-10-29; closed
2026-11-01 by ADR-0056, accepted).** Every environment's workload, and the probe the broker runs in it,
is host uid 10001 — there is no user-namespace remapping (SECURITY.md item 22; the profile's
`userns: remap`, SANDBOX.md §2, was not built). Each
environment's tasks are bounded twice at 256: by its own pids cgroup (`PIDS_LIMIT`) and by
`RLIMIT_NPROC` (ADR-0047's profile, `dwk-sandbox-profile`). The cgroup counts one
environment; `RLIMIT_NPROC` counts **the uid, across every environment**. So a workload
that holds its own environment's task bound exhausts the count every other environment
starts processes against.

*Observed* (local Docker 29.9.2, Docker Desktop on WSL2; the neighbour test, §3 R8): while
environment A's workload held its bound (`sandbox-fixture workload-hold-tasks`), the broker
refused B's workload `ENVIRONMENT_NOT_CLEAN` — the probe's measurement in B could not start.
A disposable diagnostic, run once and removed, exec'd the fixture in B by hand: as uid
10001 it failed `EAGAIN` ("resource temporarily unavailable"); as uid 10002, in the same
container at the same moment, it ran — B's own cgroup had room. Nothing was left behind:
the evidence's containers were removed and the four that predated it kept.

*Consequence* (read from the authority's code, `state/workload.rs` `destroy_reason`; not
exercised end to end): through `process.exec`, that refusal records the other run's
workload `FAILED` and destroys its environment as drifted — and by the same count a
preparation meanwhile cannot run its probe either. The window is A's wall clock; A's next
invocation can open it again.
It fails closed — nothing runs unmeasured, nothing crosses an environment, the broker and
the authority keep answering — but **one run can deny every other run its environment**.
It is not uncontrolled host exhaustion: the count is one uid's, at 256.

*Not changed:* no limit, profile or measured invariant was touched to make the case pass.
Each remedy changes ADR-0047's accepted profile or ADR-0052's identity model, so each is a
new ADR: a host uid per environment (user-namespace remapping, or a uid range the broker
allocates — which also touches the workspace's shared group 10001); or `RLIMIT_NPROC` raised
to a host-wide backstop at least the live-environment cap times `PIDS_LIMIT` (16 × 256),
leaving the per-environment bound to the cgroup alone. Until the owner decides, R8 is not
met and M5e.2 cannot be complete.

*The decision, drafted (2026-10-30):* [ADR-0056](adr/0056-m5e-cross-run-task-limit-isolation.md),
**Proposed**, compares the alternatives (a host uid per environment; the cgroup as the bound
with `RLIMIT_NPROC` a backstop; a parent cgroup; and four rejected) and recommends the second,
with the backstop at twice the live-environment cap times `PIDS_LIMIT` (8 192) — not
16 × 256, which leaves no room for a container the authority does not count. It changes
nothing until the owner accepts a remedy; its acceptance evidence (§6 there) restores R8 as a
required case, adds the same through the authority and at the cap, and a negative control
that fails with `nproc` back at 256. The reproducer now measures before it fails: how fast
the broker refused B, A's own count and refusal, and whether B serves again once A ends. Run
locally on 2026-10-30 (Docker 29.9.2): B refused `ENVIRONMENT_NOT_CLEAN` 1.25 s after asking
while A held 253 threads and its next was refused `EAGAIN`; A's residue proved clean; once A
ended B measured clean and served; nothing was left behind.

*The owner's decision (2026-10-31):* **Option B selected, its implementation authorised** —
not ADR-0056's acceptance, which follows its hosted evidence. *Built* (unstaged for the
owner's commit): `RLIMIT_NPROC` derived in `dwk-sandbox-profile` as
`PIDS_LIMIT × MAX_LIVE_ENVIRONMENTS × 2` = 8 192, a compile-time assertion beside it, the
plan's `--ulimit nproc=8192:8192`, and both vantages measuring it exactly (the same checks,
the value changed); `PIDS_LIMIT` (256), the live cap (16), every identity and every other
invariant unchanged. One deviation from the draft, recorded in ADR-0056 §2: the cap stays the
authority's, since accepted ADR-0047 §5 keeps the authority off the profile's crate; the
profile keeps a copy to size the backstop, and an architecture test holds the two equal. The
neighbour test is required again (§3, R8), with a second through the authority, a hosted-only
cap case in the new required `sandbox-capacity` job, and the negative control
(`make sandbox-neighbour-mutations`).

*Measured locally, 2026-10-31* (Docker 29.9.2, Docker Desktop on WSL2; hosted pending): at the
broker, A held 254 threads, its cgroup at 256 of 256 by the runtime's count — its own bound —
while B was served (exit 0, uid 10001) in 1.45 s, measured clean, the broker's collection
answering at once; both kept, then destroyed by their labels. Through the authority, while A
held 254 threads at 256 of 256, B's preview was answered in 1 ms and its `process.exec` —
environment prepared, judged `READY` and run — completed in 3.1 s; every workload of both runs
`COMPLETED`, both environments `READY`. The negative control, the backstop put back at 256,
failed both as F-R8: at the broker B was refused `ENVIRONMENT_NOT_CLEAN` in 1.24 s while A held
253 threads at 255 tasks — the uid's count reached before A's cgroup — and through the
authority B's `process.exec` was refused `ENVIRONMENT_UNAVAILABLE`; the file was restored
byte-identically. The cap case refused locally, NOT EXERCISED, as it must.

*Hosted, then accepted (2026-11-01):* the owner committed the remedy as `615e77e`, and
hosted run [41242001763](https://github.com/Onwcan/DireWolf/actions/runs/41242001763)
(run no. 114) passed, 29 of 29 jobs: `sandbox-workload` with its ten `neighbour-*` cases
among its 150, `sandbox-capacity` with its four `capacity-*` cases — 15 environments each at
its own 256-task bound, 3 840 tasks of uid 10001, the 16th prepared, measured clean and served
as uid 10001, all 16 destroyed by their labels, in about 327 s, by the job's log as the owner
read it (this checkout reads the jobs' conclusions, not their logs) — and `sandbox-foundation`
with `nproc` measured at 8 192 from both vantages. The owner then formally accepted
ADR-0056 on 2026-11-01: Option B, the backstop of 8 192, its deployment contract (§4 there)
and its residuals (§5 there) — one host uid for every environment, processes of uid 10001
DireWolf did not start, more than one full set of uncounted environments, and pressure other
than tasks beside a neighbour — none narrowed. **F-R8 is closed and R8 is met.** The negative
control has run by hand, locally, not hosted.

**F-RELAY — the relay's record was not held to three settings its plan asks for (M5e.2,
2026-11-02; fixed in process as `f3ae200`, whose hosted run
[41358634372](https://github.com/Onwcan/DireWolf/actions/runs/41358634372) — run no. 118 —
passed 29 of 29 jobs by their conclusions).** `HOST_PROXY_RELAY` judges the relay's record
(`inspect.rs`, `Record::relay_exact`) against its plan (`relay_plan.rs`), but did not read the
plan's `--cgroupns private`, its `--memory-swap` (the relay's 64 MiB, so no swap), or the
runtime's private UTS namespace — read for the environment, and for the relay its PID, IPC and
user namespaces were. A runtime that ran the relay in the host's cgroup or UTS namespace, or
with its swap unbounded, would have had it judged exact. Found by reading the code against the
plan; no container was run. These are the relay's settings — DireWolf's unprivileged forwarder
in the environment's network namespace — not the environment's hard rules: no hard rule,
profile constant, evidence case or level changes, and none of this is E6. *Built (committed as
`f3ae200`):* the three are read and required; the relay test's conforming record
carries them as the runtime records them, and the test refuses each weakened (host UTS, the
host's cgroup namespace, swap unlimited or doubled) and each unreadable — it failed before the
change, and removing any one of the three checks fails it again. The conforming relay on a real
runtime is `sandbox-egress`'s `proxy-only-host-proxy-relay`, which run 41358634372's
`sandbox-egress` job required and passed with the three checks in force; no weakened relay is
run.

**F-EVICT — a full workload table could forget an ending its authority had not collected
(M5e.2, 2026-11-02; fixed in process as `df4fa24`, whose hosted run
[41430527997](https://github.com/Onwcan/DireWolf/actions/runs/41430527997) — run no. 119 —
passed 29 of 29 jobs by their conclusions, its tests in `make test`).** ADR-0052 §8 keeps a workload's ending
"until it is collected", but the broker's supervisor (`sandbox/supervisor.rs`) evicted the
oldest *ended* workload from a full table, collected or not. The table is full in steady state
— an ended workload leaves it only by eviction, so after 16 workloads every start evicts one —
and the authority collects a parked launch only between its worker's other requests
(`server/worker.rs`). So a start, of any run, that reached the broker after another run's long
workload ended and before that ending was collected evicted it: the collection found nothing,
and the authority recorded the finished workload `UNKNOWN` (`WORKLOAD_UNCONFIRMED`) and destroyed
its environment. It fails closed — nothing ran unjudged, nothing crossed an environment — but one
run could cost another its result and its environment. Found by reading the supervisor against
ADR-0052 §8 and the worker; reproduced in process, not on a runtime. *Built (committed as
`df4fa24`):* an ending is marked once a collection answers it; a full table evicts its
oldest collected ending, or one nobody collected for `WORKLOAD_SUPERVISION_SECONDS` — an
authority that stopped, or recorded its workload `UNKNOWN`, never collects it, and such endings
would otherwise fill the table for good — and otherwise refuses `WORKLOAD_TABLE_FULL`, nothing
run. Two supervisor tests failed before the change (an uncollected ending evicted; a table of
uncollected endings admitting a start), a third holds the horizon; 4 of 4 mutants killed.

**F-TEARDOWN — a preparation whose teardown failed could be answered as a refusal (M5e.2,
2026-11-02; fixed in process as `df4fa24`, hosted with F-EVICT in run 41430527997).** The broker's `prepare` (`sandbox/oci.rs`)
takes an environment that did not measure clean down whole — helpers, environment, proxy — but
answered with the teardown's own refusal when one of its steps refused. A refusal tells the
authority that provably nothing remains: it records the environment `REFUSED` — final, not
counted live, never destroyed — while the refused step (a listing the runtime failed, a client
file changed since it was proved, a malformed record) may have left the environment that did
not measure clean, or its relay, running until the authority's next start reconciles by label.
`prepare`'s two other teardowns, after a failed start or measurement, already answered
`Unconfirmed`. Found by reading; not run on a runtime. *Built (committed as `df4fa24`):* an
environment not kept is answered `Unconfirmed` whenever its teardown did not finish, so the
authority records it `UNKNOWN` — counted live, and destroyed by its labels. The test failed
before the change (`Refused(RUNTIME_UNAVAILABLE)` answered); 2 of 2 mutants killed. Neither
finding changes a hard rule, profile constant, invariant, evidence case or level, and neither is
E6.

**F-ABSENT — a runtime the client could not ask was read as a container gone (M5e.2,
2026-11-02; fixed in process as `f0f237f`, whose hosted run
[41446389484](https://github.com/Onwcan/DireWolf/actions/runs/41446389484) — run no. 120 —
passed 29 of 29 jobs by their conclusions, at its tests' levels; the interruption itself is not
reproduced on any runtime).** The broker proves a container gone
from the runtime's record (`sandbox/oci.rs`, `record`): its client's `container inspect`
answering an empty array — after a removal (`remove`, and so every teardown and destruction),
before one (`destroy`, `AlreadyGone`), for a helper, and for how a workload's environment ended.
A reconciliation's listing (`list`) read the same answer the same way: a container missing from
an inspection that failed was one removed since the listing. But the client answers that way
whenever it could not ask: against a runtime it cannot reach — its socket gone, its engine
restarting — Docker's CLI 29.9.2 prints exactly `[]` and exits 1, the reason on stderr only,
byte for byte what it prints for a container the runtime does not hold (observed against a
socket path that does not exist; nothing was created). So a runtime that stopped answering
between two of the broker's steps proved a container gone: a removal whose own command failed
answered `Removed`, and the authority recorded the environment `DESTROYED`; a not-clean
environment's teardown, or a failed start's, answered as complete, and the authority recorded
`REFUSED` — each final and not counted live, while the container stood — still running whatever
ran in it, its workspace mounted, unless a restart of the runtime without `live-restore` stopped
it — until the authority's next start reaped it as an orphan. And a reconciliation whose
inspection failed after its listing answered a
complete listing of no environment: every live record went `LOST`, or `DESTROYED`, every
container still standing — where its own contract says a runtime that cannot be listed
completely changes nothing. It fails open in the authority's accounting, never across an
environment: each one keeps its own profile, but drops out of the live count that the cap of 16
and ADR-0056's backstop (twice the cap's tasks) are sized against, and out of reach of every
destruction but the next start's. Found by reading `record` against the client's error path; the
client's answers were observed, no environment was run for it. *Built (committed as
`f0f237f`):* absence is believed only from a listing the runtime answered — an empty inspection is
checked by the client's `container ls --all --filter id=<id>`, which fails when the runtime did
not answer, and a container it still holds, or a listing that failed, is `RUNTIME_UNAVAILABLE`,
so a removal is `Unconfirmed`; and a reconciliation's listing is complete only when each
container it named was inspected, or a second complete listing the runtime answered no longer
holds it. Two tests failed before the change (an empty inspection taken as absence; a failed
inspection taken as a store without environments) and pass after it; 7 of 7 mutants killed.
Locally on Docker 29.9.2 (Docker Desktop on WSL2, before the commit), the real-runtime suites
that remove, destroy and reconcile passed with the change: `sandbox-foundation` (109 `real-oci`
and 20 `in-process` lines), `sandbox-release` (19 `real-oci`, 26 `dwkp-end-to-end`, 62
`fake-broker`), `sandbox-workload` (112 `real-oci`, 38 `dwkp-end-to-end`) and `sandbox-egress`
(104 `real-oci`, 19 `in-process`), the four containers that predated them kept and none left
behind. The failure itself — a runtime that stops answering between two steps — is not
reproduced on a runtime: no engine is stopped for it. No hard rule, profile constant, invariant,
evidence case or level changes, and none of this is E6. Hosted, run 41446389484 ran F-ABSENT's
unit tests in `make test` and every required real-runtime job over the changed removal,
destruction and listing, and passed; that shows the change keeps every existing case, at its
level, and that the decision holds as unit-tested — not a runtime that stopped answering
mid-operation, which no hosted job does either.

*The evidence's side (2026-11-02; committed as `b6a8a1e`, whose hosted run
[41471750928](https://github.com/Onwcan/DireWolf/actions/runs/41471750928) — run no. 121 —
passed 29 of 29 jobs by their conclusions).* The real-runtime
suites held the same weakness in their own assertions: each of seven (`sandbox_foundation.rs`,
`sandbox_egress.rs` and `sandbox_workload.rs` at the broker; `sandbox_agent.rs`,
`sandbox_lifecycle.rs`, `sandbox_secret.rs` and `sandbox_workload.rs` at the authority) asked
whether a container exists by its client's `container inspect` exiting 0, so an assertion that
the broker or the authority had removed one — 50 of the 90 calls are `!…exists(…)` — would pass
against a runtime that did not answer. The tasks' before-and-after census is no backstop for
those: each test's reaper removes its store's containers before the census is taken, so the
census shows what the evidence left, never whether a removal it claimed was the product's. *Built
(committed as `b6a8a1e`):* every suite's `exists` asks one shared listing,
`crates/*/tests/runtime_support` — the client's `container ls --all --filter id=<id>` for a full
id only — which answers only from a listing the client succeeded at and fails its test on
anything else: a failed client, another id, two, an unreadable line, a name or a short id. Its
unit tests run in `make test`; their negative control gives it the client's answers to an
unreachable runtime as Docker's CLI 29.9.2 prints them, which the replaced helper read as gone,
and requires the test to fail. An architecture test (`test_m5e_attribution.py`) holds the two
crates' copies equal, every suite's `exists` to it, and no suite's existence to an inspection's
exit status. No case, level, task, CI job or production line changes; the census stays as it was,
mandatory and checked. Hosted, run 41471750928 ran those unit tests and that architecture test in
`make test`, and every required real-runtime job with the new `exists`, and passed — the
assertions' logic and wiring, at their levels; it stops no runtime either.

**Additional review, 2026-11-02, after baseline run #122:** two new, independently
reproduced defects are fixed, hosted-verified since by run 41535101815 (below). **F-RELPROP:** `inspect::relay_exact` omitted requested and effective
bind propagation even though `relay_plan` requests `rprivate`; both now must match,
with 20 negative record mutations and two conforming controls. **F-PROXY-CLOSE:**
runtime re-proof could refuse before `Sandbox::destroy` entered its callback and
closed the proxy; closing now occurs outside that callback, preserving the refusal
and the neighbour's proxy. Both regressions fail against the original behavior
and pass with the fixes, **in process**; those regressions create no OCI container.
The [closure assessment and review handoff](M5E2_FINAL_CLOSURE_REVIEW.md) records
evidence qualification, alternative paths, validation and limitations, including the
overbroad execution of the existing E2 topology-mutation target during validation.
Neither fix is E6: all 15 rows remain **BLOCKED**, ADR-0057 **Proposed** under R-B,
M5e.2 **IN PROGRESS** and M5e.3–M5e.6 **NOT STARTED**.

**Independent review, 2026-11-03:** both reproductions hold — each regression fails
on the code before its fix, and each `rprivate` comparison, removed alone, fails its
test. The review found that the new comparison masked three existing relay-mount
negative controls: their mutated records carried no propagation, so removing the
relay's `RW` or `Source` check passed every test. Those records now carry the plan's
propagation, and a new test changes each field of the relay's one mount alone, on the
requested and the effective record, and gives the mount twice; each of the relay
mount's twelve comparisons, removed alone, now fails a test. Test-only: no production
line changed. The destruction's accounting limit stands as the closure assessment
states it: a refused or indeterminate destruction answers no counters, and a later
retry finds the proxy closed — as a runtime failure inside the callback already did.
Committed as `396d87b`; hosted, run 41535101815 (no. 123) ran both regressions and the
relay-mount tests in `make test` and passed — at their levels, in process; neither is E6.

## 6. Safe implementation sequence

Each step keeps every production control as it is; each lands with its own
local gates, then the owner's commit and a hosted run, before the next — with one
exception, the owner's (§10, "M5e.3's sequencing"): M5e.3 may proceed while M5e.2 is
open. No step enables npm in production.

| Step | Delivers | Product change | Exit |
|---|---|---|---|
| **M5e.1** Attribution | `level` and `enforcement` on every line of `sandbox-foundation`, `sandbox-egress`, `sandbox-workload`, `sandbox-secret` and `sandbox-workspace` evidence, each naming the existing mechanism (the probe's measured invariant, `environment.refused`/`.drifted`, the proxy's decision and the egress disposition counters, the authority's refusal, the namespace's errno, the client's own TLS verification); each `require_*` refuses a line without them; SANDBOX.md §6 reworded: a contained attempt is attributed, not individually audited (OD-E1) | none (test, task and documentation) | every existing case still reports, now attributed; the negative controls of M5d.6 generalised |
| **M5e.2** Closure | the profile weakenings on `PROXY_ONLY` (R3), `weakened-host-uts` (R2); the cross-run suite (R9); a bounded neighbour case (R8); a runtime restart under a running authority (R11), hosted-only | none expected; a finding is a separate, reviewed change | each new case required by name; the restart case NOT EXERCISED locally, required hosted |
| **M5e.3** Fixtures | §7's registries, generated deterministically from synthetic content, served by the existing per-run-PKI HTTPS origin on loopback through the broker's evidence-only resolver; unit tests of the generators | none | fixtures reproducible bit for bit from a seed; no network beyond loopback |
| **M5e.4** pip, and npm refused | a registry tools image built **on the runner** (§8); pip against the granted fixture registry and against an ungranted one; npm **refused** `HYGIENE_NOT_EVIDENCED` before anything is prepared — today's fail-closed behaviour, evidenced | none: pip as it is today, what it does not neutralise stated; [ADR-0055](adr/0055-m5e-pip-hygiene-profile.md)'s profile is M5e.5's, behind the same evidence-only fence as npm's (OD-E2) | `make sandbox-registry-evidence` hosted-green; locally NOT EXERCISED, by design |
| **M5e.5** The npm profile | ADR-0054's profile in `hygiene.rs`, reachable only through the evidence-only option (ADR-0054 §7, OD-E3), npm trusting only the image's trust file (OD-E6); its evidence (ADR-0054 §8) and its hosted mutation review (OD-E7) | yes, behind the decided fence; production still fail-closed | every ADR-0054 §8 case hosted-green |
| **M5e.6** The gate | an eval suite requiring `M5e` that runs the M5 evidence tasks and requires every case at its level with its attribution; architecture tests for each new job; committed negative controls; the owner's decisions; on ADR-0054's acceptance, npm's profile enabled; then `M5` joins the available milestones and `pending-kernel/sandbox-egress` gets its runner | the enabling change only after acceptance | hosted green on the committed tree; M5's acceptance is the owner's |

Where each step stands (2026-10-29): **M5e.1 COMPLETE** (hosted run 40774766063). **M5e.2 BUILT in part, hosted verification pending** — no product change, no new CI job: R2 and R3 in process, required by `sandbox-foundation-evidence`; R9 on a real runtime, required by `sandbox-workload-evidence`. R8's neighbour case is built and **fails** — finding F-R8 (§5a) — so no task requires it. Two of its deliverables are **not built**: real `PROXY_ONLY` containers weakened one hard rule at a time, and R11's runtime restart under a running authority (hosted-only, OD-E8). M5e.3–M5e.6 are not started.

Where each step stands (2026-10-30): R2 and R3 in process and R9 **hosted-verified** (run 40954372045's `sandbox-foundation` and `sandbox-workload` jobs); R2's real-container `weakened-host-uts` added; R11's hosted restart **built** as the required `sandbox-restart` job, never executed; the three privileged jobs CI #106 lost repaired, unverified until the next hosted run; R8 **fails** and F-R8 is open, its remedy proposed in ADR-0056; real weakened `PROXY_ONLY` containers still not built. **M5e.2 is IN PROGRESS**, and cannot close before the owner decides F-R8, its evidence passes, and R11 passes hosted.

Where each step stands (2026-10-31): the CI #106 repair, R2's `weakened-host-uts`, R9 and **R11 hosted-verified** (run 41130431929, 28 of 28 jobs). F-R8's remedy — ADR-0056's Option B, selected by the owner for implementation — **built**, with R8 required again at the broker and through the authority, its cap case hosted-only (`sandbox-capacity`) and its negative control; R3 judged over a real runtime's own `PROXY_ONLY` record, in process. All pending the owner's hosted run. Real weakened `PROXY_ONLY` containers stay **NOT EXERCISED** (not built). **M5e.2 is IN PROGRESS (partial)**: it closes when the hosted run passes R8 and the cap, the owner accepts ADR-0056, and the owner decides whether R3's real-container level is required or its residual accepted. M5e.3 is NOT STARTED; its handoff is §7a.

Where each step stands (2026-11-01): hosted run 41242001763 (`615e77e`, 29 of 29 jobs) passed R8 — the neighbour at the broker and through the authority, and the cap — and R3's captured-record cases (`in-process`); R11 passed again. The owner **accepted ADR-0056** on 2026-11-01, so F-R8 is closed and R8, R9 and R11 are hosted-verified. What is left of M5e.2 is R3's real-container level: real `PROXY_ONLY` containers weakened one hard rule at a time are **NOT EXERCISED** (not built), and whether that level is required or its residual accepted is the owner's separate decision — neither ADR-0056's acceptance nor any in-process case decides it. **M5e.2 stays IN PROGRESS** until it is decided. M5e.3 is NOT STARTED. The residual is recorded for that decision in [ADR-0057](adr/0057-m5e-proxy-only-real-container-evidence-residual.md), **Proposed**.

Where each step stands (2026-11-01, R-B): hosted run 41304247232 (`576b249`, 29 of 29 jobs) passed with ADR-0057 committed. The owner selected **R-B**: R3 needs E6, real `PROXY_ONLY` containers weakened one hard rule at a time, which is **BLOCKED** — not built and not planned while the earlier safety control stands — and no other evidence stands in for it. ADR-0057's U4 is closed in process (built, hosted run pending). **M5e.2 is IN PROGRESS, R3 E6 BLOCKED**: it closes only once E6 exists under a plan the owner approves within that control, passes hosted at `real-oci`, and the owner closes the milestone. M5e.3 is NOT STARTED.

Where each step stands (2026-11-01, U4 hosted): hosted run 41323258812 (`b25c3e6`, run no. 116, 29 of 29 jobs) passed U4's three cases over both records, `in-process`, with every other required case of the 29 jobs. R2, R8, R9 and R11 stay hosted-verified; of R3, E1–E5 are evidenced at their levels and **E6 is BLOCKED** — reviewed against every existing source (§3a), none observes it, and §3b states what genuine E6 evidence must carry. Built since, unstaged, hosted run pending: the gate's outcome checks and the R-B guard (§3, R17). None of it is E6, and none closes R3. **M5e.2 is IN PROGRESS, R3 E6 BLOCKED**; M5e.3 is NOT STARTED.

Where each step stands (2026-11-02): hosted runs 41349869654, 41358634372 and 41430527997 (`e746aee`, `f3ae200`, `df4fa24`; run nos. 117–119, 29 of 29 jobs each) passed the gate's outcome checks and the R-B guard (R17) and the fixes of F-RELAY, F-EVICT and F-TEARDOWN (§5a). R2, R8, R9, R10 and R11 stay hosted-verified; of R3, E1–E5 are evidenced at their levels and **E6 is BLOCKED**, unchanged. Built since, unstaged, hosted run pending: F-ABSENT's fix (§5a). None of it is E6, and none closes R3. **M5e.2 is IN PROGRESS, R3 E6 BLOCKED**; M5e.3 is NOT STARTED.

Where each step stands (2026-11-02, F-ABSENT hosted): hosted run 41446389484 (`f0f237f`, run no. 120, 29 of 29 jobs) passed F-ABSENT's fix at its tests' levels; a runtime that stops answering mid-operation is reproduced by no job. R2, R8, R9, R10, R11 and R17 stay hosted-verified; of R3, E1–E5 are evidenced at their levels, E6 has no qualifying exercised case and all 15 of its rows are **BLOCKED** (§3a), unchanged. Built since, unstaged, hosted run pending: the evidence's side of F-ABSENT, each real-runtime suite's `exists` (§5a). None of it is E6, and none closes R3. **M5e.2 is IN PROGRESS, R3 E6 BLOCKED**; M5e.3 is NOT STARTED, and does not start before M5e.2 closes (§7a).

Where each step stands (2026-11-02, evidence side hosted): hosted run 41471750928 (`b6a8a1e`, run no. 121, 29 of 29 jobs) passed F-ABSENT's evidence side. Done, and hosted-verified at its tests' levels: the engineering hardening M5e.2's reviews found (§5a). Not met: M5e.2's acceptance — R3 needs E6, which has no qualifying evidence; all 15 of its rows are **BLOCKED** (§3a) and [issue #19](https://github.com/Onwcan/DireWolf/issues/19) tracks it. ADR-0057 stays **Proposed**, the owner's R-B binding; a runtime that stops answering between two of the broker's steps is still reproduced by no job. **M5e.2 is IN PROGRESS, R3 E6 BLOCKED**; M5e.3–M5e.6 are NOT STARTED.

Where each step stands (2026-11-03, M5e.3 sequencing): hosted run 41535101815 (`396d87b`, run no. 123, 29 of 29 jobs) passed F-RELPROP's and F-PROXY-CLOSE's fixes at their tests' levels (§5a). M5e.2's acceptance is still not met: R3 needs E6, all 15 of its rows are **BLOCKED** (§3a), [issue #19](https://github.com/Onwcan/DireWolf/issues/19) tracks it, and ADR-0057 stays **Proposed** under R-B. By the owner's sequencing exception (§10), M5e.3 may start ahead of M5e.2's close, as §7a orders it — the deterministic, offline generators and fixtures first; it is NOT STARTED. M5e.4–M5e.6 still follow M5e.2's close, and M5e.6's gate and M5's acceptance wait for E6. **M5e.2 is IN PROGRESS, R3 E6 BLOCKED**; M5e.3–M5e.6 are NOT STARTED.

Where each step stands (2026-11-03, M5e.3's offline fixtures): M5e.3 is **IN PROGRESS**, out of sequence: its generator, PEP 503 index and npm registry are built with their unit tests and §7a's guard (§7a), unstaged, hosted run pending; the per-run CA and the origins are not. Nothing of it is evidence or touches R3: E6 stays **BLOCKED**, all 15 rows, [issue #19](https://github.com/Onwcan/DireWolf/issues/19) OPEN, ADR-0057 **Proposed** under R-B. **M5e.2 is IN PROGRESS, R3 E6 BLOCKED**; M5e.3 is IN PROGRESS; M5e.4–M5e.6 are NOT STARTED.

Where each step stands (2026-11-04, M5e.3 built): hosted run 41720068934 (`6be8c41`, run no. 126, 27 of 29 jobs) failed only Windows' `make test`: two fixture tests whose marker directory was pytest's Windows `tmp_path`. Fixed since (§7a), unstaged, hosted run pending. Built since, unstaged, hosted run pending: M5e.3's per-run CA and its two origins, with the proxy's side shown in process (§7a). So M5e.3's implementation is complete under the owner's exception; it closes on its hosted run. M5e.2 is **PARTIALLY IMPLEMENTED / ASSURANCE BLOCKED**: its engineering is hosted-verified; E6 is required and **BLOCKED**, all 15 rows, [issue #19](https://github.com/Onwcan/DireWolf/issues/19) OPEN, and ADR-0057 **Proposed** under R-B. **M5e.2 is IN PROGRESS, R3 E6 BLOCKED**; M5e.3's implementation is complete, hosted validation pending; M5e.4–M5e.6 are NOT STARTED.

## 7. Hermetic fixtures

All synthetic, generated at test time from a seed, served on loopback, never
fetched:

- **A PEP 503 "simple" index** over HTTPS: a pure-Python wheel (`ZIP` with
  `METADATA`, `WHEEL` and `RECORD` written by the standard library) whose import
  writes nothing; a second wheel depending on the first; a source distribution
  whose build backend would write a marker if it ran (to show whether pip
  builds it); a wheel carrying a `.pth` file that would write a marker if it
  ran; an image `pip.conf` naming the ungranted index; and a certificate the
  image's system store trusts but pip's pinned trust file does not
  (ADR-0055 §9). No tampered-wheel case: outside hash-checking mode pip does
  not check a wheel against its index, and ADR-0055 §7 says so.
- **An npm registry**: a packument (`GET /<name>`) per package and its `.tgz`
  (written with `tarfile`), with `dist.integrity` (sha512) and `dist.tarball`;
  a package with `preinstall`, `install`, `postinstall` and `prepare` scripts
  that would each write a marker; a dependency whose tarball URL names an
  ungranted host; a dependency named by a git URL, whose `prepare` script
  would write a marker; a packument redirecting to an ungranted host; a tampered
  tarball; a `package-lock.json` the evidence generates for `npm ci`; and a
  workspace `.npmrc` that tries to turn scripts back on, change the user and
  global configuration, turn TLS verification off and name its own CA.
- **Two origins**: the granted registry and an ungranted one with a valid
  certificate from the same per-run CA, so a refusal is the proxy's decision,
  never a TLS failure.
- **A per-run CA**, baked into the registry tools image when it is built — the
  image is built per run anyway — at npm's trust path (`/etc/direwolf/npm-ca.pem`,
  ADR-0054 §4, OD-E6) and at pip's (`/etc/direwolf/pip-ca.pem`, ADR-0055 §5).
  Never a production setting, and never in the workspace.
- Reached through the broker's evidence-only resolver
  (`--allow-evidence-egress`, logged as such), as M5b and M5d.5 do: the
  production IP guard is unchanged and still refuses loopback.

## 7a. M5e.3 handoff (prepared 2026-10-31; M5e.3 out of sequence since 2026-11-03, built 2026-11-04, hosted validation pending)

M5e.3 was to start only once M5e.2 had closed — its hosted run (passed, run
41242001763), ADR-0056's acceptance (2026-11-01), and R3's real-container level, which the owner required on 2026-11-01
(R-B on [ADR-0057](adr/0057-m5e-proxy-only-real-container-evidence-residual.md)) and which is BLOCKED (E6, not built).
On 2026-11-03 the owner made one narrow exception to that order (§10, "M5e.3's
sequencing"): M5e.3 may proceed while M5e.2 stays open. It changes when this step may
start, not what it is or what any other step requires. The order within it: the
generator, the index and the registry first — deterministic, offline, standard
library only, no socket — then the per-run CA, which cannot come from a seed (it
is made afresh for every run, as `tests/net_http/make-pki.sh` makes the
net.http evidence's), and the origins. The table is the brief, not evidence;
what is built of it is recorded below it.

| Piece | Build | Done when |
|---|---|---|
| Generator | one standard-library-only module, `generate(seed, out)`; every byte from the seed: fixed timestamps (ZIP's 1980-01-01, tar and gzip at 0), sorted entries, fixed tar owner, group, mode and names, no host path; package names and versions derived from the seed | the same seed gives byte-identical output twice, another seed differs — unit tests, local and hosted |
| PEP 503 index | `/simple/` and `/simple/<name>/` pages, each link carrying `#sha256=`; a pure-Python wheel whose import writes nothing; a second wheel depending on it; a source distribution whose build backend would write a marker; a wheel whose `.pth` would write one; an image `pip.conf` naming the ungranted index | each wheel's `RECORD` matches its contents; the pages parse with the standard library's HTML parser |
| npm registry | a packument per package (`dist.tarball`, `dist.integrity` as `sha512-…`) and its `.tgz` under `package/`; `preinstall`, `install`, `postinstall` and `prepare` scripts each writing a marker; a dependency whose tarball names the ungranted host; a git-URL dependency with `prepare`; a packument redirecting to the ungranted host; a tarball tampered against its integrity; a generated `package-lock.json` for `npm ci`; a workspace `.npmrc` that tries to re-enable scripts, change the user and global configuration, turn TLS verification off and name its own CA | every untampered tarball matches its SHA-512 integrity and the tampered one does not; the lockfile names exactly the packuments' integrity |
| Origins | the granted registry and an ungranted one on loopback, each served by the existing per-run-PKI HTTPS origin, reached only through the broker's evidence-only resolver | a refusal of the ungranted one is the proxy's decision, never a TLS failure |
| Per-run CA | generated per run, never committed and never in a workspace; M5e.4 bakes it into the registry tools image at npm's one trust file (`/etc/direwolf/npm-ca.pem`, OD-E6: image CA only) and pip's (`/etc/direwolf/pip-ca.pem`, ADR-0055 §5) | — |
| Guards | the production IP guard unchanged — loopback refused outside the evidence-only resolver; no fixture fetched from, or naming, a public host; no real third-party package at any time | an architecture test holds the generator to the standard library, no network module, no public host name |

**Built (2026-11-03), unstaged, hosted run pending: the generator, the index and
the registry.**

- **The generator.** `tests/sandbox/registry_fixtures.py`, `generate(seed, out)`:
  - standard library only, and nothing but bytes;
  - every name, version and module value from the seed (`dwfx-<tag>-<role>`);
  - archives sorted and stored, not compressed: ZIP entries of 1980-01-01, tar
    members 0644 of owner 0 modified at 0, gzip modified at 0 around stored
    blocks — so no compressor's version changes a byte.
- **Its output.** What each origin serves, by route (a file, or a 302 to the
  ungranted host); the image `pip.conf`; the npm project with its lockfile; the
  hostile `.npmrc`; and a manifest of the seed, the two hosts (RFC 6761's
  `granted-registry.test` and `ungranted-registry.test`), every package by
  role, every marker and every file's SHA-256.
- **Markers.** Empty files in the workspace (`/workspace`, the profile's
  `WORKSPACE_TARGET`).
- **Beyond the table's rows,** for ADR-0055 §9's cases:
  - a granted page whose file is on the ungranted host;
  - a page redirected to that host;
  - the ungranted index and registry each serving a package, so pointing at
    either finds what it asked for and a refusal can only be the proxy's.
- **The git dependency's tree** is emitted but routed by no origin: none speaks
  git, and its URL names the ungranted host.
- **The unit tests** (`tests/sandbox/test_registry_fixtures.py`, in `make
  test`) hold the generator's, the index's and the registry's "done when":
  - same seed same bytes, another seed different, a fixed seed's bytes
    recorded by digest, no output naming where it was written;
  - fixed archive metadata, every RECORD, every page and link hash;
  - every integrity, the tampered tarball, the lockfile;
  - that each marker is written when its code runs: the `.pth` under
    `site.addsitedir`, each build-backend hook in process, and every npm
    script by the one command template (no `node` runs here: package-manager
    tools are hosted-only, the owner's direction 3, §1). A missing marker
    therefore cannot mean broken code.
- **The guard** (`tests/architecture/test_m5e_registry_fixtures.py`) is the
  Guards row's architecture test. It holds the generator to:
  - the standard library, with no network, process, dynamic-import or C module
    and no code-running builtin;
  - no literal URL host in its source;
  - only its two `.test` hosts in everything it generates;
  - only its own packages and dependencies;
  - markers in the profile's workspace.
- **Not built on 2026-11-03:** the per-run CA and the origins (below).

**Fixed and built (2026-11-04), unstaged, hosted run pending: Windows, the per-run CA
and the origins.**

- **The Windows marker directory.** Hosted run 41720068934, `make test` on
  windows-latest: `generate()` took only a POSIX marker directory, so pytest's
  `tmp_path` (`C:\Users\runneradmin\...`) was refused and two tests failed.
  - **Now:** a marker directory is an absolute POSIX or Windows path of plain
    segments (`[A-Za-z0-9._~-]`), with no `.` or `..`, in one canonical form:
    forward slashes, no trailing one. Python and Node accept that form on both
    platforms. One function, `marker_path`, builds every marker.
  - **What reaches generated code:** only `[A-Za-z0-9._~/:-]` reaches the
    generated Python, JavaScript and shell text, so no quoting can change what
    it runs.
  - **Determinism:** the default `/workspace` writes the same bytes as before,
    so the recorded digest is unchanged.
  - **Tests:**
    - each accepted spelling, POSIX and Windows, and its canonical form;
    - the refused ones: relative, drive-relative, UNC, `.` and `..`, quotes, a
      backslash in a POSIX path, `$`, backtick, `%`, space, control and
      non-ASCII characters;
    - the npm command split as a POSIX shell splits it, and the `.pth`'s and
      the backend's paths parsed back;
    - the same fixtures, byte for byte, for every spelling of one directory;
    - markers written where this host's own spelling, with a trailing
      separator, names.
  - **Run locally:** on native Windows Python 3.12 with the test files
    unchanged; hosted Windows pending.
- **The per-run CA.** `tests/net_http/make-pki.sh`, the net.http evidence's
  per-run PKI, now also makes, afresh every run in a temporary directory and
  never committed:
  - `registry-granted` and `registry-ungranted`: each origin its own name,
    under the same anchor;
  - `registry-rogue`: the granted name under the rogue authority;
  - a third authority, `system`, and `registry-system`, the granted name under
    it: what an image's system store may trust and a registry tool's pinned
    trust file must not (ADR-0055 §9).
- **The origins.** `tests/net_http/origin.py --routes manifest.json --side
  granted|ungranted` is the existing per-run-PKI HTTPS origin on 127.0.0.1,
  answering exactly that side's routes in the generated manifest:
  - each file with its content type, read once at start from the manifest's
    own directory, or its redirect;
  - 404 for any other path, 405 for any method but GET, and `Connection: close`
    on every response;
  - it refuses to start on a route naming a file outside that directory, or on
    a side the manifest lacks;
  - its net.http paths are unchanged.
- **Their tests** (`tests/sandbox/test_registry_origins.py`, in `make test`;
  Linux only, where the PKI script and the evidence run). A standard-library
  client that verifies the certificate and its name, trusting the per-run
  anchor alone, shows:
  - every route of both origins answers exactly the manifest's bytes, content
    type and redirect;
  - each origin answers nothing of the other's and no other path;
  - both certificates verify, each for its own name only, under the one anchor;
  - the wrong name, the rogue issuer and the `system`-only certificate each
    fail verification, the last accepted only under `system`;
  - the PKI differs every run;
  - a stopped origin's port is closed;
  - an origin given an escaping route or a missing side refuses to start.
- **The proxy's side, in process** (`crates/dwkd-broker/src/egress/tests.rs`,
  in `make test`). These use the real `Proxies`, guard and evidence-only
  fixture resolver, over the generator's two names as its source spells them:
  - a tunnel to the granted origin carries a client hello naming it;
  - a `CONNECT` to the ungranted origin, or to the granted name at its port,
    is `TARGET_NOT_GRANTED`, decided before any resolution and before a byte
    reaches it;
  - without the fixture's loopback exception, the production guard refuses
    the granted origin as a blocked address.
- **What this shows.** "A refusal of the ungranted one is the proxy's decision,
  never a TLS failure" is shown in two halves, each in process, at its level:
  - the proxy refuses the ungranted origin before any TLS begins;
  - the ungranted origin's TLS is as valid as the granted one's.
- **What it doesn't.** No real client through a real environment's relay and
  proxy reaches these origins here: that needs a measured `PROXY_ONLY`
  environment, and is M5e.4's hosted evidence, not M5e.3's.

Not M5e.3's: the registry tools image (M5e.4, built on the hosted runner from
pinned Node.js/npm and pip versions checked against recorded checksums,
OD-E4), any pip or npm run, and any change to `hygiene.rs`. ADR-0054 and
ADR-0055 stay **Proposed**; npm stays `HYGIENE_NOT_EVIDENCED`. Nor anything of E6:
no M5e.3 fixture, case or line weakens a hard rule or a topology, stands for E6 or
counts toward R3, and M5e.3's completion claims nothing for M5e.2.

## 8. CI jobs and tasks

| Task | Job (required by `ci`) | Runs | Notes |
|---|---|---|---|
| `make sandbox-registry-evidence` | `sandbox-registry` | hosted only | builds the registry tools image on the runner from pinned Node.js/npm and pip versions, each checked against a recorded checksum before use (OD-E4), offline `FROM scratch`, `--network none`, named by content; prints each tool's version and SHA-256; NOT EXERCISED locally, never a pass |
| `make sandbox-registry-mutations` | a workflow the owner triggers by hand, never required by `ci` | manual, hosted; unit-killable mutants also locally | each guard weakened in turn; a hosted-only kill is reported from the hosted run, never as a local one (OD-E7) |
| `make sandbox-closure-evidence` (or new cases in the existing tasks) | existing jobs, or `sandbox-closure` | local and hosted; the runtime-restart case hosted-only | the restart case runs only on a disposable runner, as `sandbox-workspace` and `sandbox-agent` already provision identities there. **As built (M5e.2, 2026-10-29):** new cases in the existing tasks — the in-process R2/R3 cases in `make sandbox-foundation-evidence`, the R9 cases in `make sandbox-workload-evidence`, both already required by `ci` — so no job was added; R8's failing neighbour test is in no task (F-R8, §5a); the restart case and its job are not built. **As built (2026-10-30):** `make sandbox-restart-evidence` in the required job `sandbox-restart` (R11), the only job that sets `DW_RUNTIME_RESTART=1`; R2's `weakened-host-uts` in `make sandbox-foundation-evidence`. And the three jobs that switch to a fresh session of the runner's user (`filesystem-operations`, `sandbox-workspace`, `sandbox-agent`) hand their `DW_*` values across it with `scripts/ci_handoff.py`, which proves the uid, the group and the values on the far side and is held by `tests/architecture/test_ci_privileged_handoff.py` — run under a stub `sudo` that resets the environment as sudo-rs does, with each lost or weakened handoff failing it. **As built (2026-10-31):** R8's neighbour tests in `make sandbox-workload-evidence` (the broker's and the authority's); R8 at the cap in `make sandbox-capacity-evidence`, the required job `sandbox-capacity`, the only one that sets `DW_CAPACITY_EVIDENCE=1` (held by `tests/architecture/test_ci_capacity.py`); R3's captured-record cases in `make sandbox-egress-evidence`; the negative control `make sandbox-neighbour-mutations`, run by hand like every mutation review |
| the M5e gate eval | `evals` (strict) | hosted; local reports NOT EXERCISED for the hosted-only parts | requires `M5e`; `M5` only at acceptance |

Each new job gets the `test_ci_*` treatment: present, Linux, unconditional, no
`continue-on-error`, no secrets, exactly its command, required once by `ci`;
its case lists equal to what its suites print; its evidence lines' levels and
attribution checked; and a committed negative control showing a dropped case,
a wrong level, a missing attribution and a weakened workflow each fail.

## 9. Local versus hosted verification

| Evidence | Local (WSL, one identity, Docker) | Hosted |
|---|---|---|
| M5a foundation, M5b egress, M5c `net.http`, M5d workload, secret and release | runs | required |
| M5d.4 workspace, privileged half | NOT EXERCISED | required |
| M5d.5 agent, three-identity half | NOT EXERCISED | required |
| authority peer-credential check (second identity) | NOT EXERCISED | required |
| M5e.1 attribution | runs | required — passed (run 40774766063) |
| M5e.2 closure: the hard rules under `PROXY_ONLY` (in process), cross-run | runs | required — passed (run 40954372045's `sandbox-foundation`, `sandbox-workload`) |
| M5e.2 real-container host UTS (R2) | runs | required — passed (run 41130431929) |
| M5e.2 the hard rules over a real `PROXY_ONLY` record (R3, in process) | runs | required (`sandbox-egress`) — passed (run 41242001763), `in-process` |
| M5e.2 U4 under `PROXY_ONLY`, in process (R3): the runtime's default seccomp profile, the swap limit | runs | required (`sandbox-foundation`; over the real record, `sandbox-egress`) — passed (run 41323258812), `in-process` |
| M5e.2 real `PROXY_ONLY` containers weakened one hard rule at a time (R3, E6) | not built | **BLOCKED** — required by the owner's R-B (ADR-0057, 2026-11-01); not built and not planned while the safety control stands; no existing source observes it (§3a) |
| M5e.2 each R2/R3 line's outcome held to what it claims; the R-B guard (R17) | runs | required (`sandbox-foundation`, `sandbox-egress`; their controls and the guard in `make test`) — passed (run 41349869654) |
| M5e.2 findings F-RELAY, F-EVICT, F-TEARDOWN (§5a): unit tests | runs | required (`make test`) — passed (runs 41358634372, 41430527997) |
| M5e.2 finding F-ABSENT (§5a): unit tests; the real-runtime suites over the changed removal and listing | runs | required (`make test`; the existing `sandbox-*` jobs) — passed (run 41446389484); a runtime that stops answering mid-operation: NOT EXERCISED, by any job |
| M5e.2 F-ABSENT's evidence side (§5a): each suite's `exists` by a listing the runtime answered; its unit tests and negative control; the architecture test | runs | required (`make test`; the real-runtime suites that call it) — passed (run 41471750928) |
| M5e.2 neighbour (R8), at the broker and through the authority | runs (since ADR-0056's Option B) | required (`sandbox-workload`) — passed (run 41242001763) |
| M5e.2 neighbour at the live-environment cap (R8) | NOT EXERCISED, never local: the task and the test refuse | required (`sandbox-capacity`, disposable runner) — passed (run 41242001763) |
| M5e.2 neighbour negative control (R8) | runs (`make sandbox-neighbour-mutations`) | by hand, like every mutation review |
| M5e.2 runtime restart (R11) | NOT EXERCISED, never local: the task and the test refuse | required (`sandbox-restart`, disposable runner) — passed (run 41130431929) |
| The privileged jobs' handoff (CI #106) | its contract and a stub-`sudo` execution run | passed (run 41130431929) |
| M5e.3 fixture generators, their unit tests and guard (§7a) | runs | required (`make test`) — passed on ubuntu-latest and macos-latest (run 41720068934); failed on windows-latest there, fixed 2026-11-04, hosted run pending |
| M5e.3 registry origins, their per-run CA, and the proxy's side in process (§7a) | runs (Linux) | required (`make test`, ubuntu-latest) — built 2026-11-04, hosted run pending; macOS and Windows: NOT EXERCISED, by design |
| M5e.4–M5e.5 pip and npm against the fixtures | NOT EXERCISED (no pip or npm installed on the host, by decision) | required |
| M5e.6 gate | the local parts | required |

## 10. Owner decisions (2026-10-26)

The owner decided each point on 2026-10-26, one at a time, after its options were laid
out. The question and the plan's recommendation are kept beside each decision. These
decide how M5e is built; none accepts ADR-0054 or anything else.

| # | Question | Recommendation |
|---|---|---|
| OD-E1 | SANDBOX.md §6 asks for "an audit record naming the denial" for each contained attempt; M5b records containment in the environment's measurement, "not yet per attempt". Is an **attributed** denial — the case names the existing event or measurement that enforced it — what §6 means? | Yes: attribution from existing events and measurements (direction 4), §6's sentence reworded to say so in the M5e change; no new per-attempt event |
| OD-E2 | pip: today a `pip` executable is kept with nothing pip-specific (G3). Does M5e add a pip profile (refuse `--trusted-host`, `--no-verify` forms and `--index-url` over HTTP; `--only-binary :all:` so no build backend runs), with its own evidence — in ADR-0054 or a sibling ADR? | Yes, a pip profile in a sibling Proposed ADR, so ADR-0054 stays narrow; until then M5e.4 evidences pip as it is and says what it does not neutralise |
| OD-E3 | How the npm profile is exercised before acceptance without being enabled in production (ADR-0054 §7) | An evidence-only start-up option of the authority, logged `REDUCED ASSURANCE` and fenced by an architecture rule, removed when ADR-0054 is accepted |
| OD-E4 | The registry tools' provenance: the runner's preinstalled Node.js/npm and Python/pip, or pinned versions verified by checksum | Pinned versions verified by checksum, from the runner's tool cache or a pinned setup action; the image records each tool's digest either way |
| OD-E5 | M5's acceptance wording: the contract lists `local` (deferred to M6) and says `npm install` (ADR-0054 allows `install` and `ci`) | Confirm that M5's acceptance excludes `local`, and that `npm install` and `npm ci` both satisfy it |
| OD-E6 | ADR-0054's surface: whether `--cafile`/`--ca` stay allowed (the evidence's per-run CA needs one) and `--strict-ssl=false` stays refused | Allow a CA file, refuse turning verification off (ADR-0054 §4) |
| OD-E7 | Mutation review for hosted-only evidence: run the registry campaign hosted (manual workflow) or accept unit-killable mutants only | A manual hosted run, its result recorded; never a local kill claimed for a hosted-only case |
| OD-E8 | Whether a runtime restart (R11) is an M5e gate case or a documented M6+ reliability item | An M5e case, hosted-only on a disposable runner |

| # | The owner's decision, 2026-10-26 | What follows |
|---|---|---|
| OD-E1 | **Attribution**, as recommended | M5e.1 attributes every case to the existing event or measurement that enforced it; SANDBOX.md §6 is reworded in M5e.1 to say a contained attempt is attributed, not individually audited; no new audit event |
| OD-E2 | **A sibling ADR for pip**, as recommended | [ADR-0055](adr/0055-m5e-pip-hygiene-profile.md), a pip profile, drafted 2026-10-27, **Proposed**; ADR-0054 stays npm-only; M5e.4 evidences pip as it is today and states what it does not neutralise |
| OD-E3 | **An evidence-only start-up option**, as recommended | ADR-0054 §7: logged `REDUCED ASSURANCE`, refused without the evidence's other fixture options, fenced by an architecture rule, removed at acceptance |
| OD-E4 | **Pinned versions verified by checksum**, as recommended | §8: exact Node.js/npm and pip versions from a SHA-pinned setup action or the runner's tool cache, checked against recorded checksums before the image is built; a version change is a reviewed diff |
| OD-E5 | **`local` excluded; `npm install` and `npm ci` both**, as recommended | the ROADMAP's M5e acceptance and M5 contract say so, citing ADR-0052 OD-7 |
| OD-E6 | **Image CA only** — not the recommendation | ADR-0054 §§2–4: `--cafile` and `--ca` are refused; the launcher pins `npm_config_cafile` to one operator-provided trust file at a fixed image path (`/etc/direwolf/npm-ca.pem`, proposed), pinned by the image manifest; that file is npm's whole trust store, so a public-registry operator includes public roots; a missing file fails closed; the evidence bakes its per-run CA there; a workspace `.npmrc` naming a CA must take no effect |
| OD-E7 | **A manual hosted run**, as recommended | §8: a workflow the owner triggers runs `make sandbox-registry-mutations`; unit-killable mutants also run locally; a hosted-only kill is reported as hosted |
| OD-E8 | **An M5e case, hosted**, as recommended | M5e.2's runtime-restart case on a disposable runner; the ROADMAP's M5e deliverables list it; a gap it exposes is a separate, reviewed product change |

**R3's real-container level (2026-11-01).** On ADR-0057 §7 the owner selected
**R-B — require the real-container level**: not the residual the record
proposed (R-A), nor its deferral to the gate (R-C). R3 is met only by real
`PROXY_ONLY` containers weakened one hard rule at a time (E6), at the level the
contract states; E1–E5 stay supporting evidence at their levels, and M5's
acceptance wording is unchanged. E6 is BLOCKED: the earlier safety control
stands, and producing E6 needs a plan the owner approves within it
(ADR-0057 §8).

**M5e.3's sequencing (2026-11-03).** E6 is BLOCKED, so M5e.2 cannot close, and §6
and §7a started M5e.3 only after M5e.2 closed. E6 is an unresolved gap in the
assurance evidence, not a vulnerability found. The owner made one narrow
exception to that order: **M5e.3's fixture work may proceed while M5e.2 stays
IN PROGRESS.** What it decides, and what it does not:

- **It moves when M5e.3 may start, and nothing else.** M5e.3's scope is §7a's
  brief, in §7a's order — the deterministic, offline generators and fixtures
  first. M5e.3 closes on its own exit (§6) and its hosted run, and its closing
  claims nothing for M5e.2. M5e.4–M5e.6 still follow M5e.2's close; taking any
  other step out of order needs a decision of its own.
- **R-B stands, and E6 with it.** ADR-0057 stays **Proposed** and outside the
  accepted digest, its residual not accepted; E6 stays required, its 15 rows
  **BLOCKED** (required 15, passed 0), §3b's criteria unchanged. No M5e.3
  fixture, case or line weakens a hard rule or a topology, stands for E6 or
  counts toward R3.
- **M5e.2 stays open, and in view.** M5e.2 stays **IN PROGRESS** and
  [issue #19](https://github.com/Onwcan/DireWolf/issues/19) stays OPEN, cited
  by each status that follows.
- **Nothing accepted, required or measured changes.** No accepted ADR or its
  digest, production control, hard rule, invariant, evidence level,
  architecture guard, CI job or requirement, eval or baseline changes; M5e.3
  adds tests and guards (§7a) and removes none.
- **M5's acceptance waits for E6.** M5e.6's gate and M5's acceptance stay where
  R-B put them: after genuine E6 evidence closes R3 and the owner closes M5e.2.
  Neither `M5e` nor `M5` joins the available milestones before then.
- **It does not authorise producing E6.** That still needs a plan the owner
  approves within the safety control, or genuine independent evidence meeting
  §3b that the owner accepts (ADR-0057 §8); this decision is neither.

`tests/architecture/test_m5e_r3_closure.py` holds the exception to that while
ADR-0057 stands: this is the plan's one record of it; no status document claims
M5e.4–M5e.6, M5e or M5 complete; the ROADMAP's M5e heading keeps M5e.4–M5e.6
not started; the plan's current status and the ROADMAP's "Still to do" cite
issue #19; and neither `M5e` nor `M5` is an available milestone.

## 11. What this plan does not do or claim

It changes no code, evidence, CI job, eval or baseline. It does not start M5e,
accept ADR-0054, or mark M5e or M5 complete. It claims nothing as verified that
no required case shows: §3's "Hosted" rows name cases a required job ran at the
baseline; every other row is a gap. M5e's evidence, like M5d's, will show what
its cases show — not that a container is a VM, that the host kernel is
untrusted, or that a package's own code is safe once a workload runs it.
