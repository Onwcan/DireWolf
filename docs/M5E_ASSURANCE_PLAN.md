# M5e — The M5 defensive assurance gate: gap analysis and implementation plan

**Project:** [DireWolf](https://github.com/Onwcan/DireWolf)\
**Baseline:** `f8aeef97ec0bcc356d8a2421be709496fe275d70` (`main`, verified 2026-10-26)\
**Verified hosted CI of the baseline:** [run 40331005080](https://github.com/Onwcan/DireWolf/actions/runs/40331005080), 27 of 27 jobs successful\
**Status (as written, 2026-10-26):** Planning only. M5e is NOT STARTED: no M5e code, evidence or CI job exists, and no M5e evidence has run. M5 stays IN PROGRESS.\
**Status (2026-10-26, later):** the owner decided the plan's eight open points, OD-E1 to OD-E8 (§10). M5e is still NOT STARTED.\
**Status (2026-10-27):** the sibling pip ADR the owner decided on (OD-E2) is drafted, [ADR-0055](adr/0055-m5e-pip-hygiene-profile.md), **Proposed**; SANDBOX.md §6 says what a contained attempt's evidence is (OD-E1); and a test now holds every evidence case §3 cites to the task that requires it. That is M5e.1's groundwork, not M5e.1: no evidence line has changed. M5e is still NOT STARTED.\
**Status (2026-10-27, later):** after the groundwork's hosted run ([40497912001](https://github.com/Onwcan/DireWolf/actions/runs/40497912001), `a0d6ade`, 27 of 27), **M5e.1 is built**: every line of the five suites' evidence says its level and enforcement, and each task refuses one that does not as the contract says ([SANDBOX.md](SANDBOX.md) §6a; R16 below). It passed locally on a real runtime; it is complete when a hosted run of the owner's commit passes. M5e is IN PROGRESS; M5e.2–M5e.6 are not complete.\
**Status (2026-10-29):** **M5e.1 is COMPLETE** — committed as `f42f44a` and verified, with the CI recovery after it (`9175307`, `bbedd06`) and PR #17 (`6fd0bc7`), by hosted [run 40774766063](https://github.com/Onwcan/DireWolf/actions/runs/40774766063) on `6fd0bc7`, 27 of 27 jobs. **M5e.2 is BUILT in part, hosted verification pending:** R2 and R3 are evidenced in process by the broker's own host judgement and decision, R9 on a real runtime (§3). **R8 FAILS**: its neighbour case found that environments are coupled through the one host uid they share — finding **F-R8** (§5a), the owner's to decide; nothing was changed to make it pass. The real weakened `PROXY_ONLY` containers and R11's runtime restart are not built (§3, §6). M5e is IN PROGRESS; M5 stays IN PROGRESS.\
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
| R2 | `sandbox-foundation-evidence`: `every_weakened_profile_is_detected` — `weakened-writable-root`, `-root-user`, `-privileged`, `-runtime-socket-mounted`, `-capability-added`, `-seccomp-unconfined`, `-seccomp-default-profile`, `-host-network`, `-host-pid`, `-host-ipc`, `-no-new-privileges-disabled`, `-resource-limits-dropped`, `-extra-device`, `-mutable-image-tag`, `weakened-count`; `drift-pids-limit-raised`. Since M5e.2, in process (the broker's own host judgement and its decision, `oci::clean`, given one record at a time): `no-network-weakened-host-uts-refused`, `proxy-only-weakened-host-uts-refused` | Hosted; the in-process host-UTS cases built, hosted pending | Host UTS is refused by the production judgement under both topologies, in process. **Not built:** a real container weakened to the host's UTS namespace — no weakened container is added in M5e.2. The gate's own failure is shown per task (a missed case fails it); an M5-level meta-test is M5e.6's. |
| R3 | `sandbox-egress-evidence`: `weakened_topologies_are_detected` — `weakened-bridge-network`, `weakened-missing-relay`, `weakened-relay-tampered`, `weakened-proxy-variables-removed`, `drift-extra-peer-listening`, `drift-fake-resolver-in-namespace`, `drift-egress-directory-opened`, `drift-setup-left-running`, `drift-relay-stopped`, `weakened-topology-count`. Since M5e.2, in process, every hard rule judged under a `PROXY_ONLY` spec: `proxy-only-conforming-kept`, `no-network-conforming-kept`, `proxy-only-weakened-writable-root-refused`, `proxy-only-weakened-root-user-refused`, `proxy-only-weakened-privileged-refused`, `proxy-only-weakened-capability-added-refused`, `proxy-only-weakened-no-new-privileges-disabled-refused`, `proxy-only-weakened-seccomp-unconfined-refused`, `proxy-only-weakened-host-pid-refused`, `proxy-only-weakened-host-ipc-refused`, `proxy-only-weakened-host-network-refused`, `proxy-only-weakened-mutable-image-tag-refused`, `proxy-only-weakened-runtime-socket-mounted-refused`, `proxy-only-weakened-extra-device-refused`, `proxy-only-weakened-resource-limits-dropped-refused` | Partial; in process built, hosted pending | Each nonconforming record changes exactly the invariants it states and the production decision refuses it under `PROXY_ONLY`; the inside vantage under `PROXY_ONLY` stays the egress suite's (`proxy-only-container-capabilities-empty`, `proxy-only-container-raw-sockets-refused`). **Not built:** real `PROXY_ONLY` containers weakened one rule at a time — in-process evidence is the judgement's, not a container's. |
| R4 | `sandbox-egress-evidence`: `bypass-raw-ipv4`, `-raw-ipv6`, `-icmp`, `-vsock`, `-udp-external`, `-udp-ipv6-external`, `-dns-external`, `-dns-ipv6-external`, `-dns-local-stub`, `-dns-desktop-host`, `-dns-embedded-runtime-resolver`, `-tcp-external-dns`, `-tcp-private-lan`, `-tcp-host-loopback-origin`, `-tcp-cloud-metadata`, `-tcp-nat64-metadata`, `-tcp-ipv4-mapped`, `-tcp-link-local-neighbour`, `bypass-proxy-variable-redirected`; `sandbox-agent-evidence`: `a06-*`, `a07-*` | Hosted | None for the topology. For package managers: M5e.4 repeats direct-route attempts from the pip and npm invocations themselves. |
| R5 | `sandbox-egress-evidence` (strict CONNECT parse, exact grants, tunnel limit); `sandbox-agent-evidence`: `a05-connect-absolute-form-refused`, `a05-connect-address-literal-refused`, `a05-connect-another-method-refused`, `a05-connect-host-header-disagrees-refused`, `a05-connect-host-not-canonical-refused`, `a05-connect-smuggled-body-refused`, `a05-tls-sni-mismatch-closed`, `a05-tls-sni-missing-closed` | Hosted | **Missing for registries:** an ungranted registry, a tarball or wheel on an ungranted host, and a redirect to one. M5e.4. |
| R6 | Sandbox egress is an opaque tunnel, so TLS is the client's: `a03-https-granted-origin-tls-verified`, `a05-tls-untrusted-issuer-refused-by-the-client`, `a05-tls-certificate-for-another-name-refused-by-the-client`. The kernel's own path: `net-http-evidence` (verified per hop) | Hosted | **Missing for pip and npm:** each verifies the fixture registry under a per-run CA, refuses an untrusted issuer, and its verification is not turned off by an argument (ADR-0054 for npm; [ADR-0055](adr/0055-m5e-pip-hygiene-profile.md) for pip, both Proposed). M5e.4–M5e.5. |
| R7 | Kernel path, `net-http-evidence`: `ssrf-*` (IP literals, `ssrf-ipv4-mapped`, `ssrf-6to4`, `ssrf-mixed-answer`, …), `dns-rebinding-pinned-within-request`, `dns-rebinding-next-request`, `redirect-*` (`-blocked-address`, `-metadata-name`, `-mixed-address`, `-ungranted-host`, `-sixth-hop`, `-downgrade`, …), `credential-cross-origin-redirect`, `origin-confusion-idna-label`, and the authority's own pipeline: `guard-loopback-answer`, `guard-metadata-ip-answer`, `guard-mixed-answer`, `metadata-name-before-resolution`. Proxy path, `sandbox-egress-evidence`: `resolver-metadata-blocked`, `resolver-rebinding-pinned`, `resolver-mixed-refused-outright`, `bypass-tcp-cloud-metadata`, `bypass-tcp-nat64-metadata`, `bypass-tcp-ipv4-mapped` | Hosted | The suite is spread over two tasks and has no single gate. M5e.6's gate requires both, by name. Out of M5's scope and stated so: link-preview and markdown-image exfiltration (channels, M10+) and a `LOCAL_ONLY` model call (M7). |
| R8 | `sandbox-foundation-evidence`: `resource-pids-bounded`, `resource-memory-oom-killed`, `resource-file-size-bounded`; `sandbox-workload-evidence`: `workload-fork-loop-reaped`, `workload-daemon-reaped`, `workload-wall-clock-timed-out`; `sandbox-workspace-evidence`: `workload-fills-to-enospc`; the 16-environment and workload budgets (`public-exec-budget-exhausted-refused`) | Hosted, each limit alone; **the neighbour case FAILS** (finding F-R8, §5a) | Each limit holds for the environment it bounds. **Failed (M5e.2):** one environment held at its own task bound while another is served — the broker's neighbour test (`a_neighbour_at_its_task_bound_leaves_another_environment_and_the_broker_serving`) finds the other environment's probe and workload unable to start, so the other is refused `ENVIRONMENT_NOT_CLEAN`. The test stays, required by no task and printing no evidence line, as the finding's reproducer. **Not shown either:** memory or disk pressure beside a neighbour — each limit is shown alone (`resource-memory-oom-killed`, `workload-fills-to-enospc`). |
| R9 | `persistence-tmp-marker-not-inherited`, `workload-nothing-persists`, `release-spares-another-runs-environment`, `release-other-run-still-runs`, `release-spares-another-runs-proxy-only-environment`, one environment per run (schema, ADR-0052 §4). Since M5e.2, on a real runtime: `cross-run-processes-not-visible`, `cross-run-other-environment-refused`, `cross-run-destroy-spares-the-other`, `cross-run-next-environment-holds-nothing-of-the-last` | Hosted; the cross-run cases built, hosted pending | Run A sees none of run B's processes, cannot name B's environment, and destroying it leaves B's workload running; the next environment is a fresh container holding nothing of A's. **Not shown:** A reaching B's relay (each relay listens in its own environment's namespace — `proxy-only-relay-shares-the-namespace-unprivileged` — but no cross-relay attempt is made). **By design and stated:** runs bound to one workspace directory share it (ADR-0052 §6) — a documented residual, not a gap. |
| R10 | `orphan-ended-record-reaped`, `reconcile-helper-orphan-reaped`, `broker-restart-orphans`, `foreign-*`; the release and lease teardown (`sandbox-release-evidence`, 62 + 45 cases) | Hosted | None. |
| R11 | Reconciliation at an **authority** start: stopped environments destroyed, missing ones `LOST`, twins untouched. What a runtime restart leaves, each shown alone on a real runtime: a stopped environment refused before any workload (`workload-stopped-environment-refused`), a removed one never reported clean (`workload-environment-removed-mid-run-not-clean`), an unreachable runtime refused (`exit-runtime-unavailable`), an uncertain ending settled `UNKNOWN` and its environment destroyed (`unknown-ending-environment-destroyed`) | Partial; **hosted restart NOT BUILT** | **Not evidenced:** a **runtime** restart under a running authority — the containers' end detected and settled as a whole, nothing believed still running, a new workload served after. Hosted-only (it restarts the runner's daemon), never local (OD-E8). Not built in M5e.2: a required hosted job that has never run would turn the aggregate red without evidence, so it lands as its own reviewed step. |
| R12 | `tamper-substituted-probe`, `tamper-changed-byte`, `tamper-extra-field`, `tamper-truncated-output`, `tamper-malformed-output`, `tamper-flood-output`, `tamper-hang-timeout`; `drift-*`; `mount-substitution-destroys-before-the-workload` (the workspace's privileged half) | Hosted | None. |
| R13 | `fronting-residual-carried-and-bounded`, `budget-*`, `a08-tunnel-limit`, `a08-download-budget`, `a08-upload-budget` | Hosted | None; the residual stays stated (NETWORK_SECURITY.md). |
| R14 | — | **Missing** | No pip in any evidence image (the tools image copies the standard library only, `ensurepip` excluded), no registry fixture, no case. `pip` falls under the obligation's "anything else" row and is kept with **no** pip-specific neutralisation — reachable only under an operator policy without `argv_safe`, since the shipped packs deny `pip install` (R3) (§4, G3). [ADR-0055](adr/0055-m5e-pip-hygiene-profile.md) proposes the profile. M5e.3–M5e.5. |
| R15 | — | **Missing, and refused by design** | npm is `HYGIENE_NOT_EVIDENCED` (ADR-0052 §5a), although `npm_config_ignore_scripts=true` is already among the launcher's variables. ADR-0054 (Proposed) defines the profile and the evidence it needs. M5e.3–M5e.5. |
| R16 | `sandbox-agent-evidence` and `sandbox-release-evidence` lines carry `level` and `enforcement`; `environment.refused` and `environment.drifted` records; the broker's egress counted by disposition; since M5e.1 (complete: hosted run 40774766063 on `6fd0bc7`), every line of `sandbox-foundation-evidence`, `sandbox-egress-evidence`, `sandbox-workload-evidence`, `sandbox-secret-evidence` and `sandbox-workspace-evidence` too, each case held to its level and mechanisms (`scripts/dw.py`, `ATTRIBUTION`; SANDBOX.md §6a); M5e.2's in-process and real-runtime cases join the same contract | Hosted (M5e.1 complete) | Was: M5a, M5b and M5d.1–M5d.4 lines carried only `suite`, `case`, `outcome`. M5e.1 added attribution to every line, from existing events and measurements only (owner direction 4), and §6 says so (OD-E1, decided). No per-attempt audit event was added. |
| R17 | `tests/architecture/test_ci_*` (each job present, unconditional, required by `ci`, exact command; the task's and the eval's case lists equal); the strict eval gate under GitHub Actions; the reviewed baseline (`evals/baselines/main.json`, never rewritten by a run); mutation campaigns; the ADR history anchor | Hosted | Each new job, task and eval gets the same treatment (M5e.6). The negative controls run by hand for M5d.6 become committed tests. |
| R18 | — | Deferred | `local` is M6's (ADR-0052 OD-7). The ROADMAP's M5 contract and M5e section say so, and M5's acceptance excludes it (OD-E5, decided). |

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
  plus `weakened-host-uts` (R2).
- **G6 — Runtime restart is not evidenced (R11).**
- **G7 — Cross-run isolation is evidenced in parts, not as a suite (R9).**
- **G8 — No bounded neighbour case for exhaustion (R8).** Built in M5e.2, and it
  fails: finding F-R8 (§5a).
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

## 5a. Findings

**F-R8 — environments share one host uid's task count (M5e.2, 2026-10-29; open, the
owner's to decide).** Every environment's workload, and the probe the broker runs in it,
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

## 6. Safe implementation sequence

Each step keeps every production control as it is; each lands with its own
local gates, then the owner's commit and a hosted run, before the next. No step
enables npm in production.

| Step | Delivers | Product change | Exit |
|---|---|---|---|
| **M5e.1** Attribution | `level` and `enforcement` on every line of `sandbox-foundation`, `sandbox-egress`, `sandbox-workload`, `sandbox-secret` and `sandbox-workspace` evidence, each naming the existing mechanism (the probe's measured invariant, `environment.refused`/`.drifted`, the proxy's decision and the egress disposition counters, the authority's refusal, the namespace's errno, the client's own TLS verification); each `require_*` refuses a line without them; SANDBOX.md §6 reworded: a contained attempt is attributed, not individually audited (OD-E1) | none (test, task and documentation) | every existing case still reports, now attributed; the negative controls of M5d.6 generalised |
| **M5e.2** Closure | the profile weakenings on `PROXY_ONLY` (R3), `weakened-host-uts` (R2); the cross-run suite (R9); a bounded neighbour case (R8); a runtime restart under a running authority (R11), hosted-only | none expected; a finding is a separate, reviewed change | each new case required by name; the restart case NOT EXERCISED locally, required hosted |
| **M5e.3** Fixtures | §7's registries, generated deterministically from synthetic content, served by the existing per-run-PKI HTTPS origin on loopback through the broker's evidence-only resolver; unit tests of the generators | none | fixtures reproducible bit for bit from a seed; no network beyond loopback |
| **M5e.4** pip, and npm refused | a registry tools image built **on the runner** (§8); pip against the granted fixture registry and against an ungranted one; npm **refused** `HYGIENE_NOT_EVIDENCED` before anything is prepared — today's fail-closed behaviour, evidenced | none: pip as it is today, what it does not neutralise stated; [ADR-0055](adr/0055-m5e-pip-hygiene-profile.md)'s profile is M5e.5's, behind the same evidence-only fence as npm's (OD-E2) | `make sandbox-registry-evidence` hosted-green; locally NOT EXERCISED, by design |
| **M5e.5** The npm profile | ADR-0054's profile in `hygiene.rs`, reachable only through the evidence-only option (ADR-0054 §7, OD-E3), npm trusting only the image's trust file (OD-E6); its evidence (ADR-0054 §8) and its hosted mutation review (OD-E7) | yes, behind the decided fence; production still fail-closed | every ADR-0054 §8 case hosted-green |
| **M5e.6** The gate | an eval suite requiring `M5e` that runs the M5 evidence tasks and requires every case at its level with its attribution; architecture tests for each new job; committed negative controls; the owner's decisions; on ADR-0054's acceptance, npm's profile enabled; then `M5` joins the available milestones and `pending-kernel/sandbox-egress` gets its runner | the enabling change only after acceptance | hosted green on the committed tree; M5's acceptance is the owner's |

Where each step stands (2026-10-29): **M5e.1 COMPLETE** (hosted run 40774766063). **M5e.2 BUILT in part, hosted verification pending** — no product change, no new CI job: R2 and R3 in process, required by `sandbox-foundation-evidence`; R9 on a real runtime, required by `sandbox-workload-evidence`. R8's neighbour case is built and **fails** — finding F-R8 (§5a) — so no task requires it. Two of its deliverables are **not built**: real `PROXY_ONLY` containers weakened one hard rule at a time, and R11's runtime restart under a running authority (hosted-only, OD-E8). M5e.3–M5e.6 are not started.

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

## 8. CI jobs and tasks

| Task | Job (required by `ci`) | Runs | Notes |
|---|---|---|---|
| `make sandbox-registry-evidence` | `sandbox-registry` | hosted only | builds the registry tools image on the runner from pinned Node.js/npm and pip versions, each checked against a recorded checksum before use (OD-E4), offline `FROM scratch`, `--network none`, named by content; prints each tool's version and SHA-256; NOT EXERCISED locally, never a pass |
| `make sandbox-registry-mutations` | a workflow the owner triggers by hand, never required by `ci` | manual, hosted; unit-killable mutants also locally | each guard weakened in turn; a hosted-only kill is reported from the hosted run, never as a local one (OD-E7) |
| `make sandbox-closure-evidence` (or new cases in the existing tasks) | existing jobs, or `sandbox-closure` | local and hosted; the runtime-restart case hosted-only | the restart case runs only on a disposable runner, as `sandbox-workspace` and `sandbox-agent` already provision identities there. **As built (M5e.2, 2026-10-29):** new cases in the existing tasks — the in-process R2/R3 cases in `make sandbox-foundation-evidence`, the R9 cases in `make sandbox-workload-evidence`, both already required by `ci` — so no job was added; R8's failing neighbour test is in no task (F-R8, §5a); the restart case and its job are not built |
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
| M5e.2 closure: the hard rules under `PROXY_ONLY` (in process), cross-run | runs | required — pending a hosted run of the owner's commit |
| M5e.2 neighbour (R8) | runs, and **fails** (F-R8) | not required until the owner's remedy lands |
| M5e.2 runtime restart | NOT EXERCISED, never local | required (disposable runner) — not built |
| M5e.3 fixture generators | runs | required |
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

## 11. What this plan does not do or claim

It changes no code, evidence, CI job, eval or baseline. It does not start M5e,
accept ADR-0054, or mark M5e or M5 complete. It claims nothing as verified that
no required case shows: §3's "Hosted" rows name cases a required job ran at the
baseline; every other row is a gap. M5e's evidence, like M5d's, will show what
its cases show — not that a container is a VM, that the host kernel is
untrusted, or that a package's own code is safe once a workload runs it.
