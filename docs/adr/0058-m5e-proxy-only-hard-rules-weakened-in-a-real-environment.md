# ADR-0058: M5e.2 — R3's E6: each hard rule weakened in a real `PROXY_ONLY` environment the released broker prepared, by a test-only runtime that does not do what the plan asks, measured from both vantages and refused by the production decision

**Status:** Accepted · **Date:** 2026-11-09 (proposed and built 2026-11-08 under the owner's authorisation, committed as `3ca842c`; its first hosted run observed F-E6-HOSTNET, remedied by ADR-0059 at `14405ab`; accepted by the owner on 2026-11-09 after hosted CI run 42525106398 at `14405ab` — 31 of 31 jobs, `sandbox-proxy-weakened` and the `ci` aggregate among them — and the offline review of its E6 log, §§9, 10) · **Supersedes:** [ADR-0057](0057-m5e-proxy-only-real-container-evidence-residual.md) · **Refines:** [ADR-0047](0047-m5a-oci-execution-environment-and-measured-assurance.md) §9 (weakened profiles are caught by measurement), [ADR-0048](0048-m5b-proxy-only-topology-and-connect-proxy.md) §§9, 14 (`PROXY_ONLY`'s measurement and its weakened topologies) · **Addresses:** R3's E6 ([M5E_ASSURANCE_PLAN.md](../M5E_ASSURANCE_PLAN.md) §§3a, 3b), [issue #19](https://github.com/Onwcan/DireWolf/issues/19) · **Refined by:** [ADR-0059](0059-m5e-proxy-only-peer-joins-only-its-own-network-namespace.md) (accepted 2026-11-09: the host-network case, after F-E6-HOSTNET, §8) · **Implementation authorised by:** the owner, 2026-11-08 — the implementation and its evidence path only, not acceptance

> **ADR-0057's E6 is built: for each of the fifteen rows ADR-0057 §1a names,
> the released, unmodified broker prepares a genuine `PROXY_ONLY` environment
> along its production path, and the container runtime it is handed records
> and runs the environment with exactly that row's hard rule weakened. The
> broker's own measurement must catch it from the vantage(s) §1a names and its
> production decision must refuse it; a conforming control through the same
> runtime must be kept. Every raw observation is digested where it is made,
> checked again from its bytes, and published with the run's provenance. It
> runs only on a disposable GitHub-hosted runner. Its first hosted run, at
> `3ca842c`, observed F-E6-HOSTNET (§8), and the broker was changed because
> of it (ADR-0059). The hosted run at that change, `14405ab` (run
> 42525106398), passed every case — the control kept, each of the sixteen
> weakened cases refused by exactly its row's invariants, all fifteen rows —
> and the owner accepted this record on 2026-11-09 (§10).**

Accepted on 2026-11-09. The owner's authorisation of E6's implementation
(2026-11-08), the implementation and its first hosted run, ADR-0059's fix and
its hosted run (42525106398 at `14405ab`), the review of that run's evidence,
and this formal acceptance were separate steps, taken in that order. It
supersedes ADR-0057: R3's real-container level, which the owner's R-B
required, is evidenced here, and ADR-0057's residual was never accepted. What
this evidence does not show is stated in §10 and under Consequences, and
acceptance does not narrow it.

## Context

**What R-B requires.** The owner selected R-B on ADR-0057 (2026-11-01): R3's
real-container level is required, the residual is not accepted, and M5e.2
cannot close without E6 — real `PROXY_ONLY` containers weakened one hard rule
at a time, measured from both vantages and refused by the production broker
(ADR-0057 §§1, 8). The plan's §3b says what such evidence must carry; its
§3a found that no existing source observes it.

**Why it was not built before.** An earlier session's work on exactly that was
stopped by a safety control, and the owner directed that it not be worked
around (ADR-0057, Context). On 2026-11-08 the owner authorised this defensive
assurance work on the project's own sandbox, in writing, within the applicable
safety controls and with no control circumvented, in an isolated and
disposable environment (§3b, criterion 1). It was built openly under that
authorisation: what it does is stated here, in its tests and in its job, and
nothing was obscured to get past any control.

**Why the weakening cannot be the broker's.** The broker's plan spells
`oci-strict` and nothing else: TX032 refuses a weakening word in `plan.rs`,
and the plan's tests hold that it spells every hard rule (ADR-0057 §4). That
must stay true. So a weakened environment the production broker prepares can
only come from where ADR-0057 §4 says one could: **a runtime that does not do
what the plan asks.**

## Decision

### 1. The evidence path: a faulty runtime at the runtime's API

The test (the egress suite's `e6` module,
`crates/dwkd-broker/tests/sandbox_egress.rs`), playing the authority as every
broker suite does, hands the released broker a runtime socket that is a
test-only forwarder between the real client the authority hashed and the real
daemon. The forwarder relays every request and every answer byte for byte —
the version check, the image check, the relay's and the probe's copies, the
setup's `run`, the relay's `create` and `start`, every `inspect`, every
`exec`, every removal — **except one request**: the `create` whose labels name
the case's environment and the `environment` role, in which it changes
exactly the field (for the resource limits, the two fields) that M5a's
matching weakening flag puts there (§3). The daemon then records and runs
exactly that container. Nothing the daemon or the kernel answers is changed:
the record the broker judges is the daemon's own, and the probe's report is
the kernel's view from inside, read through the same socket, which keeps a
copy of each.

So everything that makes the environment `PROXY_ONLY` is the broker's own:
its proxy opened before anything could connect, the environment created in
the `none` network with the broker's proxy variables, the relay in the image
hashed against the authority's digest, the setup run and removed, the relay
started in the environment's namespace with the broker's directory mounted —
and so is the measurement (`HOST_*` from the record, `CONTAINER_*` from the
digest-pinned probe) and the decision (`kept_or_taken_down`, `oci::clean`)
that refuses it and tears it down whole. The broker under test is the
released binary, unmodified; the test changes no product line.

### 2. The control, and what keeps a refusal the weakening's

The same forwarder with no fault must forward a conforming environment's
`create` byte for byte, and the broker must keep it — every required
invariant passing, the topology's four included — and then destroy it
exactly. Each weakened case must have asked for that same strict plan (its
labels aside, its environment compared as a set: Docker's CLI 29.9.2 orders
the proxy variables differently from one invocation to the next, which the
judgement does not depend on), and the daemon must have received it with
**exactly** the case's fields changed and no other.

### 3. The cases

ADR-0057 §1a's fifteen rows, one case each; the resource-limit row's task
backstop (ADR-0056) a second case of its row. The host's network runs last.

| Case | §1a's row | The `create` field(s) changed | Must fail (vantage) |
|---|---|---|---|
| `e6-weakened-writable-root-refused` | Read-only root | `HostConfig.ReadonlyRootfs` | `HOST_ROOT_READ_ONLY`, `CONTAINER_ROOT_READ_ONLY` (both) |
| `e6-weakened-root-user-refused` | Non-root user | `User` | `HOST_USER_NON_ROOT`, `CONTAINER_UID_GID` (both) |
| `e6-weakened-privileged-refused` | Not privileged | `HostConfig.Privileged` | `HOST_NOT_PRIVILEGED`, `CONTAINER_CAPABILITIES_EMPTY`, `CONTAINER_DEVICES_MINIMAL`, `CONTAINER_PROC_RESTRICTED` (both) |
| `e6-weakened-runtime-socket-mounted-refused` | No runtime socket | `HostConfig.Binds` | `HOST_NO_RUNTIME_SOCKET`, `HOST_MOUNTS_EXACT`, `CONTAINER_NO_RUNTIME_SOCKET` (both) |
| `e6-weakened-capability-added-refused` | Capabilities dropped | `HostConfig.CapAdd` | `HOST_CAPABILITIES_DROPPED`, `CONTAINER_CAPABILITIES_EMPTY` (both) |
| `e6-weakened-no-new-privileges-disabled-refused` | `no-new-privileges` | `HostConfig.SecurityOpt` | `HOST_NO_NEW_PRIVILEGES`, `CONTAINER_NO_NEW_PRIVILEGES` (both) |
| `e6-weakened-seccomp-unconfined-refused` | Pinned seccomp, not unconfined | `HostConfig.SecurityOpt` | `HOST_SECCOMP_PROFILE`, `CONTAINER_SECCOMP_PROFILE_ACTIVE` (both) |
| `e6-weakened-seccomp-default-profile-refused` | Pinned seccomp, not the runtime's default | `HostConfig.SecurityOpt` | the same (both) |
| `e6-weakened-host-pid-refused` | Private PID namespace | `HostConfig.PidMode` | `HOST_PID_NAMESPACE_PRIVATE`, `CONTAINER_PID_NAMESPACE_PRIVATE` (both) |
| `e6-weakened-host-ipc-refused` | Private IPC namespace | `HostConfig.IpcMode` | `HOST_IPC_NAMESPACE_PRIVATE` (host only) |
| `e6-weakened-host-uts-refused` | Private UTS namespace | `HostConfig.UTSMode` | `HOST_UTS_NAMESPACE_PRIVATE` (host only) |
| `e6-weakened-mutable-image-tag-refused` | Image pinned by digest | `Image` | `HOST_IMAGE_PINNED` (host only) |
| `e6-weakened-extra-device-refused` | No devices | `HostConfig.Devices` | `HOST_NO_DEVICES`, `CONTAINER_DEVICES_MINIMAL` (both) |
| `e6-weakened-resource-limits-dropped-refused` | Resource limits | `HostConfig.PidsLimit`, `HostConfig.MemorySwap` | `HOST_RESOURCE_LIMITS`, `CONTAINER_CGROUP_LIMITS` (both) |
| `e6-weakened-task-backstop-at-256-refused` | Resource limits (the 8 192 task backstop) | `HostConfig.Ulimits` (`nproc` 256) | `HOST_RESOURCE_LIMITS`, `CONTAINER_RLIMITS` (both) |
| `e6-weakened-host-network-refused` | Isolated network | `HostConfig.NetworkMode` | `HOST_NETWORK_ISOLATED`, `CONTAINER_NETWORK_ISOLATED`, `CONTAINER_DIRECT_EGRESS_REFUSED`, `CONTAINER_DIRECT_DNS_REFUSED` (both) |

With the control (`e6-faulty-runtime-forwards-a-conforming-environment-kept`)
and the count (`e6-row-count`), 18 cases, suite `sandbox-proxy-weakened`, each
at `real-oci` (`scripts/dw.py`, `E6_ROWS`, `ATTRIBUTION`). The test's rows and
the task's are held equal, and their coverage of §1a's rows and vantages
checked, by `tests/architecture/test_m5e_e6.py`.

### 4. What each case must show, three times over

1. **In the test, as it runs.** Exactly one `create` weakened — the
   environment's, in exactly its fields — every other forwarded unchanged; the
   setup and the relay made — for the host's network neither, the broker's own
   `relay_withheld network=FAIL`, and the host's loopback, kept before and
   after, unchanged (ADR-0059 §3); the environment **not kept**, and the broker's
   own `environment_prepared … retained=false` event; the probe's report
   arrived; every invariant of the row `FAIL`; the record the broker judged
   showing the weakening; every inside verdict of the broker's answer equal to
   the probe's own report; nothing of the environment left — no container of
   its labels, no listener directory.
2. **In its line** (`e6_outcome_problem`, through
   `require_attributed_evidence`). Refused by exactly the row's invariants, of
   the vantage its enforcement names; every other invariant that did not pass
   reported (`also:`); the topology's four reported whatever their verdicts
   (`topology:`) — how a weakening and the topology interact is observed
   (ADR-0057 §3, U3), not assumed; the fields changed; for the host's network,
   that the host's loopback gained nothing (`none`, ADR-0059). The control
   kept, its topology passing; the count complete. A row not exercised fails
   E6 whole.
3. **From the raw bytes, independently** (`e6_check_raw`, Python, over what
   the test wrote). Each case's eight files — the create as sent and as
   received, the daemon's record (the measurement's read), the probe's raw
   stream and its report, the broker's answer, its requests and its events —
   and for the host's network a ninth, the host's loopback before and after,
   at the digest the test printed when it wrote them, and nothing else; the
   same plan for every case; the row's fields alone changed; the record
   showing the weakening; the report exactly the stream's stdout; the broker's
   inside verdicts the report's; the refusal in the answer and in the event;
   the environment's record read before any peer was asked for; the setup and
   relay created — for the host's network neither, the withholding in the
   broker's event, no relay measured and the loopback unchanged, as the line
   says; the line's topology the answer's.

### 5. Where it runs

Only on a disposable GitHub-hosted runner: the required job
`sandbox-proxy-weakened` runs `make sandbox-proxy-weakened-evidence` with
`DW_E6_EVIDENCE=1`, which no other job sets; the task refuses before it builds
anything anywhere else (NOT EXERCISED, which fails), and refuses Docker
Desktop. The one case that could touch the host — the host's network, in
which the broker's setup, run in a namespace that is the host's, added the
proxy address to the host's own loopback until ADR-0059's gate (§8) — is
refused by the test itself anywhere but such a runner: what protects the host
there is the gate under test. A run anywhere else is development, never E6.

### 6. Against §3b's criteria

| §3b | How it is met |
|---|---|
| 1. Authorisation | The owner's authorisation of 2026-11-08 (this record's status line); a disposable GitHub-hosted runner, enforced by the task and the test (§5) |
| 2. Provenance | The published manifest: the commit (and `GITHUB_SHA`), whether the tree was clean, the run's URL and attempt, the runner's image and kernel, the runtime's version, API, OS and architecture, the client's path, identity and SHA-256, the probe's and relay's SHA-256 (equal to what the measurement pinned), every image |
| 3. Authentic observations | Per case, the daemon's record as the broker read it and the probe's raw stream, unedited, each with its SHA-256 — kept by the forwarder, never re-typed |
| 4. Vantage attribution | Each refusal names its invariants; the gate holds them to the vantage the contract gives each case (three host-only rows, the rest both) |
| 5. `PROXY_ONLY`, really | The broker's own preparation and its `PROXY_ONLY` measurement; the topology's four invariants reported for every case; the control kept through the same runtime |
| 6. One hard rule at a time | Exactly the row's fields changed, from the control's plan; every other invariant that moved reported |
| 7. The production refusal | `retained=false` from the broker's `prepare`, and its own event — its measurement and `oci::clean`, never a re-implementation; a container that failed to start would show no measurement and fail the case |
| 8. Cleanup and ownership | Per case, no container of the environment's labels and no listener directory; the task's before-and-after census of every container and network |
| 9. Completeness | 16 cases over all 15 rows, the control and the count required by name; one not exercised fails E6 |
| 10. Integrity and reproducibility | Every file digested where it is written and checked again where it is read; all of them, base64, and one manifest with its own digest published into the job's log; `make sandbox-proxy-weakened-review` (`DW_E6_LOG=<downloaded log>`) re-verifies a hosted log offline, needing no runtime |

### 7. Observed in development, not evidence (2026-11-08)

Run on the developer's Docker Desktop (engine 29.9.2, API 1.56) by a scratch
harness through the task's own helpers, `DW_E6_EVIDENCE=1` and no hosted
runner — so the host's network was refused by the test, as §5 requires, and
the count and the attribution gate failed, as they must off a runner. The
control was kept; each of the other fifteen cases was refused by exactly its
row's invariants, the topology's four passing in every one; and the 128 raw
observations passed the independent check. Also reported, never hidden: the
runtime socket also fails `CONTAINER_MOUNTS_EXPECTED`; seccomp unconfined
also fails the canaries `CONTAINER_UNSHARE_BLOCKED` and
`CONTAINER_KEYRING_BLOCKED`; and the host's PID and IPC namespaces also fail
`HOST_NOT_PRIVILEGED` — the daemon records more than the one field there, and
nothing that hides the weakening. The client hangs up on one of `docker run
--rm`'s two `wait` requests for the setup; the forwarder records each such
hang-up in the case's requests, and a step the broker needed and did not get
would fail that step. **None of this is E6**: it ran on a daemon that is not
disposable, at no hosted commit, and without the host's network.

### 8. The host's network and the setup: predicted, observed, remedied

**Predicted (2026-11-08).** A runtime that gives the environment the host's
network namespace makes the broker's setup — root with `NET_ADMIN`, joining
the environment's namespace — add `169.254.7.1/32` to **the host's own
loopback**, and the relay then serves the run's proxy on the host's network
until the measurement refuses the environment and tears it down; the teardown
removes the containers and the listener but not the address. Not fail-open
(the environment is refused), but a host-side residue and a short exposure of
the run's grant to the host, under a runtime that ignores `--network none`:
finding **F-E6-HOSTNET**. Not remedied before the hosted run, so that the run
could observe it.

**Observed (hosted, `3ca842c`, run
[42484188848](https://github.com/Onwcan/DireWolf/actions/runs/42484188848)).**
Exactly that: the daemon's record shows `NetworkMode: host`; the setup and the
relay were created and started; the case reported
`host-loopback-added:169.254.7.1/32`, the hard rule refused from both
vantages. The residue was the line's word alone, not a raw observation, so the
offline review could not hold it (ADR-0059, Context).

**Remedied (built 2026-11-08, the owner's direction "build the fix first";
committed as `14405ab`).** [ADR-0059](0059-m5e-proxy-only-peer-joins-only-its-own-network-namespace.md):
the broker makes no peer unless the started environment's record passes
`HOST_NETWORK_ISOLATED`. The host-network case must now show no setup, no
relay, the broker's `relay_withheld network=FAIL`, and the host's loopback
unchanged, kept raw; the gate accepts `host-loopback-added:none` and nothing
else. The gate is the network's alone: every other weakening still gets its
peer, so the interaction this record exists to observe stays observed.

**Verified (hosted, `14405ab`, run
[42525106398](https://github.com/Onwcan/DireWolf/actions/runs/42525106398)).**
The daemon's record again `NetworkMode: host`; the broker read it right after
the environment started and made no setup and no relay; its event
`relay_withheld network=FAIL`; the same four invariants refused the
environment, `HOST_PROXY_RELAY`, `HOST_RELAY_DIGEST` and
`CONTAINER_PROXY_REACHABLE` failing beside them for want of a peer; the host's
loopback `127.0.0.1/8` before and after, kept raw; the line
`host-loopback-added:none` (ADR-0059 §6).

### 9. What closes E6, R3 and issue #19

1. The owner commits this change and ADR-0059's; the hosted
   `sandbox-proxy-weakened` job at that commit passes with every case at its
   level — the host's network with no peer and nothing gained (§8) — and the
   `ci` aggregate with it. (The run at `3ca842c` was of the broker before
   ADR-0059 and does not count.)
2. The owner reviews the hosted log — `make sandbox-proxy-weakened-review`
   over the downloaded log, and the manifest's provenance against the run.
3. The owner accepts ADR-0059 and this record. Then ADR-0057's status becomes
   "Superseded by ADR-0058", the index moves it to the superseded table, and
   `dwcheck adr --record` records all three in the accepted digest — ADR-0057
   too, because `dwcheck` holds a superseded record as immutable as an
   accepted one. The `test_m5e_r3_closure.py` guard, amended in the same
   change, then requires exactly that: ADR-0057 never Accepted, outside the
   digest while it stood, and inside it, at its bytes, once superseded by
   this record — which must itself be accepted and in the digest.
4. The owner explicitly authorises R3 satisfied and M5e.2 complete, and
   closes issue #19 once the hosted run of the change that records it
   passes.

*Taken (2026-11-09).* Step 1: `14405ab`, hosted run 42525106398, 31 of 31 jobs
(§10). Step 2: the review passed (§10), run for the owner. Step 3: the owner
accepted ADR-0059 and this record on 2026-11-09; ADR-0057 reads "Superseded
by ADR-0058", and the digest and the guard say so. Step 4: the owner
authorised R3 satisfied and M5e.2 complete on 2026-11-09
([M5E_ASSURANCE_PLAN.md](../M5E_ASSURANCE_PLAN.md) §10); issue #19 is the
owner's to close, after this change's own hosted run.

Before these steps E6 was **NOT EXERCISED — hosted evidence pending**, R3 was
not met, M5e.2 was IN PROGRESS, and ADR-0057 was Proposed under the owner's
R-B.

### 10. The hosted evidence (run 42525106398 at `14405ab`)

*Hosted (run
[42525106398](https://github.com/Onwcan/DireWolf/actions/runs/42525106398),
run no. 142, attempt 1, at `14405ab`, 2026-11-08): 31 of 31 jobs, the `ci`
aggregate among them; `sandbox-proxy-weakened` is job
[128866884086](https://github.com/Onwcan/DireWolf/actions/runs/42525106398/job/128866884086).*
A GitHub-hosted Ubuntu 26 runner (image 20261101.186.1, kernel
7.0.0-1019-azure), Docker 29.4.2, API 1.54, `runc`, cgroup v2. All 18 cases at
`real-oci`:

| Case | Refused by (vantage) | Also reported |
|---|---|---|
| `e6-faulty-runtime-forwards-a-conforming-environment-kept` | — kept, every required invariant passing, the topology's four passing; forwarded unchanged; destroyed | — |
| `e6-weakened-writable-root-refused` | `HOST_ROOT_READ_ONLY`, `CONTAINER_ROOT_READ_ONLY` (both) | none |
| `e6-weakened-root-user-refused` | `HOST_USER_NON_ROOT`, `CONTAINER_UID_GID` (both) | none |
| `e6-weakened-privileged-refused` | `HOST_NOT_PRIVILEGED`, `CONTAINER_CAPABILITIES_EMPTY`, `CONTAINER_DEVICES_MINIMAL`, `CONTAINER_PROC_RESTRICTED` (both) | none |
| `e6-weakened-runtime-socket-mounted-refused` | `HOST_NO_RUNTIME_SOCKET`, `HOST_MOUNTS_EXACT`, `CONTAINER_NO_RUNTIME_SOCKET` (both) | `CONTAINER_MOUNTS_EXPECTED` |
| `e6-weakened-capability-added-refused` | `HOST_CAPABILITIES_DROPPED`, `CONTAINER_CAPABILITIES_EMPTY` (both) | none |
| `e6-weakened-no-new-privileges-disabled-refused` | `HOST_NO_NEW_PRIVILEGES`, `CONTAINER_NO_NEW_PRIVILEGES` (both) | none |
| `e6-weakened-seccomp-unconfined-refused` | `HOST_SECCOMP_PROFILE`, `CONTAINER_SECCOMP_PROFILE_ACTIVE` (both) | `CONTAINER_SECCOMP_FILTER`, `CONTAINER_NETWORK_ISOLATED`, `CONTAINER_UNSHARE_BLOCKED`, `CONTAINER_KEYRING_BLOCKED` |
| `e6-weakened-seccomp-default-profile-refused` | `HOST_SECCOMP_PROFILE`, `CONTAINER_SECCOMP_PROFILE_ACTIVE` (both) | none |
| `e6-weakened-host-pid-refused` | `HOST_PID_NAMESPACE_PRIVATE`, `CONTAINER_PID_NAMESPACE_PRIVATE` (both) | `HOST_NOT_PRIVILEGED` |
| `e6-weakened-host-ipc-refused` | `HOST_IPC_NAMESPACE_PRIVATE` (host) | `HOST_NOT_PRIVILEGED` |
| `e6-weakened-host-uts-refused` | `HOST_UTS_NAMESPACE_PRIVATE` (host) | none |
| `e6-weakened-mutable-image-tag-refused` | `HOST_IMAGE_PINNED` (host) | none |
| `e6-weakened-extra-device-refused` | `HOST_NO_DEVICES`, `CONTAINER_DEVICES_MINIMAL` (both) | none |
| `e6-weakened-resource-limits-dropped-refused` | `HOST_RESOURCE_LIMITS`, `CONTAINER_CGROUP_LIMITS` (both) | none |
| `e6-weakened-task-backstop-at-256-refused` | `HOST_RESOURCE_LIMITS`, `CONTAINER_RLIMITS` (both) | none |
| `e6-weakened-host-network-refused` | `HOST_NETWORK_ISOLATED`, `CONTAINER_NETWORK_ISOLATED`, `CONTAINER_DIRECT_EGRESS_REFUSED`, `CONTAINER_DIRECT_DNS_REFUSED` (both) | none; no peer (§8), the host's loopback gained nothing |
| `e6-row-count` | refused 16 of 16 cases; rows 15 of 15 | — |

In every weakened case the daemon received the control's plan with exactly
the row's field(s) changed, the environment was not kept, and nothing of it
was left; in every case but the host's network the setup and the relay were
made, the topology's four passing. The task's census found no evidence
container or network left, and the three networks that predated the run kept.
Every line but the host's network is byte-identical to run 42484188848's.

*Reviewed offline (2026-11-09), for the owner.* `make
sandbox-proxy-weakened-review` over the downloaded job log (SHA-256
`aa208e4cb07b2e4d88cf051052faec041d0cd8b7fc35641dbc08777aa6752330`) passed:
the manifest's SHA-256
`4f5ec9950bd6e502393d20be014c74b25dc325397b7abc062b3551f63f5e0840`, 137 raw
observations over 17 cases, each at its digest; the provenance the run's own —
commit and `GITHUB_SHA` `14405ab`, a clean tree, run 42525106398 attempt 1,
job `sandbox-proxy-weakened`, the runner and runtime above, the client
`/usr/bin/docker` with its SHA-256, the probe's and the relay's SHA-256, every
image. The same review refuses run 42484188848's log, and refused fifteen
tampered copies of this one, each for its own reason (ADR-0059 §6).

*What it does not show.* The weakening is injected at the runtime's API, so
the daemon records it: a runtime that lies in its record is not modelled
(Consequences). Three rows — the IPC and UTS namespaces and the mutable image
tag — are refused from the host's vantage alone, as ADR-0057 §1a's contract
gives them. The probe's and the relay's SHA-256 in the manifest are those the
run built and the measurement pinned; the repository records no expected
value for them, so they are checked against the run, not against a pin.
ADR-0059's gate trusts the runtime's record (its §2). The evidence is one
hosted run on one runner image and runtime version; a change to either is
caught only by the required job's next run.

## Consequences

**Positive.** E6 exists, as R-B requires, at the real-container level and
through the production path: the broker's own topology, measurement and
decision, over a container the real daemon recorded and ran weakened. It
closes ADR-0057's U1–U3 on its evidence (the record of a weakened
`PROXY_ONLY` environment, the inside vantage under each weakening, and how
each weakening and the topology interact), with every other moved invariant
reported. It is a required job, so a later change to the broker, the probe,
the topology or the runtime that stops a weakening being refused under
`PROXY_ONLY` fails CI. The raw observations make the result reviewable by
someone who trusts neither the test nor the task. Its hosted run at
`14405ab` passed every case (§10), and R3's real-container level, which the
owner's R-B required, is met on it.

**Negative.** The weakening is injected at the API, so the daemon records it:
this shows each hard rule caught when the runtime's record and the kernel
tell the truth about a weakened container, not a runtime that lies in its
record — the inside vantage is the defence there, and no case here models
it. A required job that runs privileged and host-sharing containers on every
commit is CI time and risk the hosted runner bears. The host's network case
changed the runner's loopback before ADR-0059 (§8), and would again under a
broker without its gate. The forwarder is some 650 lines of test
code (the whole `e6` module about 2 100, its own unit tests included) that
must keep parsing the client's HTTP; its unit tests, against a fake daemon,
run in `make test`. The probe's and the relay's digests are checked against
the run that built them, not against a pin the repository records (§10).

## Alternatives considered

**A weakening switch in the broker, test-only.** Rejected: the product would
hold a path to a weaker plan, which TX032 and ADR-0047 §4 exist to refuse.

**Containers made by the test, as M5a's `NO_NETWORK` cases are.** Rejected for
E6: the topology — the proxy listener, its directory, the setup, the relay —
would be the test's re-implementation, not the broker's, which §3b's criteria
5 and 7 refuse; it stays the right shape for E3.

**An OCI runtime shim behind the daemon.** Rejected for E6: it would weaken
the running container while the daemon's record stays strict — a lying
runtime, whose host-only rows (IPC, UTS, the image) no vantage could catch.
That is a different, deeper experiment; it is not what §1a's rows ask, and it
would need its own decision.

**An external laboratory.** Not needed: the owner's own disposable hosted
runner is isolated and disposable (§3b, criterion 1), and its log is the
record.

## Owner decision

**2026-11-08.** The owner authorised E6's implementation, its approach the
implementer's, within the applicable safety controls and in an isolated,
disposable environment ([M5E_ASSURANCE_PLAN.md](../M5E_ASSURANCE_PLAN.md) §10,
"E6's evidence path") — the implementation and its evidence path only. After
the first hosted run observed F-E6-HOSTNET, the owner directed: "Build the fix
first" (ADR-0059).

**2026-11-09: accepted.** After run 42525106398 at `14405ab` passed every case
and its E6 log was reviewed (§10), the owner adopted ADR-0059 and then this
record — the verified evidence for ADR-0057 §1a's fifteen rows — with ADR-0057
superseded by it, and approved the change that records it ("Yes, build it").
The limits §10 states stand as stated. Acceptance changed no product code,
protocol, schema, dependency or CI gate: the job stays required, and every
case in it.

## Revisit if

A hosted run of `sandbox-proxy-weakened` fails or shows an invariant move that
§10 does not record; ADR-0059's gate changes; the topology, the probe's or the
record's hard-rule code, or the runtime client changes; or a runtime that
misreports its record is to be modelled.
