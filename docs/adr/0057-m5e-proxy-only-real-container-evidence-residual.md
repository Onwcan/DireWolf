# ADR-0057: M5e.2 — R3's real-container residual: `PROXY_ONLY`'s weakened-profile closure is shown by real topologies, a real runtime's own record and the production judgement, not by real weakened `PROXY_ONLY` containers

**Status:** Proposed — the owner selected **R-B** on 2026-11-01 (§8): the real-container level is required, the residual is not accepted · **Date:** 2026-11-01 · **Would limit (on acceptance, and only with the owner's separate approval of that change):** R3's claim in M5's acceptance ([ROADMAP.md](../ROADMAP.md), M5e and "The M5 contract"; §5) — not approved: under the owner's R-B (§8) it limits nothing · **Refines:** [ADR-0047](0047-m5a-oci-execution-environment-and-measured-assurance.md) §9 (weakened profiles are caught by measurement), [ADR-0048](0048-m5b-proxy-only-topology-and-connect-proxy.md) §§9, 14 (`PROXY_ONLY`'s measurement and its weakened topologies) · **Addresses:** requirement R3 and gap G5 of [M5E_ASSURANCE_PLAN.md](../M5E_ASSURANCE_PLAN.md) (§§2–4) · **Drafting authorised by:** the owner, 2026-11-01 ("Record a residual ADR") — the drafting only: not an acceptance of the residual, not evidence, and not a change to M5's acceptance contract

> **Every hard rule weakened under `PROXY_ONLY` is refused by the production
> judgement over a real runtime's own record of a real `PROXY_ONLY`
> environment; the same measurement catches each hard rule weakened in a real
> `NO_NETWORK` container, from both vantages; and every weakened or drifted
> `PROXY_ONLY` topology is caught on a real container. No real `PROXY_ONLY`
> container has been run with a hard rule weakened. This record states that
> gap as a residual, says exactly what is and is not shown, and asks the owner
> whether M5e.2 may close with it.**

This is a proposal, and the owner has answered its question: on 2026-11-01
the owner selected **R-B — require the real-container level** (§§7–8), not
R-A, the residual this record proposed. So the residual is **not accepted**,
§5's limited claim is **not approved**, and nothing here waives R3: R3 is not
met at the real-container level, M5e.2 stays in progress, and M5's
acceptance contract stands as written. The record stays Proposed, outside the
accepted digest, as the statement of the gap R-B requires closed (§8).

## Context

**What R3 asks.** M5's contract requires the defaults of
[SANDBOX.md](../SANDBOX.md) §2 verified at runtime and "a weakened-profile
meta-test for each hard rule" that makes the gate fail
([ROADMAP.md](../ROADMAP.md), "The M5 contract"; SANDBOX.md §6). M5e's
deliverables add the weakened-profile closure for `PROXY_ONLY`, which the M5e
plan states as R3: the weakenings also hold, and are caught, in a
`PROXY_ONLY` environment ([M5E_ASSURANCE_PLAN.md](../M5E_ASSURANCE_PLAN.md)
§2).

**Where M5e.2 stands (2026-11-01).** R2, R8, R9 and R11 are hosted-verified —
R8 first in hosted run
[41242001763](https://github.com/Onwcan/DireWolf/actions/runs/41242001763)
at `615e77e` (29 of 29 jobs), where the other three passed again — and the
owner accepted
[ADR-0056](0056-m5e-cross-run-task-limit-isolation.md), F-R8's remedy, on
2026-11-01. That acceptance decides R8 and nothing about R3. R3 is the one
requirement of M5e.2 still open.

**Why the real-container level is missing.** Real `PROXY_ONLY` containers
weakened one hard rule at a time were planned for M5e.2. An earlier session's
work on exactly that was stopped by a safety control, and the owner directed
that it not be worked around (M5E_ASSURANCE_PLAN.md §3, R3). What M5e.2 built
instead is the production judgement over records, the last of them a real
runtime's own. This record documents that gap; it plans no way around the
stop, and nothing here was built or run to produce container evidence.

**How an environment is judged.** Two vantages, one decision
([ADR-0047](0047-m5a-oci-execution-environment-and-measured-assurance.md) §8;
[ADR-0048](0048-m5b-proxy-only-topology-and-connect-proxy.md) §9): the broker
reads the runtime's `container inspect` record (the `HOST_*` invariants), and
the digest-pinned probe inside the environment reports what the kernel says
about it (the `CONTAINER_*` invariants); `PROXY_ONLY` requires every one,
`NO_NETWORK` all but the relay's digest and the proxy's reachability. Two
facts of the code bound what a topology can change:

- **The host judgement of every hard rule reads the same fields under both
  topologies** (`crates/dwkd-broker/src/sandbox/inspect.rs`, `Record::judge`).
  Only `HOST_PROXY_ENVIRONMENT` takes the topology; `HOST_PROXY_RELAY` and
  `HOST_RELAY_DIGEST` are `PROXY_ONLY`'s own. A `PROXY_ONLY` environment is
  itself an interface-free namespace — its record's network mode is `none`,
  as a `NO_NETWORK` one's is — and what makes it `PROXY_ONLY` is around it:
  its proxy variables, the loopback address its setup container adds, and the
  relay that joins its namespace (ADR-0048 §2).
- **The probe attempts the same for both topologies**
  (`crates/dwk-sandbox-probe/src/linux.rs`, `measure`): the topology is named
  so that a report is of a stated environment, and the authority decides which
  verdicts each topology requires.

So the hard rules' code is shared. What is not shared is the runtime's
behaviour, and the kernel's, when one hard rule is weakened in a container
that is also part of `PROXY_ONLY`'s arrangement.

## Decision (proposed; the owner's answer is §8)

### 1. What R3's evidence is, by level

Each row is evidence a required task asks for by name, at the level its lines
carry ([SANDBOX.md](../SANDBOX.md) §6a); nothing is listed on any other basis.

| # | Evidence | Cases | Level | Hosted |
|---|---|---|---|---|
| E1 | Real `PROXY_ONLY` preparation and measurement | `proxy-only-prepare-clean`, `proxy-only-measure-clean-again` (both vantages); `proxy-only-host-*` (capabilities dropped, network isolated, proxy environment, proxy relay, relay digest); `proxy-only-container-*` (capabilities empty, network isolated, proxy reachable, direct egress and direct DNS refused, raw sockets refused); `proxy-only-relay-shares-the-namespace-unprivileged` | `real-oci` | `sandbox-egress`, since M5b; again in run 41242001763 |
| E2 | Real topology and network isolation | `weakened-bridge-network`, `weakened-missing-relay`, `weakened-relay-tampered`, `weakened-proxy-variables-removed`, `drift-extra-peer-listening`, `drift-fake-resolver-in-namespace`, `drift-egress-directory-opened`, `drift-setup-left-running`, `drift-relay-stopped`, `weakened-topology-count`; every direct path out refused (`bypass-*`, R4) | `real-oci` | `sandbox-egress`, as E1 |
| E3 | Real weakened hard rules, under `NO_NETWORK` | `weakened-writable-root`, `-root-user`, `-privileged`, `-runtime-socket-mounted`, `-capability-added`, `-no-new-privileges-disabled`, `-seccomp-unconfined`, `-seccomp-default-profile`, `-host-pid`, `-host-ipc`, `-host-uts`, `-host-network`, `-mutable-image-tag`, `-extra-device`, `-resource-limits-dropped`, `weakened-count`; `drift-pids-limit-raised` | `real-oci`; both vantages, except host IPC, host UTS and the image tag (host-side facts) | `sandbox-foundation`, since M5a; host UTS since run 41130431929 |
| E4 | The production judgement over a real runtime's own `PROXY_ONLY` record | `captured-proxy-only-conforming-kept` and eighteen `captured-proxy-only-weakened-*-refused`: the `PROXY_ONLY` hard rules of E5 (U4's three among them since 2026-11-01) and the task backstop put back at 256 | `in-process` — the record is real; each weakening, and its judgement, are made in the test process | `sandbox-egress`, run 41242001763; U4's three built 2026-11-01, hosted run pending |
| E5 | The production judgement over hand-written records | `proxy-only-conforming-kept`, `no-network-conforming-kept`; `proxy-only-weakened-*-refused` for host UTS, a writable root, root, privileged, an added capability, `no-new-privileges` off, seccomp unconfined, host PID, host IPC, host network, a mutable tag, the runtime socket, an extra device and the limits dropped; since 2026-11-01 (U4) the runtime's default seccomp profile, the swap limit lifted, and the pids and swap limits lifted together; `no-network-weakened-host-uts-refused` | `in-process` | `sandbox-foundation`, since run 40954372045; U4's three, hosted run pending |
| E6 | **Real `PROXY_ONLY` containers, one hard rule weakened at a time, measured from both vantages** | none | — | **NOT EXERCISED — BLOCKED**: not built and not planned; required by the owner's R-B (§8) |

### 1a. By hard rule

The same evidence, one hard rule to a row: the invariants a weakening of it
must fail, and from which vantage the architecture measures them (ADR-0047
§8) — three are host-only facts, read from the runtime's record, which no
probe is asked to see from inside. Case names are abbreviated
(`…` = `proxy-only-weakened-`, `captured-` the same over the real record).
E6 is not a column: for every row it is **NOT EXERCISED — BLOCKED** (§8).

| Hard rule | Invariants that must fail (vantage) | Real `NO_NETWORK` (E3, `real-oci`) | `PROXY_ONLY` judged, the host's invariants only (E5; E4 as `captured-`; `in-process`) |
|---|---|---|---|
| Read-only root | `HOST_ROOT_READ_ONLY`, `CONTAINER_ROOT_READ_ONLY` (both) | `weakened-writable-root` | `…writable-root-refused` |
| Non-root user | `HOST_USER_NON_ROOT`, `CONTAINER_UID_GID` (both) | `weakened-root-user` | `…root-user-refused` |
| Not privileged | `HOST_NOT_PRIVILEGED`; `CONTAINER_CAPABILITIES_EMPTY`, `CONTAINER_DEVICES_MINIMAL`, `CONTAINER_PROC_RESTRICTED` (both) | `weakened-privileged` | `…privileged-refused` |
| No runtime socket | `HOST_NO_RUNTIME_SOCKET`, `HOST_MOUNTS_EXACT`, `CONTAINER_NO_RUNTIME_SOCKET` (both) | `weakened-runtime-socket-mounted` | `…runtime-socket-mounted-refused` |
| Capabilities dropped | `HOST_CAPABILITIES_DROPPED`, `CONTAINER_CAPABILITIES_EMPTY` (both) | `weakened-capability-added` | `…capability-added-refused` |
| `no-new-privileges` | `HOST_NO_NEW_PRIVILEGES`, `CONTAINER_NO_NEW_PRIVILEGES` (both) | `weakened-no-new-privileges-disabled` | `…no-new-privileges-disabled-refused` |
| The pinned seccomp profile, not unconfined | `HOST_SECCOMP_PROFILE`, `CONTAINER_SECCOMP_PROFILE_ACTIVE` (both) | `weakened-seccomp-unconfined` | `…seccomp-unconfined-refused` |
| The pinned seccomp profile, not the runtime's default | the same (both) | `weakened-seccomp-default-profile` | `…seccomp-default-profile-refused` (U4) |
| Private PID namespace | `HOST_PID_NAMESPACE_PRIVATE`, `CONTAINER_PID_NAMESPACE_PRIVATE` (both) | `weakened-host-pid` | `…host-pid-refused` |
| Private IPC namespace | `HOST_IPC_NAMESPACE_PRIVATE` (host only) | `weakened-host-ipc` | `…host-ipc-refused` |
| Private UTS namespace | `HOST_UTS_NAMESPACE_PRIVATE` (host only) | `weakened-host-uts` | `…host-uts-refused` |
| Isolated network | `HOST_NETWORK_ISOLATED`, `CONTAINER_NETWORK_ISOLATED`, `CONTAINER_DIRECT_EGRESS_REFUSED`, `CONTAINER_DIRECT_DNS_REFUSED` (both) | `weakened-host-network` | `…host-network-refused` |
| Image pinned by digest | `HOST_IMAGE_PINNED` (host only) | `weakened-mutable-image-tag` | `…mutable-image-tag-refused` |
| No devices | `HOST_NO_DEVICES`, `CONTAINER_DEVICES_MINIMAL` (both) | `weakened-extra-device` | `…extra-device-refused` |
| Resource limits, the 8 192 task backstop included | `HOST_RESOURCE_LIMITS`, `CONTAINER_CGROUP_LIMITS` (both) | `weakened-resource-limits-dropped` (pids and swap lifted); `drift-pids-limit-raised` | `…resource-limits-dropped-refused` (pids raised); `…swap-limit-lifted-refused`, `…pids-and-swap-limits-lifted-refused` (U4); `captured-…task-backstop-at-256-refused` (E4 only) |

`PROXY_ONLY`'s own invariants — `HOST_PROXY_ENVIRONMENT`, `HOST_PROXY_RELAY`,
`HOST_RELAY_DIGEST`, `CONTAINER_PROXY_REACHABLE` — are the topology's, not
hard rules, and are weakened on real containers already (E2).

### 2. What is proven

- **The decision.** Given a `PROXY_ONLY` record with exactly one hard rule
  weakened, the production decision (`oci::clean`) refuses the environment,
  and exactly the invariants the weakening states fail (E5) — and it does so
  over the runtime's own field names, defaults and ordering, not only an
  imitation of them (E4). This is judgement, never an environment's
  measurement, and no line of it says otherwise.
- **The measurement, in a real container.** The same two vantages, with the
  same hard-rule code as `PROXY_ONLY` uses (Context), catch each hard rule
  weakened in a real container the runtime actually ran (E3).
- **`PROXY_ONLY`'s own boundary, in real containers.** A `PROXY_ONLY`
  environment is prepared and measured clean from both vantages (E1); each
  weakened or drifted topology is caught (E2); and every direct path out is
  refused by the topology itself (E2, R4).

### 3. What remains unverified

- **U1 — the runtime's record of a weakened `PROXY_ONLY` environment.** E4
  and E5 change one field of a conforming record and assume the runtime,
  asked for that weakening, would change that field and nothing that
  hides it. Under `NO_NETWORK` that was shown (E3); under `PROXY_ONLY` — with
  its proxy variables, its setup container's address and its relay in the
  same namespace — it was not.
- **U2 — the inside vantage under a weakening.** In a `PROXY_ONLY`
  environment the probe has only ever reported a conforming one. So under
  `PROXY_ONLY` each hard rule's refusal is shown from one vantage, the host's
  judgement; ADR-0047's two vantages are shown against weakenings under
  `NO_NETWORK` only.
- **U3 — a weakening's interaction with the topology.** What an added
  capability, privilege, the host's PID namespace or an extra device gives a
  workload in the namespace it shares with its relay, and whether the
  topology's own invariants (`CONTAINER_RAW_SOCKETS_REFUSED`,
  `CONTAINER_DIRECT_EGRESS_REFUSED`, `HOST_PROXY_RELAY`) move with it. This
  record claims no answer.
- **U4 — two weakenings were not judged under `PROXY_ONLY` even in process.**
  The runtime's *default* seccomp profile (`weakened-seccomp-default-profile`)
  was a real case under `NO_NETWORK` only; and the in-process "limits dropped"
  cases raise the pids limit alone, where the real `NO_NETWORK` case also
  lifts the swap limit. **Closed in process on 2026-11-01**, a test-only
  change: `proxy-only-weakened-seccomp-default-profile-refused`,
  `proxy-only-weakened-swap-limit-lifted-refused` and
  `proxy-only-weakened-pids-and-swap-limits-lifted-refused` — the last
  lifting both limits as the real `NO_NETWORK` case asks the runtime to
  (`--pids-limit -1`, `--memory-swap -1`) — over the hand-written record (E5)
  and over the real runtime's own (`captured-*`, E4), each `in-process` and
  required by name, with controls for every resource-limit field missing or
  mismatched and for every other seccomp profile; their hosted run is
  pending. That closes U4's judgement, not U1–U3: only E6 closes those.

### 4. Security implications

**Where a weakened `PROXY_ONLY` environment could come from.** Not from
DireWolf's plan: it is built from the profile's constants
(`dwk-sandbox-profile`), and the plan tests hold that it spells every hard
rule and no weakening (`crates/dwkd-broker/src/sandbox/plan_tests.rs`). It
could come from a runtime that does not do what the plan asks — a daemon
default, an authorisation plugin, a different runtime behind the client the
authority hashed (ADR-0047 §2) — or from a change after preparation, which
the next measurement sees (ADR-0047 §9's drift;
[ADR-0052](0052-m5d-sandboxed-process-exec.md), the broker's re-judgement
before every workload).

**What stops it, and what is not shown.** Both vantages, on every
preparation and every workload, with code the topologies share. The residual
is a runtime behaviour peculiar to `PROXY_ONLY`'s arrangement that weakens a
hard rule while neither the runtime's record nor the kernel's view from
inside shows it the way it does under `NO_NETWORK`. Were both vantages to miss
it, a weakened environment would be served as `oci-strict` under
`PROXY_ONLY`.

**Its weight.** The impact would be whatever the weakening grants — up to the
host-level access the hard rules exist to deny (the runtime socket,
privilege, the host's namespaces) — so it is high. Its likelihood rests on
what is shown: the hard rules' code is the same for both topologies and
catches each weakening in a real `NO_NETWORK` container, and the decision
refuses each weakening in a real `PROXY_ONLY` record. This record rates the
likelihood low and **unmeasured**, not absent. Unlike F-R8, the residual is
**not fail-closed** by construction: if both vantages missed a weakening,
nothing else would refuse the environment.

**What it does not touch.** `PROXY_ONLY`'s network boundary keeps its own
real-container evidence (E1, E2); R4–R7 and R9–R13 keep theirs; ADR-0056 and
R8 are unaffected.

### 5. The proposed limitation of M5's acceptance claim

**Not approved — the owner selected R-B (§8).** The wording below is not
M5's claim and limits nothing; it is kept as what was proposed.

If — and only if — the owner accepts this record **and** separately approves
the change of wording, R3's claim in M5's acceptance reads:

> Weakened-profile closure for `PROXY_ONLY` is shown by real weakened and
> drifted topologies, by real `PROXY_ONLY` environments measured clean from
> both vantages, by each hard rule weakened in a real `NO_NETWORK` container
> and caught from both vantages where it is visible from inside, and by the
> production judgement refusing each hard rule weakened in a real runtime's
> own `PROXY_ONLY` record. Real `PROXY_ONLY` containers weakened one hard rule
> at a time are not exercised (ADR-0057).

Until that approval, ROADMAP.md's M5e acceptance and its M5 contract stand as
written, and R3 is not met. Either way, no evidence line is relabelled: E4 and
E5 stay `in-process`, no case is added or removed, and M5e.6's gate requires
every R3 case at the level it carries.

### 6. Conditions, if accepted

**Moot under R-B (§8)**, kept as proposed; U4 was closed in process all the
same (§3).

- The residual is stated wherever M5's weakened-profile closure is claimed:
  the ROADMAP's M5e section, the M5e plan's R3 row, SANDBOX.md §6 and the
  README's M5 status.
- E1–E5 stay required by name in their tasks and, at M5e.6, in the gate; a
  missing or NOT EXERCISED R3 case fails it as today.
- §3's U4 is either closed in process — the default-profile case and the swap
  limit judged under `PROXY_ONLY` too, a test-only change for the owner's
  approval — or carried in the residual by name.
- Acceptance is revisited on any trigger below.

### 7. The owner decision required (decided 2026-11-01: R-B, §8)

| | **R-A — accept the residual (proposed; not selected)** | **R-B — require the real-container level (selected 2026-11-01)** | **R-C — defer it to the gate (not selected)** |
|---|---|---|---|
| R3 at M5e.2 | Met at E1–E5, with §5's claim | Not met until E6 exists | Not met; carried to M5e.6 or later |
| M5e.2 | Closes once this record is accepted and §5's wording approved | Stays in progress | Closes on everything but E6, which stays open by name |
| M5's acceptance | With §5's limited claim | As written, after E6 | Waits for E6 |
| Work it needs | None beyond §6 | A separate, owner-approved plan for producing E6, given the safety stop; nothing here plans or builds it | The same as R-B, later |
| Residual | §§3–4, stated | None of §3's, once E6 passes | §§3–4 until then |

The record proposes R-A because the unshown part is narrow (§§2–3) and the
only option that closes it, R-B, depends on work that was stopped and that
the owner directed not be worked around; it does not argue that the residual
is negligible. R-B and R-C are the owner's
to choose instead. None of the three is taken by this record, by ADR-0056's
acceptance, or by any in-process case. The owner took R-B (§8).

### 8. The owner's decision: R-B (2026-11-01)

After hosted run
[41304247232](https://github.com/Onwcan/DireWolf/actions/runs/41304247232)
(run no. 115, at `576b249`, 29 of 29 jobs), which carried this record and
ADR-0056's acceptance, the owner selected **R-B — require the real-container
level**. What it decides:

- **R3's real-container requirement stays binding.** M5's acceptance
  contract and the ROADMAP's M5e acceptance stand as written; no wording is
  limited, and §5 is not approved.
- **The residual is not accepted.** R-A was not selected, and neither was
  R-C: E6 is required for M5e.2, not deferred to the gate. No document, this
  one included, waives R3.
- **E1–E5 remain supporting evidence, at their levels.** E4 and E5 stay
  `in-process`; a captured record judged in process does not replace a
  container, and no line is relabelled.
- **E6 is required — and blocked.** The safety control that stopped the
  earlier work on real weakened `PROXY_ONLY` containers stands, and its
  prerequisites are binding: this record plans no way around it, and nothing
  built since builds, plans or runs such a container. E6 needs a plan the
  owner approves that can be carried out within that control; until one
  exists, E6 is NOT EXERCISED — BLOCKED, R3 is not met, and M5e.2 stays in
  progress.
- **Nothing accepted was weakened.** No accepted ADR (ADR-0056 included),
  profile constant, hard rule, evidence case or CI gate changed; R-B decides
  R3's evidence requirement and nothing else.
- **U4 is closed in process** (§3): a gap in the supporting evidence, closed
  as supporting evidence — not E6.

**This record's disposition.** It stays **Proposed** and outside the
accepted digest: it is now the statement of the gap R-B requires closed, not
a decision to accept it, and accepting it would accept the residual R-B
refused. When real-container evidence closes the gap, the record that states
that evidence supersedes this one — "Superseded by", the one disposition
besides Accepted that the [template](README.md) provides — and it moves to
the index's superseded table as history. It is not withdrawn: its account of
the gap is what that evidence answers.

## Consequences

**Positive.** M5's weakened-profile claim under `PROXY_ONLY` says exactly
what the evidence shows, at the level each line carries; nothing in process
is relabelled as a container. The gap is named (E6, U1–U4), so the gate and
any later claim can be checked against it. M5e can move on once the owner
decides, without a change to code, evidence or CI.

**Under R-B, as decided.** R-A's negatives below do not arise — R3 keeps its
full claim — but M5e.2 cannot close until E6 exists, and E6 is blocked: M5e.2,
and with it M5, wait on a plan for E6 the owner approves within the safety
control. The residual of §§3–4 stands exactly as stated until E6 passes.

**Negative.** Under R-A, R3 is never shown at the level the contract's
wording implies; the two-vantage design is not shown against a weakened
`PROXY_ONLY` environment; the residual is not fail-closed; and a later change
of runtime or topology could widen it while E4 and E5 kept passing, since they
judge records rather than run containers.

## Alternatives considered

**Relabel E4 or E5 as real-container evidence.** Rejected. The level of a line
is the contract M5e.1 built ([SANDBOX.md](../SANDBOX.md) §6a); a judgement
over a record, even the runtime's own, is not an environment's measurement,
and a line claiming otherwise is what the attribution exists to refuse.

**Argue E3 covers `PROXY_ONLY`.** Rejected as a substitute: that the code is
shared is an argument about DireWolf, not evidence of the runtime's or the
kernel's behaviour in `PROXY_ONLY`'s arrangement. Kept as supporting evidence
(§2).

**Close M5e.2 on ADR-0056's acceptance.** Rejected: ADR-0056 decides R8 alone.

**Drop R3, or reword M5's contract, without the owner.** Rejected: the
contract is the owner's (§5).

## Revisit if

The owner approves a plan to produce E6 (then evidence replaces this residual,
and this record is superseded); the `PROXY_ONLY` topology changes (a veth pair,
a user namespace, another relay arrangement); either vantage's hard-rule code
starts to depend on the topology (`Record::judge`, the probe's `measure`); the
runtime, or the client the authority hashes, changes how it records an
environment that shares its namespace; or any weakened environment, in either
topology, is found served.
