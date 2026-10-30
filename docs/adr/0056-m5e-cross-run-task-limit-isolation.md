# ADR-0056: M5e — cross-run task-limit isolation: each environment's tasks bounded by its own pids cgroup, `RLIMIT_NPROC` raised to a host-wide backstop no set of environments the authority allows can reach (finding F-R8)

**Status:** Proposed · **Date:** 2026-10-30 · **Would amend (on acceptance):** [ADR-0047](0047-m5a-oci-execution-environment-and-measured-assurance.md) §5 (the `oci-strict` profile's `nproc`, and the value `HOST_RESOURCE_LIMITS` and `CONTAINER_RLIMITS` measure), [ADR-0052](0052-m5d-sandboxed-process-exec.md) §10 (the per-environment quotas) · **Refines:** [ADR-0048](0048-m5b-proxy-only-topology-and-connect-proxy.md) (its relays are already bounded by their cgroup alone) · **Addresses:** finding F-R8 and requirement R8 of [M5E_ASSURANCE_PLAN.md](../M5E_ASSURANCE_PLAN.md) (§3, §5a) · **Drafting authorised by:** the owner, 2026-10-30 — the drafting only, not a remedy

> **One environment's tasks are bounded by its own pids cgroup and by
> nothing it shares with another. `RLIMIT_NPROC`, which the kernel counts per
> host uid across every environment, becomes a host-wide backstop set above
> anything the authority's live-environment cap allows — so a workload at its
> own bound can never stop another run's probe or workload from starting.
> Nothing changes in production until §6's evidence has passed in hosted CI
> and the owner accepts this ADR.**

This is a proposal. It accepts nothing, changes no limit, no measured
invariant and no evidence requirement, and enables nothing. Until the owner
accepts it, finding F-R8 stays open, R8 stays failed, and M5e.2 cannot close.

## Context

**The finding (M5e.2, 2026-10-29).** Every environment's workload — and every
probe the broker runs in it — is host uid 10001 (`SANDBOX_UID`; there is no
user-namespace remapping, [SECURITY.md](../SECURITY.md) item 22, and the
design's `userns: remap` was never built, [SANDBOX.md](../SANDBOX.md) §2). Each
environment's tasks are bounded twice at 256 by the profile
(`dwk-sandbox-profile`): by its own pids cgroup (`PIDS_LIMIT`, `--pids-limit`)
and by `RLIMIT_NPROC` (`--ulimit nproc=256:256`). The two are not the same
kind of bound. The pids cgroup counts the tasks **of one environment**.
`RLIMIT_NPROC` is a per-process limit on a count the kernel keeps **per real
uid in its user namespace** — here the initial one — across every process of
that uid on the host: `fork`/`clone` fails `EAGAIN` once the count reaches the
caller's limit, and a process that changes to that uid (`docker exec`'s runtime
does) is marked over the limit and its `execve` fails `EAGAIN`. So a workload
that holds its own environment's bound exhausts the count every other
environment starts processes against.

*Observed* (Docker 29.9.2, Docker Desktop on WSL2):
`sandbox_workload.rs`'s
`a_neighbour_at_its_task_bound_leaves_another_environment_and_the_broker_serving`
holds environment A at its bound with `sandbox-fixture workload-hold-tasks`;
the broker then refuses environment B's workload `ENVIRONMENT_NOT_CLEAN`,
because the probe it runs in B before any workload cannot start. A one-off
diagnostic `exec`'d the fixture in B at the same moment: as uid 10001 it
failed `EAGAIN`, as uid 10002 it ran — B's own cgroup had room. Measured again
on 2026-10-30 by the reproducer itself: B refused 1.25 s after asking, while A held
253 threads beside its init and its own main thread and its next one was refused
`EAGAIN` (errno 11); once A ended, B measured clean and its next workload ran — the
coupling lasts exactly as long as the pressure. *Read from
the authority's code, not exercised end to end:* through `process.exec`, that
refusal records B's workload `FAILED` and destroys B's environment as drifted
(`state/workload.rs`, `destroy_reason`). It fails closed — nothing runs
unmeasured, nothing crosses an environment — but one run can deny every other
run its environment for as long as its wall clock lets it hold the bound, and
again on its next invocation. R8 requires the opposite.

**What each environment's tasks are, and where they are counted.** An
environment's init (the probe, holding), its workload and everything the
workload starts, and every `docker exec` the broker makes into it (the probe's
measurement, `workspace`, `reap`) are in that environment's cgroup and count
against its 256. Its relay and setup containers (`PROXY_ONLY`) run as
`RELAY_UID` 10002 in cgroups of their own (`RELAY_PIDS_LIMIT` 144) and carry
**no** `nproc` limit: ADR-0048 already bounds a shared-uid container by its
cgroup alone. The authority allows at most `MAX_LIVE_ENVIRONMENTS` = 16 live
environments across every run (`PREPARING`, `READY`, `DESTROYING`, `UNKNOWN`;
ADR-0052 §2a). What it does not count: a container whose record ended but
which survived (an orphan, removed at the next reconciliation), containers of
another DireWolf store on the same host, and any other process of uid 10001
an operator runs.

**What the two bounds were for.** ADR-0047 §5 set both at 256 as defence in
depth: the cgroup as the bound, the rlimit as a second, independent one if the
cgroup were absent. Since M5a the pids limit is a required, measured invariant
from the runtime's record (`HOST_RESOURCE_LIMITS`), and an environment without
it is never used; the rlimit is measured too, by the broker
(`HOST_RESOURCE_LIMITS`) and from inside by the probe (`CONTAINER_RLIMITS`,
"Max processes"). Changing either value therefore amends an accepted,
measured contract — which is why this is an ADR and not a fix.

## Decision (proposed)

### 1. The per-environment bound is the cgroup

`PIDS_LIMIT` stays 256 per environment, measured as today. It is the only
bound one environment's tasks meet that another environment's tasks do not
share. No change to the relay's or the setup's limits.

### 2. `RLIMIT_NPROC` becomes a backstop the allowed environments cannot reach

`RLIMIT_NPROC` (soft and hard) becomes `PIDS_LIMIT × MAX_LIVE_ENVIRONMENTS × 2`
= 256 × 16 × 2 = **8 192**, still set by the plan and still measured exactly
from both vantages; only the value changes.

Why that bound, and not `16 × 256`: B can start a task while
`count(uid 10001) < RLIMIT_NPROC`. Every environment is held to `PIDS_LIMIT`
by its cgroup, so with *n* containers of uid 10001 the count is at most
*n* × 256, and a task of B is refused by the rlimit only if
*n* × 256 ≥ `RLIMIT_NPROC`. The authority's cap bounds *n* at 16 for its own
live environments; it does not bound the containers it does not count (an
orphan awaiting reconciliation, a second store on the host). A limit of
exactly 16 × 256 leaves no room for one of those, and at that point one
saturated set of environments couples again. Doubling it absorbs up to one
full set of uncounted containers — 16 more at their bound — before any
coupling can return; beyond that it is a stated residual (§5). The value is
the owner's to set at acceptance; the formula and its margin are what this
ADR proposes.

The constant is derived, not repeated: `MAX_LIVE_ENVIRONMENTS` moves from the
authority's `state/workload.rs` to `dwk-sandbox-profile` beside `PIDS_LIMIT`
(the authority uses it from there), and a compile-time assertion holds
`RLIMIT_NPROC >= 2 * MAX_LIVE_ENVIRONMENTS * PIDS_LIMIT`, so a later change to
either cannot silently reopen F-R8.

### 3. What stays as it is

One host uid for every environment; the workspace group 10001, its mode 2770,
the umask 0007 and every measurement of the workspace; the relay's identity;
secret delivery; the broker's posture (it refuses to run as 10001 or 10002);
every other measured invariant; exact-label ownership and destruction; the
live-environment cap; `UNKNOWN` and non-replay.

### 4. Deployment contract, stated

One DireWolf store's environments use uid 10001 on a host. No other process
of that uid runs there. The operator's runtime adds no default `nproc`
`ulimit` of its own (Docker's `default-ulimits`): the plan sets the value
explicitly and both vantages measure it, so a different one refuses the
environment rather than weakening the backstop.

### 5. What it never claims

Separation of host identity between runs: every environment is still uid
10001, so a workload that escaped its container — outside the threat model,
the host kernel is trusted ([SECURITY.md](../SECURITY.md) item 2) — would hold
the same uid as every other run's processes. Isolation from processes of uid
10001 that DireWolf did not start, or from more than one full set of
uncounted containers. Any bound on memory, CPU or disk pressure beside a
neighbour other than each environment's own cgroup (each already shown alone).

### 6. The evidence acceptance requires (hosted, every case required by name)

- **R8, restored as a required case:** environment A holds at least
  `PIDS_LIMIT − 8` tasks (asserted from the fixture's own count, so the
  pressure cannot quietly be reduced) while environment B, prepared, starts
  and completes its own workload as uid 10001; B is measured clean after and
  not destroyed; A's bound held, its workload ended and its residue proved
  clean; the broker answered throughout; both are destroyed by their exact
  labels and nothing else is.
- **Through the authority:** the same over `process.exec` — B's workload
  `COMPLETED`, B's environment not drifted or destroyed, the authority
  answering while A holds its bound.
- **At the cap:** 16 environments live, 15 holding their bound, the 16th
  prepared, measured and served — on the disposable hosted runner only, and
  bounded: 16 × 256 tasks of one uid, sleeping, for at most the wall clock
  given.
- **Negative control:** the same R8 case with `RLIMIT_NPROC` restored to 256
  fails (`ENVIRONMENT_NOT_CLEAN`), in the mutation review.
- **The measurement still bites:** a record or a probe reading with any
  other `nproc` (256, unlimited) is refused, and a record without its pids
  limit is refused, from both vantages.

### 7. Before acceptance

Nothing in production reads this ADR. The change it describes — two
constants, one assertion, the plan's value and the two measurements — lands
as one reviewed change behind §6's evidence, after the owner's decision.

## Consequences

**Positive.** Neighbour survival under the documented model: no set of
environments the authority allows, plus one full set it does not count, can
stop another environment's probe or workload. The per-environment bound is
the one already measured, and the one the relays already rely on. No new
durable state, no new privilege, no new identity, nothing new for the
operator to provision. A small change to the trusted computing base: two
constants, one compile-time assertion, one plan value, two measured values.
Portable to any runtime that supports the pids cgroup, which M5a already
requires.

**Negative.** The per-uid rlimit no longer bounds one environment on its own:
were an environment's pids cgroup absent, `nproc` would let it reach 8 192
tasks instead of 256 — an environment without its pids limit is refused by
both vantages before any workload, so that path is closed by measurement,
not by the rlimit. Coupling returns past the margin: foreign processes of uid
10001, or more than one full set of uncounted containers. Host identity is
not separated per run (§5). The measured contract of two accepted ADRs
changes, and the evidence that holds it must be redone.

## Decision matrix

| | **B — cgroup bound, `nproc` backstop (proposed)** | **A — a host uid per environment** | **C1 — a parent cgroup with an aggregate `pids.max`** |
|---|---|---|---|
| Isolation strength | Per environment by cgroup; per uid only past the margin | Per environment by cgroup and by uid; foreign uid-10001 tasks irrelevant | Per environment by cgroup; aggregate by the parent, not by uid |
| Availability guarantee | Holds for ≤ 16 counted + 16 uncounted environments | Holds for any number, foreign tasks included | Holds while every container of the parent is DireWolf's and counted; orphans and a second store share the parent |
| Operational complexity | None new | An operator-reserved uid range; nothing else on the host may use it | The operator provisions a slice (systemd driver) or a cgroupfs parent per host |
| TCB impact | Two constants, an assertion, a plan value, two measurements | Durable uid allocation in `kernel.db`, its reconciliation, the plan, both measurements, the posture over a range | The plan, a new measured invariant (`CgroupParent` and its `pids.max`), which the probe cannot read from a private cgroup namespace |
| Accepted ADRs | Amends ADR-0047 §5, ADR-0052 §10 (values only) | Amends ADR-0047 §5, ADR-0052 §§4–6, 10, 13 (the identity model) | Amends ADR-0047 §5, ADR-0052 §10, adds a deployment requirement |
| Additional privilege | None | None for the broker (`--user` takes any uid); the operator reserves the range | The operator creates the parent; none for DireWolf |
| Workspace semantics | Unchanged | Files owned by a different uid per run, group 10001 unchanged; interoperation through the group as today | Unchanged |
| Migration | None: new environments only | A schema change; live environments drained or destroyed | None for records; host provisioning |
| Portability | Any runtime with the pids cgroup | Any runtime with `--user`; Docker has no per-container user namespace, so remapping would not help | systemd- or cgroupfs-specific |
| Crash recovery | Unchanged | A slot is freed only when its container is proved gone; `UNKNOWN`/`DESTROYING` keep theirs; reconciliation reclaims | Unchanged |
| Evidence required | §6 | §6, plus allocation, reuse after a crash, a slot never shared, the range refused to daemons | §6, plus the parent measured, and a missing parent refused |

## Alternatives considered

**A — an independent host uid per environment.** The strongest: the per-uid
count no longer couples anything, foreign tasks of 10001 stop mattering, and
host identity differs per run, which would narrow what an escaped workload
holds. It is also the largest change. Each live environment needs a uid from
an operator-reserved range, allocated durably with the `PREPARING` intent,
never shared while its container may exist (`UNKNOWN` and `DESTROYING` keep
theirs; `LOST` and a confirmed removal free it), and reconciled at start.
Both vantages must compare the user with the allocated uid instead of a
constant; the broker's posture must refuse a daemon anywhere in the range;
the workspace contract keeps group 10001, but its files are owned by a
different uid per run. Docker offers no per-container user namespace — its
`userns-remap` maps every container into one range, which would keep the
coupling — so the uids are plain host uids. Not chosen now: it adds durable
state and a schema change for a property B provides under the documented
model. It is the revisit path.

**C1 — a parent cgroup bounding the aggregate, `nproc` removed.** It moves
the aggregate bound from the uid to the cgroup hierarchy (`--cgroup-parent`
with a `pids.max` of 16 × 256), which foreign processes of 10001 cannot touch.
But it needs the operator to provision the parent, a new invariant the probe
cannot measure from inside its private cgroup namespace, and orphans or a
second store in the same parent couple again. Not chosen; it can complement B
later.

**C2 — `nproc` removed, the cgroup alone.** Exactly the relays' model, and the
smallest change. It drops the independent per-uid bound entirely, where B
keeps one at no cost to availability. Not chosen.

**C3 — admission by the uid's count.** Counting uid 10001's tasks before B
starts cannot stop A taking them after; it races, and the broker cannot see
the host's task table under Docker Desktop's VM. Rejected.

**C4 — the probe under another uid.** B would be measured, and its workload
would still fail to start. Rejected.

**C5 — `PIDS_LIMIT` lowered to fit 16 environments under 256.** Sixteen tasks
per environment breaks ordinary workloads (a test runner, a compiler, git).
Rejected.

## Owner decision

Required before anything changes: accept B as proposed (and the backstop's
factor), or choose A, or another remedy. Acceptance follows §6's evidence in
hosted CI. Until then: F-R8 open, R8 failed, M5e.2 open; the neighbour test
stays the finding's reproducer, required by no task.

## Revisit if

DireWolf must share a host with other workloads of uid 10001, or with a
second store; a per-run host identity becomes worth its state (a container
escape class the threat model starts to cover); the runtime offers
per-container user namespaces; or the kernel's accounting of `RLIMIT_NPROC`
changes.
