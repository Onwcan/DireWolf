# ADR-0069: An environment's user namespace and security-module confinement are measured from inside and reported, never assumed -- the identity map stays the contract, and only an enforcing profile both vantages name counts

**Status:** Proposed · **Date:** 2026-11-17 (designed, built and reviewed locally 2026-11-17 for finding F-05; its hosted AppArmor evidence observed on CI #198 (run 44706359028, `3584f3e`, 2026-11-20); nothing here is accepted) · **Would amend (on acceptance):** [ADR-0047](0047-m5a-oci-execution-environment-and-measured-assurance.md) §5 (AppArmor/SELinux labels stay "not a required invariant", and are now measured and reported) and the reading of its `HOST_USERNS_NOT_HOST` (§6: the runtime was not told to use the host's mode -- **not** a user namespace of the container's own) · **Refines:** [ADR-0052](0052-m5d-sandboxed-process-exec.md)'s residual "No user-namespace remapping" and [ADR-0056](0056-m5e-cross-run-task-limit-isolation.md) §5's "every environment is the same host uid": both now measured in each environment, not only stated · **Leaves open:** user-namespace remapping (OD-1), a required security module (OD-2), carrying the judgement to the authority (protocol 13, OD-3)

> **What an environment's own kernel says about who runs in it and what
> confines it is read by the digest-pinned probe and judged by the broker
> against the runtime's record and the host's kernel.** The deployment
> contract's identity map -- workload uid 10001 *is* host uid 10001 -- is
> reported as exactly that, never as remapping. AppArmor or SELinux counts as
> enforcing only where the host's kernel runs it, the probe's kernel gives the
> process an enforcing profile or a confined domain, and the runtime's record
> names the same one. Landlock, which DireWolf installs nowhere, is never
> counted. The judgement is a broker event: no invariant, no admission and no
> private-protocol field changes.

Proposed. The change is built so that its evidence can run; the accepted
records' bodies are unchanged (README.md, rule 1).

## Context

**What the documents claimed.** SANDBOX.md §2's profile listed `userns:
remap` and `apparmor/selinux: enforced where available`; its §5 platform table
marked "User namespace remap" and "Landlock (host exec)" as available on
Linux; its §4 said host execution "additionally applies Landlock"; and
THREAT_MODEL.md's STRIDE row for sandbox escape listed "user namespaces" among
the mitigations.

**What was built.** Remapping never was: ADR-0047 §5 moved it to M5d, ADR-0052
records it as a residual and ADR-0056 builds its task backstop on its absence.
Four accepted contracts depend on the identity map: the workspace's group
10001 and mode 2770 (ADR-0052 §6), the host-wide `RLIMIT_NPROC` backstop
(ADR-0056), the proxy directory's ACL naming uid 10002 (ADR-0048 §3) and the
proxy's peer check admitting only uid 10002 (ADR-0068). The one invariant
with "userns" in its name, `HOST_USERNS_NOT_HOST`, checks only that the
record's `HostConfig.UsernsMode` is not `host`; Docker's default is the empty
string, so it passes for a container that shares the host's initial user
namespace -- which every environment does. Its name read as more than it
checks. No code read a container's security label: ADR-0047 §5 left labels to
the runtime's default, "not a required invariant", and nothing measured
whether there was one. No code installs a Landlock ruleset; the container's
seccomp allowlist admits the three Landlock calls, so a workload may restrict
itself, which is not DireWolf's confinement. Host execution is not shipped
(ADR-0052 §12).

**Reproduced** on `cba8111`, Docker Desktop on WSL2, kernel
`6.18.58.1-microsoft-standard-WSL2`, 2026-11-17:

| observed | value | what a naive reader would have said |
|---|---|---|
| `/proc/self/uid_map`, `gid_map` (host distribution and environment) | `0 0 4294967295` | -- |
| the environment's record, `HostConfig.UsernsMode` | empty | `HOST_USERNS_NOT_HOST` passes: "own user namespace" |
| `/sys/module/apparmor/parameters/enabled` | `N` | -- |
| `/sys/kernel/security/lsm` | absent (`securityfs` not mounted) | -- |
| `/sys/fs/selinux` | absent | -- |
| `/proc/self/attr/current` | `kernel` | a security label |
| `/proc/self/attr/apparmor/current` | `EINVAL` | -- |

The `kernel` label is SELinux built into the kernel and never initialised:
it labels every process and confines none.

## Decision

### 1. The properties

| | property | as built |
|---|---|---|
| A | the workload's uid inside is not its uid on the host | **not held**, by contract: the identity map |
| B | uid 0 inside is not uid 0 on the host | **not held** (identity map); no process in an environment runs as uid 0 or keeps a capability, `no-new-privileges`, seccomp |
| C | two environments' workloads are distinct host uids | **not held**; ADR-0056 §5's residual |
| D | the runtime was not told to use the host's user-namespace mode | **held**: `HOST_USERNS_NOT_HOST`, unchanged |
| E | the mapping an environment really has is known, from inside | **held** (this ADR): the probe reads it |
| F | a security module confines the environment where the host runs one | **measured and reported** (this ADR); not required |
| G | no document or name claims A, B, C or F where it does not hold | **held** (this ADR): corrected |

### 2. The user namespace: Option D, the identity map kept and reported

The contract keeps the identity map. The probe reads `/proc/self/uid_map`
and `gid_map` (at most 8 lines of three decimal numbers, as the kernel prints
them) in its version-4 report; the broker reports:

| seen | reported |
|---|---|
| the record says `host` | `UNSUPPORTED:record:host-mode` (`HOST_USERNS_NOT_HOST` refuses it, unchanged) |
| both maps are exactly `0 0 4294967295` | `UNSUPPORTED:inside:shared` -- no remapping, as the contract states |
| any other map | `UNVERIFIED:inside:remapped` -- seen from inside only (the record has no map to compare), and served by no contract |
| no map | `UNVERIFIED:none:unobserved` (a version-3 probe) |

A remapped environment is never `ENFORCED`: the runtime's record does not
carry the map, so only one vantage sees it, and the four contracts above
refuse such an environment anyway (§5).

### 3. Security modules: both vantages, on a host that runs the module

States are F-03's (ADR-0065, `crate::effective::Condition`); here `REDUCED`
means a weaker mode than the module's enforcement was observed, not an
operator's acknowledgement. Each judgement says where it was seen: `both`,
`inside`, `record`, `host`, `build` or `none`.

- **AppArmor.** `UNSUPPORTED:host` unless the host's AppArmor `enabled`
  parameter is `Y` and the kernel's module list, where readable, names it.
  Then the probe's label -- `attr/apparmor/current`, or `attr/current` where
  SELinux does not run -- against the record's `AppArmorProfile`: `NAME
  (enforce)` with the record naming `NAME` (not `unconfined`) is `ENFORCED`;
  `(complain)` with the same name, or `unconfined` with the record naming
  none or `unconfined`, is `REDUCED`; a label the judgement cannot parse is `UNVERIFIED`, and so is
  any disagreement between the vantages (`contradiction`) or a missing label.
- **SELinux.** `UNSUPPORTED:host` unless `selinuxfs` is mounted. Then the
  probe's `attr/current` must equal the record's `ProcessLabel`; a missing
  one, or a different one, is `UNVERIFIED`. An unconfined domain
  (`unconfined_t`, `spc_t`, `unconfined_service_t`, `kernel_t`, `initrc_t`)
  or a permissive host is `REDUCED`; any other domain on an enforcing host is
  `ENFORCED`.
- **Landlock** is `NOT_APPLICABLE:build:no-ruleset`, whatever the kernel
  offers.

A label alone is never confinement (the `kernel` label above), nor is a
profile only the runtime names, nor a module only the kernel offers.

### 4. Reported, never admitted on

The broker writes one event per judgement of an environment:

```text
sandbox_identity environment=<id> userns=STATE:seen:detail apparmor=… selinux=… landlock=…
```

Every field is a fixed word or a profile or domain name restricted to
`[A-Za-z0-9._/-]` and 64 characters. An environment without enforcement is
still prepared, as before: Docker Desktop, the supported configuration on
Windows, runs no AppArmor, and refusing it would refuse that configuration.
Requiring a module (OD-2) or carrying the judgement to the authority and its
audit (OD-3) needs new invariants or fields, which are protocol 13's; private
broker protocol 12 is unchanged.

### 5. Why not remap now: the contracts it would break, each fail-closed

Under any remapping the kernel translates the workload's 10001 and the
relay's 10002 into other host uids. Then:

- **the workspace** (ADR-0052 §6): the workload is no longer group 10001 on
  the host, so it cannot write the `2770` root, and inside, the root's owner
  and group read as unmapped, which the probe's workspace measurement
  refuses;
- **the proxy directory** (ADR-0048 §3): its ACL names 10002, so the relay
  cannot reach the socket;
- **the proxy's peer check** (ADR-0068): `SO_PEERCRED` reports the relay's
  uid as the broker's namespace sees it, not `RELAY_UID`, so the connection
  is closed unread;
- **the task backstop** (ADR-0056): Docker's daemon-wide `userns-remap` maps
  every container into one range, so the coupling stays; per-environment
  ranges change its arithmetic.

Each refuses; none would silently weaken. Remapping therefore needs its own
decision that revisits all four, never an exception in one of them.

### 6. Wire, store, configuration

The probe report (broker-internal, closed schema, from the digest-pinned
probe) goes to version 4 with an optional `identity`: its uid and gid maps
and its two security attributes. A version-4 report must carry it and a
version-3 report must not; version 3 stays accepted. DWKP, private broker
protocol 12, the invariants, the store and every flag are unchanged.

## Consequences

- Each environment's user namespace and confinement is said where the broker
  says everything else it measures, from what the kernel reported.
- `HOST_USERNS_NOT_HOST` keeps its wire name and check; its documentation
  says what it is not.
- The documents claim no remapping, no Landlock and no unconditional LSM.

## Residuals

- **One host uid for every environment** (ADR-0056 §5): unchanged.
- **uid 0 inside is host uid 0.** Nothing in an environment runs as uid 0; an
  escape that gained it inside would hold it on the host. Remapping (OD-1) is
  what would bound that.
- **No module on Docker Desktop.** An environment there has no AppArmor or
  SELinux confinement, as before; it is now said.
- **The broker's alone.** The judgement is on the broker's event log; the
  authority and its audit do not see it (OD-3).
- **The probe is trusted** for the map (the record has none to compare), as
  it is for every inside fact (ADR-0047).
- **Which relay connected** (ADR-0068's open question) stays open: under the
  identity map every environment's relay is uid 10002 in the host's
  namespace, and nothing here tells them apart.
- **Not exercised:** a remapped daemon, rootless Docker or Podman, an SELinux
  host, a runtime that refuses a label. Their states are tabled from the
  kernel's formats, not observed on a real host.

## Alternatives considered

- **A: the daemon's `userns-remap`.** A system-wide change to the operator's
  Docker; one range for every container, so property C is still not held,
  and it breaks the four contracts of §5. Not chosen.
- **B: a user namespace per environment with idmapped workspace mounts.**
  The real answer to A, B and C; Docker offers no per-container mapping, and
  the workspace, ACL, peer-check and backstop contracts would each be
  rebuilt around per-environment uids the broker allocates (ADR-0056's own
  revisit path). Deferred (OD-1).
- **C: a rootless runtime.** Changes the daemon, its networking and its cgroup
  delegation under every evidence suite. Deferred (OD-1).
- **D: keep the identity map, measure and report it, correct the documents**
  -- chosen: no control weakened, nothing on the wire changed.
- **Security modules as new invariants now.** Refused: it would change
  protocol 12 and refuse the supported Windows configuration.
- **Landlock in the probe.** A workload confinement of its own, with its own
  rules for a workspace, `/tmp` and the toolchain; not this finding's.

## Owner decisions

- OD-1 the identity map remains the deployment contract (D); remapping (A, B
  or C) needs its own ADR revisiting ADR-0048 §3, ADR-0052 §6, ADR-0056 and
  ADR-0068;
- OD-2 security-module confinement is reported, not required; requiring
  AppArmor or SELinux where the host runs it would be a new invariant
  (protocol 13);
- OD-3 the judgement reaches the authority and its audit only with protocol
  13, beside F-03's broker posture (D6, [F03_EFFECTIVE_POSTURE.md](../F03_EFFECTIVE_POSTURE.md) §8);
- OD-4 Landlock and host execution stay unbuilt; host execution's
  confinement keeps its own ADR with M6 (ADR-0052 §12).

**Decided 2026-11-20** (recorded in full in
[ADR-0070](0070-adr-0069-decisions-host-vantage-required-lsm-and-what-stays-deferred.md)):
OD-1 keeps the identity map as the contract -- the host-side vantage is
approved, per-environment remapping is not built; OD-2 is met by
ADR-0070's operator opt-in, approved as implemented; OD-3 is deferred to
a separate security-architecture phase (protocol 13 together with F-03's
D6); OD-4 is deferred to M6's host execution. This ADR stays
**Proposed**.

## Evidence

- `crates/dwk-proto/src/brokerp/sandbox.rs`: the report's version rule, the
  kernel's map format and the label's bounds.
- `crates/dwk-sandbox-probe/src/linux.rs`: the probe reads its own map.
- `crates/dwkd-broker/src/sandbox/identity_tests.rs`: the judgement's tables
  for every state above; this host's kernel files; the real kernel's identity
  map and, in an unprivileged user namespace of its own (`unshare`), a real
  remapped one judged `UNVERIFIED:inside:remapped`.
- `crates/dwkd-broker/tests/sandbox_foundation.rs`, in a real environment
  (`make sandbox-foundation-evidence`): the broker's event says
  `userns=UNSUPPORTED:inside:shared`, `landlock=NOT_APPLICABLE`, SELinux
  unsupported where `selinuxfs` is absent, and the AppArmor state this host's
  kernel and the container's record call for -- `UNSUPPORTED:host` on Docker
  Desktop (observed locally), `ENFORCED:both:docker-default` on an Ubuntu
  runner (the hosted `sandbox-foundation` job: observed on CI #198 (run 44706359028, `3584f3e`, 2026-11-20),
  `apparmor=ENFORCED:both:docker-default`, with ADR-0070's host vantage
  making the user namespace `UNSUPPORTED:both:shared`).
- `make sandbox-identity-mutations`: the judgement's eleven guards weakened
  in turn, each killed by a named test. The probe report's two rules -- the
  version rule and the identity map -- were weakened the same way once while
  this was built (both killed by `dwk-proto`'s tests); they are not in the
  table, because `scripts/` may not name the private protocol's module
  (TX016).

## Rollback and deployment

Reverting removes an event line and the probe's version-4 fields; a version-3
probe is still accepted. Nothing is stored or migrated. A deployment changes
nothing: the probe's digest changes with its source, as for any probe change.

## Revisit if

A supported runtime gives each container its own user namespace with
idmapped mounts; protocol 13 is opened; host execution is shipped; or a
hosted run reports a label the judgement does not recognise.
