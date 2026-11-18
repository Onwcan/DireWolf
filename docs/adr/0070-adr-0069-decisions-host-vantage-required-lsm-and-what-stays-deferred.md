# ADR-0070: ADR-0069's four decisions -- the user namespace seen from the host too, a security module an operator can require, and what stays deferred with its exact prerequisite

**Status:** Proposed · **Date:** 2026-11-17 (designed, built and reviewed locally 2026-11-17; hosted evidence pending, and nothing here is accepted) · **Builds on:** [ADR-0069](0069-f05-user-namespace-and-lsm-assurance-are-measured-not-assumed.md) (Proposed), its OD-1 to OD-4 · **Would amend (on acceptance):** ADR-0069 §2 (the user namespace from two vantages where the host shows it) and §4 (one admission effect: the operator's required module) · **Leaves unchanged:** DWKP, private broker protocol 12, its 52 invariants, the store, the probe report (version 4), and every existing flag

> **The container's user namespace is now read from the host's side too**,
> where the broker shares the runtime's pid namespace and the container's
> first process's control group names the container: two vantages that agree
> say `both`, two that disagree say `contradiction`. **An operator may
> require AppArmor or SELinux** (`--require-lsm`): the broker then serves only
> where the host's kernel enforces that module and refuses, with the existing
> `UNSUPPORTED`, every environment the judgement does not call `ENFORCED` --
> nothing falls back to reporting. **Remapping (OD-1), the authority's record
> of the judgement (OD-3, protocol 13) and Landlock (OD-4) stay unbuilt**, each
> for a stated, checkable reason.

## Context

ADR-0069 (F-05) measured each environment's identity and confinement and
reported it, and recorded four owner decisions:

- **OD-1** keep the identity map as the deployment contract unless a reviewed
  remapping architecture replaces it;
- **OD-2** report LSM confinement rather than require it;
- **OD-3** carry the judgement to the authority's audit with protocol 13;
- **OD-4** Landlock and host execution unbuilt.

This ADR takes each as far as it can go without weakening a control,
changing protocol 12 or refusing the supported Windows configuration (Docker
Desktop on WSL2, which runs no AppArmor and no SELinux).

## Decision

### OD-1: the identity map stays; the host's own vantage is added

**Current behaviour (ADR-0069).** The probe reads `/proc/self/uid_map` and
`gid_map` inside; the record says only `UsernsMode`. One vantage.

**Built.** Where the broker shares the runtime's pid namespace (a native
Linux host), it reads `/proc/<pid>/cgroup`, `uid_map` and `gid_map` of the
container's first process (`State.Pid` in the record). The process counts as
the container only if a line of its control-group file ends in exactly
`/<id>` (the `cgroupfs` driver) or `/docker-<id>.scope` (systemd's) for the
record's 64-hex-digit id -- no prefix, substring or parent counts -- read
before the maps and again after them, so a pid reused between the reads is no
vantage. Each file is read to at most 4 KiB.

| inside | host | reported |
|---|---|---|
| identity | identity | `UNSUPPORTED:both:shared` |
| any | a different map | `UNVERIFIED:both:contradiction` |
| remapped | the same map | `UNVERIFIED:both:remapped` |
| identity | not visible (Docker Desktop) | `UNSUPPORTED:inside:shared` |
| none | identity | `UNSUPPORTED:host:shared` |
| none | none | `UNVERIFIED:none:unobserved` |

The comparison rests on a kernel fact shown on a real unprivileged user
namespace (`a_real_namespace_reads_the_same_from_inside_and_from_the_host`):
a process's maps read by itself and by a process outside its namespace state
the same ids.

**Remapping, evaluated.** The five options against OD-1's sixteen
requirements:

| option | per-environment identity | finding |
|---|---|---|
| A. daemon-wide `userns-remap` | no: one range for every container | a system-wide daemon change; property C (environments apart) still not held; the workspace group, the relay ACL, F-04's peer check and the task backstop all refuse it (ADR-0069 §5) |
| B. per-container user namespace | yes, where the runtime offers it | Docker Engine 29.9 offers none per container (`--userns` takes `host` or nothing else); Podman's `--userns=auto` does, and is not a supported runtime |
| C. rootless runtime | no: one range per daemon | changes networking and cgroup delegation under every evidence suite |
| D. idmapped workspace mounts | a mount property, not a namespace | needs B first; Docker exposes no idmapped bind mount |
| E. identity map, reported | no | **kept** (ADR-0069), now from two vantages |

**The migration design (not built).** A remapped deployment needs, in one
reviewed change, all of: a runtime with per-container user namespaces (B);
a broker-allocated, non-overlapping 65 536-id range per environment, recorded
before the container is created and never reused while any container
labelled with it exists (reconciliation reaps by label first); the workspace
mounted idmapped so the workload's mapped uid owns it, with the authority's
pinned root and the quota unchanged and the broker's filesystem tools still
acting on host ids; the egress directory's ACL naming the environment's own
mapped relay uid, and F-04's peer check expecting that uid (so no other
environment's relay shares it); and ADR-0056's `RLIMIT_NPROC` arithmetic
re-derived per uid, since each environment's tasks then count against its own
host uid. Each of ADR-0048 §3, ADR-0052 §6, ADR-0056 and ADR-0068 is revisited
by that change. Until a supported runtime offers B, it cannot be built
without weakening one of them, and it is not.

### OD-2: a required security module, opt-in per deployment

**Built.** `dwkd-broker serve --require-lsm apparmor|selinux`:

- **Before serving**, the broker reads the host's kernel: AppArmor must be
  enabled and listed; SELinux must be enforcing (permissive is not). If not,
  it refuses to start -- `cannot serve: --require-lsm <module>: … a required
  module is never waived` -- before its socket exists.
- **For every environment it measures** (preparation and each later
  measurement), only `ENFORCED` meets the requirement. `REDUCED` (complain,
  unconfined, permissive, an unconfined domain), `UNVERIFIED` (a
  contradiction, nothing seen inside) and `UNSUPPORTED` each refuse the
  environment with `UNSUPPORTED`, after taking it down; a preparation refused
  so says `UNSUPPORTED`, not `RUNTIME_FAILED`. Teardown, reaping and
  reconciliation never run the judgement, so a requirement cannot keep an
  environment alive.
- One event per judgement: `sandbox_lsm_required environment=… module=…
  outcome=met|refused state=…`.
- No flag turns the requirement off, none is implied, and the parser takes
  each module by its one spelling, once.

**Why opt-in, not a new invariant.** A new `SandboxInvariant` is a wire value
of protocol 12; an unconditional requirement would refuse Docker Desktop.
`UNSUPPORTED` already exists, and the authority already refuses an
environment the broker refuses. What the authority cannot see is *why*: that
is OD-3.

**Not built.** An active refusal probe -- an action only the profile denies,
attempted inside -- needs an action no other layer (dropped capabilities, the
read-only root, seccomp) already refuses for an unprivileged uid, and none
was found that holds on every supported host; the judgement remains the
two-vantage label comparison. SELinux has no real host in the evidence.

### OD-3: deferred -- protocol 13 is its own change

**Not built.** Carrying the judgement (and F-03's broker posture, D6) to the
authority's audit is a private-protocol migration: the design package for
D6 estimates 30-35 files and 1 800-3 000 changed lines, every private
vector, both daemons' evidence harnesses and the hosted cross-uid suites, and
its own Step 0 (owner choices O-1…O-8) has not been taken. Shipping half a
handshake beside unrelated work would leave the authority unable to say
which of two brokers measured what. When it is built, it adds to the D6
design: `EnvironmentPrepared` and `EnvironmentMeasured` carrying the four
judged properties as broker-reported (never authority-assessed, never able
to raise the authority's assurance), and a distinct refusal for a required
module instead of `UNSUPPORTED`.

### OD-4: deferred -- no confined worker opens a file

**Not built.** Every process DireWolf runs today is either in an OCI
environment (the probe, the relay, workloads) or the broker's own exchange
worker, whose seccomp program allows no path-based filesystem call at all --
no `open`, `openat`, `creat`, `mkdir`, `unlink`, `rename`, `link` or
`execve` (kernel-proven in every worker, ADR-0053 §5). A Landlock ruleset
there would confine nothing the filter does not already refuse. Installing
one also needs either `unsafe` (forbidden workspace-wide) or a reviewed
crate, a dependency decision. Landlock's real target is host execution,
which needs M6's approvals and stays disabled; when built, the launcher
would install a ruleset after detecting the ABI and before `execve`: the
workspace read-write, the toolchain read-only, nothing else, and (ABI 4 and
later) no TCP bind or connect -- never a replacement for M6, capabilities,
seccomp or the sandbox.

## Consequences

- On a native Linux host the user namespace is said from two vantages, and a
  probe that disagreed with the host would say so.
- A deployment that requires AppArmor runs no environment AppArmor does not
  enforce, and a host that cannot enforce it is not served at all.
- Docker Desktop, without the flag, is unchanged.

## Residuals

- The identity map stays: one host uid for every environment's workload and
  one for every relay (ADR-0056 §5, ADR-0068's open question).
- The judgement and the requirement's reason stay on the broker's event log;
  the authority sees `UNSUPPORTED` (OD-3).
- The host vantage's pid reuse guard is the control-group re-read; it is
  defended in review, not by a mutant (no unit test can make a pid change
  owner between two reads).
- Not exercised locally: the host vantage (Docker Desktop's processes are
  another kernel's) and the required module's environments (no AppArmor);
  both are the hosted `sandbox-foundation` job's.

## Alternatives considered

- **A required-module invariant on the wire now.** Refused: protocol 12.
- **Require AppArmor wherever the kernel runs it, unasked.** Refused: a
  deployment's assurance changing with a kernel parameter, without the
  operator saying so, is a silent policy.
- **Remapping by daemon configuration.** Refused: OD-1's table.

## Owner decisions

- **OD-A** accept the host vantage as ADR-0069 §2's second vantage;
- **OD-B** accept `--require-lsm` as an operator's opt-in, refused as
  `UNSUPPORTED` until protocol 13 gives it a code of its own;
- **OD-C** schedule protocol 13 (D6 and this judgement together) as its own
  phase;
- **OD-D** keep Landlock with host execution under M6.

## Evidence

- `crates/dwkd-broker/src/sandbox/identity_tests.rs`: the control-group
  table, the two-vantage table, a real user namespace read from both sides,
  the required module's tables.
- `crates/dwkd-broker/src/config.rs`: `--require-lsm` named once, by its one
  spelling, never defaulted.
- `crates/dwkd-broker/tests/sandbox_foundation.rs`
  (`make sandbox-foundation-evidence`): the userns vantage the test itself
  can see; a broker requiring a module the host does not run refuses to
  start (observed locally for both); where AppArmor runs, a conforming
  environment is prepared and met, and one started `apparmor=unconfined` is
  refused (hosted, pending).
- `make sandbox-identity-mutations`: 20 mutants, the nine of this ADR among
  them, each killed by a named test.
- `tests/architecture/test_f05_identity.py`: the pins, and the exchange
  worker's filter holding no path-based filesystem call (OD-4).

## Rollback and deployment

Reverting removes an event line, a flag and a host-side read. A deployment
that never passes `--require-lsm` changes nothing.

## Revisit if

A supported runtime offers per-container user namespaces with idmapped
mounts; protocol 13 is opened; host execution is built; or the exchange
worker's filter ever allows a path-based call.
