# ADR-0047: M5a — the OCI execution environment and measured assurance

**Status:** Accepted · **Date:** 2026-10-02 · **Amends:** [ADR-0018](0018-authority-broker-split.md) (the broker now drives a container runtime through its client, and holds the runtime's control socket's authority), [ADR-0039](0039-durable-authority-state.md) (schema version 7: the environment ledger), [ADR-0043](0043-m4b-private-broker-channel-and-brokered-fs-read.md), [ADR-0045](0045-m4d-process-execution-broker.md) and [ADR-0046](0046-m4e-secret-handles-backends-injection-and-redaction.md) (private protocol version 5; the launch helper runs the runtime client) · **Refines:** [SANDBOX.md](../SANDBOX.md) §§1–2 (the trait, `oci-strict`, the seccomp policy and the measured level, as built)

> **An execution environment is usable only at the level its measurement
> earns.** The broker prepares one `oci-strict` container per environment
> through the runtime client the authority resolved and hashed, and measures
> it from two vantages — the runtime's own record, and a digest-pinned probe
> running inside it. Every required invariant must be observed `PASS`; one
> `FAIL`, one `UNOBSERVABLE`, one missing, and the environment is refused and
> removed. The authority takes the lower of what the kind declares and what
> was measured; there is no score. Weakened profiles are shown to be caught by
> the measurement, not merely never built. M5a runs nothing inside an
> environment but the probe: no workload, no network, no egress — those are
> M5b–M5d.

## Context

[SANDBOX.md](../SANDBOX.md) set out the `ExecutionEnvironment` abstraction, the
`oci-strict` profile, its hard rules and the idea of a *measured* assurance
level before any of it existed. M4 built what a sandbox needs underneath — the
authority/broker split and private channel (ADR-0043), executable identity and
descriptor launch (ADR-0045), durable intent before effect (ADR-0039,
ADR-0044 §10). M5 is too large to land as one change (ADR-0042 §1's reasoning
for splitting M4 applies), so it is decomposed ([ROADMAP.md](../ROADMAP.md)):

| slice | what |
|---|---|
| **M5a** | the OCI foundation and measured assurance — **this ADR** |
| M5b | the `PROXY_ONLY` topology and the CONNECT proxy |
| M5c | `net.http`, SSRF and redirect policy, credential egress: mode A's consumer |
| M5d | production sandboxed `process.exec`, modes B/C wired, workspace hygiene |
| M5e | the complete M5 adversarial gate and closeout |

M5a is deliberately the part everything else stands on and nothing reaches yet:
the environment exists, is measured, has a durable lifecycle and exact
cleanup, and **no public caller can cause one to be made**.

## Decision

### 1. Scope

M5a owns: the execution-environment abstraction (broker side) and its `oci`
implementation; the `oci-strict` profile as data; the digest-pinned probe and
its closed report; the host-side measurement; the authority's judgement of the
level; the environment's durable lifecycle, crash windows and reconciliation;
private protocol version 5; schema version 7; the real-container evidence, its
eval suite and CI job.

M5a does **not** own: running a workload in an environment (M5d); any network
but none (`PROXY_ONLY` is refused as unavailable until M5b); the CONNECT proxy,
DNS pinning, SNI, SSRF guard, `net.http`, redirects or credential egress
(M5b–M5c); secret modes B/C in a sandbox (M5d); the `local` environment's
Landlock/Seatbelt confinement (M5d); approvals (M6).

### 2. The OCI control path: the runtime's own client, as an M4 launch

**Chosen:** the Docker-compatible CLI, resolved and hashed by the authority's
M4 executable resolver (ADR-0045 §5), handed to the broker as a descriptor with
its working directory, re-proved there (`process::verify::identities`), and
executed by descriptor through the M4d launch helper — once per step, through a
duplicate of the proved descriptor, with the descriptor proved unchanged
(`fstat`: object, size, times) before each step. Every argument vector is built
in one file (`sandbox/plan.rs`) from typed values and the profile's constants.
No shell, no path search, no string parsed as a command line.

**The client's environment is built from nothing** but `HOME`, which points at
an empty directory the broker owns (0700, beside its socket); the endpoint is
pinned by `--host unix://<socket>` and the configuration by `--config <that
directory>` on every call. So `DOCKER_HOST`, `DOCKER_CONTEXT`,
`DOCKER_CONFIG`, TLS and proxy variables, the user's `~/.docker` (contexts,
credential helpers, plugins, hooks) and Docker Desktop's context selection
cannot redirect or influence the broker. No step pulls, logs in, builds or
names a plugin subcommand.

**Alternatives rejected.** The Engine API over the socket (a new HTTP parser
and client in the broker's TCB, for no measurement the CLI cannot give);
driving `runc`/`crun` directly (root, image unpacking and an image store of our
own); a Rust container crate (a large new dependency for less than the CLI
provides, and still the daemon underneath). The CLI costs process starts
(§14's latency) and a trusted binary, which M4 already knows how to prove.

**The daemon is trusted** — it is the host's most privileged component — to
report its own configuration truthfully (§8's host vantage) and to apply it; the
probe (§8) checks what the kernel actually applied.

**Access to the runtime socket is host-root-equivalent.** Whoever can reach
it can start a privileged container. The operator must make the socket
reachable by the broker's uid and nothing on the cognition side; M5a's evidence
runs one uid for all three roles (like M4's same-identity evidence) and says
so. No code path gives the socket to an environment (§5 rule, measured §9).

### 3. The abstraction, and no public route

`sandbox::environment::ExecutionEnvironment` (broker) is designed against
`oci` and `local` only (SANDBOX.md §1): `declared`, `prepare`, `measure`,
`run_probe` (the one program M5a runs in an environment: spawn, then collect),
`destroy`, `list`. `ExecOutcome` distinguishes exited, killed, timed out,
environment gone, runtime unavailable and a distinct `Unobservable`, decided by
asking the runtime and the container after any non-zero exit, because the
client's own failures share exit codes with the program's.

The authority's operations — `attach_sandbox`, `environment_prepare`,
`environment_measure`, `environment_destroy`, `environment_reconcile` — are an
**in-process API with no DWKP route**. Only the evidence harness attaches a
sandbox; `dwkd-authority serve` has no option that does; TX035 keeps the
server, the authority's `main`, the CLI and the runtime from naming them.
Public DWKP is unchanged.

### 4. Private protocol version 5

Four authorisations — `broker.environment_prepare`, `_measure`, `_destroy`,
`_list` — each carrying exactly two descriptors (the runtime client, then its
working directory, `/`), with typed fields only: environment and run ids, the
store instance, the profile and topology by name, the image by content digest
(`sha256:` + 64 hex, never a tag), the probe's SHA-256, the workspace's path
and `(device, inode)`, the runtime socket path, and the client's identity. **No
field is a runtime flag, option map or mount specification** (TX036); every
undeclared member is refused. The exchange deadline is the kind's own: 120 s
for prepare and measure, 60 s for destroy and list, 10 s as before for every M4
operation; both sides use the same value. Versions 1–4 are refused, exactly;
the four results each name exactly one operation and are checked against the
operation sent.

### 5. `oci-strict`, as data

The profile's values live in `dwk-sandbox-profile`, a dependency-free crate
linked by the broker (which applies them) and the probe (which checks them) —
**not** by the authority, which judges verdicts and needs none of them, and
**not** in `dwk-proto`, because none of it is a wire contract. (A first draft
put the seccomp policy in `dwk-proto` only to keep `keyctl` out of the broker's
source for TX028; that let an architecture check shape the architecture, and
was reversed.) The wire vocabulary — invariants, verdicts, levels, the probe
report, image and container identifiers — stays in `dwk-proto`.

Every hard rule of SANDBOX.md §2, with no parameter that disables one:
digest-named image, `--pull never`; `--user 10001:10001`; read-only root; the
workspace as the one bind (`rprivate`), `/tmp` (512 MiB, executable) and
`/var/tmp` (128 MiB, `noexec`) as `tmpfs`, both `nosuid,nodev`; `--cap-drop
ALL` and no addition; `no-new-privileges`; DireWolf's seccomp profile (§7);
private IPC and cgroup namespaces, the runtime's private PID/UTS/user
namespaces left so; `--network none`; no device requested; pids 256, memory
2 GiB with swap equal (none), 2 CPUs, `nofile`/`nproc`/`fsize`/`core` limits,
`oom_score_adj` 500; no restart; no log driver; the probe as PID 1. One
container per environment, one live environment per run (§11). TX032 keeps
every weakening word out of the one file that spells the plan.

**Not mount flags here:** the workspace bind carries no `nosuid,nodev` (the
runtime offers none for binds); `no-new-privileges` defeats set-id escalation
and the device cgroup plus `--cap-drop ALL` (no `mknod`) defeat device nodes.
The workspace disk quota, the 600 s workload wall clock and user-namespace
remapping are M5d's (they concern workloads), and AppArmor/SELinux labels are
the runtime's default where it has them, not a required invariant.

### 6. Declared, measured, effective — and no score

The `oci` kind **declares** `CONTAINER_ISOLATION`. A measurement **earns**
that level only if every required invariant is present exactly once and
`PASS`; otherwise it earns `NONE` — one `FAIL`, one `UNOBSERVABLE`, one
missing, or one reported twice is enough, and there is no partial credit and
no weight. The **effective** level is `min(declared, measured)`, computed by
the authority (`crate::sandbox::judge`). An environment below its kind's
required level is refused, with the most specific failure class
(`PROBE_MISMATCH`, `IMAGE_MISMATCH`, `RESOURCE_LIMIT_FAILED`,
`ASSURANCE_FAILED`, `ASSURANCE_UNOBSERVABLE`), never "used with a warning".
The broker judges no level; its one decision of its own is conservative: a
prepared container that did not measure clean is removed before it answers.

### 7. The seccomp profile

DireWolf's own allowlist, written from the system-call table, not copied from
any runtime's default: default action `ERRNO(EPERM)`; native architectures
only (`x86_64`, `aarch64`, no 32-bit sub-architectures). Refused: `ptrace`,
`process_vm_readv`/`writev`, `kcmp`, `perf_event_open`, `bpf`, `userfaultfd`,
`keyctl`, `add_key`, `request_key`, `mount`, `umount2`, `pivot_root`, the new
mount API, `unshare`, `setns`, the `io_uring` calls, module and kexec loading,
clock setting, `personality`, and the rest listed in the profile.

**`clone` and `clone3`.** `clone` is admitted only when `(flags &
CLONE_NEW*) == 0` (all eight namespace flags, a masked comparison); `clone3`,
whose flags live in memory a filter cannot read, answers `ENOSYS`, so a C
library falls back to `clone`. Ordinary processes and threads work: the
evidence spawns a child and a thread inside a strict environment, and the
probe's own canary spawns a child (`subprocess-and-thread-creation`).

**`socket(AF_VSOCK)` is refused.** A virtual socket reaches the hypervisor
host (a WSL2 VM, Docker Desktop's, Firecracker) and is not confined by a
network namespace; admitting it would let a `--network none` environment talk
to its host. `socket` and `socketpair` are admitted for every other family.

**Measured where it is enforced.** The host vantage compares the profile the
runtime recorded with ours, byte for byte. Inside, "a filter is on"
(`Seccomp: 2`) is necessary but **not sufficient** — Docker Desktop stacks a
filter of its own on every container, so an unconfined container still shows
mode 2 there. The discriminating check is `CONTAINER_SECCOMP_PROFILE_ACTIVE`:
two canaries the runtime's default profile admits and DireWolf's refuses — a
`ptrace` attach to the probe's own child and a `process_vm_readv` of its own
memory.

| denied call | evidence |
|---|---|
| `ptrace`, `process_vm_readv` | ACTIVE ATTEMPT (the canaries) |
| `mount`, `umount2`, `pivot_root` | ACTIVE ATTEMPT |
| `unshare` (seven namespace flags), `setns` | ACTIVE ATTEMPT |
| `keyctl` | ACTIVE ATTEMPT |
| `socket(AF_VSOCK)` | ACTIVE ATTEMPT |
| `add_key`, `request_key` | PROFILE-MEASURED ONLY (need a keyring handle only `keyctl` gives) |
| `process_vm_writev`, `kcmp`, `perf_event_open`, `bpf`, `userfaultfd`, `io_uring_setup` | PROFILE-MEASURED ONLY (no safe wrapper; no `unsafe` was added) |
| `clone` with a namespace flag, `clone3` | PROFILE-MEASURED ONLY for the rule; normal `clone` ACTIVE (a child and a thread) |

An active refusal of `mount`, `pivot_root`, `setns` or `keyctl` shows the call
is refused, by the filter or by missing capabilities; the host's byte-exact
profile comparison is what shows the filter is DireWolf's.

### 8. Measured assurance: two vantages, one probe

**Host vantage** (`sandbox/inspect.rs`): the runtime's `container inspect`
record, parsed by the protocol's strict JSON lexer (bounded at 1 MiB), each
invariant reading only the fields that state it; absent or ill-shaped is
`UNOBSERVABLE`. Nineteen `HOST_*` invariants from the record, plus
`HOST_PROBE_DIGEST` and `HOST_WORKSPACE_IDENTITY` (below). DireWolf's labels
must be exactly the environment's; labels in other namespaces are the
runtime's own metadata (Docker Desktop's client adds `desktop.docker.io/*` to
every container) and are neither required nor refused.

**The probe** (`dwk-sandbox-probe`, 1.4 MB, a static-pie ELF — proved static
from its headers by the evidence task, no interpreter, no `DT_NEEDED`) is PID 1
of the environment (`hold`) and, on `measure`, reports twenty-one
`CONTAINER_*` invariants in a closed schema: `PASS`, `FAIL` or `UNOBSERVABLE`
per invariant, and the workspace's `(device, inode)`. It reads what the kernel
reports about itself (`/proc/self/status`, `limits`, mountinfo, cgroup files,
`/dev`), and attempts what an escaping workload would, through safe wrappers,
last. It connects to nothing, hashes nothing, reads no configuration from its
environment (TX033). It runs as the container's configured user, never one the
step chooses.

**The probe is believed only by digest.** Before it runs, the broker copies
its bytes out of the container's own read-only root through the runtime and
hashes them against the authority's pinned SHA-256 (`sandbox/digest.rs`, the
third file TX018 lets hash). A changed, substituted or linked probe is `FAIL`,
and is never run. A pinned probe whose output is not exactly one report — not
JSON, truncated, an extra member, a duplicate, a host invariant, more than 16
KiB, or nothing within its 30 s step — makes every container invariant
`UNOBSERVABLE`. None of these can degrade to "continue anyway".

### 9. Weakened profiles are caught by measurement

Test code — never product code — builds the strict plan from the profile's own
constants, shows it measures clean, then applies one weakening at a time to a
real container and requires the named invariants to `FAIL`. Measured locally
(§14): writable root; root user; privileged; the runtime socket mounted; one
capability added; `no-new-privileges` disabled; seccomp unconfined; the
runtime's *default* seccomp profile; host PID; host IPC; host network; a
mutable tag; an extra device; resource limits dropped — **14 of 14 detected**,
twelve from both vantages (host IPC and the tag are host-side facts). Drift is
shown the same way: an environment prepared clean, then changed by the runtime
(`container update --pids-limit`), fails `HOST_RESOURCE_LIMITS` and
`CONTAINER_CGROUP_LIMITS` on its next measurement, and the authority destroys
it.

### 10. Topology

`NO_NETWORK` is the only topology M5a builds, and it is the evidence harness's:
the broker builds it only when started with `--allow-evidence-topology`, and
refuses it otherwise; `PROXY_ONLY` is refused as unavailable (M5b), and an
authority configuration naming it is rejected. Nothing claims `PROXY_ONLY`
exists.

### 11. Durable lifecycle: schema version 7

`environment` (one row per environment, `STRICT`): its id (`env_…`, minted
with the intent), run, profile, topology, image, probe digest, declared,
measured and effective levels, container once known, state, failure class,
incarnation and times. The intent (`PREPARING`) is durable **before** the
broker is told anything; states move only forward (a trigger):
`PREPARING → READY | REFUSED | UNKNOWN | DESTROYING`; `READY → DESTROYING |
LOST`; `UNKNOWN → DESTROYING | DESTROYED | LOST`; `DESTROYING →
DESTROYING | DESTROYED | LOST`. `REFUSED`, `DESTROYED` and `LOST` are final.
Identity and intent never change; a container once known never changes; **a
run has at most one environment that is not final** (a partial unique index).
Migration from version 6 is additive; the store verifies exactly as before.

Twelve audit events, one per transition or reconciliation action:
`environment.intent_recorded`, `.ready`, `.refused`, `.outcome_unknown`,
`.measured`, `.drifted`, `.destroy_intent`, `.destroyed`, `.destroy_failed`,
`.lost`, `.reconciled`, `.orphan_reaped`. None carries a secret.

**Reconciliation** lists every container labelled as this store's and
classifies each against the records: still running (measured again: clean
stays, drift is destroyed); stopped (destroyed); missing (`LOST`, or
`DESTROYED` if a destruction was pending); pending (`UNKNOWN`/`DESTROYING`:
destroyed by label); ambiguous (more than one container with exactly the
environment's and run's labels: untouched); foreign; orphan. **A container is
foreign — never touched — unless its environment id is one this store
recorded**: every environment is recorded before the runtime is told, so a
label naming an unrecorded id was copied. A copy naming a recorded environment
but another run is foreign too, and does not make the genuine container
ambiguous. An **orphan** is a container exactly labelled as a recorded,
*ended* environment; it is removed by the same destruction that re-proves its
labels immediately before. A runtime that cannot be listed completely changes
nothing (`unobservable`). Reaping by name is never done.

### 12. Crash windows

| window | durable state before → after | external effect possible | on restart | retry class |
|---|---|---|---|---|
| W1 before the intent commits | nothing → nothing | none | nothing | RETRY-SAFE |
| W2 intent durable, broker told nothing | `PREPARING` | none | `UNKNOWN`; no label: `LOST` | NON-RETRYABLE for that id; a new environment may be prepared |
| W3 broker mid-preparation (created, not answered) | `PREPARING` | a labelled container | `UNKNOWN`; reaped by label: `DESTROYED` | UNKNOWN |
| W4 answered, outcome not durable | `PREPARING` | a kept container | as W3 | UNKNOWN |
| W5 outcome durable | `READY` / `REFUSED` | the container (READY) | READY re-measured: clean stays, drift destroyed | — |
| W6 destruction durable, broker told nothing | `DESTROYING` | none yet | removed by label, or found gone: `DESTROYED` | RETRY-SAFE |
| W7 broker removed it, answer lost | `DESTROYING` | removed | found gone: `DESTROYED` | RETRY-SAFE |

Reconciliation queries: live rows (`PREPARING`, `READY`, `DESTROYING`,
`UNKNOWN`) before the listing, and the row of every environment a listed
container names after it. At start, every `PREPARING` row is a previous
incarnation's and becomes `UNKNOWN` (a first implementation compared against
the incarnation counter before the new one was stored and converted nothing;
the real-container evidence found it). W2, W3 (the broker aborting after
creation), W4 and W6 are exercised against the real runtime; W1, W5 and W7
follow from the same transitions and their unit tests.

### 13. Images

The evidence images are built offline `FROM scratch` from local bytes (the
static probe at its path, mode 0755), for the runtime's own platform, and
named by the **local image id** the runtime returns — a content digest of the
image — not a registry `RepoDigest`, which a local build does not have; the
difference is stated rather than papered over. The environment is created by
that id with `--pull never`; the host check requires both the image and the
id it was created by to be the pinned one, so a container created from a tag
fails `HOST_IMAGE_PINNED`. A missing image is `IMAGE_MISSING`, never a pull.
Acquiring an image is an explicit setup step, separate from execution.

### 14. Evidence, eval, CI

`make sandbox-foundation-evidence`: setup (static build, ELF proof, digests,
images, a trusted client — Docker Desktop's WSL client is mode 0775 on an
ISO9660 mount, which M4's contract refuses, so an owner-installed copy with
its own pinned digest is used; the contract is not relaxed), then the broker's
and the authority's real-container suites, every case required, **no
evidence container left and every pre-existing container still present**. No
runtime, no container, no measurement: NOT EXERCISED, which fails. The
`m5a-sandbox-foundation` eval suite (gated; `requires = ["M5a"]`, a
sub-milestone — `M5` stays unavailable) runs the same task; the
`sandbox-foundation` CI job runs it on the runner's Docker Engine, required by
the aggregate.

Bounded active resource evidence in a strict environment: 254 threads then
`EAGAIN` (pids 256); 1021 descriptors then `EMFILE`; an allocation OOM-killed
before 2 GiB (`oom_kill` counted in the cgroup's events); a file stopped at
exactly 1 GiB by `SIGXFSZ`. CPU is configuration-measured only (`cpu.max`).

Latency, measured locally by the broker suite (Docker Desktop 29.8.1 in WSL2,
kernel 6.18, debug broker, 10 rounds per run, two runs; evidence, not an
SLO): prepare — create, start and the full two-vantage measurement — median
916 / 913 ms, p95 963 / 924 ms; measure alone median 128 / 128 ms, p95
133 / 144 ms; destroy median 735 / 746 ms, p95 749 / 760 ms. The cost is
dominated by the runtime client's process starts and the daemon.

### 15. Dependencies and the TCB

No new third-party crate. Two workspace members: `dwk-sandbox-probe`
(depends on `dwk-proto`, `dwk-sandbox-profile`, and the already-locked `nix`,
`rustix`, `linux-keyutils`) and `dwk-sandbox-profile` (no dependencies;
`serde_json` as a test oracle). `nix` gains the `sched`, `mount`, `ptrace` and
`uio` features for the probe (code, not crates; in a whole-workspace build they
unify into the broker's `nix`, which names none of them — TX023). The probe's
`AF_VSOCK` attempt uses `rustix`'s `net`, which the workspace already enables:
no feature is added to `rustix`. (`nix`'s own `socket` feature was tried first
and rejected: it pulls in `memoffset`, a crate the lockfile did not have.) The
lockfile gains exactly the two in-tree packages and the broker's edge to the
profile; no third-party package is added, removed or changed. The
authority's measured closure is unchanged (`dwcheck closure`). The broker's
code grows by the sandbox module; its trust grows by the runtime socket (§2).
No `unsafe`.

### 16. Platform contract

Linux with a Docker-compatible runtime (native, or Docker Desktop's VM on
Windows/WSL2 and macOS). Elsewhere the broker does not serve (ADR-0043) and the
evidence is NOT EXERCISED.

What this decision was accepted on: the complete real-container evidence on
Docker Desktop 29.8.1 in WSL2 (§14), with every local gate green. Native Docker
Engine is exercised by the hosted `sandbox-foundation` job, whose first run on
the committed tree is M5a's remaining acceptance gate ([ROADMAP.md](../ROADMAP.md));
Docker Desktop on macOS is within the contract but not exercised.

### 17. Residual risks

- The runtime daemon is trusted to report and apply its configuration; the
  probe observes what the kernel applied from inside, not what the daemon
  might apply later.
- Socket access is root-equivalent; separation of the broker's uid from the
  cognition side is the operator's (§2), measured in M5a only as one uid.
- Some denials are PROFILE-MEASURED ONLY (§7).
- The workspace bind lacks `nosuid,nodev` as mount flags (§5).
- A trusted probe is trusted: a probe the authority pinned that lied would be
  believed. Its bytes are reviewed code in this repository.

### 18. Explicit exclusions

No workload execution, no `local` environment confinement, no network, no
proxy, no `net.http`, no credential egress, no secret modes B/C in a sandbox,
no approvals. `direwolf doctor --sandbox` is M17's.

## Consequences

The environment exists, is measured and has a durable, exact lifecycle, with
real-container evidence that its measurement catches every weakening the
evidence applies. M5b–M5d build on it without re-deciding any of it; no
production path reaches it until M5d.

## Alternatives considered

- **Trust construction** (never build a weak profile, measure nothing): cannot
  detect drift, a daemon that ignores a flag, or a changed image. Rejected.
- **A weighted assurance score**: lets passing invariants average away a
  failing one. Rejected (SANDBOX.md §1).
- **Profile policy in `dwk-proto`**: rejected (§5).
- **Reaping by name or by label alone**: would destroy copied or foreign
  containers. Rejected (§11).
- **Engine API, `runc`/`crun` directly, a container crate**: rejected (§2).

## Revisit if

- a runtime other than Docker-compatible is needed (Podman's socket speaks the
  same API; `crun` alone would need §2 reopened);
- remote or VM execution becomes real (the trait is rewritten, SANDBOX.md §1);
- a safe wrapper appears for a PROFILE-MEASURED-ONLY call (§7).
