# ADR-0052: M5d — production sandboxed `process.exec`: the authority decides a workload, the broker runs exactly that plan in a measured `oci-strict` environment, as the environment's own identity, and nothing of it outlives its invocation

**Status:** Proposed · **Date:** 2026-10-13 · **Would amend (on acceptance):** [ADR-0018](0018-authority-broker-split.md) (the broker runs workloads, never as its own uid), [ADR-0039](0039-durable-authority-state.md) (schema version 9: the workload ledger, §4), [ADR-0043](0043-m4b-private-broker-channel-and-brokered-fs-read.md) (private protocol version 8, §3), [ADR-0045](0045-m4d-process-execution-broker.md) (a process can run in an environment; the host floor is unchanged), [ADR-0047](0047-m5a-oci-execution-environment-and-measured-assurance.md) (the probe becomes the environment's init: it reaps orphans and, asked, ends every other process; `run_probe` gains a sibling, `run_workload`), [ADR-0050](0050-m5c-kernel-performed-net-http-ssrf-redirects-and-credential-egress.md) (§21's ptrace-posture prerequisite becomes a check the broker makes at start) · **Refines:** [ADR-0008](0008-sandbox-default.md) and [ADR-0024](0024-sandbox-network-topology.md) (as realised by [ADR-0048](0048-m5b-proxy-only-topology-and-connect-proxy.md)), [ADR-0046](0046-m4e-secret-handles-backends-injection-and-redaction.md) §13 (modes B/C reach a sandboxed target, M5d.3), [ADR-0051](0051-external-agent-interoperability.md) (Proposed; its M5d prerequisites), [SANDBOX.md](../SANDBOX.md) §§1–4, [POLICY.md](../POLICY.md) (`when.environment = "sandbox"`)

> **A workload runs only where the authority decided it may, as the
> environment's own user, and is gone when its invocation is.** The authority
> decides every workload — run, epoch, capability, policy for a *sandbox*
> action, obligations, the environment's measured level, the executable's
> pinned identity in the image, a per-run budget — and records the intent
> before the broker is told anything. The broker re-judges the environment
> from the runtime's record, proves the executable's bytes in the image, runs
> exactly the plan's words through the runtime client as uid 10001 in
> `/workspace`, bounds its output and its wall clock, and then has the
> environment's init end every other process in it. Nothing falls back to the
> host. No workload ever runs as the broker's uid or the authority's.

## Context

M5a built the environment and measured it; M5b gave it exactly one network
peer; M5c made the kernel an HTTPS client. Nothing has run inside an
environment but the probe. M5d is where DireWolf first runs code it did not
write, on purpose, at an agent's request: `pytest` reading `conftest.py`, `npm`
running lifecycle scripts, a build running `build.rs` (SANDBOX.md §4a). The
sandbox — not the allowlist — is the boundary that holds there.

Already built, and reused rather than rebuilt:

| Built | Where | What M5d takes from it |
|---|---|---|
| The runtime client, resolved and hashed by the authority, re-proved and executed by descriptor through the launch helper, one typed argv per step | M5a, ADR-0047 §2, `sandbox/oci.rs`, `sandbox/plan.rs` | the only way a workload is started |
| `oci-strict`: uid 10001, read-only root, caps dropped, `no-new-privileges`, DireWolf's seccomp allowlist, private namespaces, pids/memory/CPU/rlimits, one workspace bind | M5a, ADR-0047 §5 | the workload's whole confinement; unchanged |
| The runtime-record judgement (every `HOST_*` invariant) and the digest-pinned probe | M5a, `sandbox/inspect.rs`, `sandbox/digest.rs` | re-run before every workload; the same tar check proves the workload's executable |
| `PROXY_ONLY`: the relay and the opaque CONNECT proxy, the run's exact grants | M5b, ADR-0048 | the workload's only network; unchanged, no second egress path |
| The environment ledger, crash windows W1–W7, reconciliation by exact label | M5a, ADR-0047 §§11–12 | a workload's environment is destroyed when its outcome is uncertain |
| Process plans: capability, both gates, obligations, bounded streams, `UNKNOWN` never repeated | M4d, ADR-0045 | the authority's half of a workload |
| Modes B/C: the value as a pipe's read end, never in a message | M4e, ADR-0046 §§11, 13 | delivered to a sandboxed target in M5d.3 |
| The exchange worker's conditions | M5c, ADR-0050 §21 | no untrusted code as the broker's uid; the ptrace posture verified at start |

## Decision

### 1. Scope and non-goals

**M5d delivers**, in six checkpoints (§18): a workload run in a measured
`oci-strict` environment under an authority-decided plan; the public
`process.exec` routed there; secret modes B/C to a sandboxed target;
`workspace_exec_hygiene` enforced there; the workspace ownership model and a
disk quota; the workload wall clock; lifecycle integration with runs; and the
escape suite with an agent-shaped workload.

**Not M5d:** M5e's merge gate and package-manager acceptance; approvals (M6:
`REQUIRE_APPROVAL` stays a denial); any change to host execution (M4d's floor:
no production host launch before M6); external agents, ACP or an MCP server
(M29, ADR-0051); seccomp or Landlock for the exchange worker (M9); gVisor,
Kata, Firecracker.

### 2. The public operation contract

`process.exec` keeps its typed call (executable path, arguments as exact
bytes, working directory, output bound) and gains no field that chooses where
it runs: **the kernel decides the environment**. A run whose environment is
`READY` at `CONTAINER_ISOLATION` runs `process.exec` there — the canonical
action's environment is `sandbox`, policy's `when.environment = "sandbox"`
rules apply, and M4d's host floor does not, because nothing runs on the host.
A run without one gets M4d's host path, floor and all: decided, audited and
denied before M6. **There is no fallback**: a sandboxed plan whose
environment drifts, disappears or cannot be judged is refused, never retried
on the host.

The executable is named by its path **inside the image**, and its identity is
the pair (image content digest, the file's SHA-256) from the operator's image
manifest (§5). The result says where it ran and at what level.
`process.status`/`kill` of a sandboxed workload are not separate tools in
M5d: a workload is one bounded invocation (spawn, then collect), as the probe
is; a long-lived workload with its own handle is M5d.5's decision (OD-5).

**The capability.** A workload needs `process.exec` for its executable's
identity, decided by both gates like any launch — the capability gate against
the run's grants, policy with `environment = sandbox`. A *concrete* grant
(`process.exec:/usr/bin/python3`) is resolved at admission by M4d's resolver
**on the host** (ADR-0045 §21): it means the host's file, whose digest is not
the image's, so it covers no image executable. Until admission can resolve a
declaration against the image manifest (OD-9, M5d.2), only an unconstrained
grant (`process.exec:*`) covers a workload — and policy, which sees the
executable's path, the environment and the argument classification, decides
which executables a run may start. Nothing is widened: a run without such a
grant runs no workload.

**As built in M5d.1:** no public route yet — an in-process authority API,
`Authority::workload_run`, as M5a's environment API was (TX035 keeps the
server, `serve`, the CLI and the runtime from naming it). M5d.2 adds the DWKP
route (§18).

### 3. The private protocol: version 8

`broker.workload_run` carries, with exactly two descriptors (the runtime
client and its working directory, as every environment operation): the
environment's specification (as `environment_measure`'s), the container the
authority recorded, and the workload — the executable's absolute path in the
image and its pinned SHA-256, the arguments as exact bytes (`ProcessArgs`'s
bounds), the stdout and stderr bounds (each at most 128 KiB), and the wall
clock in seconds (1 to 600). **No field is a runtime flag, a user, an
environment variable, a mount, a working directory or a shell string**
(TX036, extended). Its deadline is the wall clock's maximum plus the
environment's margin, on both sides. The result: how it ended — exited (code),
killed (signal), timed out, environment gone, runtime unavailable,
`UNOBSERVABLE` — its bounded stdout and stderr with whether each was cut, its
elapsed time, and the **residue**: whether the environment's init then proved
every other process gone (`PASS`), found some it could not end (`FAIL`), or
could not say (`UNOBSERVABLE`). Refusals before anything ran: the environment
not found, foreign, not running or no longer clean by its record
(`ENVIRONMENT_NOT_CLEAN`), the executable's bytes not the pinned ones
(`DIGEST_MISMATCH`), the probe not the pinned one. A workload that may have
started and whose end nothing proves is `indeterminate`
(`WORKLOAD_UNCONFIRMED`).

M5d.3 adds `broker.workload_secret_run`: the same, with the secret's pipe as a
third descriptor (§7).

### 4. Authority state: schema version 9

Append-only by trigger, migrated transactionally from 8 with data:
`workload` — one row per invocation: run, environment, the executable's path
and SHA-256, the arguments' SHA-256 (never the arguments), the wall clock and
output bounds charged at the intent, the idempotency key, then exactly once
`COMPLETED` (with how it ended, the exit code or signal, the bytes of each
stream and whether each was cut, the residue verdict, the elapsed time),
`FAILED` (refused, provably nothing ran) or `UNKNOWN`. A run's workload budget
is read from its rows (count and wall-clock seconds charged), never refilled,
like `net.http`'s (§10). A `LAUNCHING` row a dead incarnation left is ended
`UNKNOWN` at start and **its environment is destroyed** (§9): nothing proves
the workload is not still running in it.

### 5. OCI workload execution

In the broker, in this order, all within one exchange:

1. Re-prove the runtime client (ADR-0047 §2).
2. **Re-judge the environment from the runtime's record**: the container is
   the recorded one, labelled as exactly this environment of this run and
   store, running, and every required `HOST_*` invariant passes now — image,
   user, read-only root, capabilities, `no-new-privileges`, seccomp,
   namespaces, network, mounts, no runtime socket, no devices, limits, labels,
   proxy environment, and for `PROXY_ONLY` its one relay. Anything else
   refuses (`ENVIRONMENT_NOT_CLEAN`, `FOREIGN_ENVIRONMENT`,
   `ENVIRONMENT_NOT_FOUND`) and nothing runs.
3. **Prove the bytes**: the executable is copied out of the container's own
   root as a tar stream and must be exactly one regular file whose SHA-256 is
   the pinned one (`sandbox/digest.rs`); a symbolic link, a directory, a second
   entry or other bytes refuse (`DIGEST_MISMATCH`). The image is content
   addressed and the root read-only, so the bytes proved are the bytes run.
   The trusted probe is proved the same way, because step 5 runs it.
4. **Run exactly the plan**: `container exec --user 10001:10001 --workdir
   /workspace <container> <path> <args…>` through the launch helper — no
   `--privileged`, `--env`, `--interactive`, `--tty` or `--detach`, no other
   user, no shell; the client's stdin `/dev/null`; stdout and stderr drained
   to their bounds; the wall clock the helper's deadline. The process sees the
   environment's variables only (for `PROXY_ONLY`, the proxy's), never the
   broker's or a caller's.
5. **End every other process**: the probe — the environment's init since
   M5d.1, which reaps every orphan reparented to it — is run as
   `reap`: it signals every process of the environment but itself and init
   (`kill(-1, SIGKILL)` in the environment's pid namespace), waits until none
   remains, and reports how many it ended and how many remain. A daemonised
   grandchild, a process that left its group, a forking loop: all are the
   environment's, all end. The client's own death (the deadline) does not end
   an `exec`'d process — the runtime keeps it — so this step, not the deadline,
   is what makes "gone" true.
6. **Classify** the ending by asking the runtime and the container (ADR-0047
   §3's `ExecOutcome`), never from the client's exit code alone.

**Why the probe.** It is already the environment's first process, run from the
image, pinned by digest and proved before it is run; giving init its duty
(reaping) and one more closed command (`reap`) adds no binary to trust and no
privilege — it ends only what its own uid may signal, which is every
workload process (`no-new-privileges`, no capability, one uid).

**As built (M5d.1), measured on Docker Engine 29.8.2.** The runtime client's
`exec` returns when the program exits even while a process it left holds the
standard output pipe open (case `workload-output-held-open-child-reaped`):
the client's return says the program ended, not that the environment is
quiet, and that process is ended by step 5. A broker killed while a workload
runs leaves the `exec`'d process running in its environment
(`broker-crash-workload-still-running`) until the authority destroys the
environment (`broker-restart-destroy-ends-it`). Exit codes 125, 126 and 127
are the client's own as well as a program's, so none is believed
(`workload-ambiguous-exit-unobservable`). The workload's standard error is
returned bounded and never logged by the broker.

### 6. Workspace ownership

As built through M5c the workspace is the operator's directory, bind-mounted
read-write; with no user-namespace remapping the workload writes as host uid
10001. **Owner decision OD-3** (M5d.4): (a) a workspace group — the operator's
directory group-owned by a dedicated group with the set-group-id bit, the
workload and the broker members, files `0660`/directories `2770` —
recommended for V1; (b) an id-mapped bind mount mapping 10001 to the
workspace owner — stronger, needs runtime support not yet universal; (c)
copy-in/copy-out — the workload works on a copy, changes return through the
brokered filesystem tools — strongest, costs a copy. Until M5d.4 the evidence
uses its own scratch workspace and says so (as M5a's did).

### 7. Secret modes B and C to a sandboxed target (M5d.3)

The value never enters an argument vector, the runtime client's environment,
a runtime configuration, a log, durable state or an answer. **Recommended
(OD-4):** the broker writes the value to the `container exec`'s **stdin**,
length-prefixed, to a trusted launcher in the image (the probe's `inject`
command, pinned by digest like `reap`), which reads exactly that many bytes,
closes stdin, and then — mode B — executes the target with `NAME=value`
added to its environment, or — mode C — puts the value in a pipe on
descriptor 3 and executes the target. The runtime's client and daemon carry
the bytes in memory on the way (stated, like the broker's own transient
copy); neither writes them to disk or names them in a command line or a
container configuration. Rejected: `container exec --env NAME=value` (the
value in the client's argv and the daemon's exec record), `--env-file` (the
value in a file). **Mode C's descriptor is inherited by a grandchild** the
target starts without closing it, exactly as on the host (ADR-0046 §13) — in
an environment every grandchild is the environment's, confined by it and
ended by `reap`, but a grandchild can read the value. Workload output is
redacted on return (ADR-0046 §21); a value a workload writes into the
workspace is the workload's act, and stays there (residual).

**Mode C's descriptor and grandchildren, analysed.** The pipe's read end is
descriptor 3 of the target and cannot be close-on-exec, because the target
reads it after `execve`. Every process the target starts without closing it
inherits it — a test runner's workers, a build's compilers, a daemon it
forks. What the design (built in M5d.3) gives: the pipe carries the value once and the launcher closes
its write end, so a descendant reads the value only if it reads before the
target does or the target leaves it unread; every descendant is the
environment's — uid 10001, no capability, no network but the environment's
— and `reap` ends it when the invocation ends, so none outlives the
invocation; nothing of the value reaches an argument vector, an environment
variable of the runtime client, a runtime configuration or a log. What it
does not give, recorded as a residual rather than claimed: a descendant
the target starts before reading can read the value instead of it, and a
descendant may copy the value anywhere the environment can write, including
the workspace and the run's granted origins. Mode C therefore confines a
credential to the workload's process tree for one invocation, not to one
process; a target that must keep it from its own children must close
descriptor 3 before it starts them (stated in the operator documentation
with M5d.3). Mode B's variable is inherited the same way, by construction.

### 8. Lifecycle

`LAUNCHING` (the intent, durable before the broker hears anything) →
`COMPLETED` / `FAILED` / `UNKNOWN`, exactly once. One workload at a time per
environment (OD-5). **The broker serves one connection at a time** (ADR-0050
§9 relies on it: at most one exchange worker alive), so in M5d.1 a running
workload holds the private channel for its wall clock and every other
brokered operation waits behind it. That is acceptable for an in-process API
with no public route; it is not for production. M5d.2 therefore splits a run
into a start and a collection (as M4d's `process_start`/`process_status`), or
serves workload operations on their own connections — and, before either
lands, reviews D11's worker count again, as ADR-0050 §21 requires of any
change to how the broker starts processes. **A workload whose residue is not `PASS`, or whose
outcome is `UNKNOWN`, takes its environment down with it**: the environment's
destruction is made durable in the same transaction as the workload's outcome
and performed at once, so no later workload of the run shares an environment
with a process nothing accounts for. A run's release destroys its environment
(M5d.6); reconciliation at start removes environments a dead incarnation left.

### 9. Crash windows

| Window | Durable state | On restart | Semantics |
|---|---|---|---|
| W8 workload intent durable, nothing sent | `LAUNCHING` | `UNKNOWN`; the environment destroyed | NON-RETRYABLE; never run again |
| W9 the broker running it | `LAUNCHING` | as W8 — the runtime keeps an `exec`'d process when its client dies, so only the environment's destruction ends it | UNKNOWN |
| W10 answered, outcome not durable | `LAUNCHING` | as W8 | UNKNOWN |
| W11 outcome durable, the environment's destruction pending | `COMPLETED`/`UNKNOWN` + `DESTROYING` | the destruction completes (W6/W7) | RETRY-SAFE |

A broker killed while a workload runs leaves the workload running in its
environment until the authority destroys it; the authority's answer is
`UNKNOWN`, never a retry.

### 10. Resource quotas

Per environment, unchanged from M5a and measured: 256 pids, 2 GiB memory with
swap equal to it (no swap), 2 CPUs, `nofile` 1024, `nproc` 256, `fsize` 1 GiB,
`/tmp` 512 MiB and `/var/tmp` 128 MiB. Per workload: the wall clock (1–600 s,
SANDBOX.md §2's `timeout`, enforced by the broker and completed by `reap`),
stdout and stderr each at most 128 KiB, the arguments' bounds. Per run: a
workload budget — 100 workloads and 3 600 wall-clock seconds by default
(OD-8), charged at the intent, never refunded. **Disk quota (OD-6, M5d.4):**
DireWolf creates no filesystem (that needs root); recommended: the operator
provides each workspace on a size-bounded filesystem, the probe measures its
capacity from inside (`statvfs`) against the declared quota, and an
unbounded one refuses the environment. Until then `fsize` bounds one file,
not the total (residual).

### 11. Network containment

Exactly M5b's: a workload in a `PROXY_ONLY` environment reaches the run's
granted origins through the relay and the opaque proxy and nothing else;
`NO_NETWORK` remains the evidence's topology. **No second egress path**, no
proxy for a workload in the broker's `net.http` client, no credential
injected by the proxy. A workload's network is its environment's, measured
before it runs and re-judged from the record before each workload.

### 12. The `local` environment

**Recommended (OD-7): not in M5d.** A `local` workload runs on the host; the
broker is not root and cannot start it as any uid but its own, which ADR-0050
§21 forbids for untrusted code; Landlock has no safe API in the TCB without a
new dependency; and a host launch needs a per-invocation approval (M6)
anyway. `local` stays M4d's host floor, unreachable before M6, and gets its own
ADR with M6 — the roadmap's M5d deliverable "the `local` environment's
confinement" moves there.

### 13. OS identity separation

| Identity | Who | Enforced by |
|---|---|---|
| authority | `dwkd-authority` | the broker refuses an authority uid equal to its own (ADR-0043 §1) |
| broker | `dwkd-broker`, its launch helper and exchange workers | refuses root; refuses an authority uid equal to its own; **refuses to serve when its own or the authority's uid is a sandbox identity** (10001, 10002) — M5d.1 |
| workload | uid 10001 inside every environment, its own pid, mount, IPC, UTS and cgroup namespaces | the plan's literal `--user`, re-judged from the record (`HOST_USER_NON_ROOT`) and measured from inside (`CONTAINER_UID_GID`) |
| relay | uid 10002 | M5b |

Without user-namespace remapping, 10001 inside is 10001 on the host — so a
broker or authority with that uid would share an identity with every workload
(the kernel keyring of a uid, signals across a shared namespace, a file the
uid owns). The start-up refusal closes it. **The ptrace posture (ADR-0050
§21, R4)** is checked at the broker's start from M5d.1: it reads
`/proc/sys/kernel/yama/ptrace_scope` and its own executable's owner and mode,
and refuses to serve unless the scope is at least 1 or the binary is
execute-only (root-owned, no read bit) — or a development flag,
`--allow-traceable-workers`, logs `REDUCED ASSURANCE`. **As built:** the
facts are read once at start and logged (`deployment_posture`); the decision
is a pure function of the configuration, the uids and the posture
(`admit`), whose unit test drives every posture — so the refusal is proved
on a development or CI host whose own Yama setting already closes the
window, and is never inferred from that host's configuration. A production
host's posture is the deployment's; the broker refuses to serve on one that
does not close the window. Real multi-identity
evidence that a workload reaches neither the authority's state, a secret
store, the broker's sockets nor the runtime's socket is M5d.5's hosted job
(three users and the runtime); M5d.1 shows it in one identity, where the
environment's mount namespace already names none of them.

### 14. Attack surface and residual risks

- **The runtime daemon is trusted** (ADR-0047 §2), now to start exactly the
  `exec` it is asked for. The runtime's socket remains root-equivalent and the
  broker's alone.
- **Activity inside a workload is not individually recorded** (ADR-0027,
  SANDBOX.md §4a): the audit records the workload, its plan and its ending.
- **A workload can write to the whole workspace** it is given, including
  control files a later tool reads (`.git/config`, `conftest.py`); the
  authority's later reads treat workspace content as untrusted
  (`LOCAL_UNVERIFIED`), and symlinks it plants are refused by the resolver.
- **No user-namespace remapping** (SANDBOX.md §2's `userns: remap` is not
  applied): uid 10001 is a host uid. Separated from the daemons by the
  start-up refusal; not from another host account an operator gives 10001.
- **The probe is trusted** to end what it can see; a process it cannot signal
  cannot exist in the environment (one uid, no capability), and the residue
  verdict says when it could not prove that.
- **Disk** (until OD-6) and **workspace ownership** (until OD-3) as stated.
- **Mode C grandchildren** (§7).

### 15. Architecture rules

TX050 (new): `sandbox/workload_plan.rs` is the one place a workload's
command line is spelled, and spells no `--privileged`, `--env`, `--env-file`,
`--interactive`, `--tty`, `--detach`, `--cap-add`, `--security-opt`,
`--device` or root user; TX035 extended to `workload_run`; TX036 extended to
the workload's forbidden field names (a user, an environment, an entrypoint, a
shell); TX033 keeps the probe connecting to nothing — `reap` signals and reads
`/proc`, nothing else. Each with a violation fixture and its findings pinned.

### 16. Dependencies and the TCB

**No new crate.** The probe's `nix` gains the `signal` feature (code of a
crate already linked, not a crate); everything else is the broker's and the
authority's existing code. No `unsafe`.

### 17. Acceptance and adversarial evidence

`make sandbox-workload-evidence` on a real OCI runtime, every case required,
NOT EXERCISED fails; a hosted job `sandbox-workload`; `make
sandbox-workload-mutations` weakening each guard in turn. Cases: the plan's
identity (uid 10001, no capability, `no-new-privileges`, never root);
executable substitution (another file, a symlink, other bytes, a missing
file); a drifted, stopped, foreign or unlabelled environment; output bounds;
the wall clock; a process tree — children, a daemonised grandchild, a process
that left its group, a forking loop — ended by `reap`, nothing left; the
environment's variables only; direct TCP and DNS refused from the workload;
writes outside the workspace refused; no runtime socket, no host path; the
broker's identity collisions refused; the ptrace posture reported; the
authority's gates (capability, policy for `sandbox`, an unenforceable
obligation, no `READY` environment, a lower level, a spent budget) refusing
before anything is recorded or run; a crash at W8–W10 leaving `UNKNOWN`, the
environment destroyed and the workload never run again; a repeated
idempotency key answered from the record; and an **agent-shaped workload**
— long-lived, with child processes, file operations in the workspace, and
network attempts — contained and ended. Every security guard has a mutant
that must make the evidence fail.

**As built (M5d.1).** `make sandbox-workload-evidence` runs nine broker and
five authority real-container tests, selected by name and each required to
run, which must report every case of `scripts/dw.py`'s `WORKLOAD_CASES`; no
container the evidence made may remain and none that predates it may go. The
hosted job is `sandbox-workload`, required by `ci`. `make
sandbox-workload-mutations` weakens thirty guards one at a time — the
deployment's identity and posture checks, the plan's user and working
directory, the digest proof, the re-judgement, the output and wall-clock
bounds, the client's ambiguous exits, `reap` and init's reaping, the residue
verdict, the authority's level, state, both gates, the sandbox action, the
obligations, the budget, idempotency, and every fail-closed destruction —
and each must fail the guards' unit suites or the evidence; every file is
restored and its SHA-256 checked. The review is run locally before a
checkpoint is offered; the hosted workflow does not run it. Three decisions
are proved by unit tests over every input because the evidence's
environments never present the input: a residue `reap` could not prove
clean destroys the environment; a live environment that is not `READY` —
`PREPARING`, `DESTROYING`, `UNKNOWN` — runs nothing (the schema's trigger
refuses the intent as well); and a `READY` environment below
`CONTAINER_ISOLATION` runs nothing. The review itself found three tests too
weak before it passed — the wall clock was bounded only by the round trip,
the budget's count was masked by its seconds, and "no ready environment"
was exercised only by a destroyed one — and each was tightened.

**Not evidenced by M5d.1, and not claimed:** a workload in `PROXY_ONLY` (the
evidence's environments are `NO_NETWORK`, so the agent-shaped workload's
network attempts are refused for want of any network — M5d.5 runs it with
declared origins); the three-identity separation (M5d.5); a concrete
`process.exec:<path>` grant refused for a workload (OD-9, M5d.2); return-path
redaction of a real secret value in a workload's output (M5d.3); and the
posture refusal on a real host whose window is open (proved by unit test;
the evidence host's own posture is reported, `posture-reported-matches-host`).

### 18. Implementation checkpoints

| Checkpoint | Delivers | Accepted when |
|---|---|---|
| **M5d.1** Authorised OCI workload lifecycle | §§3–5, 8–10, 13: protocol 8's `workload_run`; the broker's re-judgement, digest proof, fixed plan, bounds, wall clock and `reap`; the probe as init; schema 9; `Authority::workload_run` (no public route) with every gate; fail-closed environment destruction; the start-up identity and ptrace-posture checks | its real-container evidence, mutants and every earlier evidence green locally and in hosted CI |
| **M5d.2** Public sandboxed `process.exec` | the DWKP route (§2), the shared idempotency namespace, results naming environment and level; `workspace_exec_hygiene` enforced in the environment | hostile-client and eval coverage; the shipped packs' sandbox rules exercised |
| **M5d.3** Secrets B/C in the sandbox | §7 | residue evidence as M4e's: the value only in the target, redacted on return |
| **M5d.4** Workspace ownership and disk quota | §§6, 10 (OD-3, OD-6) | the authority's tools and the workload both work on the workspace; a full disk refused, measured |
| **M5d.5** The agent-shaped escape suite and multi-identity evidence | a long-lived agent-shaped workload in `PROXY_ONLY` with declared origins; the hosted three-identity job | ADR-0050 §21's uid-boundary condition shown with real users |
| **M5d.6** Closeout | run release destroys the environment; the gated eval `m5d-sandbox-exec`; this ADR accepted | every checkpoint's evidence in hosted CI |

### 19. Owner decisions

| # | Decision | Recommendation |
|---|---|---|
| OD-1 | Who chooses where `process.exec` runs | **the kernel**: a `READY` environment means sandbox, nothing means M4d's host floor; no runtime field, no fallback |
| OD-2 | A sandboxed executable's identity | **the operator's image manifest** (path → SHA-256) beside the image digest, proved from outside before every run; workspace scripts run only as arguments of a manifest executable |
| OD-3 | Workspace ownership | **(a) a workspace group** for V1; (c) copy-in/copy-out later where stronger isolation is wanted |
| OD-4 | Modes B/C delivery | **the trusted launcher over the exec's stdin** |
| OD-5 | Concurrency and long-lived workloads | **one workload at a time per environment**; long-lived workloads with handles decided at M5d.5 |
| OD-6 | Disk quota | **an operator-provided bounded filesystem, measured by the probe**; refuse when unbounded |
| OD-7 | `local` | **not in M5d**; with M6, by its own ADR |
| OD-8 | Default budgets | per workload ≤ 600 s and 128 KiB per stream; per run 100 workloads and 3 600 s |
| OD-9 | What a concrete `process.exec:<path>` grant means for a run whose environment is a sandbox | **resolved against the image manifest** (path → the pinned digest) when the run is admitted with an execution environment configured, instead of the host's resolver; until then only `process.exec:*` covers a workload and policy narrows it |

## Consequences

**Positive.** The first code DireWolf runs at an agent's request runs where
the boundary was measured, as an identity that is nobody else's, and is gone
when its invocation is; the authority still decides every one, and an
uncertain one costs its environment rather than a guess. The probe, the
plan, the record's judgement and the ledger are reused, not duplicated.

**Negative.** Every workload pays a record inspection, two `container cp`
digests and an extra `exec` for `reap` (measured in the evidence). One
workload at a time per environment. A lost answer destroys the environment,
and with it `/tmp`'s contents. No `local` before M6. Workspace ownership and
disk quota are not solved by M5d.1.

## Alternatives considered

- **Run each workload as a new container's first process** (the pid namespace
  then ends every descendant by itself). It needs a measurement per workload
  (seconds), and gives up the environment the run was measured in; `reap`
  gives the same ending in the measured environment.
- **The runtime's `exec` and the deadline alone.** The runtime keeps an
  `exec`'d process when its client dies: a deadline would end the client and
  leave the workload.
- **A second trusted binary in the image as the supervisor.** One more digest
  to pin and prove, for the duty the environment's init already has.
- **Docker's `--init`.** A runtime-supplied init whose bytes DireWolf does not
  pin.
- **`--env` for mode B.** The value in an argument vector and the daemon's
  exec record.

## Revisit if

The runtime offers id-mapped workspace mounts everywhere DireWolf runs (OD-3
(b)); a workload needs to outlive one invocation (OD-5); M6 makes host
execution reachable (`local`, OD-7); M9 brings a reviewed seccomp or Landlock
API; user-namespace remapping becomes the runtime default on supported hosts.
