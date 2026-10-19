# ADR-0052: M5d — production sandboxed `process.exec`: the authority decides a workload, the broker runs exactly that plan in a measured `oci-strict` environment, as the environment's own identity, and nothing of it outlives its invocation

**Status:** Proposed (M5d.1, M5d.2 and M5d.3 built; M5d.2's refinements §§2a and 5a — OD-10 and OD-11 — approved by the owner on 2026-10-19 with conditions, §19; this ADR's acceptance remains M5d.6's) · **Date:** 2026-10-13 · **Revised:** 2026-10-19 · **Would amend (on acceptance):** [ADR-0018](0018-authority-broker-split.md) (the broker runs workloads, never as its own uid), [ADR-0039](0039-durable-authority-state.md) (schema version 9: the workload ledger, §4), [ADR-0043](0043-m4b-private-broker-channel-and-brokered-fs-read.md) (private protocol version 8, §3), [ADR-0045](0045-m4d-process-execution-broker.md) (a process can run in an environment; the host floor is unchanged), [ADR-0047](0047-m5a-oci-execution-environment-and-measured-assurance.md) (the probe becomes the environment's init: it reaps orphans and, asked, ends every other process; `run_probe` gains a sibling, `run_workload`), [ADR-0050](0050-m5c-kernel-performed-net-http-ssrf-redirects-and-credential-egress.md) (§21's ptrace-posture prerequisite becomes a check the broker makes at start) · **Refines:** [ADR-0008](0008-sandbox-default.md) and [ADR-0024](0024-sandbox-network-topology.md) (as realised by [ADR-0048](0048-m5b-proxy-only-topology-and-connect-proxy.md)), [ADR-0046](0046-m4e-secret-handles-backends-injection-and-redaction.md) §13 (modes B/C reach a sandboxed target, M5d.3), [ADR-0051](0051-external-agent-interoperability.md) (Proposed; its M5d prerequisites), [SANDBOX.md](../SANDBOX.md) §§1–4, [POLICY.md](../POLICY.md) (`when.environment = "sandbox"`)

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

**As built in M5d.2.** The route is the tool messages at **version 5**
(`direwolf.tool.invoke` and `direwolf.tool.preview` and their answers;
versions 1–4 unchanged, and a version-4 `process.exec` is still the host
floor's). Version 5's call is version 3's plus at most two narrowings —
`timeout_seconds` (1–600) and `max_stream_bytes` (1–131 072) — and no member
that names an environment, an image, a user, a variable or a launcher: any
other member is a schema violation at the decoder
(`public-exec-smuggled-environment-refused`). With an execution environment
attached (§2a) a version-5 `process.exec` is sandboxed and never reaches the
host (`public-exec-never-on-the-host`); without one it is version 4's,
decided and denied by the floor; every other version-5 tool is version 4's
call, answered at version 5.

*The order.* Both gates first, for a **sandbox** action: a launch the
capability gate or policy denies prepares no environment (its plan names the
run's environment only when the run already has one, from an earlier
permitted launch). A permitted
launch is then refused before any intent when its executable is not in the
manifest (`EXECUTABLE_NOT_IN_IMAGE`), its working directory is not the
workspace root (`WORKING_DIRECTORY_UNSUPPORTED`), its run has no environment
and none can be prepared (`NO_ENVIRONMENT`, `ENVIRONMENT_UNAVAILABLE`), the
environment is not `READY` (`ENVIRONMENT_NOT_READY`) or is below
`CONTAINER_ISOLATION` (`ASSURANCE_INSUFFICIENT`), it is running a workload
(`ENVIRONMENT_BUSY`), the run was admitted against another image or manifest
(`IMAGE_CHANGED`), or the budget is spent (`BUDGET_EXHAUSTED`). The result,
`process_exec_sandboxed`, names the environment, the measured level, the
executable as (image, path, SHA-256), how it ended, both bounded streams, the
residue and whether the environment was destroyed; a failure names the
environment and whether it was destroyed. The plan's action states the launch
(`DIRECT` or `HYGIENE`, §5a) and the count and SHA-256 of the argv **as
executed** — any hygiene arguments included — never the arguments.

*Long workloads.* The broker answers a start once it has judged the
environment, proved the bytes and started the workload; the authority's
worker **parks** the request (at most 16 at once) and collects it every
250 ms between its other requests. Other connections, other runs and the
broker's other clients are served while it runs
(`public-exec-authority-answers-during-a-workload`,
`public-exec-broker-answers-during-a-workload`,
`public-exec-two-runs-at-once-in-two-environments`).

*Idempotency.* A key names one invocation in **one namespace every tool
shares**: schema 10's `workload_idempotency` (subject, session, key →
invocation) and triggers on it and the three other ledgers (file operations,
host processes, `net.http`) that refuse a key any of them holds. A key used
again — by the same tool or another, before or after a restart — is
`IDEMPOTENCY_KEY_REUSED`, and nothing runs again
(`public-exec-key-never-runs-twice`, `public-exec-cross-tool-key-refused`,
`production-replay-after-restart-refused`). A sandboxed launch's own repeat
is refused, not replayed: its answer carries output the runtime produced
once. A key belongs to the session's lease holder: the same key from another
connection is fenced (`STALE_EPOCH`) before anything is decided.

*OD-9, as built.* An admission made with an execution environment
configured resolves the run's concrete `process.exec:<path>` declarations
**against the manifest**: the grant is the manifest's (path, SHA-256), and a
path the manifest lacks refuses the admission. The run is bound to the
attached image and manifest (schema 10's `run_image`, the manifest's digest
under the domain `direwolf.sandbox.image_manifest.v1`), and a launch in a run
bound to another is `IMAGE_CHANGED`. A run admitted before any environment
was configured keeps its host-resolved grant, which covers no image
executable (`od9-host-resolved-grant-covers-no-image-executable`); a concrete
grant covers its one executable and nothing else
(`od9-concrete-grant-covers-nothing-else`).

**As built in M5d.3: tool messages version 6** (§7). Version 5's twelve
members, `process_exec` gaining one optional `credential_handle` -- a
handle, never a value, a mode, a variable, a descriptor or a length -- under
the same mandatory key. A plan that consumes a credential states a second
action, `spawn_injection{handle, mode, decision}`, beside its workload
action; the plan is `ALLOW` only if both are. Results, refusals and failures
are version 5's payloads: `CREDENTIAL_UNAVAILABLE` when the credential cannot
be used here (not configured, revoked, replaced, not allowed for this
executable, no spawn mode, a variable the environment sets, or **no
execution environment attached** -- then nothing runs on the host instead),
`CREDENTIAL_FAILED` when it could not be read or carried before anything
ran. A version-5 call cannot name a credential. Versions 1–5 are unchanged.

### 2a. A production environment (M5d.2; OD-10, approved by the owner 2026-10-19)

ADR-0047 gave the environment lifecycle no production caller "until M5d".
M5d.2 gives it exactly one — the authority itself — and the runtime none.
This extends ADR-0047 as that ADR anticipated, rather than contradicting it:
its lifecycle, measurement, judgement, crash windows and reconciliation are
used unchanged, and no new way to reach them is public.

- **The operator attaches one at start.** `dwkd-authority serve
  --sandbox-config <file>`: an absolute path, read once through the trusted
  operator-file reader (a regular file owned by root or the authority's uid,
  writable by nobody else, under directories only they can change, at most
  64 KiB), strict TOML — every member known, every integer base 10 — naming
  the runtime client and its socket, the image and the probe by digest, the
  topology (`PROXY_ONLY` for production, with its relay digest and egress
  budgets; `NO_NETWORK` only where the broker was started for evidence), the
  workload budget and the manifest (path → SHA-256). It requires a broker. A
  file that is not trusted or does not parse stops the server before its
  socket is bound. There is no reload, and no DWKP operation, flag of the
  runtime's or variable that attaches, prepares, measures, destroys or
  reconciles an environment (`public-no-lifecycle-operation`). TX053 confines
  the attachment to `server/sandbox.rs`; TX035 keeps every other public path
  from naming the lifecycle.
- **The authority prepares a run's environment when a permitted launch needs
  one** and the run has none live (§2's step 2a): recorded, measured from both
  vantages and judged by ADR-0047's lifecycle, W1–W7 included, then the launch
  decided again from the fence on. At most eight environments per run
  (`ENVIRONMENT_BUDGET_EXHAUSTED`); a preview never prepares; a preparation
  that does not end `READY` refuses the launch (`ENVIRONMENT_UNAVAILABLE`) and
  nothing is tried on the host.
- **A preparation's deadline and failure.** The exchange is bounded by the
  environment deadline, **120 s**, on both sides (ADR-0047 §4). A refusal is
  recorded and nothing remains. A deadline that expires after the order left
  proves nothing about the container: the environment is recorded `UNKNOWN`,
  the launch refused `ENVIRONMENT_UNAVAILABLE`, nothing runs and nothing is
  tried on the host; the run's next launches are refused
  `ENVIRONMENT_NOT_READY` at once, with no new exchange, and the uncertain
  environment is destroyed before any other is prepared (below) or at the
  next start (unit evidence against a fake broker,
  `a_preparation_past_its_deadline_is_unknown_refused_and_never_on_the_host`).
- **Environments are bounded across runs** (found in the M5d.2 review). A
  run's release does not destroy its environment before M5d.6, and
  reconciliation keeps a `READY` one; preparation reachable from production
  would therefore let a runtime that admits, launches and releases runs leave
  idle environments without bound. So before the authority prepares one, it
  destroys **at most one** environment that can never run a workload again —
  `READY` in a run no longer `ACTIVE`, or `UNKNOWN` or `DESTROYING` in any
  run, never one a workload is `LAUNCHING` in — durably first, as every
  destruction (reason `RECLAIMED`); and at most **16** environments are live
  at once across every run (as many as the broker supervises), a launch that
  would need another being refused `BUDGET_EXHAUSTED` before anything is
  prepared (`ended-runs-environment-reclaimed`, `live-environments-bounded`,
  unit; `public-exec-ended-runs-environment-reclaimed`, real).
- **Preserved:** the kernel's decision of where it runs (OD-1);
  `CONTAINER_ISOLATION` as the minimum; no host fallback; the operator's
  pinned digests; the durable lifecycle and its reconciliation at start; no
  user mount, flag or profile; no host launch before M6.
- **Residuals, as approved.** A preparation is one broker exchange: it holds
  the authority's worker and its broker link for its duration — **at most
  the 120 s environment deadline**; about 3 s for the preparation and the
  first launch together on the evidence host (Docker Engine 29.8.2,
  `public-exec-environment-prepared-by-the-authority` reports it) — so other
  requests wait for it as they wait for any brokered call (a workload, by
  contrast, never holds either, §8). A launch that reclaims an environment
  first holds the worker for that destruction too, bounded the same way, so
  a launch that needs an environment holds it for at most one destruction and
  one preparation. An ended run's environment idles until the next
  preparation or start (M5d.6 makes the release destroy it); at most 16 are
  live, so the 17th concurrently active run with an environment is refused
  until one ends. The configuration is fixed for the server's life, so
  `IMAGE_CHANGED` guards a binding that today changes only across restarts
  (shown with a planted binding).

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

**As built in M5d.2: version 9.** `broker.workload_run` is replaced by a
start and a collection, as M4d's `process_start`/`process_status`.
`broker.workload_start` carries the same two descriptors and the same
authorisation plus one closed word, the **launch** (`DIRECT` or `HYGIENE`,
§5a); the broker judges the environment, proves the bytes, admits the
workload to its supervisor and starts it, and answers once it has started —
within the environment deadline (120 s), not the wall clock.
`broker.workload_collect` carries no descriptor, names the invocation and the
broker generation that started it, and is answered within the exchange
deadline (10 s) with the workload's progress — still running, or its ending
with the residue exactly as version 8's result — or, when nothing ran, why.
The supervisor holds at most 16 workloads and **one unended workload per
environment** (`WORKLOAD_TABLE_FULL`, `WORKLOAD_IN_USE`); an ending is kept
until it is collected, and a collection repeats it. A collection for a
workload the broker does not hold, or for another generation's, is
`indeterminate` (`WORKLOAD_UNCONFIRMED`): a restarted broker cannot say what
its predecessor's workload did.

**As built in M5d.3: version 10.** `broker.workload_secret_start` is
`broker.workload_start` with the secret's one-shot pipe as the **third**
descriptor and three typed fields: the handle, the delivery (`FD_AT_SPAWN` or
`ENV_AT_SPAWN`) and mode B's variable -- present exactly for B, and never a
process-control name or one the environment sets (the shared decoder refuses
it). No field carries the value, its length or a runtime flag. It is answered
as a start, under its own operation; it is collected as any workload, and its
ending carries `redactions` -- how many whole occurrences of the value the
broker replaced in both streams, a count only -- exactly for a
secret-bearing workload (the authority treats a count on any other, or none on
one, as a broker not keeping the protocol: `UNKNOWN`).

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

**As built in M5d.2: schema version 10**, migrated transactionally from 9:
`workload_idempotency` — the key namespace every tool shares (§2), its rows
never updated or deleted, with triggers here and on the file-operation,
process and `net.http` ledgers refusing a key another holds — and `run_image`
— a run's image and manifest digest, fixed at admission (no update, no
delete), with a trigger refusing a workload intent in a run whose environment
is of another image.

**As built in M5d.3: schema version 11**, migrated transactionally from 10:
`workload_secret` links a workload to the one spawn use it consumes -- a
`secret_injection` row of mode `fd_at_spawn` or `env_at_spawn`, its consumer
the executable's (path, SHA-256) in the image -- made once, at both intents,
in the workload's own intent transaction, and never updated or deleted. A
restart that finds the workload `LAUNCHING` finds its use `INTENT`, and ends
both `UNKNOWN`. No column holds a value, a prefix, a length or a digest of
one.

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

### 5a. `workspace_exec_hygiene` in an environment (M5d.2; OD-11, approved by the owner 2026-10-19)

The shipped `balanced` and `power` packs allow sandboxed `process.exec` only
with `workspace_exec_hygiene` (SANDBOX.md §4a). M4d showed the obligation
cannot be kept on the host; §5's step 4 forbids `--env` and any other
variable on the runtime's command line. Three mechanisms were weighed:

| Mechanism | What it prevents | What hostile argv can still do | What workspace configuration stays active |
|---|---|---|---|
| **A trusted launcher in the image** (chosen) | configuration from outside the invocation: git's global and system files and any injected by variable, Python's user site and the implicit script or working directory on `sys.path`, pytest's cache, Cargo's network, npm's lifecycle scripts | undo a setting with an option the tool ranks above the environment — so those invocations are refused (below) | a repository's `.git/config` and hooks, `conftest.py`, `build.rs`, `package.json` scripts the invocation runs, a script named as an argument |
| An immutable profile (the variables in the environment's configuration when it is prepared) | the same variables, for every process of the environment | the same | the same — and every workload gets them, obligated or not; no per-tool arguments; the measured environment changes |
| Explicit denial | everything the obligation covers | nothing runs | — but the shipped packs could perform none of their authorised workloads |

**Chosen: the launcher.** The broker starts a workload carrying the
obligation as `container exec --user 10001:10001 --workdir /workspace
<container> /usr/libexec/direwolf/sandbox-probe launch hygiene <path>
<args…>`: the digest-pinned probe, proved before every workload like `reap`,
sets exactly the profile's `HYGIENE_ENVIRONMENT` — `GIT_CONFIG_GLOBAL=/dev/null`,
`GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_COUNT=0`, `PYTHONNOUSERSITE=1`,
`PYTHONSAFEPATH=1`, `CARGO_NET_OFFLINE=1`, `npm_config_ignore_scripts=true` —
over the environment's own, and executes the program with `argv[0]` its path
(exit 127 if it cannot). No variable is spelled on the runtime's command line
or carried on the wire (TX050, TX036); the launch is one closed word the
authority decides. The authority puts the tool's own neutralising arguments
first in the argv it records and hashes (pytest: `-p no:cacheprovider`), and
refuses as `OBLIGATION_UNENFORCEABLE`, before any intent:

- an invocation whose own arguments undo a setting — git's `-c`,
  `--config-env` or `--exec-path` before its subcommand, `clone -c` or
  `--config`; Python's `-E`; pytest's `-p cacheprovider`;
- a tool with no real-tool evidence in an environment yet — `npm`, `npx`,
  `pnpm`, `yarn`, `bun`, `cargo` — which therefore stays fail-closed; and
  (found in the M5d.2 review) the same tools reached through a wrapper: a
  `cargo-*` subcommand binary, `rustup` and `corepack` whatever they are
  asked, and a runner (`env`, `time`, `xargs`, …) or `uv` whose arguments
  name one of them to run (`rustup run stable cargo build`, `corepack pnpm
  install` and `env cargo build` were otherwise argv-safe and would have run
  under the launcher as if the obligation were kept).

The shipped packs also require `when.argv_safe`, so an interpreter (R1), a
runner (R2) or an exec-style option (R3: `git -c`) is denied by policy before
the obligation is considered; the refusals above hold for operator policies
that do not. A shell or interpreter such a policy allows runs whatever its
own code says — `npm` included — and the obligation makes no claim about it.

**Measured with the real tools** (`make sandbox-workload-evidence`, the host's
`git` and Python and the locked pytest in a `FROM scratch` image): the
launcher adds exactly its variables to the environment's
(`hygiene-launcher-adds-exactly-its-variables`); git reads the image's system
configuration directly and not through the launcher
(`hygiene-git-system-config-not-read`); a `json.py` in the working directory
shadows the standard library directly and not through the launcher
(`hygiene-python-working-directory-not-on-path`); pytest writes its cache
directly and not with the prefix (`hygiene-pytest-cache-not-written`); and
the shipped packs run `git` and `pytest` that way, deny the undoing and the
unevidenced forms, and run nothing for them (`shipped-*`).

**What it does not claim.** Interpreter flags and variables do not make
untrusted code safe. A repository's own configuration is still read
(`hygiene-residual-repository-config-read`), and its hooks, `core.fsmonitor`
or `core.sshCommand` can run; a `conftest.py` still runs
(`hygiene-residual-conftest-runs`); so would a `build.rs` or a lifecycle
script the invocation names. These are workspace content executed by a tool
the run was allowed to start: the obligation does not reach them, and the
environment — uid 10001, no capability, read-only root, its network, its
limits, `reap` — is what bounds them (SANDBOX.md §4a, consequence 1). The
environment's `HOME` is `/`, read-only, so no user file there is workspace
content either way.

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

**As built (M5d.3; OD-4's recommendation, refined).** The path, end to end:

1. **The authority decides, then records.** A version-6 `process_exec` naming
   a handle is decided in one transaction: the fence, the run, the key; the
   manifest's executable; then, before either gate and reading nothing, the
   handle's metadata, the run's admitted revision (`REPLACED`, `REVOKED`), the
   **consumer** and the **mode**; then both gates for the workload (a
   `SANDBOX` action) **and** both gates for `secret.use:<handle>` in the
   `SANDBOX` environment, keeping only `audit_level`. Permission to run the
   executable is never permission to use the secret, and no shipped pack has
   a `secret.use` rule (SAFE denies it; BALANCED and POWER default-deny it):
   the evidence uses a dedicated operator test policy. Approvals stay closed
   until M6 (a `REQUIRE_APPROVAL` rule denies). Both intents -- the workload's
   and the use's, linked -- are durable before anything is read.
2. **The consumer is the image's executable.** The operator's metadata names
   consumer paths; in an environment each is the executable the image
   manifest pins at that path, by its SHA-256, never the host file there --
   the identity rule of ADR-0046 §15 applied to the image, as OD-2 and OD-9
   apply it to grants. A run is bound to its manifest (`run_image`), and the
   broker proves the bytes before every launch, so a replaced binary is not
   the consumer. An egress-only secret names no consumer and reaches no
   process. *This refinement is the owner's to confirm with OD-4.*
3. **The kernel chooses the mode:** C (descriptor 3) before B (the operator's
   variable), never the request. Mode B's variable is refused if it is a
   process-control name or one the environment or `workspace_exec_hygiene`
   sets (`HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, `NO_PROXY`, and every
   `GIT_*`, `PYTHON*`, `CARGO_*` name): the shared contract refuses it, and the
   launcher refuses it again.
4. **The value is read last, once.** With no transaction open, after the
   runtime client is resolved and hashed and the workspace re-pinned: the
   backend read (zeroizing), the redaction index learns it, a mode B value
   holding a NUL is refused, and it leaves the authority as a one-shot pipe,
   the authority's copy zeroed (ADR-0046 §11). A value that cannot be read or
   carried fails the launch `CREDENTIAL_FAILED`; provably nothing ran.
5. **The broker reads it only after the judgement.** On the supervisor's
   thread, after it re-judged the environment from the runtime's record and
   proved the executable, it reads the pipe once (a FIFO, read-only, at end
   of file, 1 byte to 32 KiB) -- a refused workload never reads it (measured:
   the pipe is still full after a digest refusal).
6. **Over the client's standard input, to the trusted launcher.** The launch
   helper gives the runtime client the value **framed** -- a 4-byte
   big-endian length, the value, end of file -- as its standard input, and
   nothing else changes: the same `container exec` as an ordinary workload's
   (`workload_plan::run_with`) with the one word that attaches standard
   input, and the probe's `launch secret-fd|secret-env[-hygiene] [NAME]`
   before the executable. *Measured on Docker Engine 29.8.2:* without that
   word the client forwards nothing (the process reads `/dev/null`); with it
   the client forwards the bytes and they appear in no `inspect`, exec
   inspect, log or event record, while the command line does appear in the
   runtime's events -- which is why the value is never a word of it. The
   word is spelled in `workload_secret_plan.rs` alone (TX055); every other
   workload, environment step and probe run still has standard input
   `/dev/null` (TX050), and the ordinary plan is unchanged.
7. **The launcher delivers and executes.** The pinned probe reads exactly
   one frame -- nothing, a short prefix, a length of zero or past 32 KiB, a
   byte short or a byte more executes nothing (exit 127) -- puts the value on
   descriptor 3 (mode C, a pipe holding it then end of file) or adds
   `NAME=value` to the environment's own variables (mode B), sets
   `workspace_exec_hygiene`'s variables for a `-hygiene` profile, replaces
   its standard input with `/dev/null`, wipes its copy, refuses to run with
   any other descriptor open, and executes the absolute path. npm, Cargo,
   `rustup` and `corepack` stay fail-closed under the obligation (§5a).
8. **The return path.** The broker's drains replace every whole occurrence
   -- one split across reads included -- with `[redacted:<handle>]` as the
   bytes arrive, keep no part of one, and report the count; the authority
   then redacts with its exact index and known shapes before anything is
   recorded or answered, and the run is `LOCAL_UNVERIFIED`.
9. **The ending.** A completed workload's use is `INJECTED` and counted once;
   a provably-unrun one `FAILED` with the typed reason; an uncertain one
   `UNKNOWN`, its environment destroyed, the use not counted -- in the
   workload's own outcome transaction. A key names one invocation for ever:
   nothing is read, handed over or run again after any crash (§9).

*Residuals, recorded and not hidden* (§14): descriptor 3 and the variable are
inherited by every descendant the target starts; the runtime's client and
daemon carry the value in memory on its way; a program that transforms the
value (encodes, splits across separate writes beyond a whole occurrence,
reverses) passes redaction; a malicious consumer can copy it into the
workspace or to an origin the run may reach. Return-path redaction keeps an
honest program's echo from cognition; it is **not** protection against a
malicious consumer, which the environment's containment and the operator's
choice of consumer bound.

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

**As built in M5d.2.** Start and collection (§3): a running workload holds
neither the private channel nor the authority's worker. In the broker each
started workload has one supervising thread — it waits for the runtime
client the launch helper started, drains its streams to their bounds, runs
`reap` and records the ending — at most 16 at once, and the table's slot is
the only shared state (a mutex, never held across a wait). Every descriptor
of a workload is the launch helper's, close-on-exec, and the runtime client is
spawned under the broker's fork guard, so none reaches another workload's
client. **D11 reviewed again** (ADR-0050 §21): the broker still serves one
connection at a time and starts at most one exchange worker; a supervising
thread runs no untrusted code (the runtime client is the pinned one, the
workload runs in the environment as uid 10001), so the worker count and its
conditions are unchanged.

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

**As built in M5d.2**, W9 has its own crash point (`WorkloadAfterStart`,
after the start's answer and before the first collection): an authority
killed there leaves the workload running; the next incarnation finds the row
`LAUNCHING`, ends it `UNKNOWN` and destroys the environment, which ends the
workload (`crash-w9-unknown-environment-destroyed`; through the released
binary, `production-crash-mid-workload-unknown-destroyed`). A broker killed
during a public launch answers `OUTCOME_UNKNOWN` with the environment's
destruction durable, completed when a broker answers again
(`public-exec-unknown-destroys-environment`).

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
- **M5d.3, as built (§7).** A credential's descendants: descriptor 3 and mode
  B's variable are inherited by every process the target starts (measured,
  `fd-at-spawn-inherited-by-a-descendant`, `env-at-spawn-inherited-by-a-descendant`);
  confined by the environment and ended by `reap`, not restricted to one
  process. The runtime's client and daemon hold the framed value in memory
  while forwarding it (the client is pinned and hashed; neither writes it to
  a record, an event or a log -- measured). Redaction matches whole
  occurrences of the exact value and known shapes; a consumer that transforms
  or exfiltrates it (the workspace, an allowed origin) is not stopped by it.
  The launcher is the pinned probe, trusted by digest like `reap`.

### 15. Architecture rules

TX050 (new): `sandbox/workload_plan.rs` is the one place a workload's
command line is spelled, and spells no `--privileged`, `--env`, `--env-file`,
`--interactive`, `--tty`, `--detach`, `--cap-add`, `--security-opt`,
`--device` or root user; TX035 extended to `workload_run`; TX036 extended to
the workload's forbidden field names (a user, an environment, an entrypoint, a
shell); TX033 keeps the probe connecting to nothing — `reap` signals and reads
`/proc`, nothing else. Each with a violation fixture and its findings pinned.

**M5d.2:** TX035 narrowed — the route may name the private start and
collection only through the broker link, and nothing public names the
lifecycle; **TX053** (new) — only `server/sandbox.rs` attaches the operator's
configuration; TX036 extended to a launcher, its arguments and the
obligation's variables on the wire; TX050 extended to any launcher but the
probe's own words (`env`) and to a `NAME=value` word in the plan;
**TX054** (new) — `serve_authority` and `Served::operate`, the evidence's door
to the public route (§17), are named by the server module alone.

**M5d.3:** **TX055** (new) -- the word that attaches the runtime client's
standard input (`--interactive`, or `-i` alone or combined) is spelled in
`workload_secret_plan.rs` alone, across the broker; **TX056** (new) -- that
plan spells nothing else TX050 bans. TX014's exemption gains the route tests'
fake broker, which reads the pipe a secret-bearing start hands it (as the
secret-use tests' fake does a hop's); TX026 is unchanged (the variable's NUL
check is the handoff's, beside the header check). Each with a violation
fixture and its findings pinned.

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

**As built (M5d.2).** The same task runs eleven broker and eleven authority
real-container tests. The broker's add the start/collect split — a start
answered before its workload ends, a second workload in an environment
refused, the broker serving others meanwhile, a collected ending repeated, a
collection of another generation's workload and after a broker restart
`WORKLOAD_UNCONFIRMED` — and the trusted launcher with the real `git`,
Python and pytest. The authority's reach the public route through a **real
DWKP client**: through the server seam serving an authority the test built
(`serve_authority`, the evidence's door), and through the released
`dwkd-authority serve --sandbox-config` itself; the caller is the transport's
peer credential, the environment the authority's own preparation, the
result's identity the image's, the user 10001; a long workload timed out and
reaped while other runtimes are served; key reuse, cross-tool reuse, a key
from another connection; bounded output and a reaped daemon; a smuggled
field and a lifecycle operation refused by the decoder; a broker killed
mid-launch; the budget; image bytes that are not the pinned ones; OD-9's
three cases; the shipped `balanced` and `power` packs with the tools image;
and W9 in-process and through the released binary. `make
sandbox-workload-mutations` grows to 52 mutants: M5d.1's thirty and
twenty-two of M5d.2's guards — the host floor deciding a sandboxed launch, a
denied launch preparing, unbounded preparation per run and across runs, the
reclamation of environments that can never run again, the image binding, a
busy environment, the key namespace in both directions, a launch holding the
worker, the supervisor's per-environment, table and generation bounds, the
launcher ignored or setting nothing, the hygiene refusals (wrappers included)
and prefix, and the operator file's strictness.

**As built (M5d.3).** `make sandbox-secret-evidence` first runs the
authority's mode B/C pipeline against a fake broker with **real kernel-keyring
values** (labelled so: delivery is the real suites'), every case required --
the value read once, after both intents; C before B; both gates; every
refusal and denial reading nothing; the stored revision replaced or revoked;
failures before anything ran; thirteen crash windows; no host fallback --
then six broker and four authority real-container tests, each required to
run, which must report every case of `SECRET_SANDBOX_CASES`: the released
broker delivering a **synthetic** value on descriptor 3 and as `GH_TOKEN`
(fingerprints compared, never values), the descendants' inheritance, the
hygiene launcher composed with each mode, the value absent from argv, the
runtime's records, events and logs, redaction of an echo split across reads,
every malformed handoff refused and the pipe unread after a refused
judgement, the launcher refusing every other frame and every reserved name,
a broker stopped after the read running nothing; and the real authority over
a **real DWKP client** -- the server seam and the released `serve
--sandbox-config --secrets-file` -- delivering, redacting, refusing, denying
under every shipped pack, ending `UNKNOWN` and destroying the environment
after a crash, and never running a key twice. The hosted job is
`sandbox-secret`, required by `ci`. `make sandbox-secret-mutations` weakens
22 guards one at a time -- the plan attaching standard input (both ways), the
frame, the third descriptor, the broker reading before it judges, a NUL in a
variable, the start's answer, the drains' redaction and its count, the
launcher's frame, names and standard input, both gates, the plan's injection
decision, C before B, the consumer, a reserved variable, the variable's NUL,
no host fallback, the linked use, an unknown ending and a missing count --
and kills all 22, twelve by the unit suites and ten by the real-container
evidence; M5d.2's campaign, its targets moved to the code M5d.3 reshaped,
still kills 52 of 52. Every file is restored and its SHA-256 checked.

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
| **M5d.2** Public sandboxed `process.exec` | the DWKP route (§2), the shared idempotency namespace, results naming environment and level; `workspace_exec_hygiene` enforced in the environment; as built also private protocol 9's start and collection (§3), schema 10 (§4), OD-9, the production environment (§2a) and the trusted launcher (§5a) | hostile-client and eval coverage; the shipped packs' sandbox rules exercised; §§2a and 5a decided by the owner |
| **M5d.3** Secrets B/C in the sandbox | §7; as built also tool messages version 6 (§2), private protocol 10 (§3), schema 11 (§4), TX055–TX056 (§15) | residue evidence as M4e's: the value only in the target, redacted on return — **built** |
| **M5d.4** Workspace ownership and disk quota | §§6, 10 (OD-3, OD-6) | the authority's tools and the workload both work on the workspace; a full disk refused, measured |
| **M5d.5** The agent-shaped escape suite and multi-identity evidence | a long-lived agent-shaped workload in `PROXY_ONLY` with declared origins; the hosted three-identity job | ADR-0050 §21's uid-boundary condition shown with real users |
| **M5d.6** Closeout | run release destroys the environment; the gated eval `m5d-sandbox-exec`; this ADR accepted | every checkpoint's evidence in hosted CI |

### 19. Owner decisions

| # | Decision | Recommendation |
|---|---|---|
| OD-1 | Who chooses where `process.exec` runs | **the kernel**: a `READY` environment means sandbox, nothing means M4d's host floor; no runtime field, no fallback |
| OD-2 | A sandboxed executable's identity | **the operator's image manifest** (path → SHA-256) beside the image digest, proved from outside before every run; workspace scripts run only as arguments of a manifest executable |
| OD-3 | Workspace ownership | **(a) a workspace group** for V1; (c) copy-in/copy-out later where stronger isolation is wanted |
| OD-4 | Modes B/C delivery | **the trusted launcher over the exec's stdin** — **built in M5d.3** (§7), with the consumer resolved against the image manifest (§7 item 2), for the owner to confirm |
| OD-5 | Concurrency and long-lived workloads | **one workload at a time per environment**; long-lived workloads with handles decided at M5d.5 |
| OD-6 | Disk quota | **an operator-provided bounded filesystem, measured by the probe**; refuse when unbounded |
| OD-7 | `local` | **not in M5d**; with M6, by its own ADR |
| OD-8 | Default budgets | per workload ≤ 600 s and 128 KiB per stream; per run 100 workloads and 3 600 s |
| OD-9 | What a concrete `process.exec:<path>` grant means for a run whose environment is a sandbox | **resolved against the image manifest** (path → the pinned digest) when the run is admitted with an execution environment configured, instead of the host's resolver; until then only `process.exec:*` covers a workload and policy narrows it — **built in M5d.2** (§2) |
| OD-10 | How a production authority gets an environment (M5d.2) | **the operator's file at start, the authority preparing a run's environment on its first permitted launch** (§2a); no runtime-facing lifecycle operation; preparation's bounded hold on the worker accepted as stated, or made a start/collection pair before M5d.6 — **approved by the owner, 2026-10-19, with conditions (below)** |
| OD-11 | How `workspace_exec_hygiene` is kept in an environment (M5d.2) | **the pinned probe as a trusted launcher**, the per-tool arguments first, undoing invocations and unevidenced tools refused (§5a); the residuals it does not reach stated, never claimed — **approved by the owner, 2026-10-19, with conditions (below)** |

**Owner decisions, 2026-10-19 (M5d.2).** OD-10 and OD-11 are approved for
M5d.2's implementation, on these conditions, each met as stated; the ADR
stays Proposed until M5d.6, and OD-1 to OD-9 await the owner with it.

- **OD-10.** Approved: operator-controlled production attachment and
  preparation, with the authority choosing where a launch runs, operator-
  pinned manifests, the measured assurance and no host fallback. *Conditions
  and how they are met:* the bounded preparation delay is documented — at
  most the 120 s environment deadline per exchange, a launch that needs an
  environment holding the worker for at most one destruction and one
  preparation (§2a); its timeout and failure behaviour is verified — a
  refused preparation leaves nothing, an expired deadline records `UNKNOWN`,
  refuses the launch `ENVIRONMENT_UNAVAILABLE`, runs nothing on the host, and
  the uncertain environment is destroyed before another is prepared (§2a,
  unit evidence); the production boundary is preserved — no DWKP lifecycle
  operation, the operator's file read once through the trusted reader, TX053
  and TX035, no host fallback, `CONTAINER_ISOLATION` the minimum. The review
  found and fixed one unbounded availability issue: idle environments of
  ended runs accumulated without bound; they are now reclaimed and at most 16
  are live (§2a).
- **OD-11.** Approved: the digest-pinned probe as the trusted hygiene
  launcher. *Conditions and how they are met:* the Git, Python and pytest
  protections proved with the real tools are kept (§5a, the `hygiene-*` and
  `shipped-*` cases); `npm` and Cargo stay fail-closed until real-tool
  evidence exists — directly, and (fixed in the review) through `cargo-*`,
  `rustup`, `corepack`, a runner or `uv`; and hygiene is **not** claimed to
  prevent arbitrary workspace code execution — a repository's configuration
  and hooks, `conftest.py`, `build.rs`, a lifecycle script or a script named
  as an argument still run, and **kernel-enforced OCI containment (§5, ADR-0047
  §5) remains the security boundary**.

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
disk quota are not solved by M5d.1. M5d.2's preparation holds the
authority's worker for its duration — at most 120 s per exchange (§2a) — an
ended run's environment idles until the next preparation, at most 16 are
live, and `npm`-family tools and `cargo`, directly or through a wrapper, stay
refused under the obligation until evidenced (§5a). M5d.3's credential
reaches the program's whole process tree, not one process, and its return
path redacts what an honest program echoes, not what a malicious one
transforms (§7).

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
