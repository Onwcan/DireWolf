# ADR-0052: M5d — production sandboxed `process.exec`: the authority decides a workload, the broker runs exactly that plan in a measured `oci-strict` environment, as the environment's own identity, and nothing of it outlives its invocation

**Status:** Proposed (M5d.1, M5d.2 and M5d.3 built; M5d.2's refinements §§2a and 5a — OD-10 and OD-11 — approved by the owner on 2026-10-19 with conditions, §19; M5d.4 built, its hosted CI green at `1c8ccbe` (run 39854518873), OD-3, OD-6 and OD-12 — the `DIRECT` launch through the trusted launcher — still awaiting the owner's review, §§5a, 6, 10, 19; M5d.5 built, its one-identity evidence passing locally and its three-identity evidence hosted-only, awaiting the owner's commit and hosted CI, OD-5 for the owner, §§17, 19; this ADR's acceptance remains M5d.6's) · **Date:** 2026-10-13 · **Revised:** 2026-10-23 · **Would amend (on acceptance):** [ADR-0018](0018-authority-broker-split.md) (the broker runs workloads, never as its own uid), [ADR-0039](0039-durable-authority-state.md) (schema version 9: the workload ledger, §4), [ADR-0043](0043-m4b-private-broker-channel-and-brokered-fs-read.md) (private protocol version 8, §3), [ADR-0045](0045-m4d-process-execution-broker.md) (a process can run in an environment; the host floor is unchanged), [ADR-0047](0047-m5a-oci-execution-environment-and-measured-assurance.md) (the probe becomes the environment's init: it reaps orphans and, asked, ends every other process; `run_probe` gains a sibling, `run_workload`), [ADR-0050](0050-m5c-kernel-performed-net-http-ssrf-redirects-and-credential-egress.md) (§21's ptrace-posture prerequisite becomes a check the broker makes at start) · **Refines:** [ADR-0008](0008-sandbox-default.md) and [ADR-0024](0024-sandbox-network-topology.md) (as realised by [ADR-0048](0048-m5b-proxy-only-topology-and-connect-proxy.md)), [ADR-0046](0046-m4e-secret-handles-backends-injection-and-redaction.md) §13 (modes B/C reach a sandboxed target, M5d.3), [ADR-0051](0051-external-agent-interoperability.md) (Proposed; its M5d prerequisites), [SANDBOX.md](../SANDBOX.md) §§1–4, [POLICY.md](../POLICY.md) (`when.environment = "sandbox"`)

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
  from naming the lifecycle. **M5d.4:** the file's `[workspace]` table is
  required and says what every run's workspace is (§§6, 10): `quota_bytes`
  (16 MiB to 16 TiB) — production's — or `unverified_evidence = true`, never
  both; the second is served only by a broker started with
  `--allow-unverified-workspace`, and both daemons log `REDUCED ASSURANCE`.
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

**As built in M5d.4: version 11.** The environment's specification — on
preparation, measurement and every workload start — gains an optional
`workspace_bound`: the operator's quota, the capacity the authority's
`fstatvfs` of its pinned root counts and the owner its `fstat` finds (§§6,
10). Present, the workspace contract is **bounded** and its three host
invariants are required; absent, the contract is the evidence harness's
unverified workspace, which a broker serves only when its operator started it
with `--allow-unverified-workspace` (`WORKSPACE_UNVERIFIED` otherwise, before
anything is created). The probe's report goes to version 3 with the mounted
workspace's facts, and a new closed probe command, `workspace`, reports them
again — writing nothing — before every workload. New refusals:
`WORKSPACE_GROUP_CONTRACT` (a brokered name change in a directory of the
workspace group that is not set-group-id and group-writable; public
`WRITE_DENIED`), `NO_SPACE` (`ENOSPC` or `EDQUOT` with nothing changed; public
`BROKER_EXECUTION_ERROR`, the class every failed brokered change has, the
audit naming `NO_SPACE`) and `WORKSPACE_UNVERIFIED`. **What a start's answer
means** (made precise by M5d.4's W9 review): the environment was judged, the
bytes proved and the workload admitted to the supervisor, whose thread then
starts the runtime client — so the answer precedes the runtime's `exec`, by
design ("nothing runs that a start did not answer for"). The workload's
process can therefore appear after an authority that received the answer has
already died; W9 is evidenced accordingly (§9).

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

**M5d.4: every workload through the launcher — for the owner's review
(OD-12).** The runtime's `exec` gives a process the umask `0022` and has no
option to change it, so a file a workload made would be `0644` — readable,
but not writable, by the workspace group that the broker and the authority
share with it (§6). The broker therefore starts a `DIRECT` workload as
`container exec --user 10001:10001 --workdir /workspace <container>
/usr/libexec/direwolf/sandbox-probe launch direct <path> <args…>` too: the
same digest-pinned probe, proved before every workload, with a new profile,
`direct`, that sets **no variable** and only the umask; and every profile —
`hygiene` and M5d.3's four included — now sets the umask `0007` immediately
before its `exec`. What did not change: the executable and its exact
arguments (`argv[0]` its path, no shell); uid and gid 10001; standard input
`/dev/null` for every launch but M5d.3's secret ones, whose frame is read and
replaced by `/dev/null` before the `exec`; no descriptor beyond 0–2 (3 for
mode C) — the launcher refuses to `exec` with any other; no variable but the
profile's; the digest of the target proved before the start as before. The
launcher's failure is its reserved exit (`LAUNCH_FAILED`), never believed as
the program's. Measured: a file and a directory the workload makes are `0660`
and `0770` (`2770` under a set-group-id root), its umask `0007`
(`umask-0007-through-the-direct-launcher`). The workload may change its own
umask; the root's `2770` keeps every identity outside the group out whatever
it does. **Flagged for the owner:** this widens the launcher from M5d.2's
obligated launches to every launch; it is not presented as approved.

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

**As built (M5d.4): OD-3(a), for the owner's review.**

- **The group is `10001`, the workload's own primary gid** (`WORKSPACE_GROUP`
  = the profile's `SANDBOX_GID`, a compile-time assertion keeps them one).
  The workload reaches the workspace through its primary group; nothing is
  added to its command line (no `--group-add`) and the plan's identity is
  unchanged. Measured on Docker Engine 29.8.2: `docker exec --user
  10001:10001` gives gid 10001 and the supplementary groups `10001` only.
- **The root:** owned by root or the authority's own uid — never 10001, which
  could change its mode — of group 10001, mode **exactly `2770`**; the
  authority and the broker are supplementary members of the group, and
  nobody else is. Files the workload makes are `0660` and directories `2770`
  (the launcher's umask `0007`, §5a; the set-group-id bit inherited); files
  the broker makes are `0660` (`CREATED_FILE_MODE`) of the root's group.
- **Measured from both vantages before anything uses it**, and again before
  every workload: the authority holds its pinned root's descriptor against
  the contract — owner, group, mode, its own membership of the group by
  `/proc/self/status`, and none of its own state, socket or secret files on
  that filesystem — and sends what it found (§3); the probe reports from
  inside the mounted root's identity, owner, group and mode, the mount's own
  root (`/`) and `nosuid,nodev`, and the broker judges the two:
  `HOST_WORKSPACE_IDENTITY`, `HOST_WORKSPACE_OWNERSHIP` (the probe's facts and
  the broker's own membership) and `CONTAINER_WORKSPACE_GROUP_INHERITED` (the
  probe makes a directory and a file and finds them group 10001, the
  directory set-group-id; a full filesystem falls back to the root's own
  metadata). Required for the bounded contract; the evidence harness's
  unverified contract requires none of them and says so (§10).
- **Nothing is repaired.** No daemon changes a root's mode, owner or mount:
  a root that is not the contract's is refused with the reason
  (`WORKSPACE_OWNER`, `WORKSPACE_GROUP`, `WORKSPACE_MODE`,
  `WORKSPACE_GROUP_MEMBERSHIP`, …), before the broker hears of it; found so
  under a `READY` environment, before a workload, it is drifted and
  destroyed (TX057).
- **The broker keeps the group's convention.** A brokered name change in a
  directory of group 10001 that is not set-group-id, or not the group's to
  write — a workload cleared the bit — is refused unchanged
  (`WORKSPACE_GROUP_CONTRACT`, public `WRITE_DENIED`), rather than leaving a
  file the workload cannot reach.
- **A brokered change waits while a workload may write the workspace**
  (ADR-0044 §3). Under OD-3(a) the workload is in the group that may write
  the workspace, and Linux has no compare-and-swap of a directory entry, so
  the broker's checks exclude untrusted writers rather than defend against
  them; the exclusion is now in time. `fs.write`, `fs.patch`, `fs.move`,
  `fs.delete` and staging reclamation fail `SHARED_DIRECTORY` before anything
  is sent — the audit naming `excluded_by: WORKLOAD_IN_WORKSPACE` — while any
  run whose workspace root is the same directory (by device and inode) has a
  workload `LAUNCHING`, or an environment `UNKNOWN` or `DESTROYING`; a
  reclamation waits `EXPECTED`. Reads are unaffected: the resolver is built
  against concurrent renames (ADR-0042 §4). **Why it cannot race:** the
  intent of every workload is durable (`LAUNCHING`) before the broker hears
  of it; a workload's terminal state is recorded only after `reap` proved
  every process of its environment gone, or with the environment's
  destruction; the authority serves one request at a time, so the exclusion's
  read and the effect it guards are one step that no workload start can
  enter; and the broker serves one connection at a time, so an effect sent by
  an incarnation that then died completes before any later request is read.

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

**M5d.4.** The start's answer says the workload was judged, proved and
admitted; its supervising thread then starts the runtime client (§3). While
a workload is `LAUNCHING` — and while an environment is `UNKNOWN` or
`DESTROYING` — no brokered change of a name, and no reclamation, is made in
its workspace or that of any run bound to the same directory (§6); its
`COMPLETED`, `FAILED` or `UNKNOWN` ends that.

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

**W9's evidence, corrected in M5d.4.** The case counted the environment's
processes at once after the authority stopped, and once failed with none
counted. The cause is in the design, not the launcher: the start's answer
precedes the runtime's `exec` (§3), so a count taken at once can run before
the workload exists. The evidence now waits — bounded, 60 s — for the
workload's own process: uid 10001 with the target's argument vector, which
proves the launcher reached its `exec` and the target runs as the workload's
identity while the authority is gone (`crash-w9-running-after-start`); then
the restart ends it `UNKNOWN` and destroys the environment, and the same key
is answered from its record (or the run's end), never run again, with no
second workload record, environment or container (`crash-w9-never-run-again`).
W8–W11 together passed six runs of six, and the whole workload evidence
135 of 135 cases, after the change.

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

**As built (M5d.4): OD-6, for the owner's review.** The operator's file
declares the quota (`[workspace] quota_bytes`, 16 MiB to 16 TiB, §2a); each
workspace root must be **the root of a filesystem of its own** of that size —
a `tmpfs`, a loop-mounted image, a volume, a project-quota directory exposed
as its own mount — `nosuid,nodev`. The authority's `fstatvfs` of its pinned
root and the probe's `statvfs` of `/workspace` each count the capacity
(`f_blocks × f_frsize`, overflow-checked); it must be at most the quota and
no more than a quarter below it (`capacity_within_quota`), and the mount must
be the filesystem's root (mountinfo's root field `/`): a host directory on a
larger filesystem — measured: a plain directory reports the whole disk and a
non-root mount root — is `WORKSPACE_UNBOUNDED` before anything is created,
or `HOST_WORKSPACE_CAPACITY` failed from inside. The capacity is measured
again before every workload; one that changed — a remount, another
filesystem mounted over the root — drifts the environment, which is
destroyed before the workload. **When the filesystem is full** the kernel
says so: a brokered write, creation or deletion that meets `ENOSPC` or
`EDQUOT` changes nothing and fails `NO_SPACE` (public
`BROKER_EXECUTION_ERROR`), every change before it durable first; the
workload sees its own `ENOSPC`; another workspace, a filesystem of its own,
is untouched — nothing is borrowed. `/tmp` (512 MiB) and `/var/tmp` (128 MiB)
stay the environment's own `tmpfs`, never the workspace, and `RLIMIT_FSIZE`
(1 GiB) still bounds one file: it is not the quota. **The evidence
harness's unverified contract** (`unverified_evidence = true`) bounds
nothing and proves no group; both daemons log `REDUCED ASSURANCE`, the
broker serves it only with `--allow-unverified-workspace` (TX059), and it is
never evidence of this section's guarantee.

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
- **Disk and workspace ownership (M5d.4, §§6, 10).** The guarantee is the
  operator's provisioning, measured: a workspace that is not a filesystem of
  its own of the quota's size, or not the group's as stated, is refused, never
  repaired. What remains: every member of group 10001 — the workload, the
  authority, the broker — can read and write everything in every workspace
  the group owns, so any other host account given gid 10001 shares them; the
  workload can fill its own workspace (its own run's denial of service, never
  another's), change its own umask or the modes of files it owns, and clear
  a directory's set-group-id bit — the root's `2770` keeps every identity
  outside the group out regardless, and the broker refuses to change a name
  in such a directory (`WORKSPACE_GROUP_CONTRACT`); the quota is a
  filesystem's, so its granularity is the operator's (the capacity may lie a
  quarter below the declaration); and the unverified contract proves none of
  it, for evidence only.
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

**M5d.4:** **TX057** (new) -- the authority's state layer, resolver and
sandbox configuration change no mode, owner, extended attribute or mount and
allocate or format nothing: the workspace is measured and refused, never
repaired; **TX058** (new) -- the root's mode `2770` and the launcher's umask
`0007` are spelled once, in `dwk-proto`'s sandbox contract, and named
everywhere else; **TX059** (new) -- the unverified workspace is acknowledged
in one place per daemon: the broker's command line, the operator's file.
TX015 and TX021 exempt the broker's full-filesystem unit test, which reads
and writes its own `tmpfs` and re-executes itself in its own user and mount
namespace. Each with a violation fixture and its findings pinned.

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

**As built (M5d.4).** `make sandbox-workspace-evidence` first runs the
in-process half, every case required: the broker's group convention and
no-room class, and a **real** 256 KiB `tmpfs` filled to `ENOSPC` in the
test's own unprivileged user and mount namespace — a write, a creation and a
deletion each refused `NO_SPACE` with nothing changed; and the authority's
contract and exclusions against the route tests' **fake broker** (labelled
so) — a workspace not the contract's refused before the broker hears of it,
the contract said in the audit, no name change and no reclamation while a
workload may run, an environment of uncertain end excluding until it is
gone, a replaced root destroying its environment, drift answered
`ENVIRONMENT_NOT_CLEAN`. Then real containers, selected by name and each
required to run: three broker and four authority tests that any host with a
runtime runs — the broker refusing an unverified workspace it was not told to
allow, and a bound the probe contradicts (an unbounded directory, a forged
capacity, a forged identity) with its container removed; production refusing
an unprovisioned workspace before the broker, the released `serve` refusing
it too; the umask through the `direct` launcher; `/tmp` and `/var/tmp` apart
from the workspace; the exclusion while a workload runs, said by the audit,
and lifted when it ended — and one broker and five authority tests that only
an operator-provisioned host runs (`DW_WORKSPACE_PRIVILEGED=1`: the hosted
`sandbox-workspace` job creates the group 10001 and the harness mounts, and
undoes, two 64 MiB `tmpfs` roots, a loop-mounted 64 MiB `ext4` image and an
unbounded root): both filesystems accepted with every workspace invariant
`PASS`; interoperation through the group — the workload makes and the broker
reads, the broker makes and the workload changes, the broker replaces and
the workload reads, modes `0660`/`2770` and group 10001 throughout —
`nobody` refused both ways; a wrong group, a cleared set-group-id bit, modes
`2775` and `2777`, a workload-owned and a foreign-owned root, a quota twice
the filesystem, an unbounded host directory and a subdirectory of a bounded
filesystem each refused and left exactly as found; a grown filesystem and a
filesystem mounted over the root each destroying the environment before the
workload; a real `ENOSPC` on the `ext4` image — the workload writing until
not one more block fits, its file closed between rounds (a first `ENOSPC`
is not a full filesystem: ext4 counts blocks preallocated for an open file
as used and frees them on close, which is how hosted run 39585235773 found
room for the write this case expected refused), the room left measured from
the host as less than the brokered write needs, then that write failing
`NO_SPACE` with nothing changed and no staging left, another workspace's
free space unchanged and writable, room made and the same write made in
full, a new incarnation's store whole; and the released `serve` with a
quota. Without the privileged
half those cases are NOT EXERCISED and the task fails after reporting the
rest. No container, mount, loop device or directory the evidence made may
remain. `make sandbox-workspace-mutations` weakens 26 guards one at a time —
the contract's owner, group, mode, membership, bound, tolerance and private
filesystems, a bounded workspace sent with no bound, the exclusion and its
two states, the reclamation's wait, drift and its public answer, the
operator file's default, the broker's identity, membership, capacity and
contract judgements and its waiver, the probe's mount root, the group
convention, both no-room classes, the launcher's umask and the `direct`
launch — and each must fail the guards' unit suites or the evidence that can
run where it runs; the privileged half's NOT EXERCISED is never counted as a
kill. Measured: 26 of 26 killed, 25 by the unit suites and one -- the
launcher's umask -- by the real-container evidence; one
kill credited to the broker's suite was a flake of an M4d resource-count test
(`launches_leave_no_descriptor_or_thread_behind`) and was re-run against the
authority's own suite, which kills it. M5d.2's campaign, its three targets
moved to the code M5d.4 reshaped, still kills 52 of 52, M5d.3's 22 of 22,
net.http's 10 of 10 and D11's 26 of 26. The wire contract's own ownership and capacity judgements are proved by
`dwk-proto`'s unit tests, not by a mutant: the harness may not name that
module (TX016).

**As built (M5d.5).** `make sandbox-agent-evidence` runs an **agent-shaped
workload** the way a runtime runs one: a real DWKP client, the released
`dwkd-authority serve --sandbox-config` (an operator file naming `PROXY_ONLY`,
its relay by digest, four tunnels, 64 KiB up and 256 KiB down per
environment), the released broker and a real runtime. The workload is the
fixture's `workload-agent-net` -- a plan, two long-lived workers and a
daemonised helper -- and its network tool (`tests/sandbox/agent_net.py`) run
by the image's Python as a **stock HTTPS client that verifies its origin**
against the run's test anchor, which the workspace carries as an agent's own
trust would; the image is M5d.2's tools image with the pinned relay added (no
new dependency). The destinations are local HTTPS origins under a PKI made
for the run, named by the broker's evidence-only resolver -- fixtures, said
so; the production resolver has no exception (M5b). Every case names its
level and what enforced it, and a line without both fails the task. One
identity, any Linux host with a runtime, three tests, 50 cases, measured
locally on Docker Desktop 29.9.2 (WSL2): the route to a measured
`CONTAINER_ISOLATION`, `PROXY_ONLY` environment and no host launch; the
agent's processes all 10001:10001 inside and from the host, the relay's
10002; the granted origin answering `200` with the bytes it served, through
`urllib` honouring the proxy variable and through the tool's own CONNECT;
another host, another port and a granted name the address guard blocks
refused by the proxy (`TARGET_NOT_GRANTED`, `ADDRESS_BLOCKED`) with the
origin never contacted; six malformed CONNECTs refused by its parser
(`TARGET_NOT_CANONICAL`, `NOT_CONNECT`, `MALFORMED`); a mismatched and a
missing server name closed before anything is dialled; a certificate for
another name and one from an untrusted issuer refused by **the agent's own
verification** -- the workload's guarantee, not DireWolf's, and attributed
so; direct TCP to a public address and to the bridge gateway, UDP, DNS and
the C resolver finding no route (`ENETUNREACH`), the host's loopback origin
not the environment's (`ECONNREFUSED`), raw, packet and virtual sockets
`EPERM`; the proxy variables exactly the relay's, and the workload rewriting
them -- another host, another port, none -- finding no other path; writes
outside the workspace `EROFS` and no runtime socket or daemon path in the
environment; everything the agent left ended by `reap`, init alone after;
the tunnel limit (four of six, then `TUNNEL_LIMIT`), the upload budget
(65 536 of 65 536 bytes, spent staying spent), the download budget (under
256 KiB of 1 MiB asked), the wall clock (`TIMED_OUT`, reaped, the environment
kept clean) and the run's workload budget (`BUDGET_EXHAUSTED` before
anything is recorded); a broker lost mid-agent (`OUTCOME_UNKNOWN`, the
environment destroyed at the next start) and an authority lost mid-agent
(`UNKNOWN`, destroyed), and the same keys never running again; the grant in
the environment's intent record and the egress **counted by disposition**
in its destruction record -- the audit's whole account of the network:
counts at the end, never one event per refused attempt. **Three
identities**, only where `DW_AGENT_PRIVILEGED=1` provisions them (the
required hosted job `sandbox-agent`, a disposable runner; two tests, 25
cases, NOT EXERCISED locally, which fails the task): the authority as the
runner (A); the broker as `dwbroker` (B), in the runtime socket's group and
the workspace group and nothing else; the DWKP runtime as `dwruntime` (C),
its connection a relay of its own (`tests/authority/agent_runtime_client.py
relay`) so the kernel reports C to the authority; `nobody` as a stranger; a
64 MiB `tmpfs` workspace of group 10001, root `2770`, the authority's. Each
uid and group is read from the kernel, the workload's and the relay's from
the runtime's host; C admitted and A, B and the stranger refused by the peer
policy, audited; C read nothing from the broker's private channel; the
authority's store, audit, policy, operator file and a synthetic secret, the
runtime's socket and the workspace closed to C; no other identity reads a
daemon's `/proc` or signals it; the broker's start-up posture the production
one, and a broker told its authority is 10001 or 10002 refusing to serve;
the agent reaching its origin as C's run; what it wrote `0660` in group
10001 and read back by the broker for C (A09); and an authority and a broker
lost mid-agent, `UNKNOWN`, destroyed, never replayed. `make
sandbox-agent-mutations` weakens eleven guards one at a time -- the
authority's peer policy, the broker's peer check, a relay-uid authority, the
proxy's grant, server name and tunnel limit, a grant that is not HTTPS, a
launch judged as the host's, `reap`, the wall clock and the restart's
`UNKNOWN` -- each to fail a unit suite or the one-identity evidence.
Measured: 11 of 11 killed, nine by the guards' suites (the private channel's
stranger test among them) and two by the agent evidence -- `reap`, by the
agent's descendants left behind, and the wall clock, by the agent ended at
four times its own bound -- every file restored and its SHA-256 checked; the
three-identity half is never counted as a kill. The review tightened one
case first: the wall clock's bound was 120 s for a 10 s agent, loose enough
to let a fourfold clock through, and is now 10 to 35 s. No product code,
protocol, schema or dependency changed.

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
| **M5d.4** Workspace ownership and disk quota | §§6, 10 (OD-3, OD-6); as built also private protocol 11 (§3), probe report 3, every launch through the launcher (§5a, OD-12), the exclusion in time (§6), TX057–TX059 (§15) | the authority's tools and the workload both work on the workspace; a full disk refused, measured — **built; hosted CI green at `1c8ccbe` (run 39854518873); the owner's review of OD-3, OD-6 and OD-12 outstanding** |
| **M5d.5** The agent-shaped escape suite and multi-identity evidence | a long-lived agent-shaped workload in `PROXY_ONLY` with declared origins; the hosted three-identity job; as built (§17) `make sandbox-agent-evidence`, the required hosted job `sandbox-agent`, `make sandbox-agent-mutations` -- no protocol, schema, dependency or product-code change | ADR-0050 §21's uid-boundary condition shown with real users — **built; the one-identity half passing locally; the three-identity half hosted-only, awaiting the owner's commit and hosted CI; OD-5 for the owner** |
| **M5d.6** Closeout | run release destroys the environment; the gated eval `m5d-sandbox-exec`; this ADR accepted | every checkpoint's evidence in hosted CI |

### 19. Owner decisions

| # | Decision | Recommendation |
|---|---|---|
| OD-1 | Who chooses where `process.exec` runs | **the kernel**: a `READY` environment means sandbox, nothing means M4d's host floor; no runtime field, no fallback |
| OD-2 | A sandboxed executable's identity | **the operator's image manifest** (path → SHA-256) beside the image digest, proved from outside before every run; workspace scripts run only as arguments of a manifest executable |
| OD-3 | Workspace ownership | **(a) a workspace group** for V1; (c) copy-in/copy-out later where stronger isolation is wanted — **built in M5d.4 as (a)** (§6): the group 10001, the workload's own gid; a root of root or the authority, mode `2770`; nothing repaired; brokered changes excluded while a workload may write — for the owner to confirm |
| OD-4 | Modes B/C delivery | **the trusted launcher over the exec's stdin** — **built in M5d.3** (§7), with the consumer resolved against the image manifest (§7 item 2), for the owner to confirm |
| OD-5 | Concurrency and long-lived workloads | **one workload at a time per environment**; long-lived workloads with handles decided at M5d.5 — **recommended and built in M5d.5 (§17): no handle.** A long-lived agent is one bounded invocation (start, then collection, M5d.2) whose children and daemons live within its wall clock (at most 600 s) and are ended by `reap` when it returns; nothing outlives the invocation, no public operation names a running workload, and `process.status`/`kill` stay the host's. A client-visible persistent handle, or a workload that outlives one invocation, would need its own decision and evidence — for the owner to confirm, not approved |
| OD-6 | Disk quota | **an operator-provided bounded filesystem, measured by the probe**; refuse when unbounded — **built in M5d.4** (§10): measured by the authority and the probe, the mount's own root, within a quarter below the declared quota, again before every workload; `ENOSPC` changes nothing — for the owner to confirm |
| OD-7 | `local` | **not in M5d**; with M6, by its own ADR |
| OD-8 | Default budgets | per workload ≤ 600 s and 128 KiB per stream; per run 100 workloads and 3 600 s |
| OD-9 | What a concrete `process.exec:<path>` grant means for a run whose environment is a sandbox | **resolved against the image manifest** (path → the pinned digest) when the run is admitted with an execution environment configured, instead of the host's resolver; until then only `process.exec:*` covers a workload and policy narrows it — **built in M5d.2** (§2) |
| OD-10 | How a production authority gets an environment (M5d.2) | **the operator's file at start, the authority preparing a run's environment on its first permitted launch** (§2a); no runtime-facing lifecycle operation; preparation's bounded hold on the worker accepted as stated, or made a start/collection pair before M5d.6 — **approved by the owner, 2026-10-19, with conditions (below)** |
| OD-11 | How `workspace_exec_hygiene` is kept in an environment (M5d.2) | **the pinned probe as a trusted launcher**, the per-tool arguments first, undoing invocations and unevidenced tools refused (§5a); the residuals it does not reach stated, never claimed — **approved by the owner, 2026-10-19, with conditions (below)** |
| OD-12 | How a workload gets the workspace's umask (M5d.4) | **every launch through the pinned probe**, `DIRECT` included as the variable-free profile `direct`, every profile setting the umask `0007` before its `exec` (§5a); the target, its arguments, its identity, its descriptors and its standard input unchanged — **built in M5d.4; flagged for the owner's review, not approved** |

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

**M5d.4 (2026-10-20), awaiting the owner.** OD-3, OD-6 and OD-12 are built
as recommended and are **not** approved; nothing here presents them as
approved. The owner is asked to confirm: OD-3(a) with the workload's own gid
as the workspace group and the exclusion of brokered changes in time (§6);
OD-6 as an operator-provisioned filesystem of its own, measured from both
vantages, with the quarter's tolerance (§10); and OD-12, every launch through
the trusted launcher (§5a) — the one change to how a `DIRECT` workload is
started since M5d.2.

**M5d.5 (2026-10-23), awaiting the owner.** M5d.4's hosted CI passed at
`1c8ccbe` (run 39854518873); that verifies its evidence and approves none of
OD-3, OD-6 and OD-12, which still await the owner. M5d.5 asks the owner to
confirm OD-5 as built (§17): an agent is one bounded invocation with its
children, never a handle. M5d.5 changed no product code, protocol, schema or
dependency, so it needs no other decision; its evidence's own fixtures --
the broker's evidence-only resolver, the run's test anchor in the agent's
workspace, the unverified workspace of the one-identity half -- are labelled
as fixtures, and none is a production setting.

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
disk quota are not solved by M5d.1; M5d.4 solves them only for a workspace an
operator provisions as a filesystem of its own, of the group 10001, and
refuses every other — the operator now has a filesystem to make per
workspace, and a brokered change waits while a workload runs in its
workspace (`SHARED_DIRECTORY`). M5d.2's preparation holds the
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
