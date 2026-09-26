# ADR-0045: M4d — process execution: the executable the authority hashed, executed from the descriptor the broker re-proved, and no production launch until approvals exist

**Status:** Accepted · **Date:** 2026-09-26 · **Amends:** [ADR-0018](0018-authority-broker-split.md) (the broker now starts processes, from a descriptor, and supervises them), [ADR-0036](0036-m3-authority-operations-and-the-capability-wire-form.md) (`ToolInvoke` and `CanonicalPreview` get a version 3: the eight filesystem tools and three process tools as one closed sum), [ADR-0039](0039-durable-authority-state.md) (schema version 5: the process ledger), [ADR-0043](0043-m4b-private-broker-channel-and-brokered-fs-read.md) and [ADR-0044](0044-m4c-filesystem-operations-plans-and-atomic-mutation.md) (private protocol version 3; the broker's blast radius now includes executing what it is handed) · **Refines:** [ADR-0005](0005-tool-system.md) (the process tools and their retry classes), [ADR-0037](0037-capability-specifications-and-canonical-authority-identities.md) (an executable scope is a canonical path and a digest), [ADR-0042](0042-m4a-canonical-filesystem-resolution.md) (the working directory is a resolved workspace directory)

> **The object executed is the object the authority resolved and hashed: the
> broker re-proves the descriptor the authority opened and hands it to
> `execveat(fd, "", AT_EMPTY_PATH)` — no path, no `PATH` search, no shell, no
> `/proc/self/fd`.** Every process M4d can start runs on the host with the
> broker's privileges, so the kernel launches one only when the operator opted
> in **and** a per-invocation approval exists. Approvals are M6's: **no
> production build of M4d launches anything.** What M4d ships is the whole
> machinery behind that floor — the resolver, the plan, both gates, the durable
> intent, the private operations, the helper, the supervisor — proven against
> real targets through the broker and against a fake broker through the
> authority, and labelled as which.

## Context

M4 is five parts (ADR-0042 §1): canonical resolution (M4a), the private
channel and `fs.read` (M4b), the filesystem tools (M4c), **process execution
(M4d)**, secrets (M4e). [TOOL_SYSTEM.md](../TOOL_SYSTEM.md) §3 lists
`process.exec`, `process.status` and `process.kill`;
[CAPABILITIES.md](../CAPABILITIES.md) §2 defines the `process` verbs `exec`,
`inspect` and `signal`; [SANDBOX.md](../SANDBOX.md) §4 says there is no
execution environment before M5. M4d therefore decides what a host launch is,
and makes sure none happens without an approval nobody can yet give.

The M4d work was reviewed at four checkpoints before the broker was written:
whether the checked object is the executed object (§9), what makes a digest
worth pinning (§5), whether `workspace_exec_hygiene` can be enforced on the
host (§11), and what an output bound means (§14). Their answers are recorded
where they apply.

## Decision

### 1. Scope

Three tools: `process.exec` (launch one native executable), `process.status`
(observe one this run launched) and `process.kill` (SIGKILL it and its process
group). Three capability verbs: `process.exec`, `process.inspect`,
`process.signal`. **Excluded:** a shell, a `PATH` search, scripts, a pty or
interactive stdin, environment variables chosen by the runtime, secrets (M4e),
the sandbox and network isolation (M5), approvals (M6), streaming output or
waiting (a status is a snapshot), `QueryInvocationStatus` (M9), signals other
than SIGKILL, any process the run did not launch, and any platform but Linux
(§24).

### 2. The production floor, and the four kinds of evidence

Every process M4d can start runs on the host (no execution environment until
M5), so the kernel performs a host `process.exec` only if **both** hold,
whatever policy says:

1. the operator opted in (`--allow-host-execution`; policy's
   `security.allow_host_execution`) — otherwise `HOST_EXECUTION_DISABLED`;
2. a **per-invocation approval** exists — otherwise `APPROVAL_REQUIRED`.

No approval can exist before M6. There is no flag, feature, configuration key
or environment variable that supplies one, and no automatic approval. **Public
`process.exec` is therefore unreachable in every production build**: it is
resolved, planned, decided, audited and refused; `process.status` and
`process.kill` can only name a process a launch recorded, which production
never records. The one approval stand-in is `#[cfg(test)]`, inside the
authority's unit tests.

The evidence is labelled by what it runs, and never counted as more:

| | what | runs a process? |
|---|---|---|
| **A** production floor | the released daemons end to end: every shipped profile refuses, zero broker connections, no rows (`tests/process_production.rs`) | no — that is the claim |
| **B** hygiene override | the real `git` and `python3` undoing the environment form of `workspace_exec_hygiene` (§11) | yes, by the harness, not by DireWolf |
| **C** real broker | the broker's process module and helper starting real targets — re-proof, races, output, kill, table (`src/process/tests.rs`); the real broker binary over its socket (`tests/private_protocol.rs`); three identities on hosted CI (`tests/process_foreign.rs`, §22) | **yes** |
| **D** fake broker | the authority's state machine after the floor — durable order, idempotency, `UNKNOWN`, lookups, crash windows — against an in-process fake (`src/state/process/tests.rs`) | **no**, and it says so |

### 3. The order, and the decision

The same shape as the filesystem tools (ADR-0044 §4):

```text
1 (tx)    locate: fence, run, key; the call's bounds; for a launch the run's
          root binding; for status/kill the run's own process and its STORED
          identity (read by grammar, never looked up)
2 (none)  a launch only: resolve the executable (§5) and the working
          directory beneath the pinned root (§7)
3 (tx)    decide: the plan, both gates, the obligations, the host floor.
          Preview or denial: record and stop. Otherwise the invocation id,
          for a launch the process id and its LAUNCHING row, the key -- the
          INTENT; COMMIT, fsync
4 (none)  a launch only: the executable opened O_RDONLY by its one name and
          proved to be the object hashed; the working directory likewise
5         the broker: one authorisation
6 (tx)    the outcome, the process's recorded state, a status's taint;
          COMMIT, fsync; answer
```

A denial's reason is chosen in a fixed order: an unevaluable policy input
(`UNRESOLVED_POLICY_INPUT`), the opt-in (`HOST_EXECUTION_DISABLED`), policy
(`DENIED_BY_RULE`, `DEFAULT_DENY`), the capability (`NO_CAPABILITY`), the
obligations (`OBLIGATION_UNENFORCEABLE`), the approval (`APPROVAL_REQUIRED`).
A preview performs steps 1–3 and records the plan; it contacts no broker and
writes no process row.

### 4. Public protocol version 3

`direwolf.tool.invoke` and `direwolf.tool.preview` gain a version 3, registered
beside versions 1 and 2, which are kept exactly. A call is exactly one of
eleven typed members — the eight filesystem calls of version 2 and
`process_exec`, `process_status`, `process_kill`; a version-2 decoder never
sees a process call.

* `process_exec`: `executable` (an absolute host path), `args` (after
  `argv[0]`), optional `cwd` (a workspace path; the root when absent).
* `process_status`, `process_kill`: `process_id` — the opaque id a launch
  returned (a UUID the authority minted), never a pid.
* A plan action for a process carries: verb, the executable identity (path and
  digest), for a launch the working directory, `arg_count`, the argv digest
  and its classification (`SAFE`/`REINTERPRETING`), for status/kill the
  process id; the gates; the effect; the reason.
* Results: a launch returns the process id and `RUNNING`; a status returns
  the state (`RUNNING`, `EXITED`, `SIGNALED`, `UNOBSERVABLE`), exit code or
  signal, `timed_out`, and each stream's retained bytes, observed count and
  `truncated`; a kill returns `SIGNALED` or `ALREADY_EXITED`.

The request carries nothing the authority decides: no capability, no digest,
no `argv[0]`, no environment, no argv classification, no raw pid. New refusal
reasons (`EXECUTABLE_*`, `SCRIPT_UNSUPPORTED`, `NOT_NATIVE_EXECUTABLE`,
`EXECUTABLE_RACE`, `ARGV_TOO_LARGE`, `UNKNOWN_PROCESS`), failure reasons
(`EXECUTABLE_CHANGED`, `EXEC_FAILED`, `PROCESS_TABLE_FULL`,
`BROKER_ENVIRONMENT_UNSAFE`, `PROCESS_UNOBSERVABLE`) and decision reasons
(`HOST_EXECUTION_DISABLED`, `APPROVAL_REQUIRED`) are version 3's only.
[DWKP_OPERATIONS.md](../DWKP_OPERATIONS.md) holds the ADR-0029 argument: this
is a new version of an existing operation, not a new operation, and not a
second path from cognition to effect — the runtime proposes; the authority
resolves, decides, records; the broker executes only what it was handed.

### 5. The executable resolver, identity and the byte-stability contract

`resource::exec` turns an absolute host path into an `ExecutableIdentity` —
the canonical path of the object found, and the SHA-256 of the bytes it held
when hashed through the descriptor that was checked. It is the only code that
mints one (TX024; the constructor is `pub(in crate::resource)`).

* **Absolute paths only; no `PATH` search, ever.** `git`, `./git`, the empty
  string, `..`, `//`, a trailing `/`: `EXECUTABLE_PATH_INVALID`. One spelling
  per path, at most 4096 bytes.
* **Symlinks are followed, at most 32 (`MAX_SYMLINKS`, stricter than the
  kernel's 40), to the final object** — one component at a time, by
  `openat(O_PATH | O_NOFOLLOW)` relative to held descriptors and
  `readlinkat` — then the canonical components are re-walked from `/`
  following nothing, to prove the canonical path binds the object hashed.
  Mount crossings are allowed (an executable lives where the host installed
  it); what one could hide is refused by filesystem type instead. Policy and
  capabilities compare the identity, never the spelling.
* **Multicall and hard links.** `argv[0]` is the canonical path (§7), so a
  multi-call binary that dispatches on the name of a symlink it was invoked
  through (busybox applets as symlinks, `clang++`) sees its own canonical
  name. A hard link is its own canonical path and keeps its name.
* **Kind.** A directory, FIFO, socket or device: `EXECUTABLE_NOT_REGULAR`; no
  execute bit: `EXECUTABLE_NOT_EXECUTABLE`; larger than 512 MiB:
  `EXECUTABLE_TOO_LARGE`; `#!`: `SCRIPT_UNSUPPORTED` (a script is its
  interpreter's argument, which §8 classifies — never supported by
  launching the script); not ELF: `NOT_NATIVE_EXECUTABLE`.
* **The byte-stability contract.** A digest is worth pinning only if no other
  principal can change the bytes behind it — the kernel does not freeze an
  inode an executor holds open. So the file's owner is root or the
  authority's uid, and neither group nor others may write it (an ACL's mask
  shows in the group bits); every directory on the canonical path is owned by
  root or the authority and not group/other-writable unless sticky; no
  set-user-ID or set-group-ID bit and no `security.capability`; not on NFS,
  SMB/CIFS, 9P, FUSE, AFS, Ceph, Coda, procfs or sysfs. Anything else:
  `EXECUTABLE_UNTRUSTED`. A file owned by the broker's or the runtime's uid is
  refused; root-owned `/usr/bin/*` resolves.
* **Residual trust.** Root and the authority's own uid can still change the
  bytes. The broker re-hashes the very descriptor it will execute (§9), so a
  change before that is refused; a change by root or the authority between the
  broker's hash and `execveat` is not detected (after `execveat`, writes fail
  `ETXTBSY`). This is stated, not closed.
* **Dynamic linking.** The identity is the executable file's. The loader
  (`PT_INTERP`) and shared libraries (`DT_NEEDED`) are resolved by the loader
  from its own search path at exec time; they are not hashed, and their
  integrity is the host's. A static executable is wholly covered.

### 6. Capabilities and the tool mapping

| tool | verb | scope | retry class |
|---|---|---|---|
| `process.exec` | `process.exec` | the executable identity | `NON_RETRYABLE` |
| `process.status` | `process.inspect` | the identity the process was launched as | `RETRY_SAFE` |
| `process.kill` | `process.signal` | the identity the process was launched as | `NON_RETRYABLE` |

A new declaration naming a concrete executable is resolved and hashed at
admission; a stored grant, and a launched process's identity, are re-read by
grammar alone (`stored_executable_identity`, one module: §21). A grant whose
digest no longer matches the file is not a grant for it (`NO_CAPABILITY`).

### 7. Working directory and argv

* **cwd** is a workspace path resolved beneath the run's pinned root by the
  M4a resolver as an existing directory, opened and proved in step 4, and
  handed over as a descriptor; the helper `fchdir`s to it.
* **`argv[0]` is the canonical path** of the resolved executable — the
  authority constructs it; the runtime cannot.
* **Bounds:** at most 128 arguments after `argv[0]`, each at most 8192 bytes,
  at most 65 536 bytes in all (`ARGV_TOO_LARGE`); no NUL. Every argument is
  passed as exactly its bytes: shell text is data.
* **The argv digest** (`state/digest.rs`) is the SHA-256 of the canonical
  argv — `argv[0]` and every argument, length-prefixed — which an approval
  will bind (M6).
* **`argv_allowlist`** constrains `process.exec`: the first argument is the
  selector. A grant with an allowlist covers an invocation only if it lists
  that selector exactly (token equality, not substring or prefix); an
  invocation with no argument, or whose first argument is not a token, needs
  an unconstrained grant.

### 8. `argv_safe`: the classifier

`resource::exec::argv` classifies an argv as `SAFE` or `REINTERPRETING` —
whether what runs it would treat an argument as code. It is the kernel's
classification, never the runtime's; policy matches it with
`when.argv_safe`. Four rules, first match: the executable is an interpreter or
shell by its canonical name (`python3.14`, `bash`, `node`, `make`…); a runner
(`env`, `xargs`, `timeout`, `sudo`, `ssh`, `busybox`…); an exec-style option
where it stands (`find -exec`, `tar --to-command`, `rsync -e`, `gcc -B`,
`git -c`/`--upload-pack`/aliases/external subcommands, `cargo` external
subcommands and `+toolchain`, `npm run`); or an argument naming a shell or
runner. It is conservative and incomplete by construction: `SAFE` means no
rule fired, not that the program is harmless.

### 9. The launch contract: descriptors, re-proof, descriptor-bound exec

`broker.process_start` carries exactly **two** descriptors, in order: the
executable (`O_RDONLY`, a regular file) and the working directory
(`O_RDONLY`, a directory) — never `O_PATH`. Any other count, order or kind is
refused before anything runs. Immediately before starting the helper the broker
re-proves, **through the descriptor it will execute**: each descriptor's mode,
kind and `(st_dev, st_ino)` against the authorisation; the byte-stability
contract (§5); the ELF magic; the SHA-256, read by `pread` with size, mtime
and ctime unchanged across the read (`DIGEST_MISMATCH`,
`EXECUTABLE_UNTRUSTED`).

The helper executes with **`execveat(executable_fd, "", argv, envp,
AT_EMPTY_PATH)`** — `nix::unistd::execveat`, a safe function over the raw
`SYS_execveat` system call. There is no path walk between the proof and the
exec: **`/proc/self/fd` is not used to execute** (glibc's `fexecve` falls
back to it; this does not call glibc's). A path replaced, renamed, deleted,
rewritten or chmodded after the hand-off does not change what runs (race
evidence R1–R9). The broker reads `/proc/self/fd` only to list its own
descriptors (§12).

### 10. Environment

The target's environment is built from nothing: `HOME=/nonexistent`,
`LANG=C.UTF-8`,
`PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin` — the
`BASE` profile, fixed in `dwk-proto`. The helper is spawned with
`env_clear()`; nothing of the broker's or the authority's environment is
inherited, and the runtime cannot add a variable. No secret reaches a target
(M4e owns secret injection).

### 11. What the host cannot enforce

* **`workspace_exec_hygiene` is unenforceable in M4d**, and an action carrying
  it is denied `OBLIGATION_UNENFORCEABLE`. Its only host-side means is the
  environment (`GIT_CONFIG_NOSYSTEM`, `GIT_CONFIG_GLOBAL=/dev/null`,
  `GIT_CONFIG_COUNT=0`, `PYTHONSAFEPATH`, `PYTHONNOUSERSITE`,
  `npm_config_ignore_scripts`, `CARGO_NET_OFFLINE`…), and the real tools undo
  it: a repository's own `.git/hooks/pre-commit` runs whatever the
  environment says; `git -c alias.x='!cmd'` runs a command with
  `GIT_CONFIG_COUNT=0`; `python3 -c "import sys; sys.path.insert(0, '')"`
  restores what `PYTHONSAFEPATH` removed (evidence B,
  `tests/hygiene_override.rs`). `npm --ignore-scripts=false` and
  `cargo --config net.offline=false` override their variables by those tools'
  documented precedence (command line over environment); `conftest.py` and
  `build.rs` are workspace content no variable reaches. Setting the variables
  would claim a neutralisation the host cannot deliver. The `hygiene` profile
  was removed from the private protocol and the schema.
* **`network_deny`**, `force_environment`, `read_only_workspace` and every
  other obligation that needs an execution environment (M5) or an approval
  (M6): unenforceable, so denied.

### 12. The launch helper

The helper is the broker's own binary, `dwkd-broker exec-helper`, spawned by
`std::process::Command` (the only `Command` in the broker, TX021) with
`env_clear()`, stdin `/dev/null`, stdout the stdout pipe's write end, stderr
the helper's end of a control socket, and `process_group(0)` — its own process
group. No `pre_exec`, no `fork`, no `unsafe` (`unsafe_code = "forbid"`,
workspace-wide, unchanged).

The broker sends the launch on the control socket: argv, envp and a crash flag
(`DWXH1`), with the executable, the working directory and the stderr pipe's
write end by `SCM_RIGHTS`. The helper, in order: checks the peer is its parent
and the broker's uid; `dup2`s the stderr pipe over stderr; applies resource
limits, soft = hard — `RLIMIT_NOFILE` 1024, `RLIMIT_CORE` 0, `RLIMIT_FSIZE`
1 GiB, `RLIMIT_CPU` 600 s, `RLIMIT_AS` 16 GiB (`RLIMIT_NPROC` is deliberately
absent: it counts every process of the broker's uid, so it would starve
unrelated processes or bound nothing — `pids.max` is M5's); `fchdir`s; arms
`PR_SET_PDEATHSIG = SIGKILL` and re-checks its parent; sets `no_new_privs`;
lists its own descriptors (`/proc/self/fd`, `fdinfo`) and refuses if any
descriptor ≥ 3 lacks `FD_CLOEXEC` (the target receives exactly 0, 1 and 2);
writes `X`; `execveat`s. A failure writes `F`, the stage and the errno, and
exits 127. Invoked any other way the helper exits 2 and does nothing.

**The exec handshake.** The control socket is close-on-exec. `X` then end of
file with no failure record **is** the exec; an `F` record is a refusal at a
stage (`EXEC_SETUP_FAILED`, or `EXEC_FAILED` for `execveat` itself, e.g.
`ENOEXEC`); end of file with nothing, or no `X` within 5 s, is
`EXEC_SETUP_FAILED`; `X` followed by anything irregular is
`LAUNCH_UNCONFIRMED` — indeterminate, recorded `UNKNOWN`. Between `X` and
`execveat` lies a window of a few instructions: a SIGKILL landing exactly there
(from root or the broker's own uid) would read as an exec.

Before spawning, the broker checks its own descriptor table the same way; a
broker holding an inheritable descriptor launches nothing
(`INHERITED_DESCRIPTOR` → `BROKER_ENVIRONMENT_UNSAFE`): it cannot close one
without `unsafe`, so it refuses instead of leaking it.

### 13. Supervision

* **pidfd.** Right after the handshake the broker opens a pidfd for the child
  (`pidfd_open`), before it could be reaped, so no signal or wait ever names a
  pid that might have been reused.
* **Output.** Two threads drain stdout and stderr concurrently to end of file:
  the first `stream_limit` bytes of each are kept, every byte is counted, and
  draining never stops, so a target is never blocked on a full pipe (12 MiB on
  both streams at once, into 1 KiB bounds, exits 0). Output enters the answer
  hex-encoded with `observed` and `truncated`; it never enters the audit
  record (counts only), and a status with output taints the run
  `LOCAL_UNVERIFIED`.
* **Reaping.** A reaper polls `waitid(P_PIDFD, WEXITED | WNOHANG | WNOWAIT)`
  every 10 ms; when the leader exits it kills the process group while the
  leader is still unreaped (so the group id cannot be reused), then reaps.
* **Wall clock.** 600 s (`PROCESS_WALL_CLOCK_SECONDS`), after which the group
  is SIGKILLed and `timed_out` set. A test-only constructor shortens it; no
  production path can.
* **Kill.** Under the entry's lock: if unreaped and not exited,
  `pidfd_send_signal(SIGKILL)` and `kill(-pgid, SIGKILL)` → `SIGNALED`;
  otherwise `ALREADY_EXITED`. A signal whose delivery is uncertain is
  `SIGNAL_UNCONFIRMED` → `UNKNOWN`.
* **Descendants.** A descendant that left the process group (`setsid`,
  `setpgid`) or was reparented escapes both the group kill and the wall clock:
  the host has no containment for it before M5's cgroup. Stated, not closed.
* **The table** is in memory, at most 8 entries; a launch into a table of 8
  running processes is `PROCESS_TABLE_FULL`; an ended entry is evicted oldest
  first. A handle is `(process_id, generation)`: an unknown id is
  `UNKNOWN_PROCESS`, an id already present `PROCESS_ID_IN_USE`.

### 14. Obligations that are kept, and the output bound

| obligation | `process.exec` | `process.status` | `process.kill` |
|---|---|---|---|
| `max_output_bytes=N` | each stream keeps its first ⌊N/2⌋ bytes, never more than 128 KiB per stream; `N < 2` is unenforceable | kept iff the launch's bound is within `N` | kept (no output) |
| `audit_level=full` | kept | kept | kept |
| anything else | unenforceable (§11) | unenforceable | unenforceable |

`max_output_bytes` is the **combined** stdout+stderr bound. A profile that
allows more than 256 KiB (POWER's 4 MiB) is narrowed to 256 KiB combined:
safe, because a bound is a maximum, and stated.

### 15. Restarts

* **The broker.** A restarted broker is a new **generation** (128 bits from
  the operating system's random source). Its predecessor's targets received
  the parent-death signal when it died; the new one holds none of them, and a
  handle naming another generation is refused `STALE_GENERATION` — never
  matched to a pid. The authority records such a process `UNOBSERVABLE`.
* **The authority.** A launch whose intent is recorded but whose outcome is
  not is `UNKNOWN` after a restart and is never sent again; a process
  recorded `RUNNING` keeps its record, and a later status learns from the
  broker whether its generation still supervises it.

### 16. Durable state: schema version 5

`kernel.db` schema 5 adds `process_invocation` (every process tool
invocation: tool, retry class, process id, state `INTENT` → `COMPLETED` /
`FAILED` / `UNKNOWN` / `INTERRUPTED`), `tool_process` (every launch: the
identity, device and inode, cwd, arg count, argv digest and class,
environment — `CHECK (environment = 'BASE')` —, stream limit, generation,
state `LAUNCHING` → `RUNNING` / `EXITED` / `SIGNALED` / `FAILED` / `UNKNOWN` /
`UNOBSERVABLE`), and `process_idempotency` (subject, session, key, request
digest, invocation). **The intent — the invocation and, for a launch, its
`LAUNCHING` row — is committed and its audit record fsynced before any
descriptor that could launch exists**, and the outcome before the answer. A
key names one invocation for ever: any reuse — the same request or not — is
refused `IDEMPOTENCY_KEY_REUSED` before anything is resolved, and performs
nothing, so a runtime's retry can never repeat a launch or a kill.

### 17. Failure, `UNKNOWN` and the crash campaign

An effect whose outcome is not proved is `UNKNOWN`, and nothing performs it
again — a launch or a kill is never retried by the authority. A launch that
is `UNKNOWN` has no process a status or a kill may name
(`UNKNOWN_PROCESS`): nobody knows what, if anything, it started. A launch
refused before the target ran (`EXEC_SETUP_FAILED`, `EXEC_FAILED`, a
re-proof refusal) is `FAILED`. A status is retry-safe: an interrupted one is
`INTERRUPTED`, a lost one `FAILED`. The campaign (evidence D, and the broker's
own crash points in evidence C) covers E1–E8 (launch: before and after the
intent, the broker accepting then being lost, the helper created, before the
target's exec, the handshake lost, the result before the outcome, the outcome
before the answer), K1–K6 (kill) and S1–S3 (status).

### 18. Private protocol version 3

Version 3 only (the daemons ship together; 1 and 2 are refused). New kinds
`broker.process_start` (two descriptors, §9), `broker.process_status` and
`broker.process_kill` (none). The authorisation carries the invocation, the
process id, the identity (path, digest, device, inode), the cwd's identity,
argv, the environment profile and the per-stream limit; status and kill carry
the process id and the generation. New refusals: `DIGEST_MISMATCH`,
`EXECUTABLE_UNTRUSTED`, `EXEC_SETUP_FAILED`, `EXEC_FAILED`,
`INHERITED_DESCRIPTOR`, `PROCESS_TABLE_FULL`, `PROCESS_ID_IN_USE`,
`UNKNOWN_PROCESS`, `STALE_GENERATION`; indeterminates `LAUNCH_UNCONFIRMED`,
`SIGNAL_UNCONFIRMED`. The runtime and the CLI cannot name any of it, nor the
helper's mode (TX016).

### 19. What stays unresolved

`fs.exec_bit` stays `UNRESOLVED_RESOURCE`: changing a file's mode is not a
process operation, and M4d does not decide it.

### 20. Dependencies and the TCB

**The authority's closure is unchanged** (the same crates; ADR-0019 is not
amended). **The broker's closure grows by** `nix` 0.31.3 (pinned `=`, default
features off, `process` and `fs`: `execveat` and `dup2_stderr` only, TX023),
`libc` 0.2.189 (bindings, no C; already in the workspace lock, new to the
broker) and `cfg_aliases` 0.2.2 (a build dependency of `nix`). `cfg-if` was
already there. Build scripts: `nix` and `libc` each emit `cfg`s; no
proc-macro, no native code compiled. Both contain `unsafe` internally (FFI);
DireWolf's own code has none. `rustix` 1.1.5 gains the `process` and `thread`
features in the broker's manifest (before: `fs`, `net`, `std`, `time`) — code,
no crates (`linux-raw-sys/prctl`). In a whole-workspace build Cargo unifies
those features into the one `rustix` the authority also links; the authority
names none of them (TX008, TX010), and a build of `dwkd-authority` alone does
not enable them.

### 21. The stored-identity reader

`stored_executable_identity` reads an identity the authority itself resolved
and wrote — a grant, a launched process — by grammar alone, with no lookup.
One module (`state/scopes.rs`) may name it (TX024); a new declaration or
request becomes an identity only through the resolver. The zero-lookup proof
counts resolver calls on the thread (evidence D: admission replay 0, stored
grant 0, a launch resolves).

### 22. Evidence and its gate

`make process-broker-evidence` runs every suite of §2 A–D, requires every
named case to print its `PROC-EVIDENCE` line, fails a suite that ran zero
tests, and then runs the three-identity test by name when `DW_BROKER_AS` and
`DW_PEER_AS` are set — the authority as the runner, the broker as its own
user, `nobody` as the hostile runtime, each proven by numeric uid first.
There the broker's uid executes a descriptor it cannot reach by name (the
path answers `EACCES` for it; after the path is replaced, the original runs),
and the runtime's uid reads nothing from the broker's socket or its helper.
Without the identities that half is `NOT EXERCISED` and the task fails. CI's
required job **process broker (make process-broker-evidence)** creates the
broker user and runs it; the `ci` aggregate requires it.

### 23. The M5 and M6 boundaries

**M5** owns the execution environment: namespaces, a cgroup (`pids.max`,
memory, a process tree the kill reaches entirely), network isolation, a
read-only workspace — everything §11 and §13 say the host cannot do. **M6**
owns approvals: when one exists, the floor of §2 passes for the invocation it
binds (executable identity and argv digest). Until then M4d's launch path is
reachable only by the test stand-in.

### 24. Platform contract

Linux only: `openat2`, `execveat`, pidfds (Linux 5.3+; `waitid(P_PIDFD)`
5.4+), `PR_SET_PDEATHSIG`. On every other platform the executable resolver
answers `UNSUPPORTED_PLATFORM`, nothing is launched, and no weaker fallback
exists; the protocol, schema and pure-state tests run everywhere.

### 25. Residual risks

A change to the executable by root or the authority's uid between the broker's
hash and `execveat` (§5); unhashed shared libraries and loader (§5); a SIGKILL
in the handshake's last window (§12); descendants that leave the group (§13);
a symlink-dispatching multicall binary seeing its canonical name (§5);
ambient host authority of the broker's uid for every launched target — the
reason no production launch exists before M5 and M6.

### 26. Explicit exclusions

The exclusions of §1; no shell, `pre_exec`, `fork`, manual FFI, libc exec or
`/proc/self/fd` exec (TX022); no environment inheritance; no automatic
approval and no production flag that stands in for one; no credentials or
secret handles; no signals but SIGKILL; no `RLIMIT_NPROC`; no cgroups; no
network isolation. **M4 is incomplete; M4e is next.**

## Consequences

**Security.** The executed object is the resolved, hashed, re-proved object —
by descriptor, with no path in between — and no production build executes at
all. Every step before the broker is durable; an unproved effect is `UNKNOWN`
and never repeated. The broker gains a new capability, execution, bounded by
what it is handed and by the identity it runs as.

**Negative.** The broker's uid is the target's uid: a launched process has the
broker's full host authority, which is why the floor exists. `nix` and `libc`
enter the broker's closure. Output is capped at 256 KiB combined and
POWER's larger bound is narrowed. Descendants can escape. Scripts are refused
rather than run through their interpreter. `workspace_exec_hygiene` and
`network_deny` deny rather than degrade. Linux only.

**Operational.** Nothing to configure: `--allow-host-execution` alone launches
nothing, by design. A broker started with an inheritable descriptor refuses
every launch until restarted cleanly.

## Alternatives considered

* **`fexecve` / `/proc/self/fd/<n>`.** Puts procfs — mounted or not, masked or
  not — between the proof and the exec, and glibc's `fexecve` falls back to it.
  Rejected for `execveat(AT_EMPTY_PATH)` through `nix`.
* **A `pre_exec` closure, or hand-rolled `fork`/`execve`.** Both need
  `unsafe`; the invariant forbids it. Rejected for a helper process.
* **Exec by path after hashing.** Executes whatever the name binds by then.
  Rejected.
* **Enforce `workspace_exec_hygiene` with environment variables.** Shown
  bypassable with the real tools (§11). Rejected: a false guarantee.
* **Run scripts through their interpreter.** Then the interpreter is the
  executable and the script its argument, which §8 already classifies —
  launching a script directly would hide that. Rejected.
* **`RLIMIT_NPROC`.** Per-uid, not per-target. Rejected for M5's `pids.max`.
* **A production approval stand-in, or allowing host execution on opt-in
  alone.** Would make DireWolf run model-chosen programs with the broker's
  authority before approvals and a sandbox exist. Rejected.

## Revisit if

M5 provides an execution environment (hygiene, network denial and descendant
containment become enforceable); M6 provides approvals (the floor opens for
approved invocations); Linux gains a way to execute a descriptor with the
file's bytes frozen; a non-Linux platform must launch processes; or more than
SIGKILL is needed.
