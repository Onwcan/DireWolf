# Sandbox and Filesystem Security

Covers the `ExecutionEnvironment` abstraction, the default OCI profile, filesystem containment, and honest per-platform assurance levels.

---

## 1. The interface

```rust
trait ExecutionEnvironment {
    fn id(&self) -> EnvironmentId;
    fn assurance(&self) -> AssuranceLevel;     // declared, surfaced to policy and to the user
    fn prepare(&self, spec: &EnvSpec) -> Result<EnvHandle>;
    fn spawn(&self, h: &EnvHandle, cmd: &CanonicalCommand, io: IoSpec) -> Result<ProcHandle>;
    fn signal(&self, p: &ProcHandle, sig: Signal) -> Result<()>;
    fn collect(&self, p: &ProcHandle) -> Result<ExecOutcome>;
    fn destroy(&self, h: EnvHandle) -> Result<()>;
}

enum AssuranceLevel { None, ProcessIsolation, ContainerIsolation, VmIsolation }
```

`assurance()` is a first-class, policy-visible value. A rule can say "this action requires at least `ContainerIsolation`," and an environment that cannot provide it is refused rather than silently accepted. This is how we keep isolation and authorization orthogonal instead of letting one disable the other.

**Declared is not enough (M5a, implemented — [ADR-0047](adr/0047-m5a-oci-execution-environment-and-measured-assurance.md)).** `assurance()` is what an environment *says* it provides. M5a adds a **measured** value, from two vantages: the container runtime's own record of the container, and a digest-pinned, read-only probe that runs inside each prepared environment and checks every hard rule of §2 — no container socket, not privileged, no shared host namespace, no added capability, the seccomp profile applied, a read-only root — each as PASS or FAIL. The effective assurance is the lower of declared and measured; a failed required invariant refuses the environment and is audited. There is deliberately **no weighted score**: a weighted sum lets one failed invariant be averaged away by several passing ones. `direwolf doctor --sandbox` reports the same measurement (M17). ([COMPETITIVE_ANALYSIS.md](COMPETITIVE_ANALYSIS.md) §17 G2.)

**As built in M5a** ([ADR-0047](adr/0047-m5a-oci-execution-environment-and-measured-assurance.md) §3). The broker's trait is `declared`, `prepare`, `measure`, `run_probe` (spawn-then-collect of the one program M5a runs in an environment: the probe), `destroy` and `list`; `ExecOutcome` distinguishes exited, killed, timed out, environment gone, runtime unavailable and `Unobservable`. `spawn`/`signal`/`collect` of an arbitrary workload are M5d's. The authority judges the level; the broker never does.

**As built in M5d.1** ([ADR-0052](adr/0052-m5d-sandboxed-process-exec.md) §§3–5, 8–10, 13). The trait gains `run_workload`: one bounded invocation, spawn then collect, of an executable named by its path in the image and pinned by the operator's manifest. Before it runs, the broker re-judges the recorded container from the runtime's record (every required `HOST_*` invariant but the workspace's identity, which the probe measured when the environment was prepared) and proves the executable's bytes, copied out of the container, against the pinned digest. It runs `container exec --user 10001:10001 --workdir /workspace` with exactly the workload's arguments — no shell, no added environment, no terminal, no standard input — bounds each stream and the wall clock, and then runs the probe's `reap`: the probe is the environment's init, reaps every orphan, and on `reap` signals every process but itself and init and waits until none remains. The client's return does not mean the environment is quiet (measured: it returns while a process the workload left holds its output open), and a deadline does not end an `exec`'d process (measured: the runtime keeps it), so `reap`, not the deadline, makes "gone" true. A residue `reap` does not prove clean, or an ending nothing proves, destroys the environment. Workloads are reachable only through an in-process authority API; the public `process.exec` reaching an environment is M5d.2's, the `local` environment M6's (ADR-0052 OD-7).

**As built in M5d.2** (ADR-0052 §§2, 2a, 3, 5a). `spawn` and `collect` are separate: the broker answers a start once the workload runs and keeps its ending until it is collected, at most 16 supervised and one per environment. The public `process.exec` (tool messages version 5) reaches the run's `READY` environment when the operator started the authority with `serve --sandbox-config`, and the authority prepares that environment itself on the run's first permitted launch — first destroying at most one environment that can never run again (an ended run's, or one of uncertain end), with at most 16 live — within the 120 s environment deadline; nothing a request says chooses or reaches the environment, and nothing falls back to the host.

**As built in M5d.3** (ADR-0052 §7). A launch may consume **one credential** (tool messages version 6, `credential_handle`): mode C on descriptor 3 or mode B in the operator's variable, chosen by the kernel, delivered by the pinned probe as a trusted launcher from a frame on the runtime client's standard input -- the one command line that attaches it -- after the broker judged the environment and proved the executable. The ordinary launch is unchanged and keeps standard input `/dev/null`. The credential is inherited by the program's descendants, all of them the environment's; no shipped pack allows `secret.use`.

**As built in M5d.4** (ADR-0052 §§6, 10; OD-3, OD-6 and OD-12 approved by the owner as built, 2026-10-26). The workspace is shared, not copied: its root is the root of a filesystem of its own that the operator provisions and declares (`[workspace] quota_bytes` in the file `serve --sandbox-config` reads), `nosuid,nodev`, of group 10001 — the workload's own gid, so nothing is added to its command line — mode `2770`, owned by root or the authority, with the authority and the broker in the group and nobody else. The authority (by its pinned root's descriptor) and the probe (from inside) measure it before an environment is prepared and before every workload: owner, group, mode, the authority's and the broker's membership, the mount's own root, and a capacity at most the quota and no more than a quarter below it; anything else is refused with its reason, or — found under a live environment — destroys it, and is never repaired. Every launch goes through the pinned probe (`launch direct`, or `hygiene` or a secret profile), which sets the umask `0007`, so what the workload makes is `0660`/`2770` and the broker's `0660`, all the group's. A brokered change of a name waits while a workload may be running in the same workspace (`SHARED_DIRECTORY`); a full filesystem changes nothing and fails `NO_SPACE`. The profile's `disk_quota` (below) is that filesystem, not an overlay; `fsize` still bounds one file. The evidence harness's `unverified_evidence = true` proves neither group nor bound and is served only by a broker started with `--allow-unverified-workspace`.

**As built in M5d.5** (ADR-0052 §§11, 13, 17; OD-5 — no handle — approved by the owner as built, 2026-10-26). Nothing in the sandbox changed; what is new is the evidence that the pieces hold together for an agent. A long-lived, multi-process, agent-shaped workload in a `PROXY_ONLY` environment, started through the public `process.exec` on the released `serve`, reaches **exactly** its run's granted HTTPS origins — with its own TLS client verifying them; the broker terminates no TLS and is given no trust anchor — and nothing else: every other destination, CONNECT form and server name is refused by the proxy, every path around the proxy finds no route in the namespace, and the workload's own proxy variables, rewritten, open nothing new. Long-lived means a bounded invocation: the agent's children and daemons live within its wall clock (at most 600 s) and `reap` ends them when it returns; there is no workload handle and nothing outlives the invocation (OD-5). The separation of the three host identities — the authority, the broker and the runtime client — and of the workload's 10001 and the relay's 10002 from all of them is measured on the hosted runner only, which alone has three users and a provisioned workspace. **Still assumed, not proved by any of this:** the OCI runtime and the host's root are trusted (containment is not a VM boundary); every member of group 10001 shares every workspace of that group; a credential a workload holds (modes B/C) reaches its whole process tree; an allowed origin receives whatever the workload chooses to send it.

### Implementations

| Implementation | Assurance | Status |
|---|---|---|
| `oci` (Docker/Podman) | `ContainerIsolation` | **V1 default** |
| `local` | `None` | V1, opt-in, loud |
| `ssh` | — | **Removed from the trait's design set.** |
| `microvm` (Firecracker / Kata / gVisor) | — | **Removed from the trait's design set.** |

> The trait is designed against `oci` and `local` **only**. Its signature — `spawn → ProcHandle`, `collect → ExecOutcome` — is shaped for local processes; a remote worker needs streaming, reconnection, partial results and a session surviving a kernel restart, and `microvm` needs multi-second async `prepare`. Designing for those now would produce an abstraction that gets rewritten the moment a second real implementation lands, which is the definition of one that bought nothing. **We will rewrite the trait when remote execution is real**, and that is cheaper than guessing.
>
> `AssuranceLevel::VmIsolation` remains as an enum variant (harmless, and policy can already express a requirement for it). `collect` returns a distinct `Unobservable` variant, separate from "process exited", so a container-runtime restart is never mistaken for a completed process.

## 2. Default OCI profile (`oci-strict`)

```yaml
image:            direwolf/sandbox-base:<pinned-digest>   # digest, never a tag
user:             10001:10001                              # non-root, no host-uid overlap
read_only_root:   true
workdir:          /workspace
mounts:
  - { source: <workspace>, target: /workspace, mode: rw,  nosuid: true, nodev: true }
  - { type: tmpfs, target: /tmp,     size: 512Mi, nosuid: true, nodev: true, noexec: false }
  - { type: tmpfs, target: /var/tmp, size: 128Mi, nosuid: true, nodev: true, noexec: true }
network:          PROXY_ONLY      # isolated netns; veth; NO default route; NO resolver;
                                  # exactly one reachable peer: 169.254.7.1:8080 (broker CONNECT proxy)
cap_drop:         [ALL]
cap_add:          []              # empty. Not DAC_OVERRIDE, not CHOWN, not FOWNER.
no_new_privileges: true
seccomp:          direwolf-default.json    # stricter than the runtime default; see §3
apparmor/selinux: enforced where available
pids_limit:       256
memory:           2Gi
memory_swap:      2Gi             # == memory, i.e. swap disabled
cpus:             2.0
ulimits:          { nofile: 1024, nproc: 256, fsize: 1Gi, core: 0 }
disk_quota:       5Gi             # workspace overlay
timeout:          600s            # wall clock, enforced by the supervisor, not the container
oom_score_adj:    500
device_cgroup:    deny-all except /dev/null,zero,random,urandom,tty
ipc:              private
uts:              private
userns:           remap           # Linux: user namespace remapping where available
```

**As built in M5a** ([ADR-0047](adr/0047-m5a-oci-execution-environment-and-measured-assurance.md) §5): every line above, with these differences stated rather than implied. `network` is `NO_NETWORK` (the evidence harness's topology, only with the broker's `--allow-evidence-topology`) or, since M5b, `PROXY_ONLY` ([ADR-0048](adr/0048-m5b-proxy-only-topology-and-connect-proxy.md): the same interface-free namespace, `169.254.7.1/32` added to its loopback by a one-shot setup container, and an unprivileged relay as its only peer; the environment's proxy variables are exactly the broker's). The device set also admits `/dev/full` and `/dev/ptmx` (the runtime's defaults), and nothing else. The workspace bind carries no `nosuid,nodev` as mount flags — the runtime has none for binds — and `no_new_privileges`, `cap_drop: ALL` (no `mknod`) and the device cgroup deliver what they would. `disk_quota`, the 600 s workload `timeout` and `userns: remap` concern workloads and are M5d's; AppArmor/SELinux labels are the runtime's default where it has them, not a required invariant.

### Hard rules — no configuration option exists to violate these

1. **The container socket is never mounted.** `/var/run/docker.sock` and equivalents are denied by policy and refused by the supervisor. Mounting it is equivalent to granting root on the host.
2. **`--privileged` is never used.** No code path emits it.
3. **No host PID, network or IPC namespace sharing.**
4. **No capability is added back.** Notably we do **not** retain `DAC_OVERRIDE`/`CHOWN`/`FOWNER`, which some comparable systems keep for convenience: `DAC_OVERRIDE` defeats file-permission containment *inside* the sandbox, which is where we put the workspace.
5. **Images are pinned by digest**, verified against a recorded hash, and never pulled implicitly mid-run.
6. **One container per run by default.** Not one shared persistent container: a shared container is a cross-session contamination channel and lets a compromised earlier run leave a payload for a later one. Reuse is opt-in per-workspace and never across agents.

### Seccomp

DireWolf's own **allowlist**, stricter than a runtime's default deny-list: default action `EPERM`, native architectures only, and refused among others: `ptrace`, `process_vm_readv/writev`, `kcmp`, `perf_event_open`, `bpf`, `userfaultfd`, `keyctl`/`add_key`/`request_key`, `mount`/`umount2`/`pivot_root`, `unshare`/`setns`, `clone` with namespace flags (`clone3` answers `ENOSYS` so the C library falls back to an inspectable `clone`), `io_uring_setup`, and `socket(AF_VSOCK)` — a virtual socket reaches the hypervisor host and a network namespace does not confine it. `io_uring` is blocked because it has repeatedly been a sandbox-escape surface and almost nothing an agent runs needs it. Ordinary child processes and threads still work, and are shown to. Which denials are active attempts and which are measured from the profile's content is stated in [ADR-0047](adr/0047-m5a-oci-execution-environment-and-measured-assurance.md) §7.

Deviations from the profile are recorded in the audit log and shown by `direwolf doctor`.

## 3. Filesystem security

### The core decision: identity, not strings

Every filesystem operation resolves to a **file descriptor obtained under a pinned root**, and policy matches on `(device, inode)`, not on a path string.

```
1. Check:      already NFC (refused, never normalised), no NUL, valid UTF-8,
               no bidi/format control chars (U+202A–U+202E, U+2066–U+2069, U+200B–U+200F)
2. Open root:  workspace root fd, proved to be the directory the operator bound
3. Resolve:    openat2(root_fd, rel, { RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS
                                     | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV })
4. Identify:   fstat -> (dev, ino)
5. Policy:     match on identity
6. Operate:    on the SAME fd. Never re-open by path.
```

Step 6 is what actually closes TOCTOU. Re-opening by path between the check and the operation reintroduces every race the resolution just eliminated.

**As built in M4a** ([ADR-0042](adr/0042-m4a-canonical-filesystem-resolution.md)): steps 1–4 are the authority's resolver. The root's identity is recorded when the operator binds it to a workspace, and every pin re-proves it, so a directory put in its place is refused rather than followed. Each component is opened relative to the previous descriptor, its name is verified against its directory — spelled exactly as on disk, with no canonically equivalent twin beside it — and the chain is re-verified after the walk. Step 6 is M4b's, on the checked descriptor.

**Platform fallbacks.** `openat2` requires Linux 5.6+. **M4a implements no fallback**: on older Linux, macOS and Windows every resolution is refused as unsupported ([ADR-0042](adr/0042-m4a-canonical-filesystem-resolution.md) §5). The intended fallback — a manual component-wise walk with `O_NOFOLLOW` at each step plus `fstat` verification, slower and slightly weaker — needs its own ADR and evidence before it exists; when it does, it is reported by `direwolf doctor` and recorded in the environment's assurance metadata rather than being silently equivalent.

### Attacks and defences

| Attack | Defence |
|---|---|
| `../../../etc/passwd` | `RESOLVE_BENEATH`; resolution never escapes the root fd |
| Symlink to `/etc/shadow` | `RESOLVE_NO_SYMLINKS` for policy-relevant resolution |
| Symlink swapped between check and use | Operate on the fd, never re-resolve |
| Hardlink to a file outside the workspace | Not a symlink, so no `RESOLVE_*` flag applies. Cross-device hardlinks are impossible; a same-device one is **read** through its inside name (refusing every multiply-linked file would break pnpm, `git clone --local` and build caches, and planting the link needs read access to the target already), and **modifying** a regular file with more than one link is refused, because the change would reach names outside the workspace ([ADR-0042](adr/0042-m4a-canonical-filesystem-resolution.md) §7) |
| Bind-mount escape | `RESOLVE_NO_XDEV`; mount changes inside the sandbox are blocked by seccomp (`mount` denied) |
| `/proc/self/root`, `/proc/<pid>/cwd` magic links | `RESOLVE_NO_MAGICLINKS`; `/proc` masked in the sandbox |
| **Unicode normalisation escape** — homoglyph or alternate normalisation producing a different string that resolves to the same file, or vice versa | NFC normalisation **before** comparison, and identity matching after resolution so the string never decides. *(This is the class behind a published `workspaceOnly` escape in a comparable system.)* |
| Windows: `CON`, `NUL`, `AUX`, ADS (`file.txt:hidden`), 8.3 short names (`PROGRA~1`), trailing dots/spaces, `\\?\` prefixes | Reserved-name rejection, ADS rejection, long-path canonicalisation, trailing-character rejection, and a final `GetFinalPathNameByHandle` identity check |
| Case-insensitive filesystem confusion (macOS/Windows) | Identity comparison post-resolution; never case-sensitive string compare on a case-insensitive FS |
| Race on directory creation (`mkdir` then someone replaces it) | `O_DIRECTORY|O_NOFOLLOW` and identity verification after creation |
| Unsafe temp files | Temp files created via `O_TMPFILE` or `mkostemp` inside the sandbox tmpfs, 0600, never in a shared `/tmp` on the host |
| Quota exhaustion / disk fill | Per-environment quota, `fsize` rlimit, write accounting |
| Zip/decompression bomb | Output byte accounting against the capability's `max_bytes`; extraction tools run with a hard fsize rlimit |

### Workspaces

A workspace is the unit of filesystem scope: a directory, a device+inode identity, an optional git repository, and an optional snapshot mechanism. Subagents get isolated workspaces — an **independent clone** where the workspace is a repo, a COW/reflink copy otherwise. Linked `git worktree`s are **not** used, because their config and hooks live in the parent's common directory ([ADR-0025](adr/0025-subagent-workspace-clone.md), [ORCHESTRATION.md](ORCHESTRATION.md) §5).

### Provisioning a workspace for sandboxed execution (M5d.4, operator)

[ADR-0052](adr/0052-m5d-sandboxed-process-exec.md) §§6, 10 — OD-3 and OD-6 approved by the owner as built, 2026-10-26. The daemons measure and refuse; **they never create, mount, `chmod` or `chown` a workspace** (TX057), so the operator does, as root, once per workspace. Every step below is the operator's and is checked, not repaired, before every environment and every workload.

1. **The group.** `groupadd --gid 10001 <name>` — the gid every workload runs as (the name is the operator's); add the authority's and the broker's users to it (`usermod --append --groups <name> <user>`), and **nobody else**: every member reads and writes every workspace. Restart both daemons so they hold the group; the authority checks its own membership, the broker its own.
2. **A filesystem of its own per workspace**, exactly the size of the quota you will declare (no more, and not more than a quarter less), mounted `nosuid,nodev` with the workspace root as **the filesystem's root** — a directory inside a larger filesystem is refused, because the measured bound would be the larger filesystem's and two workspaces would share it. Any filesystem the kernel bounds will do: a `tmpfs` (`mount -t tmpfs -o size=8g,nosuid,nodev …`), a loop-mounted image (`fallocate -l 8G img && mkfs.ext4 img && mount -o loop,nosuid,nodev img …`), a logical volume, or an XFS project quota exported as its own mount. Not on the filesystem of the authority's state directory, its socket or its secret files (`WORKSPACE_FILESYSTEM_SHARED`).
3. **The root:** `chown <authority-user or root>:10001 <root> && chmod 2770 <root>` — owned by root or the authority, never uid 10001; the group 10001; exactly `2770` (set-group-id, so everything made inside stays the group's).
4. **Declare it:** bind the root as the workspace's root as before, and in the file `dwkd-authority serve --sandbox-config` reads, `[workspace]` with `quota_bytes = <bytes>` (16 MiB to 16 TiB). Start the broker without `--allow-unverified-workspace`.

**Verify, read-only:** `stat -c '%U:%g %a' <root>` says the owner, `10001` and `2770`; `findmnt -no TARGET,OPTIONS <root>` names the root itself with `nosuid,nodev`; `df -B1 --output=size <root>` is the quota or at most a quarter below it; `id <authority-user>` and `id <broker-user>` list group 10001. A preparation that fails says why (`WORKSPACE_OWNER`, `WORKSPACE_GROUP`, `WORKSPACE_MODE`, `WORKSPACE_GROUP_MEMBERSHIP`, `WORKSPACE_UNBOUNDED`, `WORKSPACE_QUOTA_MISMATCH`, `WORKSPACE_FILESYSTEM_SHARED`), in `environment.refused`. **What it buys and what it does not:** the workload, the authority's tools and the broker share the workspace and nobody else can; the workload can fill its own workspace and no other. Every member of group 10001 can read and write all of it. The evidence harness's `[workspace] unverified_evidence = true` (with the broker's `--allow-unverified-workspace`) proves none of this, logs `REDUCED ASSURANCE` on both daemons, and is never a deployment.

## 4. Host execution (`local`)

Sometimes genuinely necessary — GPU access, hardware, a toolchain that cannot be containerised.

Requirements, all of which must hold:

1. `security.allow_host_execution = true` in kernel-side config (not runtime-writable, not settable by the agent).
2. A capability explicitly scoped to `environment=host`.
3. Per-invocation approval. No standing grant covers host execution.
4. A visible, persistent indicator in the CLI/UI for the duration.
5. An audit record with `assurance=None` and the full canonical command.
6. Still subject to: env scrubbing, rlimits, egress proxy routing, output caps, and the full policy pipeline. Host execution removes *isolation*, not *authorization*.

On Linux, host execution additionally applies Landlock (where available) and a seccomp filter, giving partial containment even without a container. This is `AssuranceLevel::ProcessIsolation`, reported honestly as less than `ContainerIsolation`.

## 4a. The allowlisted-interpreter problem

An executable allowlist assumes a binary's identity determines its behaviour. For every entry on a realistic allowlist, it does not.

`pytest` executes `conftest.py`. `git` honours `core.pager`, `core.hooksPath` and `core.fsmonitor` from a repository's own `.git/config`, and runs `.git/hooks/*`. `npm` runs lifecycle scripts from `package.json`. `cargo` compiles and runs `build.rs`. `python3` auto-imports `sitecustomize.py` and `.pth` files. All of these read **the workspace the agent can write.**

So an agent holding only `fs.write:${WORKSPACE}` and an `ALLOW`-ed `pytest` has arbitrary code execution inside the sandbox, without a single approval. Three consequences must be stated plainly rather than papered over:

1. **Containment still holds.** The code runs inside `oci-strict`: non-root, no network, read-only root, caps dropped. This is not a host escape, and the sandbox — not the allowlist — is the boundary that stops it. That is exactly the division of labour [ADR-0008](adr/0008-sandbox-default.md) intends.
2. **`process.exec` argv scoping and executable hashing are blast-radius and auditability controls, not confinement.** `(path, sha256)` in an approval binding identifies the binary; it says nothing about the config the binary will read. We should not claim otherwise.
3. **Sub-workspace `fs.*` scoping is unenforceable once `process.exec` is granted.** The sandbox mounts the workspace at directory granularity, so an exec'd process reads and writes the whole mount with no per-file capability check, no canonicalisation and no per-file audit record. A thousand writes produce one `process.exec` audit entry.

Point 3 requires a correction elsewhere: [OBSERVABILITY.md](OBSERVABILITY.md) §1's claim that "the absence of a record means the action did not go through the kernel" holds for **brokered operations**, not for filesystem activity inside a granted exec. Stated precisely: *every side effect crossing the sandbox boundary is recorded; activity inside a sandbox during a recorded `process.exec` is not individually recorded.*

### Mitigations we do ship

- **`workspace_exec_hygiene`** (a policy obligation): the exec broker neutralises auto-loaded configuration for the invocation — `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_COUNT=0`, `PYTHONNOUSERSITE=1`, `PYTHONSAFEPATH=1`, `-p no:cacheprovider` for pytest, `--ignore-scripts` for npm, `CARGO_NET_OFFLINE=1`. Default-on for every allowlisted interpreter in `BALANCED`. **Not shipped on the host (M4d, [ADR-0045](adr/0045-m4d-process-execution-broker.md) §11):** these settings are undone by the target's own argv (`git -c`, `python3 -c "sys.path.insert(0, '')"`, `npm --ignore-scripts=false`, `cargo --config`) and never reach a repository's own `.git/hooks`, `conftest.py` or `build.rs` — shown with the real tools by `make process-broker-evidence`. On the host the obligation is therefore **unenforceable**, and an action carrying it is denied `OBLIGATION_UNENFORCEABLE`; only an execution environment (M5) can keep it. **In an environment (M5d.2, [ADR-0052](adr/0052-m5d-sandboxed-process-exec.md) §5a):** the broker starts the workload through the digest-pinned probe, which sets the variables above and executes the program; pytest's `-p no:cacheprovider` goes first in its recorded argv; an invocation whose own arguments undo a setting (`git -c`/`--config-env`/`--exec-path`, `python -E`, `pytest -p cacheprovider`) and every `npm`-family tool and `cargo` (no real-tool evidence yet), directly or through `cargo-*`, `rustup`, `corepack`, a runner or `uv`, are still denied `OBLIGATION_UNENFORCEABLE`. Measured with the real `git`, Python and pytest. A repository's own configuration and hooks, `conftest.py` and `build.rs` still run — consequence 1 above, not the obligation, is what bounds them.
- **Control-surface paths require approval to write**, even inside the workspace: `.git/config`, `.git/hooks/**`, `conftest.py`, `package.json` (`scripts`), `build.rs`, `.cargo/config.toml`, `sitecustomize.py`, `*.pth`, `.envrc`, `Makefile` when `make` is allowlisted. These are a small, enumerable set and writing one is a genuinely unusual act for a refactoring task.
- **`fs.patch` canonicalises every path inside the diff** ([ARTIFACTS.md](ARTIFACTS.md) §5), not just the target root.

None of this makes the allowlist a confinement boundary. It narrows what an injected instruction can reach without a prompt, and it makes the interesting writes visible.

## 5. Platform assurance

| Property | Linux | macOS | Windows |
|---|---|---|---|
| Container isolation | Native (namespaces, cgroups v2) | Docker Desktop **VM** — arguably stronger | Docker Desktop + WSL2 (Linux VM) |
| seccomp | ✅ | ✅ inside the VM | ✅ inside WSL2 |
| Landlock (host exec) | ✅ 5.13+ | ✗ | ✗ |
| Seatbelt (host exec) | ✗ | ✅ `sandbox_init` (deprecated but functional) | ✗ |
| Job objects / restricted tokens (host exec) | ✗ | ✗ | ✅ partial |
| `openat2` RESOLVE_* | ✅ 5.6+ | ✗ — no resolver in M4a (a fallback walk needs its own ADR) | ✗ — no resolver in M4a (a fallback walk + handle identity needs its own ADR) |
| cgroup resource limits | ✅ | via VM | via VM |
| User namespace remap | ✅ | n/a | n/a |
| **Overall host-exec assurance** | **Good** | **Moderate** | **Weak** |
| **Overall sandboxed assurance** | **Good** | **Good** (VM) | **Good** (VM) |

**The honest summary for Windows users** — which is the platform this project is being designed on: sandboxed execution via Docker Desktop/WSL2 is fine, because the work happens inside a Linux VM. *Native* Windows host execution is materially weaker: no Landlock or Seatbelt equivalent, weaker path semantics, and a filesystem with several extra escape surfaces (ADS, short names, reserved names). The supported configuration is therefore **WSL2 + Docker Desktop**, and `direwolf doctor` will say so:

```
⚠  Host execution on native Windows: AssuranceLevel::None
   Landlock/Seatbelt unavailable; path canonicalisation uses the fallback walker.
   Recommended: run the kernel inside WSL2.  Continue anyway with
   security.allow_host_execution=true, understanding the reduced guarantee.
```

We prefer a loud, specific warning over a silent downgrade. A security property that varies by platform without telling anyone is worse than not having it.

## 6. Escape-resistance evaluation

The security eval suite ([EVALS.md](EVALS.md)) includes, at minimum:

- path traversal via every encoding we know of (`..`, URL-encoded, UTF-8 overlong, Unicode-normalised, Windows short-name, ADS)
- symlink and hardlink escape, including swap-after-check races run in a tight loop
- `/proc` and magic-link access
- container socket access, `--privileged` attempts, capability re-acquisition attempts
- `mount`, `unshare`, `setns`, `ptrace`, `io_uring` attempts
- resource exhaustion: fork bomb, memory bomb, disk fill, fd exhaustion
- device access attempts
- direct network access from a `PROXY_ONLY` sandbox: raw sockets, direct DNS, connecting to any address other than the proxy endpoint, and ignoring the proxy environment variables
- writes outside the workspace mount
- persistence attempts across container lifecycles

Acceptance: **all contained, each attributed to what contained it** (the owner's decision OD-E1, 2026-10-26, [M5E_ASSURANCE_PLAN.md](M5E_ASSURANCE_PLAN.md) §10). Every case's evidence names the mechanism and the record or measurement that shows it: an authority or broker refusal in the audit log; the environment's own records (`environment.refused`, `environment.drifted`, the destruction's egress counted by disposition); the proxy's decision; an invariant the probe measured; the errno the namespace returned; or the client's own verification. **What is not claimed:** that each attempt inside the namespace — a refused syscall, an absent route — is itself an audit record. DireWolf has no per-attempt syscall audit, and adds none: such an attempt is measured by the evidence and shown by the environment's measurement, not written to the log one by one. Silent containment is still insufficient: a case that cannot say what contained it fails the gate, and an operator's signal is the environment's measurement and the records the kernel already writes.

**M5d.1 runs workloads against that half** (`make sandbox-workload-evidence`, [ADR-0052](adr/0052-m5d-sandboxed-process-exec.md) §17): the plan's identity, executable substitution, drifted, stopped, foreign and missing environments, output and wall-clock bounds, process trees that detach, leave their session, daemonise or fork in a loop — all ended — writes outside the workspace, the runtime socket and host paths, direct TCP and DNS, and an agent-shaped workload with helpers, workers and workspace files; `make sandbox-workload-mutations` weakens each guard in turn. Its environments are `NO_NETWORK`; a workload in `PROXY_ONLY` is M5d.5's.

**M5d.5 runs an agent in `PROXY_ONLY` against it** (`make sandbox-agent-evidence`, [ADR-0052](adr/0052-m5d-sandboxed-process-exec.md) §17): over a real DWKP client and the released `serve`, the granted synthetic origin reached by a verifying HTTPS client and every other host, port, CONNECT form, server name, direct TCP/UDP/DNS path and rewritten proxy variable refused — each attributed to the proxy's decision, the namespace's errno, or the agent's own TLS verification; the budgets, the wall clock, `reap`, a broker and an authority lost mid-agent, and no replay; and, on the hosted `sandbox-agent` job only, three host identities with every cross-identity boundary attempted. The audit records the environment's egress as counts by disposition when it is destroyed, not one event per refused attempt. `make sandbox-agent-mutations` weakens each identity, proxy, policy, cleanup and non-replay guard in turn.

**M5d.6 ends an environment with its run** (`make sandbox-release-evidence`, [ADR-0052](adr/0052-m5d-sandboxed-process-exec.md) §8): a run's `ReleaseRun` records the destruction of its live environment in the release's own transaction, before the broker is told, and the broker then removes exactly that environment by its recorded container and labels — its relay and setup containers with it in `PROXY_ONLY`, the egress counted by disposition at the destruction. A workload still running in it, with every process it left, ends with the container and is settled `UNKNOWN`, never rerun. A destruction the broker cannot confirm stays `DESTROYING` and is completed by the next preparation or at the next start. Another run's environment, an unlabelled container of the same image and another store's copy of the labels are never touched; a fenced, foreign or repeated release ends nothing. The answer is still `Ack`: the release, and its environment's destruction, are durable — not that the removal was confirmed. A run a lease's end reaped is not released, and its environment is still reclaimed before the next preparation (ADR-0052 §2a). `make sandbox-release-mutations` weakens each release guard in turn.

**The M5d closeout ends an environment with its lease's end too** (the owner's decisions of 2026-10-26, [ADR-0052](adr/0052-m5d-sandboxed-process-exec.md) §§8–9, 19; accepted 2026-10-26, M5d complete). In the transaction that records a run `REAPED` — a holder's `ReleaseLease`, or an `AcquireLease` that rotates, takes over or re-acquires the lease — the run's live environment is recorded `DESTROYING` before the broker is told; the request then removes at most one environment, by its recorded container and labels, holding the worker for at most the 120 s environment deadline, and the rest are removed by the next preparation or the next start. A restart destroys every reaped run's `READY` environment by its labels instead of measuring it again and keeping it (ADR-0047 §12's W5, amended). A workload running in a reaped run's environment ends with it, settled `UNKNOWN`, never rerun; a new holder inherits nothing. Another session's environment and containers the store did not record are never touched; the caller names no environment, and `Ack` still says the destruction is durable, not confirmed. **Residual:** a lease that only expires reaps nothing, so its runs stay fenced and their environments idle — counted among the 16 — until the session is acquired again or the authority restarts; no expiry sweep exists. And what a lease's end leaves `DESTROYING` holds back brokered changes in the workspace it shares — `SHARED_DIRECTORY`, M5d.4's exclusion, unrelaxed — until a later preparation or a restart removes it (accepted by the owner as a residual on 2026-10-26, one destruction per request kept, ADR-0052 §19).

**M5a runs the containment half that exists** on a real OCI runtime (`make sandbox-foundation-evidence`, [ADR-0047](adr/0047-m5a-oci-execution-environment-and-measured-assurance.md) §§9, 14): container-socket, privilege, capability, `mount`/`unshare`/`setns`/`ptrace`/keyring attempts, bounded pid, fd, memory and file-size pressure, device access, and persistence across environments. The SSRF cases of the kernel's own requests are M5c's (`net.http`, `make net-http-evidence`, complete), which never uses an environment or its proxy; a workload's are M5d's. **M5b adds the `PROXY_ONLY` half** (`make sandbox-egress-evidence`, [ADR-0048](adr/0048-m5b-proxy-only-topology-and-connect-proxy.md) §14): every direct TCP, UDP, DNS, raw, packet, ICMP and virtual-socket attempt from inside refused with its errno and mechanism, tunnels through the real relay and proxy, only the relay's uid able to reach the broker's socket, and nine weakened or drifted topologies detected. Its containment is recorded in the environment's measurement and audit record (`environment.refused`, `environment.drifted`), not per attempt — attributed, as the acceptance above says.

**The gate must be shown able to fail.** For each hard rule of §2, a meta-test runs the suite against a deliberately weakened profile — a bridge network, a writable root, an added capability, unconfined seccomp, a mounted container socket — and the gate must fail. A containment suite that passes a weakened sandbox measures nothing. A case that cannot run reports NOT EXERCISED, which fails the gate rather than skipping it.

### 6a. What a line of evidence says (M5e.1)

Every line of the foundation, egress, workload, secret and workspace evidence — their in-process halves included — says, beside its suite, case and outcome, the **level** it was measured at and its **enforcement**: the existing mechanism that enforced, or observed, what the case shows (the owner's OD-E1; [M5E_ASSURANCE_PLAN.md](M5E_ASSURANCE_PLAN.md) §6, M5e.1). `scripts/dw.py` holds the contract — each required case's level and the mechanisms its line may name (`ATTRIBUTION`) — and each of the five tasks refuses, naming the suite and case, a line that is unreadable, of a suite or case its inventory does not hold, reported twice, without an outcome, NOT EXERCISED, at another level, or attributed to a mechanism the vocabulary lacks or the case does not exercise; a required case that never reports fails as NOT EXERCISED (`require_attributed_evidence`). `tests/architecture/test_m5e_attribution.py` holds the contract to the suites' sources and shows each of those refusals. The agent's and the release's lines keep their own contracts (M5d.5, M5d.6).

**What it proves, and what it does not.** The attribution names the mechanism a passing case exercised; that the mechanism held is the case's own assertions', at the level the line names. A line is printed only after those assertions held — metadata alone proves nothing. It is not a new audit record: the audit log holds what the authority and the broker already record (refusals, the ledger, `environment.refused`, `environment.drifted`, the egress counted by disposition), the environment's measurement holds the invariants, and a refused syscall or an absent route inside the namespace is shown by its case and the measurement, never logged one by one. What only a provisioned host runs is its own level, and NOT EXERCISED — failing the task — wherever it did not run.

| Level | What ran |
|---|---|
| `in-process` | the product's own code in the test process — the broker's exchange code on a real full tmpfs of its own; no broker serving an environment |
| `fake-broker` | the real authority and store against the route tests' fake broker, which contains nothing: what the authority decides, records and refuses, never containment |
| `real-oci` | the released broker on a real OCI runtime, the test playing the authority or calling the real authority's own API |
| `dwkp-end-to-end` | a real DWKP client on the authority's socket — the seam's or the released `serve`'s — over the same |
| `privileged-oci` | what only an operator-provisioned host runs — the group 10001, filesystems of their own, `sudo` — which only `DW_WORKSPACE_PRIVILEGED=1` provisions (the hosted `sandbox-workspace` job) |

| Enforcement | What enforced or observed it |
|---|---|
| `measured-host`, `measured-inside`, `measured-both` | an invariant the broker measured: from the host (the runtime's record and its own), from inside by the digest-pinned probe, or both (ADR-0047) |
| `measured-before-work` | the environment measured again before a workload, and refused when not clean |
| `probe-digest-pin`, `relay-digest-pin`, `executable-digest-pin` | bytes proved against their pinned digest before they run: the probe's, the relay's, a workload's executable |
| `probe-report-validation`, `probe-step-deadline` | only a well-formed, bounded report from the pinned probe believed; the probe's step bounded |
| `workspace-contract-measured` | the broker judging the probe's facts about the workspace against the bound the authority sent |
| `capabilities-and-seccomp`, `capabilities`, `seccomp`, `no-new-privileges`, `oci-user` | the profile as the kernel holds it: dropped capabilities, the seccomp filter, no-new-privileges, the environment's user |
| `read-only-root`, `container-tmpfs`, `mount-namespace`, `workspace-mount` | the environment's filesystem: a read-only root, a `/tmp` of its own, no runtime socket or host path, the workspace its one writable host path |
| `cgroup-limit`, `rlimit`, `filesystem-quota` | resource bounds: the cgroup's (pids, memory), the resource limits (descriptors, file size), a filesystem's own size |
| `topology-no-route`, `topology-nothing-listening`, `topology-no-resolver`, `platform`, `platform-or-capabilities` | the environment's network namespace, by the errno an attempt got — M5b's own words: no route, nothing listening, no resolver; or the platform refusing the socket |
| `proxy-only-topology`, `egress-socket-acl`, `egress-listener-lifecycle`, `launch-environment` | the `PROXY_ONLY` topology the broker built: the unprivileged relay in the environment's namespace, a socket only the relay's uid reaches, the listener ended with its environment, exactly the broker's variables in a launch |
| `relay-and-connect-proxy-grant`, `connect-proxy:grant`, `connect-proxy:canonical-target`, `connect-proxy:address-guard`, `connect-proxy:resolver`, `connect-proxy:resolver-deadline`, `connect-proxy:server-name`, `connect-proxy:upload-budget`, `connect-proxy:download-budget`, `connect-proxy:tunnel-limit` | the broker's CONNECT proxy: a granted tunnel carried; or its decision, by the part of the proxy that made it |
| `egress-disposition-counters` | the egress counted by disposition at the destruction, never by destination or payload |
| `exact-label-ownership`, `exact-label-cleanup`, `fresh-container-per-environment`, `runtime-client` | the broker's lifecycle: only its store's exactly-labelled containers listed, acted on and removed; a fresh container per environment; what the runtime answered, classified |
| `broker-admission`, `broker-start-up-admission`, `broker-start-up-posture`, `broker-workspace-convention`, `broker-secret-admission`, `broker-workload-admission` | the broker refusing before anything is made or run: an authorisation, an identity it must not start as and the posture it reports, a directory breaking the workspace group's convention, a malformed secret handoff, a second workload |
| `broker-launch`, `direct-launcher`, `hygiene-launcher`, `trusted-launcher`, `secret-stdin-handoff` | how a workload starts: the authorised arguments byte for byte; the direct launcher's umask; `workspace_exec_hygiene`; the pinned probe as the trusted launcher delivering a credential; a credential only on the runtime client's standard input |
| `broker-log-discipline`, `output-bound`, `output-redaction`, `ending-classification`, `broker-wall-clock` | what a workload leaves: lengths, never content, in the log; output bounded and counted; a credential redacted; its ending classified; its wall clock |
| `environment-init-reap`, `residue-measurement`, `broker-census` | what remains after: every process but init ended; the residue measured; the broker's own descriptors, threads and children |
| `broker-start-collect`, `workload-generation`, `broker-judgement-before-exec`, `broker-fail-closed` | start and collect: answered after the judgement, others served meanwhile; collected only under its generation; nothing run before the judgement; no answer from a broker that died |
| `authority-gates`, `authority-plan`, `authority-policy`, `authority-capability`, `authority-obligation`, `authority-image-manifest`, `authority-request-bounds`, `authority-run-budget`, `authority-taint` | the authority's gates, before anything is recorded or sent: the plan, the policy, the capabilities, the obligations, the image manifest, a request's bounds, the run's budget, the taint a workload raises |
| `authority-route`, `authority-environment-decision`, `authority-environment-judgement`, `authority-grant-derivation`, `authority-workspace-contract`, `authority-workspace-exclusion` | the authority's sandbox route: where a launch runs (never the host), the assurance an environment earned, the egress grant derived from the run's own, the workspace contract it holds the pinned root to, the exclusion while a workload may write |
| `authority-ledger`, `authority-ledger-intent-first`, `authority-idempotency`, `authority-lease-fence`, `authority-reconciliation`, `authority-reclamation` | the authority's durable state: the ledger, its intent recorded before the broker is told, a key never run twice, the lease's fence, reconciliation after a crash, an ended run's environment reclaimed |
| `authority-audit`, `authority-audit-at-destruction` | an audit record the authority writes |
| `kernel-process-credentials`, `dwkp-schema` | the caller's identity from the kernel's peer credentials; the protocol's schema |
| `secret-metadata`, `secret-backend`, `secret-value-validation`, `secret-not-persisted` | a credential's stored metadata and revision, the backend's answer, the value's own validity, and no value in the store, the audit or a log |
| `workspace-group-10001`, `workspace-root-2770` | the workspace group and its root's mode (ADR-0052 §6), in the agent evidence's words |
| `runtime-process-list` | an observation, not an enforcement: the test's own listing of the environment's processes |
| `residual-contained-by-the-environment`, `residual-inherited-by-descendants` | the residuals ADR-0052 states — what hygiene leaves runs, contained by the environment; a credential's descendants inherit it — measured, never neutralised |
| `telemetry` | the foundation's latency: the broker's own timings, required to say `measured` and carry its numbers; never containment |
