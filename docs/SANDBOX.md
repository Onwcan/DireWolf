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

- **`workspace_exec_hygiene`** (a policy obligation): the exec broker neutralises auto-loaded configuration for the invocation — `GIT_CONFIG_GLOBAL=/dev/null`, `GIT_CONFIG_NOSYSTEM=1`, `GIT_CONFIG_COUNT=0`, `PYTHONNOUSERSITE=1`, `PYTHONSAFEPATH=1`, `-p no:cacheprovider` for pytest, `--ignore-scripts` for npm, `CARGO_NET_OFFLINE=1`. Default-on for every allowlisted interpreter in `BALANCED`. **Not shipped on the host (M4d, [ADR-0045](adr/0045-m4d-process-execution-broker.md) §11):** these settings are undone by the target's own argv (`git -c`, `python3 -c "sys.path.insert(0, '')"`, `npm --ignore-scripts=false`, `cargo --config`) and never reach a repository's own `.git/hooks`, `conftest.py` or `build.rs` — shown with the real tools by `make process-broker-evidence`. On the host the obligation is therefore **unenforceable**, and an action carrying it is denied `OBLIGATION_UNENFORCEABLE`; only an execution environment (M5) can keep it.
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

Acceptance: **all contained, each with an audit record naming the denial.** Silent containment is insufficient — an escape attempt that is blocked but not recorded means an operator has no signal that they are under attack.

**M5a runs the containment half that exists** on a real OCI runtime (`make sandbox-foundation-evidence`, [ADR-0047](adr/0047-m5a-oci-execution-environment-and-measured-assurance.md) §§9, 14): container-socket, privilege, capability, `mount`/`unshare`/`setns`/`ptrace`/keyring attempts, bounded pid, fd, memory and file-size pressure, device access, and persistence across environments; the SSRF cases wait for M5c. **M5b adds the `PROXY_ONLY` half** (`make sandbox-egress-evidence`, [ADR-0048](adr/0048-m5b-proxy-only-topology-and-connect-proxy.md) §14): every direct TCP, UDP, DNS, raw, packet, ICMP and virtual-socket attempt from inside refused with its errno and mechanism, tunnels through the real relay and proxy, only the relay's uid able to reach the broker's socket, and nine weakened or drifted topologies detected. Its containment is recorded in the environment's measurement and audit record (`environment.refused`, `environment.drifted`), not yet per attempt.

**The gate must be shown able to fail.** For each hard rule of §2, a meta-test runs the suite against a deliberately weakened profile — a bridge network, a writable root, an added capability, unconfined seccomp, a mounted container socket — and the gate must fail. A containment suite that passes a weakened sandbox measures nothing. A case that cannot run reports NOT EXERCISED, which fails the gate rather than skipping it.
