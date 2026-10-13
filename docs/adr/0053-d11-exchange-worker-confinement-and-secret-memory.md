# ADR-0053: D11 hardening — the HTTPS exchange worker confines itself with an exact syscall filter and is vouched for from the kernel before it is handed anything; a credential hop runs only where its memory cannot reach swap

**Status:** Proposed · **Date:** 2026-10-13 · **Would amend (on acceptance):** [ADR-0050](0050-m5c-kernel-performed-net-http-ssrf-redirects-and-credential-egress.md) (§9's worker gains a syscall filter and a broker-side vouching before its hand-over; §21's ptrace posture is read again before every worker, and a swap condition joins the conditions), [ADR-0046](0046-m4e-secret-handles-backends-injection-and-redaction.md) (§10: where a credential's memory may be, for mode A), [ADR-0019](0019-language-rationale-v2.md) and [ADR-0033](0033-protocol-source-of-truth-and-tcb-dependencies.md) (the broker's dependency set: `seccompiler`, and a direct edge to `libc`) · **Refines:** [ADR-0018](0018-authority-broker-split.md), [ADR-0045](0045-m4d-process-execution-broker.md) (the launch helper is unchanged), [ADR-0052](0052-m5d-sandboxed-process-exec.md) (Proposed; M5d.1's start-up posture check, now per hop for exchange workers) · **Leaves unchanged:** every accepted ADR's body; ADR-0052 stays Proposed and M5d.1 a historical checkpoint.

> **A worker that a malicious origin compromises can no longer reach
> anything its broker's uid could.** Before it can receive a byte, the
> exchange worker installs a seccomp program that allows exactly the calls a
> hop was measured to make -- no new socket, no `connect`, no `execve`, no
> `fork`, no `ptrace`, no `open`, no signal to another process -- and proves
> it by attempting each forbidden operation and requiring the kernel's
> `EPERM`. The broker then reads the worker's own `/proc` entries -- filter,
> `no_new_privs`, untraced, not dumpable -- and only then hands it the
> connection and the credential. A hop that carries a credential is
> performed only where the broker's memory and its worker's cannot be
> written to swap; elsewhere it is refused, unless the operator acknowledged
> it for development.

## Context

### D11 as built (ADR-0050 §9, read from the source at `cd45f5f`)

One short-lived process, `dwkd-broker http-worker`, per `net.http` hop. The
broker judges the hop again, dials the pinned address, reads the credential
once from the authority's pipe into a `Zeroizing` buffer and hands it on in a
fresh pipe (`http/render.rs`), spawns the worker with an empty environment,
`/dev/null` for stdin and stdout and a socket pair for stderr, its own
process group, and **sends the hand-over -- the connection and the
credential's pipe, by `SCM_RIGHTS` -- immediately**. The worker checks that
its peer is its parent broker, hardens itself (`RLIMIT_CORE` 0,
`PR_SET_DUMPABLE` 0, the parent-death signal, its parent unchanged,
`no_new_privs`, no inherited descriptor), receives the hand-over, performs
TLS and HTTP/1.1, redacts echoes, answers and exits; the broker reaps it and
decodes the answer strictly. Crash semantics: no `S` marker means nothing was
sent (`HTTP_WORKER_FAILED`); after it, `EXCHANGE_UNCONFIRMED`.

What that did not give:

- **No confinement of the worker's own calls.** A memory-safety bug in the
  response path (`rustls`, `ring`, the framing) would run an origin's code
  as the broker's uid: free to open a new connection to anywhere the host
  can reach (the egress guard is the broker's, not the kernel's), to execute
  a program, to signal the broker, to open the broker uid's files, to trace
  or read another worker.
- **The hand-over preceded the hardening.** The connection and the
  credential's pipe were queued in the worker's socket before it had made
  itself non-dumpable: a same-uid process that opened `/proc/<worker>/mem`
  in that window keeps the descriptor after the worker hardens (reads through
  an open `mem` descriptor are not re-checked), and a tracer attached in it
  stays attached.
- **The start-up posture** (Yama `ptrace_scope` ≥ 1 or an execute-only
  binary) was read once, at the broker's start (M5d.1).
- **Swap** was not considered: the credential's memory, in the broker and
  in the worker, could be written to a swap device.

### Threat model for this decision

In: an origin that controls everything after the TLS handshake's
verification -- response heads, bodies, timing -- and may turn a parser bug
into code execution in the worker; a process of the broker's uid other than
the broker and its ancestors (a compromised worker of another hop, or one a
careless deployment runs); local unprivileged users; a swap device and
whoever later reads it. Out: root and `CAP_SYS_PTRACE`/`CAP_SYS_ADMIN`; the
kernel; the hypervisor and the host of a VM (WSL2's included); physical
access and cold boot -- named where a deployment measure reduces them
(§§10, 12), never claimed.

### Primary sources studied (2026-10-13)

| Source | Mechanism | Applies here | Limitation | Decision |
|---|---|---|---|---|
| [Linux seccomp filter](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html), [seccomp(2)](https://man7.org/linux/man-pages/man2/seccomp.2.html) | BPF over `seccomp_data`; `no_new_privs` or `CAP_SYS_ADMIN` to install; inherited; most restrictive action wins | the worker's program | the architecture must be checked or numbers overlap across conventions; pointers cannot be inspected; vDSO calls are not seen | §5: arch check, x32 refused, argument rules only on values |
| [execve(2)](https://man7.org/linux/man-pages/man2/execve.2.html), [PR_SET_DUMPABLE](https://man7.org/linux/man-pages/man2/PR_SET_DUMPABLE.2const.html), kernel `fs/exec.c` (`would_dump`, `begin_new_exec`, master) | `execve` resets dumpable to 1, or to `suid_dumpable` when the executing user cannot read the binary | the window, and the execute-only deployment | a parent's `PR_SET_DUMPABLE` is not inherited across `execve` | §4 |
| [Yama](https://www.kernel.org/doc/html/latest/admin-guide/LSM/Yama.html) | scope 1: attach only to descendants or a declared tracer; scope 3 cannot be lowered | the window | host-global; an ancestor may still attach | §4: required unless the binary is execute-only |
| [cgroup v2](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html) | `memory.swap.max` hard cap; `swap.current`, `swap.events`; lowering the cap does not recall existing swap | §7 | needs the memory controller delegated; hibernation is outside it | §7 |
| systemd [`systemd.resource-control`](https://github.com/systemd/systemd/blob/main/man/systemd.resource-control.xml) (source of the man page; the freedesktop page refused the connection) | `MemorySwapMax=` → `memory.swap.max`; transient scopes by `systemd-run` | the deployment and the evidence | a unit file is not proof: the cap is read from the cgroup | §§7, 13 |
| [mlock(2)](https://man7.org/linux/man-pages/man2/mlock.2.html) | `mlock`, `mlockall(MCL_FUTURE|MCL_ONFAULT)` | assessed | `MCL_FUTURE` beyond `RLIMIT_MEMLOCK` fails later allocations; locks do not survive hibernation | §7: deferred |
| [memfd_secret(2)](https://man7.org/linux/man-pages/man2/memfd_secret.2.html) | memory removed from the kernel's direct map, never swapped | assessed | default on since 6.5; must be mapped (no safe API here); does not reach copies a TLS library makes | §11: deferred |
| [kernel parameters](https://raw.githubusercontent.com/torvalds/linux/master/Documentation/admin-guide/kernel-parameters.txt) | `init_on_alloc=`, `init_on_free=` | the deployment | boot-time, host-wide, a cost on every allocation | §10: documented and reported |
| [Landlock](https://man7.org/linux/man-pages/man7/landlock.7.html) | unprivileged LSM: filesystem rights, TCP bind/connect (ABI 4), signal and abstract-socket scoping (ABI 6) | assessed | a second layer over what the filter already denies; no safe API in the tree | §9: deferred |
| [WSL configuration](https://learn.microsoft.com/en-us/windows/wsl/wsl-config) (rev. 7ea1c6f) | `.wslconfig` `[wsl2] swap=0`, `kernelCommandLine`; the VM restarts to apply | development | the guest's swap is not the host's pagefile | §13 |
| [Chromium Linux sandbox](https://chromium.googlesource.com/chromium/src/+/refs/heads/main/sandbox/linux/README.md) | layers: namespaces/setuid helper and non-dumpable, then seccomp-BPF per process type, tested under the sandbox | design reference | a setuid helper and namespaces are a privileged TCB a short-lived worker does not need | layered, self-tested filter; no helper |
| [OpenSSH `ssh-agent.c`](https://github.com/openssh/openssh-portable/blob/master/ssh-agent.c) (`$OpenBSD: ssh-agent.c,v 1.333 2026/09/22`) | a dedicated agent: core limit 0, tracing disabled, `pledge`/`unveil`, `freezero`/`explicit_bzero`, peer uid checked | design reference | `pledge` is OpenBSD's; seccomp is Linux's equivalent | confirms the shape: a dedicated process, no core, no tracing, a narrowed syscall surface |
| [libsodium memory management](https://libsodium.gitbook.io/doc/memory_management) | `sodium_memzero`, `sodium_mlock` (+`MADV_DONTDUMP`), guarded allocations | design reference | locks are bounded by `RLIMIT_MEMLOCK`; stacks and registers are not covered; recommends disabling or encrypting swap and hibernation | not a dependency; its recommendation is §7's |
| [`zeroize`](https://docs.rs/zeroize/latest/zeroize/) (docs 1.9.1; locked 1.9.0) | volatile writes and a fence; `Zeroizing` | the owned buffers (§8) | moves and reallocations leave copies; nothing about memory the program does not own or swap | §8 |

No code, test or fixture was taken from any of them.

## Decision

### 1. Objectives

O1 A compromised worker cannot create network authority: no socket of any
family, no new peer, address or listener on the descriptors it holds.
O2 It cannot execute a program or create a process. O3 It cannot reach
another process: no `ptrace`, `process_vm_*`, `pidfd_*`, `kill` beyond
itself, `open` (so no `/proc/<pid>/mem`). O4 It cannot change its identity
or namespaces. O5 Nothing is handed to a worker the broker has not seen,
from the kernel, to be confined, untraced and closed to its own uid.
O6 A credential hop's memory cannot be written to swap, or the hop is
refused. O7 Every one of these is shown on real processes, and every guard
has a mutant that fails a test.

### 2. What is unchanged

The worker's process boundary, its hand-over protocol (`DWHW1`), its
answer, the crash semantics, the egress guard, DNS pinning, redirect policy,
TLS verification, origin binding, budgets, redaction, the durable ledger,
the authority's decisions. Every hop that worked still works: the HTTP
suites, credential echoes, concurrent hops, kill and overrun cases pass with
every worker confined.

### 3. Sequence

| step | worker | broker |
|---|---|---|
| 0 | -- | reads the host: start-up window closed; for a credential hop, its own memory cannot reach swap -- before it reads the credential |
| 1 | notes `PR_GET_DUMPABLE` as its image began; checks its peer is its parent | spawns it |
| 2 | hardens itself (unchanged) | -- |
| 3 | installs its filter; attempts 14 forbidden operations, requires `EPERM` from each; writes `R`, its image's dumpability, the answers | reads the ready line (judged strictly: every answer refused); reads `/proc/<pid>/status` and the owner of `/proc/<pid>/mem`; for a credential hop, the worker's swap |
| 4 | receives the hand-over | sends it -- or, any check short, kills the worker and hands nothing |
| 5–6 | unchanged | unchanged |

### 4. Start-up protection

- **Nothing before vouching.** The hand-over is sent only after the broker
  has read, from the kernel, `Seccomp: 2`, `Seccomp_filters` ≥ 1 (where the
  kernel reports it, 5.9+), `NoNewPrivs: 1`, `TracerPid: 0`, and
  `/proc/<pid>/mem` owned by another uid than the worker's (the kernel makes
  a non-dumpable task's restricted `/proc` entries root's; the directory
  itself keeps its uid, for `ps`). Non-dumpable at that moment means no
  process of the broker's uid can attach or open the worker's memory from
  then on; `TracerPid` 0 at that moment means none is attached. The
  remaining exposure is a `/proc/<worker>/mem` descriptor opened in the
  window between `execve` and the worker's `PR_SET_DUMPABLE(0)` -- the
  worker holds no credential and no connection then, but such a descriptor
  would read it later.
- **The window has no observer** under either posture the broker requires,
  read at start **and before every worker**: Yama ≥ 1 (a process of the
  broker's uid that is not an ancestor cannot open the worker's memory) or
  an execute-only binary (root-owned, no read bit: the kernel makes the image
  non-dumpable at `execve`, `would_dump()`, so there is no window at all --
  the worker reports `dumpable=0` from its first instruction, shown by the
  hosted job). An open window refuses the hop unless
  `--allow-traceable-workers`. The ancestor exception of Yama scope 1 adds
  nothing: an ancestor of the broker can already trace the broker. A posture
  changed after start needs root (outside the model) and is seen at the next
  hop anyway.
- **No worker can be that observer.** Every other worker is filtered: no
  `open`, `ptrace`, `process_vm_readv`, `pidfd_getfd`. In a deployment whose
  broker uid runs nothing else, no process of that uid can observe a worker.
- **Rejected:** a pre-exec launcher (code between `fork` and `execve` is
  `unsafe` here, TX for no closure between them, and it would not change
  what `execve` resets); setting dumpability in the parent (reset by
  `execve`); a privileged helper (a root TCB for what an execute-only binary
  gives).

### 5. The worker's syscall filter

- **Installed by the worker itself, before it can receive anything**, after
  authentication and hardening. No pre-exec stage: before its hand-over the
  worker has read nothing but its parent's authenticated channel, so no
  state an attacker controls precedes the filter; a pre-exec stage would
  need code between `fork` and `execve`.
- **The program** (`http/confine.rs`, built from the target's own `libc`
  constants): the architecture must be this build's (`AUDIT_ARCH_X86_64` or
  `_AARCH64`), else **`KILL_PROCESS`**; on `x86_64` a number with the x32
  bit set kills too. Allowed with no argument rule (28): `read`, `write`,
  `readv`, `writev`, `recvfrom`, `sendto`, `recvmsg`, `sendmsg`,
  `shutdown`, `close`, `fstat`, `getrandom`, `munmap`, `mremap`, `brk`,
  `madvise`, `futex`, `sched_yield`, `rt_sigprocmask`, `rt_sigaction`,
  `rt_sigreturn`, `sigaltstack`, `clock_gettime`, `getpid`, `gettid`,
  `restart_syscall`, `exit`, `exit_group`. Allowed with argument rules (5):
  `fcntl` (`F_GETFD`, `F_SETFD`, `F_GETFL`, `F_SETFL`, `F_DUPFD_CLOEXEC` --
  never `F_SETOWN` or `F_DUPFD` to a chosen number), `setsockopt`
  (`SOL_SOCKET` with `SO_RCVTIMEO` or `SO_SNDTIMEO`), `mmap` and `mprotect`
  (never `PROT_EXEC`), `tgkill` (this process only). Everything else:
  **`EPERM`**.
- **Measured, not guessed.** The set is what real workers called after
  hardening across the HTTP suites (credential hops, echoes, deadlines,
  malformed responses, kills), recorded by a ptrace recorder written for the
  purpose (development tooling, not in the repository), then proved: the
  suites pass with every worker confined. The identities the worker's proof
  needs (`getuid`, `geteuid`, `getppid`) are read before installation;
  nothing a hop does needs them.
- **`EPERM`, not `KILL`, for a forbidden call.** The operation is not
  performed either way. `EPERM` lets every worker prove its own filter
  (below) and keeps the refusal measurable; a wrong architecture or the x32
  convention -- never legitimate -- kills (OD-2).
- **Installation**: `seccompiler::apply_filter_all_threads` -- the one call
  that hands the kernel a pointer (`no_new_privs`, then
  `seccomp(SET_MODE_FILTER, TSYNC)`), from a reviewed crate (§16).
- **Proof, every worker**: 14 attempts made without effect -- sockets of
  three families, a socket pair, `connect`, `bind`, `listen`, `accept` on its
  control channel, `execve` of a path that cannot exist, `open` of
  `/proc/self/mem`, `pidfd_open`, `kill(parent, 0)`, `setresuid` to itself,
  `setns` -- each must answer `EPERM`, or the worker exits; the broker
  requires every answer refused. Unconfined, the same attempts succeed or
  fail for their own reasons (a test shows it).
- **Evaluation**: `confine_tests.rs` interprets the installed program for
  every number below 1024, both other conventions and every argument rule.
- **Architectures**: `x86_64` exercised; `aarch64` compiled from the same
  names, **not exercised** by any job; any other: no program, so no worker
  runs and `net.http` is refused there -- fail-closed (OD-7).

### 6. Identity: a dedicated worker uid -- deferred

The broker is not root and cannot change uid. Options weighed: a setuid or
capability-holding launcher (a root TCB, rejected); a user namespace (the
same host uid, and its creator holds every capability in it -- no
separation, rejected); **a systemd socket-activated worker service running
as a dedicated system user**, each broker connection a fresh worker, the
connection and credential passed over that socket -- feasible without any
broker privilege. It is deferred (OD-1): the worker would no longer be the
broker's child (parent-death, process-group kill, reaping and the `S`-marker
crash semantics would be redesigned), the deployment would need a second
user and units, and its evidence needs root. What it would add over this
decision is defence if the filter were bypassed (a kernel bug): `kill`,
`ptrace` and file access across uids blocked by the kernel's own checks.
M5d.1's separation -- no daemon with the workload's or relay's uid -- is
unchanged.

### 7. Swap

- **Per credential hop, twice**: the broker's own memory before it reads the
  credential, the worker's before it is handed it. Protected means no swap
  device, or a cgroup on the process's path whose `memory.swap.max` is `0`
  (systemd's `MemorySwapMax=0`). Otherwise the hop is refused
  (`HTTP_WORKER_FAILED`, nothing read, nothing sent, an event naming why)
  unless `--allow-swappable-workers` -- `REDUCED ASSURANCE` at start. A hop
  without a credential is unaffected; the broker's start-up reports the
  posture and says that credential hops will be refused.
- **Three claims, kept apart.** (1) *New anonymous pages of the broker and
  its worker cannot be swapped out* -- enforced where verified, read from the
  kernel per hop. (2) *Pages already swapped are recalled* -- not claimed:
  lowering a cap does not recall them, so the cap must be in force from the
  broker's start (systemd applies it before `execve`); each worker is new,
  and the broker's credential buffers are allocated per hop after the check.
  (3) *No plaintext ever reaches persistent storage* -- **not claimed**:
  hibernation writes all of memory whatever the cgroup or a lock says; a
  hypervisor may page the guest (WSL2's VM is backed by Windows memory, which
  Windows may page); a crash dump (`kdump`) is the host's.
- **`mlock`: deferred.** Locking an owned buffer needs a raw pointer
  (`unsafe` here); `mlockall(MCL_FUTURE)` makes later allocations fail at
  `RLIMIT_MEMLOCK` and could fail a hop mid-exchange; neither reaches the TLS
  library's copies, which the cgroup cap does.

### 8. Zeroization: reviewed, unchanged

Every buffer the broker's code owns that holds the value is `Zeroizing` and
sized once: the read buffer (`secret::read_value`), the composed header
(shared without a copy by the header value), the needle and its failure
table, the request's render buffer, every response buffer. Error paths drop
them (zeroed); a release build aborts on panic, so destructors do not run --
the process ends and its pages go back to the kernel. What the code does not
own and cannot erase through a safe API: `rustls`'s record buffers (the
request's plaintext is encrypted in place after the handshake; a response's
plaintext -- an echoed credential included -- sits in `rustls`'s buffer
until the worker exits), the `http` crate's response header map, and kernel
pipe and socket buffers. That is why the worker is a process (ADR-0050 §9),
and what §§7 and 10 reduce. No owned copy was found unzeroed; the code is
unchanged.

### 9. Landlock: deferred

Available on the development kernel (ABI 7). It would add an LSM-enforced
second layer -- no filesystem access, no TCP bind/connect, signals and
abstract sockets scoped, `ptrace` across domains refused -- over calls the
filter already refuses, for a new dependency or `unsafe`. Revisit with M6's
host launches, where no filter applies (OD-6).

### 10. Kernel page zeroing: documented and reported

`init_on_free=1` zeroes pages and slab objects as they are freed (and
`init_on_alloc=1` as they are allocated), host-wide, from boot, at a cost on
every allocation: a worker's freed pages -- the TLS library's copies
included -- are zeroed when it exits, instead of when the page is next
handed out. Recommended for production, never required; the broker reports
what the command line says (`deployment_posture … init_on_free=…`) and never
infers the build's default.

### 11. `memfd_secret`: deferred

Available on the development kernel (Linux 6.18; default since 6.5). It
would keep a staging copy of the credential out of the kernel's direct map
and out of swap -- but the value must be copied into the HTTP request and
`rustls`'s buffers to be sent, and an echo arrives in `rustls`'s buffers; the
staging copy is already short-lived and, under §7, unswappable. Mapping it
needs `unsafe` or a new crate. No proof of concept was built: it would not
plausibly improve the protection of the copies that matter.

### 12. Hardware memory encryption

AMD SME/TSME or Intel TME encrypt DRAM against physical and cold-boot reads;
AMD SEV-SNP or Intel TDX isolate a VM's memory from its host. Optional
deployment measures for those threats, outside DireWolf's model; never a
requirement for an ordinary installation.

### 13. Deployment requirements

Production (native Linux; [BROKER_HARDENING.md](../BROKER_HARDENING.md)): the
broker as a dedicated, non-root system user that runs nothing else; started
by systemd with `MemoryAccounting=yes`, `MemorySwapMax=0`, `LimitCORE=0`,
`NoNewPrivileges=yes`; its binary root-owned `0711` **and** Yama ≥ 1
(either suffices for the broker, both recommended); hibernation disabled or
its image encrypted; `init_on_free=1` recommended. Verified on the host by
the broker itself (its start-up event and every hop) and, read-only, by
`make d11-posture`. Development (WSL2, a workstation): the acknowledgements,
each logged; optionally `[wsl2] swap=0` in `%UserProfile%\.wslconfig`, which
takes effect only after the WSL VM is restarted -- the owner's action, never
the tooling's.

### 14. Compatibility

Linux with seccomp filters and `TSYNC` (3.17+); `Seccomp_filters` is read
where reported (5.9+). cgroup v2 for a cap; on v1 a host with swap refuses
credential hops. Without Yama, the binary must be execute-only. `x86_64` is
the exercised architecture.

### 15. Cost

Measured on the development machine (WSL2, Linux 6.18, 24 CPUs), release
builds of `cd45f5f` and of this change, the same harness in both: 60
measured hops of each kind against a local TLS origin after 5 unmeasured,
each hop in its own worker, two rounds run alternately.

| hop | before p50 | hardened p50 | before p90 | hardened p90 |
|---|---|---|---|---|
| plain | 1.06 / 1.04 ms | 1.25 / 1.26 ms | 1.33 / 1.27 ms | 1.45 / 1.51 ms |
| credential | 1.08 / 1.11 ms | 1.32 / 1.31 ms | 1.42 / 1.31 ms | 1.59 / 1.71 ms |

About 0.2 ms more per hop -- some 20 % of a loopback hop, under 1 % of a
hop that crosses a network -- for the filter's installation, 14 refused
attempts, one more read on the control channel, three `/proc` reads and the
host's posture, and for a credential hop two swap readings. Memory is
unchanged (no buffer is added, nothing is locked). Not measured: concurrent
hops at scale, and hosts other than this one.

### 16. Dependencies and the TCB

**`seccompiler` 0.5.0** (new; Apache-2.0 OR BSD-3-Clause; rust-vmm,
Firecracker and Cloud Hypervisor in production; last release 2025-03;
default features off, so no `serde`): only `apply_filter_all_threads` is
used -- its `unsafe` is one `prctl` and one `syscall` over a slice the kernel
copies. Its one dependency, `libc`, was already in the tree. **`libc`
0.2.189**: a direct edge (no new crate) for the program's numbers and
constants. **`nix`**: one reviewed new use, `execv` for the proof's
attempt (TX043 exempts `http/confine.rs` by name). The authority's closure
does not change. TX051 keeps the filter in one module.

### 17. Residual risks

- A kernel bug in seccomp or in an allowed call (`recvmsg`, `mmap`, …)
  bypasses the filter: the worker is still the broker's uid (OD-1).
- The window between `execve` and the worker's hardening, where neither
  posture holds and the operator acknowledged it (development only).
- Hibernation, a hypervisor's paging, a crash dump: outside §7.
- Library-owned plaintext until the worker exits; physical memory until a
  freed page is reused, unless `init_on_free=1`.
- Root, `CAP_SYS_PTRACE`, the kernel.
- `aarch64`'s program is not exercised.

### 18. Negative tests

`make d11-hardening-evidence`: the program evaluated for every number, both
other conventions and every argument rule; a real worker confined and proved
so before it is handed anything (`/proc` read by the test); a same-uid
observer refused by a worker by every way in; stand-ins lacking exactly one
property -- a filter, non-dumpability, an untraced state, an honest ready
line -- handed nothing, and a complete one handed its connection; an open
window and swappable memory refusing hops (the credential provably unread);
a credential hop under a real `MemorySwapMax=0` cgroup, its worker in it;
memory pressure there ending in the OOM killer with `swap.current` 0; and,
in the hosted job, an execute-only binary whose worker is non-dumpable at
`execve` and the Yama-0 counterexample. `make d11-hardening-mutations`: 22
guards weakened one at a time, each killed.

### 19. Revisit if

The kernel offers a way to make an exec'd image non-dumpable without root
ownership of the binary; systemd socket activation is part of the supported
deployment (OD-1); Landlock or a seccomp API without `unsafe` joins the tree;
`aarch64` gains a job; M6 makes host launches reachable.

### 20. Owner decisions

| # | Decision | Recommendation |
|---|---|---|
| OD-1 | A dedicated worker uid | **later**, as a systemd socket-activated worker service under its own user, with its own crash-semantics design |
| OD-2 | A forbidden call: `EPERM` or kill | **`EPERM`** (self-proof, measurable); kill for a wrong architecture or x32 |
| OD-3 | Swap: refuse credential hops, or refuse to serve | **refuse credential hops**, report at start |
| OD-4 | Start-up posture | **either** Yama ≥ 1 or an execute-only binary, **both** recommended |
| OD-5 | `init_on_free=1` | **recommended**, reported, not required |
| OD-6 | Landlock | **later**, with M6's host launches |
| OD-7 | `aarch64` | ship the compiled program, fail closed if it lacks a call; or refuse `net.http` there until a job exercises it |

## Consequences

**Positive.** An origin that compromises a worker holds a process that can
read and write the descriptors it was handed, allocate, and exit. The broker
hands nothing to a process it has not seen confined. A credential's memory
is kept off swap, or the hop does not happen.

**Negative.** A new dependency in the broker. A small cost per hop. A
deployment with swap must cap the broker's cgroup or acknowledge it. Other
architectures than `x86_64`/`aarch64` lose `net.http` until reviewed.

## Alternatives considered

A filter on the whole broker through systemd's `SystemCallFilter=` (the
broker needs sockets, `execveat` and the runtime client: far wider); seccomp
in the launch helper (M4d's targets: no production launch before M6); a
handwritten installer with `unsafe` (the workspace forbids it; a reviewed
crate's two lines instead); `libseccomp` (a C library and its build); a
setuid launcher (a root TCB); `MCL_FUTURE` locking (unbounded failure mode).
