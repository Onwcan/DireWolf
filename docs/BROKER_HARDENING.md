# Deploying the broker's HTTPS exchange workers hardened

What the host must give `dwkd-broker` so that its `net.http` exchange workers
run as [ADR-0053](adr/0053-d11-exchange-worker-confinement-and-secret-memory.md)
decides (Proposed), how the broker checks it, and how to check it yourself.
Nothing here is applied by DireWolf's tooling to a machine on its own: every
setting is the operator's action.

## What the broker enforces by itself

| Property | Enforced | Where |
|---|---|---|
| A worker's syscall filter: no socket, `connect`, `execve`, `fork`, `ptrace`, `open`, signal to another process | always, by the worker before it can receive anything; proved per worker | `http/confine.rs` |
| The broker vouches for each worker from the kernel (filter, `no_new_privs`, untraced, not dumpable) before handing it anything | always | `http/vouch.rs` |
| The start-up window: Yama `ptrace_scope` ≥ 1 or an execute-only broker binary | read at start and before every worker; an open window refuses the hop | `posture.rs`, `http::WorkerPolicy` |
| A credential hop's memory cannot reach swap | read before the broker reads the credential and again for the worker; refused otherwise | `posture.rs`, `http::WorkerPolicy` |

Each refusal can be acknowledged for development only, and is logged
`REDUCED ASSURANCE` at start: `--allow-traceable-workers`,
`--allow-swappable-workers`. A production configuration passes neither.

## Native Linux with systemd (production)

1. **A dedicated system user** for the broker, running nothing else, never
   root, never uid 10001 or 10002 (the sandbox's), never the authority's.
2. **The binary root-owned and execute-only**, so the kernel makes every
   worker non-dumpable at `execve`:

   ```bash
   sudo install -o root -g root -m 0711 dwkd-broker /usr/libexec/direwolf/dwkd-broker
   ```

3. **Yama at 1 or more** as well (`kernel.yama.ptrace_scope`; most
   distributions ship 1). Either 2 or 3 suffices for the broker; both are
   recommended.
4. **A service unit that caps swap at zero**, among its other limits:

   ```ini
   [Service]
   User=dwbroker
   ExecStart=/usr/libexec/direwolf/dwkd-broker serve --socket /run/direwolf/broker.sock --authority-uid 991
   MemoryAccounting=yes
   MemorySwapMax=0
   LimitCORE=0
   NoNewPrivileges=yes
   ```

   A unit file is not proof. The broker reads its own cgroup's
   `memory.swap.max` (and every ancestor's) at start and before every
   credential hop, and logs it:
   `event=deployment_posture … swap=capped:/system.slice/dwkd-broker.service`.
5. **Hibernation disabled**, or its image on encrypted storage: a hibernation
   image holds all of memory, whatever a cgroup or a memory lock says.
6. **Recommended, not required**: `init_on_free=1` on the kernel command line
   (freed pages zeroed at once; a cost on every allocation). The broker
   reports what the command line says (`init_on_free=on|off|default`).

### Verify, read-only

```bash
make d11-posture
```

It prints Yama, the broker binary's owner and mode, swap devices, this shell's
cgroup and where swap is capped to zero, page zeroing, hibernation,
`RLIMIT_MEMLOCK`, and whether `memfd_secret` and Landlock exist -- and changes
nothing. On the running broker:

```bash
journalctl -u dwkd-broker | grep -E 'deployment_posture|REDUCED ASSURANCE|NOTICE'
cat /sys/fs/cgroup/system.slice/dwkd-broker.service/memory.swap.max
```

## A host without swap

No swap device means no anonymous page can be written to swap: credential
hops are performed, re-checked every hop (`swap=no-device`). A swap device
added later is seen at the next hop.

## A host without the optional features

| Missing | Effect |
|---|---|
| Yama | the binary must be execute-only, or the broker refuses to serve (and every hop) |
| cgroup v2's memory controller | a host with swap refuses credential hops; add `MemorySwapMax=0` on a v2 host or run without swap |
| `x86_64` or `aarch64` | no reviewed syscall program: no worker starts, `net.http` is refused |
| `init_on_free` | reported `default`; nothing refused |

## WSL2 (development)

The WSL2 guest is a VM: its swap is a file on the Windows side
(`%Temp%\swap.vhdx` by default), and Windows may page the VM's memory to its
own pagefile, which no Linux setting reaches. A development broker therefore
runs with the acknowledgements, each logged. To give the guest no swap at all
-- optional, and the owner's action:

```ini
# %UserProfile%\.wslconfig
[wsl2]
swap=0
```

It applies only after the WSL VM restarts (`wsl --shutdown` from Windows,
which stops every running distribution). Without restarting anything, a
credential hop can be exercised under a real no-swap cgroup with the user's
own systemd:

```bash
systemd-run --user --scope -p MemorySwapMax=0 -- <command>
```

which is what `make d11-hardening-evidence` does.

## Docker-based evidence

The sandbox evidence (`make sandbox-*-evidence`) starts brokers through its
harnesses with development flags; it does not run credential hops. The
`net.http` and secret evidence acknowledge swap (`--allow-swappable-workers`)
on hosts that have it; the strict refusal is shown by
`make d11-hardening-evidence`.

## Evidence

`make d11-hardening-evidence` runs on any Linux host and reports what it could
not exercise; `DW_D11_PRIVILEGED=1` with passwordless sudo (the hosted job)
adds a root-owned execute-only binary and the Yama-0 counterexample, each
undone after. `make d11-hardening-mutations` weakens each guard in turn.
