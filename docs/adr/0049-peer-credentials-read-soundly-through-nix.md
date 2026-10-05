# ADR-0049: Peer credentials are read soundly, through `nix`; a pid the kernel cannot name is no pid

**Status:** Accepted · **Date:** 2026-10-06 · **Amends:** [ADR-0019](0019-language-rationale-v2.md) (the authority's dependency set: `nix` and `memoffset`), [ADR-0035](0035-m3-authority-dependency-set.md) (§3: peer credentials through `rustix`), [ADR-0041](0041-m3e-authenticated-dwkp-transport.md) (the DWKP server's peer read), [ADR-0043](0043-m4b-private-broker-channel-and-brokered-fs-read.md) (§1: both ends of the private channel's peer check), [ADR-0045](0045-m4d-process-execution-broker.md) (the launch helper's parent check) · **Refines:** [ADR-0048](0048-m5b-proxy-only-topology-and-connect-proxy.md) (its "Revisit if" on a sound peer-credential read is now met)

> **`SO_PEERCRED` is read through `nix`'s safe `getsockopt`, which returns
> the kernel's `ucred` as it is.** The kernel reports a pid of **0** for a
> peer in a pid namespace the reader cannot see; `rustix` 1.1.5 read that
> into a non-zero `Pid`, which is undefined behaviour. Each daemon now has
> one reader. A pid of 0 is recorded as no pid, the uid decides exactly as
> before, and the launch helper never takes a peer it cannot see for its
> parent. The authority's closure grows by `nix` and `memoffset`.

## Context

Four places identify a Unix-socket peer through the kernel (`SO_PEERCRED`):
the authority's DWKP server (`server/peer.rs`, [ADR-0041]), the authority's
end of the private channel (`broker/link.rs`, [ADR-0043] §1), the broker's
listener (`listener.rs`, ADR-0043 §1), and the broker's launch helper, which
proves its control socket's peer is its parent broker (`process/helper.rs`,
[ADR-0045]). All four used `rustix::net::sockopt::socket_peercred`.

M5b measured what that read does with a peer the reader cannot see: on
Docker Desktop, a container connecting to a socket in the WSL distribution
is reported as **uid 10002, gid 10002, pid 0** ([ADR-0048] §3). The kernel's
answer is right: `SO_PEERCRED` translates the peer's pid into the reader's
pid namespace, and a process outside it has no number there. `rustix` 1.1.5
is not: its generic `getsockopt` reads the option into a
`MaybeUninit<UCred>` and calls `assume_init`, and `UCred.pid` is a
`Pid(NonZeroI32)`. A zero there is undefined behaviour. In practice the
niche made the `io::Result<UCred>` decode as an error with a meaningless
code (measured: `Uncategorized`), so every caller failed closed — by
accident, not by a decision. 1.1.5 is the newest release and `rustix`'s
main branch reads it the same way.

**Who can reach it.** Only a peer outside the reader's pid namespace: one
in an ancestor or a sibling namespace. Every namespace a local user can make
is a descendant of the one they are in, so a daemon in the host's initial pid
namespace sees every local process with a real pid. The undefined read is
reached when a daemon runs inside a pid namespace — a container, a WSL
distribution (each has its own) — and something outside it connects, as
Docker Desktop's containers do.

Nothing safer was available without a new crate: the standard library's
`UnixStream::peer_cred` is still unstable in the pinned Rust 1.98.1; no
crate already in the lockfile offers a sound read; and a hand-written
`getsockopt` would be `unsafe`, which the workspace forbids.

## Decision

### 1. The read

Each daemon has exactly one reader of a peer's credentials, and it calls
`nix::sys::socket::getsockopt(socket, sockopt::PeerCredentials)`. `nix`
reads the option into a `libc::ucred`, three plain integers, so any value
the kernel writes is a value; it returns uid, gid and pid as they are.

| daemon | reader | its callers |
|---|---|---|
| authority | `server/peer.rs` (`peer_credentials`) | the DWKP server; `broker/link.rs`, which no longer reads the option itself |
| broker | `peer.rs` (`of`) | `listener.rs`; the launch helper |

### 2. What a pid of 0 means

A pid that is not positive — the kernel's 0 for a peer this process cannot
see — is **no pid**, never a guess and never 0 in a record:

- **The DWKP server and the private channel judge by uid alone**, as ADR-0041
  and ADR-0043 already decided: the uid is the subject, and the pid is
  diagnostic (pids are recycled, so none ever scoped anything). A listed uid
  in another pid namespace is served; an unlisted one is refused and
  audited with its uid and **no** `pid` field. Before this ADR such a peer
  was refused by the undefined read's accidental error, which was never a
  decision; refusing it deliberately was considered and rejected
  (Alternatives).
- **The launch helper never takes a peer it cannot see for its parent.** Its
  check is the same uid *and* a visible pid equal to its parent's. A broker
  and the helper it spawns share a pid namespace, so the honest case always
  has a pid; a hidden peer, or a parent the helper cannot see, is not
  authentic and the helper exits having done nothing.

### 3. Dependencies and the TCB

`nix` 0.31.3 is already pinned, already in the lockfile, and already linked
by the broker (`process`, `fs`; ADR-0045). Its `socket` feature adds one
crate to the lockfile, `memoffset` 0.9.1 (offsets for socket-address
structures), whose build script uses `autocfg`, already locked. The
workspace entry now enables no feature of `nix`, and each crate names the
ones it uses: the authority **`socket` only**, on Linux only; the broker
`process`, `fs`, `socket`; the probe what it had.

The authority's measured closure (`dwcheck closure`; `cargo tree -e
normal,no-proc-macro`): Linux x86_64 and aarch64 **98 → 100** third-party
crates (`nix`, `memoffset`); the union over every target **147 → 149**. Its
build-only list gains `cfg_aliases` (nix's build script) and `autocfg`
(memoffset's); neither compiles C. `nix`'s other dependencies — `libc`,
`bitflags`, `cfg-if` — were already linked (`libc` through `getrandom`
since M4e). `rustix` stays in the authority for the filesystem resolver
(ADR-0042), the private channel's descriptor passing (ADR-0043) and its own
hardening, and no longer reads peer credentials there. Licences: MIT
(`nix`, `memoffset`, `cfg_aliases`), MIT/Apache-2.0 (`autocfg`); `cargo
deny` clean.

No DireWolf code gains `unsafe`; `nix`'s FFI is its own, as `rustix`'s was.

### 4. Architecture rules

- **TX043** (new): `nix` is named only in `crates/dwkd-authority/src/server/peer.rs`,
  `crates/dwkd-broker/src/peer.rs` and the launch helper; a `use nix as _;`
  acknowledgement is not a finding. Violation fixture: a second peer reader
  in the authority; the fixture's three exempt files name `nix` and are not
  findings.
- **TX023** keeps the exec and the steps before it in the launch helper and
  gives up its pattern for the name `nix` to TX043.
- **TX008** drops its exemption for `server/peer.rs`, which no longer names
  `rustix`.

### 5. Evidence

- The real kernel, a peer the reader cannot see: the broker's launch tests
  (`process::tests`, which may start a process) make a socket pair and hand
  one end, as stdin, to a copy of the test run under `unshare --user
  --map-current-user --pid --fork`. A socket pair carries its maker's
  credentials, and the maker is outside the copy's pid namespace. The
  broker's reader reports the uid and no pid, and the helper's check refuses
  the peer as its parent. Measured: `HIDDEN-PEER uid=1000 pid=none
  parent=false`. With `rustix`'s read put back, the same test gets an error
  (`Uncategorized`) and fails. Where unprivileged user namespaces are not
  available, it says NOT EXERCISED.
- The conversion — a pid of 0 or below is no pid — is unit-tested in both
  daemons, and each reader is tested against the real kernel for a peer it
  can see.
- Not shown: a whole daemon serving a peer it cannot see. A daemon in an
  unprivileged user namespace sees the root-owned ancestors of its socket
  directory as owned by the overflow uid and refuses to start (measured: the
  broker, `/tmp is owned by uid 65534`), and that check is not weakened for
  a test. The authority's own reader is shown for the hidden case only
  through the shared conversion, because the authority's sources may start
  no process (TX010).

## Consequences

**Positive.** No reader of a peer's credentials is undefined behaviour for
any value the kernel can return. A pid the kernel cannot name is handled by
a stated rule instead of an accident, and the audit says "no pid" rather than
an invented one. Each daemon reads credentials in one place.

**Negative.** The authority links two more crates and `nix`'s socket code: a
larger TCB to buy back soundness. A uid-listed peer outside the daemon's pid
namespace, refused by accident before, is now served — which is what ADR-0041
and ADR-0043 say a uid means. The hidden-pid case is shown against the real
kernel only where unprivileged user namespaces exist, and only for the
broker's reader.

## Alternatives considered

- **Upgrade `rustix`.** 1.1.5 is the newest release and its main branch has
  the same typed read; no release fixes it.
- **The standard library's `UnixStream::peer_cred`.** Unstable in Rust
  1.98.1; the workspace builds on stable.
- **A hand-written `getsockopt`.** `unsafe`, which every DireWolf crate
  forbids (ADR-0035).
- **A patched copy of `rustix`.** A fork of a TCB crate to maintain by hand,
  for the one function `nix` already offers soundly.
- **Keep relying on the error.** Undefined behaviour is not a mechanism: a
  compiler, an optimisation level or a `rustix` change can make it anything.
- **Refuse a peer whose pid cannot be seen.** The pid never decided anything;
  refusing on it would key identity to pid-namespace topology and turn away
  a containerised runtime whose uid is listed.

## Revisit if

- `rustix` publishes a sound peer-credential read (an optional pid, or a
  checked one): the authority could drop `nix` again.
- The standard library stabilises `UnixStream::peer_cred` with an optional
  pid: prefer it to either crate.
- ADR-0048's egress socket adds a peer-uid check after `accept` as defence in
  depth, which this read now makes possible (it is not added here; the
  directory's ACL remains that socket's control).

[ADR-0035]: 0035-m3-authority-dependency-set.md
[ADR-0041]: 0041-m3e-authenticated-dwkp-transport.md
[ADR-0043]: 0043-m4b-private-broker-channel-and-brokered-fs-read.md
[ADR-0045]: 0045-m4d-process-execution-broker.md
[ADR-0048]: 0048-m5b-proxy-only-topology-and-connect-proxy.md
