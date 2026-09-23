# ADR-0041: M3e — the authority serves DWKP on a Unix-domain socket to peers the kernel identifies, one fresh lease holder per connection

**Status:** Accepted · **Date:** 2026-09-23 · **Amends:** [ADR-0019](0019-language-rationale-v2.md) (the authority dependency set gains `rustix` and the crates it brings) · **Records:** what [ADR-0035](0035-m3-authority-dependency-set.md) §3 decided, as M3e actually linked it · **Refines:** [ADR-0000](0000-authority-plane-separation.md) (the process boundary is now a running process), [ADR-0011](0011-session-concurrency.md) (a lease holder is one accepted connection), [ADR-0018](0018-authority-broker-split.md) (the runtime reaches only the authority), [ADR-0028](0028-policy-input-ownership.md) (the subject is a policy input the runtime cannot supply), [ADR-0029](0029-packaging-runtime-first-decoupled-authority.md) (platform assurance), [ADR-0032](0032-wire-contract-framing-strict-json-and-jcs.md) (which protocol errors close a connection), [ADR-0039](0039-durable-authority-state.md) (transport audit events)

> **The runtime cannot lie about who it is.** It may choose bytes; it may not
> choose identity. It may choose a session id; it may not choose the lease
> holder. It may open a socket; it may not turn that socket into authority.

## Context

M3d built the authority as a library that trusts its caller: an
`AuthenticatedSubject` is whatever in-process code asserts, and a
`LeaseHolder` comes from `Authority::connect`, which M3d's tests called. Until a
real process stood between an untrusted runtime and that library, every M3
claim was a claim about an API, not about a boundary. M3e is the milestone that
makes the boundary exist:

```text
untrusted client process
      │  Unix-domain stream socket
      ▼
dwkd-authority serve
      │  kernel peer credentials (SO_PEERCRED) → operator's closed uid list
      ▼
Authority::connect(subject)      — one fresh LeaseHolder per accepted socket
      │  strict DWKP decode, handshake first
      ▼
Authority::dispatch(caller, request)   — the M3d state machine, unchanged
```

ADR-0035 selected `rustix` for peer credentials and stated that nothing would
fake a uid on a platform without one. ADR-0040 reconciled the M3 wire so that
every request has a truthful answer, which left M3e nothing to add to the
protocol: its job is to transport it.

## Decision

### 1. Local transport: a Unix-domain stream socket, and nothing else

`dwkd-authority serve` binds one `std::os::unix::net::UnixListener`. There is no
TCP listener, no localhost fallback, no HTTP, no TLS, no WebSocket and no
async runtime: "no Unix socket here" means the server is unavailable, never
that it weakens to something else. `architecture.toml` TX007 keeps `std::net`,
the TCP types and the async/HTTP/TLS stacks out of `server/`; TX009 keeps a
listener out of every other product crate, including the broker (ADR-0018:
runtime → authority, never runtime → broker).

### 2. The socket name is part of the boundary

Peer credentials stop a local process impersonating the runtime to the
authority. They do nothing to stop the runtime impersonating the **authority**
to a later client — the CLI, a restarted runtime — by removing the socket and
binding its own at the name. So the name is protected, and the server refuses
to serve from a name it cannot protect:

| what | rule |
|---|---|
| the socket path | absolute; its final component is never followed — a symlink there is refused, whatever it points at |
| the **IPC directory** (the socket's parent) | a real directory, **owned by the authority's uid**, **no group or other write bit**. Created `0711` when absent (others may reach the socket; they cannot list, create, remove or rename in it). An operator who wants the filesystem to narrow who can even connect pre-creates it `0710` with the runtime's group; the server accepts any mode without a group/other write bit |
| every ancestor | after resolving symlinks once and proving by `(device, inode)` that the result is the directory that was checked (the ADR-0039 state-directory rule, reused), owned by root or the authority and not group/other-writable **unless sticky** (`/tmp`), where no one can rename an entry they do not own |
| the socket file | bound only after all of the above holds; mode set to `0666` |
| one server per name | an exclusive lock on `<name>.lock` in the IPC directory, held for the life of the process |

The socket's mode is **not** DireWolf's access control; the kernel-reported uid
is. A bind creates the socket with `0777 & ~umask`, which is never wider than
`0666` in the one respect that matters for a socket (`connect` needs write),
and the directory is final before the bind — so there is no pre-permission
window, and no `umask` manipulation (which would need `unsafe`).

The authority learns its own effective uid without `libc`: a file created
`O_EXCL` in the IPC directory is owned by the creating process's effective uid
(M3d's state-directory probe, reused). A `--allow-uid` naming that uid is
refused unless the operator also passes `--allow-authority-uid`, which the
server announces on stderr as reduced assurance: a peer with the authority's
uid can open `kernel.db` directly, so the process boundary does not constrain
it. It exists for one-user development machines and tests, and it is never
implied.

### 3. Stale sockets

A killed authority leaves its socket file. Under the lock, the name is
inspected with `lstat` and removed **only** if it is a socket, owned by the
authority's uid, inside the checked IPC directory, and `connect` to it is
refused (nothing listens), with its `(device, inode)` re-checked immediately
before the unlink. A regular file, a directory, a symlink, a FIFO, a socket
owned by anyone else, or a socket something is listening on is never removed:
the server refuses to start and names what it found. An orderly stop removes
the socket only if the name still holds the inode it bound.

### 4. Peer identity: the kernel's, before a byte is read

For each accepted connection, in this order and before any byte is read:

1. `rustix::net::sockopt::socket_peercred` — the credentials the kernel recorded
   when the peer called `connect(2)`: its **effective uid** and its pid then.
2. The operator's peer policy: is that uid in the explicit, closed list given
   with `--allow-uid`? No wildcard, no group rule, no user-name match, no
   exception for root (uid 0 is admitted exactly when listed).
3. The connection limit.

A refused peer's socket is closed unanswered: it learns nothing about DWKP, its
versions, sessions, epochs, runs or policy — not even whether its bytes parse,
because none are read. The refusal is audited with the kernel's uid and pid.

**The subject is the uid.** Never a DWKP field (none exists, and ADR-0028 forbids
one), an environment variable (the server clears nothing and reads nothing from
its environment), the socket's path, a command line or a runtime database. The
pid is **diagnostic only**: pids are recycled, so it appears in audit records
and scopes nothing — it is not part of `(subject, session_id, idempotency_key)`.

### 5. One connection, one holder

After admission the connection's thread asks the authority worker for
`Authority::connect(AuthenticatedSubject::unix_uid(uid))` — **exactly once**. The
`CallerContext` it gets back (the subject and a fresh `LeaseHolder`) lives on
that thread's stack, is passed to nothing else, and dies with the connection.
There is no map from uid, pid, session, request id or token to a holder.

So two connections from one uid are **one subject and two holders**, and the
second cannot become the writer of the first's session by virtue of the uid: it
is `LEASE_HELD` on acquire and `STALE_EPOCH` on every fenced request, which is
M3d's rule (ADR-0039 §6, §7) doing what it was built for.

### 6. Disconnect invents nothing

A socket closing ends the connection and nothing else. It is not
`ReleaseLease`, `ReleaseRun`, a lease rotation or a resumption: the lease stays
exactly as M3d's release, expiry and restart rules leave it, and the object
able to present its holder is gone. A reconnect is a stranger that waits for
expiry — or for an authority restart, which invalidates every holder. No
accepted ADR asks for implicit disconnect cleanup, and adding one would be a
state-machine change, not a transport detail.

### 7. The connection state machine

```text
AwaitingHandshake ──Handshake with a common version──▶ Established(v)
      ├── Handshake with no common version ──▶ PROTOCOL_VERSION_UNSUPPORTED, close
      └── anything else ─────────────────────▶ close, no answer
Established(v) ──one of the six authority requests in envelope v──▶ dispatch, stay
      ├── a request in another envelope version ──▶ PROTOCOL_VERSION_UNSUPPORTED, close
      ├── a second Handshake ─────────────────────▶ close, no answer
      └── a response or an event ─────────────────▶ close, no answer
```

The handshake uses `dwk-proto`'s own negotiation (`negotiate`, the
`HANDSHAKE_ENVELOPE_VERSION`, a floor equal to the lowest supported version, so
an offer cannot pull a connection below it). This build speaks envelope version
1. Message schema versions stay their own strict contracts: the three ADR-0040
responses are sent at version 2 and only 2, from the registry.

**No authority request is dispatched before a handshake has been accepted**, by
construction: the transition function (`server/protocol.rs`, pure, unit- and
property-tested) returns "dispatch" only from `Established`, and the only way in
is an accepted handshake.

An ordering violation gets **no answer**. `direwolf.protocol.error` says the
bytes did not form a valid message (PROTOCOL.md §2.1); a request before the
handshake, a second handshake or a response sent to the authority all decoded
perfectly, and no wire code says "out of order". Borrowing
`PROTOCOL_UNKNOWN_OPERATION` would tell the peer to repair a message that is
not broken. The connection closes and `audit.log` records why.

### 8. Protocol errors: which close, which continue

| what arrives | answer | connection |
|---|---|---|
| an authority request the state layer answers — including `direwolf.authority.refused` | the response | **continues** |
| a framing error: empty, oversized (from the header alone), reserved content type | `direwolf.protocol.error` | **closes**: a length-prefixed stream has no trustworthy next boundary (ADR-0032) |
| end of stream inside a frame | `PROTOCOL_FRAME_TRUNCATED` if the peer still reads | closes; the partial request never reaches the authority |
| a complete frame that does not decode (UTF-8, JSON, depth, duplicate key, number, unknown or forbidden field, unknown or reserved operation, unsupported version) | `direwolf.protocol.error` | **closes** |
| a handshake with no common version | `PROTOCOL_VERSION_UNSUPPORTED`, naming the supported range | closes |
| an ordering violation (§7) | none | closes |
| the authority cannot answer truthfully (§10) | none | closes |
| end of stream between frames | none | a normal disconnect, not a violation |
| a deadline (§9) | none | closes |

Closing on every protocol error, not only on framing ones, is deliberate: DWKP's
peers ship together (ADR-0023), so malformed input is a bug or an attack;
ADR-0032 already accepted that "a single bad frame closes the connection"; and a
closed connection costs a probing client its holder, so a decoder is not an
oracle to be walked in a loop on one connection. A protocol error answering
bytes that never decoded names no cause (`causation_id` is optional on that
message for exactly this reason).

### 9. Bounds

| resource | bound |
|---|---|
| connections served at once | **32** (`MAX_CONNECTIONS`). An allowed peer over it is accepted by the kernel, identified, refused before a byte is read, given no holder, and audited |
| requests in flight per connection | **1**: read a whole frame, decode, dispatch, write the whole response, then read the next. No pipelining, multiplexing or stream ids; responses come in request order |
| frame body | 1 MiB, from the header alone (`dwk-proto`'s `FrameDecoder`) |
| buffered per connection | one frame body plus a 16 KiB read chunk |
| handshake | complete within **5 s** of accept |
| one frame | complete within **5 s** of its first byte — a peer trickling a byte at a time holds a slot for a bounded time |
| silence between frames | the lease TTL **+ 5 s**: a connection quieter than a lease's lifetime cannot be keeping one alive |
| one response write | **5 s**: a peer that stops reading loses its connection and blocks no one else |
| the authority worker's queue | 64 jobs |
| the kernel's accept backlog | `SOMAXCONN`; beyond it `connect` fails in the kernel |

Timeouts are availability controls, not verdicts: a timeout closes a connection
and is never answered with `STALE_EPOCH` or any other authority reason. They are
not audited.

### 10. One worker owns the authority

The `Authority` lives on one worker thread; connection threads send it jobs —
*mint a holder*, *dispatch this decoded request*, *record this transport event* —
over a bounded channel. Every M3 operation is one short `BEGIN IMMEDIATE`
transaction and an audit `fsync`, and SQLite is a single-writer store, so
letting connection threads contend through SQLite's busy handler would only turn
contention into `AuthorityError::Busy` — which is not `STALE_EPOCH`, not
`LEASE_HELD`, not a denial and not a protocol error, and so has no truthful wire
answer. With one owner no two authority transactions contend and `Busy` is
unreachable from the server (the state directory's lock excludes any other
writer). Correctness still comes from the state layer — transactions, the epoch
fence, idempotency — not from this serialisation, which buys predictability.

What `Authority::dispatch` returns decides the connection's fate:

| `dispatch` returns | the connection | the server |
|---|---|---|
| a response body | answered | serves on |
| `Poisoned` (SQLite corruption or I/O error, audit I/O, audit divergence) | closed, unanswered | **stops**: the worker refuses everything, the accept loop ends, the socket is removed, and `serve` exits with status 4 |
| anything else — `Busy`, an invariant, an exhausted id or epoch counter, a constraint | closed, unanswered: no wire answer says it truthfully | serves on |

A poisoned authority is never served from again in that process, and nothing
creates a fresh store: the next start re-verifies the files, and a structural
fault's quarantine marker keeps it shut (ADR-0039 §5).

### 11. Transport audit events

Four new record kinds, written through M3d's transactional outbox and `fsync`ed
like every other, through one narrow state-layer entry point,
`Authority::record_transport_event`, which takes a closed `TransportEvent` —
never text, bytes or a field name:

| event | fields | when |
|---|---|---|
| `transport.peer_refused` | `uid`, `pid`, `reason: uid_not_allowed` | the kernel's uid is not in the peer policy |
| `transport.connection_refused` | `uid`, `pid`, `reason: connection_limit` | an allowed peer over the limit |
| `transport.protocol_violation` | `uid`, `holder`, `violation`, `code` | a framing, decoding, version or ordering violation closed a connection |
| `transport.audit_suppressed` | `class`, `count` | the rate limit withheld records of a class |

Every field is kernel-reported (`uid`, `pid`) or authority-chosen (`holder`, a
closed `violation` word, a closed `ErrorCode`); no peer byte, frame or detail
string is recorded. A record is a few hundred bytes.

**Bounded.** Each class may write **32 records per 60-second window**; beyond
that the worker counts, and writes one `transport.audit_suppressed` record with
the count when the window ends (at the next event of that class, or on the
worker's one-second idle tick). The worst case an attacker can drive is therefore
three classes × 33 fixed-size records a minute, whatever its connection rate,
and suppression is itself on the record. The one-off events an evaluation
provokes are far below the bound and are always written.

Timeouts, clean disconnects and accepted connections are not audited: none is a
refusal of authority, and one record per connection would be telemetry.

`audit.log` remains the only security record. The server's stderr carries
bounded operational lines (never a peer's bytes); nothing reads them back, and
nothing decides anything from them.

### 12. Configuration is the operator's, on the command line

```text
dwkd-authority serve --state-dir DIR --socket /abs/path/kernel.sock
                     --allow-uid UID [--allow-uid UID ...] [--allow-authority-uid]
                     (--policy-shipped NAME | --policy-file PATH ... --policy-profile NAME)
                     --mode safe|balanced|power [--ceiling CAP ...]
                     [--lease-ttl-ms MS] [--allow-host-execution]
```

Typed, strict (an unknown, repeated or valueless flag is a usage error, exit 2),
bounded (64 uids, the policy loader's own file and source bounds, the ceiling
bound), and read from nothing else — no environment variable, no config
framework, and no DWKP operation (`ConfigureAuthority`, `SetAllowedUid`,
`InstallProfile` and the like do not exist and must not). Policy files are read
by the state layer with a size bound checked before the read. Agent profiles,
skills and workspaces are installed by the operator's own tooling through M3d's
in-process `OperatorBootstrap` **before** a runtime connects; nothing on the wire
installs one. M17 owns the product CLI; this is the smallest honest entry point.

Exit codes: 2 usage, 3 unsupported platform, 1 did not start, 4 stopped because
the store was poisoned. The server has no signal handling: `SIGTERM` or
`SIGKILL` ends the process where it stands, the socket file stays behind, and
the next start removes it under §3's rules. No graceful `SIGTERM` is claimed.

### 13. Platforms

| platform | status |
|---|---|
| **Linux** | **The assurance claim.** `SO_PEERCRED` through `rustix`'s safe wrapper, which on x86_64 and aarch64 makes raw syscalls through `linux-raw-sys` with no libc. Everything in this record is implemented and exercised, including a real foreign uid (§15). |
| **macOS** | **Unsupported, stated.** macOS has `LOCAL_PEERCRED`/`getpeereid`, a different mechanism. `rustix` 1.1.5 does not expose it on Apple targets, stable Rust's `UnixStream::peer_cred` is still unstable (rustc 1.98.1), and a hand-written `getsockopt` would be `unsafe` in the authority, which ADR-0035 rejected. `serve` exits 3 with a sentence saying so, **before creating, opening or starting anything**. Nothing substitutes the server's own uid for a peer's. `verify-audit`, `--version`, `--help` and the library work. `rustix` is not linked on macOS at all. |
| **native Windows** | **Unavailable.** No Unix peer credential and no accepted design for authenticating a named-pipe client; no loopback-TCP "equivalent", no user-name-as-uid. `serve` exits 3 before touching anything; the rest works. WSL2 is the supported path (ADR-0029). `rustix` is not linked. |

### 14. `rustix` enters the TCB — measured

Measured on 2026-09-23 with rustc 1.98.1, from this workspace's resolution
(`cargo tree -p dwkd-authority --edges normal --target <triple>`,
`cargo metadata --locked`, `dwcheck closure --report`), not predicted.

```toml
rustix = { version = "=1.1.5", default-features = false, features = ["std", "net", "time"] }
# declared by dwkd-authority under [target.'cfg(target_os = "linux")'.dependencies]
```

`time` is still required: without it `net`'s `sockopt` module does not compile
(re-measured). `rustix` 1.1.5 is the newest release (`cargo info`).

**Runtime-linked, per target** (added by M3e; `bitflags` 2.13.2 and `libc`
0.2.189 were already reviewed):

| target | added |
|---|---|
| `x86_64-unknown-linux-gnu` | `rustix` 1.1.5, `linux-raw-sys` 0.12.1 |
| `aarch64-unknown-linux-gnu` | `rustix` 1.1.5, `linux-raw-sys` 0.12.1 |
| `powerpc64le`/`s390x-unknown-linux-gnu` (rustix's libc backend) | those two, and `errno` 0.3.14 |
| `aarch64`/`x86_64-apple-darwin`, `x86_64-pc-windows-msvc` | **nothing** — the dependency is Linux-only |

**The exact gate's union** (it does not evaluate target conditions, so the
allowlist must hold on every target Cargo resolved): **25 runtime-linked
crates**, up from 20: `rustix`, `linux-raw-sys`, `errno`, `windows-sys` 0.61.2
and `windows-link` 0.2.1. The last two are rustix's and errno's `cfg(windows)`
dependencies; since the authority depends on rustix for Linux only, **no
supported build links them**, and they are reviewed because an allowlist that
must hold on every target has to name them. Every licence is already in
`deny.toml` (`rustix`, `linux-raw-sys`: Apache-2.0 WITH LLVM-exception OR
Apache-2.0 OR MIT; the rest MIT OR Apache-2.0).

**Build-only:** unchanged — `cc`, `find-msvc-tools`, `shlex`, `pkg-config`,
`vcpkg` (5). `rustix` has a build script, which probes the compiler for its
backend and emits cfgs; it compiles no C.

**Unsafe:** DireWolf's Rust has **none** — the workspace's
`unsafe_code = "forbid"` is unchanged, and no FFI was written. The `unsafe`
that performs the syscall is inside `rustix` and `linux-raw-sys`, maintained
libraries whose purpose is that boundary. SQLite's C is still in the
authority's address space (ADR-0039), so this record does not say the authority
is memory-safe; it says its Rust is.

`architecture.toml` records the five crates with their reasons; TX008 allows
`rustix` in `server/peer.rs` alone; RS010–RS015 are unchanged and green.
`fuzz/Cargo.lock` carries the same versions.

### 15. Evidence: real processes, and a real second uid

The M3e evidence is **real-process**: tests spawn the released `dwkd-authority`
binary (`CARGO_BIN_EXE_dwkd-authority` — the operator's `serve`, not a test
server), prepare state through the in-process operator API **before** the server
starts, and talk to it from another process over the socket, reading
`audit.log` through a verifier-backed reader (`read_audit_log`, new in the state
API). M3d's in-process suites stay what they are and are not counted as boundary
evidence.

| suite | what it proves |
|---|---|
| `transport_server.rs` | every request round-trips with its response bound to it; the subject is the kernel's uid; an unlisted uid is refused before a byte is read, with the kernel's pid in the record; the authority's own uid is never an implied peer; one uid on two connections is two holders; 24 concurrent connections, 24 distinct holders; a reconnect inherits nothing and a disconnect releases nothing; a connection left behind by its own rotation is fenced; `SIGKILL`, restart over the dead socket, every holder forgotten, `ADMISSION_ENDED`; a poisoned store stops the server (exit 4); socket-name attacks by the authority's own uid; usage errors |
| `transport_hostile.rs` | the hostile DWKP client of EVALS.md §3: framing, 17 decoder attacks including the reserved `ToolInvoke`/`CanonicalPreview`/`ModelCall` names, 22 attempts to assert a policy input (`taint_level`, `origin`, `privacy_class`, `workspace_sensitivity`, active skills, skill trust, a standing grant, the policy mode, `subject`, `uid`, `lease_holder`) in the envelope and in the payload, the handshake-first protocol, and every state fence a runtime reaches. Each violation is matched to its `transport.protocol_violation` record; "never reached `Authority::dispatch`" is proven by the state layer writing no record for it |
| `transport_stress.rs` | the connection limit, slowloris (silent, partial frame, trickle), a peer that never reads, connection and replay storms, and the audit rate limit — while a well-behaved peer is served |
| `transport_foreign.rs` | a client running as a **different OS user** (`sudo -n -u $DW_PEER_AS`, from the harness): refused on the uid the kernel reports, which equals the client's own `geteuid()`; nothing parsed; a 100-connection flood from it while the allowed peer is served; and that user cannot unlink, rename over, bind beside or at, shadow, move or chmod the socket or its directory |

The M3 evaluations run these suites and the existing lattice and engine evidence
(§16). The cross-uid suite needs a second identity; on a machine without one it
is **not exercised** — `#[ignore]`d in `cargo test`, failing
`make authority-transport-evidence`, and listed as NOT EXERCISED (never passed)
by a local `make eval-check`. CI's Linux jobs provide one (`nobody`, through the
runner's passwordless sudo) and run the eval gate strictly (§16).

### 16. M3 evaluations are active

`AVAILABLE_MILESTONES` gains `"M3"`, and the five properties that waited for it
move from the non-gating `pending-kernel` suite to **`authority-security`**, a
**merge gate**, each with a registered runner that measures the product:

| eval | runner | where it can run |
|---|---|---|
| `hostile-dwkp-client` | `transport_hostile` + `transport_stress`, 65 expected cases | Linux |
| `peer-credential-check` | `transport_foreign`, 4 expected cases | Linux, with a second identity |
| `epoch-fencing` | `transport_server`'s fencing, restart and poison cases, 7 | Linux |
| `policy-denies-by-default` | each shipped pack's `default` rule, with `rule_source`, audited — in process, because a proposal over DWKP is `NO_CANONICAL_ACTION` until M4 | everywhere |
| `capability-attenuation` | 20 000 generated delegation chains over the real lattice (the 10⁶ campaign stays `make capability-evidence`) | everywhere |

Every expected case is listed in the runner, so a case that stops running is a
failure naming it; every transport evidence line names the binary that served
it, which must exist and be `dwkd-authority`; and each result reports how many
cases were contained at each layer — peer gate, framing, decoder, connection
protocol, state fence, capability/policy, resource bound, filesystem — so
defence-in-depth erosion is visible (EVALS.md §3).

The harness gains two closed, runtime-evaluated preconditions: `platforms`
(`linux`, `macos`, `windows`) and `needs` (`second-identity`). An unmet one
yields SKIP with a generated "not exercised" reason — never a pass, never
pending (the property exists). `make eval-check` lists such evals separately;
with `DW_EVAL_REQUIRE_EXERCISED=1`, as CI's eval job runs it, not exercising a
gating eval **fails** the gate. The baseline records `pass` for all five: the
expectation of the gate that can run them.

### 17. The M3e / M4 boundary

M3e transports the M3 wire and adds nothing to it: **zero DWKP schema delta**.
`ToolInvoke`, `ToolCancel`, `ModelCall`, `CanonicalPreview`, `CreateArtifact`,
`ReadArtifact`, `QueryBudget`, `QueryInvocationStatus`, `ListVisibleTools`,
`SpawnSubagent`, `McpOpen`, `McpClose` and `ChannelSend` remain reserved —
indistinguishable on the wire from an invented name, with no handler, stub or
"not implemented" answer. `QueryAuthority` with `proposed` is still
`NO_CANONICAL_ACTION`: the socket does not make an execution environment, a
destination address, argv safety, a canonical path or an executable identity
appear. There is no broker socket, no filesystem canonicalisation, no
`openat2`, no executable hashing, no DNS, no approval, no budget and no provider.
M4 owns the canonical action, the first tool, the canonicaliser and the private
authority→broker hop.

## Consequences

### Security consequences

- A completely compromised runtime can send the authority any bytes, and cannot
  choose its subject or its lease holder, skip the handshake or the decoder,
  assert a policy input, use a stale epoch or another connection's holder,
  reach a reserved operation, or make `QueryAuthority` decide an action — each
  shown against the real process.
- Another local user cannot speak DWKP to the authority unless the operator
  listed its uid, and cannot replace the socket to impersonate the authority.
- The authority now listens. Its attack surface grows by exactly one socket,
  gated by the kernel's identification before its first read.
- `root` is not special in DireWolf's peer policy, and it can subvert the host
  anyway; this record claims nothing against root.

### TCB consequences

Five crates in the reviewed union, two on the platforms that serve (§14); the
first syscall-wrapper crate in the authority. No HTTP, TLS, async or container
stack; no new C.

### Portability consequences

The server runs on Linux only. macOS and native Windows keep every
non-serving capability and refuse `serve` explicitly. A macOS server needs
either a safe `getpeereid` in a maintained library or an ADR accepting a
reviewed exception; neither exists today.

### Operational consequences

- An operator runs `dwkd-authority serve` with explicit directories, uids and
  policy; the runtime runs as its own user in the listed set.
- A killed server leaves a socket file, which the next start removes safely.
- CI gains a Linux job with a second identity (`nobody`), and the eval gate
  becomes strict there.

### Explicit limitations

- **No graceful shutdown.** `SIGTERM` is not handled; the stale-socket rule is
  the recovery path.
- **Idle and slow peers of an allowed uid hold slots** up to the bounds in §9; a
  compromised runtime can exhaust its own uid's 32 connections and so deny
  service to itself (and to other listed uids). Foreign uids hold nothing.
- **The rate-limit window is 60 s**; a suppression count for a burst is written
  when the window ends, and is lost if the process is killed before then. The
  first 32 records of each class in a window are never lost.
- **ACLs and capabilities (`CAP_DAC_OVERRIDE`) are not inspected** by the
  socket-path checks; the claim is about owners and mode bits, and a privileged
  user is outside the threat model (ARCHITECTURE.md §34).
- **The cross-uid evidence needs a second identity**, which a one-user
  workstation does not have; it is exercised in CI, and reported as not
  exercised elsewhere.
- **macOS and Windows have no server.** That is the honest state, not a TODO
  disguised as support.

## Alternatives considered

**A thread per connection contending through SQLite (no worker).** Simpler, and
M3d's own concurrency evidence shows the store stays correct under contention.
Rejected: the loser of a long contention gets `Busy`, which has no truthful wire
answer, and the server's latency becomes a function of SQLite's busy handler.

**An async runtime (`tokio`/`mio`).** Rejected: a large new TCB closure for a
transport that serves at most 32 local connections with one request in flight
each; the standard library's blocking I/O with timeouts bounds everything the
threat model needs.

**Continue after a decode error.** Framing stays synchronised after a bad body,
so it would be safe for the byte stream. Rejected for DWKP: the peers ship
together, a malformed message is a bug or an attack, ADR-0032 already accepted
closing on a bad frame, and continuing lets one connection probe the decoder
indefinitely.

**Answer an ordering violation with a protocol error.** Rejected: every
available code asserts something false about a message that decoded.

**Socket mode `0660` and a group as the access control.** Rejected as the
*default*: it needs a group the authority would have to be told, and it would
stop a foreign uid at `connect(2)` with `EACCES` — before the kernel's peer
credential, which is the control this milestone must demonstrate. Kept as an
operator choice: a pre-created `0710` IPC directory is accepted.

**`nix` for `getpeereid` on macOS; a hand-written `getsockopt`.** Rejected by
ADR-0035 (size; `unsafe` in the authority), and not revisited here.

**Implicit `ReleaseLease` on disconnect.** Rejected: a state transition no
accepted ADR defines, and one that would let a flaky socket end a lease the
holder still meant to keep.

**A `--config` TOML file.** Rejected for M3e: a second operator-input format
and parser surface for eight values; M17 owns the product's configuration.

## Revisit if

- A maintained, safe API for `LOCAL_PEERCRED`/`getpeereid` appears in a crate
  the authority could link, or `UnixStream::peer_cred` stabilises — macOS could
  then serve with its own, stated, guarantees.
- A Windows named-pipe client authentication design is accepted.
- A DWKP operation needs more than one request in flight per connection, or more
  than 32 connections.
- The authority must accept a peer whose uid alone does not say enough (a
  per-process identity, a signed runtime), which would be a new admission
  design, not a longer uid list.
- `rustix` stops supporting the `linux-raw-sys` backend on a supported target.
