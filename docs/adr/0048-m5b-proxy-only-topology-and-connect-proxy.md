# ADR-0048: M5b — the `PROXY_ONLY` topology and the opaque CONNECT proxy

**Status:** Accepted · **Date:** 2026-10-04 · **Amends:** [ADR-0024](0024-sandbox-network-topology.md) (how `PROXY_ONLY`'s one peer is realised: a loopback address in an interface-free namespace, not a veth pair), [ADR-0047](0047-m5a-oci-execution-environment-and-measured-assurance.md) (§4 private protocol version 6; §8 the network invariants; §10 `PROXY_ONLY` exists; §11 labels schema 2 with roles), [ADR-0018](0018-authority-broker-split.md) (the broker gains its one outbound path), [ADR-0043](0043-m4b-private-broker-channel-and-brokered-fs-read.md) (§1: the broker listens on one egress socket per `PROXY_ONLY` environment besides its private socket, and connects to the addresses its proxy pins) · **Refines:** [NETWORK_SECURITY.md](../NETWORK_SECURITY.md) §§1–4, 8 (the sandbox egress path, as built)

> **A `PROXY_ONLY` environment has no route, and exactly one peer.** Its
> network namespace is the runtime's `none` network — loopback only. A
> one-shot setup container adds `169.254.7.1/32` to that loopback; an
> unprivileged relay in the same namespace listens there and forwards each
> connection, unread, to a broker socket mounted into it alone, in a
> directory only the relay's uid may search. Behind that socket the
> broker's CONNECT proxy accepts one strict request per connection,
> checks the target against the run's own exact
> `network.https` grants, resolves the name **once** on the host, refuses an
> answer with any blocked address outright, requires the TLS server name to
> be the CONNECT host before it dials anything, dials only the pinned
> address, and carries bytes it never reads within budgets enforced at the
> socket. It does not terminate TLS, has no CA, changes no trust store and
> injects nothing. A process that ignores the proxy variables has no path —
> measured, not asserted.

## Context

ADR-0024 decided that sandboxed processes reach the network only through an
opaque CONNECT proxy at `169.254.7.1:8080` in a namespace with no default
route and no resolver, and that the proxy enforces the CONNECT host, SNI
agreement, the IP guard, DNS pinning and byte budgets. It described the
namespace as "a veth pair". ADR-0047 built the execution environment and
deferred `PROXY_ONLY` to this slice (M5b of [ROADMAP.md](../ROADMAP.md)).

What M5b must establish, and what it must not do:

- **Contract**: no route to anything but the proxy endpoint; the proxy
  enforces the grant; every bypass a process can attempt — direct TCP and
  UDP, direct DNS, raw, packet and ICMP sockets, another peer, ignoring or
  redirecting the proxy variables — fails, and the mechanism that refused it
  is known; the fronting residual is shown honestly.
- **Not M5b**: `net.http`, redirects, credential egress, a sandboxed
  workload in production (M5c–M5d). The public DWKP is unchanged.

Two facts shaped the realisation. First, the broker is not root and must not
need to be: creating a veth pair and routing to it needs `CAP_NET_ADMIN` in
the host's network namespace, and on Docker Desktop the namespace lives in
another VM distribution the broker cannot touch at all. Second, the fewer
peers a namespace has, the less there is to measure: an interface, a
neighbour table and a route are each something to get wrong.

## Decision

### 1. Scope

The topology, the relay, the broker's per-environment proxy, the grant's
derivation in the authority, the measurement and the lifecycle of all of it,
the evidence, the architecture rules and the eval suite. Nothing runs inside
an environment but the probe (and, in the evidence only, a test fixture via
the runtime's own `exec`).

### 2. The topology as built: a loopback address, not a veth pair

The environment container is created exactly as M5a's, in the runtime's
`none` network: one interface, `lo`. Then, in that namespace:

1. **setup** — a one-shot container (`docker run --rm`), joining only the
   environment's network namespace (`--network container:<environment>`),
   runs the pinned image's relay as `sandbox-relay setup`: one netlink
   `RTM_NEWADDR` adding `169.254.7.1/32`, scope host, to `lo`, then exits and
   is removed by the runtime. It is the one DireWolf container that holds a
   capability: root inside, `--cap-drop ALL --cap-add NET_ADMIN`, read-only
   root, no new privileges, the `oci-strict` seccomp profile, no mount, no
   variable. The relay binary's digest is checked (`docker container cp`,
   tar, SHA-256 against the authority's pin) **before** setup runs; a relay
   that is not the pinned one is never started.
2. **relay** — a long-lived container in the same namespace, uid/gid
   10002 (its own, not the environment's 10001), no capability, read-only
   root, no new privileges, the seccomp profile, bounded (144 pids, 64 MiB,
   0.5 CPU), given exactly one mount: the broker's directory for this
   environment, read-only, at `/run/direwolf-egress`. It runs
   `sandbox-relay serve`: listen on `169.254.7.1:8080`, and for each
   connection connect to `/run/direwolf-egress/proxy.sock` and copy bytes
   both ways — a clean end passed on as a half-close, a failure ending both.
   It parses nothing (TX039).

Inside the namespace there is no route at all (`/proc/net/route` is its
header; IPv6 has only reject routes and `lo`'s), no resolver reachable, and
one listening peer. Measured on Docker Desktop: every external, metadata,
host-gateway, LAN, link-local-neighbour, IPv6, IPv4-mapped and NAT64
destination fails `ENETUNREACH`; the proxy address on any other port fails
`ECONNREFUSED`.

This amends ADR-0024's "veth pair": the namespace has strictly fewer peers
(none but its own loopback), the broker needs no host privilege and no
iptables, and the same construction works on native Docker Engine and on
Docker Desktop's separate VM distribution. Everything else ADR-0024 decided
stands, except that the per-tool proxy configuration it names is not written
here: the environment gets the four standard variables (§8), and routing
package managers is M5d's.

### 3. The broker's socket: the kernel checks the relay's uid on its directory

The broker owns `<its socket directory>/egress/` (0700). Opening a proxy
creates `egress/<environment>/` (0700), binds `proxy.sock` (0666) in it, and
only then gives the directory a POSIX access ACL — the owner everything, the
relay's uid (10002) search, the mask search, group and others nothing (shown
as `0710` with an ACL) — read back and compared byte for byte, all before the
environment is created. A filesystem that cannot keep the ACL refuses the
proxy (`PROXY_UNAVAILABLE`). Destroying the environment closes the listener,
ends its tunnels (`ENVIRONMENT_CLOSED`) and removes both. A broker that
starts removes what a dead one left there — its own directories holding at
most its own dead socket — and nothing else.

**Who can connect is the kernel's permission check on the directory, by
uid.** The directory is bind-mounted, read-only, into exactly one container,
the relay, and its ACL goes wherever it goes. Its location alone would not be
a boundary: Docker Desktop on WSL2 re-exposes every bind source at
`/mnt/wsl/docker-desktop-bind-mounts/<distribution>/<hash>`, beneath a
world-searchable directory that every WSL distribution shares and that
outlives the container (measured). There the 0700 root is not on the path,
and only the directory's own permissions stand between another uid — the
cognition side's included, whose M9 launch profile keeps Unix sockets — and
the socket. With the ACL only the broker's uid, the relay's uid and
privileged root can traverse it, wherever it appears. Measured: through the
same directory mounted into a test-only container, the environment's uid,
root without capabilities, `nobody` and another uid with the relay's gid are
refused `EACCES`, and the relay's uid connects. `HOST_PROXY_RELAY` re-reads
the ACL at every measurement, so a loosened directory is drift.

`SO_PEERCRED` is deliberately not consulted: on a runtime whose containers
live in a pid namespace the broker cannot see (Docker Desktop's engine runs in
a sibling WSL distribution) the kernel reports the relay's uid and gid
correctly but its pid as **0** — measured: uid 10002, gid 10002, pid 0 — and
`rustix` 1.1.5's `socket_peercred` reads that into a non-zero `Pid`, which is
undefined behaviour, not an error. A check that is unsound for exactly the
peers it serves is not a check; the sound alternative (`nix`'s `socket`
feature) pulls in `memoffset`, a crate the lockfile does not have. The ACL is
the same uid check, made by the kernel at path resolution rather than after
`accept`, through `rustix::fs` (`lsetxattr`, `lgetxattr`), which the workspace
already builds.

**What reaching the socket gives.** The socket is not an authority channel:
nothing about its peer is believed and every check is made on the bytes. Its
peer gets exactly this environment's grant — its exact hosts, through the
guard, the pin and the server-name check — within this environment's budgets
and at most 64 connections at once, and never a credential (ADR-0024: the
sandbox path injects none). Besides the relay, the broker's uid and
privileged root can reach it — both already the broker's equals — and, where
a runtime re-exposes the directory as Docker Desktop does, a host process
running as uid 10002, which could only spend this environment's budget and
appear in its counters. The authority's and the broker's own channels are
different: they authenticate an authority-bearing peer by its
kernel-reported uid. Their use of the same unsound `rustix` call is
pre-existing and is recorded as a separate finding, not changed here.

This amends ADR-0043 §1, whose table has the broker listen on its private
socket "and nothing else" and connect to nothing: it now also listens on one
egress socket per `PROXY_ONLY` environment, accepting from that environment's
relay only and never from the authority's side, and it connects to the
addresses its proxy pins (§4). TX009 names `egress/proxy.rs` beside
`listener.rs`; TX037 confines the dial to `egress/tunnel.rs`. Everything else
ADR-0043 decided about the private channel stands.

### 4. The CONNECT proxy: one request, at most one opaque tunnel

| step | what is checked | refusal |
|---|---|---|
| request | exactly `CONNECT host:port HTTP/1.1` (or 1.0): single spaces, CRLF only, ≤ 8 KiB, ≤ 32 headers, token names, no folding, no control or non-ASCII byte, no `Content-Length`/`Transfer-Encoding`, at most one `Host` equal to the target; bytes after the blank line are the tunnel's, never a second request | `400` `MALFORMED`, `NOT_CONNECT`, `TARGET_NOT_CANONICAL`; `408` `REQUEST_TIMEOUT` |
| target | a canonical host — the one implementation in `dwk_proto::wire::host`, which the authority's capability scope also uses — never an address literal (a last label all digits, or `0x` and hex digits: what a resolver reads as IPv4), userinfo, a bracket, uppercase, Unicode or a trailing dot; a strict decimal port | `TARGET_NOT_CANONICAL` |
| grant | exactly a granted `(host, port)`, by bytes | `403` `TARGET_NOT_GRANTED` |
| name | not a cloud metadata name (`metadata.google.internal`, `metadata.goog`, `instance-data`) | `ADDRESS_BLOCKED` |
| tunnels | fewer open than the grant's limit | `TUNNEL_LIMIT` |
| resolve | the broker's resolver, once, 5 s deadline | `RESOLUTION_FAILED`, `RESOLUTION_TIMEOUT` |
| guard | the **whole** answer (§6) | `ADDRESS_BLOCKED`, `ADDRESS_MIXED` |
| — | `HTTP/1.1 200 Connection Established` | |
| hello | a strict, bounded `ClientHello` (§7) whose one server name is the CONNECT host, without ECH, within 10 s | closed: `CLIENT_HELLO_*`, `SNI_*`, `ECH_REFUSED` |
| dial | the pinned addresses in order, 10 s in all — never the name again | closed: `CONNECT_FAILED` |
| tunnel | bytes each way within the environment's budgets, idle 120 s, life 3600 s | closed: `UPLOAD_BUDGET`, `DOWNLOAD_BUDGET`, `IDLE_TIMEOUT`, `LIFETIME_EXCEEDED`, `ENVIRONMENT_CLOSED`; clean: `CLOSED` |

A refusal before `200` is answered with the status and
`X-DireWolf-Egress: <DISPOSITION>`, nothing else; after `200` it is the
connection closed. There is no fallback of any kind: nothing in the broker
dials except `egress/tunnel.rs`, after every check (TX037). TLS is the only
tunnelled protocol — a tunnel whose first bytes are not a `ClientHello` is
refused — so plain HTTP, and any protocol without a server name, has no path
through the proxy.

### 5. The grant: the run's own exact `network.https` grants

The authority derives a `PROXY_ONLY` environment's destinations at intent,
from the run's admitted grants (immutable since admission): every
`network.https` capability whose host is **exact**, on its port or 443 when
it names none. A wildcard (`*.example.com`), `*`, an address literal,
`network.http` and `network.tcp` give nothing; the probe's reserved
`.invalid` name is never a destination; more than 64 destinations is refused,
never truncated. The budgets are the operator's
(`SandboxConfig::proxy_only` with an `EgressConfig`: 1–64 tunnels, 1 byte–16
GiB each way), within protocol bounds; the deadlines are the broker's
constants. The intent's audit record carries the whole grant — destinations,
relay digest, budgets.

**Budgets are environment-wide and never refilled.** Each direction reads at
most one byte past what is left; what fits is carried, the rest is dropped
and the tunnel is closed, so the budget is spent exactly at the socket and
every later tunnel finds it spent. Connection count is enforced as tunnels
open at once; the relay additionally caps forwarded connections at 64.

### 6. Resolution, the IP guard and pinning

Production resolution is the host's own resolver (`getaddrinfo` through the
standard library) on a worker thread the deadline abandons; at most 32
resolutions are in flight, abandoned ones included. The answer is judged
whole: IPv4 loopback, this-network, RFC 1918, CGNAT, link-local (metadata),
special-use, documentation, the 6to4 relay, benchmarking, multicast and
reserved are blocked; IPv6 is allowed only within `2000::/3`, minus
documentation, discard and `2001::/23` (Teredo included); NAT64 and 6to4
addresses are judged by the IPv4 address they embed; IPv4-mapped and
IPv4-compatible addresses are blocked outright. **Any blocked address
refuses the answer** — all blocked is `ADDRESS_BLOCKED`, a mixture is
`ADDRESS_MIXED` (NETWORK_SECURITY.md "DNS rebinding") — and production has
no exception mechanism.

The name is resolved once per tunnel and the tunnel dials only that answer.
A rebinding name is therefore pinned for its tunnel and judged afresh for the
next — measured: the first tunnel reaches the pinned origin, the second gets
the blocked answer and is refused.

### 7. The server name

The hello is read from the first bytes of the granted tunnel, before
anything is dialled, as handshake records reassembled incrementally (any
fragmentation; ≤ 64 KiB buffered, ≤ 16 KiB message): TLS 1.0–1.2 record
framing, one `ClientHello`, every length exact, each extension at most once,
`server_name` with exactly one `host_name` of at most 253 bytes. None is
`SNI_MISSING`, more than one `SNI_AMBIGUOUS`; an `encrypted_client_hello`
extension is `ECH_REFUSED` — its outer name is not the server the inner hello
is for. The name must equal the CONNECT host byte for byte.

### 8. Proxy variables

The environment is given exactly `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`
(`http://169.254.7.1:8080`) and `NO_PROXY` (`localhost,127.0.0.1,::1`), each
in both cases — `dwk-sandbox-profile` constants. Nothing is inherited: the
broker never reads its own environment in the egress or sandbox code (TX042),
and the runtime client runs with an empty private configuration directory, so
a user's client configuration cannot inject proxies. The variables are a
convenience for tools; the topology is the containment. No per-tool
configuration (npm's, pip's, cargo's, git's) is written: routing package
managers is M5d's.

### 9. Measurement: the probe reports facts, the authority judges

Seven invariants join ADR-0047's 42 (49):

| invariant | vantage | judged by |
|---|---|---|
| `HOST_PROXY_ENVIRONMENT` | runtime record | the environment's proxy variables are exactly the broker's (`PROXY_ONLY`) or none (`NO_NETWORK`), in any spelling |
| `HOST_PROXY_RELAY` | runtime record + broker | the peers are the topology's: one exact relay (§2, in this environment's namespace, this environment's directory mounted read-only, labels exact), the broker's proxy for it open on the socket it bound in a directory still holding exactly the relay-only ACL (§3), no setup left — or, for `NO_NETWORK`, none of the three |
| `HOST_RELAY_DIGEST` | runtime copy | the running relay's file hashes to the pin |
| `CONTAINER_PROXY_REACHABLE` | probe | `169.254.7.1:8080` answers the probe's CONNECT for a reserved `.invalid` name with DireWolf's `403 TARGET_NOT_GRANTED` (waiting at most 4 s for the relay to listen, and only on `ECONNREFUSED`) |
| `CONTAINER_DIRECT_EGRESS_REFUSED` | probe | TCP and UDP to the profile's external, metadata, host, LAN, link-local, IPv6, mapped and NAT64 destinations fail with no route; the proxy address on other ports is refused; a connection or a silence fails it |
| `CONTAINER_DIRECT_DNS_REFUSED` | probe | a fixed question over UDP and TCP to the configured and the well-known resolvers gets no answer |
| `CONTAINER_RAW_SOCKETS_REFUSED` | probe | raw and packet sockets cannot be made; an ICMP socket, where one can be, reaches nothing |

`PROXY_ONLY` requires all 49; `NO_NETWORK` all but `HOST_RELAY_DIGEST` and
`CONTAINER_PROXY_REACHABLE`. The probe reports a verdict per attempt and no
destination it was not compiled with; the authority judges. Probe report
version 2. New failure classes: `RELAY_MISMATCH`, `NETWORK_TOPOLOGY_FAILED`.

### 10. Lifecycle

Prepare: open the proxy → create and start the environment → check the
relay's digest → setup → create and start the relay → measure → keep, or take
it down whole (helpers, environment, listener). Destroy: the helpers first,
then the environment — each proved labelled as this environment of this store
immediately before removal — then the listener closed, whatever the runtime
managed, its counters returned. Labels schema 2 adds `io.direwolf.role`
(`environment`, `relay`, `setup`); a listing reports each container's role.

The listeners live in the broker process. **A broker restart fails closed**:
the relay can no longer reach a proxy, the next measurement fails
`HOST_PROXY_RELAY` and `CONTAINER_PROXY_REACHABLE`, and the environment is
destroyed — never reconnected to a proxy that was not the one its grant was
given to. Reconciliation classifies helpers with their environment's record:
a live record's helpers are its own; a live record whose environment
container is gone but whose helpers remain is pending (destroyed, removing
them) rather than missing; an ended record's helpers are one orphan, reaped
through the environment's destruction. A container that merely resembles a
helper — another store's, another owner's, unlabelled — is foreign and
untouched.

### 11. Private protocol version 6

`EnvironmentSpec` gains `relay_sha256` and `egress` (the grant: typed
targets, tunnel limit, two budgets); the measure authorisation carries the
digest and never a grant; measure and destroy answers carry `egress`
counters (per disposition, bytes each way — no host, no payload);
`OwnedEnvironment` carries `role`; `PROXY_UNAVAILABLE` is a new refusal.
Versions 1–5 are refused. Nothing on the wire names a resolver, an exception,
a proxy endpoint or trust material (TX036). The public DWKP is unchanged.

### 12. What the proxy sees, and what it does not

**Visible**: the CONNECT host and port, the resolved addresses, the TLS
server name, connection metadata and timing, byte counts. **Not visible**:
the HTTP path, headers, body or response inside TLS, the encrypted `Host`,
credentials inside TLS. Audit and the broker's events carry dispositions and
counts — the intent records the grant, the measurement and the destruction
record counters — never a payload; the broker's event lines carry no host.

### 13. The evidence-only fixture resolver

`dwkd-broker serve --allow-evidence-egress <file>` replaces the resolver with
a fixture file (names → answers in order: addresses, `fail`, `timeout`; and
`allow <ip>` exceptions) and says so loudly at start. It exists so the
evidence controls what names resolve to — acceptable, blocked, mixed,
rebinding, failure, timeout — and can reach its own loopback origin, while
the real proxy, guard, deadline, topology and relay judge it. It is the only
exception mechanism anywhere, and no production configuration names it: a
broker without it resolves through the host and blocks loopback (measured).

### 14. Evidence, eval, CI

`make sandbox-egress-evidence`: static probe, relay and workload fixture,
proved static; probe and relay digests pinned; three offline `FROM scratch`
images (the product's — probe and relay; the evidence's — with the fixture;
one with a relay one byte different); then eight broker tests and one
authority test, every test and every one of 104 cases required; **no
evidence container or network left, every pre-existing one still there**.
No runtime: NOT EXERCISED, which fails. It covers the strict topology and
its three containers; only the relay's uid reaching the broker's socket
(the environment's uid, root without capabilities, `nobody` and the relay's
gid refused); tunnels through the real relay (granted bytes both
ways, through the proxy variable; host, port and literal refused; blocked,
metadata, mixed, failing, timing-out and rebinding answers; SNI mismatch,
missing, ECH and plain HTTP); budgets at the socket (upload exact, spent
stays spent, download, tunnel limit); the fronting residual; every bypass,
each with its errno and mechanism; ambient proxy settings; nine weakened or
drifted topologies (the socket's directory opened to other uids among them),
each detected; crashes, restart and foreign resources;
and a production broker. The `m5b-sandbox-egress` eval suite runs it; the
`sandbox-egress` CI job runs it on the runner's Docker Engine. M5a's
evidence (`make sandbox-foundation-evidence`) stays required and green.

Measured on Docker Desktop 29.8.1 in WSL2 (debug broker; evidence, not an
SLO): a clean `PROXY_ONLY` preparation, setup and relay and the 49-invariant
measurement included, took 4.1–5.5 s across runs, most of it the probe's
bounded DNS waits.

### 15. Dependencies and the TCB

No new third-party crate, no new feature, no `unsafe`. One workspace member,
`dwk-sandbox-relay` (`dwk-sandbox-profile`, and the already-locked `rustix`
with the workspace's features). The socket directory's ACL is set and read
through `rustix::fs`, whose `fs` feature the workspace already enables. The
broker's code grows by the egress module
and its trust by one outbound path; the authority's measured closure is
unchanged (`dwcheck closure`). `dwk_proto::wire::host` replaces the
authority's own label check with the shared one (same rule, one
implementation).

### 16. Architecture rules

TX009, TX013 and TX015 exempt the egress files by name, each with its
reason; TX033 and TX036 are amended deliberately. New: TX037 (the broker dials
only from the tunnel), TX038 (no TLS, credential, secret or `unsafe` on the
egress path or in the relay), TX039 (the relay is a byte pump), TX040 (only
the setup holds a capability), TX041 (the relay plan spells no other
weakening), TX042 (no ambient proxy setting reaches an environment) — each
with a violation fixture.

### 17. Platform contract

Linux, with a Docker-compatible runtime whose containers can join another
container's network namespace and bind-mount a host directory (native Docker
Engine; Docker Desktop on Windows/WSL2, measured), and that does not remap
container uids (the ACL names the relay's uid as the kernel sees it); and a
filesystem that keeps POSIX ACLs for the broker's socket directory (ext4,
xfs, btrfs and tmpfs as Linux distributions build them) — otherwise no
`PROXY_ONLY` environment is prepared. Accepted locally on the
evidence of §14; native Docker Engine is exercised by the hosted
`sandbox-egress` job, whose first run on the committed tree is M5b's
remaining acceptance gate.

### 18. Residual risks

- **Domain fronting** (NETWORK_SECURITY.md §1): inside an agreeing tunnel the
  proxy cannot see a request for another origin served from the same front.
  Measured: such a request is carried, and only the environment's budget
  bounds it. Mitigations are narrow grants, the budgets, and keeping
  credential-bearing requests on `net.http`.
- **A granted host is trusted with what is sent to it**: the proxy enforces
  where, not what.
- **ECH is refused**, so a client that insists on it cannot use the proxy.
- **The relay is identified by the kernel's uid check on its socket's
  directory**, not by a peer credential (§3): privileged root and the broker's
  own uid can reach the socket — both already the broker's equals — and,
  where a runtime re-exposes the directory as Docker Desktop does, so can a
  host process running as uid 10002; what any of them gets is this
  environment's grant within its budget.
- **Docker Desktop keeps its bind-mount entries** under `/mnt/wsl` after a
  container is removed (measured): each environment's directory, deleted and
  empty, stays listed there. They are Docker Desktop's, hold nothing, and are
  not DireWolf's to remove.
- **The guard judges address ranges, not the host**: a granted name that
  resolves to a public address of the host itself, or of its own network,
  passes it, and is reachable on the granted port with the granted server
  name.
- A peer added to the namespace by someone with runtime access (which is
  root-equivalent) is detected only where it listens on a measured address.
- The host's resolver is trusted for what it returns; the guard judges what
  that is.
- Measurement is periodic: a change between two measurements is found by the
  next one.

### 19. Explicit exclusions

No `net.http`, no redirects, no credential egress (mode A's consumer), no
secret modes B/C wired, no production sandboxed `process.exec`, no
package-manager routing in production, no change to the age/getrandom
decision. M5 is not complete.

## Consequences

**Positive.** `PROXY_ONLY` exists and is measured: an environment's only
network peer is the proxy, every direct path fails at the topology, and the
proxy's checks are shown on real traffic through the real relay. The broker
needs no host privilege. The grant is the run's own, decided at admission.

**Negative.** Three containers per environment and a 4–5.5 s preparation. The
broker gains its first outbound path — narrow, single-sited and after every
check, but real. The broker's listeners are in-process, so a broker restart
destroys every `PROXY_ONLY` environment rather than resuming it. TLS is the
only tunnelled protocol, and ECH clients cannot use the proxy. The relay's
identity is a uid check made through file-system permissions (an ACL) rather
than a peer credential, which needs a filesystem that keeps POSIX ACLs and a
runtime that does not remap uids.

## Alternatives considered

- **A veth pair to a broker-side peer (ADR-0024's wording).** Needs
  `CAP_NET_ADMIN` in the host namespace (or a privileged helper), does not
  reach Docker Desktop's VM, and adds an interface and a route to measure.
  The loopback-address realisation gives the same single peer with none of
  that.
- **Ordinary bridged networking plus firewall rules.** Rejected by ADR-0024
  and again here: a route exists and must be filtered rather than not exist,
  filtering by IP cannot enforce the server name, and the evidence shows the
  measurement catches it (`weakened-bridge-network`).
- **The proxy listening on TCP in the namespace from the broker.** The broker
  cannot listen inside another namespace without `setns` privilege; the relay
  is the minimal thing that can.
- **Checking the relay with `SO_PEERCRED`.** Unsound on the measured platform
  (§3).
- **The directory's location alone (a 0700 root above a traversable
  directory).** What the first implementation did. Docker Desktop re-exposes
  bind sources outside the root (§3), so on that platform any local uid could
  reach a live environment's socket; found in review, measured, and replaced
  by the ACL.
- **An unguessable socket name, or a token the relay presents.** Every bound
  socket's path is listed in `/proc/net/unix` for every local user to read,
  and a token would put a secret on the egress path (TX038). The ACL needs
  neither.
- **Re-resolving per connection attempt, or filtering a mixed answer.**
  Re-resolution is what rebinding exploits; filtering a mixed answer accepts
  the attack's shape.

## Revisit if

- A runtime cannot join a container's network namespace or bind-mount the
  egress directory (the topology would need another realisation).
- `rustix` (or the workspace) gains a sound peer-credential read that
  tolerates an invisible pid — then add the uid check after `accept` as
  defence in depth.
- Anything credential-bearing, or anything the authority grants beyond the
  environment's own destinations, is ever carried on this socket: it must
  then authenticate its peer, not only be reachable by one uid.
- A supported runtime remaps container uids (the ACL would have to name the
  relay's mapped uid).
- ECH becomes common for granted hosts (the refusal would need a design that
  can still agree on the server).
- `net.http` (M5c) needs the proxy's resolver or guard: share them, do not
  fork them.
