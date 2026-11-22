# ADR-0068: The CONNECT proxy admits a connection only from the relay's uid, as the kernel reports it -- after `accept`, before a byte is read, beside the directory's ACL

**Status:** Proposed · **Date:** 2026-11-16 (designed, built and reviewed locally 2026-11-16 for finding F-04; its cross-uid and hidden-pid evidence observed on CI #201 (run 44818094052, `3998de2`) in `make proxy-peer-evidence`, recorded in [PRE_M6_REMEDIATION.md](../PRE_M6_REMEDIATION.md); nothing here is accepted) · **Would amend (on acceptance):** [ADR-0048](0048-m5b-proxy-only-topology-and-connect-proxy.md) §3 ("`SO_PEERCRED` is deliberately not consulted": it is now consulted, after `accept`, as a second and independent check; the ACL stays) · **Refines:** [ADR-0049](0049-peer-credentials-read-soundly-through-nix.md) (its "Revisit if" on the egress socket is met with its reader) · **Leaves open:** a proof of *which* process or environment connected, beyond its uid (F-05's user namespaces and LSM)

> **Each connection the broker's per-environment CONNECT proxy accepts is
> admitted only if the kernel reports the relay's uid (`RELAY_UID`, 10002)
> for it.** The broker asks right after `accept`, before it reads a byte, holds
> a handler slot or starts a thread. Any other uid -- the broker's own, an
> authority's, root's, anyone's -- and a peer whose credentials cannot be read
> is closed unanswered and recorded. Only the uid decides: a pid the broker
> cannot see is no pid, and no gid is read. The directory's ACL stays, and
> either check alone refuses.

Proposed. The change is built so that its evidence can run; the accepted
records' bodies are unchanged (README.md, rule 1).

## Context

**What ADR-0048 built.** A `PROXY_ONLY` environment's one peer is a relay
container, uid 10002, which forwards each connection to the broker's
per-environment Unix socket. Who can reach that socket is decided by the
kernel's permission check on its directory: mode `0710` with a POSIX ACL
that lets the relay's uid search it and nobody but the broker do more,
beneath a `0700` root, bind-mounted read-only into that relay alone. The
socket is `0666` because the directory already decides.

**Why the ACL was the only check.** ADR-0048 §3 left `SO_PEERCRED` out on
purpose: on a runtime whose containers live in a pid namespace the broker
cannot see (Docker Desktop on WSL2), the kernel reports the relay as uid
10002, gid 10002, **pid 0**, and the only reader then, `rustix` 1.1.5's,
turned that pid into undefined behaviour. "A check that is unsound for
exactly the peers it serves is not a check." Its "Revisit if" named the
remedy: a sound reader that tolerates an invisible pid.

**What changed.** ADR-0049 (accepted) moved every reader to `nix`'s safe
`getsockopt`, which returns the kernel's `ucred` as it is; a pid of 0 is
recorded as no pid. The broker has one such reader (`crate::peer::of`),
already used by its private channel and its launch helper. ADR-0049's own
"Revisit if" records that the egress socket could now add the uid check
after `accept`.

**The finding.** F-04, as recorded by the remediation programme: "proxy
socket peer not checked by `SO_PEERCRED`". No longer audit text is
available; the scope here is what the code and the two records establish.
Reproduced on `dc05c32`: a production proxy (relay uid 10002) answered a
CONNECT from uid 1000 -- the directory's owner, which the ACL lets through --
with `HTTP/1.1 403` for an ungranted host, i.e. it parsed and judged a
request from a peer that is not the relay. Whatever reaches the socket is
served; the ACL alone decides who can.

What the ACL already guarantees, and still does: the environment's uid,
root without `CAP_DAC_OVERRIDE`, `nobody` and a uid holding the relay's gid
are refused `EACCES` at the directory (measured in `sandbox_egress.rs`); a
loosened directory is drift (`HOST_PROXY_RELAY`). What it does not: an
independent statement, at the socket, of who connected -- a weakened or
mis-set directory, a runtime that re-exposes it, or the broker's own uid
reach a proxy that serves them.

## Decision

### 1. The check

```text
accept ──▶ closing?                          yes → stop (the broker's own wake-up is never judged)
       ──▶ SO_PEERCRED (crate::peer::of)      unreadable → close; egress_peer_unidentified
       ──▶ uid == RELAY_UID ?                 no → close; egress_peer_refused uid=N
       ──▶ a handler slot (64 at most)        full → TUNNEL_LIMIT
       ──▶ a thread: the CONNECT, the grant, the workload's authorisation,
           the resolver, the guard, the server name, the budgets   (unchanged)
```

- **Accepted:** exactly the uid `RELAY_UID` (10002), the constant the relay's
  container runs as and the ACL names. Every proxy the broker builds admits
  that and nothing else; no flag, environment variable, configuration value
  or byte of the request names another. The one way to name another uid,
  `Proxies::admitting`, is compiled into the crate's tests only, where the
  test stands where the relay does as its own uid.
- **The pid** is not consulted. It is `None` for a relay in a pid namespace
  the broker cannot see, which is how Docker Desktop reports every relay;
  refusing it would refuse the real relay there, and a visible pid vouches
  for nothing. The broker is not the relay's parent, so ADR-0045's parent
  check does not apply.
- **No gid is read.** The reader's `Peer` has no gid; a matching gid cannot
  compensate for a wrong uid.
- **A read the kernel refuses** is a refusal, never a pass and never a fall
  back to the ACL alone.
- **Not the broker's uid, not the authority's.** The broker refuses to serve
  if its own uid or its authority's is a sandbox identity (`SANDBOX_UID`,
  `RELAY_UID`; ADR-0052 §13), so neither can ever be the relay's.

### 2. Before anything is spent

The check comes after the closing check -- so the broker's own wake-up
connection, made to end the accept loop, is never judged -- and before the
handler slot, the thread and the first read. A refused peer holds no slot, so
it cannot push the relay's connections into `TUNNEL_LIMIT`; it never reaches
the CONNECT parser, the grant, the workload's authorisation (F-17), the
resolver, an outbound connection, a budget or a counter. Each is closed on the
accepting thread at once, so a flood creates no thread and waits on nothing.

### 3. What a refused peer sees, and what is recorded

The connection is closed with nothing written: no HTTP status (the socket is
not HTTP to a peer it does not serve) and no DWKP refusal (it is not the
public protocol). The broker records `egress_peer_refused environment=<id>
uid=<uid> refused=<n>` or `egress_peer_unidentified environment=<id>
refused=<n>` on its event log -- the kernel's uid and the authority's own
words, never a byte the peer sent -- and counts it per proxy. It is never an
`EgressDisposition`: the egress counters, a workload's report and the
authority's records stay what tunnels did, so a refusal is told apart from an
ACL refusal (`EACCES` at `connect`, which the broker never sees), a malformed
CONNECT (`400`), a request too slow (`408`), a destination refused (`403`,
with its disposition) and an outbound failure (`CONNECT_FAILED`, counted
after the `200`).

### 4. The ACL stays

The two checks are independent: the ACL is the kernel's at path resolution,
before `connect` succeeds; the uid check is the kernel's record of the
connected peer, after `accept`. Either alone refuses. The ACL keeps doing what
the uid check cannot -- keeping every other uid from even connecting, and
`HOST_PROXY_RELAY`'s measurement of it -- and the uid check keeps a loosened
or mis-set directory from serving whoever reaches it.

### 5. What a uid proves, and what it does not

The check proves "the connecting peer had the relay's uid". It does not prove
"this connection came from this environment's relay process". Every relay of
every environment is uid 10002, and so is any host process an operator runs as
it: kernel credentials do not tell them apart. What keeps a connection to its
environment is unchanged -- each environment's directory is mounted into its
own relay alone, the ACL, and the environment's own grant, budgets, lifetime
and workload authorisation. A stronger, per-process or per-namespace proof
would need what the broker cannot get for an invisible pid (§Alternatives)
and belongs with F-05's user namespaces and LSM work.

### 6. Wire, store, configuration

DWKP, the private broker protocol (12), the store schema, the relay, the ACL
and every flag are unchanged. Nothing is configured: `RELAY_UID` is a
constant. A runtime that remaps container uids already needs ADR-0048's
revisit (the ACL names 10002); this check names the same uid, so such a
runtime is refused the same way, fail-closed.

## Consequences

- A connection that reaches the socket by any route other than the relay's
  uid -- the broker's own uid, root, a uid a loosened directory lets through --
  is closed before it is read, and said.
- The relay is still served wherever the kernel reports its uid, Docker
  Desktop's invisible pids included.
- The egress unit tests, which stand where the relay does as their own uid,
  name that uid as their relay explicitly.

## Residuals

- **Same uid, different process.** Any process running as uid 10002 that
  reaches a socket is the relay to this check (§5).
- **Root.** Host root can reach the directory and could run as 10002; it is
  outside the threat model, as in ADR-0048.
- **No audit-chain record.** The refusal is on the broker's event log and
  counted per proxy, not in the authority's `audit.log`: the authority never
  sees the connection. Carrying it there would change the private protocol.
- **Hosted evidence.** The cross-uid cases run only with a second identity,
  on the hosted `sandbox-egress` job. On CI #201 they ran as uid 65534
  (`DW_PEER_AS=nobody`), and both were contained. The hidden-pid case needs
  unprivileged user and pid namespaces: the job lifts the runner's AppArmor
  restriction first, and on CI #201 that case was contained too
  (`kernel-hidden-pid`). Only the unit runs of other jobs, where the
  restriction stands, print NOT EXERCISED for it (corrected 2026-11-22).

## Alternatives considered

- **A: keep the ACL as the only check.** Rejected: it is F-04. The reason it
  was the only check is gone (ADR-0049).
- **B: the relay's kernel uid after `accept`, beside the ACL** -- chosen: the
  smallest independent check, with the reader every other broker peer check
  uses, and sound for an invisible pid.
- **C: also require the relay's pid, or its parent, or its `/proc` entry.**
  Rejected: the pid is 0 for every relay on Docker Desktop, a pid names no
  process across recycling, and the broker is not the relay's parent.
- **D: a namespace or pidfd proof** (`SO_PEERPIDFD`, the peer's network or pid
  namespace). Not now: a pidfd for a process in a pid namespace the broker
  cannot see gives it no namespace it can compare, and the readers the
  workspace links expose none. F-05's user-namespace work is where a
  per-environment identity belongs.
- **E: a token or secret the relay presents.** Rejected, as in ADR-0048: a
  secret on the egress path (TX038) proves possession, not identity, and every
  relay would hold one.
- **F: an `EgressDisposition` for a refused peer.** Rejected: it would change
  the private protocol and mix refusals of who connected with what tunnels
  did.

## Owner decisions

- OD-1 the uid check is added and the ACL kept (B);
- OD-2 the pid is ignored and a hidden pid admitted on its uid;
- OD-3 a refusal closes unanswered and is recorded on the broker's event
  log, not as a disposition;
- OD-4 the hosted `sandbox-egress` job runs `make proxy-peer-evidence` last,
  with `DW_PEER_AS` and the AppArmor restriction lifted on its disposable
  runner;
- OD-5 a per-process or per-environment proof deferred to F-05.

## Evidence

- `crates/dwkd-broker/src/egress/tests.rs`, the `f04_` tests:
  - the decision: the relay's uid with a visible pid, with none; every other
    uid with any pid; every read error (unit);
  - a uid the ACL lets through -- this process, the directory's owner, as
    the broker's uid would be -- closed unread: nothing parsed, counted,
    resolved, dialled or spent from a workload's authorisation (a real Unix
    socket and the kernel's `SO_PEERCRED`);
  - three times the handler slots of refused connections hold no slot, are
    never counted against the tunnel limit, and the environment still closes
    promptly;
  - the order in `accept`, read from the source;
  - a peer whose pid the reader cannot see -- a real kernel pid of 0, in an
    unprivileged user and pid namespace -- admitted by its uid and refused by
    another;
  - hosted only, with `DW_PEER_AS`: a real foreign uid refused through a
    deliberately loosened, disposable directory, and the same client served
    only by proxies that admit it as their relay.
- The real relay through the ACL, in real containers: `sandbox_egress.rs`
  and the agent suites, unchanged, now through the uid check
  (`make sandbox-egress-evidence`, `make sandbox-agent-evidence`).
- `make proxy-peer-evidence` (every case required) and
  `make proxy-peer-mutations` (each guard weakened in turn).

## Rollback and deployment

The change is one check in the broker's accept loop; reverting it restores
ADR-0048's ACL-only behaviour with nothing to migrate. A deployment whose
relay does not run as uid 10002 as the kernel reports it -- a runtime that
remaps container uids -- already fails ADR-0048's ACL and is not supported; it
now fails this check too, the same way.

## Revisit if

A supported runtime remaps container uids; F-05 gives each environment an
identity the kernel can report; the broker gains a way to tell relays apart
that does not depend on a visible pid; or anything credential-bearing is ever
carried on this socket (ADR-0048's own revisit).
