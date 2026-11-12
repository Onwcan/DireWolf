# ADR-0060: A `network.https` grant that carries a constraint gives a `PROXY_ONLY` environment no destination

**Status:** Proposed · **Date:** 2026-11-12 (proposed and built 2026-11-12 for finding F-19; its hosted evidence is pending and nothing here is accepted) · **Would amend (on acceptance):** [ADR-0048](0048-m5b-proxy-only-topology-and-connect-proxy.md) §5 (which of a run's grants become a `PROXY_ONLY` environment's destinations) · **Addresses:** finding F-19

> **A `PROXY_ONLY` environment's destinations are the run's exact
> `network.https` grants that carry no constraint.** A grant that carries
> `methods` or `max_requests` gives no destination: the proxy carries an
> opaque tunnel and sees no request in it, so it could keep neither, and a
> tunnel made from such a grant would carry more than the grant allows. The
> grant still authorises `net.http`, where the authority decides every
> request and keeps both. One function in the authority changes; the proxy,
> the private protocol, the store and policy do not.

Proposed. The change is built so that its evidence can run; ADR-0048's body
is unchanged, as every accepted record's is (README.md, rule 1), and §5 of
that record stays the accepted derivation until this one is accepted. M5's
accepted evidence used unconstrained grants throughout, so none of its
results depends on what this record changes.

## Context

**The derivation.** ADR-0048 §5 gives a `PROXY_ONLY` environment its
destinations at intent, from the run's admitted grants: every `network.https`
capability whose host is exact, on its port or 443. A wildcard, `*`, an
address literal, `network.http` and `network.tcp` give nothing; the probe's
reserved name is never a destination; more than 64 destinations is refused.

**The constraints.** A capability is a verb, a scope and constraints
([CAPABILITIES.md](../CAPABILITIES.md) §2). A network verb may carry two:
`methods`, narrower as a subset, and `max_requests`, narrower as a smaller
count. A missing constraint is unconstrained, which is the widest value, and
attenuation may only narrow.

**Where the constraints are kept.** `net.http` keeps both
([ADR-0050](0050-m5c-kernel-performed-net-http-ssrf-redirects-and-credential-egress.md)
§5): the authority decides each request for
`network.https:<host>:<port>?methods=<m>&max_requests=<n>` and charges the
count before anything is sent. The CONNECT proxy cannot: it does not
terminate TLS (ADR-0048 §§4, 7), so it sees a CONNECT target, a port, an
address, a server name and byte counts, and never a method or where one
request ends and the next begins.

**Finding F-19** (review of 2026-11-12). The derivation read a capability's
verb, host and port, and not its constraints. A run granted
`network.https:api.example.com?methods=GET&max_requests=5` therefore held,
for every sandboxed workload, a tunnel to `api.example.com:443` over which
any method could be sent any number of times, within the environment's
tunnel and byte budgets. Two things followed:

- a capability narrowed by a constraint conferred more through the sandbox
  than it states, so narrowing a grant did not narrow what a workload could
  do with it;
- a run could not hold `net.http`-only authority over a host: any exact
  `network.https` grant was also a workload's tunnel.

It was not a route to a host the run was not granted. The exact-host rule,
the IP guard, the pinned resolution, server-name agreement and the budgets
were as ADR-0048 states them.

No evidence case covered a grant that carries a constraint: the unit test of
the derivation and the real-environment case each granted unconstrained
capabilities only.

## Decision

1. **Only an unconstrained grant gives a destination.** The derivation skips
   a `network.https` capability whose constraint set is not empty. The test is
   "any constraint at all", not a list of the two a network verb can carry
   today: the set is closed ([CAPABILITIES.md](../CAPABILITIES.md) §2), and a
   constraint added to it later gives no destination until a decision says
   the tunnel can keep it.
2. **Each capability is judged alone.** An unconstrained grant of a
   destination gives it whether or not a constrained grant names it too; a
   constrained grant adds nothing and removes nothing. Nothing of one grant
   completes another: a constrained grant's port is not a destination because
   the same host is granted, unconstrained, on a different port. A destination
   two unconstrained grants name is still there once.
3. **Absent, not refused.** A constrained grant does not refuse the
   preparation. The environment is prepared with the destinations that remain
   — possibly none — and the proxy answers a CONNECT to any other name
   `TARGET_NOT_GRANTED`, as it does for a name only a wildcard covers.
   Refusing would stop a run that holds a constrained grant for `net.http`
   and runs workloads that need no network, which is the ordinary shape.
4. **What is unchanged.** Wildcards, `*`, address literals, `network.http`,
   `network.tcp` and the probe's reserved name give nothing, constrained or
   not. The bound is on destinations: 64 is a whole grant and a 65th is
   refused (`EGRESS_GRANT_TOO_LARGE`), never truncated; a constrained grant
   is not a destination and is not counted. `net.http` decides a constrained
   grant exactly as before.
5. **Nothing new is recorded.** The intent's audit record already carries
   the whole grant (`egress_targets`), and the admission's record every
   capability granted, constraint included. Read together they say which
   grant gave no destination.

## Consequences

**A tunnel is asked for as what it is.** A workload reaches a host only when
the run holds that host unconstrained, which its agent profile, its active
skills and the mode ceiling must each cover. An operator who writes
`?methods=GET` gets a grant that only `net.http` can use, and says so by
writing it.

**Compatibility.** A deployment that gave a workload its registry or origin
through a constrained grant loses that tunnel: the workload's CONNECT is
refused `TARGET_NOT_GRANTED`. The remedy is the unconstrained grant, which
states what the tunnel carried all along. No shipped pack, fixture or
evidence case has that shape.

**Not addressed here, and stated so.**

- Policy is still not consulted for a tunnel's destination: the capability
  decides it at admission (finding F-17, designed separately).
- A workload's network use still does not raise a run's taint above
  `LOCAL_UNVERIFIED` (finding F-01, designed separately).
- Through an unconstrained grant the tunnel carries any method and any
  request, bounded by the tunnel and byte budgets, and domain fronting inside
  an agreeing tunnel remains ADR-0048's residual. This record stops a
  constraint being dropped; it does not make the tunnel inspect anything.
- An operator who expected a destination and finds none has two audit
  records to read, not one that names the reason. A record of its own is left
  to F-17's design, which decides what else is said about a tunnel.

## Alternatives considered

- **Keep the constraints in the proxy.** It would have to terminate TLS: a
  certificate authority trusted inside every environment and plaintext in the
  broker. ADR-0048 rejected that, and nothing here reopens it.
- **Refuse the preparation** when an exact grant carries a constraint.
  Rejected (decision 3): it turns a narrower grant into a denial of work that
  needs no network.
- **Treat a wide constraint as none** — all seven methods, or a count no
  workload reaches. A constraint that is sometimes not one gives the
  derivation two readings of the same grant; rejected.
- **Count tunnels as requests** to keep `max_requests`. One tunnel carries
  many requests (keep-alive, HTTP/2), so the count would be of something
  else; rejected.
- **State it as a limitation and change nothing.** Leaves attenuation
  unsound on this path: a narrower grant would keep conferring the wider
  effect. Rejected.
- **A verb of its own for workload egress**, apart from the one `net.http`
  is decided on. It separates "the authority performs a request" from "a
  workload holds a tunnel" by name, which this record does by a rule. It
  changes the capability vocabulary and every profile that grants egress, so
  it is not decided here; F-17's design weighs it.

## Evidence

Each line names what was measured and where. Local results are not hosted
acceptance.

- **Unit** (`crates/dwkd-authority/src/sandbox.rs`): a constrained grant is
  no destination, alone or with both constraints, on any port; an
  unconstrained grant is the only source of a destination, in any order, and
  nothing of a constrained grant completes it; a constraint makes a
  destination of nothing that was not one; the bound counts destinations, not
  constrained grants. Against the derivation as ADR-0048 §5 states it, three
  of the four fail (measured 2026-11-12: a `methods=GET` grant on port 8443
  became the destination `api.example.com:8443`).
- **A real `PROXY_ONLY` environment** (`make sandbox-egress-evidence`,
  `real-oci`): `grant-constrained-https-not-destinations` — three constrained
  grants the admission's record shows as granted are absent from the intent's
  destinations, and the destination one of them shares with an unconstrained
  grant is there once (`authority-grant-derivation`); and
  `constrained-grant-name-not-granted` — from inside the environment, through
  the real relay and proxy, a CONNECT to a name only a constrained grant names
  is refused `TARGET_NOT_GRANTED` and its origin is not reached
  (`connect-proxy:grant`). Both are required cases of the task.
- **Mutation** (`make sandbox-agent-mutations`): the guard removed — a
  constrained grant becomes a destination again — must be killed.

**Measured locally, 2026-11-12** — Linux, Docker Engine 29.9.3, one identity.
These are not hosted acceptance.

- The derivation's unit tests pass: 13 of 13 under `sandbox::`, 437 in the
  authority's library suite.
- `make sandbox-egress-evidence` passes, with both cases reported at
  `real-oci`.
- The same task with the guard removed fails: the real authority records
  `methods.example.com` and `counted.example.com` among a real environment's
  destinations.
- `make sandbox-agent-mutations` kills 12 of 12, this mutant in the
  authority's unit suite.

Acceptance needs the hosted `sandbox-egress` job, the three-platform tests,
the `boundaries` job and the `m5e-gate` job green on the committed revision,
and the mutation review's result recorded.

## Revisit if

- a tunnel can keep a constraint — a decision that the proxy terminates TLS,
  or a kernel-performed fetch that replaces the tunnel for a class of
  destination;
- a constraint is added to the network verbs;
- workload egress gets a verb of its own, which would make this rule that
  verb's definition.
