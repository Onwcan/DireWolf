# ADR-0059: M5e.2 — F-E6-HOSTNET: a `PROXY_ONLY` environment's peer joins only a network namespace the runtime's record shows is the environment's own

**Status:** Proposed · **Date:** 2026-11-08 · **Would amend (only on the owner's acceptance, after its hosted evidence passes):** [ADR-0048](0048-m5b-proxy-only-topology-and-connect-proxy.md) §§2, 10 (the preparation order: the environment's record is read before its peer is made) · **Refines:** [ADR-0058](0058-m5e-proxy-only-hard-rules-weakened-in-a-real-environment.md) §§4, 5, 8 (what E6's host-network case must show) · **Addresses:** finding F-E6-HOSTNET ([M5E_ASSURANCE_PLAN.md](../M5E_ASSURANCE_PLAN.md) §5a), observed by the hosted E6 run at `3ca842c` · **Implementation authorised by:** the owner, 2026-11-08 ("Build the fix first") — the implementation and its evidence path only: not an acceptance of this record or of ADR-0058, not evidence, and not a change to M5's acceptance contract

> **The broker no longer makes a `PROXY_ONLY` environment's setup or relay
> until the runtime's own record of the started environment shows a network
> namespace of its own** — the runtime's `none` network and no other, nothing
> published, no extra host: exactly `HOST_NETWORK_ISOLATED`, which
> `PROXY_ONLY` already requires. Otherwise it makes neither, says so, and
> measures: the environment is refused as before, but nothing of the run is
> put into a namespace that is not the environment's. E6's host-network case
> must now show no setup, no relay, and the host's loopback unchanged, kept
> as a raw observation. Built 2026-11-08; **hosted evidence pending** — the
> hosted run that observed F-E6-HOSTNET was of the broker before this change.

## Context

**What was observed.** The owner committed E6 (ADR-0058) as `3ca842c`. Its
required job ran in hosted run
[42484188848](https://github.com/Onwcan/DireWolf/actions/runs/42484188848)
(attempt 1, run no. 141; a GitHub-hosted Ubuntu 26 runner, image
20261101.186.1, kernel 7.0.0-1019-azure, Docker 29.4.2, API 1.54), which the
owner reported green. An offline review of its downloaded log
(`make sandbox-proxy-weakened-review`, manifest SHA-256 `0e3d3e00…`, 136 raw
observations) held. Its host-network case showed what ADR-0058 §8 predicted.
The daemon's record of the environment says `NetworkMode: host`, its sandbox
key the host's own namespace. The broker connects the peer before it
measures (ADR-0048 §10), and its requests show the setup and the relay
created and started. So the setup added `169.254.7.1/32` to the runner's own
loopback, and the case reported `host-loopback-added:169.254.7.1/32`. The
relay served the run's proxy on the host's network until the measurement
refused the environment and tore it down: the case took well under a second
from the environment's start to its last observation. The teardown removed
the containers and the listener, not the address.

The environment was refused — never kept, never fail-open — but the broker
changed the host, and exposed the run's grant there, under a runtime that ran
the environment outside `--network none` and said so in its own record.

**A gap in E6's review.** What the host's loopback gained was a field of the
case's line, not a raw observation: changing it to `none` in the published log
still passed the offline review. The line was the test's word alone.

**Why the order mattered.** ADR-0048 §10's preparation is: open the proxy →
create and start the environment → check the relay's digest → setup → create
and start the relay → measure → keep, or take it down whole. The setup — root,
`NET_ADMIN`, `--network container:<environment>` — joins whatever namespace
the runtime gave the environment, and only the measurement, afterwards, judges
which one that was.

**The owner's decision.** On 2026-11-08, asked whether to accept the residue
or build the remedy before ADR-0058's acceptance, the owner directed: build
the fix first. E6 is then evidenced again, hosted, over the fixed broker.

## Decision (proposed)

### 1. The peer's gate

Once the environment has started, and before anything is done for its peer,
the broker reads the runtime's record of it (the same `container inspect` the
measurement reads; `oci.rs`, `connect_peer`) and makes the peer only if that
record is labelled as this environment of this store and run and is judged
`HOST_NETWORK_ISOLATED` (`inspect.rs`, `Record::peer_may_join`): the
runtime's `none` network and no other attached, no port bound or published, no
extra host. That namespace is the environment's own and holds its loopback
alone. Otherwise the broker makes neither the setup nor the relay, emits
`relay_withheld network=FAIL` (`=UNOBSERVABLE` when the record could not be
read or does not say), and measures. The relay's digest, the setup and the
relay then follow as before. Preparation becomes:

open the proxy → create and start the environment → **read its record: a
namespace of its own, or no peer** → check the relay's digest → setup → create
and start the relay → measure → keep, or take it down whole.

### 2. What it changes, and what it does not

- **Nothing the production decision keeps is refused by it.** The gate is
  `HOST_NETWORK_ISOLATED`'s own verdict over the record, and `PROXY_ONLY`
  requires that invariant (`required_invariants`): an environment whose peer
  is withheld would have been refused anyway. The one new refusal is a record
  the runtime could not answer at the gate — the peer is withheld and the
  environment refused, fail-closed; a retry costs a preparation, never a
  weaker environment.
- **Narrow on purpose.** Only the namespace is gated. Every other hard rule
  broken still gets its peer, in a namespace that is the environment's own and
  touches nothing else, and the measurement refuses it as before — so E6 keeps
  observing how each weakening and the topology interact (ADR-0057 §3, U3).
- **Unchanged:** the plan, the measurement, the invariants and their vantages,
  the decision (`oci::clean`), the private protocol, the labels, `NO_NETWORK`
  (which has no peer). One more `inspect` per `PROXY_ONLY` preparation.
- **The record is the runtime's**, trusted for its own configuration as
  ADR-0047 §8 states. A runtime that records `none` and runs the environment in
  the host's namespace is not stopped by this gate: the setup would change the
  host's loopback, and the inside vantage (`CONTAINER_NETWORK_ISOLATED`) would
  refuse the environment afterwards, as before. ADR-0058 states that no case
  models such a runtime.

### 3. What E6's host-network case must now show

ADR-0058's evidence is refined, its cases, rows and levels unchanged:

1. **In the test.** No setup and no relay made, or asked for, for that
   environment; the broker's own `relay_withheld network=FAIL`;
   `HOST_PROXY_RELAY` and `HOST_RELAY_DIGEST` failing (no peer measured); the
   host's IPv4 loopback (`ip -o -4 addr show dev lo`) observed before and
   after, kept raw as the case's ninth file `host-loopback.txt`, holding
   `127.0.0.1/8`, never the proxy address, and unchanged. The line says
   `host-loopback-added:none`, and the gate accepts nothing else. Every other
   case: the setup and the relay made, and no `relay_withheld`.
2. **From the raw bytes** (`e6_check_raw`). The same, independently: the
   loopback file read and compared; the line's residue the file's; no setup
   or relay `create` in that case's requests; and, for every case, the
   environment's record read after it started and before any peer was asked
   for — the gate, seen at the socket. A tampered residue now fails the
   offline review.
3. **The record kept** (`record.json`) is the measurement's own read — the
   first after its version check — not the gate's.
4. **Still a disposable runner's alone** (ADR-0058 §5): a broker without this
   gate changes the host, and the test refuses the case anywhere else.

Run 42484188848's log fails the new review, by design: its host case made a
peer in the host's namespace. It stays what it is — the observation that
produced this record — and is not E6 evidence for the broker as it now is.

### 4. Built (2026-11-08), not evidence

The gate and its unit tests: the conforming record lets the peer join; the
host's, another container's, a bridge or user network, a second network, a
published port, an extra host or another environment's labels withhold it; a
record that does not say is never a pass; of every hard rule broken in the
record, only the network's withholds the peer, and each one broken is still
refused; over the real runtime's captured `PROXY_ONLY` record, the same. E6's
test and its Python gate and review, as §3 states, with synthetic negative
controls for each way the host case could mislead. A local development run of
E6 against a developer's Docker Desktop is stated in M5E_ASSURANCE_PLAN.md
§3a.1; the host's network is refused there by the test, as ADR-0058 §5
requires, so nothing local shows this gate on a namespace that is the host's.

### 5. What resolves F-E6-HOSTNET

1. The owner commits this change; the hosted `sandbox-proxy-weakened` job at
   that commit reports the host's network with `host-loopback-added:none`, no
   setup and no relay, and every other case as ADR-0058 requires; `ci` with
   it.
2. The owner reviews that log (`make sandbox-proxy-weakened-review`).
3. The owner accepts this record (then `dwcheck adr --record`), and ADR-0058
   by its §9.

Until then F-E6-HOSTNET is **OBSERVED, FIX BUILT — hosted evidence pending**,
E6 is NOT EXERCISED for the broker as it now is, R3 is not met, M5e.2 stays IN
PROGRESS, and issue #19 stays open.

## Consequences

**Positive.** A runtime that ignores `--network none` and says so no longer
gets the broker to change the host's loopback or to serve a run's grant on the
host's network. It is held by a required job: a later change that makes a peer
in a namespace that is not the environment's fails E6 at the socket, in the
raw bytes and in the review. The review gap is closed: what the host's
loopback held is a raw, digested observation.

**Negative.** One more runtime call per `PROXY_ONLY` preparation. A record the
runtime fails to answer at the gate refuses an environment that might
otherwise have been kept. E6 must run hosted again before ADR-0058 can be
accepted. The gate trusts the record: a runtime that misreports it is
caught only afterwards, by the inside vantage, after the setup has run. The
host-network case still runs only on a disposable runner, because what
protects the host there is the gate under test. ADR-0048 is accepted and
immutable, so its §10 is amended only by this record's acceptance.

## Alternatives considered

**Judge every host invariant before the peer** (ADR-0058 §8's first wording).
Rejected: broader than the finding — no other hard rule makes the setup touch
anything but the environment's own namespace — and it would withhold the peer
from fourteen rows, hiding the interaction between each weakening and the
topology that E6 exists to observe.

**Measure fully, the probe included, before the peer.** Rejected: the probe's
`PROXY_ONLY` measurement includes `CONTAINER_PROXY_REACHABLE`, which needs the
relay; it would take two probe runs or a new probe mode for nothing the record
does not already say.

**Remove the address at teardown.** Rejected: it cleans up afterwards. The
relay would still serve the grant on the host's network meanwhile, and a broker
that crashes between the setup and the teardown would leave the address.

**Accept the residue as a residual.** Not chosen: the owner directed the fix.

## Revisit if

A runtime is found that records `none` but runs the environment elsewhere (a
check from inside, before the setup, would then be needed); the topology, the
setup or the relay changes; or the hosted E6 at the fixed commit shows anything
but no peer and an unchanged loopback for the host's network, or a change in
any other case.
