# ADR-0061: Each sandboxed workload's egress is decided by policy, the run's novelty and its workspace's exposure, and held by the broker for the workload's life

**Status:** Proposed · **Date:** 2026-11-13 (designed and reviewed 2026-11-12, built 2026-11-13 for finding F-17; its hosted evidence is pending and nothing here is accepted) · **Would amend (on acceptance):** [ADR-0048](0048-m5b-proxy-only-topology-and-connect-proxy.md) §§5–7, 12 (what the CONNECT proxy carries, in what order it decides, and what it records), [ADR-0052](0052-m5d-sandboxed-process-exec.md) §§5, 8 (what a workload's start carries and what its ending reports) · **Builds on:** [ADR-0060](0060-a-constrained-network-grant-gives-no-proxy-only-destination.md) (Proposed: which grants are destinations) · **Addresses:** finding F-17

> **A tunnel opens only while a workload the broker supervises holds an
> egress authorisation that allows it.** The authority decides that
> authorisation at each launch, by both gates, for every destination of the
> environment's grant: `query::decide` on `network.https:<host>:<port>` in
> `SANDBOX`, once for each combination of the run's novelty for the
> destination (`NOVEL`, `SEEN`) and the workspace root's exposure (pristine,
> exposed), and once per piece of the address space the policy's own ranges
> cut. The broker holds the decision for exactly the workload's life, judges
> every CONNECT and every pinned address by it, and on the first byte any
> origin sends to any workload on a workspace root, switches every
> authorisation on that root to its exposed cells and ends every open tunnel
> they no longer allow -- before that byte is forwarded. Every tunnel this
> allows, ADR-0048 already allowed: the proxy's ceiling, address guard,
> pinned resolution, server-name agreement and budgets are unchanged and
> decide first.

Proposed. The change is built so that its evidence can run; ADR-0048's and
ADR-0052's bodies are unchanged, as every accepted record's is (README.md,
rule 1), and their sections stay the accepted design until this record is
accepted.

## Context

**What the proxy enforced.** ADR-0048 gives a `PROXY_ONLY` environment a
grant at preparation -- the run's exact `network.https` destinations
(ADR-0060: the unconstrained ones), a tunnel limit and byte budgets -- and the
broker's CONNECT proxy holds every tunnel to it: the exact host and port,
the IP guard over the whole DNS answer, one pinned resolution, server-name
agreement before the dial, the budgets at the socket. The proxy does not
terminate TLS and evaluates no policy.

**Finding F-17** (review of 2026-11-12). Policy never decided a tunnel. A
destination was granted at admission, and from then on every workload of
the run reached it, whatever the active policy said about `network.https`:

- a rule that denies a host, or an address range (`power`'s
  `deny-internal-ranges`), denied `net.http` and was ignored by tunnels;
- `approve-egress-when-tainted` (`balanced`, `power`) -- a tainted run's
  first contact with a destination needs a human -- stopped `net.http` and
  not a workload, so a workload could send workspace content to a granted
  host it had never reached, after it had read untrusted content;
- a `network.https` rule's obligations (`max_output_bytes`) bound `net.http`
  and nothing on a tunnel.

It was not a route to a host the run was not granted, and not a bypass of
ADR-0048's rules: the gap was the policy gate, on the one path where the
authority did not decide each effect.

**Constraints the design has to live with.** The proxy sees a CONNECT
target, a resolved address, a server name and byte counts; it sees no
request (ADR-0048 §§4, 7). A policy decision needs the run's context --
taint, origin, privacy, novelty -- which only the authority holds. The
broker runs no policy (ADR-0018). A tunnel's address is known only after
resolution, inside the broker. And content a workload downloads can be read
by any later workload on the same workspace root, including another run's
(`state/workspace.rs`).

## Decision

### 1. Invariants (EG-1 to EG-14)

- **EG-1 Ceiling.** Only an exact, unconstrained `network.https` grant is a
  destination (ADR-0048 §5, ADR-0060). The broker checks it first.
- **EG-2 Both gates per tunnel.** A tunnel opens only if its cell allows
  every pinned address. A cell is the authority's decision for the
  destination, chosen by novelty and exposure at the moment of the check,
  from `query::decide` on `network.https:<host>:<port>` in `SANDBOX`.
- **EG-3 Decision before effect.** The authorisation and every input it was
  computed from are durable in the workload's intent transaction before the
  broker hears of the workload.
- **EG-4 Lifetime.** An authorisation exists only while its workload is
  supervised; its tunnels end when the workload ends (`WORKLOAD_ENDED`), and
  a CONNECT with none in force is refused (`NOT_AUTHORISED`).
- **EG-5 Fixed context.** Policy revision, origin, launch taint (T0),
  privacy, configuration flags and standing grants cannot change under a
  running workload: the authority compares the context's digest at every
  collection and destroys the environment if it differs
  (`EGRESS_CONTEXT_DRIFT`).
- **EG-6 Exact addresses.** An address piece is exactly a set of addresses on
  which the production evaluator decides one way. A DNS answer partly
  allowed is refused whole (`POLICY_ADDRESS_DENIED`). A policy that cannot
  be partitioned refuses every address-dependent cell
  (`EGRESS_POLICY_TOO_FINE`).
- **EG-7 Novelty.** A destination becomes `SEEN` for the run only on the first
  byte an origin sends over an authorised tunnel. An uncertain reach takes
  the stricter of the `NOVEL` and `SEEN` decisions. Tunnel reach never
  feeds `net.http` novelty.
- **EG-8 Exposure.** On the first origin byte of any tunnel of any
  environment on a workspace root, before that byte is forwarded, every
  authorisation on the root switches to its exposed cells -- the stricter of
  the decisions at every taint from T0 to `EXTERNAL_UNTRUSTED` -- and every
  open tunnel on the root its exposed cell no longer allows is ended
  (`EXPOSURE_REVOKED`). The tunnel the byte came over has reached its
  destination and is held to the seen cell; every other open tunnel keeps
  the novelty it was admitted with, the stricter. Exposure is durable per
  root; an uncertain ending counts as exposed.
- **EG-9 Obligations.** Only obligations a tunnel can keep are accepted:
  `max_output_bytes` becomes a per-tunnel downstream bound, the smallest
  across the cell's allowed pieces (`TUNNEL_OUTPUT_LIMIT`), and
  `audit_level` is recorded. Any other obligation refuses the cell
  (`OBLIGATION_UNENFORCEABLE` in the decision record).
- **EG-10 Fail closed.** An error, an exceeded bound, an unevaluable input, a
  missing proxy or a missing authorisation refuses. Nothing is truncated.
- **EG-11 Typed facts.** The broker evaluates no policy. The one address
  lookup lives in `dwk-proto` (`WorkloadEgress::piece`), shared by the
  broker and the authority's tests. The broker refuses an authorisation
  naming a destination outside its environment's grant
  (`EGRESS_NOT_GRANTED`).
- **EG-12 Observation.** A workload's ending reports, per destination: how
  each CONNECT ended, bytes each way, whether it was reached, and the
  distinct addresses judged (at most 8, with a count of the rest), and
  whether any origin byte reached the workload. The intent records every
  input, so the authorisation can be decided again to its digest.
- **EG-13 Fixed rules first.** The ceiling and the metadata name are checked
  before the authorisation; the IP guard, the pinned resolution,
  server-name agreement and the budgets are unchanged.
- **EG-14 Only narrows.** Every tunnel this allows, ADR-0048 allowed. No path
  is added.

### 2. Cells

Each destination of the grant carries four cells: novelty (`NOVEL`, `SEEN`)
by exposure (pristine, exposed). A pristine cell is decided at the run's
taint at launch (T0). An exposed cell is the meet -- a piece allowed only
where every decision allows it, at the tightest bound -- of the decisions at
every taint from T0 to `EXTERNAL_UNTRUSTED`: taint only rises, so those are
the only levels the run can reach. A destination the run has reached starts
`SEEN`; a workload starts exposed when its root's durable exposure record
says so, or when another workload on the root is still launching with an
authorisation that allows anything. Novelty comes from the run's `net.http`
hops that completed TLS and from tunnel reach; a reach that is uncertain
decides both ways and keeps the stricter.

A `REQUIRE_APPROVAL` decision is a refusal: every admitted run is
unattended (`api`), the shipped packs' `deny-approval-needed-when-unattended`
postcondition denies it, and no approval path for a cell exists before
F-18 / M6.

### 3. The address partition

Let R be every range in the `ip_in` of every rule and postcondition whose
verb admits `network.https`. Within a family ranges nest or are disjoint,
and the only production reader of a destination address in `policy/` is
`address_in`; so the evaluator's answer depends on an address only through
its most specific range in R, or "none" for its family. R cuts the address
space into at most |R| + 2 pieces -- piece 0 the IPv4 addresses in no range,
piece 1 the IPv6 ones, piece 2 + i the addresses whose most specific range
is range i -- and the decision is taken once per non-empty piece, at a
representative address, by the production evaluator itself, so first-match
order, postconditions and the mandatory default are what decide. A decision
that does not need the address (the evaluator returns no
`Unevaluable(ResolvedAddress)` without one) holds for every address and is
used whole. IPv4-mapped, compatible and NAT64 addresses are IPv6 and never
converted. More than 256 ranges refuses every address-dependent cell
(`EGRESS_POLICY_TOO_FINE`); activation never fails on it.
`policy/partition_tests.rs` holds the partition to the evaluator by property
tests (exactness over random policies and every range boundary, the
shortcut, the representatives, the shared lookup);
`tests/architecture/test_f17_partition_premise.py` holds the premise to the
source (outside `policy/`, whose code and tests do no IO).

### 4. Wire, store and bounds

- Private protocol **12** (from 11): `broker.workload_start` and
  `broker.workload_secret_start` carry `egress` (a `WorkloadEgress`) exactly
  for a `PROXY_ONLY` environment; `broker.workload_collect`'s ending carries
  `egress` (a `WorkloadEgressReport`); refusal `EGRESS_NOT_GRANTED`; six new
  dispositions, `NOT_AUTHORISED`, `POLICY_DENIED`, `POLICY_ADDRESS_DENIED`,
  `TUNNEL_OUTPUT_LIMIT`, `WORKLOAD_ENDED`, `EXPOSURE_REVOKED` (29 of the 32
  the protocol allows). Public DWKP is unchanged.
- Store schema **12** (from 11): `workload_egress` (one row per workload: the
  root, the authorisation and its digest, the per-destination decisions,
  the context digest, settled once to `REPORTED`, `NOTHING_RAN` or
  `UNCERTAIN`, never deleted), `tunnel_reach` and `workspace_exposure`
  (append-only).
- An authorisation is at most 128 KiB encoded, asserted at compile time to
  fit the private frame beside the largest workload start; a larger one
  refuses the launch (`EGRESS_AUTHORISATION_TOO_LARGE`).

### 5. The proxy's order

Parse; the ceiling; the metadata name; an authorisation in force
(`NOT_AUTHORISED`); the cell allows some piece (`POLICY_DENIED`, before any
resolution); the tunnel limit; resolve; the guard; every pinned address in
an allowed piece (`POLICY_ADDRESS_DENIED`), taken under the root's lock
with the exposure then in force; `200`; the server name; the dial; on the
first origin byte, under the same lock, the reach and the exposure
transition and the re-check of every open tunnel on the root -- the tunnel
that delivered the byte as `SEEN`, every other by the novelty it was
admitted with -- before the byte is forwarded; the pump, with the
per-tunnel bound. Under the shipped packs a tainted run's reached
destination stays allowed, so the tunnel that reached it carries its
answer; under a policy that refuses tainted traffic outright it is shut
before the workload sees a byte. A tunnel admitted on a root already
exposed keeps the cell it was admitted with.

### 6. Settlement and recovery

A report consistent with the authorisation settles it `REPORTED`: each
reached destination is recorded as certain reach, and an exposed report
exposes the root. A start provably refused settles it `NOTHING_RAN`. Any
other ending -- a lost, malformed or inconsistent report, an `UNKNOWN`
ending, and every workload `reconcile_open` closes after a crash -- settles
it `UNCERTAIN`: every destination some cell allows becomes uncertain reach,
and the root is exposed. No recovery path restores a less restrictive
authorisation.

### 7. Audit

The workload's intent records `egress_sha256`, `egress_context_sha256`,
`egress_exposed_at_start`, `egress_partition` and `egress_decisions` (per
destination: its reach, and per cell how many pieces it allows and the rules
that decided). The store keeps the authorisation and the per-piece rules. An
environment's destruction records its proxy's counters and whether every
report its workloads gave fits within them (`egress_workload_reports`,
`egress_reports_within_counters`).

### 8. Evidence re-baselined

M5's real-runtime evidence opened tunnels with no workload. Since F-17 the
broker's own evidence opens them while a supervised workload holds an
authorisation allowing the environment's whole grant, so every M5 case is
decided by the mechanism it always was, and the same CONNECT with none
held is a new negative case. The authority's evidence policies gain one
`network.https` rule each -- `when.environment = "sandbox"` and
`when.host_matches` naming exactly the hosts their cases need -- and a
standing control: a granted host no rule allows, refused before resolution.
No case is removed, renamed, re-levelled or re-attributed;
`tests/architecture/m5e_cases_before_f17.txt` pins all 647 attributed cases,
and 21 are added to them (11 at the broker and 9 through the authority on a
real runtime, the registry's standing control hosted); the agent suite's own
contract gains its standing control (`a04-granted-name-denied-by-policy`). `make sandbox-egress-policy-mutations` weakens each guard of this
record in turn.

## Consequences

- The shipped packs now decide sandboxed egress as they decide `net.http`.
  Under `balanced` or `power`, once a workspace root is exposed, a workload
  reaches only destinations its run has already reached that the allowlist
  permits: an install that touches a second host (an index, then its file
  host) stops at the second host. That is the packs' own taint rule; an
  operator who wants registries exempt writes an explicit rule before it.
  The shipped packs are not changed here (F-06, F-12).
- A policy must allow a destination for a workload to reach it. A
  `PROXY_ONLY` configuration under a policy with no `network.https` rule
  reaches nothing.
- Every M5 evidence policy, and the M5e.5 manual workflow's, carries an
  explicit sandbox network rule.
- The broker holds per-root state in memory; a broker restart loses it, and
  the authority's durable exposure record is what the next launch is decided
  by.

## Residuals and what is assigned elsewhere

- **F-01:** which taint level network content carries (and loosening "the
  stricter of every level" to it); the run's durable taint and the taint of
  workload output after an exposed workload; `net.http`, filesystem, exec
  and approval decisions after it; content a tainted run's cognition writes
  into a shared root; how taint provenance is shown.
- **F-02:** a durable intent per tunnel or per-tunnel mediation; concurrency
  within one run, which would have to turn the tripwire into
  re-authorisation.
- **F-18 / M6:** every approval path; approval of a cell before launch,
  bound per ADR-0021, by an approver distinct from the subject.
- **Not claimed:** which bytes derived from which content; containment of a
  workload that is hostile from its first instruction, which may use its
  pristine cells before anything reaches it -- correct under the policy,
  since nothing external has reached the run then. Tunnel reach is weaker
  than `net.http`'s verified handshake, which is why it never feeds
  `net.http` novelty. Audit is per workload and destination, not per
  tunnel; a crash loses tunnel-level detail, recorded as uncertain and
  exposed.

## Alternatives considered

- **A. Preparation-time policy only.** Decide destinations once, at
  preparation. Rejected: the decision goes stale as taint and novelty
  change, and a context change under a running environment would go
  unseen.
- **B. Per-tunnel authority mediation.** The broker asks the authority for
  every CONNECT. Strongest record, but a synchronous round trip per tunnel
  on a single authority worker, and a durable intent per tunnel; it needs
  F-02 first.
- **C. Policy in the broker.** Rejected: the broker would hold the run's
  context and the policy engine, against ADR-0018's split.
- **D (chosen).** Decide per launch, by both gates, for every destination,
  novelty, exposure and address piece; hold the typed result in the broker
  for the workload's life.

## Evidence

Built and run locally on 2026-11-13; **hosted evidence is pending** and the
record stays Proposed until it passes and the decision is accepted:

- unit and property tests: `dwk-proto`'s wire and lookup, the authority's
  partition (P-1 to P-6), decision, settlement and reconciliation, the
  broker's proxy (`egress/tests.rs`), and the in-process route tests
  `f17_*`;
- real runtime: `sandbox_egress.rs`
  (`a_workloads_egress_authorisation_holds_in_the_real_topology` and every
  M5b case under a held workload) and `sandbox_lifecycle.rs` (two F-17
  tests through the real authority), both in `make sandbox-egress-evidence`;
- hosted only: the agent suite's three-identity half, the registry suite and
  the M5e.5 manual workflow, whose policies gained the network rule.

## Revisit if

- F-01 decides the taint network content carries: the exposed cells may
  then be decided at that level, not the strictest.
- F-02 brings per-tunnel durable records or concurrency within a run.
- F-18 / M6 brings an approval path: `REQUIRE_APPROVAL` cells stop being
  refusals.
- A new predicate reads the destination address: the partition's premise
  must be proved again (the structural test fails first).
