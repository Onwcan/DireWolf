# ADR-0073: F-06 OF-2 -- the operator's egress allowlist is a ceiling every policy is under: no network action reaches a destination the operator did not name, whatever a policy allows

**Status:** Proposed · **Date:** 2026-11-20 (implementation authorised 2026-11-20 as ADR-0071's OF-2; designed, built and tested locally 2026-11-20; hosted evidence pending; nothing here is accepted) · **Builds on:** [ADR-0071](0071-f06-an-operator-egress-allowlist-every-shipped-network-rule-requires.md) (Proposed; its OF-1 approved as implemented 2026-11-20), [ADR-0050](0050-m5c-kernel-performed-net-http-ssrf-redirects-and-credential-egress.md), [ADR-0061](0061-workload-egress-decided-by-policy-novelty-and-exposure.md), [ADR-0028](0028-policy-input-ownership.md) · **Would amend (on acceptance):** ADR-0071 §5 ("a policy file of the operator's own is unchanged") · **Leaves unchanged:** DWKP, the private broker protocol, the store's schema, the allowlist's grammar and its one flag, the shipped packs, the address guard, DNS pinning, SNI agreement and every budget

> **The operator's `--egress-allowlist` is now a ceiling, not a predicate a
> policy may choose to require.** After a policy's rules and postconditions,
> the evaluator denies every network action whose destination the allowlist
> does not name -- exact host, port and path -- whatever the policy said:
> a shipped pack, an operator's own file, a rule that allows
> `network.https` with no condition at all. The input is computed once, by
> the authority, from the operator's file; no caller and no run supplies it.
> The ceiling only narrows: a rule that denies still denies, by its own name,
> and nothing past the ceiling -- the grant, taint and novelty, the address
> guard, budgets -- is widened by it.

## Context

ADR-0071 made every shipped network rule require `destination_allowlisted`:
without the operator's file, BALANCED and POWER reach no destination. An
operator's own policy file could still allow network actions without the
predicate -- `when.verb = "network.https"` and nothing else -- and then reach
every destination a run's grant named. The allowlist held only where a
policy author remembered it. ADR-0071 left the choice as OF-2; on 2026-11-20
its implementation was authorised as an independent boundary, not a
convention for policy authors.

The authority already has one decision function for every action, the state
layer's `query::decide`, and it is the policy evaluator's only product
caller. Every path that can produce agent-initiated outbound traffic decides
there: each `net.http` hop (a redirect's hop decided again from the start,
ADR-0050), each destination, novelty, taint and address piece of a
workload's launch (F-17, ADR-0061), and every preview of a proposed network
action through the query path. There is no third network path.

## Decision

### 1. The ceiling is the evaluator's last step

`policy::evaluate` runs the policy's two phases and then the ceiling: a
decision about a network action (`network.*`) that is not `DENY` stands only
where the action's `destination_allowlisted` is `true`; otherwise it becomes
`DENY`. Missing counts as outside, so an action built without the input can
never reach the network. A decision that already denies -- by a rule, by
`default`, or because an input was unresolved -- is returned as it is, and a
non-network action is untouched.

### 2. The input is the authority's, computed once

`query::decide` computes the input for every network action from the
allowlist the authority read at start (`EgressAllowlist::admits`): the
action's capability names one exact host and one port, and an entry names
both for the path the action's environment takes -- `Host`, a
kernel-performed `net.http` hop (`net_http`); `Sandbox`, a workload's tunnel
(`workload`). A wildcard host, no port or another scope family is outside.
Whatever the action's builder or caller set is replaced. The two builders
(`net.http`'s hop and a workload's launch) no longer compute it: one place,
one answer, and the policy's predicate reads the same value. No DWKP message,
private-protocol field or runtime input carries it.

### 3. The decision names the ceiling

A narrowed decision is `DENY` from the reserved rule
`operator-egress-ceiling`, reason `OUTSIDE_EGRESS_ALLOWLIST`, source
`--egress-allowlist:1` (the file as a whole: no line decides, the absence of
an entry does). It is recorded as one last postcondition: the rule the policy
matched stays on the decision, so an explanation shows what the policy said
and what overruled it; no approval is offered and no obligation kept. No
policy file may declare the id or claim the reason -- the loader refuses
both. On the wire a `net.http` denial is `DENIED_BY_RULE` naming the
ceiling's rule and source; a workload's cell summary names it; the audit
records both. Nothing in DWKP changes.

### 4. What it does not change

- A rule that denies keeps its decision and its name, inside the ceiling or
  out (POWER's `deny-internal-ranges` on a named metadata address, an
  operator's own `DENY`).
- A tainted run's novel destination that a policy would send for approval is
  denied outside the ceiling -- nobody is asked to approve past it -- and
  still needs its approval inside it.
- The run's grant, taint and novelty, the address guard (a named private or
  metadata address is still refused), DNS pinning (one resolution per hop),
  SNI agreement, credential origin binding and every budget decide in their
  order, unchanged. The ceiling never widens any of them.
- The shipped packs keep requiring the predicate: the same input, now also
  under the ceiling.

### 5. Revocation and lifecycle

The file is read once, at start. Removing an entry takes effect at the next
start; a restart reaps every run (ADR-0071 §6), so no run outlives the list
it was decided under, and every `net.http` hop after it is decided against
the new list. A workload already launched keeps the decision it was launched
with until it ends (ADR-0061): **editing the file revokes nothing until the
authority restarts.** F-17's recorded context digest includes the file
(ADR-0071 §6).

### 6. Compatibility

An operator policy that allowed network actions without naming destinations
loses its network until the operator lists each one. Migration: write
`--egress-allowlist` with one entry per destination and path -- every hop,
including a CDN host a redirect leads to, and both `net_http` and `workload`
where both reach it. SAFE has no network rule and is unchanged; BALANCED and
POWER already required the input and behave as before. A deployment started
without the file says so: `egress allowlist: none -- the egress ceiling
admits no destination`.

## Consequences

- No agent-initiated network action reaches a destination the operator did
  not name, whatever policy is loaded.
- A policy file is again only policy: the operator's ceiling is not
  something a rule can omit.
- Evidence suites and test harnesses that reach origins under operator test
  policies name those origins in their allowlist, by exact host and port.

## Residuals

- An allowlisted upload-capable host is still an exfiltration route,
  bounded by its budgets; domain fronting through an allowlisted shared host
  (R12) is unchanged.
- No immediate revocation: a running workload's tunnels end with it, and a
  file change waits for a restart.
- The allowlist is not part of the policy revision recorded with each
  decision; the ceiling's decisions name it, and F-17's context digest
  includes it (OC-2).
- An external daemon's own egress (an Ollama the operator runs) is not
  DireWolf's and is not under this ceiling (ADR-0072 OM-3).

## Alternatives considered

- **A loader rule requiring the predicate in every network `ALLOW`.**
  Refused: it is still a property of a policy file, and a rule that allows
  by another route would carry it only by convention.
- **The ceiling in each builder.** Refused: two places to keep equal, and a
  third network path would have to remember it.
- **The ceiling in the broker.** Refused: the broker performs what the
  authority decided; a second decision point would disagree with the
  audited one.

## Owner decisions

- **OC-1** accept this ADR (and with it ADR-0071 §5's amendment);
- **OC-2** whether the allowlist's digest joins the policy revision each
  decision records;
- **OC-3** ADR-0071 OF-3 (partially decided 2026-11-20): a future
  `model_download` path needs its own separately authorised egress, and
  per-entry quotas are evaluated on their own. Neither is built here.

## Evidence

- `crates/dwkd-authority/src/policy/fixtures.rs`: an operator policy
  allowing every host is under the ceiling (not said, said false, said true;
  sandbox and host; a non-network action untouched); an approval cannot lift
  it and a denial keeps its name; no file may declare the id or claim the
  reason.
- `crates/dwkd-authority/src/state/net_http/tests.rs`
  (`of2_a_policy_allowing_every_hop_reaches_only_what_the_operator_allowlisted`):
  absent, other path, other port, neighbour denied by the ceiling with
  nothing resolved or sent; exact performed; a denying rule kept.
- `crates/dwkd-authority/tests/state_query.rs`
  (`a_proposal_cannot_say_its_own_destination_is_allowlisted`): a caller's
  claim is replaced by the operator's file.
- `crates/dwkd-authority/tests/net_http_evidence.rs`
  (`an_operator_policy_cannot_lift_the_egress_ceiling`, `make
  net-http-evidence`): the real broker and real origins under an operator
  policy allowing every hop -- seven required cases, `of2-operator-policy-*`.
- `make egress-allowlist-mutations`: G11 and G12 retargeted at the one
  computation, and G14--G19 for the ceiling (it narrows nothing, a missing
  input counts as inside, an approval is left to a human, a caller's claim
  stands, the reserved id or reason is a file's), each killed by a named
  test.
- `tests/architecture/test_f06_egress_allowlist.py`: one setter, the
  evaluator's ceiling, its one caller.

## Rollback and deployment

Reverting returns the allowlist to a predicate only the shipped packs
require. Deploying it means every operator policy's destinations are in the
allowlist before the restart that loads it.

## Revisit if

A second network path is added; a destination can be decided outside
`query::decide`; the allowlist becomes reloadable at run time; or OC-2 is
decided.
