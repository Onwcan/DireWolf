# ADR-0040: M3d reconciliation — an admission key outlives its run but never replays it, and a proposed action the authority cannot canonicalise is refused rather than decided

**Status:** Accepted · **Date:** 2026-09-22 · **Amends:** [ADR-0036](0036-m3-authority-operations-and-the-capability-wire-form.md) (§2's claim that `QueryAuthority` with `proposed` "decides"; §6's decision correspondence; §8's bound request, case 3 and its restart paragraph; §10's reason set and pairing table), [ADR-0039](0039-durable-authority-state.md) (§8's digest, its cross-restart and released-run paragraphs; §9's withheld `fs`/`process` case; §12's decision table and its two protocol gaps) · **Refines:** [ADR-0011](0011-session-concurrency.md) (what a lease rotation does to runs), [ADR-0023](0023-dwkp-strict-schema.md) (a breaking change to three response messages, versioned)

> Two claims that M3d inherited could not both be true of the state M3d built,
> and one convention M3d adopted to satisfy the wire was a small lie. This
> record fixes all three before M3d is committed, rather than leaving M3e to
> transport semantics nobody had defined.

## Context

### Contradiction 1: a replay across a tenure change

[ADR-0036](0036-m3-authority-operations-and-the-capability-wire-form.md) §8
says a lost `AdmitRun` response followed by a retry "must resolve to the
admission that already happened", and that durability across restart is M3d's.
The same section binds `epoch` into the request digest. M3d
([ADR-0039](0039-durable-authority-state.md) §7) invalidates every live holder
when the authority restarts, the next `AcquireLease` moves the session to a new
epoch, and every run admitted under the old epoch is reaped.

So after a restart the retry necessarily carries a different epoch, its digest
differs, and M3d answered `IDEMPOTENCY_CONFLICT` — "you sent a different
request" — to a caller that sent the same one. ADR-0039 §8 then reported
"across an authority restart, a replay is unreachable". Both halves were
accurate descriptions of the code; together they quietly retracted the property
§8 had promised, and named the result with a reason that describes a different
fault.

### Contradiction 2: a decision nobody could make

ADR-0036 §2 says `QueryAuthority` carrying `proposed` "exercises the entire
pipeline … and decides". A `proposed` value is a `CapabilityText`. What policy
decides on is a `CanonicalAction`
([POLICY.md](../POLICY.md) §1 rule 3; M3c's `policy::action`): a resolved
capability **plus facts only a canonicaliser can produce** — where it runs, what
address it reaches, whether that destination is new to the run, how its argv
would be interpreted, how many bytes it moves.

M3d built the action from the text alone. It supplied `Environment::Sandbox`
because nothing else could, left every other fact absent, reported `fs` and
`process` proposals as a `WireGap`, reported an unevaluable `ip_in` rule as a
`WireGap`, and answered a proposal outside the vocabulary with
`CAPABILITY_MALFORMED` attributed to the policy's `default` rule "by convention,
because the wire requires a rule". No rule had run.

The fabricated environment was not cosmetic. M3c's predicates read an absent
`argv_safe`, `max_bytes` or `destination_novel` fact as *does not match*. For an
`ALLOW` rule that fails closed; for a `DENY` or `REQUIRE_APPROVAL` rule it
silently switches the rule off. `balanced.toml`'s `approve-egress-when-tainted`
is exactly such a rule, ordered ahead of `allow-package-registries`: evaluated on
an action with no novelty fact, a tainted run's `network.https:github.com`
would have been answered `ALLOW` by the rule after it.

## Decision

### Part 1 — admission across a tenure change

#### Three properties, named apart

| Property | Meaning | M3d provides |
|---|---|---|
| **Duplicate suppression** | One `(subject, session_id, idempotency_key)` never produces a second logical admission, whatever happens between attempts. | **Yes, permanently** — across retries, releases, lease rotations, expiries and authority restarts. The record is never deleted. |
| **Same-response replay** | A retry receives the grant the lost response carried. | **Within the tenure that admitted it, while its run is active.** |
| **Run resumption** | A run continues after the authority or the runtime lost it. | **No.** A run's authority ends with its lease. Resumption re-admits under a new key; checkpoint and resume semantics are M9's ([RELIABILITY.md](../RELIABILITY.md) §7: "a run suspended for three days must not resume on authority revoked yesterday"). |

ADR-0036 §8 used "resolve to the admission that already happened" for all
three. They are different properties, and only the first survives a tenure
change without breaking something else.

#### The options

| | A. Keep `epoch` bound; a retry in a new tenure is `IDEMPOTENCY_CONFLICT` | B. Unbind `epoch`; a matching digest returns the recorded `RunGrant` | C. Rebind the admission to the new tenure | **D. Unbind `epoch`; replay only a live run; an ended admission is a typed permanent refusal** |
|---|---|---|---|---|
| Stale-writer fencing | holds (fence first) | holds (fence first) | holds only if the rebind is itself fenced | holds (fence first) |
| Duplicate-admission prevention | holds | holds | holds | holds |
| Lost-response recovery | within the tenure; across it, the caller is told something false | "recovers" a grant whose run is reaped and whose epoch is fenced — a success answer that authorises nothing | recovers, by reviving authority | within the tenure; across it, a true answer and a clear remedy |
| Released-run non-resurrection | holds | holds, but hands back the released run's grant as if current | **violated** unless re-minted, which is a second admission | holds, and says so |
| Authority restart | the restart's effect is misreported as a client error | the restart's effect is hidden behind a success | the restart is undone: pre-crash authority returns | the restart's effect is reported as what it is |
| Old runtime / zombie | fenced | fenced | fenced, but a revived run is a target | fenced |
| Audit correctness | records a conflict that did not happen | records a replay of authority that no longer exists | must invent a `rebound` transition and its evidence | records the refusal with the original run and its end state |
| M9 boundary | respected | respected | **crossed**: reviving a reaped run is resumption | respected |
| Client behaviour | one reason for two situations with the same remedy; a real conflict is indistinguishable from an ended admission | must check whether a returned grant is usable, i.e. treat success as maybe-failure | simplest-looking, and wrong | two reasons, one remedy each: a conflict is a bug, an ended admission means admit again under a new key |

C is rejected outright: there is no way to put a reaped run's authority under a
new epoch that is not either resurrection or a second admission, and "rebind"
would be a name for one of those. B is rejected because a `RunGrant` must mean
*a run you may use now*. A is the smallest edit and describes the restart as the
caller's mistake. **D is chosen.**

#### The contract

**The bound request.** The RFC 8785 encoding of the decoded `AdmitRun` with
`id`, `ts`, `correlation_id`, `causation_id` **and `epoch`** removed, hashed as

```text
SHA-256( "direwolf.dwkp.admit_run.request.v2" || 0x00 || u64be(len) || JCS )
```

`schema_version`, `session_id`, `idempotency_key` and the whole payload stay
bound. `epoch` leaves the digest because it is not a property of *what* was
asked — it is the tenure the asker holds — and the tenure is enforced
separately, and more strictly, by the three rules below. The domain string
moves to `v2` so that no digest computed under the old definition can ever be
compared with one computed under this one.

**The order, unchanged in its first step:**

1. **The fence.** Lease, holder, subject, epoch and expiry, before anything
   else. A stale caller is `STALE_EPOCH` whatever key it presents.
2. **The record** for `(subject, session_id, idempotency_key)`. None: a first
   admission, exactly as before.
3. **The digest.** Different: `IDEMPOTENCY_CONFLICT`, whatever state the
   recorded run is in. The first admission is untouched.
4. **The run.** Same digest, and the recorded run is `ACTIVE` **and** was
   admitted under the epoch the caller holds now: **same-response replay** —
   the recorded `RunGrant`: same `run_id`, `epoch`, `policy_revision`,
   `profile`, `granted[]` with the same `cap_id`s, and `withheld[]`. Nothing is
   re-minted and nothing is re-evaluated.
5. **Otherwise — the run is `RELEASED` or `REAPED`:** refused
   **`ADMISSION_ENDED`**. The key is spent; it will never admit a run, and the
   run it did admit will never be active again. The caller admits again under a
   new key if it still wants a run.

An `ACTIVE` run recorded under any epoch other than the caller's current one
cannot exist — a lease change reaps every run admitted under the old epoch, in
the same transaction — so meeting one is a store that contradicts itself, and
the operation fails with an invariant error: no grant, no refusal, nothing
committed.

**What each situation now produces**, for the same subject, session and key:

| Situation | Answer |
|---|---|
| retry in the same tenure, run active | the recorded `RunGrant` |
| retry in the same tenure, run released by the caller | `ADMISSION_ENDED` |
| retry after the holder rotated its own lease | `ADMISSION_ENDED` |
| retry after the lease expired and was re-acquired | `ADMISSION_ENDED` |
| retry after an authority restart and re-acquisition | `ADMISSION_ENDED` |
| same key, changed payload, any tenure | `IDEMPOTENCY_CONFLICT` |
| any of the above presented with an old epoch, or by an old connection | `STALE_EPOCH` |
| same key under another subject | that subject's own scope: a first admission of its own, which neither reveals nor touches this one |

**Audit.** `run.admit_refused` with reason `ADMISSION_ENDED` carries the
original `run_id` and its end state. A replay is `run.admit_replayed`, as
before. Nothing is written but the audit record.

**Retention** is unchanged: none. A record is never deleted, which is what
makes the refusal permanent.

#### Why no second logical admission can occur

1. `(subject, session_id, idempotency_key)` is the primary key of
   `admission_idempotency`, so a scope has at most one record.
2. The record, the run and its grants are written in one `BEGIN IMMEDIATE`
   transaction, so a record exists exactly when its admission does.
3. Every path after step 2 either returns that record's run or refuses; no path
   that finds a record reaches minting.
4. Writers are serialised by `BEGIN IMMEDIATE`, so two concurrent retries both
   see the record the first one wrote — or neither sees one, and exactly one of
   the two inserts succeeds.
5. Triggers forbid deleting a record, deleting a run, and returning a released
   or reaped run to `ACTIVE`.

#### Lease rotation by the current holder

`AcquireLease` from the connection that already holds the live lease is a
deliberate **rotation**: the session moves to `epoch + 1`, the old epoch is
fenced in the same transaction, and every run admitted under it is reaped
(audited, cause `lease_reacquired`). It exists so that a holder whose
`LeaseGrant` was lost can recover a usable epoch without waiting out the TTL;
the price is that it ends the holder's own runs, exactly as a restart would.
There is still one row per session, so there is never a second holder.

### Part 2 — `QueryAuthority` and a proposed action

#### What M3 can construct, by family

"Canonical action" means [POLICY.md](../POLICY.md)'s: a resolved capability and
every fact a rule may read about it. `when.environment` applies to every verb,
so an action without a known environment is incomplete for every verb.

| Family (verbs) | Resolved capability from text? | Capability coverage truthful? | Every predicate input available? | Policy truthful? | Honest on the M3 wire as a decision? |
|---|---|---|---|---|---|
| `fs.*` (`read`, `write`, …) | **No** — a canonical path only M4 can derive ([ADR-0037](0037-capability-specifications-and-canonical-authority-identities.md)) | no | no: path, bytes, environment | no | no |
| `process.*` (`exec`, …) | **No** — an executable identity only M4 can derive | no | no: identity, argv classification, environment | no | no |
| `network.*` (`http`, `https`, …) | yes (host scope) | yes | no: destination address (M4), novelty (M4/M5), environment (M5) | no | no |
| `browser.*`, `channel.*` | yes | yes | no: novelty, environment | no | no |
| `memory.*`, `agent.*`, `artifact.*` | yes | yes | no: environment — performed by the kernel, and no accepted decision says what environment a kernel-performed action has | no | no |
| `model.call`, `secret.use`, `scheduler.*`, `mcp.*` | yes | yes | no: environment | no | no |
| outside the vocabulary | no | no | no | no | no |

No proposal expressed as capability text determines a complete canonical action
in this build. Capability coverage alone is computable for most families, but
coverage alone is one gate, and ADR-0006 does not permit one gate to answer for
both.

#### The contract through M3e

- **Without `proposed`:** `EffectiveAuthority` — the run's grant, withheld list,
  policy revision and mode. Complete: every withheld capability now has a wire
  reason (below).
- **With `proposed`:** after the fence (`STALE_EPOCH`) and the run check
  (`UNKNOWN_RUN`), **`direwolf.authority.refused` with `QUERY_AUTHORITY` /
  `NO_CANONICAL_ACTION`**, for every proposal. No policy rule runs, no rule is
  attributed, and nothing is decided. The audit record
  (`authority.query_refused`) keeps the proposal and the kernel's own
  classification of why — `unknown_vocabulary`, `unresolved_resource` or
  `action_facts_unavailable` — for an operator; the wire keeps one reason,
  because the caller has one remedy: do not ask this build to decide it.

`QueryAuthority` with `proposed` is therefore **not** an action-authorisation
API before M4, and nothing in M3 claims otherwise. An `AuthorityDecision` is
produced only from a complete canonical action. In M3d the only source of one is
the in-process `Proposal::Action` entry that M4's canonicaliser will use; tests
stand in for it, and prove the decision mapping and its rule attribution there.
No DWKP message reaches that path.

#### Every outcome, classified

| Outcome | Kind | Answer |
|---|---|---|
| bytes that do not form a valid message | protocol error | `direwolf.protocol.error` |
| stale epoch, unknown run | authority-state refusal | `STALE_EPOCH`, `UNKNOWN_RUN` |
| a proposal outside the vocabulary | authority-state refusal | `NO_CANONICAL_ACTION` |
| a proposal naming an `fs` or `process` resource | authority-state refusal | `NO_CANONICAL_ACTION` |
| a proposal whose action facts the request cannot carry | authority-state refusal | `NO_CANONICAL_ACTION` |
| both gates evaluated on a complete canonical action | decision | `AuthorityDecision`, naming the rule that decided |

A decision's `rule_id` is always the rule that produced the effect: the matched
rule, the narrowing postcondition, the rule whose `REQUIRE_APPROVAL` became
`DENY`, or — for `DEFAULT_DENY` — the policy's own mandatory `default` rule,
which is a rule in the operator's file that matched, not a placeholder.

#### Withheld at admission

An `fs` or `process` capability requested at `AdmitRun` is withheld with the new
`WithheldReason` **`UNRESOLVED_RESOURCE`**: the capability names a resource
whose canonical identity the authority could not derive. That stays true after
M4, for a path that does not exist or an executable that cannot be identified,
so the reason is not a placeholder for a milestone.

### Part 3 — the DWKP change

| Message | Change | `schema_version` |
|---|---|---|
| `direwolf.authority.refused` | `RefusalReason` gains `ADMISSION_ENDED` (paired with `ADMIT_RUN`) and `NO_CANONICAL_ACTION` (paired with `QUERY_AUTHORITY`): 7 reasons, 11 pairs | 1 → **2** |
| `direwolf.authority.effective` | `DecisionReason` loses `CAPABILITY_MALFORMED`; `AuthorityDecision.required_capability` becomes required; `WithheldReason` gains `UNRESOLVED_RESOURCE` | 1 → **2** |
| `direwolf.run.grant` | `WithheldReason` gains `UNRESOLVED_RESOURCE` | 1 → **2** |
| `direwolf.run.admit`, `direwolf.authority.query` | none: the shapes are unchanged, and what changed is which answer they receive | 1 |

`CAPABILITY_MALFORMED` leaves `DecisionReason` for the reason ADR-0036 §10 moved
`RUN_NOT_ADMITTED` out of it: every decision reason is the outcome of an
evaluation that ran, and "the kernel does not know this capability" is the
reason none could. `required_capability` was optional only for that case.

**Compatibility.** Widening or narrowing a closed enum, and making a field
required, are breaking changes ([PROTOCOL.md](../PROTOCOL.md) §6). DWKP's two
peers ship together ([ADR-0023](0023-dwkp-strict-schema.md)) and no DWKP
version has been released, so each changed message supports exactly version 2:
a version-1 instance is `PROTOCOL_VERSION_UNSUPPORTED` naming `2..2`. Decoding
both versions would need two payload types per message, and a version-1 decoder
of these enums would accept values version 2 forbids. The generated schemas, the
Python bindings and the shared vectors change with the Rust types, as
[ADR-0033](0033-protocol-source-of-truth-and-tcb-dependencies.md) requires.

M6's `REQUIRE_APPROVAL` will therefore take `direwolf.authority.effective` to
version 3, not 2.

## Consequences

### Security consequences

- An idempotency key can never admit twice, and can never return authority that
  has ended — within a tenure, across a rotation, or across a restart.
- A `RunGrant` means a run the caller may use now. It is never returned for a
  released or reaped run.
- Fencing still precedes every idempotency lookup, and the four refusals that
  can answer an `AdmitRun` are checked in a fixed order: `STALE_EPOCH`, then
  `IDEMPOTENCY_CONFLICT`, then `ADMISSION_ENDED`, then `UNKNOWN_AGENT_PROFILE`.
- No decision is made about an action the authority could not describe
  completely, so no rule is switched off by a missing fact and no environment is
  assumed.
- No response attributes an effect to a rule that did not produce it.

### Operational consequences

- A runtime that loses an `AdmitRun` response across an authority restart gets
  `ADMISSION_ENDED` and admits again under a new key. It must not reuse keys
  across logical admissions, which ADR-0036 already required.
- A client that relied on `QueryAuthority` with `proposed` for a dry run gets a
  refusal until M4. Nothing in the repository relied on it.
- Three message schemas are at version 2. Every DWKP peer ships in the same
  release, so this is one coordinated change, as every DWKP change is.

### Explicit limitations

- Before M4 there is no wire path to a policy decision at all. M3's acceptance
  evidence for policy is M3c's fixture suites and M3d's in-process decisions on
  complete canonical actions supplied by tests.
- `ADMISSION_ENDED` does not say *why* the run ended. The audit record does;
  the caller's remedy is the same in every case.
- A caller that genuinely wants a second run with an identical request must
  use a new key. That was already true, and is the point of the key.

## Alternatives considered

**Option A** (keep `epoch` bound; conflict across tenures). Smallest diff, no
wire change. Rejected: it reports the authority's own restart as the caller's
mistake, makes a real conflict indistinguishable from an ended admission, and
writes an audit record of a conflict that did not happen.

**Option B** (unbind `epoch`; replay the recorded grant regardless). Rejected: a
success response for a run that has been reaped, carrying an epoch that is
fenced, is a credential that looks usable and is not.

**Option C** (rebind across tenures). Rejected: every concrete meaning of
"rebind" is resurrection of a reaped run or a second admission, and either
invents M9's resumption semantics inside M3d.

**Keep deciding proposals whose action is "complete enough" for the loaded
policy** — evaluate, and refuse only if a rule actually reads a missing fact.
Rejected for M3: it needs a third truth value for every action fact in M3c's
evaluator, the answer would change whenever an operator edited an unrelated
rule, and environment is missing for every verb anyway.

**Assume an environment** ("sandboxed is the default", ADR-0008). Rejected: the
default describes where execution goes, not a fact about a particular action,
and `deny-host-exec-unless-opted-in` is the rule it would silently switch off.

**Answer with `EffectiveAuthority` and no `decision`.** ADR-0036 §6 already told
readers to treat that as unusable. Rejected: it is an untyped refusal inside a
success message.

**A protocol error for an unknown capability.** Rejected: the message is
well-formed ([ADR-0036](0036-m3-authority-operations-and-the-capability-wire-form.md)
§3 puts vocabulary on the authority side deliberately), and a protocol error
would send the caller to repair a correct message.

**Three refusal reasons** — unknown vocabulary, unresolved resource, missing
facts. Rejected: they share one remedy, and the distinction is kept in the
audit record where an operator can use it.

**Support versions 1 and 2 side by side.** Rejected: DWKP peers ship together,
nothing is released, and a version-1 decoder of these enums is wrong about
version-2 values in both directions.

## Revisit if

- M4's canonicaliser can build complete canonical actions: `QueryAuthority` may
  then decide proposals it can canonicalise, and the family table above is what
  changes.
- M9 designs resumption: it may define how a checkpointed run is re-admitted,
  but not by reviving a reaped run.
- A client needs to know *why* an admission ended, which would argue for a field
  on the refusal and a version bump — never for returning the grant.
