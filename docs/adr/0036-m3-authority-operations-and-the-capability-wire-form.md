# ADR-0036: M3 defines AdmitRun, ReleaseRun and QueryAuthority; ToolInvoke stays reserved until a tool exists

**Status:** Accepted · **Date:** 2026-09-17 · **Refines:** [ADR-0023](0023-dwkp-strict-schema.md), [ADR-0028](0028-policy-input-ownership.md), [ADR-0031](0031-repository-layout-and-boundary-enforcement.md) · **Amends:** [ADR-0032](0032-wire-contract-framing-strict-json-and-jcs.md) (adds one field shape, the bounded array; adds a second cross-field check) · **Refines further:** [ADR-0006](0006-policy-and-capability-boundary.md) (a state refusal is not a policy decision), [ADR-0011](0011-session-concurrency.md) (the wire form of a fencing rejection)

> M3 is the milestone that answers *"is this subject authorised to attempt this
> abstract effect?"*. Three operations carry that question and its answer, and
> they get their first wire forms here. The fourth, `ToolInvoke`, is the one
> that performs an effect — and it cannot be designed before the milestone that
> builds the first tool, because the only shapes available to M3 are an opaque
> argument map or a duplicate of `QueryAuthority`.
>
> Two further things the wire has to settle before any of it is implemented:
> `AdmitRun` mints authority, so a retried admission must resolve to the
> admission that already happened (section 8); and the decision it answers with
> carries what this build can actually decide, which through M5 is `ALLOW` or
> `DENY` and nothing else (section 9). And a request that is well-formed but
> refused by authority state — a stale epoch, a held lease, a replayed key — is
> neither a protocol error nor a policy denial, and gets a typed refusal of its
> own (section 10).

## Context

[ADR-0033](0033-protocol-source-of-truth-and-tcb-dependencies.md) makes
`crates/dwk-proto/src/dwkp/registry.rs` the authoritative operation inventory;
everything else is generated. M2 defined four operations — `Handshake`,
`Heartbeat`, `AcquireLease`, `ReleaseLease` — and reserved sixteen. A reserved
operation has no message schema, and a message naming one is rejected as
`PROTOCOL_UNKNOWN_OPERATION` exactly like a misspelled one, "until its owning
milestone designs its payload and re-examines its second-path argument".

M3 owns the semantics of five of those sixteen: `AdmitRun`, `ReleaseRun`,
`QueryAuthority`, `ToolInvoke` (pipeline) and `CanonicalPreview` (jointly with
M4). It needs wire forms for the authority decisions it makes.

Two things had to be decided before any of them could be written: how a
capability appears on the wire, and whether `ToolInvoke` can be designed yet.

## Decision

### 1. Three operations are defined; `ToolInvoke` and `CanonicalPreview` stay reserved

| Operation | M3a status | Request | Responses |
|---|---|---|---|
| `AdmitRun` | **defined** | `direwolf.run.admit` | `direwolf.run.grant`, `direwolf.protocol.error` |
| `ReleaseRun` | **defined** | `direwolf.run.release` | `direwolf.ack`, `direwolf.protocol.error` |
| `QueryAuthority` | **defined** | `direwolf.authority.query` | `direwolf.authority.effective`, `direwolf.protocol.error` |
| `ToolInvoke` | reserved | — | — |
| `CanonicalPreview` | reserved | — | — |

`Handshake`, `Heartbeat`, `AcquireLease` and `ReleaseLease` are **unchanged**.
Their M2 wire forms are sufficient for M3: each carries exactly the envelope
fields its semantics need and an empty or minimal payload, and M3 supplies the
server behaviour behind them rather than new fields. Redesigning a sufficient
operation would be a coordinated release of runtime and kernel for no gain.

### 2. `ToolInvoke` stays reserved, deliberately

The protocol change review's first question is *why an existing operation
cannot do the job*. For a ToolInvoke defined at M3 there is no answer:

- Its request must **name a tool from the canonical inventory with typed
  arguments the kernel canonicalises itself**. No tool exists until M4, and the
  canonicaliser that makes `fs.read`'s `path` argument decidable is M4's
  deliverable. An argument shape designed by the milestone before that one would
  be designed twice, and a DWKP change is a coordinated release, never a rolling
  one.
- The only M3-available alternatives are both rejected on sight. **An argument
  map** (`args: {...}` uninterpreted by the kernel) is the opaque payload the
  second-path rule forbids — an operation that relays bytes the kernel does not
  interpret cannot police what those bytes do. **A decision-only ToolInvoke**,
  which validates the run and lease, checks capability and policy, audits, and
  returns a decision without performing anything, is `QueryAuthority` with a
  different name.
- M3's acceptance question is fully answerable without it. `QueryAuthority`
  carrying a `proposed` capability exercises the entire pipeline — admission,
  lease, epoch, capability, policy, `rule_source`, audit — and decides. What it
  does not do is *perform*, which is precisely what M3 must not do anyway.

So M3 builds the pipeline and proves it through `QueryAuthority`; M4 gives
`ToolInvoke` its first wire form alongside the first tool and the canonicaliser.
The registry entry records this reasoning where it is durable, and
`crates/dwk-proto/tests/dwkp.rs::tool_invoke_is_still_reserved_after_m3` fails if
anybody quietly defines it.

### 3. A capability crosses the wire as validated text, parsed by the authority

`CapabilityText` is a bounded string in the grammar of
[CAPABILITIES.md](../CAPABILITIES.md) §2 — `verb ":" scope [ "?" constraints ]`
— at most 512 characters, with an explicit ASCII character set.

**`dwk-proto` checks the lexical form and the bounds, and nothing else.** It
does not know what a verb means, which scopes contain which, or how two
constraints compare. That is the ⊑ lattice; it is policy vocabulary; it belongs
in the authority, and putting it in the protocol crate would put the capability
engine in the TCB's shared wire library, against
[ADR-0031](0031-repository-layout-and-boundary-enforcement.md). A string that
parses here is still refused by the authority if its verb, scope type or
constraint key is not one the kernel knows: **unknown forms fail closed there.**

The character set is explicit ASCII rather than "anything but whitespace"
because the Rust validator and the Python `pattern` must agree exactly, and
"what is a space" is a Unicode question — the class of question
[ADR-0034](0034-protocol-depends-on-no-unicode-database.md) removed from the
protocol.

This is **not an opaque payload**. The kernel interprets every capability it
receives, in its own closed vocabulary; nothing is relayed uninterpreted.

### 4. A capability grant is referenced by id, not carried as a token

[CAPABILITIES.md](../CAPABILITIES.md) §4 describes a `CapabilityToken` with a
MAC. M3's wire form carries `cap_id` — a `cap_`-prefixed UUIDv7 — and the
granted capability, and no MAC.

The reason is in that section itself: *"The MAC is defence in depth, not the
primary control. The kernel holds authoritative state for every live token in
`kernel.db` … A token is only valid if the kernel's own record says so."* The
record is the control; the MAC is a cheap pre-filter before a database lookup.
M3 has the record and does not yet need the optimisation, and a MAC that no
attacker has tried to forge because nothing consumes it is a field that looks
like security. Adding it later is an additive field on a response, which is the
compatible direction.

`uses_remaining`, `not_before`, `not_after` and `binding` are **not** on the
wire at M3. Binding is M6's; expiry semantics belong with the approval and lease
work that uses them. Representing them now would be fabricating fields the
kernel cannot populate.

### 5. `AdmitRun` carries names, never assertions

```
AdmitRun { agent_profile, skills[], requested_capabilities[] }
```

Every field is a **name the kernel resolves against its own records**, never a
property the kernel derives ([ADR-0028](0028-policy-input-ownership.md)):

- `agent_profile` selects a profile; the kernel supplies its declared
  capabilities. An unknown name is a denial, not a protocol error.
- `skills` selects skills to activate. Skills only ever *narrow* — the mint
  expression intersects over them — so naming more can only reduce authority,
  and naming none yields the profile's own ceiling, which is the maximum
  anyway.
- `requested_capabilities` is a request. Asking for more yields less, never
  more, and the difference comes back as `withheld[]` so the agent can tell a
  human what it lacks.

There is **no** `mode`, `profile_ceiling`, `workspace_sensitivity`, `taint`,
`privacy_class`, `origin`, `provenance` or `approved` field, in this or any
other request. `crates/dwk-proto/tests/dwkp.rs::the_runtime_cannot_express_a_policy_input_in_any_defined_message`
enforces that mechanically, and now does so **direction-aware**: the derived
properties appear in no message at all, and the authority vocabulary
(capabilities, grants, profiles, revisions, decisions) appears only in
kernel-to-runtime responses plus four request fields sanctioned by name.

### 6. `QueryAuthority` answers in one shape, with an optional decision

The request carries an optional `proposed` capability. The response always
carries effective authority; it carries a `decision` exactly when a `proposed`
was sent. The correspondence is an **authority-side guarantee**, not a schema
constraint: `wire_struct!`'s only cross-field check is `ordered(a <= b)`, and
its closed set is deliberate, because every check must be mirrored by the Python
generator and an open-ended validation hook is where the two diverge. This
follows the existing corpus — `ProtocolErrorPayload`'s `violation`, `path` and
`supported` are populated conditionally by the sender in the same way.

A reader that asked for a decision and did not receive one must treat the
response as unusable, never as an allow. That is stated in the field's own
documentation, which is where a reader will look.

### 7. The wire gains one new field shape: the bounded array

M2 had no array-shaped field. Authority answers are sets, so `BoundedList<T, MAX>`
is added to `dwk-proto`, with `maxItems` mandatory in the schema and the length
checked **before** any element is decoded. `Violation::TooManyItems` already
existed — the protocol anticipated this — and the Python generator was extended
deliberately, as [CONTRIBUTING.md](../../CONTRIBUTING.md) requires, with a
matching `validate.sequence` that enforces the same bound and the same
"`null` is not an omitted item" rule.

### 8. `AdmitRun` requires an `idempotency_key`; nothing else carries one

Admission mints authority. A lost response is the ordinary failure of a socket,
not an exotic one, and the retry that follows it must resolve to the admission
that already happened — otherwise one logical admission becomes an unbounded
number of independently admitted runs, each holding its own grant, none of them
released, all of them invisible to the caller that believes it has one run. This
is not a hypothetical: it is what "at least once" means on any transport that
can drop a reply.

The envelope already has the field for it. `idempotency_key` has been in
[ADR-0032](0032-wire-contract-framing-strict-json-and-jcs.md)'s envelope since
M2, unused, waiting for an operation that needed it. Inventing a second
admission-attempt identifier next to it would leave two fields meaning the same
thing, and the older one would rot.

**The contract:**

| | |
|---|---|
| **Presence** | **Required** on `direwolf.run.admit`. `Forbidden` on every other defined operation, as before. |
| **Scope** | The tuple `(authenticated peer identity, session_id, idempotency_key)`. The peer identity is the one the kernel verifies on connect (`SO_PEERCRED` and its equivalents, M3e), never a claim in the message. |
| **The bound request** | The canonical (RFC 8785) encoding of the decoded request with `id`, `ts`, `correlation_id` and `causation_id` removed — those four legitimately differ between a request and its own retry, and nothing else does. `schema_version`, `epoch` and the whole payload are therefore bound. |
| **The record** | The bound request's digest, the `run_id` minted for it, and the `RunGrant` that was returned. |

**The four cases, in the order the kernel decides them:**

1. **Epoch first.** Fencing is checked before the key is looked at. A stale
   epoch is `STALE_EPOCH` whatever key accompanies it: presenting a key must
   never be a way around the fence, and a zombie runtime holding a valid old key
   is exactly the caller fencing exists to stop.
2. **No record for the scope** — the authority admits, mints the `run_id`, and
   writes the record **durably before the response is emitted**
   ([RELIABILITY.md](../RELIABILITY.md) §1, intent before effect). A crash
   between the write and the send leaves a retryable state; a crash the other way
   round would leave an admitted run no caller knows about.
3. **A record whose digest matches** — the recorded `RunGrant` is returned again.
   The same `run_id`, the same `epoch`, the same `policy_revision`, the same
   `granted[]` with the same `cap_id`s, the same `withheld[]`. No second
   admission, no re-evaluation of policy, no widening, no new row anywhere. The
   envelope's `id`, `ts` and `causation_id` are per-message and differ, because
   they describe the message and not the grant.
4. **A record whose digest differs** — refused, fail closed. The key is never
   reinterpreted for a different admission, and the first admission is never
   amended by the second request's contents. A caller that changes its mind
   changes its key.

**A different subject is a different scope**, so case 4 is unreachable across
subjects: guessing another caller's key does not return their grant, and does
not collide with it either — it is simply a first request under a scope of its
own. Making the subject part of the scope rather than checking it afterwards is
what removes the whole class.

**Durability across restart** is M3d's, in `kernel.db` with the rest of the
authority's state, including the retention window after which a record is
forgotten — the "dedupe window" [PROTOCOL.md](../PROTOCOL.md) §8 already names.
A window that is too short reopens case 2 for a slow retry; that is a tuning
decision with evidence, and M3a is not the place to guess at it.

**Why required and not optional.** An optional key gives the kernel two paths,
and the undeduplicated one is the path a retry takes — the safe behaviour would
exist and go unused, which is the worst of both. It costs a caller one generated
string. It is also what makes the *test* meaningful: a missing key is a refusal
with a location, not a silent fallback.

The key names an admission *attempt*, not a run. `run_id` stays `Forbidden` on
the request: [ADR-0028](0028-policy-input-ownership.md)'s rule that the kernel
assigns identity is untouched, and a caller choosing its own key is choosing a
handle for its own retries, not naming kernel state.

**What this corrects.** [PROTOCOL.md](../PROTOCOL.md) §1 said the key is
"mandatory on any request with a side effect", and `AdmitRun` is not
effect-bearing — it changes kernel records only. The old rule named the wrong
property. The property that needs a key is **mutation of authority state**,
which is the larger set, and §1 now says so. The `IdempotencyKey` doc comment
claiming its semantics arrive at M9 is corrected in the same change.

`ReleaseRun` needs no key: releasing an already-released run is acknowledged
rather than refused, so a retry is indistinguishable from success and cannot
resurrect anything — idempotent by shape, which is better than idempotent by
bookkeeping. `QueryAuthority` needs none either: it is pure, and repeating it
against the same state returns the same answer. Both keep `Forbidden`, and a
test asserts that `AdmitRun` is the only operation that permits a key.

### 9. No approval semantics on the M3 wire

The first draft of `AuthorityDecision` had `effect: ALLOW | DENY |
REQUIRE_APPROVAL` and a reason `APPROVAL_REQUIRED`. Both are removed.

**What the accepted ADRs actually require.**
[ADR-0006](0006-policy-and-capability-boundary.md) — accepted, amended by
[ADR-0028](0028-policy-input-ownership.md), unsuperseded on this point — says
"Policy is a pure deterministic function over a canonical action returning
`ALLOW | DENY | REQUIRE_APPROVAL` plus a rule id, source location and
explanation." That binds the **policy function**, which is M3c's, and M3c will
honour it: `balanced.toml` ships rules whose effect is `REQUIRE_APPROVAL`, and
collapsing them inside the evaluator would lose both the rule author's intent
and the audit record of it.

It says nothing about DWKP. No accepted ADR requires the M3 **wire** to carry a
third value, and the milestone assignment that puts the policy engine in M3 and
approvals in M6 comes from [ROADMAP.md](../ROADMAP.md), which is not an ADR.

**So the wire carries what the authority decided, not what a rule preferred.** An
authority with no approval registry, no binding hash, no prompt renderer and no
human to ask cannot obtain an approval, and therefore refuses. That is not an
invention for this ADR: [APPROVALS.md](../APPROVALS.md) already fixes the
direction — `REQUIRE_APPROVAL` with no human present degrades to `DENY`, never
to `ALLOW`. Through M5, no human is ever present. The mapping is total and
fail-closed, and it happens where the internal `Effect` becomes a
`DecisionEffect`.

**Why not ship the value anyway.** A closed enum value that nothing in the build
can produce and nothing can satisfy is a value every client has to invent a
behaviour for, and the cheap invention is `if effect != DENY { proceed }`. That
is a fail-open written by someone reading a schema in good faith. The
information is not lost: the decision carries `rule_id` and `rule_source`, so the
rule that refused can be read, and it is the rule that says
`effect = "REQUIRE_APPROVAL"`.

**And not through another field.** Re-routing the removed effect into the reason
enum, a boolean, or an "advisory" string would be the same semantics with worse
spelling. `APPROVAL_REQUIRED` goes with it.

**The cost, stated plainly.** Widening a closed enum is a breaking change under
[PROTOCOL.md](../PROTOCOL.md) §6, so M6 adds `REQUIRE_APPROVAL` with a
`schema_version` bump on `direwolf.authority.effective`, coordinated as every
DWKP change already is. That is the price, and it is the right one: a deliberate
version bump at the milestone that can honour the value beats shipping a value
nothing honours and hoping every reader guesses the safe way.

### 10. A well-formed request the authority refuses gets a typed refusal

Sections 8 and 9 each ended by naming a refusal the wire could not carry. That
is the tell: `AdmitRun` must be able to say *idempotency conflict* and *unknown
agent profile*, `AcquireLease` must be able to tell the loser of a contended
acquire that it lost, and every epoch-carrying request must be able to say
*stale epoch* — and `AdmitRun`'s declared responses were `direwolf.run.grant`
and `direwolf.protocol.error`, neither of which is a refusal.

**The root cause is older than M3a.** M2 defined four operations that could not
fail for any reason except being malformed, because M2 had no authority state to
refuse against. `protocol.error` was therefore sufficient, and the inventory
recorded the gap in prose rather than in a type — `AcquireLease`'s entry already
said "M3 adds the policy denial for a session the caller may not lease; a
protocol error is not that denial." M3a gave those operations state and
inherited the assumption. Postponing the shape to M3d would mean committing a
protocol M3d must immediately widen.

**Using `protocol.error` would be a lie**, and an actionable one. It says
`PROTOCOL_SCHEMA_VIOLATION` with a JSON Pointer at the offending member; for a
message that decoded perfectly there is no offending member, and the caller is
sent to repair a message that was already correct. A client that retries on
"malformed" and gives up on "denied" — the sensible policy — would do exactly
the wrong thing in both directions.

#### Three answers, because there are three remedies

| Answer | What happened | What the caller does |
|---|---|---|
| `direwolf.protocol.error` | The bytes did not form a valid message. Nothing was evaluated. | Fix the message. |
| **`direwolf.authority.refused`** | The message was valid; the authority's own state does not permit the operation to be attempted. No policy ran, no capability was consulted. | Re-acquire the lease, admit the run, or stop retrying. |
| `direwolf.authority.effective` with `effect: DENY` | Both gates of [ADR-0006](0006-policy-and-capability-boundary.md) ran against real state and refused. | Ask for less, or change policy. |

Merging any two to save a message type leaves a caller choosing between three
remedies with two signals, and the failure mode of guessing wrong is a retry
loop against a refusal that will never change. This is the same separation
[ADR-0023](0023-dwkp-strict-schema.md) already draws between a parser error and
a decision, extended to the third case M3 creates.

#### The shape: two fields, and no third

```
direwolf.authority.refused   response, causation_id required, schema_version 1
  required operation  RefusedOperation   closed, 6 values
  required reason     RefusalReason      closed, 5 values
  x-direwolf-check: paired(operation -> reason)
```

One message serves all six operations rather than six near-identical ones. It
stays closed because both fields are closed **and their combination is closed**:
the schema carries the permitted `(operation, reason)` table, and a pair it does
not list is refused at the boundary in both languages. That is what keeps a
shared response from becoming a generic escape hatch — a shared envelope with an
open reason set would be one.

`operation` is not redundant with `causation_id`. The envelope binds the refusal
to the message that caused it, which is what a caller with the request in hand
needs; `operation` is what makes the pairing expressible, and what keeps a
refusal legible in an audit record that no longer has the request beside it.

**There is no `detail`, no `hint`, no map, and no `current_epoch`.**
`ProtocolErrorPayload` carries a detail because a malformed message needs a human
to repair *a message*; a refusal needs the caller to take one of five known
actions, and the reason names it. Every byte beyond that is the authority telling
a caller about state the caller could not otherwise see, which is how a refusal
becomes an oracle. `STALE_EPOCH` in particular must not carry the kernel's
current epoch: that is precisely the value a fenced runtime needs to un-fence
itself, and handing it over would undo [ADR-0011](0011-session-concurrency.md)
point 5.

#### The closed reason set, and why each one exists

| Reason | Exists because | Operations |
|---|---|---|
| `STALE_EPOCH` | [PROTOCOL.md](../PROTOCOL.md) §3 and ADR-0011 point 5 name it; without it a fenced request has no answer | every request carrying an epoch |
| `LEASE_HELD` | ADR-0011 point 2 — exactly one process wins the conditional acquire, and the others must be told | `AcquireLease` |
| `IDEMPOTENCY_CONFLICT` | §8 case 4: same key, different canonical request, fail closed | `AdmitRun` |
| `UNKNOWN_AGENT_PROFILE` | `AdmitRun`'s payload already specified "an unknown name is a denial, not a protocol error" | `AdmitRun` |
| `UNKNOWN_RUN` | `QueryAuthority` on a run with no admission cannot be answered: there is no grant, profile or policy revision to report | `QueryAuthority` |

Five, and the matrix is nine pairs:

| | `STALE_EPOCH` | `LEASE_HELD` | `IDEMPOTENCY_CONFLICT` | `UNKNOWN_AGENT_PROFILE` | `UNKNOWN_RUN` |
|---|:-:|:-:|:-:|:-:|:-:|
| `ACQUIRE_LEASE` | | ✓ | | | |
| `RELEASE_LEASE` | ✓ | | | | |
| `HEARTBEAT` | ✓ | | | | |
| `ADMIT_RUN` | ✓ | | ✓ | ✓ | |
| `RELEASE_RUN` | ✓ | | | | |
| `QUERY_AUTHORITY` | ✓ | | | | ✓ |

`Handshake` is absent: it runs before there is any authority state to refuse
against. `AcquireLease` cannot be fenced because it is the operation that
*issues* the epoch.

#### What was deliberately left out

- **`RUN_NOT_ADMITTED` as a distinct reason from `UNKNOWN_RUN`.** In M3 a run
  exists because it was admitted; there is no pre-admission run record. Keeping
  them apart would answer differently for "never existed" and "already
  released", which is a probe for which run ids are real. One answer.
- **`UNKNOWN_LEASE` and `LEASE_RELEASED`.** Both would turn a harmless retry of
  an idempotent release into an error, which is the behaviour `ReleaseRun`
  already rejects, and both leak whether a session exists. Releasing a lease the
  kernel no longer records is acknowledged.
- **"There is no lease at all" as a reason separate from `STALE_EPOCH`.** The
  remedy is identical — `AcquireLease` — and the distinction is a
  session-existence oracle. `STALE_EPOCH` is defined to mean *the epoch you
  presented is not the current one, because it is older or because there is no
  current one*.
- **`UNKNOWN_SKILL`.** `AdmitRun` carries skill names, but the kernel-side skill
  registry is M11's. A reason no milestone can produce is a branch a client
  writes and never exercises, which is the mistake §9 corrected.
- **A refusal per operation.** Six messages differing only in which reasons they
  admit; the pairing table expresses the same constraint in one.

#### `RUN_NOT_ADMITTED` leaves `DecisionReason`

M3a's first draft put it there, because there was nowhere else. It was wrong:
every other `DecisionReason` is the outcome of an evaluation that *ran*, and
"this run holds no admission" is the reason no evaluation could happen. A kernel
reporting it has no `granted[]`, no `profile` and no `policy_revision`, so it
cannot fill an `EffectiveAuthority` at all — the message it would have to send
is unconstructible. It is now `RefusalReason::UnknownRun`.

This narrows `direwolf.authority.effective`'s reason enum, which is a breaking
change to a message **this same uncommitted batch created**. It is made now, for
the reason this ADR is being amended at all: a shape M3d would have to replace
should not be committed.

#### The second cross-field rule, spent deliberately

This ADR's own "Revisit if" said a second cross-field rule would mean extending
`wire_struct!` and the Python generator's closed check set on purpose. This is
that. `x-direwolf-check` gains `kind: "paired"` beside `kind: "ordered"`; the
generator still refuses a `kind` it does not know, so the rule cannot be added
to Rust and silently skipped in Python.

## Consequences

### Security consequences

- The effect path stays closed. No defined operation is effect-bearing after
  M3, and a test asserts it.
- A retried admission cannot mint a second grant, and the scope of the key means
  one subject cannot reach another's admission record by guessing a key. A
  mismatched replay is refused rather than reinterpreted.
- Presenting an idempotency key is not a way past epoch fencing: fencing is
  checked first.
- The wire offers no decision value a reader could mistake for "not denied,
  therefore permitted". `DecisionEffect` is exactly `ALLOW` and `DENY` until a
  milestone exists that can honour a third.
- A refusal cannot be mistaken for a protocol error, so a client's retry policy
  can distinguish "the message was wrong" from "the state says no". Neither can
  be mistaken for a policy denial.
- A refusal carries no state the caller did not already have. `STALE_EPOCH`
  withholds the current epoch, and "unknown" answers are deliberately
  indistinguishable from "released", so a refusal is not a probe for which
  sessions, leases and runs exist.
- A reason an operation cannot produce is refused by the decoder in both
  languages, so a kernel bug that emits one stops at the boundary rather than
  being believed downstream.
- The runtime still cannot assert a policy input, and the test that proves it is
  now stricter than the M2 version it replaces: it distinguishes requests from
  responses and enumerates the sanctioned request fields, so a new authority
  field in a request fails the build.
- Bounded arrays bound what one frame can become. An unbounded array is an
  allocation whose size a client chooses.
- Every new negative shape is covered in both languages by the shared vectors:
  unknown field, missing field, wrong type, over-long identifier, unknown enum
  variant, malformed capability, array past its bound, null array item,
  forbidden envelope field, and the operation's name under the wrong message
  type.

### TCB consequences

None. M3a adds no dependency; `dwk-proto`'s closure stays empty, and
`[authority].allowed_third_party` stays `[]`. The crates of
[ADR-0035](0035-m3-authority-dependency-set.md) enter in M3c–M3e, where they are
first used.

### Portability consequences

None specific to this ADR: these are wire types, and both implementations are
portable. The generated Python bindings gain `list[...]` fields, which is
ordinary.

### Operational consequences

- `AdmitRun`, `ReleaseRun` and `QueryAuthority` are now on the wire and
  rejected by the *authority* rather than by the *decoder* until M3b–e implement
  their behaviour. Between M3a and M3e a well-formed `AdmitRun` decodes and
  reaches a daemon that does not exist; that is the normal state of a protocol
  defined ahead of its server, and the reserved-operation mechanism no longer
  covers these three.
- Three operations left the reserved set, so the inventory's reserved count
  drops from sixteen to thirteen.
- Every `AdmitRun` caller must generate an idempotency key and **reuse it for
  retries of that admission**. A client that generates a fresh key per attempt is
  protocol-valid and gets no protection at all, which is a client bug the
  protocol cannot detect; the runtime's own DWKP client and `direwolf doctor` are
  where that is enforced in practice.
- M6 will bump `direwolf.authority.effective`'s `schema_version` to add
  `REQUIRE_APPROVAL`. That is a coordinated release, like every DWKP change.
- A milestone that adds an authority-state failure adds a `RefusalReason` and a
  row to the pairing table, and bumps `direwolf.authority.refused`'s
  `schema_version` — widening a closed enum is breaking, and widening the
  pairing is too. M11's `UNKNOWN_SKILL` is the first one known to be coming.
- Six operations now list three possible responses instead of two. A client that
  matched exhaustively on the old pair will not compile against the new
  inventory, which is the intended way to find out.

### Explicit limitations

- **A defined wire form is not an implemented operation.** Nothing in M3a
  admits a run, evaluates a policy or mints a capability. The schemas say what a
  correct message looks like, and that is all they say.
- **`CapabilityText` parsing is lexical.** Passing it proves a string is
  shaped like a capability, not that it names a real verb, a real scope type or
  a real constraint. The authority's rejection of unknown forms is the control,
  and it does not exist yet.
- **The `decision`/`proposed` correspondence is not schema-enforced.** It is an
  authority-side guarantee with a documented reader obligation.
- **`ToolInvoke`'s absence is a deliberate scope decision, not an oversight.**
  If M4 finds that the pipeline needed a wire form earlier, this ADR is what to
  argue with.
- **The refusal is a shape, not a behaviour.** Nothing in M3a refuses anything:
  there is no lease table to contend for, no epoch to be stale against and no
  idempotency record to conflict with. M3d implements the state that produces
  these answers, and M3d is where the reasons first become reachable.
- **The reason set is sized for M3 and will grow.** It contains no reason M3's
  operations cannot produce, which means M4, M6 and M11 will each need to add
  one and bump the version. That is the deliberate trade made in §9 and applied
  again here: a closed enum that is honest about today beats one that guesses at
  tomorrow.
- **Retry safety is a contract, not an implementation.** M3a defines the field,
  its scope, the digest that is bound and what happens on mismatch. Nothing
  stores a record, and nothing deduplicates anything. The store is M3d's.
- **The wire cannot tell a caller that an approval would have helped.** Through
  M5 a refusal a human could have lifted is reported as `DENY` with the rule that
  refused. `rule_source` makes it diagnosable; it does not make it
  self-describing, and that is the accepted cost of not shipping a value nothing
  can satisfy.

## Alternatives considered

**Define `ToolInvoke` now with a per-tool typed argument union.** The honest
version of "define it at M3": eighteen tools from
[TOOL_SYSTEM.md](../TOOL_SYSTEM.md) §3, each with its own argument struct.
Rejected: M3 can police none of them, the canonicaliser that gives their
arguments meaning is M4's, and review question 8 would be satisfied by tests
asserting a schema against itself. Designing it once, late, beats designing it
twice.

**Define `ToolInvoke` with an opaque `args` object.** Rejected on sight by the
second-path rule, and by review question 5.

**A fully typed capability on the wire** — verb enum, scope union, eight
constraint variants. Rejected: it is the ⊑ lattice, expressed in JSON Schema, in
the protocol crate. It would also freeze the lattice's shape into the wire
format, so every capability-model refinement would become a protocol change.

**Carry the full `CapabilityToken` with its MAC.** Rejected for M3: the MAC is
explicitly secondary to the kernel's own record, nothing consumes it yet, and
an unexercised cryptographic field invites being trusted.

**An optional `idempotency_key` on `AdmitRun`.** Rejected: it leaves two kernel
paths, and the one a retry takes is the unprotected one. Safety that is opt-in is
safety the careless caller — the one who needs it — does not get.

**A dedicated `admission_attempt_id` payload field.** Rejected: the envelope
already has a field with exactly these semantics, sitting unused since M2. Two
fields meaning one thing is how the older one becomes wrong.

**Deduplicating on the request digest alone, with no key.** Tempting, because it
needs no new field, and wrong: two genuinely distinct admissions with identical
requests are legitimate — the same agent profile and skills, twice — and this
would silently collapse them into one run. The key is what distinguishes "again"
from "still".

**Keeping `REQUIRE_APPROVAL` on the wire as a documented placeholder.** Rejected;
see section 9. The reading `effect != DENY` is a fail-open, and it is the reading
a schema invites.

**Reporting the degraded approval case through the reason enum instead.**
Rejected: the same semantics with worse spelling, which would make the removal
cosmetic.

**Reusing `direwolf.protocol.error` for authority refusals.** Rejected: it
asserts that nothing well-formed arrived, which is false, and it sends a caller
to repair a message that was correct. It would also make the parser's error
codes an open-ended dumping ground for state failures, which is how a well-typed
error model rots.

**A refusal message per operation.** Rejected: six messages differing only in
which reasons they admit, where the pairing table says the same thing once.

**A shared refusal with a free-form `detail` or `metadata` object.** Rejected on
sight — that is the opaque payload the second-path rule forbids, wearing a
different hat, and a refusal is the worst place for one because every field is
information about state the caller could not otherwise observe.

**`STALE_EPOCH` carrying the kernel's current epoch, so the caller can resync.**
Tempting and wrong: the current epoch is exactly what a fenced zombie needs to
un-fence itself. The remedy is `AcquireLease`, which issues an epoch to whoever
legitimately wins it.

**A separate operation for "decide this proposed action".** Rejected: it is
`QueryAuthority` with a narrower request, and two operations answering the same
question is the redundancy review question 1 exists to catch.

## Revisit if

- M4's canonicaliser shows that `ToolInvoke`'s request needs a field M3's
  pipeline should have been carrying all along.
- A capability grammar extension needs a character outside the explicit ASCII
  set, which would need the Rust validator and the JSON Schema pattern changed
  together, with vectors.
- The kernel's grant lookup becomes a measured bottleneck, making the MAC
  pre-filter worth its risk.
- A **third** cross-field rule becomes necessary. The second, `paired`, was spent
  here (§10); a third would be the point to ask whether the checks want a small
  declarative language rather than one macro clause each.
- The pairing table stops being a table — if some reason became conditional on
  payload contents rather than on the operation, the annotation could no longer
  express it and the check would move into the operation's own type.
- A second operation turns out to mutate authority state in a way a retry could
  duplicate, which would make the idempotency key a property of a class of
  operations rather than of one.
- M3d's measurements show the admission record's retention window is the wrong
  shape — too short to cover a real retry, or long enough to matter for storage.
- M6 arrives, at which point `REQUIRE_APPROVAL` returns to the wire with a
  `schema_version` bump and section 9 is the record of why it was ever absent.
