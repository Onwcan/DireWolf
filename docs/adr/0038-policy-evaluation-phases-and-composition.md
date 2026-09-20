# ADR-0038: Policy evaluates in two phases, composes only by narrowing, and derives `would_require_approval` itself

**Status:** Accepted · **Date:** 2026-09-19 · **Refines:** [ADR-0006](0006-policy-and-capability-boundary.md) (the decision function gains an explicit second phase), [ADR-0028](0028-policy-input-ownership.md) (a new policy input joins the kernel-owned set, and one that looked like an input turns out not to be), [ADR-0035](0035-m3-authority-dependency-set.md) (the TOML feature set and its measured closure)

> `POLICY.md` describes a first-match evaluator that returns as soon as a rule
> matches, and then shows an `explain` output where two rules fire for one
> decision — the second conditioned on whether the first required approval. A
> single-phase evaluator cannot produce both. The rule as written is either
> unreachable or circular, and the field it turns on would, read the obvious
> way, be a boolean the runtime supplies. This is the milestone that had to
> resolve it, so this ADR resolves it.

## Context

M3c implements the policy decision function of
[ADR-0006](0006-policy-and-capability-boundary.md). Four things had to be
settled before a line of the evaluator could be written, and three of them are
security properties rather than design preferences.

### 1. `POLICY.md` contradicts itself about evaluation

[POLICY.md](../POLICY.md) §4:

```
evaluate(request) -> Decision
  1. validate request is fully canonicalised
  2. for each rule in order:
       if matches(rule.when, request) and not matches(rule.unless, request):
           return Decision::from(rule)
  3. unreachable — `default` is mandatory
```

§5 renders a decision where `approve-novel-exec` matched and *then*
`deny-approval-needed-when-unattended` produced the final `DENY`. The loop
above cannot do that: it returns at the first match.

And the rule that would have to do it is:

```toml
[[rule]]
id     = "deny-approval-needed-when-unattended"
when.origin                 = "scheduled"
when.would_require_approval = true
unless.standing_grant       = true
```

`would_require_approval` is a fact about the evaluation the rule is part of.
As a phase-one predicate it is circular. Placed after `approve-novel-exec` in
a first-match list, it is unreachable. Left as a field somebody supplies, it is
worse than either — see below.

### 2. `would_require_approval` cannot be an input

[ADR-0028](0028-policy-input-ownership.md) generalised a Phase 0 finding into
architectural principle 10: *anything the kernel reads from the runtime and
then decides on is authority the runtime holds*. `taint_level`, `origin` and
`privacy_class` moved kernel-side for exactly this reason.

A `would_require_approval: bool` on a request or a context is the same bug with
a new name. A caller that says `false` has turned off every unattended denial,
and it does not have to be a *compromised* caller — a buggy one that forgets to
set the field gets the same result, which is worse, because nobody investigates
it.

### 3. `extends` must not widen, and the general case is undecidable

[POLICY.md](../POLICY.md) §7: "A profile may only *narrow* the profile it
`extends`. Attempting to widen fails at load time."

That quantifies over **every possible action**. Checking it in general means
deciding implication between arbitrary predicates — does `path_under =
${WORKSPACE}` imply `path_under = ${WORKSPACE}/src`? does `*.example.com`
cover `api.example.com`? does `10.0.0.0/8` contain `10.1.2.0/24`? — for a
vocabulary that includes label-aware host wildcards, CIDR ranges and
component-wise path containment. That is a decision procedure, it would
instantly be the most security-critical code in the loader, and a fixture suite
demonstrating it on a hundred cases proves nothing about the hundred and first.

### 4. The TOML feature set ADR-0035 named is not the one M3c needs

[ADR-0035](0035-m3-authority-dependency-set.md) §2 accepted
`toml = { default-features = false, features = ["parse", "serde"] }`, noting
"the `serde` feature is required to reach `toml`'s value API". True of
`toml::Value` — and `toml::Value` is not what a loader wanting **source line
numbers** should use, because it does not carry them.

## Decision

### 1. Two phases

```text
Phase 1   [[rule]]           ordered, first match wins   ->  provisional decision
Phase 2   [[postcondition]]  ordered, each may only NARROW that decision
```

Phase one is [POLICY.md](../POLICY.md) §4 unchanged, including the mandatory
`default` that makes it total. Phase two is a second, deliberately smaller
array, bounded at 32 entries, whose selector is `when.provisional_effect`.

Two arrays rather than one, so the phases are something an operator **reads**
rather than an ordering they have to infer from which predicates a rule
happens to use. A `[[rule]]` may not write `provisional_effect`; a
`[[postcondition]]` may not carry `obligations` or an `approval` table. Both
are load errors.

### 2. `would_require_approval` becomes `provisional_effect`, and is never an input

The unattended rule moves to phase two and becomes:

```toml
[[postcondition]]
id     = "deny-approval-needed-when-unattended"
effect = "DENY"
reason = "NO_HUMAN_AVAILABLE"
when.provisional_effect = ["REQUIRE_APPROVAL"]
when.origin             = ["scheduled", "channel", "subagent", "api"]
unless.standing_grant   = true
```

`provisional_effect` is supplied by the evaluator from its own phase-one
result. `PolicyContext` has no such field, no constructor accepts one, and
`when.would_require_approval` is an unknown member in both tables — tested in
both.

Two smaller decisions come with it, and both are **stricter** than the
`POLICY.md` example:

- **Every origin but `interactive` is unattended.** The example names only
  `scheduled`. A `subagent` run has a human somewhere above it but not one
  watching *this* run, and an approval prompt nobody sees is a timeout or a
  reflexive click rather than a decision.
- **`unless.standing_grant` can never be satisfied before M6.**
  `StandingGrantState` has one variant, `Unavailable`. Not a `bool` defaulting
  to false: a single-inhabitant type means there is no value a caller can
  construct that claims a grant exists. M6 adds the variants, and every `match`
  on the type stops compiling that day, which is the intended way to find every
  site that has to decide what a real grant means.

### 3. Postconditions cannot widen, checked twice

**At load:** a postcondition's effect must be `⊑` *every* provisional effect it
selects, under `DENY ⊑ REQUIRE_APPROVAL ⊑ ALLOW`. A postcondition with no
selector selects all three, so only `DENY` qualifies.

**At evaluation:** the applied effect is `meet(running, postcondition)`, so a
postcondition that somehow reached the evaluator without the load check still
cannot widen. The second check makes widening *unrepresentable* rather than
merely refused, which is the difference between a rule and an invariant.

The order is total and named rather than derived from enum discriminants:
reordering the variants must not silently invert the lattice.

### 4. `extends` V1: an extending profile may only add `DENY` rules

Not a general narrowing check — a restricted subset whose non-widening property
needs no reasoning about predicates at all.

Rules compose by concatenation, the child's first, exactly as
[POLICY.md](../POLICY.md) §3 says. So for any action, first-match evaluation of
the composed policy returns either **a child rule**, whose effect is `DENY`,
the bottom of the lattice, and therefore `⊑` whatever the parent would have
returned; or **the parent's own result**, unchanged, because no child rule
matched.

In both cases `composed(a) ⊑ parent(a)`, for every `a`. Two lines, quantified
over the whole input space.

Four more restrictions come with it, each closing a way the composed policy
could mislead rather than widen:

- a child may not declare `default` — the root of the chain owns it, and two
  rules each claiming to be the one that always matches means the second is
  unreachable;
- a child may not reuse a parent's rule id, which would make an audit record
  name a rule the reader looks up in the wrong file;
- chains are bounded at depth 4 and cycles are detected before evaluation;
- the caller supplies the profile set. Nothing searches a directory for a
  parent by name, so a profile cannot pull in a file nobody reviewed.

The three shipped packs are **standalone**, not a chain: `safe`, `balanced` and
`power` permit different sets rather than differing by a few extra denials.

### 5. `toml` with `parse` only, and one crate fewer than ADR-0035 measured

```toml
toml = { version = "=1.1.6", default-features = false, features = ["parse"] }
```

The loader walks `toml::de::DeTable`, the parsed document with a byte span on
every key and value, which is gated on `parse` **alone**. Dropping `serde` is
not a saving for its own sake — it is the *more capable* choice, because
`toml::Value` carries no spans and `rule_source` has to name a real line.

The measured closure, `cargo tree -p dwkd-authority --edges normal`,
rustc 1.98.1, x86_64-unknown-linux-gnu, 2026-09-19:

| Crate | Version | Licence | Parses policy text? |
|---|---|---|---|
| `toml` | 1.1.6 | MIT OR Apache-2.0 | **yes** |
| `toml_parser` | 1.1.3 | MIT OR Apache-2.0 | **yes** |
| `winnow` | 1.0.4 | MIT | **yes** |
| `toml_datetime` | 1.1.1 | MIT OR Apache-2.0 | no |
| `serde_spanned` | 1.1.1 | MIT OR Apache-2.0 | no — the span type, non-optional |

**Five crates, not six.** No `serde_core`, no `serde_derive`, no `syn`, no
`quote`, no `proc-macro2`, no native code, no build script that compiles
anything. Every licence is already in `deny.toml`'s allowlist.

Verified three ways, because the first two disagree and only one of them is
about the artifact:

| source | answer | what it actually describes |
|---|---|---|
| `Cargo.lock` closure (RS006) | 10 crates | every recorded edge, optional or not — it pins versions, not features |
| `cargo metadata` `resolve.deps` | 10 crates | the same over-approximation |
| **`cargo tree --edges normal`** | **5** | the feature-resolved graph |
| **a clean-target build of `dwkd-authority` alone** | **5 rlibs** | **the ground truth** |

`serde_spanned` and `toml_datetime` each declare `serde_core` as
`optional = true` behind their own `serde` feature, which `toml`'s `parse`
feature does not turn on. Their activated features are `["alloc"]`, and
`alloc = ["serde_core?/alloc"]` is a **weak** reference: it enables a feature
of `serde_core` if something else already enabled the dependency, and enables
the dependency never.

### The gate that keeps this true

An exclusion list describing that state would be **fail-open**: it stays
correct only until somebody turns the feature on. So `dwcheck` computes
activation instead of being told it (`checks_cargo.py`), from each package's
own activated features expanded through its feature table, and enforces four
rules — a linked crate missing from the allowlist (**RS010**), an allowlist
entry no longer linked (**RS011**), an exclusion whose edge has become
**active** (**RS012**), and an exclusion naming no edge at all (**RS013**).

The offline `Cargo.lock` gate stays, labelled as what it is: a tripwire that
needs no toolchain and over-approximates. `make arch` runs both, and
`make check` runs `make arch`.

Demonstrated rather than argued: enabling `toml`'s `serde` feature in a
checkout, with `architecture.toml` byte-identical, turns the gate red with
eight findings — RS010 naming `serde_core`, `serde_derive`, `syn`, `quote`,
`proc-macro2` and `unicode-ident`, and RS012 naming both expired exclusions.

The version is pinned **exactly**. A policy parser is the authority's only
third-party reader of operator input, and "whichever patch the resolver picked"
is not a version anyone reviewed.

### 6. Consequences of being strict, written down

- **Unknown members fail at every level.** `when.destinatoin_novel = true` is a
  load error, not an absent predicate. This is the single most valuable
  refusal in the loader.
- **No coercion, with no exception.** `schema_version = "1"` is not `1`,
  `argv_safe = "true"` is not `true`, `max_uses = 1.5` is not `1`, a negative
  never wraps, an overflow never saturates — **and `when.verb = "fs.read"` is
  not `when.verb = ["fs.read"]`.**

  That last one was an exception in the first draft of this ADR, described as
  "between a value and a one-element list of the same type". It was still a
  coercion: two source shapes entering the compiled policy as one, so the
  representation stopped saying what the file said. A strict loader with one
  permitted coercion has to argue about which coercions are safe, and the
  argument is the failure — refusing all of them is a rule, refusing most of
  them is a habit.

  [POLICY.md](../POLICY.md) §3's operator table documents both spellings for a
  match predicate (implicit scalar is equality, a list is membership), so both
  load — as `MatchValue::Eq` and `MatchValue::In`. They decide identically for
  a single candidate, because
  `MatchValue::any` looks at the variant; they are not the same value, because
  the parser did not throw one away.

  Three shapes, one per field: **match** (scalar or list, the ten `when`
  predicates that name values), **scalar only** (`max_bytes`, `argv_safe`,
  `destination_novel`, both `unless` members, and every identifier and enum
  outside `when`), and **list only** (`obligations`, which is an output set
  rather than a match). A wrong shape is a type error in every case, and
  POLICY.md §3 carries the field-by-field table.
- **Duplicates are refused**, including by the TOML parser itself for repeated
  keys and table headers. Last-value-wins on security configuration is how a
  hardened rule becomes a permissive one.
- **A predicate that could never hold is refused at load.** A rule whose
  `when.path_under` sits beside `when.verb = ["network.https"]` never fires,
  and a denial that never fires is worse than no denial because somebody
  believes it is there.
- **An unresolvable canonical input denies.** A rule needing `${WORKSPACE}`
  when the context has no workspace, or `ip_in` when nothing was resolved, is
  refused with `UNRESOLVED_CANONICAL_INPUT` naming the rule and the missing
  value. Reading it as "did not match" would silently disable a deny rule,
  which is the strict loader's own failure mode arriving one layer later.

### 7. One destination address, not a set — and what that does not buy

`CanonicalAction` carries a single `destination_ip`. An earlier draft held a
set and matched `ip_in` when every member was in range; an adversarial fixture
found the hole. "Every" is fail-closed for an `ALLOW` and fail-**open** for a
`DENY` — a host answering with one public and one loopback address escaped a
rule denying the loopback. "Any" has the mirror-image problem. No single
quantifier over a set is safe in both directions, so the **action** is made
unambiguous rather than the predicate.

### The claim, stated exactly

> **M3c eliminates the policy-evaluation ambiguity by evaluating one canonical
> destination IP.**

That is the whole of it, and it is worth being pedantic about, because the
hole the fixture found is *called* DNS rebinding and fixing it is not the same
as being resistant to DNS rebinding.

**M3c guarantees:**

- one destination address per policy decision;
- deterministic CIDR evaluation over that address, with prefixes bounded per
  family and host bits refused;
- no ambiguous set quantifier;
- an action with no address is **refused**, not read as "did not match".

**M3c does NOT guarantee:**

- DNS pinning — M3c performs no resolution;
- resolver correctness — the address arrives as four or sixteen octets from a
  caller, and the type carries no proof of where it came from;
- that the connection the broker opens uses the address policy judged;
- TOCTOU resistance between resolution and connect.

The field is named `destination_ip` rather than `pinned_address` for exactly
that reason: nothing in the type establishes a pin, so its name must not imply
one.

### The invariant M4 and the broker owe

End-to-end rebinding resistance additionally requires:

```text
    IP evaluated by policy  ==  IP used for the authorised connection
```

with no re-resolution or substitution between decision and effect. That belongs
to M4's network canonicalisation and the broker's execution path, alongside the
CONNECT proxy's DNS pinning and SNI/host agreement
([NETWORK_SECURITY.md](../NETWORK_SECURITY.md) §1,
[ADR-0024](0024-sandbox-network-topology.md)). Neither exists yet.

**A reconnect or a re-resolution must take a fresh authority decision rather
than reuse an earlier one.** A decision is about one address; spending it on a
connection to a different address is spending a decision nobody made.

`a_policy_decision_is_about_one_destination_and_binds_nothing_to_it` makes the
requirement visible today, without implementing any networking: the same
capability and the same host with two different destination addresses produce
*opposite* decisions, which is why the address the effect uses has to be the
address the decision was made about.

## Consequences

### Positive

- The `explain` output [POLICY.md](../POLICY.md) §5 promises is now something
  the evaluator can actually produce: a primary rule, the postconditions that
  fired, and the rule the final effect came from.
- The unattended bypass is closed by *type*, not by validation. There is no
  `would_require_approval` field and no `standing_grant: bool` to forge.
- Non-widening composition is a two-line argument over the whole input space
  rather than a fixture suite.
- The authority's third-party closure is five crates, reviewed, pinned and
  fuzzed, with no proc-macro and no C.

### Negative

- **An extending profile cannot add a permission**, even one its parent would
  have permitted anyway. That is the cost of the restricted subset, and it is
  why the three shipped packs are standalone.
- **`POLICY.md` §3's rule format changes.** `would_require_approval` is gone
  and `[[postcondition]]` is new. An operator with a rule file written against
  the old prose has to move one rule; the loader tells them exactly which.
- **The authority now links a parser it did not write.** Three of the five
  crates read the policy text. `fuzz/` has coverage-guided targets and
  `tests/fuzz_smoke.rs` runs the same invariants on stable, which is mitigation
  rather than removal.
- **Two phases is more evaluator than one.** The second phase runs for every
  decision, and the benchmark includes it.

### TCB consequences

Reported as three separate numbers, because they are three different things:

| | M3c delta |
|---|---|
| Production third-party dependencies | **+5** — `toml`, `toml_parser`, `toml_datetime`, `serde_spanned`, `winnow` |
| Native / foreign code | **zero** — pure Rust, no build script compiling anything |
| Authority trusted-code surface | **increased** — roughly 3,400 lines of policy engine inside `dwkd-authority` |

"No TCB impact" is not available to a milestone that adds a parser to the
authority, and nothing in this ADR should be cited as saying otherwise.

### Explicit limitations

- **The policy context is typed, not verified.** `origin`, `taint_level` and
  `privacy_class` are the kernel-owned values [ADR-0028](0028-policy-input-ownership.md)
  requires — and M3c has no `kernel.db`, so nothing *derives* them yet. Tests
  construct them directly; M3d supplies them from kernel-owned state. Until
  then they are trusted by construction, and saying otherwise would be claiming
  a control that does not exist.
- **Shipped profiles are not signed.** [POLICY.md](../POLICY.md) §7 says they
  are. No signing key, verifier or signature exists in this build. They are
  compiled in with `include_str!`, which resists an edit on disk and nothing
  else.
- **There is no persisted policy revision or source hash.** M3a's wire
  references one; M3d owns it, along with the audit relationship and startup
  reconciliation. M3c exposes deterministic compiled metadata for M3d to hash,
  and fabricates no revision number.
- **`fs` and `process` rules are semantics without a source of values.** The
  matching is implemented and unit-tested against synthetic identities; nothing
  can *derive* a `CanonicalPath` from an OS resource until M4, because
  [ADR-0037](0037-capability-specifications-and-canonical-authority-identities.md)
  put the constructors in `crate::resource` and M3c is deliberately outside
  that visibility. Those two statements are separate and are kept separate.
- **The benchmark is one machine.** A number on a WSL2 kernel on one laptop is
  evidence, not a guarantee, and a hosted CI runner's timing is not a security
  gate.
- **`destination_ip` is not a pin.** M3c evaluates one address per decision and
  establishes nothing about where that address came from or which address the
  connection will use. §7 states the invariant M4 and the broker owe; until
  they land, DireWolf does not claim end-to-end DNS-rebinding resistance.
- **The exact closure gate needs Cargo.** It reports a finding rather than
  passing when Cargo is unavailable, so it cannot silently skip — but a
  contributor with no toolchain has only the conservative lockfile tripwire,
  which over-approximates.

## Alternatives considered

**Keep one phase and make `would_require_approval` a context field.** Rejected:
it is [ADR-0028](0028-policy-input-ownership.md)'s finding C1 in a new field.
The runtime would hold the authority to disable every unattended denial, and a
*buggy* caller gets the same result as a hostile one.

**Keep one phase and drop the unattended rule.** Rejected: it is the mechanism
[APPROVALS.md](../APPROVALS.md) relies on for the case that matters most — an
agent running at 3 a.m. with nobody to ask. Removing a control because the
evaluator's shape made it awkward is the wrong direction.

**Let a postcondition run a second full rule list.** Rejected: that is a second
DSL with a different name. Postconditions are a bounded, closed set that may
only narrow, and if they ever need to be more than that the answer is to look
again at whether the primary rules are right.

**General predicate-implication checking for `extends`.** The honest version of
POLICY.md §7, and rejected for M3c: it is a decision procedure over host
wildcards, CIDR ranges and path containment, it would be the most
security-critical code in the loader, and getting it subtly wrong fails *open*.

**Compose by `meet` of the two profiles' independent results.** Genuinely
attractive: it lifts the DENY-only restriction and keeps non-widening by the
same lattice law, since `meet(child, parent) ⊑ parent` by definition. It costs
a second full evaluation per decision and a merge rule for obligations and
approval shapes, and the merge rule is where the subtlety would hide. Recorded
as the successor rather than built now.

**`toml` with the `serde` feature, as ADR-0035 wrote it.** Rejected on
measurement: `serde_core` buys `toml::Value`, which carries no spans, so the
loader would still have had to find line numbers some other way. Fewer crates
*and* the feature the requirement needs.

**A bespoke TOML subset parser, or strict JSON through `dwk-proto`.** Both
rejected by [ADR-0035](0035-m3-authority-dependency-set.md), and nothing here
changes that reasoning. The JSON option remains the fallback if the TOML chain
ever produces a vulnerability.

**`std::net::IpAddr` for `ip_in`.** Rejected: it would need an exception in the
policy core's ambient-effect rule for a type that is inert, and an import list
with no networking module in it is easier to check than an argument about which
networking types are safe. Four or sixteen octets is all `ip_in` compares.

## Revisit if

- A real, needed policy cannot be written with the DENY-only extension subset
  and would require duplicating a whole profile to approximate — which is the
  trigger for the `meet` composition above.
- A second postcondition shape appears that is not "narrow this decision",
  which would mean phase two is turning into a language and the design needs
  re-examining rather than extending.
- M6's approval registry lands, at which point `StandingGrantState` gains
  variants, every `match` on it breaks, and each break is a site that has to
  decide what a real grant means.
- The TOML chain produces a memory-safety or denial-of-service advisory that a
  version bump cannot close, which would make
  [ADR-0035](0035-m3-authority-dependency-set.md)'s JSON fallback live.
- Policy files become reachable by attacker-chosen content from outside the
  operator's control, which would change the parser's threat model from
  "operator input" to "untrusted input" and raise the bar on everything here.
- Cargo gains a first-class way to ask for the feature-resolved link closure,
  at which point `checks_cargo.py`'s activation expansion becomes a
  reimplementation of something upstream does better and should be deleted.
- M4's network canonicalisation lands, at which point §7's owed invariant stops
  being a note and becomes a testable property — and the sentence "M3c does not
  claim end-to-end rebinding resistance" should be revisited rather than left
  to age.
