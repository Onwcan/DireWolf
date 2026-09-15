# ADR-0030: DireWolf is licensed under Apache-2.0

**Status:** Accepted · **Date:** 2026-09-12

## Context

Phase 0 identified Apache-2.0 as the leading candidate and deferred the
decision to M1 ([PRODUCT_SPEC.md](../PRODUCT_SPEC.md) §10). M1 owns it, and
"TBD" is not an acceptable state for a repository that is about to accept
contributions: every commit made under an unstated licence is a commit whose
terms have to be renegotiated later, with whoever wrote it.

Four properties constrain the choice.

**A patent grant matters more here than for most projects.** DireWolf's
distinctive claims are mechanisms — capability attenuation across a process
boundary, approval binding over a canonical action hash, per-invocation
authorisation from a decider to an executor. Those are the shape of thing
patents get filed on. A licence with an express patent grant and a termination
clause gives users a defence that a licence silent on patents does not.

**The dependency ecosystem is permissive.** The Rust crates this project will
eventually depend on are overwhelmingly MIT/Apache-2.0 dual-licensed; the
Python ones are MIT, BSD and Apache-2.0. Nothing we need forces a copyleft
choice, and `deny.toml` allowlists exactly this set.

**Commercial use must be unambiguous.** A security runtime that an organisation
cannot deploy without a legal review is a security runtime that does not get
deployed. The comparison points in [COMPETITIVE_ANALYSIS.md](../COMPETITIVE_ANALYSIS.md)
are permissively licensed, and a more restrictive choice here would be a reason
not to adopt that has nothing to do with the architecture.

**Contributions should not need a CLA.** Apache-2.0 §5 states that
contributions are submitted under the licence's terms unless explicitly marked
otherwise, which removes the need for a separate agreement. A CLA on a
pre-1.0 security project is friction that buys nothing we want.

## Decision

**Apache-2.0.** `LICENSE` holds the canonical text verbatim (11 358 bytes,
SHA-256 `cfc7749b96f63bd31c3c42b5c471bf756814053e847c10f3eb003417bc523d30`);
`NOTICE` carries the copyright line and is where third-party attributions go.
Every package manifest declares `license = "Apache-2.0"`, and
`cargo deny check licenses` enforces that nothing incompatible enters the tree.

Contributions are accepted under Apache-2.0 §5. **No CLA.**

## Consequences

**Positive.** An express patent grant with defensive termination. Compatible
with everything we expect to depend on, and with GPLv3 consumers downstream.
Familiar to legal reviewers; adoption costs nothing to explain. No CLA to
administer, and no contributor asked to sign one.

**Negative, stated rather than glossed:**

- **Apache-2.0 is incompatible with GPLv2-only.** A GPLv2-only project cannot
  link DireWolf. We accept this; the alternative that fixes it — dual
  MIT/Apache-2.0 — costs the patent grant's practical force, because a
  recipient may simply choose MIT and take no patent grant at all.
- **§4(b)'s NOTICE obligation is a real redistribution requirement**, and a
  slightly heavier one than MIT's. Downstream redistributors must carry
  `NOTICE`. This is administration, not a barrier.
- **It permits a commercial competitor to take the work**, including the
  authority plane, and offer it as a service without contributing back. Given
  [ADR-0029](0029-packaging-runtime-first-decoupled-authority.md) — the
  authority plane is the genuinely novel artifact, and shipping it standalone
  is an option we are keeping open — this is the cost most worth naming. We
  take it deliberately: a security boundary nobody may inspect, embed or fork
  is a security boundary nobody will trust, and adoption is the only route by
  which this architecture's claims get tested by people who want them to fail.

## Alternatives considered

**MIT.** Shorter, more universally understood, marginally wider compatibility
(including GPLv2). Rejected on the patent grant. MIT's implied patent licence
is a matter of legal argument rather than text, and for a project whose
contribution is a set of mechanisms, silence on patents is the wrong default.
The brevity argument is real and does not outweigh it.

**Dual MIT OR Apache-2.0** — the Rust ecosystem's convention, and the strongest
alternative. It maximises compatibility and lets a consumer pick. Rejected
because the patent grant becomes optional at the recipient's discretion, which
mostly undoes the reason for choosing Apache-2.0; and because dual licensing
needs a concrete reason, which for an application rather than a library we do
not have. Revisitable: if DireWolf ever publishes a *library* intended for
broad reuse — a capability-lattice crate, say — dual licensing that crate is a
narrow, defensible exception, and would need its own ADR.

**MPL-2.0 (weak copyleft).** File-level copyleft would keep improvements to the
authority plane public while still permitting commercial use. Genuinely
tempting for exactly the "competitor takes it" scenario above. Rejected:
file-level copyleft creates real uncertainty at a process boundary — the
question of what constitutes "the file" when the boundary is an IPC protocol is
not one we want a deployer's lawyer asking — and it would exclude us from
contexts where Apache-2.0 is pre-approved and anything else requires review.
Adoption is worth more to this project than reciprocity is.

**AGPL-3.0.** Closes the hosted-service gap completely. Rejected: it would be
disqualifying for a large share of the intended audience, and for
infrastructure meant to sit underneath other people's agents, a licence that
propagates to what sits above it is a non-starter.

## Revisit if

A patent assertion is made against a user of DireWolf and the Apache-2.0 grant
proves insufficient in practice; or a dependency we genuinely cannot replace
requires a different licence; or DireWolf publishes a general-purpose library
for which dual MIT/Apache-2.0 is the ecosystem-correct answer — in which case
the exception is scoped to that crate and recorded separately.
