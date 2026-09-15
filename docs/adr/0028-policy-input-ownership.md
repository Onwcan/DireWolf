# ADR-0028: Every policy input is derived and stored kernel-side

**Status:** Accepted · **Date:** 2026-09-12 · **Amends:** [ADR-0006](0006-policy-and-capability-boundary.md), [ADR-0012](0012-memory-provenance.md)

## Context

During Phase 0 a bug was found and fixed: the session lease epoch — the value that fences a zombie runtime — lived in `runtime.db`, which the runtime can write. A paragraph was written explaining why that was fatal, and the reasoning was applied to **exactly one field**.

Review finding C1 found the rest. `taint_level`, `origin`, `privacy_class`, `workspace.sensitivity`, the active skill set, skill trust levels, and artifact and memory provenance were all policy inputs, and all were runtime-writable. A compromised runtime could:

- set `taint_level = NONE` after reading a hostile page, disabling every taint-conditioned rule and making `require_untainted_run` standing grants — the default — spendable in exactly the run they exclude;
- set `origin = interactive` for an unattended run, defeating the unattended-degrades-to-DENY rule;
- lower `privacy_class` or `workspace.sensitivity`, defeating `LOCAL_ONLY` enforcement;
- declare an **empty active skill set**, which — since skills only narrow — *maximises* the capability intersection;
- forge an artifact trust label, laundering untrusted provenance.

The approval prompt's taint warning, described as the most decision-relevant fact on the surface, was rendered from a value the attacker controlled.

## Decision

**Generalise the reasoning rather than patch the fields**, as architectural principle 10:

> Anything the kernel reads from the runtime and then decides on is authority the runtime holds.

Concretely:

1. **Every policy input is derived and stored in `kernel.db`.** `taint_level`, `origin`, `privacy_class`, `workspace.sensitivity`, active skill set and trust levels, artifact `trust`/`provenance`, memory item `trust`/`provenance`, lease epochs.
2. **The kernel derives taint itself.** It performs every tool call and creates every artifact, so it has strictly more information than the Context Engine — and unlike the Context Engine it cannot be asked to lie. The Context Engine computes a `taint_summary` for **display and debugging only**; the manifest marks it advisory.
3. **Divergence is a signal.** Where the runtime's cached copy disagrees with `kernel.db`, the kernel's value wins, the runtime row is repaired, and the divergence is audited — a runtime whose cached taint differs from the kernel's is either buggy or compromised.
4. **Memory and context are not terms in any authority expression.** The mint formula reads agent profile, kernel-verified skills, parent grant and profile ceiling. Policy rules are read from kernel-owned files. This is the structural backstop from ADR-0012, restated as invariant I9.
5. **Content stays in `runtime.db`.** Only fields that gate a decision move; memory and artifact *content* is large and the kernel has no reason to hold it.

Recorded as invariants **I9** and **I10** in `README.md`.

## Consequences

**Positive.** The largest remaining TB2→TB4 threat class closes. The threat model gains the row it was missing. Approval prompts render from values the attacker cannot set.

**Negative.** `kernel.db` grows and the kernel does more bookkeeping. Skill verification moves kernel-side, which means the kernel parses skill manifests — a bounded, structured format, but a parser nonetheless, and it belongs in `dwkd-authority` only if kept strict. Taint derivation adds work on the tool-result path.

**Test consequence:** the **hostile DWKP client** suite becomes an M3 merge gate. Every finding above would have been caught by it and by nothing else; every existing security case drives the *model*, not the protocol.

## Alternatives considered

- **Sign the runtime's values.** The runtime would hold the key. Circular.
- **Move only `taint_level`.** The same mistake at smaller scale — this ADR exists because that is exactly what happened once.
- **Have the kernel recompute inputs on demand from the audit log.** Correct but slow on the tool-call path; the derived values are cached in `kernel.db` precisely to avoid it.

