# ADR-0001: Controlled polyglot — Rust kernel, Python runtime, TypeScript UI

**Status:** **Superseded by [ADR-0019](0019-language-rationale-v2.md)** · **Date:** 2026-09-11 · **Depends on:** ADR-0000

> **SUPERSEDED by [ADR-0019](0019-language-rationale-v2.md).** The conclusion (Rust / Python / deferred TypeScript) survives; the rationale below did not survive Phase 0 review. Three of its five Rust justifications were found unsound — the dependency-count claim was applied to the wrong boundary, the "Python cannot scrub secrets" argument attacked a strawman (**Python is memory-safe**), and the seccomp/`ctypes` argument is moot because the default sandbox path makes no isolation syscalls. Retained as a historical record. Do not cite this ADR as current rationale.

## Context

Given ADR-0000, the privileged process must have a small, auditable dependency set and be distributable as a verifiable artifact. The cognition plane has the opposite profile: high churn, heavy reliance on LLM/ML ecosystems, and a need for contributor accessibility.

Full analysis, including a 23-subsystem matrix and a cross-cutting language comparison, is in [LANGUAGE_SELECTION.md](../LANGUAGE_SELECTION.md).

## Decision

| Language | Scope | Trust |
|---|---|---|
| **Rust** | `kernel/` — policy, capabilities, approvals, budgets, secrets, fs/exec/net brokers, sandbox supervisor, audit, and the `direwolf` CLI binary | TCB |
| **Python 3.12+** | `runtime/`, `gateway/`, `evals/` | Untrusted |
| **TypeScript** | `web/` — UI only, deferred to M24 | No authority |

The partition rule: *can this code cause a side effect, hold a credential, or make an authorisation decision?* Yes → Rust. Only reasons, plans or shapes data → Python. Only renders → TypeScript.

**No FFI anywhere.** Process isolation is the product; a linked kernel would void ADR-0000.

## Rationale for Rust in the kernel, specifically

We reject "Rust because security" — we would never choose C, so this is not a memory-safety argument against a memory-unsafe alternative. The concrete reasons are narrower:

1. **Exhaustive sum types.** A new `Decision` variant that some call site silently defaults to permissive is a compile error, not a CVE. Given that authorization drift is the dominant observed failure class, this is insurance bought exactly where the claims are made.
2. **Newtypes for canonicalisation.** `CanonicalPath` and `ResolvedHost` can only be constructed by the canonicaliser, making "policy matched a raw model-supplied string" unrepresentable. In Go or Python these are all `string`.
3. **Deterministic destructors** enable best-effort secret zeroization. Python's interned immutable `str` cannot be scrubbed at all.
4. **Minimal, enforceable dependency set** via `cargo-deny` allowlists — decisive when everything linked is inside the TCB.
5. **`cargo-fuzz`** on the protocol parser, canonicaliser and policy matcher, where a parsing bug is an authority bug.

## Consequences

Two toolchains in CI; schema-driven codegen to prevent type drift; cross-language debugging mitigated by shared correlation ids and joined OTel traces; a higher bar for security-relevant contributions (intentional, still a cost). ~80 % of contributions will touch Python only.

## Alternatives considered

- **All Python, with the kernel as a second Python process running as a different user.** Genuinely strong — the privilege boundary would be identical, and it would ship faster. Rejected because the privileged process would carry a CPython interpreter plus a large transitive dependency graph inside the TCB, could not scrub secrets from memory, and would reach seccomp/Landlock through `ctypes`.
- **All TypeScript.** Weak local-ML and eval ecosystem; very large dependency graphs in the TCB.
- **Go for the kernel.** Defensible and would ship perhaps 30–40 % faster. Rejected on points 1–3 above. This is a judgement call, not a proof, and it is recorded as such.
- **Rust everywhere.** Would tax the fastest-changing 80 % of the code for no security gain and shrink the contributor pool.

## Revisit if

Rust build times or contributor scarcity measurably slow kernel security fixes — evidence being median time-to-merge for kernel security fixes exceeding two weeks over a quarter. Then Go becomes the candidate. Also: drop TypeScript entirely if the web UI has not earned its place by M27.

