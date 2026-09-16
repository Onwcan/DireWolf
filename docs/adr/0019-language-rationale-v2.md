# ADR-0019: Language rationale, revised for the authority/broker split

**Status:** Accepted · **Date:** 2026-09-12 · **Supersedes:** [ADR-0001](0001-language-and-runtime.md)

> ADR-0001's *conclusion* (Rust / Python / deferred TypeScript) survives. Its *rationale* did not survive review and is replaced here rather than defended.

## Context

Phase 0 review examined ADR-0001's five justifications for Rust and found three of them unsound:

1. **"CPython plus a large transitive dependency graph inside the TCB."** The stated figures (Python 40–120 crates/packages vs "Rust 15–40, controllable") were never reconciled with the kernel's actual job list. With `bollard` + `hyper` + `rustls` + `tokio`, the realistic count was 250–400. The argument was applied to the wrong boundary.
2. **"Python cannot scrub secrets from memory."** This argued against a strawman implementation. Nobody would hold a credential in a `str`; `bytearray` is mutable and can be zeroed. **Python is memory-safe, and nothing in this ADR claims otherwise.**
3. **"Reaches seccomp/Landlock through `ctypes`."** Contradicted by our own sandbox design: the V1 default path is `oci`, and `oci-strict` is a *container-runtime configuration* sent over a daemon socket. **In the default path the kernel makes zero direct isolation syscalls.**

[ADR-0018](0018-authority-broker-split.md) changes the premise, because the component the dependency argument is about is now much smaller.

## Decision

The same four-way partition, with rationale stated per component:

| Component | Language | Why, specifically |
|---|---|---|
| **`dwkd-authority`** | **Rust** | (a) **Exhaustive sum types** — a new `Decision`/`Effect`/`Obligation` variant that some call site silently defaults to permissive is a compile error, not a CVE. Given that authorization drift is the dominant observed failure class in this product category, this is insurance bought where the claims are made. (b) **Newtypes** — `CanonicalPath`, `ResolvedHost`, `BindingHash` constructible only by the canonicaliser, making "policy matched a raw model-supplied string" unrepresentable. (c) **A genuinely small, enforceable dependency set** — now true, post-split: no HTTP client, no TLS stack, no container client, no content parsers. `cargo-deny` allowlist, `cargo-vet`. (d) **`cargo-fuzz`** on the canonicaliser, the policy matcher and the DWKP parser, where a parsing bug is an authority bug. |
| **`dwkd-broker`** | **Rust** | Weaker case, honestly. It needs `openat2` with `RESOLVE_*` flags, `fexecve`, rlimits and fd hygiene — awkward through `ctypes` **in privileged code**, which is the combination that matters. Sharing a language and the `dwk-proto` types with authority avoids a third toolchain for one component. **Go would be a defensible alternative here** and we record that. |
| **`direwolf` CLI** | **Rust** | The installed artifact is one static binary: instant start, no interpreter bootstrap, supervises the process tree, and a checksum that means something. |
| **Runtime / gateway / evals** | **Python 3.12+** | LLM and MCP SDKs, local ML and embeddings, statistics and eval tooling, the largest contributor pool, and the highest change rate in the system. Holds no authority, so none of the Rust arguments apply. |
| **Web UI** | **TypeScript**, deferred M27 | Obvious; ships as static assets; zero runtime authority. |

**The partition rule is unchanged:** can this code make an authorisation decision, hold a credential, or perform a side effect? Authority decisions → `dwkd-authority`. Side effects → `dwkd-broker`. Reasoning and data shaping → Python. Rendering → TypeScript.

**No FFI anywhere.** Process isolation is the product.

## Consequences

The Rust surface is now justified component by component rather than by a blanket claim. The dependency-minimalism argument is true where it is made (`dwkd-authority`) and explicitly *not* claimed where it is false (`dwkd-broker` carries `bollard`, `hyper`, `rustls` — that is the point of putting them there).

Cost unchanged: two toolchains, schema-driven codegen against drift, a higher bar for security-relevant contributions.

## Alternatives considered

- **All-Python, two processes, two OS users.** Still the strongest alternative: the privilege boundary would be identical and it would ship faster. Rejected on (a) and (c) above for `dwkd-authority` only — a Python authority process would carry an interpreter plus a large package graph inside the smallest, most security-critical component, and could not use `cargo-fuzz`/`cargo-vet`. We no longer claim it "cannot scrub secrets."
- **Go for both kernel processes.** Defensible; ~30–40 % faster to first working kernel. Rejected on sum types and newtypes for authority. A judgement call, recorded as such.
- **Rust everywhere.** Taxes the fastest-changing 80 % of the code for no security gain, and shrinks the contributor pool.

## Revisit if

Rust build times or contributor scarcity measurably slow kernel security fixes (median time-to-merge for kernel security fixes > 2 weeks over a quarter). Or: if `dwkd-broker` proves to be mostly container-API glue, move it to Go and keep Rust for authority only.

