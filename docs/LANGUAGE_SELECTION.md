# Language and Runtime Selection

**Companion to [ADR-0001](adr/0001-language-and-runtime.md), which records the decision.
This document records the analysis.**

---

## 1. How we decided

We rejected two common shortcuts:

- *"Use what similar projects use."* OpenClaw is TypeScript; many agent frameworks are Python. Neither is evidence about DireWolf, whose defining requirement — a privileged authority process — most of those projects do not have.
- *"Use Rust because security."* Rust does not make software secure. The question is whether Rust's specific properties buy something concrete for *specific subsystems* that a memory-safe alternative does not.

The analysis proceeds subsystem by subsystem, then asks whether the resulting set can be collapsed.

### The constraint that drives everything

> **Superseded rationale.** This document records the Phase 0 analysis behind [ADR-0001](adr/0001-language-and-runtime.md). ADR-0001 is superseded by [ADR-0019](adr/0019-language-rationale-v2.md), which narrows the Rust justification after review found three of five arguments unsound. **The conclusion is unchanged; §2–3 below overstate the case.** Read ADR-0019 for the current rationale, and this document for how the analysis was originally done and where it went wrong.

From [ARCHITECTURE.md](ARCHITECTURE.md) §3: **the trust boundary is a process boundary.** The privileged component (then `dwkd`, now `dwkd-authority` + `dwkd-broker`) must be:

- a separate OS process running as a separate user,
- with a **small, auditable dependency set**, because everything it links is inside the trusted computing base,
- distributable as a self-contained artifact so its integrity can be verified independently of a package ecosystem.

That set of requirements, not "security vibes", is what actually constrains the language choice — and it constrains it *only for the kernel*.

---

## 2. Candidate evaluation

### Cross-cutting comparison

| Criterion | Python 3.12+ | Rust | Go | TypeScript / Node |
|---|---|---|---|---|
| LLM SDK / provider ecosystem | **Best** | Weak (HTTP by hand) | Fair | Very good |
| MCP SDK maturity | Very good (official) | Emerging | Fair | **Reference impl** |
| Local ML / embeddings | **Best** | Weak | Weak | Weak |
| Eval + statistics tooling | **Best** | Weak | Weak | Fair |
| Async/concurrency semantics | asyncio, adequate for IO-bound | **Excellent** (tokio, no data races) | **Excellent** (goroutines) | Excellent (single-threaded event loop) |
| CPU parallelism | Poor (GIL; free-threading still maturing) | **Excellent** | **Excellent** | Poor (workers only) |
| Memory safety | Safe (interpreter) | **Safe, no GC** | Safe (GC) | Safe (GC) |
| Deterministic destructors (secret zeroization) | No — immutable `str` cannot be scrubbed | **Yes** (`Drop`, `zeroize`) | No (GC) | No (GC) |
| Startup latency | 80–300 ms (imports dominate) | **1–5 ms** | 2–10 ms | 40–120 ms |
| Self-contained binary | Poor (PyInstaller is fragile) | **Excellent** | **Excellent** | Fair (bun/pkg, large) |
| Typical transitive dep count for our use | 40–120 | **15–40 (controllable)** | 20–50 | 200–800 |
| Fuzzing tooling | Atheris (fair) | **cargo-fuzz, excellent** | native fuzzing (good) | Weak |
| Property testing | Hypothesis (**best in class**) | proptest (very good) | rapid (fair) | fast-check (good) |
| Low-level OS APIs (seccomp, Landlock, namespaces, cgroups, openat2) | via ctypes, ugly | **Excellent crates** | Good (x/sys) | Poor |
| Container API clients | docker-py (good) | bollard (good) | **official client** | dockerode (good) |
| Browser automation | Playwright Python (good) | none | none | **Playwright native** |
| Windows support quality | Good | **Excellent** | Excellent | Excellent |
| Developer velocity for this team | **Highest** | Lowest | High | High |
| Hiring / contributor pool for OSS agents | **Largest** | Smaller | Medium | Large |

### On "memory safety" as an argument

We will not use C or C++, so the Rust-vs-{Go, Python, TS} comparison is **not** a memory-safety comparison — all four are memory-safe in ordinary use. Claiming otherwise would be marketing. The real Rust-specific advantages for our kernel are narrower and concrete:

1. **Exhaustive sum types.** `enum Decision { Allow, Deny, RequireApproval }` with compiler-enforced exhaustive matching means "a new decision variant was added and one call site silently defaults to allow" is a compile error, not a CVE. Go's lack of sum types makes this a code-review obligation instead.
2. **Newtype discipline for canonicalisation.** `CanonicalPath`, `ResolvedHost`, `BindingHash` as distinct types that can only be constructed by the canonicaliser make "policy matched on a raw user string" unrepresentable. In Go or Python these are all `string`, and the bug class stays open.
3. **Deterministic destruction for secret material.** `Zeroizing<Vec<u8>>` scrubs on drop. Under a GC, copies proliferate and lifetime is unpredictable; in Python, `str` is immutable and interned and cannot be scrubbed at all. This is best-effort in every language — swap, core dumps and DMA defeat it — but "best effort" is meaningfully different from "impossible."
4. **Dependency minimalism is culturally and practically achievable**, and `cargo-deny` + `cargo-audit` + `cargo-vet` make an allowlist enforceable in CI.
5. **cargo-fuzz** on the protocol parser, path canonicaliser and policy matcher, which are exactly the components where a parsing bug is an authority bug.

**Go would be a defensible alternative** and would ship faster. We record the switch cost in [ADR-0001](adr/0001-language-and-runtime.md) §Alternatives so this can be revisited honestly rather than defended tribally.

---

## 3. Subsystem-by-subsystem analysis

Legend: **✓** = chosen · ○ = viable · ✗ = rejected

| # | Subsystem | Py | Rust | Go | TS | Decision & justification |
|---|---|---|---|---|---|---|
| 1 | Agent Runtime / loop | **✓** | ✗ | ○ | ○ | IO-bound orchestration, highest churn, most experimentation. Velocity dominates; nothing here is privileged. Rust would tax the fastest-changing code for no security gain — the loop holds no authority. |
| 2 | Model Provider Layer | **✓** | ✗ | ○ | ○ | Provider SDK/spec churn is relentless. Adapters are pure data-shaping with no credentials and no sockets. |
| 3 | Context Engine | **✓** | ○ | ○ | ○ | Tokenizer bindings, heuristics, fast iteration. |
| 4 | Memory Engine | **✓** | ○ | ✗ | ✗ | Embeddings, ranking experiments, RRF tuning, evaluation of retrieval quality. Python's ecosystem is decisive. |
| 5 | Skill Engine (resolution/validation) | **✓** | ○ | ○ | ○ | Manifest parsing + orchestrating validation. The *sandbox* that runs skill tests is kernel-side. |
| 6 | Workflow Engine | **✓** | ○ | ○ | ○ | A DAG over SQLite rows. Not performance-critical. Keep with the loop. |
| 7 | Multi-Agent Orchestrator | **✓** | ✗ | ○ | ○ | Same as the loop; capability attenuation is *requested* here and *enforced* in the kernel. |
| 8 | Gateway / control plane | **✓** | ○ | ○ | ○ | V1 scale is tens of connections on a laptop. Python+uvicorn is ample. Explicit rewrite trigger in §5. |
| 9 | **Policy Engine** | ✗ | **✓** | ○ | ✗ | Security-critical, stable, small, heavily property-tested and fuzzed. Exhaustive `Decision` matching is the argument. |
| 10 | **Approval Engine** | ✗ | **✓** | ○ | ✗ | Must be unwritable by the runtime. Binding-hash and burn semantics must be exactly right; a replay bug is a full bypass. |
| 11 | **Capability Broker** | ✗ | **✓** | ○ | ✗ | The ⊑ lattice is the load-bearing invariant of the whole system. Typed, exhaustively matched, property-tested. |
| 12 | **Secret Broker** | ✗ | **✓** | ○ | ✗ | Deterministic zeroization; must not be in an address space the agent influences; must not depend on a large package graph. |
| 13 | **Sandbox Supervisor** | ✗ | **✓** | ○ | ✗ | seccomp/Landlock/cgroups/namespaces. Rust bindings are first-class; Python's are `ctypes` glue in privileged code, which is the worst combination. |
| 14 | **Process Execution Broker** | ✗ | **✓** | ○ | ✗ | Privileged spawn, env scrubbing, rlimits, fd hygiene, reaping. Wants precise control and no runtime between it and the syscall. |
| 15 | **Filesystem Broker** | ✗ | **✓** | ○ | ✗ | `openat2` with `RESOLVE_BENEATH`/`RESOLVE_NO_SYMLINKS`, fd-relative ops, Unicode-normalisation-safe canonicalisation. Newtypes prevent path-string bugs. |
| 16 | **Network Egress / Model Egress** | ✗ | **✓** | ○ | ✗ | Holds credentials, meters spend, pins DNS, blocks SSRF ranges. `rustls`+`hyper`, no OpenSSL. |
| 17 | **Audit Log** | ✗ | **✓** | ○ | ✗ | Must be append-only and unwritable by the runtime; lives with the kernel by necessity. |
| 18 | Remote Worker daemon | ✗ | **✓** | ○ | ✗ | Deployed on other machines; single static binary with mTLS is the whole point. Deferred, but will be Rust. |
| 19 | MCP integration | **✓** | ○ | ○ | ○ | Client *logic* in Python; MCP servers are *spawned* by the kernel and sandboxed. Split is deliberate. |
| 20 | Browser integration | **✓** | ✗ | ✗ | ○ | Playwright Python drives a browser inside a kernel-managed sandbox. TS would be marginally more native but would add a third runtime to the hot path. |
| 21 | CLI | ✗ | **✓** | ○ | ○ | The installed artifact is one static binary: instant startup, no interpreter bootstrap, supervises the other processes, and gives users something whose checksum means something. |
| 22 | Web UI | ✗ | ✗ | ✗ | **✓** | Obvious. Ships as static assets. **Zero runtime authority** — it is a client of the same protocol as the CLI. |
| 23 | Eval / benchmark harness | **✓** | ✗ | ✗ | ✗ | Statistics, plots, dataset wrangling. |

### Why not collapse Python into the kernel language?

If everything were Rust, we would pay: slower iteration on the 80 % of code that changes weekly; loss of the LLM/ML/eval ecosystem; a smaller contributor pool for an open-source project. And we would gain nothing, because **the code that would benefit is exactly the code we are already putting in Rust.**

### Why not collapse Rust into Python?

The privileged process would then carry a CPython interpreter plus tens of thousands of lines of transitive dependencies inside the TCB, would be unable to scrub secrets from memory, would reach seccomp/Landlock through `ctypes`, and would be distributed as a directory tree rather than a verifiable artifact. Each of those is a concrete regression against a stated requirement.

### Why not Go instead of Rust?

Go satisfies requirements 1 (separate process), 2 (small dep set) and 3 (static binary) just as well, and would ship perhaps 30–40 % faster to first working kernel. We chose Rust on points 1–5 of §2, of which the **sum types / newtypes** argument is the one we weight most: the kernel's job is to make a small number of decisions correctly forever, and the failure mode we most fear — a new code path that silently defaults to permissive — is a compile error in Rust and a code review in Go. Given that the competitive evidence (see [COMPETITIVE_ANALYSIS.md](COMPETITIVE_ANALYSIS.md)) shows authorization-boundary drift as *the* dominant real-world failure class in this product category, we are buying insurance precisely where the claims are made.

This is a judgement call, not a proof. It is recorded as such.

---

## 4. The decision

> **B. CONTROLLED POLYGLOT — three languages, strictly partitioned by trust and by change rate.**

| Language | Scope | Lines (est. V1) | Change rate | Trust |
|---|---|---|---|---|
| **Rust** | `crates/` — authority plane + CLI binary. `dwkd-authority` is the TCB; `dwkd-broker` is privileged but holds no key; the CLI holds no authority ([ADR-0031](adr/0031-repository-layout-and-boundary-enforcement.md)) | ~33–40 k | Low, deliberate | **TCB (authority only)** |
| **Python 3.12+** | `runtime/`, `gateway/`, `evals/` — cognition, edge, evaluation | ~30–45 k | High | Untrusted |
| **TypeScript** | `web/` — UI only, deferred to M24 | ~8–15 k | Medium | No authority |

**The partition is principled, not arbitrary**, which is what separates controlled polyglot from sprawl:

> **Rust holds authority. Python holds intelligence. TypeScript holds pixels.**

You can state which language a new file belongs in by answering one question: *can this code cause a side effect, hold a credential, or make an authorisation decision?* If yes → Rust. If it only reasons, plans, or shapes data → Python. If it only renders → TypeScript.

Each additional language must justify itself against a boundary that already exists for another reason. Rust rides the privilege boundary. TypeScript rides the browser boundary. Neither creates a new boundary for its own sake, and we add no fourth language.

---

## 5. Costs we are accepting, and the mitigations

| Cost | Mitigation |
|---|---|
| Two toolchains in CI | Both are first-class in GitHub Actions; `cargo` and `uv` are the only build entry points. `make dev` sets up both. |
| Cross-language type drift | **Schemas are the source of truth.** `dwk-proto` emits JSON Schema; Python types are generated and CI fails on drift. No hand-written wire structs on either side. |
| Cross-language debugging | Correlation IDs propagate across the socket; OTel spans join in one trace. `direwolf doctor` checks both halves. |
| Contributor onboarding | 80 % of contributions touch Python only. `CONTRIBUTING.md` will route contributors; kernel changes require an ADR and a security reviewer. |
| Release engineering | One release pipeline producing per-platform bundles: a Rust binary plus a Python environment. Checksums and SBOMs for both. |
| Rust velocity on the kernel | The kernel is small and *should* be slow to change. If it is changing weekly, that is a design smell, not a language problem. |

### Rewrite triggers (recorded now so they are honest later)

- **Gateway → Rust/Go** if any of: > 500 concurrent connections, p99 fan-out latency > 200 ms, gateway RSS > 500 MB, or a hosted multi-user deployment becomes a real requirement.
- **Kernel → Go** if Rust build times or contributor scarcity measurably slow security fixes. Evidence: median time-to-merge for kernel security fixes exceeding two weeks over a quarter.
- **Drop TypeScript** if the web UI does not earn its keep by M27. A terminal UI plus the CLI may be sufficient, and deleting a language is a legitimate outcome.

---

## 6. Cross-language communication

| Boundary | Transport | Encoding | Why |
|---|---|---|---|
| Runtime ⇄ Kernel | Unix domain socket (`SO_PEERCRED`) / Windows named pipe with token check | Length-prefixed JSON, canonicalised | The security boundary. Peer credentials verified; **no FFI** — a crash or memory bug in the runtime must not be able to touch kernel memory. |
| Kernel ⇄ Sandboxes | Pipes + fds, OCI API | Raw streams | Standard process supervision. |
| Gateway ⇄ Runtime | Unix socket / localhost TCP | Same protocol framing | Same schema tooling; gateway can be colocated or separate. |
| Clients ⇄ Gateway | WebSocket / SSE / HTTP | JSON per [PROTOCOL.md](PROTOCOL.md) | Standard, debuggable, browser-reachable. |
| Web UI ⇄ Gateway | WebSocket | Same protocol | The UI is just another client. |

**No FFI anywhere.** PyO3 would make the kernel a library inside the runtime process, which would destroy the entire architecture: a memory-corruption bug or a prompt-injected `ctypes` call in the runtime would then sit in the same address space as the secrets. Process isolation is the product.

JSON over msgpack/protobuf for V1: debuggability and schema tooling outweigh the bytes at our message rates. The framing layer is versioned, so a binary encoding can be negotiated later without protocol churn.

---

## 7. Quality gates per language

**Rust (kernel)** — `rustfmt`; `clippy -D warnings` plus `-W clippy::pedantic` on security crates; `#![forbid(unsafe_code)]` in every crate except `dwk-sandbox` and `dwk-exec`, where each `unsafe` block requires a comment justifying its invariants and a reviewer sign-off; `cargo test`; `proptest` for the capability lattice, path canonicaliser and approval matcher; `cargo-fuzz` for the protocol parser and canonicaliser; `cargo-deny` (licences + advisories + bans + duplicates + sources + the dependency allowlist) — and **not** `cargo-audit` as well, which reads the same advisory database ([ADR-0031](adr/0031-repository-layout-and-boundary-enforcement.md)); the authority crate's *transitive* closure is allowlisted and checked from `Cargo.lock`; MSRV pinned.

**Python (runtime/gateway)** — `ruff` (lint + format); `mypy --strict` on `loop/`, `kernelclient/`, `proto/`, `tools/`, `policy`-adjacent code, `--strict` ratcheting elsewhere; `pytest`; `Hypothesis` for context assembly, event serialisation and state-machine transitions; `dwcheck` for the boundary contracts in [ARCHITECTURE.md](ARCHITECTURE.md) §6 — chosen over `import-linter` because it also covers the Cargo graph and can run over the deliberately-invalid fixtures that prove a rule works ([ADR-0031](adr/0031-repository-layout-and-boundary-enforcement.md)); `pip-audit`; lockfile via `uv`.

**TypeScript (web)** — `tsc --strict` with `noUncheckedIndexedAccess`; ESLint; Vitest; Playwright for a small smoke suite; `npm audit` with a dependency budget.

**Cross-system** — schema-drift check; protocol compatibility tests (old client × new server, both directions); migration tests on real fixture databases; Docker-backed sandbox integration tests; crash-recovery tests (`SIGKILL` at N injection points); the security eval suite from [EVALS.md](EVALS.md) as a merge gate.

We do not set a coverage-percentage target. The gate is behavioural: **every invariant in [README.md](../README.md) §Non-negotiable invariants has at least one test that fails if the invariant is removed**, and each of those tests is named after its invariant (`test_I2_child_caps_cannot_exceed_parent`).
