# Roadmap

Dependency-ordered. Every milestone has an objective, dependencies, deliverables, acceptance criteria, tests, adversarial tests and explicit deferrals.

**Rule: no milestone is complete until its adversarial tests pass.** Not "implemented, hardening later" — the hardening is the deliverable.

## Timeline, honestly

A scope freeze without a time axis is a list, not a freeze. Independent review estimated the Rust kernel at **33–40 k lines against a stated 18–25 k**, with the underestimate concentrated in `dwk-net` and the CLI, and put V1 at **24–30 calendar months for three experienced engineers** — M3 through M6 serialise hard, and the "adversarial tests gate the milestone" rule adds roughly 30 % that no one's estimate includes.

We accept that estimate rather than defending the original. The implications are stated rather than absorbed silently:

- **V1 is a ~2-year project for a small team**, not a 12-month one.
- The riskiest assumption — that per-tool-call kernel mediation is both fast enough and *tolerable enough* — was previously first measurable at M17, roughly two years in. That is the worst property a roadmap can have, and **M3.5 exists to fix it.**
- Milestones most likely to slip: **M5** (sandbox *and* egress proxy — two products in one), **M4** (three platforms × path canonicalisation; the Windows column alone is a milestone), **M9** (crash-injection harness across a process boundary), **M2** (Rust data-carrying enums → JSON Schema → typed Python is not plumbing).
- **`evals/` had no owning milestone** while being a merge gate from M3 onward. It is now M2.5.

### M2.5 · Evaluation harness — **COMPLETE**
**Deps:** M2. Runner, fixture repos, recorded-response replay mode, mock `ExecutionEnvironment`, scoring, statistics, and the fault-injection harness that can pause a named process at a named state. **Acceptance:** the security suite's deterministic subset runs in < 5 min on a hosted runner. A merge gate with no builder is not a gate.
**Delivered:** `evals/` — deterministic discovery with stable identifiers, versioned JSONL results plus a human summary, per-suite scoring (no single score), Wilson intervals for repeated runs, a reviewed baseline that CI never rewrites, provenance-checked fixtures, recorded-response replay with no provider anywhere, the hostile-DWKP and compatibility suites over the real decoder, a fault-injection harness proved against a dummy child process, a test-only execution-environment double that `dwcheck` PY003 keeps out of the product, an explicit pending model for suites that need M3+, and a `make eval-check` CI job.
**Result:** acceptance met. The gate subset runs in well under a minute locally (21 evals: 12 pass, 9 pending, 0 fail); the deliberate-failure meta-test proves a known-bad result fails the gate. **M2.5 proves nothing about authority**: every property that needs the kernel, the brokers, the sandbox, approvals or model egress is declared pending, and pending is never a pass.
**Deferred:** live-model evals and the recorded-response corpus (M7); real-process instrumentation of the authority daemon (M3); the vertical-slice measurements, which remain M3.5.

### M3.5 · Vertical slice — the risk-retirement milestone
**Deps:** M3, M4 (partial), M2.5. One tool (`fs.read`), one profile, one approval, end to end: CLI → runtime → kernel → sandbox. **Acceptance:** published measurements of kernel round-trip latency (p50/p99, side-effecting and not), cold start, and the approval count for one pinned realistic task. **This milestone exists to find out whether the product is viable before another eighteen months are spent on it.** If p99 or approval frequency is far outside target, the design changes here, not at M18.

---

## Ordering rationale

The brief's suggested order puts the tool registry (M6) before capabilities and policy (M7). We invert that: **the kernel comes first, before there is anything to constrain.** Retrofitting a privilege boundary is the mistake this whole architecture exists to avoid, and a tool registry built against an in-process check will encode that assumption everywhere.

We also pull **events and the run state machine (M5) before the agent kernel (M4)**, because the loop should be built on top of a durable state machine rather than having one bolted on afterwards.

```
M0 architecture ─ M1 foundation ─ M2 protocol+schemas
                                     ├─ M3 KERNEL CORE (policy, caps, audit)
                                     │     ├─ M4 brokers (fs, exec, secrets)
                                     │     │     └─ M5 sandbox
                                     │     └─ M6 approvals + budgets
                                     └─ M7 providers + model egress
                                           └─ M8 storage + events + run FSM
                                                 └─ M9 agent loop
                                                       ├─ M10 tools
                                                       ├─ M11 context
                                                       ├─ M12 artifacts
                                                       ├─ M13 memory
                                                       ├─ M14 subagents
                                                       ├─ M15 task graph
                                                       ├─ M16 MCP
                                                       └─ M17 CLI + doctor
                                                             └─ M18 V1 HARDENING ── V1.0
```

---

## Phase 1 — Foundation

### M1 · Repository foundation — **COMPLETE**
**Deps:** M0. **Deliverables:** monorepo layout (`crates/` × 3, `runtime/`, `tools/dwcheck/`, `schemas/`, `tests/architecture/`); Rust workspace + Python `uv` workspace, both locked; `make dev` / `make check`; CI (format, lint, types, boundaries, tests on three platforms, `cargo-deny`, `pip-audit`, release build); **Apache-2.0** ([ADR-0030](adr/0030-licence-apache-2.0.md)); `CONTRIBUTING.md`; boundary rules as data in `architecture.toml`, enforced by `dwcheck` ([ADR-0031](adr/0031-repository-layout-and-boundary-enforcement.md)).
**Acceptance:** met. `make dev` and `make check` pass; every declared boundary rule is proved to reject a deliberate violation; every quality gate is proved to reject a bad fixture; the Rust workspace has zero third-party dependencies and no `unsafe`.
**Deferred:** release automation, containers, secret-scanning tooling (GitHub push protection is the M1 mechanism), a PR-body review guard.

### M2 · Protocol and schemas — **COMPLETE**
**Deps:** M1. **Deliverables:** `dwk-proto` types; JSON Schema emission; Python codegen; canonical JSON (RFC 8785); envelope + versioning; framing; event schema registry.
**Acceptance:** round-trip property tests in both languages; **DWKP rejects unknown fields and unknown operations** (and duplicate keys; keys colliding under Unicode normalisation are undeclared members, which is the same rejection by a mechanism that needs no Unicode table — [ADR-0034](adr/0034-protocol-depends-on-no-unicode-database.md)); **DWCP preserves unknown fields**; **the event log retains unknown events verbatim** — three separate tests, per [ADR-0023](adr/0023-dwkp-strict-schema.md), not one blanket assertion; schema-drift CI gate; parser fuzzed ≥ 1 h clean.
**Adversarial:** malformed frames, oversized frames, depth bombs, duplicate keys, non-UTF-8.
**Delivered:** `crates/dwk-proto` — bounded framing, a strict JSON lexer, RFC 8785, the envelope and version negotiation, DWKP/DWCP/event message types, and the DWKP operation inventory (4 operations defined on the wire, 16 reserved with no wire form; [DWKP_OPERATIONS.md](DWKP_OPERATIONS.md)); `tools/protogen` → `schemas/` → `scripts/gen_proto_python.py` → `runtime/src/direwolf/proto/`, over a standard-library wire layer; `make schema` / `make schema-check` and a required CI job; shared golden vectors with a V8 oracle, run by both languages; property tests in both languages; four fuzz targets under libFuzzer and a stable mutation harness, with a weekly and pull-request fuzz workflow; `dwcheck` RS008/RS009/TX002 and dev-dependency-aware RS004/RS006 for the TCB-destined `dwk-proto`; [ADR-0032](adr/0032-wire-contract-framing-strict-json-and-jcs.md) (wire contract, JCS as the one canonical encoding) and [ADR-0033](adr/0033-protocol-source-of-truth-and-tcb-dependencies.md) (source of truth, TCB dependencies).
**Result:** acceptance met. The three compatibility behaviours are separate tests in each language; both languages agree on every shared vector; generation is deterministic and drift fails CI; the parser was fuzzed for **1 h per target with libFuzzer** (cargo-fuzz 0.13.2, AddressSanitizer, debug assertions; `frame_decoder`, `dwkp_decode`, `canonical_roundtrip`, `envelope_version`; ~322 M executions in total) with **no crash, timeout or leak**, plus 1 h of the stable mutation harness (not coverage-guided) with no failure — on Linux (WSL2), 2026-09-15.
**Deferred:** every protocol *semantic* — transport, peer credentials, epoch fencing, lease expiry, dedupe (M3, M8); encoding the approval binding and response MAC (M6, JCS per ADR-0032); DWWP; a maintained secret scanner (evaluated, revisited at M4 — [CONTRIBUTING.md](../CONTRIBUTING.md) "Secrets"); `cargo deny` over `fuzz/Cargo.lock`; verification of bit-for-bit reproducible builds; aligning the Python and Rust Unicode database versions.

---

## Phase 2 — The kernel

### M3 · Kernel core: policy, capabilities, audit
**Deps:** M2. **The most important milestone in the project.**
**Decomposed** into M3a (architecture decisions and wire forms — [ADR-0035](adr/0035-m3-authority-dependency-set.md), [ADR-0036](adr/0036-m3-authority-operations-and-the-capability-wire-form.md); `AdmitRun` carries a mandatory idempotency key, a wire decision is `ALLOW` or `DENY` until M6 can honour a third, and an authority-state refusal is a typed message distinct from both a protocol error and a policy denial), M3b (capabilities and attenuation — the typed vocabulary, the `⊑` lattice, attenuation with no widening path, and the declared-vs-canonical resource split of [ADR-0037](adr/0037-capability-specifications-and-canonical-authority-identities.md)), M3c (the policy engine -- two evaluation phases rather than one, a strict bounded TOML loader, closed typed predicates, reasons and obligations, `extends` restricted to a composition that cannot widen, three shipped packs with adversarial fixture suites, and the 300-rule target measured at a p99 of 3.6 us; [ADR-0038](adr/0038-policy-evaluation-phases-and-composition.md)), M3d (durable authority state -- `kernel.db` in a private state directory, epochs fenced across restarts, leases held by a connection rather than a uid, `AdmitRun` idempotency recorded forever and checked after the fence -- replayed while the run is live, `ADMISSION_ENDED` once it has ended ([ADR-0040](adr/0040-m3d-reconciliation-admission-across-tenures-and-undecidable-proposals.md)) -- kernel-owned policy inputs and a stored, content-derived policy revision, and a hash-chained `audit.log` written through a transactional outbox with a recovery rule for every crash window; [ADR-0039](adr/0039-durable-authority-state.md)) and M3e (the real authority process boundary -- a Unix-domain DWKP server whose peers the kernel identifies before a byte is read, one fresh lease holder per connection, a handshake-first strict transport delegating every request to M3d, and hostile real-process evaluations as the M3 merge gate; [ADR-0041](adr/0041-m3e-authenticated-dwkp-transport.md)). Each stage is verifiable on its own; the acceptance criteria below are the milestone's, not any one stage's.

M3c is also where the authority's third-party dependency closure stops being
empty: five crates, all of them the TOML parser chain, pinned exactly and with
no proc-macro and no native code. M3d adds SQLite and SHA-256: fifteen more
linked crates, among them the 269,376-line SQLite C amalgamation, and five
build-only crates reviewed in a list of their own. M3e adds `rustix`, the
last of [ADR-0035](adr/0035-m3-authority-dependency-set.md)'s set, for peer
credentials -- Linux only, with `linux-raw-sys` beneath it; the exact gate's
union grows to 25 runtime crates because it must also name `errno`,
`windows-sys` and `windows-link`, which no supported build links
([ADR-0041](adr/0041-m3e-authenticated-dwkp-transport.md) §14).

M3d's acceptance evidence is `make authority-state-evidence` (real files:
store refusal and quarantine, fencing, admission, both gates, the audit chain
and its verifier, crash windows A--G in process and in a killed child, and
contention) and `make authority-write-probe`, which attempts the runtime's
forbidden writes as a second operating-system user and reports NOT EXERCISED
rather than passing where no second user exists. What M3d does **not** deliver
is a decision about a proposed action over DWKP -- `QueryAuthority` refuses one
with `NO_CANONICAL_ACTION` until M4 can build the complete canonical action
policy decides on -- nor anything reachable from outside the process.

**M3e delivers the boundary** ([ADR-0041](adr/0041-m3e-authenticated-dwkp-transport.md)): `dwkd-authority serve`,
Linux only, on a Unix-domain socket whose name the runtime cannot remove or
replace; the kernel's peer credentials checked against the operator's uid list
before a byte is read; one fresh lease holder per accepted connection;
handshake first; the production decoder; every request to the M3d dispatcher
unchanged; bounded connections, frames, deadlines and writes; a poisoned store
that stops serving; and transport refusals audited, rate-limited. Its evidence
is `make authority-transport-evidence` -- the real binary, a real socket, a
client in another process, a real second OS user, `SIGKILL` and restart, a
hostile client -- and M3's five evaluations, now active and gating
(`authority-security`). The cross-uid property and the runtime-write probe need
two identities: CI's Linux jobs provide `nobody`, and a one-user workstation
reports them NOT EXERCISED. **M3 is complete when that hosted run is green.**
M3 still provides no canonical filesystem resource, no `ToolInvoke`, no
execution, no broker effect, no sandbox, no approvals and no model provider.
**Deliverables:** capability grammar + ⊑ lattice + attenuation; policy engine + TOML rule loader + explanation; three shipped profiles with fixture suites; hash-chained audit; **`dwkd-authority`** DWKP server with peer credential verification and **strict schema rejection** ([ADR-0023](adr/0023-dwkp-strict-schema.md)); epoch fencing (kernel is the epoch authority); `kernel.db` holding **every policy input** ([ADR-0028](adr/0028-policy-input-ownership.md)); the `dwkd-authority`/`dwkd-broker` split and the per-invocation authorisation format ([ADR-0018](adr/0018-authority-broker-split.md)).
**Acceptance:** policy p99 < 200 µs at 300 rules; every decision carries `rule_source`; audit chain verifies; runtime user cannot write `kernel.db` (verified by attempting it).
**Tests:** property tests for all eight lattice properties ([CAPABILITIES.md](CAPABILITIES.md) §3); 10⁶ generated delegation chains, zero escalations; policy fixtures including negative cases.
**Adversarial:** the **hostile DWKP client suite** ([EVALS.md](EVALS.md) §3) — a client that lies in every policy-input field, replays, reorders, omits, skips preconditions, presents stale epochs, and drives every operation directly. Plus forged and replayed tokens, socket impersonation from another uid, policy files with widening `extends`, capability synthesis attempts, and DWKP schema violations (unknown fields, unknown operations, duplicate keys, NFC-colliding keys).
**Deferred:** DSL, distributed policy.

### M4 · Brokers: filesystem, exec, secrets
**Deps:** M3. **Deliverables:** canonicaliser (NFC, `openat2` + fallback walker, inode identity); fd-relative fs ops; exec broker with env scrub, rlimits, argv normalisation, executable hashing; secret broker with keychain/age backends and injection modes A–C; redaction index.
**Acceptance:** no path string reaches policy; every op uses the fd it checked; no secret in argv, ever.
**Adversarial:** the full path-traversal set ([EVALS.md](EVALS.md) §3) including Unicode normalisation and TOCTOU swap races in a tight loop; secret-in-output detection; core-dump inspection for secret residue.
**Deferred:** remote fs, Windows-native hardening beyond the fallback walker.

### M5 · Sandbox
**Deps:** M4. **Deliverables:** `ExecutionEnvironment` trait; `oci-strict` profile with `PROXY_ONLY` networking ([ADR-0024](adr/0024-sandbox-network-topology.md)); supervisor with lifecycle, limits, reaping, and **re-attach by run-id label** after a container-runtime restart; `local` environment behind opt-in; `AssuranceLevel` surfaced to policy; CONNECT proxy with IP guard, DNS pinning, SNI/host agreement and byte budgets; kernel-performed `net.http`.
**Acceptance:** defaults from [SANDBOX.md](SANDBOX.md) §2 verified at runtime, not merely configured; from a `PROXY_ONLY` sandbox, **no route exists to any address but the proxy endpoint** (verified by attempting direct connections and direct DNS); a real package manager (`pip install`, `npm install`) succeeds against an allowlisted registry and fails against a non-allowlisted one; orphan reaping exact.
**Adversarial:** full escape suite; full SSRF suite; resource exhaustion; cross-run persistence attempts.
**Deferred:** gVisor/Kata/Firecracker, SSH, remote workers.

### M6 · Approvals and budgets
**Deps:** M3. **Deliverables:** binding hash; approval registry with scopes, expiry, single-use burn; standing grants with the 90-day cap and `require_untainted_run`; kernel-rendered approval prompts; hierarchical subtractive budget ledger; unattended degradation to DENY.
**Acceptance:** every property test in [APPROVALS.md](APPROVALS.md) §10; burn is atomic under concurrency; prompts contain no model-authored text in the authoritative region.
**Adversarial:** replay, substitution, drift (file/DNS/binary swap), laundering parent↔child, environment swap, fatigue spam, budget amplification via fan-out.

---

## Phase 3 — The runtime

### M7 · Providers and model egress
**Deps:** M3. **Deliverables:** `ModelProvider` interface; Anthropic and OpenAI-compatible adapters; kernel model egress with credential injection, privacy-class enforcement, declarative usage extraction, streaming relay; router with health and circuit breakers.
**Ollama as a first-class local provider** (a project-owner requirement, recorded at M3e; nothing is implemented before M7). Ollama is a **local** model provider behind the same `ModelProvider` interface as every other -- provider and model choice stay model-agnostic. An Ollama model reference (`<ollama-model-ref>`: any reference the installed Ollama supports, a model name or a model:tag variant) is passed as **data and configuration**, and nothing matches, branches on or hard-codes a model name: `qwen3.8` in the example below is illustrative, and no model is special. Local use must fit the privacy and model-authority model of [MODEL_ROUTING.md](MODEL_ROUTING.md) and [ADR-0020](adr/0020-provider-request-path-v2.md): the kernel performs the egress, the privacy class is kernel-derived ([ADR-0028](adr/0028-policy-input-ownership.md)), and a local endpoint is an origin like any other. **`--model` selects intelligence only.** It never selects or widens policy, capabilities, approvals, the sandbox, the privacy class or the authority profile.
**Acceptance:** no provider name outside `providers/` (CI gate); a `LOCAL_ONLY` run cannot reach a vendor; metering matches provider-reported usage; an Ollama model reference changes which model answers and nothing that decides authority.
**Adversarial:** router asked to route to an unauthorised upstream; credential-to-wrong-endpoint; cross-origin redirect credential leak.

### M8 · Storage, events, run state machine
**Deps:** M2, M3. **Deliverables:** `runtime.db` schema + migrations + backup + corruption quarantine; event log + envelope + projections + rebuild; run lifecycle FSM + wait sets; session leases + fencing; idempotent ingress.
**Acceptance:** projections rebuild from scratch; corrupt handle quarantines and stops writing; two runtimes racing a session → exactly one writer, zero stale-epoch effects.
**Adversarial:** duplicate delivery ×3 → one run; corrupt pages injected; clock jumps.

### M9 · Agent kernel (the loop)
**Deps:** M7, M8. **Deliverables:** turn execution; streaming; tool-call dispatch with side-effect-class batching; cancellation and `DRAINING`; loop/repetition detection; checkpoints and resume with re-admission; `UNKNOWN` reconciliation.
**Acceptance:** all ~40 crash-injection points resume or fail closed with a specific question; no new side effects after `DRAINING`.
**Adversarial:** kill between intent and completion for a `NON_RETRYABLE` tool; cancel mid-write; infinite tool loop.

### M10 · Tool registry and core tools
**Deps:** M4, M5, M9. **Deliverables:** registry; the **18** core tools of the canonical inventory ([TOOL_SYSTEM.md](TOOL_SYSTEM.md) §3); output capping, structure-aware excerpting, sanitisation (Unicode TAG, bidi, ANSI, delimiter forgery); policy-driven tool visibility.
**Acceptance:** no tool exceeds its cap; excerpting deterministic and never splits a codepoint; denied tools' schemas absent from the request.
**Adversarial:** 500 MB output; binary output; output containing forged delimiters and nonce guesses; argument injection per tool.

### M11a · Static skills
**Deps:** M3, M11. Manifest parsing; content-hash verification; kernel-side skill registry and trust assignment; capability intersection at admission; progressive disclosure L0/L1/L2; resolution scoring.
**Acceptance:** a skill cannot widen a run's capability set (property test); a modified skill fails its hash and is `QUARANTINED`; the runtime cannot alter a skill's trust level (covered by the hostile-DWKP-client suite).
**Explicitly deferred:** synthesis, validation pipeline, registry, consolidation — all M25 ([SKILLS.md](SKILLS.md) §0).

### M11 · Context engine
**Deps:** M9. **Deliverables:** section ladder, budgeting, eviction, `ContextManifest`, trust fencing with per-run nonce, structured compaction with loss check, quarantined reader.
**Acceptance:** deterministic assembly (hash-asserted); prefix hash constant across 50 turns; P0 never evicted; digest fidelity ≥ 0.95 on the session corpus.

### M12 · Artifacts · M13 · Memory · M14 · Subagents · M15 · Task graph
**Deps:** M11 (M12), M12 (M13), M6+M11 (M14), M14 (M15).
**Highlights:** CAS with kernel-side creation and quarantine; FTS5 memory with RRF, explainability and the promotion gate; subagents with kernel-enforced attenuation, subtractive budgets, workspace isolation and the context firewall; DAG with fan-out/join, retry classes and compensation.
**Acceptance:** zero untrusted promotions without approval; zero cross-scope leakage; zero escalations across generated delegation trees; merge conflicts surfaced, never silently resolved.
**Deferred:** consolidation, embeddings, dynamic replanning, durable long workflows.

### M16 · MCP client
**Deps:** M10. Kernel-spawned sandboxed servers; untrusted descriptions; `toolset_hash` rug-pull invalidation; per-server capability grants.
**Adversarial:** malicious description; rug pull; oversized results; server attempting network without a grant.

### M17 · CLI and doctor
**Deps:** M9–M16. Full command surface; `doctor` verifying facts not settings; export/import. The CLI is **not** a `ChannelAdapter` — that claim was retracted in Phase 0.1 ([ARCHITECTURE.md](ARCHITECTURE.md) §27); the interface is designed at M20 against two real channels.
**Acceptance:** startup to first prompt **< 400 ms with a warm kernel daemon, 1–2 s cold** ([PRODUCT_SPEC.md](PRODUCT_SPEC.md) §9 — audit verification is incremental against a signed checkpoint, not O(history), and Python import time dominates the cold path); `doctor` detects a deliberately misconfigured permission by attempting the write that should fail.
**Ollama launch integration** (a project-owner requirement, recorded at M3e). Target first-class invocation:

```text
ollama launch direwolf --model <ollama-model-ref>
# e.g. ollama launch direwolf --model qwen3.8   -- illustrative only; no model is hard-coded
```

M17 exposes a stable DireWolf launch and configuration contract suitable for Ollama's launcher; validates **arbitrary** Ollama model references rather than one named model; tests the launch path in ordinary CI against a small fixture model, with real Ollama and model smoke tests in dedicated integration and release jobs rather than on every pull request. Ollama's launcher uses an application integration registry: once DireWolf's M7/M17 contract is stable, an upstream integration is proposed so that `direwolf` becomes a first-class launch target. The model reference selects intelligence only -- never policy, capabilities, approvals, sandbox, privacy class or authority profile. (M3e changes nothing in the Ollama repository and adds no Ollama dependency or provider.)

### M18 · V1 hardening → **V1.0**
Full eval suite green; fuzzing soak; 24 h soak runs; performance targets met; docs complete; third-party security review commissioned; **published eval results including failures**.

---

## Post-V1

| Version | Milestones |
|---|---|
| **V1.1** | M19 gateway · M20 channels (Telegram first) · M21 scheduler + standing intents · M22 optional embeddings |
| **V1.2** | M23 browser (Playwright, sandboxed, quarantined downloads) |
| **V2.0** | M24 memory consolidation · M25 skill learning pipeline · M26 plugins (out-of-process) · M27 web UI · M28 remote workers |
| **V2.x** | Stronger isolation (gVisor/Firecracker) · durable workflows · competitive benchmark publication · skill registry (only with signing and revocation) |

## Permanently deferred

Autonomous self-modification of policy, kernel or capabilities · fully autonomous privileged skill installation · Kubernetes-first architecture · enterprise SSO/multi-tenancy/billing · becoming a general workflow orchestrator · framework-style agent authoring APIs.

## Milestone template

```markdown
## MN · Name
Objective:            one sentence
Dependencies:         M…
Deliverables:         …
Acceptance criteria:  measurable, checkable
Tests:                unit / integration / property
Adversarial tests:    what an attacker would try
Security checks:      which invariants are re-verified
Performance:          targets
Explicitly deferred:  what this milestone does NOT do
Exit review:          architecture · security · reliability sign-off
```
