# DireWolf

> **Intelligence may propose. Policy grants authority. Execution remains controlled.**

DireWolf is a model-agnostic, local-first, security-first autonomous agent runtime.

It is built on one structural claim that most agent frameworks do not make:

**The component that reasons is not the component that is trusted.**

In DireWolf's design, the process that runs the agent loop — the process that ingests
model output, web pages, tool results, MCP responses and memory — holds **no credentials,
no network route, no filesystem handles and no ability to execute anything.** Every side
effect is requested from a separate, privileged, minimal-dependency process (the
*kernel*) which independently canonicalises the request, evaluates deterministic policy,
verifies a capability token, optionally demands human approval, injects credentials the
requester never sees, performs the effect inside a sandbox, and writes a hash-chained
audit record.

A fully compromised model — or a fully compromised agent runtime — does not imply a
compromised host. That is the target; the status below says which parts of it exist.

---

## Status: M1–M4 complete; M5 (sandbox) in progress — M5a complete

The paragraphs above describe the **design**. What is built today is the authority
plane underneath it — the kernel side of the trust boundary — and none of the agent
above it. M4, the last milestone completed, closed on hosted CI run
[36390815504](https://github.com/Onwcan/DireWolf/actions/runs/36390815504) (attempt 2);
[docs/ROADMAP.md](docs/ROADMAP.md) has every milestone's acceptance evidence.

| Milestone | Status | What it delivered |
|---|---|---|
| M1 · Foundation | **COMPLETE** | Monorepo, locked Rust and Python workspaces, quality gates, boundary rules as data (`dwcheck`), CI on three platforms |
| M2 · Protocol | **COMPLETE** | `dwk-proto`: bounded framing, a strict JSON reader, RFC 8785 canonical JSON, versioned envelopes; generated JSON Schema and Python bindings; fuzzed |
| M2.5 · Evaluation harness | **COMPLETE** | `evals/`: deterministic suites, versioned results, a reviewed baseline, fault injection; pending is never a pass |
| M3 · Kernel core | **COMPLETE** | The typed capability lattice (10⁶ delegation chains, zero escalations); the deterministic policy engine (p99 3.6 µs at 300 rules); `kernel.db` with fenced epochs and durable admission; a hash-chained audit record for every authority-changing operation, `fsync`ed before the answer; `dwkd-authority serve`, which identifies its caller through the kernel (`SO_PEERCRED`) before reading a byte |
| M4 · Brokers | **COMPLETE** | Filesystem resolution by identity (`openat2`, no symlink, mount or Unicode escape); `dwkd-broker`, a second privileged process that acts only on the authority's single-use authorisation; eight filesystem tools with atomic mutation; process execution decided on executable identity; secrets by opaque handle, with no API that returns a value, return-path redaction and residue evidence |
| M5 · Sandbox | **IN PROGRESS** | **M5a — COMPLETE, HOSTED ACCEPTANCE PASS:** the `oci-strict` execution environment, measured from the runtime's record and by a digest-pinned probe inside it, with a durable, exactly-reconciled lifecycle — reachable by no public caller. **M5b — COMPLETE, HOSTED ACCEPTANCE PASS:** `PROXY_ONLY` — an environment whose only network peer is the broker's opaque CONNECT proxy, behind a relay, enforcing the run's exact HTTPS grants, the IP guard, one pinned resolution, server-name agreement and byte budgets; every bypass measured as refused. M5c–M5e (`net.http`, sandboxed workloads, the M5 gate) not started |

**What that means in practice.** A client can connect to `dwkd-authority`, be admitted
to a run, and ask the authority to read, list, search, stat, write, patch, move or delete
files beneath an operator-bound workspace, each decided by both gates and audited. The
shipped policy packs deny every read until a home anchor exists, so a deployment reads
files with an operator policy. Process execution and secret injection are built and
tested end to end, but **no production build launches a process** — a host launch needs a
per-invocation approval, and approvals are M6's — and injected secrets have no consumer
until M5.

**What does not exist yet**, and which milestone owns it:

- a **sandboxed workload**, `net.http` and any network path a workload uses (M5c–M5e) —
  M5a builds and measures the execution environment and M5b gives it `PROXY_ONLY`
  networking (one peer: the broker's opaque CONNECT proxy), but no public caller can
  prepare one and nothing but the assurance probe runs in it; every action still runs on
  the host, and policy is told so;
- **approvals and budgets** (M6) — a decision that would need approval is a denial;
- **model providers** (M7) — native, cloud-platform, OpenAI-compatible and local or
  self-hosted families, Hugging Face and Ollama among them, every one behind the
  authority's model egress;
- the **agent runtime** — the loop, tools an agent calls, context, memory, skills,
  subagents, MCP (M8–M16) — so the runtime's own confinement is not built either (M9);
- the full **CLI** (M17): `direwolf` supports `--version` and `doctor`, and nothing else;
- channels, a scheduler, a browser, plugins, a web UI and remote workers (post-V1).

**Platforms.** The authority and the broker serve on **Linux only**; on macOS and native
Windows `serve` refuses to start rather than guess who is on the other end. The Windows
Credential Manager backend is tested and not served; the macOS Keychain backend is
compile-only. `dwkd-authority verify-audit <dir>` checks an audit chain, read-only, on
every platform.

**Evidence.** Each property above is exercised against the real binaries by a `make`
target — `authority-state-evidence`, `authority-transport-evidence`,
`filesystem-canonicalization-evidence`, `broker-fs-read-evidence`, `sandbox-foundation-evidence`,
`filesystem-operations-evidence`, `process-broker-evidence`, `secret-broker-evidence` —
and by the gated `authority-security`, `m4-security` and `m5a-sandbox-foundation` evaluations
(the last on a real OCI runtime). The halves that need
separate operating-system identities run in CI with three genuine users; on a one-user
workstation they report NOT EXERCISED, which fails rather than passes. Where the
architecture stands against comparable projects, including where it is behind, is in
[docs/COMPETITIVE_ANALYSIS.md](docs/COMPETITIVE_ANALYSIS.md).

DireWolf's own Rust contains no `unsafe`. The authority links third-party crates — among
them SQLite's C amalgamation — and the broker links a few on Linux; the reviewed sets and
their reasons are in the ADRs, and the licence obligations in [NOTICE](NOTICE).

```bash
git clone https://github.com/Onwcan/DireWolf.git direwolf && cd direwolf
make dev          # verify toolchain, sync, build, check   (idempotent)
make check        # every gate CI runs
make help         # everything else
```

Prerequisites: Rust (via [rustup](https://rustup.rs) — it reads the pinned
toolchain), Python 3.12+, `uv`, and git. Nothing else.
[CONTRIBUTING.md](CONTRIBUTING.md) has the detail; on Windows without WSL2, run
`python scripts/dw.py <task>` instead of `make`.

## Read in this order

| # | Document | What it answers |
|---|----------|-----------------|
| 1 | [docs/PRODUCT_SPEC.md](docs/PRODUCT_SPEC.md) | What DireWolf is, who it is for, what V1 does and does not do |
| 2 | [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | The system: planes, components, flows, lifecycles |
| 3 | [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | What we are defending against and what we are not |
| 4 | [docs/adr/0019-language-rationale-v2.md](docs/adr/0019-language-rationale-v2.md) | Why Rust + Python + (deferred) TypeScript |
| 5 | [docs/CAPABILITIES.md](docs/CAPABILITIES.md) → [docs/POLICY.md](docs/POLICY.md) → [docs/APPROVALS.md](docs/APPROVALS.md) | The authority pipeline, in order |
| 6 | [docs/ROADMAP.md](docs/ROADMAP.md) | Build order and acceptance criteria |
| 7 | [docs/PHASE0_REVIEW.md](docs/PHASE0_REVIEW.md) | What three adversarial reviews found, and what changed |

### Full document index

**Product & system**
[PRODUCT_SPEC](docs/PRODUCT_SPEC.md) ·
[ARCHITECTURE](docs/ARCHITECTURE.md) ·
[COMPETITIVE_ANALYSIS](docs/COMPETITIVE_ANALYSIS.md) ·
[ROADMAP](docs/ROADMAP.md) ·
[LANGUAGE_SELECTION](docs/LANGUAGE_SELECTION.md)

**Security**
[SECURITY](docs/SECURITY.md) ·
[THREAT_MODEL](docs/THREAT_MODEL.md) ·
[CAPABILITIES](docs/CAPABILITIES.md) ·
[POLICY](docs/POLICY.md) ·
[APPROVALS](docs/APPROVALS.md) ·
[SANDBOX](docs/SANDBOX.md) ·
[NETWORK_SECURITY](docs/NETWORK_SECURITY.md) ·
[SECRETS](docs/SECRETS.md)

**Runtime**
[TOOL_SYSTEM](docs/TOOL_SYSTEM.md) ·
[MODEL_ROUTING](docs/MODEL_ROUTING.md) ·
[CONTEXT](docs/CONTEXT.md) ·
[MEMORY](docs/MEMORY.md) ·
[ORCHESTRATION](docs/ORCHESTRATION.md) ·
[WORKFLOWS](docs/WORKFLOWS.md) ·
[SKILLS](docs/SKILLS.md) ·
[PLUGINS](docs/PLUGINS.md) ·
[ARTIFACTS](docs/ARTIFACTS.md)

**Platform**
[DATA_MODEL](docs/DATA_MODEL.md) ·
[STORAGE](docs/STORAGE.md) ·
[PROTOCOL](docs/PROTOCOL.md) ·
[OBSERVABILITY](docs/OBSERVABILITY.md) ·
[RELIABILITY](docs/RELIABILITY.md)

**Evaluation**
[EVALS](docs/EVALS.md) ·
[BENCHMARKS](docs/BENCHMARKS.md)

**Review**
[PHASE0_REVIEW](docs/PHASE0_REVIEW.md) — 62 findings from three independent adversarial review tracks, with dispositions.

**Decisions**: [docs/adr/](docs/adr/) — 47 architecture decision records (0000–0046), three of them superseded and kept as history. Start with [ADR-0000](docs/adr/0000-authority-plane-separation.md), then [ADR-0018](docs/adr/0018-authority-broker-split.md); everything else is downstream. The [index](docs/adr/README.md) says which are current.

---

## The five planes

```
Presentation      CLI, Web UI, chat clients           no authority, ever
      |
Edge              Gateway: transport, authn, channels  can address, cannot act
      |
Cognition         Agent loop, context, memory,         reasons; holds nothing
                  planner, model router, subagents     no creds / net / fs / exec
      |  ===================== TRUST BOUNDARY =====================
Authority         Kernel (dwkd): policy, capabilities, approvals,
                  secrets, budgets, fs/exec/egress brokers, audit
      |
Execution         OCI sandboxes, browser, MCP servers, remote workers
```

The `===` line is the only boundary that matters. It is a **process and privilege
boundary**, not a function call. Everything above it is assumed hostile.

## Why the boundary is real

Three properties fall out of putting credentials below the line rather than above it. All
three are design properties whose mechanisms arrive with model egress (M7), approvals
(M6) and the runtime's network confinement (M9); none is claimed for the current build.

1. **Budgets are not advisory.** The runtime has no provider API key and no network
   route. Model calls are performed *by the kernel*, which injects the credential and
   meters the response. An agent cannot make an unmetered model call because it cannot
   make a model call at all.
2. **Privacy routing is enforced, not intended.** "This repository may not be sent to a
   non-local provider" is checked at the egress point that holds the credential, so a
   mis-planning or manipulated router cannot leak it.
3. **Approval prompts cannot be phished.** What a human is asked to approve is rendered
   from the kernel's canonicalised request — resolved paths, resolved IPs, hashed
   argv — never from model-authored prose describing what it intends to do.

## Non-negotiable invariants

| # | Invariant | Enforced by | Status |
|---|-----------|-------------|--------|
| I1 | No side effect occurs without a kernel-verified capability token | Kernel; runtime has no other path | IMPLEMENTED for every effect that exists (M4); the runtime that must have no other path is M9 |
| I2 | `child_capabilities ⊑ parent_capabilities` — delegation only attenuates | Capability Broker lattice check | IMPLEMENTED (M3b); subagents M14 |
| I3 | The Cognition Plane never receives plaintext long-lived credentials | Secret Broker | IMPLEMENTED for secret handles (M4e); model keys M7 |
| I4 | Every authority decision is explainable: rule id, file, line | Policy Engine | IMPLEMENTED (M3c) |
| I5 | Untrusted provenance cannot be laundered into durable memory without a human | Kernel-held provenance + promotion gate; **backstopped by I9** | PLANNED (M13) |
| I6 | Approvals bind to canonical actions and are single-use by default | Approval Registry | PLANNED (M6); until then an approval-requiring action is denied |
| I7 | Default-deny network, default-deny filesystem, default-deny execution | Kernel defaults | IMPLEMENTED for filesystem and execution (M4); no network path exists before M5 |
| I8 | Budgets are reservations debited from a parent, never per-agent grants | Budget Ledger | PLANNED (M6) |
| I9 | Memory and context can never alter authority — they are not terms in any capability or policy expression | Structural: the mint formula and rule files do not read them | IMPLEMENTED structurally (M3); memory itself M13 |
| I10 | Every policy input is derived and stored kernel-side | Kernel; `runtime.db` copies are caches | IMPLEMENTED (M3d) |

## Licence

**Apache-2.0** ([ADR-0030](docs/adr/0030-licence-apache-2.0.md)). Chosen for the
express patent grant: DireWolf's contribution is a set of mechanisms, and
silence on patents is the wrong default for that. No CLA — Apache-2.0 §5
already covers contributions.

## Contributing

[CONTRIBUTING.md](CONTRIBUTING.md). The short version: one question decides
where your change goes — *can this code make an authorisation decision, hold a
credential, or cause a side effect?* If yes, it is Rust in `crates/`. If it
only reasons, plans or shapes data, it is Python in `runtime/`.

Security-sensitive changes need a second reviewer, and every new DWKP operation
needs a written argument for why it is not a second path from cognition to
effect. Report vulnerabilities privately — see [SECURITY.md](SECURITY.md).
