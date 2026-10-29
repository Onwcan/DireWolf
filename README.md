# DireWolf

[![XERJ Corpus Hub contributor](https://hub.xerj.org/contributors/Onwcan/badge.svg)](https://hub.xerj.org/contributors/Onwcan)

**XERJ Corpus Hub:** [Onwcan Contributor Profile](https://hub.xerj.org/contributors/Onwcan)

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

## Status: M1–M4 complete; M5 (sandbox) in progress — M5a to M5d and M5e.1 complete

The paragraphs above describe the **design**. What is built today is the authority
plane underneath it — the kernel side of the trust boundary — and none of the agent
above it. M4, the last whole milestone completed, closed on hosted CI run
[36390815504](https://github.com/Onwcan/DireWolf/actions/runs/36390815504) (attempt 2);
the latest verified hosted run is
[40774766063](https://github.com/Onwcan/DireWolf/actions/runs/40774766063) at `6fd0bc7`,
27 of 27 jobs. [docs/ROADMAP.md](docs/ROADMAP.md) has every milestone's acceptance
evidence, and the M5 row below is a summary of it.

| Milestone | Status | What it delivered |
|---|---|---|
| M1 · Foundation | **COMPLETE** | Monorepo, locked Rust and Python workspaces, quality gates, boundary rules as data (`dwcheck`), CI on three platforms |
| M2 · Protocol | **COMPLETE** | `dwk-proto`: bounded framing, a strict JSON reader, RFC 8785 canonical JSON, versioned envelopes; generated JSON Schema and Python bindings; fuzzed |
| M2.5 · Evaluation harness | **COMPLETE** | `evals/`: deterministic suites, versioned results, a reviewed baseline, fault injection; pending is never a pass |
| M3 · Kernel core | **COMPLETE** | The typed capability lattice (10⁶ delegation chains, zero escalations); the deterministic policy engine (p99 3.6 µs at 300 rules); `kernel.db` with fenced epochs and durable admission; a hash-chained audit record for every authority-changing operation, `fsync`ed before the answer; `dwkd-authority serve`, which identifies its caller through the kernel (`SO_PEERCRED`) before reading a byte |
| M4 · Brokers | **COMPLETE** | Filesystem resolution by identity (`openat2`, no symlink, mount or Unicode escape); `dwkd-broker`, a second privileged process that acts only on the authority's single-use authorisation; eight filesystem tools with atomic mutation; process execution decided on executable identity; secrets by opaque handle, with no API that returns a value, return-path redaction and residue evidence |
| M5 · Sandbox | **IN PROGRESS** | **M5a — COMPLETE:** the `oci-strict` execution environment, measured from the runtime's record and by a digest-pinned probe inside it, with a durable, exactly-reconciled lifecycle. **M5b — COMPLETE:** `PROXY_ONLY` — the environment's only network peer is the broker's opaque CONNECT proxy, behind a relay, enforcing the run's exact HTTPS grants, the IP guard, one pinned resolution, server-name agreement and byte budgets; every bypass measured as refused. **M5c — COMPLETE:** `net.http`, the kernel's own HTTPS request, every hop decided by the authority and a credential only at its bound origin ([ADR-0050](docs/adr/0050-m5c-kernel-performed-net-http-ssrf-redirects-and-credential-egress.md), accepted with stated conditions). **M5d — COMPLETE** ([ADR-0052](docs/adr/0052-m5d-sandboxed-process-exec.md), accepted 2026-10-26): the public `process.exec` runs, over DWKP, in a measured environment the operator attaches (`serve --sandbox-config`) — as the environment's own uid, its executable's bytes proved, its output and wall clock bounded, an uncertain ending never run again; secret modes B and C through the pinned launcher; an operator-provisioned, measured workspace; an agent-shaped workload in `PROXY_ONLY`; a run's or a lease's end destroying its environment. Its accepted residuals: a lease that only expires ends nothing until its session is acquired again or the authority restarts, and a destruction a lease's end leaves pending holds brokered writes in its workspace (`SHARED_DIRECTORY`). **D11 hardening — ACCEPTED** ([ADR-0053](docs/adr/0053-d11-exchange-worker-confinement-and-secret-memory.md); `net.http` on `x86_64` only). **M5e** (the M5 gate) — **M5e.1 COMPLETE** (hosted run [40774766063](https://github.com/Onwcan/DireWolf/actions/runs/40774766063)): every line of the sandbox evidence names its level and the existing mechanism that enforced it, and the tasks refuse one that does not — attribution, not a new per-attempt audit event. **M5e.2 BUILT IN PART, hosted verification pending:** every hard rule refused under `PROXY_ONLY` by the broker's own judgement (in process), and runs that see none of each other's processes, cannot name each other's environment and leave nothing to the next (real runtime). **Open finding (R8):** every environment runs as host uid 10001, whose `RLIMIT_NPROC` is counted across all of them, so while one workload holds its task bound, a workload another run starts is refused and that run's environment destroyed — fail-closed, nothing escapes, but one run can deny the others; the remedy is the owner's ([plan](docs/M5E_ASSURANCE_PLAN.md), F-R8). The runtime restart under a running authority and real weakened `PROXY_ONLY` containers are not built. **M5e.3–M5e.6** (registry fixtures, pip and npm, the final gate) not started, so M5 is not complete |

**What that means in practice.** A client can connect to `dwkd-authority`, be admitted
to a run, and ask the authority to read, list, search, stat, write, patch, move or delete
files beneath an operator-bound workspace, each decided by both gates and audited. The
shipped policy packs deny every read until a home anchor exists, so a deployment reads
files with an operator policy. Process execution and secret injection are built and
tested end to end. **No production build launches a process on the host** — a host launch
needs a per-invocation approval, and approvals are M6's — but when the operator attaches
an execution environment (`serve --sandbox-config`, Linux), the public `process.exec` runs
there (M5d): the authority decides each workload, the broker runs exactly its plan as the
environment's own uid in a measured `oci-strict` container, and nothing falls back to the
host. A credential (secret mode A) reaches only `net.http`'s bound origin (M5c); modes B
and C reach a sandboxed `process.exec` through the pinned launcher (M5d.3), and every
descendant of that process inherits the value.

**What does not exist yet**, and which milestone owns it:

- the **complete M5 gate** (M5e.2–M5e.6) — a container-runtime restart under a running
  authority, real weakened `PROXY_ONLY` containers, the full escape, SSRF, persistence and
  resource-exhaustion suites as one merge gate, and package-manager acceptance (`pip
  install`, `npm install` against an allowed and a refused registry; npm's and pip's
  profiles are [ADR-0054](docs/adr/0054-m5e-npm-hygiene-profile.md) and
  [ADR-0055](docs/adr/0055-m5e-pip-hygiene-profile.md), both **Proposed**, so npm stays
  refused and pip unchanged). M5d's sandboxed workloads exist and are hosted-tested,
  an agent-shaped escape suite among them, but only `process.exec` runs in an
  environment: the filesystem tools still act on the workspace through the broker on the
  host, and policy is told which. A `PROXY_ONLY` workload reaches only its granted
  origins through the broker's proxy; `net.http` (M5c, complete), the kernel's own HTTPS
  request, is the kernel's one network tool;
- **approvals and budgets** (M6) — a decision that would need approval is a denial;
- **model providers** (M7) — native, cloud-platform, OpenAI-compatible and local or
  self-hosted families, Hugging Face, Ollama and llama.cpp among them, every one behind
  the authority's model egress;
- the **agent runtime** — the loop, tools an agent calls, context, memory, skills,
  subagents, MCP (M8–M16) — so the runtime's own confinement is not built either (M9);
- the full **CLI** (M17): `direwolf` supports `--version` and `doctor`, and nothing else;
- channels, a scheduler, a browser, plugins, a web UI and remote workers (post-V1), and
  interoperability with external coding agents — ACP first, each one a contained workload
  or a client, never an authority (M29, post-V1;
  [ADR-0051](docs/adr/0051-external-agent-interoperability.md), Proposed).

**Platforms.** The authority and the broker serve on **Linux only**; on macOS and native
Windows `serve` refuses to start rather than guess who is on the other end. The Windows
Credential Manager backend is tested and not served; the macOS Keychain backend is
compile-only. `dwkd-authority verify-audit <dir>` checks an audit chain, read-only, on
every platform.

**Evidence.** Each property above is exercised against the real binaries by a `make`
target: for the authority and the brokers `capability-evidence`,
`authority-state-evidence`, `authority-transport-evidence`,
`filesystem-canonicalization-evidence`, `broker-fs-read-evidence`,
`filesystem-operations-evidence`, `process-broker-evidence` and `secret-broker-evidence`;
for the sandbox `sandbox-foundation-evidence`, `sandbox-egress-evidence`,
`net-http-evidence`, `sandbox-workload-evidence`, `sandbox-secret-evidence`,
`sandbox-workspace-evidence`, `sandbox-agent-evidence`, `sandbox-release-evidence` and
`d11-hardening-evidence`, most with a `…-mutations` review beside it. The gated
evaluations are `authority-security`, `m4-security`, `m5a-sandbox-foundation`,
`m5b-sandbox-egress`, `m5c-net-http` and `m5d-sandbox-exec`, the M5 ones on a real OCI
runtime. Every sandbox evidence line names its level (`real-oci`, `in-process`, …) and the
mechanism that enforced it, and a task refuses one that does not
([docs/SANDBOX.md](docs/SANDBOX.md) §6a). `make check` runs the core gates, not these
campaigns: most need Linux, the sandbox ones a container runtime, and some root or separate
users, so hosted CI runs every one but `capability-evidence` and `authority-state-evidence`
in a job of its own. The halves that need
separate operating-system identities, root or a dedicated filesystem run in hosted CI with
three genuine users; on a one-user workstation they report NOT EXERCISED, which fails
rather than passes. Where the architecture stands against comparable projects, including
where it is behind, is in [docs/COMPETITIVE_ANALYSIS.md](docs/COMPETITIVE_ANALYSIS.md).

DireWolf's own Rust contains no `unsafe`. The authority links third-party crates — among
them SQLite's C amalgamation — and the broker links a few on Linux; the reviewed sets and
their reasons are in the ADRs, and the licence obligations in [NOTICE](NOTICE).

```bash
git clone https://github.com/Onwcan/DireWolf.git direwolf && cd direwolf
make dev          # verify toolchain, sync, build, check   (idempotent)
make check        # the core gates: format, lint, types, boundaries, schemas, tests, evals, deps
make help         # everything else, each evidence campaign among it
```

Prerequisites: Rust (via [rustup](https://rustup.rs) — it reads the pinned
toolchain), Python 3.12+, `uv`, and git. Nothing else for `make check`; the sandbox
campaigns also need Linux and a Docker-compatible runtime.
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
[M5E_ASSURANCE_PLAN](docs/M5E_ASSURANCE_PLAN.md) ·
[LANGUAGE_SELECTION](docs/LANGUAGE_SELECTION.md)

**Security**
[SECURITY](docs/SECURITY.md) ·
[THREAT_MODEL](docs/THREAT_MODEL.md) ·
[CAPABILITIES](docs/CAPABILITIES.md) ·
[POLICY](docs/POLICY.md) ·
[APPROVALS](docs/APPROVALS.md) ·
[SANDBOX](docs/SANDBOX.md) ·
[NETWORK_SECURITY](docs/NETWORK_SECURITY.md) ·
[SECRETS](docs/SECRETS.md) ·
[BROKER_HARDENING](docs/BROKER_HARDENING.md)

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
[DWKP_OPERATIONS](docs/DWKP_OPERATIONS.md) ·
[OBSERVABILITY](docs/OBSERVABILITY.md) ·
[RELIABILITY](docs/RELIABILITY.md)

**Evaluation**
[EVALS](docs/EVALS.md) ·
[BENCHMARKS](docs/BENCHMARKS.md)

**Review**
[PHASE0_REVIEW](docs/PHASE0_REVIEW.md) — 62 findings from three independent adversarial review tracks, with dispositions ·
[M5D5_IMPLEMENTATION_HANDOFF](docs/M5D5_IMPLEMENTATION_HANDOFF.md) — a checkpoint's plan, kept as it was written.

**Decisions**: [docs/adr/](docs/adr/) — 56 architecture decision records (0000–0055), three of them superseded and kept as history, and three Proposed (0051, 0054, 0055). Start with [ADR-0000](docs/adr/0000-authority-plane-separation.md), then [ADR-0018](docs/adr/0018-authority-broker-split.md); everything else is downstream. The [index](docs/adr/README.md) says which are current.

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
| I7 | Default-deny network, default-deny filesystem, default-deny execution | Kernel defaults | IMPLEMENTED for filesystem and execution (M4) and for the two network paths that exist: a `PROXY_ONLY` environment reaches only its run's granted HTTPS origins (M5b), and `net.http` only a granted host (M5c) |
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
