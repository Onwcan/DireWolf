<div align="center">

# DireWolf

**Intelligence may propose. Policy grants authority. Execution remains controlled.**

A model-agnostic, local-first, security-first autonomous agent runtime,<br>
built so that the component that reasons is never the component that is trusted.

[![CI](https://github.com/Onwcan/DireWolf/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/Onwcan/DireWolf/actions/workflows/ci.yml)
[![Licence: Apache-2.0](https://img.shields.io/badge/licence-Apache--2.0-blue)](LICENSE)
[![Milestone: M5 complete](https://img.shields.io/badge/milestone-M5%20complete-2ea44f)](docs/ROADMAP.md)
[![Kernel: Rust, no unsafe](https://img.shields.io/badge/kernel-Rust%2C%20no%20unsafe-b7410e?logo=rust&logoColor=white)](crates/)
[![Runtime: Python 3.12+](https://img.shields.io/badge/runtime-Python%203.12%2B-3776ab?logo=python&logoColor=white)](runtime/)
[![Serves on: Linux](https://img.shields.io/badge/serves%20on-Linux-555?logo=linux&logoColor=white)](#status)
[![XERJ Corpus Hub contributor](https://hub.xerj.org/contributors/Onwcan/badge.svg)](https://hub.xerj.org/contributors/Onwcan)

[Quick start](#quick-start) ·
[Status](#status) ·
[Architecture](docs/ARCHITECTURE.md) ·
[Threat model](docs/THREAT_MODEL.md) ·
[Roadmap](docs/ROADMAP.md) ·
[Decisions](docs/adr/README.md) ·
[Security](SECURITY.md) ·
[Contributing](CONTRIBUTING.md)

**XERJ Corpus Hub:** [Onwcan Contributor Profile](https://hub.xerj.org/contributors/Onwcan)

</div>

---

## Why DireWolf

DireWolf is built on one structural claim that most agent frameworks do not make:

> **The component that reasons is not the component that is trusted.**

In DireWolf's design, the process that runs the agent loop — the process that ingests
model output, web pages, tool results, MCP responses and memory — holds **no credentials,
no network route, no filesystem handles and no ability to execute anything.** Every side
effect is requested from a separate, privileged, minimal-dependency process, the
*kernel*, which:

1. canonicalises the request independently;
2. evaluates deterministic policy;
3. verifies a capability token;
4. optionally demands human approval;
5. injects credentials the requester never sees;
6. performs the effect inside a sandbox;
7. writes a hash-chained audit record.

A fully compromised model — or a fully compromised agent runtime — does not imply a
compromised host. That is the target; [Status](#status) says which parts of it exist.

## What is built

The **authority plane** — the kernel side of the trust boundary — is built, through M5.
The agent above it is not built yet.

| | What exists | Since |
|---|---|---|
| **Deterministic policy** | Every decision explainable by rule id, file and line; p99 3.6 µs at 300 rules | M3 |
| **Capabilities that only narrow** | A typed `⊑` lattice: 10⁶ generated delegation chains, zero escalations | M3 |
| **Tamper-evident audit** | A hash-chained record of every authority-changing operation, `fsync`ed before the answer; `verify-audit` on every platform | M3 |
| **An authenticated boundary** | `dwkd-authority serve` identifies its caller through the kernel (`SO_PEERCRED`) before it reads a byte | M3 |
| **Brokered effects** | Files resolved by identity (`openat2`; no symlink, mount or Unicode escape); processes decided on executable identity; secrets by opaque handle, with no API that returns a value | M4 |
| **A measured sandbox** | `oci-strict` environments measured from the runtime's record and by a digest-pinned probe; `PROXY_ONLY` egress through the broker's CONNECT proxy; the kernel's own `net.http` | M5 |
| **Package managers, contained** | `npm ci`, `npm install` and `pip install` only under evidence-backed profiles; npx, pnpm, yarn, bun and cargo refused | M5 |
| **Evidence, not assertions** | Every property exercised against the real binaries in hosted CI, on three genuine operating-system identities where it needs them; NOT EXERCISED fails rather than passes | every milestone |

## Quick start

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

There is no agent to run yet — `direwolf` supports `--version` and `doctor`. What runs
today is the authority plane and the evidence for it.

## Status

**M1–M5 are complete.** What is built is the authority plane underneath the design and
none of the agent above it. [docs/ROADMAP.md](docs/ROADMAP.md) has every milestone's
acceptance evidence; this table summarises it.

| Milestone | Status | Completed | What it delivered |
|---|---|---|---|
| M1 · Foundation | ✅ **COMPLETE** | 2026-09-15 | Monorepo, locked Rust and Python workspaces, quality gates, boundary rules as data (`dwcheck`), CI on three platforms |
| M2 · Protocol | ✅ **COMPLETE** | 2026-09-16 | `dwk-proto`: bounded framing, a strict JSON reader, RFC 8785 canonical JSON, versioned envelopes; generated JSON Schema and Python bindings; fuzzed |
| M2.5 · Evaluation harness | ✅ **COMPLETE** | 2026-09-16 | `evals/`: deterministic suites, versioned results, a reviewed baseline, fault injection; pending is never a pass |
| M3 · Kernel core | ✅ **COMPLETE** | 2026-09-23 | The typed capability lattice (10⁶ delegation chains, zero escalations); the deterministic policy engine (p99 3.6 µs at 300 rules); `kernel.db` with fenced epochs and durable admission; a hash-chained audit record for every authority-changing operation, `fsync`ed before the answer; `dwkd-authority serve`, which identifies its caller through the kernel (`SO_PEERCRED`) before reading a byte |
| M4 · Brokers | ✅ **COMPLETE** | 2026-09-28 | Filesystem resolution by identity (`openat2`, no symlink, mount or Unicode escape); `dwkd-broker`, a second privileged process that acts only on the authority's single-use authorisation; eight filesystem tools with atomic mutation; process execution decided on executable identity; secrets by opaque handle, with no API that returns a value, return-path redaction and residue evidence |
| M5 · Sandbox | ✅ **COMPLETE** | 2026-11-11 | **M5a** (2026-10-04): the `oci-strict` execution environment, measured from the runtime's record and by a digest-pinned probe inside it, with a durable, exactly-reconciled lifecycle.<br>**M5b** (2026-10-06): `PROXY_ONLY` — the environment's only network peer is the broker's opaque CONNECT proxy, enforcing the run's exact HTTPS grants, the IP guard, one pinned resolution, server-name agreement and byte budgets; every bypass measured as refused.<br>**M5c** (2026-10-11): `net.http`, the kernel's own HTTPS request, every hop decided by the authority and a credential only at its bound origin ([ADR-0050](docs/adr/0050-m5c-kernel-performed-net-http-ssrf-redirects-and-credential-egress.md), accepted with stated conditions; its exchange worker confined by [ADR-0053](docs/adr/0053-d11-exchange-worker-confinement-and-secret-memory.md), so `net.http` runs on `x86_64` only).<br>**M5d** (2026-10-26): the public `process.exec` runs, over DWKP, in a measured environment the operator attaches (`serve --sandbox-config`) — as the environment's own uid, its executable's bytes proved, its output and wall clock bounded, an uncertain ending never run again; secret modes B and C through the pinned launcher; a measured workspace; a run's or a lease's end destroying its environment ([ADR-0052](docs/adr/0052-m5d-sandboxed-process-exec.md)).<br>**M5e** (2026-11-11): the M5 gate — each hard rule weakened in a real `PROXY_ONLY` environment, refused ([ADR-0058](docs/adr/0058-m5e-proxy-only-hard-rules-weakened-in-a-real-environment.md), [ADR-0059](docs/adr/0059-m5e-proxy-only-peer-joins-only-its-own-network-namespace.md)); one workload at its task bound unable to starve another ([ADR-0056](docs/adr/0056-m5e-cross-run-task-limit-isolation.md)); npm and pip only under evidence-backed profiles ([ADR-0054](docs/adr/0054-m5e-npm-hygiene-profile.md), [ADR-0055](docs/adr/0055-m5e-pip-hygiene-profile.md)); and every M5 evidence task judged again by one required `m5e-gate` job ([plan](docs/M5E_ASSURANCE_PLAN.md)) |
| M6 · Approvals and budgets | ⏳ next | — | Approvals bound to the canonical action, single-use by default, with scopes and expiry; standing grants capped at 90 days; kernel-rendered prompts; a hierarchical budget ledger; unattended runs degrading to DENY; host-local execution behind an opt-in (deferred from M5, ADR-0052 OD-7) |
| M3.5 · Vertical slice | ⏳ planned, after M6 | — | One tool end to end — CLI → runtime → kernel → sandbox — with published latency, cold-start and approval-count measurements; before M7, because its results can still change what follows |
| M7–M18 · to V1.0 | ⏳ planned | — | Model providers and egress (M7); storage and run state, the agent loop, tools, skills, context, artifacts, memory, subagents, the task graph and MCP (M8–M16); the CLI (M17); V1 hardening (M18) |
| Post-V1 | ⏳ planned | — | Channels, a scheduler, a browser, plugins, a web UI and remote workers; interoperability with external coding agents, ACP first (M29, [ADR-0051](docs/adr/0051-external-agent-interoperability.md), Proposed) |

**What that means in practice.** A client can connect to `dwkd-authority`, be admitted
to a run, and ask the authority to read, list, search, stat, write, patch, move or delete
files beneath an operator-bound workspace, each decided by both gates and audited. The
shipped policy packs deny every read until a home anchor exists, so a deployment reads
files with an operator policy. **No production build launches a process on the host** — a
host launch needs a per-invocation approval, and approvals are M6's — but when the
operator attaches an execution environment (`serve --sandbox-config`, Linux), the public
`process.exec` runs there: the authority decides each workload, the broker runs exactly
its plan as the environment's own uid in a measured `oci-strict` container, and nothing
falls back to the host. Only `process.exec` runs in an environment: the filesystem tools
act on the workspace through the broker on the host, and policy is told which. A
`PROXY_ONLY` workload reaches only its granted origins through the broker's proxy, and
`net.http`, the kernel's own HTTPS request, is the kernel's one network tool. A credential
(secret mode A) reaches only `net.http`'s bound origin; modes B and C reach a sandboxed
`process.exec` through the pinned launcher, and every descendant of that process inherits
the value. `npm ci`, `npm install` and `pip install` run only under their accepted
profiles ([ADR-0054](docs/adr/0054-m5e-npm-hygiene-profile.md),
[ADR-0055](docs/adr/0055-m5e-pip-hygiene-profile.md)).

**What does not exist yet**, and which milestone owns it:

- **host-local execution** (M6, ADR-0052 OD-7), and package managers beyond npm and
  pip: npx, pnpm, yarn, bun and cargo stay refused;
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

**Limits, stated.** A container is not a VM: `oci-strict` shares the host kernel, and
every environment runs as one host uid (10001). A lease that only expires ends nothing
until its session is acquired again or the authority restarts, and a destruction a
lease's end leaves pending holds brokered writes in its workspace (`SHARED_DIRECTORY`). A
sandboxed credential reaches every descendant of its process. A `.pth` file an installed
wheel carries runs at a later interpreter's start — contained by the environment, not
neutralised. [docs/SECURITY.md](docs/SECURITY.md) §5 lists every known limitation.

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
`sandbox-workspace-evidence`, `sandbox-agent-evidence`, `sandbox-release-evidence`,
`sandbox-restart-evidence`, `sandbox-capacity-evidence`,
`sandbox-proxy-weakened-evidence`, `sandbox-registry-evidence` and
`sandbox-hygiene-evidence` (the last five hosted only) and `d11-hardening-evidence`, most
with a `…-mutations` review beside it. The gated evaluations are `authority-security`,
`m4-security`, `m5a-sandbox-foundation`, `m5b-sandbox-egress`, `m5c-net-http` and
`m5d-sandbox-exec`, the M5 ones on a real OCI runtime. The M5 gate,
`make m5e-gate-check`, judges every M5 evidence task's sealed output again in the
required `m5e-gate` job, whose `m5e-gate` evaluation fails unless the gate's acceptance
verdict is READY. Every sandbox evidence line names its level (`real-oci`, `in-process`,
…) and the mechanism that enforced it, and a task refuses one that does not
([docs/SANDBOX.md](docs/SANDBOX.md) §6a). `make check` runs the core gates, not these
campaigns: most need Linux, the sandbox ones a container runtime, and some root or
separate users, so hosted CI runs every one but `capability-evidence` and
`authority-state-evidence` in a job of its own. The halves that need separate
operating-system identities, root or a dedicated filesystem run in hosted CI with three
genuine users; on a one-user workstation they report NOT EXERCISED, which fails rather
than passes. Where the architecture stands against comparable projects, including where
it is behind, is in [docs/COMPETITIVE_ANALYSIS.md](docs/COMPETITIVE_ANALYSIS.md).

DireWolf's own Rust contains no `unsafe`. The authority links third-party crates — among
them SQLite's C amalgamation — and the broker links a few on Linux; the reviewed sets and
their reasons are in the ADRs, and the licence obligations in [NOTICE](NOTICE).

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
| I1 | No side effect occurs without a kernel-verified capability token | Kernel; runtime has no other path | IMPLEMENTED for every effect that exists (M4, M5); the runtime that must have no other path is M9 |
| I2 | `child_capabilities ⊑ parent_capabilities` — delegation only attenuates | Capability Broker lattice check | IMPLEMENTED (M3b); subagents M14 |
| I3 | The Cognition Plane never receives plaintext long-lived credentials | Secret Broker | IMPLEMENTED for secret handles (M4e); model keys M7 |
| I4 | Every authority decision is explainable: rule id, file, line | Policy Engine | IMPLEMENTED (M3c) |
| I5 | Untrusted provenance cannot be laundered into durable memory without a human | Kernel-held provenance + promotion gate; **backstopped by I9** | PLANNED (M13) |
| I6 | Approvals bind to canonical actions and are single-use by default | Approval Registry | PLANNED (M6); until then an approval-requiring action is denied |
| I7 | Default-deny network, default-deny filesystem, default-deny execution | Kernel defaults | IMPLEMENTED for filesystem and execution (M4) and for the two network paths that exist: a `PROXY_ONLY` environment reaches only its run's granted HTTPS origins (M5b), and `net.http` only a granted host (M5c) |
| I8 | Budgets are reservations debited from a parent, never per-agent grants | Budget Ledger | PLANNED (M6) |
| I9 | Memory and context can never alter authority — they are not terms in any capability or policy expression | Structural: the mint formula and rule files do not read them | IMPLEMENTED structurally (M3); memory itself M13 |
| I10 | Every policy input is derived and stored kernel-side | Kernel; `runtime.db` copies are caches | IMPLEMENTED (M3d) |

## Documentation

### Read in this order

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
[M5E2_FINAL_CLOSURE_REVIEW](docs/M5E2_FINAL_CLOSURE_REVIEW.md) — M5e.2's closure assessment of 2026-11-03.

**Checkpoint handoffs** — each a checkpoint's plan, kept as it was written, its last status line current:
[M5D5_IMPLEMENTATION_HANDOFF](docs/M5D5_IMPLEMENTATION_HANDOFF.md) ·
[M5E4_IMPLEMENTATION_HANDOFF](docs/M5E4_IMPLEMENTATION_HANDOFF.md) ·
[M5E5_PREPARATION_HANDOFF](docs/M5E5_PREPARATION_HANDOFF.md) ·
[M5E5_IMPLEMENTATION_HANDOFF](docs/M5E5_IMPLEMENTATION_HANDOFF.md) ·
[M5E6_PREPARATION_HANDOFF](docs/M5E6_PREPARATION_HANDOFF.md)

**Decisions**: [docs/adr/](docs/adr/) — 61 architecture decision records (0000–0060): 55 accepted, four superseded and kept as history (0001, 0002, 0007, 0057), and two Proposed (0051, 0060). Start with [ADR-0000](docs/adr/0000-authority-plane-separation.md), then [ADR-0018](docs/adr/0018-authority-broker-split.md); everything else is downstream. The [index](docs/adr/README.md) says which are current.

---

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
