# DireWolf

> **Intelligence may propose. Policy grants authority. Execution remains controlled.**

DireWolf is a model-agnostic, local-first, security-first autonomous agent runtime.

It is built on one structural claim that most agent frameworks do not make:

**The component that reasons is not the component that is trusted.**

In DireWolf, the process that runs the agent loop — the process that ingests model
output, web pages, tool results, MCP responses and memory — holds **no credentials, no
network route, no filesystem handles and no ability to execute anything.** Every side
effect is requested from a separate, privileged, minimal-dependency process (the
*kernel*) which independently canonicalises the request, evaluates deterministic policy,
verifies a capability token, optionally demands human approval, injects credentials the
requester never sees, performs the effect inside a sandbox, and writes a hash-chained
audit record.

A fully compromised model — or a fully compromised agent runtime — does not imply a
compromised host.

---

## Status: M2.5 — protocol, schemas and the evaluation harness

**None of the above is implemented yet.** This repository contains the Phase 0
architecture package, the M1 foundation (the monorepo layout, the Rust and
Python workspaces, the quality gates, the architecture boundary checks and CI)
and the M2 wire contract:

- `crates/dwk-proto` — bounded framing, a strict JSON reader (UTF-8, depth 32,
  lexical duplicate-key rejection, an integer-only DWKP number domain, and no
  dependence on any Unicode database), RFC 8785 canonical JSON, the envelope, version
  negotiation, and the DWKP/DWCP/event message types;
- JSON Schema generated from those types into [`schemas/`](schemas/), and
  Python bindings generated from the schemas, with CI failing on drift;
- shared golden vectors run by both languages, and fuzz targets;
- `evals/` — the evaluation harness (M2.5): deterministic suites, structured
  results, a reviewed baseline, hostile-protocol suites over the real decoder,
  replayable fixtures with no model call anywhere, and a fault-injection
  harness. Properties that need the kernel are **pending**, which is counted
  apart from passing.

What M2 establishes is that **malformed DWKP is rejected structurally**, and
what M2.5 adds is the machinery to *measure* claims like that. Neither
establishes that any request is authorised: there is no kernel, no transport,
no policy and no capability check yet. See [docs/PROTOCOL.md](docs/PROTOCOL.md),
[ADR-0032](docs/adr/0032-wire-contract-framing-strict-json-and-jcs.md) and
[evals/README.md](evals/README.md).

The daemons build and refuse to run. `direwolf` supports `--version` and
`doctor`, and nothing else, because a command that exists but cannot work
invites callers, scripts and documentation to form around a shape nobody has
designed yet.

The policy engine and capability broker arrive at **M3**, the filesystem, exec and secret brokers at **M4**, the sandbox
at **M5**. See
[docs/ROADMAP.md](docs/ROADMAP.md).

```bash
git clone <url> direwolf && cd direwolf
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

**Decisions**: [docs/adr/](docs/adr/) — 35 architecture decision records, three of them superseded and kept as history. Start with [ADR-0000](docs/adr/0000-authority-plane-separation.md), then [ADR-0018](docs/adr/0018-authority-broker-split.md); everything else is downstream. The [index](docs/adr/README.md) says which are current.

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

Three properties fall out of putting credentials below the line rather than above it:

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

| # | Invariant | Enforced by |
|---|-----------|-------------|
| I1 | No side effect occurs without a kernel-verified capability token | Kernel; runtime has no other path |
| I2 | `child_capabilities ⊑ parent_capabilities` — delegation only attenuates | Capability Broker lattice check |
| I3 | The Cognition Plane never receives plaintext long-lived credentials | Secret Broker |
| I4 | Every authority decision is explainable: rule id, file, line | Policy Engine |
| I5 | Untrusted provenance cannot be laundered into durable memory without a human | Kernel-held provenance + promotion gate; **backstopped by I9** |
| I6 | Approvals bind to canonical actions and are single-use by default | Approval Registry |
| I7 | Default-deny network, default-deny filesystem, default-deny execution | Kernel defaults |
| I8 | Budgets are reservations debited from a parent, never per-agent grants | Budget Ledger |
| I9 | Memory and context can never alter authority — they are not terms in any capability or policy expression | Structural: the mint formula and rule files do not read them |
| I10 | Every policy input is derived and stored kernel-side | Kernel; `runtime.db` copies are caches |

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
