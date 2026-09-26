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

## Status: M3 complete; M4a, M4b and M4c complete; M4d — process execution, candidate; M4 incomplete

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
- the M3 authority **wire forms** (M3a): `AdmitRun`, `ReleaseRun` and
  `QueryAuthority`, with capabilities, grants, policy revisions and decisions as
  typed, bounded message fields. `ToolInvoke` — the operation that carries every
  effect — stayed reserved until the milestone that built the first tool
  ([ADR-0036](docs/adr/0036-m3-authority-operations-and-the-capability-wire-form.md));
  M4b gives it its first wire form (below).
- the **capability core** (M3b): the typed verb, scope and constraint
  vocabulary, the `⊑` lattice, set containment with no authority synthesis, and
  attenuation with no widening path — 10⁶ delegation chains, zero escalations.
  A capability that parses is an interpreted *request*; nothing mints, and
  `fs`/`process` scopes cannot become authority until M4 can resolve them —
  their identities can only be *created* by the module that will hold M4's
  canonicaliser
  ([ADR-0037](docs/adr/0037-capability-specifications-and-canonical-authority-identities.md)).
  It adds no dependency and no native code, and it does add security-critical
  code to the trusted computing base, which is where the authority's code lives.
- the **policy engine** (M3c): the deterministic decision function. A strict
  bounded TOML loader where an unknown member is an error rather than an absent
  predicate and nothing is ever coerced; a closed typed predicate vocabulary
  with no map, no regex and no DSL; ordered first-match evaluation with a
  mandatory denying default, followed by a second phase of postconditions that
  can only *narrow* the result; `safe`, `balanced` and `power` as real files
  under [`policy/`](policy/), each with fixture suites that check both the
  denial and the legitimate neighbour it must not deny; `extends` restricted to
  a composition that cannot widen, proved rather than sampled; and the M3
  performance target measured at a p99 of **3.6 µs against 200 µs** at 300
  rules ([ADR-0038](docs/adr/0038-policy-evaluation-phases-and-composition.md),
  `make policy-benchmark`).

  Two things it deliberately does not do. `would_require_approval` is **not** a
  field any caller can set — it is the evaluator's own provisional result, and
  a runtime that could state it would have turned off every unattended denial.
  And policy answers only *"should this be allowed?"*; whether the run holds
  the capability is the other gate, and neither substitutes for the other
  ([ADR-0006](docs/adr/0006-policy-and-capability-boundary.md)).

  This is the milestone where the authority's third-party dependency closure
  stops being empty: **five crates**, the TOML parser chain, pinned exactly,
  with no derive macro, no proc-macro and no native code. Three of them parse
  the policy text, so the loader is fuzzed — coverage-guided in
  [`fuzz/`](fuzz/) and on stable in every `cargo test`.
- **durable authority state** (M3d): `kernel.db`, in a private directory of
  its own, behind the operations M3a defined. Epochs are issued, fenced and
  never reused across restarts; a lease belongs to one connection, not to
  every process with the same uid; `AdmitRun` checks the fence before its
  idempotency key and records every admission forever, so a key never admits
  a second run — a retry while the run is live gets the recorded grant, and a
  retry after its lease has ended (a restart included) is told the admission
  has ended, never handed dead authority; every policy input the kernel
  decides on is a kernel row, and no DWKP message can carry one; the policy
  revision is the hash of the stored policy text; and every
  authority-changing operation writes a hash-chained `audit.log` record that
  is `fsync`ed **before** the answer is returned, with a recovery rule for
  every crash window between the two files
  ([ADR-0039](docs/adr/0039-durable-authority-state.md),
  [ADR-0040](docs/adr/0040-m3d-reconciliation-admission-across-tenures-and-undecidable-proposals.md),
  `make authority-state-evidence`).

  `QueryAuthority` reports a run's effective authority. It does **not** yet
  decide a proposed action: capability text alone does not say where an
  action runs, what it reaches or which file it names, and deciding without
  those facts would be deciding on facts the kernel invented. Until M4's
  canonicaliser can supply them, a proposal is refused with
  `NO_CANONICAL_ACTION`, and no policy rule is named for an evaluation that
  did not happen.

  It links **SQLite** — 269,376 lines of C compiled into the authority — and
  SHA-256, fifteen new crates in all. DireWolf's own Rust still contains no
  `unsafe`; the authority as a whole now contains native code, and the
  closure gate reports it as such.
- the **authority process boundary** (M3e): `dwkd-authority serve` is a real
  DWKP server on a **Unix-domain socket** (no TCP, no HTTP, no fallback). Before
  it reads a single byte of a connection, the **kernel** reports the peer's uid
  (`SO_PEERCRED`) and the operator's explicit uid list admits it — or the
  connection is closed unanswered and audited. Each accepted connection gets
  **one fresh lease holder**, so two connections from one uid are one subject
  and two writers-in-waiting, and a reconnect inherits nothing. The handshake
  must come first; every frame goes through the same strict decoder the
  protocol tests fuzz; every request goes to the M3d state machine unchanged.
  The socket's name is protected too: the runtime cannot remove or replace it
  to impersonate the authority. A hostile client suite, a real second OS user
  and a killed-and-restarted authority are run against the **real binary**,
  and they are the M3 merge gate
  ([ADR-0041](docs/adr/0041-m3e-authenticated-dwkp-transport.md), `make authority-transport-evidence`).
  **Linux only**: on macOS and native Windows `serve` refuses to start rather
  than guess who is on the other end. It adds `rustix` (and, on Linux,
  `linux-raw-sys`) for the one syscall the standard library does not expose;
  DireWolf's Rust still contains no `unsafe`.
- **canonical filesystem resolution** (M4a, the first part of M4): what a
  declared path *means*. An operator binds a workspace to a directory once;
  the authority records the directory's identity and refuses to resolve
  through its path if another directory is ever put there. `/workspace/...`
  resolves one component at a time with `openat2` relative to the previous
  descriptor — no symlink, magic link or mount point is ever crossed, `..`
  cannot escape, a name must be spelled exactly as on disk and in NFC, and
  a canonically equivalent twin makes both unnameable — and the result keeps
  the checked descriptor for the broker that will later act on it. Six race
  campaigns swap names while it resolves and must return zero escaped
  objects ([ADR-0042](docs/adr/0042-m4a-canonical-filesystem-resolution.md),
  `make filesystem-canonicalization-evidence`). **Linux only**, and it
  performs no tool effect.
- **the filesystem tools** (M4c, the third part of M4): `fs.list`, `fs.search`,
  `fs.stat`, `fs.write`, `fs.patch`, `fs.move` and `fs.delete`, as version 2 of
  the tool messages. Each call is a plan of canonical actions — a creating
  write needs `fs.write` and `fs.create`, a move `fs.delete` and `fs.create` —
  and every action must pass both gates. The broker changes one checked name
  atomically, never in place, checking it immediately before and after the
  change and undoing a change that reached anything else; an effect or an
  undo nothing proves is recorded `UNKNOWN` and never repeated. A workspace is
  writable only where the operator grants the broker's own user directory
  write permission, which is ambient authority and stated as such — and,
  since Linux cannot compare a name against an inode atomically, the grant
  must also keep untrusted writers out
  ([ADR-0044](docs/adr/0044-m4c-filesystem-operations-plans-and-atomic-mutation.md),
  `make filesystem-operations-evidence`). **Linux only.**
- **process execution, behind a floor nothing can yet pass** (M4d, the fourth
  part of M4; implemented, a candidate for acceptance): `process.exec`,
  `process.status` and `process.kill`, as version 3 of the tool messages. The
  authority resolves an absolute executable path — no `PATH` search, symlinks
  followed to one native file that only root or the authority can change —
  hashes it, and decides on that identity, with `argv[0]` its canonical path
  and every argument passed as exactly its bytes; the broker re-proves the
  descriptor the authority opened and executes **that descriptor**
  (`execveat`), through a helper with an empty environment, resource limits,
  its own process group and no inherited descriptor, drains both streams to a
  bound, and kills by pidfd and process group. **Every process would run on
  the host with the broker's privileges, so a launch needs the operator's
  opt-in and a per-invocation approval — and approvals are M6's: no build a
  user runs launches anything.** The launch path is proven by the real
  broker starting real targets, and the authority's side after the floor
  against a fake broker, labelled as such
  ([ADR-0045](docs/adr/0045-m4d-process-execution-broker.md),
  `make process-broker-evidence`). **Linux only.**
- **one brokered effect: `fs.read`** (M4b, the second part of M4).
  `ToolInvoke` and `CanonicalPreview` have their first wire forms — one typed
  call, `fs_read{path, max_bytes}`, and no tool name or argument map a second
  tool could hide in. The authority fences the request, canonicalises the path,
  derives the capability the read requires, builds the complete canonical
  action — where it runs and how many bytes it may move — and applies both
  gates; only an allowed read is resolved, opened read-only relative to its
  checked directory and proved to be the checked object, and its intent is
  recorded durably before anything else happens. Then `dwkd-broker` — its own
  process, its own user, one private Unix-domain socket that reads only from
  the authority's kernel-reported uid — receives that one descriptor by
  `SCM_RIGHTS` with a single-use authorisation bound to a channel it issued for
  that connection (no MAC, no key, no token), re-proves the descriptor, and
  reads at most the authorised bound. The authority records the outcome and
  raises the run's taint before it answers. The runtime cannot reach the
  broker, and the broker cannot reach the authority's state
  ([ADR-0043](docs/adr/0043-m4b-private-broker-channel-and-brokered-fs-read.md),
  `make broker-fs-read-evidence`, which runs with three real users in CI).
  **Linux only**, and the shipped policy packs deny every read until a home
  anchor exists; a deployment reads files with an operator policy.

What M2 establishes is that **malformed DWKP is rejected structurally**, and
what M2.5 adds is the machinery to *measure* claims like that. M3a adds the
shapes of the messages an authority will exchange, and the architecture
decisions behind them
([ADR-0035](docs/adr/0035-m3-authority-dependency-set.md),
[ADR-0036](docs/adr/0036-m3-authority-operations-and-the-capability-wire-form.md)).
**None of them establishes that any request is authorised.** M3b and M3c add
the two gates' *logic* — the lattice that answers "is this within the authority
held?" and the engine that answers "should this be allowed?" — M3d the state
they decide against, and M3e the process boundary in front of it: a runtime
can now reach the authority, and cannot choose who it is when it does. M4a
adds the first thing that looks at a filesystem — deciding which object a path
names — and M4b the first effect: reading at most 256 KiB of one checked file,
through the broker, for a run both gates allow — and M4c the other
filesystem tools, including the first that change files. M4d builds process
execution end to end and refuses every production launch, because no approval
can exist yet. There is still no secret, no sandbox (every action runs on the
host, and policy is told so), no approvals, no artifacts and no model provider
(and so no Ollama). `QueryAuthority` still reports authority and
refuses to decide a proposed action; `CanonicalPreview` is how a runtime asks
what a read would be decided.
See [docs/PROTOCOL.md](docs/PROTOCOL.md),
[ADR-0032](docs/adr/0032-wire-contract-framing-strict-json-and-jcs.md) and
[evals/README.md](evals/README.md).

`dwkd-authority serve` serves DWKP (Linux); `dwkd-authority verify-audit
<dir>` checks an audit chain, read-only, everywhere; `dwkd-broker serve`
serves the private channel (Linux) and performs the filesystem operations and
— for an authorisation no production authority can yet issue — the process
operations;
`direwolf` supports `--version` and `doctor`, and nothing
else, because a command that exists but cannot work invites callers, scripts
and documentation to form around a shape nobody has designed yet.

Secrets (M4e) complete **M4**, the sandbox at
**M5**, approvals at **M6**, and model providers — Ollama among them — at
**M7**. See [docs/ROADMAP.md](docs/ROADMAP.md).

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

**Decisions**: [docs/adr/](docs/adr/) — 44 architecture decision records (0000–0043), three of them superseded and kept as history. Start with [ADR-0000](docs/adr/0000-authority-plane-separation.md), then [ADR-0018](docs/adr/0018-authority-broker-split.md); everything else is downstream. The [index](docs/adr/README.md) says which are current.

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
