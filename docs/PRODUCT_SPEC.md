# Product Specification

---

## 1. What DireWolf is

A local-first, model-agnostic autonomous agent runtime whose defining property is that **the agent's authority is enforced by a separate privileged process the agent cannot reach.**

The one-line pitch: *an agent you can give real access to, because you can see and bound exactly what it has.*

## 2. Who it is for

**Primary for V1 — the developer who wants a *supervised* agent with a real audit trail on a machine that matters.** Source code under NDA, production credentials, customer data on disk. They are currently unwilling to give an agent host access because existing options ask them to trust a language model's judgement with it. They will accept friction for auditability, and they are present while it works.

**Primary from V1.1 — the same developer, for unattended work.** Long-running autonomous tasks on that same machine.

> The V1/V1.1 distinction is deliberate and was a review finding. An earlier draft named "long-running autonomous work" as the *V1* primary use case while deferring the scheduler, channels and remote approval out of V1 — so the defining requirement of the named user was precisely what V1 could not do. V1 ships **detached runs** (below) as the minimum unattended capability that exercises the policy path; recurring schedules and remote approval follow at V1.1.

**Secondary — the security-conscious operator.** Needs to answer "what did it do and who allowed it?" and to hand that answer to somebody else.

**Secondary — the local-first user.** Air-gapped or privacy-constrained; runs local models; unwilling to send content to a vendor.

**Explicitly not the target — the user who wants maximum capability today with minimum friction.** That user is well served by existing projects with broad channel and plugin ecosystems, and [COMPETITIVE_ANALYSIS.md](COMPETITIVE_ANALYSIS.md) §6 says so plainly. Building for them would mean permissive defaults, which is the thing we are specifically not doing.

## 2a. What DireWolf ships as

**DireWolf is a complete autonomous agent runtime.** The first-party runtime is the flagship and the reference consumer of the authority plane. Phase 1 does not pivot to a standalone security-daemon product.

Phase 0 review raised the alternative sharply: the genuinely novel artifact is the authority plane, while the cognitive runtime scores "B (planned)" against two mature competitors with ~630 k combined stars — both of which state in their own documentation that only the OS is a real boundary, and neither of which has built one. Shipping `dwkd` standalone would turn competitors into distribution.

We are not doing that, for two reasons: a security daemon with no first-party consumer has no forcing function for correctness, and there is currently zero evidence of external demand. But we are **keeping the option open at low cost** ([ADR-0029](adr/0029-packaging-runtime-first-decoupled-authority.md)) via three testable constraints:

1. DWKP operations are layered into **authority primitives** (nothing presuming DireWolf's loop, context engine or orchestration model) and **runtime-shaped conveniences** (`ListVisibleTools`, `SpawnSubagent`, `McpOpen`, `ChannelSend`).
2. No authority primitive may depend on a runtime-shaped concept. `SpawnSubagent` must remain expressible as `AdmitRun` plus attenuation; if it ever is not, the primitive layer has leaked.
3. `kernel.db` stores principals, agents, runs, capabilities, approvals, budgets, policy inputs and audit — **not** turns, messages, context manifests or task graphs.

If the authority plane later proves more valuable than the runtime, extraction becomes a packaging change rather than a rewrite.

## 3. The problem

Current agent runtimes put the authorization decision inside the process that consumes untrusted input. Tool allowlists, output scanners, approval prompts judged by an auxiliary model — all live in the same address space as the component being manipulated. They stop mistakes. They do not stop adversaries.

The empirical record supports this: the dominant failure class in deployed agent runtimes is not memory corruption but **authorization boundaries that drift in scope or lifetime** — approvals outliving their reviewed directory, a gate enforced on one code path and skipped on another, containment silently disabling approval checks, credentials injected into the wrong endpoint. These are distributed-enforcement bugs: the check exists at many call sites and one of them is wrong.

DireWolf's answer is **one enforcement point, on the other side of an OS boundary.**

## 4. User experience

```console
$ direwolf init
  Identity mode [1] separated (needs sudo once)  — see §6a
  Creating ~/.direwolf … user 'direwolf-runtime' … policy profile [balanced] …
  Docker 29.7.2 detected. Sandbox ready (PROXY_ONLY networking).

$ direwolf agent create coder --template coder --workspace ~/src/project-x
$ direwolf chat coder

> refactor the auth module to use the new token API, then run the tests

  coder  reading src/auth.py, src/tokens.py (2 files, 18 KB)
  coder  reading tests/test_auth.py
  coder  writing src/auth.py  (+42 −31)
  coder  running pytest tests/test_auth.py  … 14 passed, 1 failed
  coder  reading the failure, writing src/auth.py (+3 −1)
  coder  running pytest  … 15 passed

  Done. 2 files changed, 15 tests passing.
  6 model calls · 47k tokens · $0.31 · 2m14s · 0 approvals needed
```

Nothing was approved because nothing needed it: reads and writes inside the workspace and `pytest` from the allowlist are all within the `coder` template's ceiling. Friction appears exactly when authority is genuinely being extended:

```console
> also push this to the remote

  ┌─ DireWolf approval required ─────────────────────────────────┐
  │ Agent   coder  (run run_01J8…, interactive)                  │
  │ Action  EXECUTE /usr/bin/git push origin feature/token-api   │
  │         cwd /workspace/project-x  →  github.com (140.82.x.x) │
  │         credential  github-primary  (injected at egress)     │
  │ Rule    approve-novel-exec  (policy/balanced.toml:63)        │
  │ Grants  this exact command, once, expires in 10 minutes      │
  └──────────────────────────────────────────────────────────────┘
  [a]pprove once  [d]eny  [w]hy
```

And the authority is always inspectable:

```console
$ direwolf run authority run_01J8...
  fs.read:/workspace/project-x         from coder profile ∩ workspace
  fs.write:/workspace/project-x        from coder profile ∩ workspace
  process.exec:/usr/bin/{git,pytest,python3}   from balanced allowlist
  model.call:anthropic/*               from coder profile
  DENIED  network.*        no rule matched in profile 'balanced'
  DENIED  secret.use:*     not requested at admission
  Budget  $0.31 / $5.00 · 6/50 calls · 2m14s / 30m
```

## 5. V1 scope — frozen

### In

| Area | Scope |
|---|---|
| **Kernel (Rust)** | Policy engine, capability broker with ⊑ lattice, approval registry, budget ledger, secret broker, fs broker (fd-relative), exec broker, egress proxy, model egress with metering, OCI sandbox supervisor, hash-chained audit |
| **Runtime (Python)** | Agent loop + run state machine, wait sets, context engine + manifests + compaction, tool registry (18 core tools — [TOOL_SYSTEM.md](TOOL_SYSTEM.md) §3), subagents with attenuation, task DAG (sequence/fan-out/join), memory (episodic + semantic, FTS5), artifacts, event log |
| **Providers** | Anthropic; OpenAI-compatible (covers OpenRouter, Ollama, vLLM, LM Studio) |
| **Routing** | Rule-based, policy-constrained, cost/health aware |
| **Interface** | `direwolf` CLI — chat, run, agent, policy, grant, audit, memory, artifact, doctor, export |
| **Detached runs** | `direwolf run --detach` with a pending-approval queue (`direwolf approve --list`), local desktop notification, and unattended policy semantics. The minimum viable unattended path, without the channel surface. |
| **MCP** | Client, stdio, kernel-spawned and sandboxed, toolset-hash rug-pull detection |
| **Storage** | SQLite (two stores), migrations, backup, corruption quarantine |
| **Observability** | OTel traces/metrics, structured logs, `doctor` |
| **Evaluation** | Eval harness + the security eval suite as a merge gate |

### The V1 core tool set

**18 tools.** The canonical inventory with side-effect and retry classes is [TOOL_SYSTEM.md](TOOL_SYSTEM.md) §3 and is not restated here — an earlier draft carried a second copy that disagreed with it on both membership and count, which is exactly the failure a single source of truth prevents.

Filesystem 8 · process 3 · network 1 · memory 2 · orchestration 2 · artifacts 2.

### Out of V1 — deferred with extension points reserved

Gateway daemon and channels (Telegram, Discord, Slack) · Web UI · Browser automation · Plugins · Skill learning and any skill registry · Memory consolidation and embeddings/vector search · Scheduler and standing intents · Remote workers · Durable multi-day workflows · WhatsApp, voice, mobile, desktop apps · gVisor/Firecracker · Enterprise SSO, multi-tenancy, billing · Autonomous self-modification (permanent non-goal)

### Why these cuts

The brief's candidate V1 was roughly twice this. Each cut has a reason beyond "less work":

- **Gateway + Telegram → V1.1; `ChannelAdapter` → M20.** Channels need the gateway, cross-channel identity, remote approval and ingress idempotency — a large surface that does not test the core thesis. An earlier draft kept the `ChannelAdapter` interface in V1 and claimed the CLI implemented it, "so the abstraction is exercised by its own reference implementation." That was wrong twice: the CLI is a **Rust** binary and the interface is a **Python** type in an unbuilt package, and the capability set is Telegram-shaped (a TTY has no `edit_message`, `buttons` or `authenticates_users`). An interface whose only implementation is the degenerate case rots silently. V1 ships a CLI; the interface is designed at M20 against two real channels.
- **Browser → V1.2.** Largest single feature, highest dependency weight, and it needs the egress proxy and quarantine to be proven first.
- **Scheduler → V1.1.** Unattended runs are the highest-risk category. The policy machinery for them should be exercised interactively before anything runs while nobody is watching.
- **Memory consolidation → V2.** Retrieval quality must be measurable before we let a model rewrite the store.
- **Skill learning → V2.** The validation pipeline is most of the work, and shipping synthesis before validation is how agent-written content becomes a persistence mechanism.
- **Plugins → V2.** See [PLUGINS.md](PLUGINS.md) §1. If MCP proves sufficient, not shipping plugins is a success.
- **Vectors → optional V1.1.** FTS5 is a strong baseline; embeddings mean either a cloud call (breaking privacy class) or a heavy local dependency.

**The V1 test is not "is it impressive?" but "does the authority boundary hold, and can we prove it?"** Every cut feature is one we can add onto a proven boundary; none of them makes the boundary easier to get right.

## 6. Success criteria for V1

| # | Criterion | Measure |
|---|---|---|
| 1 | The boundary holds | 100 % of the security eval suite contained, each with an audit record |
| 2 | No second path | Static and dynamic verification that every side effect traverses the kernel |
| 3 | Delegation cannot escalate | 10⁶ generated chains, zero escalations |
| 4 | Authority is inspectable | `run authority` and `policy explain` answer correctly for every run in the eval corpus |
| 5 | Recoverable | Every crash-injection point resumes correctly or fails closed with a specific question |
| 6 | Usable | A real refactor-and-test task completes with ≤ 2 approvals under `balanced` |
| 7 | Honest overhead | Latency targets per §9, **measured and published at M3.5**. The previous formulation — "overhead vs unmediated < 10 %" — was unmeasurable, because there is no unmediated build by design, and it was flattering by construction: aggregate overhead is dominated by model latency, so it passes trivially while hiding the interactive read→edit→read loop where the cost is actually felt |
| 8 | Local-first | Full function air-gapped against a local model |

Criterion 6 is the one most likely to fail, and it is the one that decides whether anyone uses this. A secure runtime nobody can stand to use has not solved the problem.

## 6a. Install and privilege

The process model requires two OS identities, and creating one is a privileged operation on every platform. This is the *first* thing a new user does, so it gets specified rather than glossed.

```console
$ direwolf init
  DireWolf needs two identities so the agent cannot write the state that constrains it.

  [1] Separated (recommended)   creates user 'direwolf-runtime'; needs sudo once
  [2] Single-user (fallback)    same user, separated directory permissions
                                REDUCED ASSURANCE - a compromised runtime can write
                                kernel.db. doctor will report this every run.
```

Mode 2 is real and supported, because most people will run it and pretending otherwise produces a worse outcome than documenting it. In mode 2 the process boundary still exists (separate processes, separate memory, no credentials in the runtime) but the *filesystem* protection of `kernel.db` and `audit.log` does not. `direwolf doctor` reports `AssuranceLevel::ProcessIsolation` instead of full, permanently and visibly, and the security eval suite is run in both modes with results published separately.

Workspace access follows from this: the **kernel** reads and mounts the workspace; the runtime never opens workspace files at the OS level. In mode 1 that is enforced by uid; in mode 2 it is enforced only by the runtime having no filesystem code path, which is defence in depth rather than a boundary. Both facts are stated by `doctor`.

## 7. Configuration

Layered, with later layers only narrowing security-relevant settings:

```
defaults < system (/etc/direwolf) < user (~/.direwolf) < workspace (.direwolf/)
        < agent profile < runtime flags
```

**Security settings do not follow normal precedence.** `security.allow_host_execution`, policy profile selection and capability ceilings are **kernel-side only** and may not be set by workspace config, agent profile or CLI flags. Otherwise a repository could ship a `.direwolf/config.toml` that disables the sandbox — a config file in a cloned repository is untrusted content.

Secrets never appear in configuration; only handles. Configuration is schema-validated with `direwolf config validate`, and unknown keys are errors rather than silently ignored typos.

## 8. Product modes

`SAFE` / `BALANCED` (default) / `POWER` — capability ceilings plus policy rule packs, defined in [CAPABILITIES.md](CAPABILITIES.md) §6. A mode never changes only the prompt; a mode that merely tells the model to "be careful" is theatre.

## 9. Non-functional requirements

| | Target |
|---|---|
| Cold start (`direwolf chat`) | < 400 ms with a warm kernel daemon; **1–2 s cold** (Python imports dominate). Audit-chain verification at startup is incremental against a signed checkpoint — full verification is O(history) and is a `direwolf audit verify` operation, not a startup cost |
| Kernel decision latency | p99 < 5 ms for `PURE`/`READ` with a warm sandbox; **p99 15–40 ms for side-effecting calls**, which include two to three `synchronous=FULL` durable writes. On macOS, genuinely durable writes require `F_FULLFSYNC` (10–30 ms), so durability and a 5 ms p99 are mutually exclusive there — we choose durability and say so |
| Cancellation latency | `DRAINING` grace bounded at 30 s, displayed |
| Policy evaluation | p99 < 200 µs at 300 rules |
| Memory retrieval | p99 < 50 ms at 100 k items |
| Kernel RSS | < 50 MB idle |
| Runtime RSS | < 250 MB idle |
| Platforms | Linux (full), macOS (full via Docker VM), Windows (WSL2 recommended; native = reduced assurance, loudly stated) |
| Install | Single binary + a Python environment; one command |

## 10. Licence and governance

Apache-2.0 is the leading candidate (patent grant, permissive adoption, compatible with a security-tooling ecosystem). Decided at M1. Security-relevant changes require review by someone other than the author, and kernel interface changes require an ADR.
