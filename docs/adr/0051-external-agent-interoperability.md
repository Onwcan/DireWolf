# ADR-0051: External coding agents are contained workloads or clients of DireWolf, never authorities: interoperability is standards-first (ACP, MCP), and enforcement is claimed only where DireWolf contains the agent

**Status:** Proposed · **Date:** 2026-10-10 · **Would amend (on acceptance):** none — it plans post-V1 work (M29) and adds prerequisites to M5d, M6, M16 and M17 · **Refines:** [ADR-0029](0029-packaging-runtime-first-decoupled-authority.md) (its "Revisit if" — an external project delegating to the authority — is raised here as an explicit owner decision point, not decided), [ADR-0020](0020-provider-request-path-v2.md) (external agents are not model providers), [ADR-0024](0024-sandbox-network-topology.md) and [ADR-0048](0048-m5b-proxy-only-topology-and-connect-proxy.md) (a hosted agent's network is a `PROXY_ONLY` environment's)

## Context

The project owner asked (2026-10-10) whether DireWolf can interoperate with thirteen
external agent products: Claude Code, OpenClaw, Hermes Agent, Factory's Droid, Cline, Oh
My Pi, Qwen Code, OpenAI's Codex CLI, OpenCode, Hermes Desktop, Pi, GitHub Copilot CLI and
DeepSeek Harness. [COMPETITIVE_ANALYSIS.md](../COMPETITIVE_ANALYSIS.md) §7b records what
each one exposes, read at pinned revisions and in each project's own documentation. In
short:

- **These are not model providers.** Each is an agent runtime, coding harness, CLI, IDE
  integration or desktop frontend with its own tools, its own approvals and, usually, its
  own model egress and credentials. M7's provider inventory is untouched by this ADR.
- **One standard dominates the machine interfaces.** Eight of them serve the [Agent Client
  Protocol](https://agentclientprotocol.com) as the *agent* over stdio (OpenClaw's bridge,
  Hermes Agent, Cline, Oh My Pi, Qwen Code, OpenCode, Copilot CLI in public preview, DeepSeek
  Harness); every one but Hermes Desktop has a headless mode with a JSON or JSONL event
  stream; twelve are MCP clients; two serve MCP (OpenClaw, Hermes Agent). Claude Code, Codex
  CLI, Droid and Pi expose only vendor-specific programmatic surfaces at the revisions read.
- **Their native tools are theirs.** Every one can run a shell, edit files and reach the
  network itself. One approves actions with a model classifier by default and others offer
  such a mode, one auto-approves every tool in headless mode by default, one ships no
  permission system at all, and one runs its shell in-process with no `fork`/`exec`. Their approvals, sandboxes and
  "yolo" switches are their own and prove nothing to DireWolf.

Four directions of interoperability have to be kept apart, because they have opposite
security properties:

| Direction | Who is in control | What DireWolf's authority sees |
|---|---|---|
| **A** — DireWolf invokes an external agent | DireWolf launches it as a bounded task | The environment it runs in: its filesystem view, its egress, its credentials, its lifetime — not each of its tool calls |
| **B** — an external agent uses DireWolf as its enforcement boundary | The external agent decides; DireWolf performs | Only the operations the agent chooses to route through DireWolf |
| **C** — an editor or application drives DireWolf's own agent | The operator, through a client UI | Everything: the agent is DireWolf's runtime, every effect goes through the authority |
| **D** — shared tooling and configuration | Nobody new | Configuration to be judged, never authority |

## Decision

### 1. External agents are workloads or clients, never authorities

No external agent, adapter or bridge holds a capability, decides a policy, answers an
approval, chooses a privacy class or enters the authority's trusted computing base. An
external agent's output is untrusted content: it taints the run that receives it and is
never read as an instruction to the authority (the provenance and taint rules of
[THREAT_MODEL.md](../THREAT_MODEL.md)). An external agent's statement that
something was approved, allowed or safe is a string, never an approval (M6).

### 2. Direction A: a contained workload, ACP first

DireWolf invokes an external agent only as a **workload in an M5 execution environment**:
an `oci-strict` container with `PROXY_ONLY` networking, the run's workspace mounted as M5d
decides, the agent's declared model origins the only `network.https` grants, its credential
injected by mode B or C (ADR-0046) and never held by the runtime, a wall clock, a byte
budget and cancellation. Its native shell, file and network tools then act **inside** the
environment: they are *contained*, not mediated one by one, and DireWolf says so — the
audit records an environment-level effect, not the agent's individual calls.

The adapter is **one ACP client**, reviewed once, for every agent that serves ACP; a
vendor adapter (a headless JSON stream, an RPC protocol) is added only where demand is shown
and the agent offers no ACP, each one reviewed and backed by recorded contract fixtures.
The agent's ACP permission requests are answered by DireWolf's policy and approval registry
— never by an auto-allow — and an answer DireWolf gives is enforced, because the environment
is the boundary, whatever the agent then does.

### 3. Direction B: enforcement is claimed only where DireWolf contains the agent

A bridge through which an external agent asks DireWolf to perform an operation — an MCP
server exposing authority-mediated tools — is **enforcement only when the agent runs in a
DireWolf environment** with its native shell, file and network tools disabled or confined
there. Outside one, the agent keeps its own unrestricted tools; the bridge then mediates
only what the agent volunteers, and it is **advisory**: refused by default, available only
as an operator's explicit choice, labelled advisory in every audit record and in `doctor`,
and never described as compatible-and-secure.

### 4. Direction C: DireWolf serves ACP as the agent

An editor that speaks ACP drives DireWolf's own runtime through `direwolf acp`: every effect
still goes through the authority. The editor is a client UI for M6's approval registry,
never its authority — an answer from the editor counts only as the operator's answer to the
prompt the kernel rendered, bound to that prompt's binding hash.

### 5. Direction D: configuration is not authority

An MCP server definition, an instruction file (`AGENTS.md`, `CLAUDE.md` and the like), a
skill or a tool manifest written for another agent is read as an **untrusted proposal**: an
MCP server still needs its own per-server grant (M16), an instruction file is untrusted
project context (M11), and a skill passes M11a's manifest, hash and trust checks. No
session interchange is promised without a verified schema.

### 6. The security floor for every direction

- **Native tools**: contained by the environment (A), advisory (B outside an environment),
  or absent (C).
- **Approvals**: DireWolf's alone; an external agent's auto-approve, yolo or classifier
  mode is irrelevant to them.
- **Credentials**: never imported into the runtime's memory, never stored by a shim in
  plaintext; held as secret handles and injected into the environment only. A consumer
  subscription login is not proxied or redistributed; an API key is preferred.
- **Privacy**: an agent's model origins are declared and are its environment's only
  egress; a `LOCAL_ONLY` run never starts an agent whose declared origins are remote, and a
  declaration that does not match its traffic is refused at the proxy.
- **Trust**: provenance, taint, attenuation, budgets, workspace isolation, audit, crash
  reconciliation, approval binding and idempotency hold as for any workload; an external
  agent's output that flows back into a DireWolf run is untrusted input.
- **No second route**: nothing in this ADR gives any process a path to an effect that does
  not pass the authority or an environment the authority prepared.

### 7. Where the work lives

Not in M7, and not in V1: a new post-V1 milestone, **M29 · Agent interoperability**
([ROADMAP.md](../ROADMAP.md)), in three steps — **M29a** DireWolf as an ACP agent (C);
**M29b** the ACP client and external agents as contained workloads (A); **M29c** the MCP
server for agents in DireWolf environments (B). V1 gains prerequisites only, no
integration: M5d keeps any workload from running as the broker's uid and covers an
agent-shaped workload in its escape suite; M6 refuses an external agent's approval claim;
M16 stays a client and treats imported server definitions as proposals; M17's headless
contract is stable enough to be M29a's base.

### 8. The ADR-0029 decision point (not decided here)

Direction B outside a DireWolf environment would make DireWolf's authority a boundary that
*other* runtimes delegate to — ADR-0029's revisit trigger. This ADR does **not** reverse
ADR-0029: DireWolf remains a complete runtime and the authority plane is not shipped as a
separate product. It asks the owner one question, **DP-1**: *should the authority's
primitives be offered to external runtimes outside DireWolf environments, as a product?*
The recommendation is **not before M29b's evidence**, and then only by a new ADR that
amends ADR-0029.

## Consequences

**Positive.** Broad reach through one standard: one reviewed ACP client covers eight of the
thirteen, and DireWolf's own ACP server makes it usable from any ACP editor. Claims stay
honest: contained, mediated and advisory are different words in the audit and in the
documentation. The kernel boundary is untouched, and M7's provider architecture is kept
separate.

**Negative.** No interoperability before V1. A contained external agent's individual tool
calls are invisible to the authority: only its environment is enforced. Four products have
no standard interface and wait for demand or for ACP. Hosting third-party agent binaries in
environments widens M5d's escape suite and adds supply-chain review of each agent's release.
Agents that need a consumer subscription login may be usable only with an API key.

## Alternatives considered

- **Thirteen vendor adapters now.** Brittle, unreviewed surface that changes weekly (two of
  the thirteen are in preview, one is a developer preview); rejected for a standard first.
- **External agents as model providers in M7.** They are not models; it would route agent
  traffic, with its own tools and credentials, through the model-egress path.
- **An advisory MCP bridge for agents on the host, called enforcement.** The agent keeps its
  own shell; the claim would be false.
- **Ship the authority plane as a standalone product now.** ADR-0029's alternative, still
  premature: DP-1.

## Revisit if

Claude Code, Codex CLI, Droid or Pi ships an upstream ACP agent; ACP's specification makes
a breaking change; an external agent's own sandbox becomes measurable by DireWolf's probe;
the owner answers DP-1.
