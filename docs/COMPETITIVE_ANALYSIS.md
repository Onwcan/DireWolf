# Competitive Analysis: DireWolf and the agent-runtime landscape

**Research date:** 2026-09-28 (verification pass completed 2026-09-29).
**Replaces:** the 2026-09-11 analysis, which compared a specification against two projects.
**Method:** each project's own documentation, source files read one at a time at a pinned
commit, its licence file, and advisories in the GitHub advisory database. No repository was
cloned, forked, mirrored, vendored or downloaded as an archive. **No competitor code, test,
comment or configuration was copied into DireWolf**; every idea this document adopts is
reimplemented from described behaviour, under DireWolf's own design.

---

## 0. Read this first: the honesty contract

1. **DireWolf is implemented through M4, and no further.** The authority process, its
   durable state and audit chain, the filesystem, process and secret brokers, and the
   evaluations that gate them exist and pass in hosted CI. There is **no agent loop, no
   model provider, no sandbox, no approval flow, no network tool, no memory, no skills and
   no user-facing agent**. Every competitor below that runs agents is ahead on capability,
   by a wide margin.
2. **Implemented and planned are never mixed.** Every DireWolf cell in this document says
   either what exists now (with the milestone that delivered it) or what is planned (with
   the milestone that owns it). A planned control is a design argument, not a result.
3. **Every factual claim about another project is attributed** to a primary source: its
   repository at a pinned commit, its own documentation, or an advisory it published.
   Claims we could not verify there are labelled **UNVERIFIED** and excluded from every
   conclusion. **NOT FOUND** means "not found in the sources inspected at the pinned
   revision" — absence from what we read, not proof of absence.
4. **Defaults and hardened postures are both reported.** Most projects here ship a
   convenient default and document a stricter posture. Comparing DireWolf's design against
   a competitor's default would be dishonest; §9 reports both.
5. **No grades, no superlatives.** The matrix uses falsifiable labels only (§2). This
   document does not rank projects, and it does not claim DireWolf is more secure than any
   of them: DireWolf cannot yet run the workload the comparison would need.
6. **Dynamic numbers are timestamped or removed.** Stars, advisory counts and release
   cadences change daily; where one appears it carries its date and is not an argument.

---

## 1. What DireWolf is today

DireWolf's thesis is that **the component that reasons is not the component that is
trusted**: authorization, credentials and side effects live in privileged processes the
agent cannot reach. After M4, part of that thesis is measurable on real hosted identities;
most of it is not yet built.

| Area | Implemented now (milestone) | Target (owning milestone) |
|---|---|---|
| Authority process boundary | `dwkd-authority serve`: Unix-domain DWKP server; peer uid from `SO_PEERCRED` checked against the operator's list before a byte is read; one lease holder per connection (M3e). **Linux only.** | Same boundary in front of the real runtime (M9) |
| Wire contract | Bounded framing, strict JSON, RFC 8785 canonical JSON, versioned envelope; unknown fields and operations rejected; fuzzed (M2) | Approval binding and response MAC (M6) |
| Policy | Deterministic engine; closed typed predicates; two evaluation phases; `extends` cannot widen; three shipped packs with fixtures; p99 3.6 µs at 300 rules (M3c) | `policy test` / `simulate` / `explain` / `diff` in the CLI (M17) |
| Capabilities | Typed `⊑` lattice; attenuation with no widening path; 10⁶ generated chains, zero escalations (M3b) | Kernel-enforced subagent attenuation (M14) |
| Durable state and audit | `kernel.db` with fenced epochs, durable idempotent admission, kernel-owned policy inputs; hash-chained `audit.log` `fsync`ed before the answer, with a verifier (M3d) | Off-host export of chain heads, for deletion detection: operational guidance ([SECURITY.md](SECURITY.md) §4), not a milestone |
| Filesystem | Canonical resolution with `openat2` beneath an identity-pinned root; eight filesystem tools through the broker; atomic mutation; `UNKNOWN` never repeated (M4a–M4c). **Linux only.** | Fallback walker for other platforms (own ADR) |
| Process execution | Executable identity (absolute path, SHA-256), argv normalisation, empty environment, limits, `execveat` of the re-proved descriptor (M4d). **No production build launches anything**: a host launch needs a per-invocation approval, which is M6's | Sandboxed execution (M5); approvals (M6) |
| Secrets | Opaque handles; no operation returns a value; kernel keyring and age backends; one-shot handoff; return-path redaction; residue evidence; daemons dump no core (M4e) | Egress consumer `net.http` (M5); mode D (M6) |
| Taint | Run-level, monotone, held by the authority; raised to `LOCAL_UNVERIFIED` by file content and process output; a policy predicate (`when.taint_level`) the shipped packs use (M3d–M4d) | Network-sourced taint (M5); artifact and memory provenance (M12, M13) |
| Sandbox | **Foundation (M5a) and `PROXY_ONLY` networking (M5b, complete, hosted acceptance passed):** an `oci-strict` environment prepared and **measured** from the runtime's record and by a digest-pinned probe inside it, weakened profiles and topologies shown to be detected; its only network peer the broker's opaque CONNECT proxy, every bypass measured as refused; no public caller can prepare one and no workload runs in it. Policy is told every action runs on the host | Sandboxed workloads (M5d); `net.http` (M5c) |
| Approvals, budgets | **None.** A decision that would require approval is `DENY` | M6 |
| Model egress, providers | **None** (so no Ollama yet) | M7 |
| Agent loop, tools, context, memory, subagents, MCP | **None** | M8–M16 |
| CLI | `direwolf --version` and `doctor` only | M17 |
| Channels, scheduler, browser, plugins, web UI, remote workers | **None** | Post-V1 (M19–M28) |

The M4 closing evidence is hosted CI run
[36390815504](https://github.com/Onwcan/DireWolf/actions/runs/36390815504) (attempt 2):
every job succeeded, including the five M4 evidence jobs, the M3 transport evidence and the
evaluation gate, whose results include the three `m4-security` evaluations.

---

## 2. Method, labels and evidence rules

**Sources, in order of weight:** (1) source files at the pinned commit in §4; (2) the
project's own documentation at that commit or on its official site; (3) advisories the
project published; (4) nothing else. Secondary reporting (news articles, aggregators, vendor
blogs about someone else's product) is not used for any conclusion.

**Labels** — the only values a matrix cell may take:

| Label | Meaning |
|---|---|
| **IMPLEMENTED** | Present and active in the default configuration, per the inspected source or the project's own documentation |
| **PARTIAL** | Present, but narrower than the dimension: some paths, some platforms, heuristic rather than structural, or shown with a known gap |
| **OPTIONAL** | Implemented, but off by default; the operator must enable it |
| **PLANNED** | DireWolf only: owned by a named milestone, not implemented |
| **NOT IMPLEMENTED** | DireWolf only: absent, and deliberately not a V1 goal in that form |
| **NOT FOUND** | Not found in the sources inspected at the pinned revision |
| **N/A** | The dimension does not apply to what the project is |
| **UNVERIFIED** | Claimed somewhere, or plausible, but not verified against a primary source in this pass |

**Three comparisons, kept apart.** Product capability (§7) asks *what can it do*. Security
architecture (§6) asks *where is authority decided and enforced*. Security evidence and
maturity (§8) asks *what has been demonstrated, and how*. A project can lead on one and
trail on another; merging them into one score would hide exactly that.

---

## 3. Taxonomy

The projects below are not one category, and comparing across categories needs care.

| Category | What it is | Projects |
|---|---|---|
| **Personal / general agent runtimes** | A long-running agent with tools, memory, skills and channels, run by one operator | Hermes Agent, OpenClaw, NEAR AI/IronClaw, OpenFang |
| **Security-first agent platforms** | An agent runtime whose headline is a trust boundary around the agent | IronSecCo/IronClaw, OpenLegion |
| **Enforcement layers** | Not an agent: a policy and execution boundary other agents run behind | Capgate |
| **Coding agents with local sandboxes** | A developer tool that runs commands in an OS sandbox on the developer's machine | Claude Code, OpenAI Codex |
| **Execution infrastructure** | Sandboxes as a service; whoever runs inside decides the agent | Daytona |
| **Agent control centres** | A self-hosted surface that runs and schedules other agents | OpenHands (Agent Canvas) |
| **DireWolf** | An authority plane (implemented through M4) under a first-party agent runtime (planned, M7–M17) | — |

DireWolf's target overlaps the first two categories; what exists today overlaps the
enforcement-layer category, which is why the comparisons with Capgate and
IronSecCo/IronClaw say the most about the current state.

Two projects share the name "IronClaw". This document never uses the bare name:
**IronSecCo/IronClaw** is IronSecCo's Go control plane with gVisor sandboxes;
**NEAR AI/IronClaw** is NEAR AI's Rust agent with WASM tools.

---

## 4. The subjects

Snapshot commits are the `main` branch heads read on 2026-09-28/29. Links in this document
point at those commits, so they keep saying what we read even after the projects change.

| Project | Repository @ snapshot | Licence (licence file read) | Language | Stated status |
|---|---|---|---|---|
| Hermes Agent | [NousResearch/hermes-agent @ bca2e3c](https://github.com/NousResearch/hermes-agent/tree/bca2e3c5a486a7cb85a7721af937b7f9b614f131) | MIT | Python | Tagged releases (0.15.x at the time of CVE-2026-9366's fix) |
| OpenClaw | [openclaw/openclaw @ 876334d](https://github.com/openclaw/openclaw/tree/876334dc7f7f6eedcd60a96b86b7457c533e6b0f) | MIT (© OpenClaw Foundation; the GitHub API reports `NOASSERTION`, the file is MIT) | TypeScript | CalVer releases |
| IronSecCo/IronClaw | [IronSecCo/ironclaw @ 0b741b1](https://github.com/IronSecCo/ironclaw/tree/0b741b141ff5945c710cef04a8df22060ee42b79) | AGPL-3.0, with a commercial dual licence | Go | "Alpha software, work in progress", v0.1.x |
| NEAR AI/IronClaw | [nearai/ironclaw @ b0b999d](https://github.com/nearai/ironclaw/tree/b0b999d96781516ee05e6ba961d6f3ead900da96) | Apache-2.0 | Rust | Active; describes itself as a Rust reimplementation inspired by OpenClaw |
| OpenFang | [RightNow-AI/openfang @ acf2587](https://github.com/RightNow-AI/openfang/tree/acf2587e46be174c10200489c9a2d23a39a98aeb) | Apache-2.0 | Rust | v0.6.9, pre-1.0; last commit 2026-05-12 |
| OpenLegion | [openlegion-ai/openlegion @ 24efd6e](https://github.com/openlegion-ai/openlegion/tree/24efd6e06b28768cbbcd9275f43c479b3df37b18) | **PolyForm Perimeter 1.0.1 — source-available, not an open-source licence** | Python | Active |
| Capgate | [jersonboydmilan/Capgate @ 95c2bd6](https://github.com/jersonboydmilan/Capgate/tree/95c2bd6be4ea7b6975d73a647ba067245651241a) | MIT | Python | Created 2026-09-16; no numbered release (package version 0.1.0) |
| Claude Code | [anthropics/claude-code @ dec92bc](https://github.com/anthropics/claude-code/tree/dec92bc87ab6fe9c7be0fcba1f97966f902dd243) (plugins, changelog) and the official documentation | **Proprietary** ("© Anthropic PBC. All rights reserved"); the CLI source is not in the repository | — | Generally available |
| OpenAI Codex | [openai/codex @ c248f6d](https://github.com/openai/codex/tree/c248f6d48b97eb4a2aa56147a0b11b7d763278b9) | Apache-2.0 | Rust | Active |
| Daytona | [daytonaio/daytona](https://github.com/daytonaio/daytona) and the official documentation | Public repository frozen at v0.190.0 (AGPL-3.0); the project states that core development moved to a private codebase in June 2026 | — | Commercial service; public clients and SDKs |
| OpenHands | [OpenHands/OpenHands @ b9d174c](https://github.com/OpenHands/OpenHands/tree/b9d174c9ca36c27cd0b657779936ea2df29280e9) | MIT | Python / TypeScript | "Agent Canvas", beta |

**Adoption snapshot — GitHub stars, 2026-09-28, from the GitHub API.** Stars measure
attention, not quality or security, and they change daily. OpenClaw 390,756 · Hermes Agent
249,930 · Claude Code 148,535 · Codex 127,062 · OpenHands 89,472 · Daytona 71,693 · OpenFang
18,210 · NEAR AI/IronClaw 12,634 · OpenLegion 123 · IronSecCo/IronClaw 19 · Capgate 5 ·
DireWolf: not published.

Licences matter for one rule of this project: DireWolf does not reuse competitor code, so
no licence above grants DireWolf anything it uses. They are recorded because a reader
evaluating these projects needs them — and because "open source" was, for OpenLegion and
Daytona, not what the repository currently offers.

---

## 5. The finding that frames everything

Hermes Agent's [SECURITY.md](https://github.com/NousResearch/hermes-agent/blob/bca2e3c5a486a7cb85a7721af937b7f9b614f131/SECURITY.md)
still states the premise in one sentence: *"The only security boundary against an adversarial
LLM is the operating system."* OpenClaw's
[trust model](https://github.com/openclaw/openclaw/blob/876334dc7f7f6eedcd60a96b86b7457c533e6b0f/docs/gateway/security/trust-model.md)
reaches the same place from the other side: one trust boundary per gateway, "a single
operator or a mutually trusting team", with prompt-injection-only chains "not
vulnerabilities by design".

In 2026-09 the premise was treated three ways:

1. **As a disclaimer, with opt-in containment** — Hermes Agent, OpenClaw, OpenFang,
   OpenHands. The agent process is the trust domain; containers or sandboxes are available
   and off by default.
2. **As a sandbox around commands** — Claude Code, Codex, Daytona. An OS or container
   boundary contains what the agent *runs*; permission decisions still happen in the
   process that reads untrusted content (Claude Code, Codex), or are the customer's
   problem (Daytona).
3. **As an architecture** — IronSecCo/IronClaw, Capgate, OpenLegion, and NEAR AI/IronClaw on
   its container-worker path. The agent runs on the far side of a process, container or
   network boundary from the component that holds credentials and decides.

The previous edition compared DireWolf with two projects, neither of which had built the
boundary, and it was easy to read that as true of the category. **Across the wider
landscape it is not**, and DireWolf's distinguishing claim narrows accordingly. What
DireWolf has that the category-3 projects we read do not all share is a specific
combination, not a boundary as such: authorization and execution in two separate
privileged processes; decisions on canonical objects (a file by identity, an executable by
hash) rather than strings; an audit record made durable before the answer; and every
policy input, taint included, held by the authority. What DireWolf lacks, and
IronSecCo/IronClaw and OpenLegion both have, is the part a user sees first: **a sandbox
around the agent, and an agent.** Capgate's reference deployments provide the first.

---

## 6. Comparison A — security architecture

Labels per §2. "DW now" is DireWolf at the M4 closure; "DW target" names the owning
milestone. Short qualifiers in a cell are part of the finding.

### 6.1 Agent runtimes and security-first platforms

| # | Dimension | DW now | DW target | Hermes | OpenClaw | IronSecCo/IronClaw | NEAR AI/IronClaw | OpenFang | OpenLegion |
|---|---|---|---|---|---|---|---|---|---|
| S1 | Authorization decided outside the process that reads untrusted input | IMPLEMENTED (M3e; exercised against a hostile client — no DireWolf runtime yet) | M9 (real runtime) | NOT FOUND | NOT FOUND | IMPLEMENTED | PARTIAL (tools in WASM; loop and policy in the host process) | NOT FOUND (kernel and agent loop share one process) | IMPLEMENTED (trusted mesh host, untrusted agent containers) |
| S2 | Reasoning process holds no long-lived credential | PARTIAL (no operation returns a secret, M4e; model keys have no home until M7) | M7 | NOT FOUND | OPTIONAL (SecretRefs) | IMPLEMENTED (host model proxy holds keys) | PARTIAL (hidden from WASM tools; decrypted in the host process) | UNVERIFIED | PARTIAL (LLM keys mesh-only; agent-tier credentials returned in plaintext) |
| S3 | Authorization deterministic by default — no model decides | IMPLEMENTED (M3c) | — | OPTIONAL (default `smart` mode lets an auxiliary LLM approve low-risk commands) | IMPLEMENTED (tool policy is configuration) | IMPLEMENTED (deterministic verifiers) | IMPLEMENTED (capabilities, allowlists) | IMPLEMENTED (in-process) | IMPLEMENTED (ACLs) |
| S4 | Delegation can only attenuate authority | IMPLEMENTED (lattice, M3b; subagents M14) | M14 | PARTIAL (fixed blocklist for children; no per-task narrowing) | IMPLEMENTED (per-agent and subagent filters only restrict) | UNVERIFIED | UNVERIFIED | IMPLEMENTED (glob strings, in-process) | UNVERIFIED |
| S5 | Policy decides on canonical resources, not strings | IMPLEMENTED for files and executables (M4); network M5 | M5 | NOT FOUND (patterns over command text) | PARTIAL (string roots; two 2026-09 advisories in this class, fixed) | N/A (containment by sandbox) | PARTIAL (host and path allowlist) | NOT FOUND (glob over path and command strings) | UNVERIFIED |
| S6 | Approvals single-use, expiring, bound to one canonical action | PLANNED (until then an approval-requiring action is denied) | M6 | UNVERIFIED | PARTIAL (approval-scope advisories, fixed 2026-09) | IMPLEMENTED (human-approved control-plane transactions; binding details not inspected) | UNVERIFIED | UNVERIFIED | UNVERIFIED |
| S7 | Execution sandbox on by default | PARTIAL (M5a: the measured `oci-strict` environment exists; no production workload runs in it until M5d, and no production build launches a process) | M5 | OPTIONAL (default backend `local`) | OPTIONAL (default mode `off`) | IMPLEMENTED (gVisor per session on Linux) | PARTIAL (WASM tools; container workers optional) | OPTIONAL (Docker sandbox default off) | IMPLEMENTED (hardened Docker) |
| S8 | Isolation never switches authorization checks off | PLANNED (design rule, both always apply) | M5, M6 | NOT FOUND (container backends skip dangerous-command checks) | IMPLEMENTED (tool policy, sandbox and elevated are separate controls) | IMPLEMENTED | IMPLEMENTED | UNVERIFIED | IMPLEMENTED |
| S9 | Reasoning process has no network route at the OS level | PLANNED — owner assigned by this re-baseline (§17 G1) | M9 | OPTIONAL (whole-process container) | NOT FOUND | IMPLEMENTED (`network=none`) | PARTIAL (container workers only) | NOT FOUND | NOT FOUND (bridge network with internet by default) |
| S10 | Destination-allowlisted egress for tools | PLANNED (CONNECT proxy, `net.http`) | M5 | PARTIAL (SSRF guard, fail-closed DNS; not an allowlist) | PARTIAL (SSRF guard; exact-host lists for SecretRefs) | OPTIONAL (egress broker, deny-by-default once enabled) | IMPLEMENTED (host-owned proxy) | UNVERIFIED | PARTIAL (application-layer SSRF only, "no kernel-enforced fallback") |
| S11 | Credential injected at egress; value never enters the requester | PARTIAL (mode A render and B/C primitive exist; no consumer until M5) | M5 | NOT FOUND | OPTIONAL (SecretRef loopback proxy) | IMPLEMENTED (model keys) | IMPLEMENTED ("injected at host boundary") | UNVERIFIED | PARTIAL (vault calls server-side; `$CRED{}` plaintext) |
| S12 | Credential bound to endpoint and consumer | IMPLEMENTED (origin and executable-identity binding, M4e) | — | UNVERIFIED | IMPLEMENTED for SecretRefs (exact HTTPS hosts) | UNVERIFIED | IMPLEMENTED | UNVERIFIED | PARTIAL (glob-matched per agent) |
| S13 | Return-path redaction / leak scanning | IMPLEMENTED (exact values and nine shapes; file content, process output) | — | IMPLEMENTED (documented as heuristic) | UNVERIFIED | UNVERIFIED | IMPLEMENTED (both directions, fuzzed) | UNVERIFIED | UNVERIFIED |
| S14 | Secret-residue evidence (memory, core, durable state inspected) | IMPLEMENTED (M4e evidence) | — | NOT FOUND | NOT FOUND | NOT FOUND | NOT FOUND | NOT FOUND | NOT FOUND |
| S15 | Privileged-process hardening (no core, non-dumpable) | IMPLEMENTED (both daemons) | — | UNVERIFIED | UNVERIFIED | UNVERIFIED (sandbox: `no_new_privs`, no capabilities) | UNVERIFIED | UNVERIFIED | UNVERIFIED |
| S16 | Host-path containment resistant to symlink, Unicode and swap races | IMPLEMENTED (`openat2`, held descriptors, race campaigns; Linux) | other platforms: own ADR | UNVERIFIED | PARTIAL (Unicode fallback escape, fixed 2026-09) | N/A (mount boundary) | UNVERIFIED | PARTIAL (canonicalise then prefix-compare, path reopened; WASM host functions check the raw path first) | N/A (container) |
| S17 | Executable identity (resolved path and hash) decides execution | IMPLEMENTED (M4d; launch waits for M6) | M6 | NOT FOUND | UNVERIFIED | N/A (inside the sandbox) | N/A (WASM tools) | NOT FOUND (glob over the command string) | UNVERIFIED |
| S18 | Tamper-evident audit (hash chain and verifier) | IMPLEMENTED (M3d) | — | NOT FOUND (telemetry excludes arguments and results) | NOT FOUND ("best-effort", metadata only, no chain documented) | PARTIAL (append-only JSONL, no chain documented) | UNVERIFIED | IMPLEMENTED (SHA-256 chain; SQLite when attached) | NOT FOUND ("no comprehensive audit trail") |
| S19 | Audit durable before the answer; intent durable before the effect | IMPLEMENTED | — | NOT FOUND | NOT FOUND | UNVERIFIED | UNVERIFIED | UNVERIFIED | NOT FOUND |
| S20 | Taint is a policy input held by the authority | PARTIAL (run-level, monotone; files and process output; network M5, memory M13) | M5, M13 | NOT FOUND | PARTIAL (turn-level, from tools that declare network-sourced results) | UNVERIFIED | UNVERIFIED | PARTIAL (labels from substring heuristics; no propagation found) | NOT FOUND |
| S21 | Durable-memory writes gated by provenance | PLANNED | M13 | OPTIONAL (`memory.write_approval` off by default) | IMPLEMENTED (origin classes; untrusted content excluded from promotion) | UNVERIFIED | UNVERIFIED | UNVERIFIED | NOT FOUND (stated limitation) |
| S22 | Agent-authored skills or tools gated before trust | PLANNED | M11a, M25 | OPTIONAL (`skills.write_approval` off by default) | UNVERIFIED (not re-verified in this pass) | UNVERIFIED | UNVERIFIED (agent-built WASM tools; gate not inspected) | PARTIAL (Ed25519 manifest verification exists; not shown to be mandatory) | UNVERIFIED |
| S23 | Extensions isolated from the privileged process | PLANNED (V1 ships none) | M26 | NOT FOUND (plugins run with agent privileges) | NOT FOUND (native plugins in-process, "not sandboxed") | UNVERIFIED | IMPLEMENTED (WASM) | PARTIAL (WASM modules metered; native paths in-process) | UNVERIFIED |
| S24 | MCP tool-set change invalidates approvals | PLANNED (`toolset_hash`) | M16 | NOT FOUND | NOT FOUND (changed servers retired on reload; no hash-bound invalidation found) | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED |
| S25 | Hierarchical, subtractive budgets | PLANNED | M6 | NOT FOUND (child iteration limit not subtracted from the parent) | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED | PARTIAL (per-agent token budgets) |
| S26 | Unattended runs deny what would need approval | IMPLEMENTED in effect (no approval path exists before M6) | M6 | IMPLEMENTED (cron, single-query and unattended modes default to deny) | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED |
| S27 | Control plane identifies callers by an OS- or key-bound identity | IMPLEMENTED (`SO_PEERCRED`; Linux) | — | UNVERIFIED | PARTIAL (gateway token; CVE-2026-25253 in this class, fixed) | IMPLEMENTED (per-session queues) | UNVERIFIED | UNVERIFIED | UNVERIFIED |
| S28 | Authorization and execution in separate privileged components | IMPLEMENTED (authority and broker, private channel, single-use authorisation) | — | NOT FOUND | NOT FOUND | IMPLEMENTED | PARTIAL (container-worker path) | NOT FOUND | PARTIAL (mesh performs vault calls) |
| S29 | Assurance measured at run time, not declared | PARTIAL (evidence reports NOT EXERCISED, never a pass; `AssuranceLevel` is declared) | M5, M17 (§17 G2) | UNVERIFIED | PARTIAL (`openclaw security audit` checks configuration) | PARTIAL (`ironctl scan` grades configuration; containment harness in CI) | UNVERIFIED | UNVERIFIED | UNVERIFIED |

### 6.2 Enforcement layers, coding agents and infrastructure

| # | Dimension | Capgate | Claude Code | Codex | Daytona | OpenHands |
|---|---|---|---|---|---|---|
| S1 | Authorization outside the untrusted-input process | IMPLEMENTED (reference deployments) | PARTIAL (commands sandboxed; permission decisions in the agent process) | PARTIAL (same) | N/A | OPTIONAL (sandbox backends) |
| S2 | No long-lived credential in the reasoning process | IMPLEMENTED (executor holds tool credentials) | OPTIONAL (credential `mask`/`deny` for sandboxed commands; "no built-in credential deny list") | UNVERIFIED | N/A | NOT FOUND (agent server on the host by default) |
| S3 | Deterministic authorization by default | IMPLEMENTED | PARTIAL (rules deterministic; auto mode uses a classifier) | PARTIAL (default `OnRequest`: "the model decides when to ask") | N/A | UNVERIFIED |
| S4 | Delegation only attenuates | IMPLEMENTED ("delegation does not transfer authority") | UNVERIFIED | UNVERIFIED | N/A | UNVERIFIED |
| S5 | Canonical resources, not strings | PARTIAL (grant binds the exact argument hash; resources not resolved) | UNVERIFIED | UNVERIFIED | N/A | UNVERIFIED |
| S6 | Bound, single-use, expiring approvals | IMPLEMENTED (signed single-use grants; approvals re-evaluate) | UNVERIFIED | UNVERIFIED | N/A | UNVERIFIED |
| S7 | Sandbox on by default | OPTIONAL (reference deployments) | OPTIONAL (`/sandbox`) | IMPLEMENTED (sandboxed default modes, network off) | IMPLEMENTED (the product) | OPTIONAL |
| S8 | Isolation never switches checks off | IMPLEMENTED | PARTIAL (auto-allow runs sandboxed commands without prompting; deny rules still apply) | UNVERIFIED | N/A | UNVERIFIED |
| S9 | Reasoning process has no network route | IMPLEMENTED (internal networks; iptables allows only the proxy) | PARTIAL (sandboxed commands only) | PARTIAL (sandboxed commands only) | OPTIONAL (network restricted on tiers 1–2; `networkBlockAll`) | NOT FOUND (default) |
| S10 | Destination-allowlisted egress | IMPLEMENTED | IMPLEMENTED for sandboxed commands (no domain pre-allowed) | OPTIONAL (network proxy) | OPTIONAL (CIDR and domain allowlists) | UNVERIFIED |
| S11 | Credential injected at egress | IMPLEMENTED | OPTIONAL (mask with `injectHosts`; needs TLS termination) | UNVERIFIED | NOT FOUND (proxy credentials visible inside the sandbox) | UNVERIFIED |
| S12 | Credential bound to endpoint | UNVERIFIED | OPTIONAL (`injectHosts`) | UNVERIFIED | N/A | UNVERIFIED |
| S13 | Return-path redaction | UNVERIFIED | UNVERIFIED | PARTIAL (redaction function exists; coverage not verified) | N/A | UNVERIFIED |
| S14 | Secret-residue evidence | NOT FOUND | NOT FOUND | NOT FOUND | N/A | NOT FOUND |
| S15 | Privileged-process hardening | UNVERIFIED | UNVERIFIED | IMPLEMENTED (core dumps and ptrace disabled, `LD_PRELOAD`/`DYLD_*` stripped) | N/A | UNVERIFIED |
| S16 | Race-resistant host-path containment | UNVERIFIED | UNVERIFIED | UNVERIFIED | N/A | UNVERIFIED |
| S17 | Executable identity decides execution | N/A (tools, not processes) | UNVERIFIED | PARTIAL (argv rules in `execpolicy`; no hash found) | N/A | UNVERIFIED |
| S18 | Tamper-evident audit | IMPLEMENTED (hash chain, verified before extending) | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED |
| S19 | Audit durable before the answer | PARTIAL (written before the decision returns; `fsync` off by default) | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED |
| S20 | Taint held by the authority | UNVERIFIED | UNVERIFIED | UNVERIFIED | N/A | UNVERIFIED |
| S21 | Memory writes gated by provenance | N/A | UNVERIFIED | UNVERIFIED | N/A | UNVERIFIED |
| S22 | Agent-authored skills gated | N/A | UNVERIFIED | UNVERIFIED | N/A | UNVERIFIED |
| S23 | Extensions isolated | N/A | UNVERIFIED | UNVERIFIED | N/A | UNVERIFIED |
| S24 | MCP rug-pull invalidation | N/A | UNVERIFIED | UNVERIFIED | N/A | UNVERIFIED |
| S25 | Hierarchical budgets | PARTIAL (per-contract counters; no hierarchy found) | UNVERIFIED | UNVERIFIED | N/A (resource limits) | UNVERIFIED |
| S26 | Unattended runs deny | UNVERIFIED | UNVERIFIED | UNVERIFIED | N/A | UNVERIFIED |
| S27 | Caller identity bound to the OS or a key | IMPLEMENTED (tokens; optional mTLS/SPIFFE binding) | N/A (local CLI) | N/A (local CLI) | PARTIAL (API keys) | PARTIAL (session API key) |
| S28 | Authorization and execution split | IMPLEMENTED (one interceptor, one executor) | PARTIAL (network proxy outside the sandbox) | PARTIAL (network proxy outside the sandbox) | N/A | NOT FOUND (default) |
| S29 | Assurance measured at run time | PARTIAL (compromised-agent job in CI, not per deployment) | PARTIAL (`/sandbox` dependency check) | UNVERIFIED | UNVERIFIED | UNVERIFIED |

**Reading the two tables.** The rows where DireWolf is IMPLEMENTED and most others are NOT
FOUND or UNVERIFIED (S14, S16, S17, S19) are narrow, deliberate mechanisms — they are what
M3 and M4 built. The rows where DireWolf is PLANNED (S6–S11, S21–S25) are the rows a user
experiences as "is the agent contained?", and several projects implement them today.

---

## 7. Comparison B — product capability

| # | Capability | DW now | DW target | Hermes | OpenClaw | IronSecCo/IronClaw | NEAR AI/IronClaw | OpenFang | OpenLegion | Capgate | Claude Code | Codex | Daytona | OpenHands |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| P1 | Agent loop that completes tasks | PLANNED | M9 | IMPLEMENTED | IMPLEMENTED | IMPLEMENTED (alpha) | IMPLEMENTED | IMPLEMENTED | IMPLEMENTED | N/A | IMPLEMENTED | IMPLEMENTED | N/A | IMPLEMENTED |
| P2 | Model providers | PLANNED | M7 | IMPLEMENTED | IMPLEMENTED | IMPLEMENTED (via host proxy) | IMPLEMENTED | IMPLEMENTED | IMPLEMENTED | N/A | IMPLEMENTED | IMPLEMENTED | N/A | IMPLEMENTED |
| P3 | Local models | PLANNED (Ollama first-class) | M7, M17 | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED | N/A | UNVERIFIED | IMPLEMENTED (Ollama and LM Studio crates) | N/A | UNVERIFIED |
| P4 | File tools | IMPLEMENTED (eight tools through the broker; no agent calls them yet; Linux) | M10 | IMPLEMENTED | IMPLEMENTED | IMPLEMENTED | IMPLEMENTED | IMPLEMENTED | IMPLEMENTED | N/A | IMPLEMENTED | IMPLEMENTED | UNVERIFIED | IMPLEMENTED |
| P5 | Command execution | PARTIAL (built end to end; no production launch before M6) | M5, M6 | IMPLEMENTED | IMPLEMENTED | IMPLEMENTED | IMPLEMENTED | IMPLEMENTED | IMPLEMENTED | N/A | IMPLEMENTED | IMPLEMENTED | IMPLEMENTED | IMPLEMENTED |
| P6 | Web fetch / search | PLANNED | M5, M10 | IMPLEMENTED | IMPLEMENTED | IMPLEMENTED (through the egress broker) | IMPLEMENTED | IMPLEMENTED | IMPLEMENTED | N/A | IMPLEMENTED | UNVERIFIED | N/A | UNVERIFIED |
| P7 | Browser automation | PLANNED | M23 (V1.2) | IMPLEMENTED | IMPLEMENTED | UNVERIFIED | UNVERIFIED | IMPLEMENTED | IMPLEMENTED | N/A | UNVERIFIED | UNVERIFIED | N/A | UNVERIFIED |
| P8 | Messaging channels | PLANNED | M20 (V1.1) | IMPLEMENTED | IMPLEMENTED | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED | N/A | N/A | N/A | N/A | UNVERIFIED |
| P9 | Durable memory | PLANNED | M13 | IMPLEMENTED | IMPLEMENTED | UNVERIFIED | IMPLEMENTED (hybrid full-text and vector) | IMPLEMENTED | IMPLEMENTED | N/A | UNVERIFIED | IMPLEMENTED (`memories` crate) | N/A | UNVERIFIED |
| P10 | Skills | PLANNED | M11a | IMPLEMENTED | IMPLEMENTED | UNVERIFIED | UNVERIFIED | IMPLEMENTED | UNVERIFIED | N/A | IMPLEMENTED | IMPLEMENTED | N/A | UNVERIFIED |
| P11 | Subagents / multi-agent | PLANNED | M14 | IMPLEMENTED | IMPLEMENTED | UNVERIFIED | UNVERIFIED | IMPLEMENTED | IMPLEMENTED (agent fleets) | N/A | UNVERIFIED | UNVERIFIED | N/A | IMPLEMENTED (runs several agent types) |
| P12 | Scheduled / event-driven runs | PLANNED | M21 (V1.1) | IMPLEMENTED | IMPLEMENTED | UNVERIFIED | IMPLEMENTED (routines) | IMPLEMENTED ("Hands") | UNVERIFIED | N/A | UNVERIFIED | UNVERIFIED | N/A | IMPLEMENTED (automations) |
| P13 | MCP client | PLANNED | M16 | IMPLEMENTED | IMPLEMENTED | UNVERIFIED | IMPLEMENTED | IMPLEMENTED | UNVERIFIED | N/A | IMPLEMENTED | IMPLEMENTED | N/A | UNVERIFIED |
| P14 | Plugins | PLANNED | M26 (V2) | IMPLEMENTED | IMPLEMENTED | UNVERIFIED | IMPLEMENTED (WASM tools) | IMPLEMENTED | UNVERIFIED | N/A | IMPLEMENTED | IMPLEMENTED | N/A | UNVERIFIED |
| P15 | Web UI / control surface | PLANNED | M27 (V2) | UNVERIFIED | IMPLEMENTED (Control UI) | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED | IMPLEMENTED (inspect UI) | N/A | UNVERIFIED | IMPLEMENTED | IMPLEMENTED |
| P16 | Policy simulation before a change | PARTIAL (engine and fixture suites; no CLI) | M17 | NOT FOUND | NOT FOUND | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED | IMPLEMENTED (`simulate`, same engine, no grants minted) | NOT FOUND | NOT FOUND | N/A | NOT FOUND |
| P17 | Security self-check command | PARTIAL (`doctor` exists; sandbox measurement planned) | M17 | UNVERIFIED | IMPLEMENTED (`openclaw security audit`) | IMPLEMENTED (`ironctl scan`, configuration-based) | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED | PARTIAL (`/sandbox` dependency panel) | UNVERIFIED | N/A | UNVERIFIED |
| P18 | Native Windows | NOT IMPLEMENTED (serving refuses; Windows Credential Manager backend tested, not served) | WSL2 recommended; native = reduced assurance, stated | UNVERIFIED | UNVERIFIED | NOT FOUND (WSL2 required) | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED | NOT FOUND for the sandbox (WSL2) | PARTIAL (a Windows sandbox crate exists) | N/A | UNVERIFIED |

---

## 8. Comparison C — security evidence and maturity

| # | Evidence | DW now | Hermes | OpenClaw | IronSecCo/IronClaw | NEAR AI/IronClaw | OpenFang | OpenLegion | Capgate | Claude Code | Codex | Daytona | OpenHands |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| E2 | Published vulnerability process | IMPLEMENTED | IMPLEMENTED | IMPLEMENTED | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED |
| E3 | Advisories published (§11) | N/A (nothing released) | IMPLEMENTED | IMPLEMENTED | NOT FOUND | NOT FOUND | NOT FOUND | NOT FOUND | NOT FOUND | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED |
| E4 | Adversarial suite in CI against the real processes | IMPLEMENTED (hostile DWKP client; M4 evidence on three OS identities) | UNVERIFIED | UNVERIFIED | PARTIAL (red-team containment harness; **self-skips, non-fatally, with no Docker engine**) | PARTIAL (leak-detector fuzz target) | UNVERIFIED | UNVERIFIED | IMPLEMENTED (adversarial directories; Kubernetes compromised-agent job) | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED |
| E5 | Gate proved able to fail (weakened-configuration meta-test) | IMPLEMENTED (deliberate-failure meta-tests; NOT EXERCISED fails a required gate) | NOT FOUND | NOT FOUND | IMPLEMENTED (a bridge-network override must fail the gate) | NOT FOUND | NOT FOUND | NOT FOUND | UNVERIFIED | NOT FOUND | NOT FOUND | NOT FOUND | NOT FOUND |
| E6 | Fuzzing of security parsers | IMPLEMENTED (protocol and policy loader; weekly and on pull requests) | UNVERIFIED | UNVERIFIED | UNVERIFIED | IMPLEMENTED (leak detector) | UNVERIFIED | UNVERIFIED | PARTIAL (property-based tests) | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED |
| E7 | SBOM published with releases | PLANNED (M18, §17 G3) | UNVERIFIED | UNVERIFIED | IMPLEMENTED (SPDX and CycloneDX) | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED |
| E8 | Build provenance and signing | PLANNED (M18) | UNVERIFIED | UNVERIFIED | IMPLEMENTED (provenance attestation, keyless signing) | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED |
| E9 | Reproducible builds verified | PLANNED (M18; deferred since M2) | UNVERIFIED | UNVERIFIED | IMPLEMENTED (cross-machine byte comparison) | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED |
| E10 | Dependency advisory and licence gate | IMPLEMENTED (`cargo-deny`, `pip-audit`) | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED |
| E11 | Third-party notices shipped with binaries | PLANNED (M18; nothing is distributed as a binary today) | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED |
| E12 | Independent security review | PLANNED (commissioned at M18) | PARTIAL (community audit; issue open, §11) | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED | UNVERIFIED |

Maturity facts that labels do not fit, as of the snapshot:

| Project | Release status |
|---|---|
| DireWolf | Pre-release; no tags; distributed as source only |
| Hermes Agent | Tagged releases |
| OpenClaw | CalVer releases |
| IronSecCo/IronClaw | Alpha, v0.1.x |
| NEAR AI/IronClaw | Active development; release cadence not verified |
| OpenFang | v0.6.9, pre-1.0; no commit since 2026-05-12 |
| OpenLegion | Active development |
| Capgate | No numbered release; created twelve days before the snapshot |
| Claude Code | Generally available |
| Codex | Released |
| Daytona | Commercial service; public core frozen at v0.190.0 |
| OpenHands | Agent Canvas in beta |

**Deployed use.** DireWolf has none. For the others, the only figure verified here is the
star snapshot in §4, which measures attention, not deployment.

DireWolf's evidence rows are stronger than its product rows because evidence is what M1–M4
set out to produce. Its deployment history is empty, and that is the one gap no amount of
CI can fill.

---

## 9. Default versus hardened posture

"Hardened" is the stricter posture each project itself documents, not one we invented.

| Project | Default | Documented hardened posture | What the project says remains |
|---|---|---|---|
| **DireWolf (now)** | Every action not explicitly granted is denied; shipped policy packs deny every read until a home anchor exists; no process launches; serving is Linux only | No separate hardened posture: defaults are the posture | No sandbox, no runtime, no approvals (§14) |
| Hermes Agent | Terminal backend `local`; `smart` approvals; memory and skill writes unapproved; credentials in `~/.hermes/.env` (mode 0600); SSRF guard on; unattended modes deny | Container or remote backend, or wrap the whole process tree; manual approvals; write approvals on | Plugins and skills run with full agent privileges; container backends skip dangerous-command checks; prompt injection alone is out of scope ([SECURITY.md](https://github.com/NousResearch/hermes-agent/blob/bca2e3c5a486a7cb85a7721af937b7f9b614f131/SECURITY.md)) |
| OpenClaw | Sandbox `off`; plaintext credentials under `~/.openclaw`; session visibility across agents; native plugins in-process | Sandbox `all` with Docker network `none`; SecretRefs through the loopback proxy; `openclaw security audit`; [hardened baseline](https://github.com/openclaw/openclaw/blob/876334dc7f7f6eedcd60a96b86b7457c533e6b0f/docs/gateway/security/hardened-baseline.md) | Its own threat model rates exfiltration through `web_fetch` "High" and skills "Critical — skills run with agent privileges" ([ATLAS](https://github.com/openclaw/openclaw/blob/876334dc7f7f6eedcd60a96b86b7457c533e6b0f/docs/security/THREAT-MODEL-ATLAS/collection-and-exfiltration.md)) |
| IronSecCo/IronClaw | gVisor sandbox per session with `network=none` on Linux; egress broker off | Egress broker allowlist; signed image | Alpha; a live launch "still needs runsc and a provisioned/signed image"; macOS runs `runc` without seccomp enforcement — "a weaker sandbox boundary"; native Windows needs WSL2 |
| NEAR AI/IronClaw | WASM tools behind allowlists and leak scanning; local workers in-process | Container workers with no direct network route | The agent loop and credential decryption stay in the host process on the local path |
| OpenFang | One process; Docker sandbox off; WASM modules metered | Docker sandbox on (network `none` by default when on) | The kernel and the agent loop share a process; taint labels are heuristic (§10.5) |
| OpenLegion | Hardened containers (non-root, all capabilities dropped, read-only root) on a bridge network with internet | Optional microVM sandbox | SSRF protection is application-layer only, "no kernel-enforced fallback"; agent-tier credentials are returned in plaintext |
| Capgate | A library; isolation comes from its reference deployments | gVisor, Kubernetes `NetworkPolicy` with a gVisor runtime class, mTLS workload identity | Shared host kernel; audit `fsync` off by default; pre-release |
| Claude Code | Permission prompts; sandbox off until enabled with `/sandbox` | Sandbox with managed-only domains, `allowUnsandboxedCommands: false`, credential `mask`/`deny` | "Sandboxing reduces risk but is not a complete isolation boundary"; the proxy decides on the client-supplied hostname, so broad allowed domains and domain fronting remain exfiltration paths |
| Codex | Sandboxed modes with network off; `OnRequest` approvals, where the model decides when to ask | Untrusted-project approval mode; network proxy allowlists | Model-initiated escalation out of the sandbox is the default path to approval |
| Daytona | Containers; network restricted on tiers 1–2, "full internet access … by default" on tiers 3–4 | `networkBlockAll`; CIDR or domain allowlists; VM sandboxes | Credentials in `outboundProxyUrl` are exposed inside the sandbox as `HTTP_PROXY` |
| OpenHands | Quick-start without a sandbox: "the agent will have full access to your filesystem" | Docker or VM backends; firewall; session API key | "Treat the VM as you would any machine that holds production credentials" |

---

## 10. Project findings

Each entry says what the project does well, what it trades away, and — where we found one —
where a documented claim and the inspected code differ. File links are pinned to the
snapshot commit.

### 10.1 Hermes Agent

- **Posture:** the agent process is the trust domain, stated candidly in
  [SECURITY.md](https://github.com/NousResearch/hermes-agent/blob/bca2e3c5a486a7cb85a7721af937b7f9b614f131/SECURITY.md);
  two supported isolation postures (terminal backend, or wrapping the whole process tree).
- **Defaults** ([`hermes_cli/config_defaults.py`](https://github.com/NousResearch/hermes-agent/blob/bca2e3c5a486a7cb85a7721af937b7f9b614f131/hermes_cli/config_defaults.py)):
  `approvals.mode = "smart"` (an auxiliary model auto-approves commands it judges low-risk);
  cron, single-query and unattended modes `deny` — a sound default the previous edition did
  not record; deny globs that apply even in `yolo` mode; `memory.write_approval`,
  `skills.write_approval` and `skills.guard_agent_created` all false; a skills ledger with
  before/after hashes that is explicitly "never a gate".
- **Approval reviewer:** [`tools/approval_smart.py`](https://github.com/NousResearch/hermes-agent/blob/bca2e3c5a486a7cb85a7721af937b7f9b614f131/tools/approval_smart.py)
  wraps the command in delimiters under an untrusted-input system prompt. That mitigates the
  injection reported in issue #21425; it does not change the fact that a model decides.
- **Isolation and checks:** the [security guide](https://github.com/NousResearch/hermes-agent/blob/bca2e3c5a486a7cb85a7721af937b7f9b614f131/website/docs/user-guide/security.md)
  says container backends skip dangerous-command checks "because the container itself is
  the security boundary". SSRF protection fails closed on DNS failure; the MCP subprocess
  environment is filtered.
- **Delegation** ([docs](https://github.com/NousResearch/hermes-agent/blob/bca2e3c5a486a7cb85a7721af937b7f9b614f131/website/docs/user-guide/features/delegation.md)):
  children inherit the parent's toolsets minus a fixed blocklist; spawn depth 1 by default;
  a child's iteration limit is not subtracted from the parent's; children share the
  credential pool; the parent sees only a summary — a context firewall DireWolf adopted in
  2026-09.

### 10.2 OpenClaw

- **Trust model:** one boundary per gateway;
  [plugins](https://github.com/openclaw/openclaw/blob/876334dc7f7f6eedcd60a96b86b7457c533e6b0f/docs/plugins/architecture.md)
  "run in-process with the Gateway. They are not sandboxed."
- **Controls:** tool policy, sandbox and elevated mode are separate
  ([doc](https://github.com/openclaw/openclaw/blob/876334dc7f7f6eedcd60a96b86b7457c533e6b0f/docs/gateway/sandbox-vs-tool-policy-vs-elevated.md));
  sandbox backends Docker, Podman, SSH, OpenShell, Crabbox; Docker network `none` by default
  once sandboxing is on.
- **Secrets** ([runtime model](https://github.com/openclaw/openclaw/blob/876334dc7f7f6eedcd60a96b86b7457c533e6b0f/docs/gateway/secrets/runtime-model.md)):
  opt-in SecretRefs; a gateway-owned loopback proxy substitutes the value immediately before
  egress, to an exact HTTPS host list, refusing non-HTTPS. Convergent with DireWolf's
  mode A, and implemented where DireWolf's has no consumer yet.
- **Memory — a correction.** The previous edition called memory provenance DireWolf's
  "clearest differentiator" and said neither project tracked it. OpenClaw's
  [memory architecture](https://github.com/openclaw/openclaw/blob/876334dc7f7f6eedcd60a96b86b7457c533e6b0f/docs/concepts/memory-architecture.md)
  now records an origin class (owner, agent, untrusted, system) in columns "the model cannot
  write through prose"; excludes untrusted and system candidates from promotion
  structurally; gives scheduled, heartbeat and sub-agent sessions no durable candidates;
  prevents recall loops; and taints turns whose tools declare network-sourced results, with
  the coverage gap for undeclared tools stated. **This is implemented; DireWolf's is
  planned (M13).** Two of its mechanisms are adopted in §17 G6.
- **Audit** ([gateway audit](https://github.com/openclaw/openclaw/blob/876334dc7f7f6eedcd60a96b86b7457c533e6b0f/docs/gateway/audit.md)):
  metadata only, "best-effort", "absence of a row proves nothing", not a compliance archive.

### 10.3 IronSecCo/IronClaw

- **Architecture** ([architecture.md](https://github.com/IronSecCo/ironclaw/blob/0b741b141ff5945c710cef04a8df22060ee42b79/docs/architecture.md)):
  a Go control plane holds every key and every privileged action; each session's agent runs
  in a gVisor sandbox (`network=none`, empty capability sets, `no_new_privs`, non-root user
  namespace, read-only root with a tmpfs workspace); the two communicate only through a pair
  of encrypted SQLite queues. Model keys stay in a host proxy; the egress broker is opt-in
  and deny-by-default; "every control-plane mutation is a deterministic, human-approved,
  auditable transaction", with an always-human floor. The agent is compiled Go with no
  interpreter in the sandbox, so it cannot read or edit its own source.
- **Of the projects read, this architecture is the nearest to DireWolf's target, and it
  has the sandbox DireWolf does not yet have.**
- **`ironctl scan`** ([score.go](https://github.com/IronSecCo/ironclaw/blob/0b741b141ff5945c710cef04a8df22060ee42b79/internal/host/scan/score.go))
  grades a deployment 0–100 and A–F over seven dimensions with fixed, unequal weights. It
  reads configuration (`docker inspect`, manifests, Dockerfiles), not behaviour. §16 explains
  why DireWolf adopts the measurement and rejects the score.
- **CI** ([sandbox-containment.yml](https://github.com/IronSecCo/ironclaw/blob/0b741b141ff5945c710cef04a8df22060ee42b79/.github/workflows/sandbox-containment.yml)):
  a red-team escape harness plus a regression guard that a deliberately weakened sandbox (a
  bridge network override) must fail the gate — a way of proving that a containment gate
  can fail, which DireWolf adopts (§17 G2). The same job skips, without failing, when no
  Docker engine is present.
- **Releases** ([release.yml](https://github.com/IronSecCo/ironclaw/blob/0b741b141ff5945c710cef04a8df22060ee42b79/.github/workflows/release.yml),
  [reproducibility.yml](https://github.com/IronSecCo/ironclaw/blob/0b741b141ff5945c710cef04a8df22060ee42b79/.github/workflows/reproducibility.yml)):
  build-provenance attestations, keyless signing, SPDX and CycloneDX SBOMs, cross-machine
  reproducibility.
- **Limits it states:** alpha; macOS and Windows weaker; append-only JSONL audit with no
  hash chain documented.

### 10.4 NEAR AI/IronClaw

- **Pipeline** (README): WASM tool → allowlist → leak scan → credential → execute → leak scan
  → WASM. The leak scanner
  ([`leak_detector.rs`](https://github.com/nearai/ironclaw/blob/b0b999d96781516ee05e6ba961d6f3ead900da96/crates/substrates/ironclaw_safety/src/leak_detector.rs))
  scans before the outbound request and after the response, and has a fuzz target.
- **Egress** ([`network_allowlist.rs`](https://github.com/nearai/ironclaw/blob/b0b999d96781516ee05e6ba961d6f3ead900da96/crates/lanes/ironclaw_sandbox/src/sandbox_process/network_allowlist.rs)):
  a host-owned allowlist where "the worker has no direct route". The default allowlist
  includes package registries.
- **Trade:** local workers run in-process; WASM gives memory isolation for tools, not an OS
  boundary around the agent loop, which holds the decrypted credentials.
- Agent-built tools (described, then compiled to WASM) exist; whether they need approval
  before use was not verified.

### 10.5 OpenFang

- **One process.** The kernel crate depends on the runtime crate as a library
  ([Cargo.toml](https://github.com/RightNow-AI/openfang/blob/acf2587e46be174c10200489c9a2d23a39a98aeb/crates/openfang-kernel/Cargo.toml)),
  so capability checks are in-process checks, not an OS boundary.
- **Capabilities** ([capability.rs](https://github.com/RightNow-AI/openfang/blob/acf2587e46be174c10200489c9a2d23a39a98aeb/crates/openfang-types/src/capability.rs)):
  glob matching over strings; child ⊆ parent is enforced when capabilities are inherited.
- **WASM host functions** ([host_functions.rs](https://github.com/RightNow-AI/openfang/blob/acf2587e46be174c10200489c9a2d23a39a98aeb/crates/openfang-runtime/src/host_functions.rs)):
  the filesystem capability is checked against the raw path, the path is resolved after the
  check, and the file is then opened by path — a decision on one string and an action on
  another lookup. The workspace confinement helper canonicalises and prefix-compares, then
  returns a path to be opened later. Both leave a check/use window that descriptor-held
  resolution closes.
- **Metering** ([sandbox.rs](https://github.com/RightNow-AI/openfang/blob/acf2587e46be174c10200489c9a2d23a39a98aeb/crates/openfang-runtime/src/sandbox.rs)):
  wasmtime fuel and epoch interruption together — a sound design for untrusted WASM.
- **Audit** ([audit.rs](https://github.com/RightNow-AI/openfang/blob/acf2587e46be174c10200489c9a2d23a39a98aeb/crates/openfang-runtime/src/audit.rs)):
  a SHA-256 hash chain, persisted to SQLite when a database is attached.
- **A documented claim that differs from the inspected implementation.** The taint module
  ([taint.rs](https://github.com/RightNow-AI/openfang/blob/acf2587e46be174c10200489c9a2d23a39a98aeb/crates/openfang-types/src/taint.rs))
  describes preventing tainted values from reaching sensitive sinks. At the snapshot, labels
  are assigned only in
  [tool_runner.rs](https://github.com/RightNow-AI/openfang/blob/acf2587e46be174c10200489c9a2d23a39a98aeb/crates/openfang-runtime/src/tool_runner.rs),
  by substring heuristics — shell text containing metacharacters or strings such as
  `curl `, `| sh`, `base64 -d` becomes "external network"; a URL containing `token=` or
  `password=` becomes "secret". We found no taint reference in the web fetch and content
  modules, the WASM host functions, MCP, context or prompt building, the kernel's
  capability code or the memory crate, so no propagation from a source to a sink was found.
  Pattern-derived labels are an output filter, not information flow.
- Ed25519 manifest verification exists; we did not establish that spawning requires it.

### 10.6 OpenLegion

- [docs/security.md](https://github.com/openlegion-ai/openlegion/blob/24efd6e06b28768cbbcd9275f43c479b3df37b18/docs/security.md):
  the mesh host is trusted and agents "will be compromised"; containers are hardened
  (UID 1000, `no-new-privileges`, all capabilities dropped, read-only root, limits).
- **Network:** agents sit on a regular Docker bridge with internet; SSRF protection lives in
  the HTTP tool, with "no kernel-enforced fallback", and a DNS-rebinding race is
  acknowledged.
- **Credentials:** the vault injects credentials server-side for mesh calls, but agent-tier
  credentials are returned in plaintext to agents whose globs allow them.
- **Licence:** PolyForm Perimeter — source-available. It cannot be treated as an
  open-source reference.

### 10.7 Capgate

- [DESIGN.md](https://github.com/jersonboydmilan/Capgate/blob/95c2bd6be4ea7b6975d73a647ba067245651241a/DESIGN.md):
  "may this agent, under this contract, do this, with these arguments, now?" — one
  interception point and one execution path; the executor is the only holder of tool
  credentials.
- **Grants** ([executor.py](https://github.com/jersonboydmilan/Capgate/blob/95c2bd6be4ea7b6975d73a647ba067245651241a/src/capgate/executor.py)):
  signed, single-use (claimed in persistent state), unexpired, bound to agent, contract,
  action and argument hash. Delegation "does not transfer authority"; approvals re-evaluate
  policy, so an expired contract denies despite an approval.
- **Workload identity** ([doc](https://github.com/jersonboydmilan/Capgate/blob/95c2bd6be4ea7b6975d73a647ba067245651241a/docs/workload-identity.md)):
  mTLS with a SPIFFE URI, and tokens bound to the certificate thumbprint, so a token
  replayed from another machine fails.
- **Audit** ([audit.py](https://github.com/jersonboydmilan/Capgate/blob/95c2bd6be4ea7b6975d73a647ba067245651241a/src/capgate/audit.py)):
  hash-chained, verified before it is extended, written before the decision returns — with
  `fsync` off by default, so a crash can lose the record of a decision already acted on.
- **Isolation** ([isolation.md](https://github.com/jersonboydmilan/Capgate/blob/95c2bd6be4ea7b6975d73a647ba067245651241a/docs/isolation.md)):
  internal Docker networks and an iptables rule dropping everything but the proxy; gVisor
  and Kubernetes variants; a CI job with a compromised agent that asserts exactly one
  authorized side effect. `simulate` runs the same engine with no grants minted.
- Created 2026-09-16, twelve days before this research, with a handful of stars: the
  design is informative; the maturity is not established.

### 10.8 Claude Code

- Official [sandboxing documentation](https://code.claude.com/docs/en/sandboxing) (read
  2026-09-29): Seatbelt on macOS, bubblewrap plus a proxy on Linux and WSL2, an optional
  seccomp filter for Unix sockets; native Windows unsupported. No domain is pre-allowed;
  the first new domain prompts. Credentials can be denied or masked, with the proxy
  substituting the real value only for configured hosts — and only from user, managed or
  command-line settings, never from a repository's. The sandbox protects Claude Code's own
  settings, hooks, skills and MCP configuration from sandboxed writes, because a command
  that could edit them "could grant itself permissions".
- **Stated limits:** "not a complete isolation boundary"; hostname-based allowlisting
  without TLS inspection leaves domain fronting and broad domains as exfiltration paths; an
  unsandboxed retry exists unless disabled; in-process tools follow permission rules, not
  the sandbox.

### 10.9 OpenAI Codex

- [`protocol.rs`](https://github.com/openai/codex/blob/c248f6d48b97eb4a2aa56147a0b11b7d763278b9/codex-rs/protocol/src/protocol.rs):
  default approval `OnRequest` — "the model decides when to ask the user for approval";
  network access restricted by default.
- [Linux sandbox](https://github.com/openai/codex/blob/c248f6d48b97eb4a2aa56147a0b11b7d763278b9/codex-rs/linux-sandbox/README.md):
  bubblewrap with a read-only root, writable roots, `.git` and `.codex` re-bound read-only,
  `no_new_privs` and a seccomp network filter.
- [Network proxy](https://github.com/openai/codex/blob/c248f6d48b97eb4a2aa56147a0b11b7d763278b9/codex-rs/network-proxy/README.md):
  HTTP and SOCKS5 with allow and deny lists; private destinations rejected even when a
  hostname is allowlisted.
- [Process hardening](https://github.com/openai/codex/blob/c248f6d48b97eb4a2aa56147a0b11b7d763278b9/codex-rs/process-hardening/src/lib.rs):
  core dumps and ptrace disabled, loader-injection variables stripped — convergent with
  DireWolf's M4e daemon hardening, arrived at independently.

### 10.10 Daytona

- Official documentation (read 2026-09-29): sandboxes are "Linux containers by default"
  (the README separately claims a dedicated kernel; we record the documentation); VM
  sandboxes exist; lifecycle automation (auto-stop, archive, delete, snapshots, recovery).
- **Network:** restricted and not overridable on tiers 1–2; "full internet access is
  available by default" on tiers 3–4; `networkBlockAll` and allowlists available.
- **Credentials:** proxy credentials are exposed inside the sandbox as `HTTP_PROXY`.
- The public repository is frozen; the analysis of current behaviour rests on documentation.

### 10.11 OpenHands

- [README](https://github.com/OpenHands/OpenHands/blob/b9d174c9ca36c27cd0b657779936ea2df29280e9/README.md)
  and [self-hosting](https://github.com/OpenHands/OpenHands/blob/b9d174c9ca36c27cd0b657779936ea2df29280e9/docs/SELF_HOSTING.md):
  now "Agent Canvas", a control centre running OpenHands, Claude Code, Codex and other ACP
  agents locally or remotely, with scheduled and webhook automations. Without a sandbox, the
  agent server "runs directly on the host with full access to the machine's filesystem,
  environment, and network"; Docker and VM backends are available.

---

## 11. The security record, re-verified

Every entry below was re-checked against the project's own advisory or issue on 2026-09-28/29.

| Identifier | Project | Severity | What it was | Status |
|---|---|---|---|---|
| CVE-2026-25253 / [GHSA-g8p2-7wf7-98mq](https://github.com/advisories/GHSA-g8p2-7wf7-98mq) | OpenClaw (as clawdbot) | High (8.8) | The Control UI trusted a `gatewayUrl` query parameter and auto-connected, sending the gateway token to an attacker — one click to remote code execution | Patched in clawdbot 2026.1.29. **Correction:** the previous edition described an unauthenticated `/api/export-auth` endpoint; that description came from secondary reporting and does not match the advisory |
| [GHSA-3mq7-q27j-mq7q](https://github.com/openclaw/openclaw/security/advisories/GHSA-3mq7-q27j-mq7q) | OpenClaw | High | Exec approvals could outlive the working directory they were reviewed for | Published and fixed 2026-09-11 |
| [GHSA-7jfq-rmfm-29wp](https://github.com/openclaw/openclaw/security/advisories/GHSA-7jfq-rmfm-29wp) | OpenClaw | Medium | File-transfer approvals could widen durable authority | Published and fixed 2026-09-11 |
| [GHSA-vhpg-cq3w-v8p9](https://github.com/openclaw/openclaw/security/advisories/GHSA-vhpg-cq3w-v8p9) | OpenClaw | Medium | The OpenAI-compatible transport could send provider credentials to the wrong endpoint | Published and fixed 2026-09-11 |
| [GHSA-5rx7-34fw-64qg](https://github.com/openclaw/openclaw/security/advisories/GHSA-5rx7-34fw-64qg) | OpenClaw | Medium | A Unicode fallback could escape `workspaceOnly` roots | Published and fixed 2026-09-11 |
| CVE-2026-9366 / [GHSA-pgp4-xr4j-h5cg](https://github.com/advisories/GHSA-pgp4-xr4j-h5cg) | Hermes Agent | Medium | Injection in the context scanner (`_scan_context_content`) — the flaw was in the prompt-injection scanner itself | Affected < 0.15.0; **patched in 0.15.0**. **Correction:** the previous edition said no fix existed |
| [Issue #7826](https://github.com/NousResearch/hermes-agent/issues/7826) | Hermes Agent | 4 Critical, 9 High, 9 Medium (per the issue) | Community audit of v0.8.0 in default configuration | Open, labelled P2, on 2026-09-29 |
| [Issue #21425](https://github.com/NousResearch/hermes-agent/issues/21425) | Hermes Agent | — | Prompt injection into the smart-approval reviewer | Closed as not planned (2026-06-26); the code at the snapshot delimits the command. **Correction:** the previous edition said "fixed" |

**Removed from this edition** because they rested on secondary sources only: an advisory
count from a GitHub search, which changes daily and mixes unrelated packages; the claim that
a national authority restricted OpenClaw in state enterprises; a vendor's report of shell
execution on a live deployment; the link-preview exfiltration demonstration as reported by a
news site; and an exposed-instance count from a scanning vendor. Link-preview exfiltration
remains a threat class DireWolf designs for ([THREAT_MODEL.md](THREAT_MODEL.md) AC-7) — the
class does not depend on that report.

---

## 12. The pattern, and what it requires

The verified record still points the same way: the failures are **authorization boundaries
that drift in scope or lifetime** — an approval outliving its directory, a credential sent
to the wrong endpoint, a root escaped through normalisation, a token accepted from a URL, a
scanner that is itself injectable. Each is a check that exists but is enforced at many call
sites, one of which is wrong.

| Observed failure | DireWolf requirement | Status |
|---|---|---|
| Approvals outliving their reviewed scope | Approvals bind to a canonical-action hash; single-use; expiring; agent-bound ([APPROVALS.md](APPROVALS.md)) | PLANNED (M6); until then an approval-requiring action is denied |
| A gate skipped on one path | One enforcement point: every effect crosses the authority ([ARCHITECTURE.md](ARCHITECTURE.md) §8) | IMPLEMENTED for every effect that exists (M4b–M4e); the runtime that must not have a second path is M9 |
| Isolation switching approval off | Sandbox and policy are separate dimensions, both always evaluated ([POLICY.md](POLICY.md)) | PLANNED (M5, M6) |
| A model deciding authorization | Deterministic policy; a model may summarise a request for a human, never decide it | IMPLEMENTED (M3c) |
| Credentials sent to the wrong endpoint | A handle carries an origin allowlist; injection elsewhere is refused ([SECRETS.md](SECRETS.md)) | IMPLEMENTED (M4e); its egress consumer is M5 |
| Unicode or symlink path escape | Resolve by identity with held descriptors; NFC required, never applied ([SANDBOX.md](SANDBOX.md) §3) | IMPLEMENTED (M4a; Linux) |
| A credential-returning endpoint | No operation returns a secret value, at any privilege level | IMPLEMENTED (M4e) |
| An injectable safety scanner | No scanner is a gate: redaction is hygiene, and policy decides on kernel-derived facts | IMPLEMENTED as a rule (M3c, M4e) |

---

## 13. What is now real in DireWolf

Each item is exercised by tests or evidence targets that run the real code, and the
M4 closing hosted run (§1) was green.

1. **A privileged authority process that identifies its caller through the kernel**
   (`SO_PEERCRED`) before reading a byte, with a strict, fuzzed decoder and a hostile-client
   suite of 65 cases (M3e; `make authority-transport-evidence`).
2. **Deterministic policy** with reasons, obligations and a rule source for every decision;
   p99 3.6 µs at 300 rules (M3c).
3. **A capability lattice** where delegation can only narrow: 10⁶ generated chains, zero
   escalations (M3b).
4. **Durable authority state**: fenced epochs, durable idempotent admission, kernel-owned
   policy inputs, and a hash-chained audit record `fsync`ed before the answer
   (M3d; `make authority-state-evidence`); the runtime identity cannot write it
   (`make authority-write-probe`).
5. **Canonical filesystem resolution by identity**, with symlink, magic-link, mount,
   Unicode and swap-race campaigns returning zero escapes (M4a).
6. **Two privileged processes, not one**: the authority decides; the broker acts, reading
   only from the authority's kernel-reported uid, one single-use authorisation per channel,
   one descriptor (M4b).
7. **Eight filesystem tools** with atomic, never-in-place mutation and an `UNKNOWN`
   outcome that is never retried (M4c).
8. **Process execution decided on executable identity** and run from the re-proved
   descriptor — built, tested with real targets, and deliberately unable to launch in a
   production build until approvals exist (M4d).
9. **Secrets by handle only**, read after both gates and a durable intent, handed over once,
   redacted on the way back, and absent from the runtime's memory, both daemons' memory and
   every durable file afterwards (M4e).
10. **Taint that policy can act on**: a monotone run-level level held by the authority,
    raised to `LOCAL_UNVERIFIED` by file content and process output (M3d–M4d), and a
    predicate the shipped `balanced` and `power` packs use to require approval for egress
    from an `EXTERNAL_UNTRUSTED` run — a level only network sources will raise, from M5.
11. **Gates that can fail**: an evidence case that cannot run reports NOT EXERCISED and fails
    the required job; deliberate-failure meta-tests prove each gate rejects a bad result.

**None of this is a sandbox.** M4 contains no execution environment, no network path and no
approval flow; a statement that DireWolf "sandboxes" anything today would be false.

---

## 14. Where DireWolf is behind today

Stated plainly, so no one is misled:

1. **There is no agent.** No loop, no provider, no context engine, no tools an agent calls.
   Every project in §7 except Capgate and Daytona runs tasks today.
2. **There is no sandbox.** IronSecCo/IronClaw, OpenLegion, Codex and Daytona contain what
   the agent runs today; Claude Code, OpenClaw, Hermes Agent and OpenHands can.
   DireWolf's `oci-strict` is M5.
3. **There is no network path**, so no egress allowlist, no SSRF guard in operation and no
   consumer for the secret injection M4e built.
4. **There are no approvals and no budgets.** Every approval-requiring action is simply
   denied, which is safe and not usable.
5. **The runtime's network confinement is designed, not built or owned** until this
   re-baseline (§17 G1).
6. **Linux only.** Serving refuses on macOS and native Windows; the macOS Keychain backend
   is compile-only; there is no fallback path walker.
7. **No release artifacts**: no binaries, SBOM, signatures, provenance or reproducibility
   check — IronSecCo/IronClaw's release workflows produce the last four (§17 G3).
8. **No memory, skills, subagents, MCP, channels, scheduler, browser, plugins or UI** — the
   features that make the agent runtimes in §7 useful.
9. **No deployment history and no independent review.**
10. **Latency, approval frequency and usability are unmeasured** (M3.5), and they decide
    whether anyone will use the result.

**DireWolf is the wrong choice today** for anyone who needs an agent to do work. When V1
exists it will still be the wrong choice for maximum capability, broad channel coverage,
large plugin ecosystems, or a single trusted operator on a machine holding nothing
sensitive — OpenClaw's own framing, "a trusted single-operator assistant", describes a
legitimate product for which it is better suited.

---

## 15. What we take

Ideas, never code. Four classes, so it is clear what this re-baseline changed.

### Already adopted (before 2026-09-28, implemented or in the design)

| Idea | Source | Where it lives in DireWolf |
|---|---|---|
| Strip denied tools' schemas before the model call | OpenClaw | [TOOL_SYSTEM.md](TOOL_SYSTEM.md); M10 acceptance |
| Egress-time secret injection | OpenClaw | [SECRETS.md](SECRETS.md) mode A (render implemented, M4e; consumer M5) |
| Tool policy, environment and escape hatch as separate controls | OpenClaw | Capability × environment in [POLICY.md](POLICY.md) |
| Byte-stable system prompt; compression the only cache break | Hermes Agent | [CONTEXT.md](CONTEXT.md) |
| "Narrow waist": every core tool costs every turn | Hermes Agent | [TOOL_SYSTEM.md](TOOL_SYSTEM.md) footprint ladder |
| Delegation context firewall | Hermes Agent | [ORCHESTRATION.md](ORCHESTRATION.md) |
| Fresh, history-free agent per scheduled run | Hermes Agent | [WORKFLOWS.md](WORKFLOWS.md) |
| SQLite handle quarantine on structural corruption | Hermes Agent | [STORAGE.md](STORAGE.md); authority store quarantine implemented (M3d) |
| Per-session turn lease (DireWolf adds epoch fencing) | Hermes Agent, OpenClaw | Leases and fencing implemented in the authority (M3d) |
| Idempotency keys on side-effecting operations | OpenClaw | `AdmitRun` (M3a) and tool invocations (M4c) |
| Strip Unicode TAG characters from tool results | Hermes Agent | [TOOL_SYSTEM.md](TOOL_SYSTEM.md); M10 |
| Consolidation with a loss-rejection threshold | OpenClaw | [MEMORY.md](MEMORY.md) §6 |
| Candid public limitations | All the projects that publish them | [SECURITY.md](SECURITY.md) §5, this document |

### Planned before, now confirmed by a second source

| Idea | Sources | Owner |
|---|---|---|
| Policy simulation over recorded actions | Capgate `simulate` | M17 ([POLICY.md](POLICY.md) §6) |
| Approval inspection surface | Capgate inspect UI | M6 CLI queue, M27 web UI |
| Content-hash-verified skills; signing only with a registry | OpenFang manifest signing | M11a; V2.x registry |
| Memory provenance and a promotion gate | OpenClaw memory architecture | M13 |
| Egress through an authority-owned proxy | NEAR AI/IronClaw, Capgate, IronSecCo/IronClaw | M5 |
| Hierarchical budgets | No project we read implements them; Hermes Agent's non-subtracted child limit (§10.1) is the gap they close | M6 |
| Remote workers | Capgate, NEAR AI/IronClaw | M28 |
| Pre-main process hardening | Codex | Implemented independently (M4e) |

### Newly adopted by this re-baseline

Each has a ledger entry in §17 and a roadmap item.

| # | Idea | Sources | Owner |
|---|---|---|---|
| G1 | The runtime identity has no network route, verified from that identity | IronSecCo/IronClaw, Capgate | M9 |
| G2 | Sandbox assurance measured inside the environment; a failed invariant refuses the environment; weakened-profile meta-tests | IronSecCo/IronClaw (as a measurement, not a score) | M5; `doctor --sandbox` at M17 |
| G3 | Release integrity: SBOM, provenance, signing, reproducibility, generated third-party notices | IronSecCo/IronClaw; DireWolf's own licence review | M18 |
| G4 | `direwolf policy diff` — decision deltas between two policies over recorded actions | Capgate (`simulate`) | M17 |
| G5 | `direwolf security demo` — a scripted hostile runtime whose every attempt is shown with its denying audit record | Capgate, IronSecCo/IronClaw live demonstrations | M17 |
| G6 | Recall-loop prevention and unattended-session gating in memory | OpenClaw | M13 |
| G7 | Domain fronting through an allowlisted shared host stated as a residual of the opaque tunnel | Claude Code's documented limits | M5 (documented now) |

### Studied and rejected

See §16.

---

## 16. What we reject, and why

| Pattern | Seen in | Why DireWolf does not do it |
|---|---|---|
| A model deciding an approval | Hermes Agent `smart` mode; Codex `OnRequest` (the model decides when to ask) | An authorization decision made by a component that reads attacker-controlled text is advisory. A model may summarise a request for a human; it never decides |
| Choosing a sandbox switches authorization checks off | Hermes Agent container backends | Isolation bounds the damage of an allowed action; it does not decide whether the action is allowed. Both apply, always |
| A weighted containment score | IronSecCo/IronClaw `ironctl scan` | A weighted sum lets a failed invariant be averaged away: a writable root at a small weight still earns a passing grade. DireWolf reports each invariant PASS/FAIL, and one FAIL refuses the environment (§17 G2) |
| Pattern-derived taint presented as information flow | OpenFang | Labels from substrings of a command are a filter a rephrasing defeats. DireWolf derives taint from where content came from, in the authority, never from what the content looks like |
| Plaintext, runtime-readable credentials by default | Hermes Agent, OpenClaw (default), OpenLegion agent tier | Invariant I3 |
| Native plugins in the privileged process | OpenClaw, Hermes Agent | V1 ships no plugins; M26 plugins are out-of-process |
| Agent-built tools and autonomous capability packages in V1 | NEAR AI/IronClaw dynamic tools; OpenFang Hands | Agent-authored code that later runs with authority is a persistence mechanism until a validation pipeline exists (M25) |
| Unrestricted host execution as the default | Hermes Agent, OpenClaw, OpenHands | Host execution needs operator opt-in and a per-invocation approval (M4d floor) |
| Default bridge egress with application-layer SSRF only | OpenLegion | A guard in the tool is bypassed by any code path that does not use the tool; the route itself must not exist (M5 `PROXY_ONLY`, §17 G1) |
| A security gate that skips, without failing, when its environment is missing | IronSecCo/IronClaw containment job | An unexercised case reports NOT EXERCISED and fails a required gate — DireWolf's rule since M3d |
| Audit written without durability | Capgate (`fsync` off by default) | A record lost in a crash after the effect is the record an investigation needs; DireWolf `fsync`s before answering |
| Encrypted queues between host and agent on one machine | IronSecCo/IronClaw | On one host, a private Unix-domain socket whose peer the kernel identifies gives the boundary without key management; revisit for remote workers (M28) |
| A multi-host authority database | Capgate (PostgreSQL with a cluster lock) | V1 is one host; distributed authority state is a different trust problem, deferred with remote workers (M28) |

---

## 17. Gap ledger

Every candidate idea from the research, with its decision. Fields: **SOURCE** · **IDEA** ·
**DIREWOLF CURRENT STATE** · **REAL GAP?** · **DECISION** · **TARGET MILESTONE** · **WHY** ·
**ACCEPTANCE EVIDENCE** · **DOCS TO UPDATE**.

**G1 — Runtime-identity network confinement**
- SOURCE: IronSecCo/IronClaw (`network=none` sandbox), Capgate (agent reaches only the proxy).
- IDEA: the process that reasons has no network route at the operating-system level.
- DIREWOLF CURRENT STATE: stated as an actual control in [ARCHITECTURE.md](ARCHITECTURE.md) §6 and assumed by [NETWORK_SECURITY.md](NETWORK_SECURITY.md) §1 ("where the platform supports it"); **no milestone owned it and nothing tests it.** The runtime does not exist yet.
- REAL GAP?: **Yes.** Without it, budgets, privacy routing and egress policy are advisory for any code the runtime can be made to run.
- DECISION: **ADOPT.**
- TARGET MILESTONE: **M9** (the first milestone that launches the real runtime).
- WHY: the runtime needs no network: model egress is performed by the authority (M7), and its only peer is the authority's Unix socket.
- ACCEPTANCE EVIDENCE: from the real runtime identity, TCP, UDP, raw and packet sockets, DNS resolution and any connection except the authority socket fail; a CI job runs it under a real separate identity; where the platform cannot enforce it, the reduced assurance is reported, never assumed. Adversarial: a prompt-injected `socket()`, `getaddrinfo`, an abstract Unix socket aimed at the broker, an inherited descriptor, a child process.
- DOCS TO UPDATE: ROADMAP M9; NETWORK_SECURITY §1; ARCHITECTURE §6; EVALS §3; PRODUCT_SPEC §6 criterion 2.

**G2 — Measured sandbox assurance**
- SOURCE: IronSecCo/IronClaw (`ironctl scan`; the weakened-sandbox regression guard).
- IDEA: check the environment a run actually got, and prove the check can fail.
- DIREWOLF CURRENT STATE: `AssuranceLevel` is declared by the environment ([SANDBOX.md](SANDBOX.md) §1); M5 acceptance already says defaults are "verified at runtime, not merely configured", with no mechanism named.
- REAL GAP?: **Yes** — the mechanism and its failure proof.
- DECISION: **ADOPT WITH DIFFERENT DESIGN.** No weighted score (§16): each hard rule of SANDBOX §2 is a PASS/FAIL probe run inside the environment by an authority-provided, read-only, digest-checked probe; the effective assurance is the lower of declared and measured; a failed required invariant refuses the environment and is audited.
- TARGET MILESTONE: **M5** (probe and refusal); **M17** (`direwolf doctor --sandbox`).
- WHY: a configuration that looks hardened and a running container that is not are the gap between IronSecCo/IronClaw's configuration scan and its containment harness; DireWolf needs the second kind.
- ACCEPTANCE EVIDENCE: a weakened-profile meta-test per hard rule — bridge network, writable root, an added capability, unconfined seccomp, a mounted container socket — each of which must fail the gate. Adversarial: configuration that differs from runtime state; a tampered probe.
- DOCS TO UPDATE: ROADMAP M5, M17; SANDBOX §1, §6; EVALS §3.

**G3 — Release integrity and third-party notices**
- SOURCE: IronSecCo/IronClaw release and reproducibility workflows; DireWolf's own licence review (2026-09-28).
- IDEA: every distributed binary comes with an SBOM, a provenance attestation, a signature, a reproducibility check and the notices its linked closure requires.
- DIREWOLF CURRENT STATE: source-only distribution; no tags; `cargo-deny` checks licences and advisories; nothing generates attribution; reproducible builds deferred since M2; the root [NOTICE](../NOTICE) states the obligations.
- REAL GAP?: **Yes**, at the first binary release. `cargo-deny` answers "is this licence allowed?", not "is the attribution shipped?".
- DECISION: **ADOPT.**
- TARGET MILESTONE: **M18** (V1 hardening), before any binary is distributed.
- WHY: the authority links third-party crates (the broker too, on Linux); MIT, BSD and Apache licences require their notices with binary copies.
- ACCEPTANCE EVIDENCE: per-platform archives; THIRD_PARTY_NOTICES generated per binary and platform from the locked, linked closure; SBOM (CycloneDX and SPDX) equal to the linked closure; provenance and signature verified from a clean machine; a reproducibility comparison. Adversarial: an allowed-licence dependency with missing attribution fails; a platform-only dependency is not omitted; a tampered archive fails verification; SBOM drift fails.
- DOCS TO UPDATE: ROADMAP M18; CONTRIBUTING (dependencies); SECURITY §7; NOTICE; THREAT_MODEL R8.

**G4 — `direwolf policy diff`**
- SOURCE: Capgate (`simulate` runs the same engine with no grants minted).
- IDEA: before a policy change, show which decisions change.
- DIREWOLF CURRENT STATE: `policy test` and `simulate` planned at M17; no diff.
- REAL GAP?: **Yes** — a rule-level text diff hides reordering and composition effects.
- DECISION: **ADOPT.**
- TARGET MILESTONE: **M17.**
- WHY: first-match evaluation makes order significant; `extends` makes composition significant; both are invisible in a text diff.
- ACCEPTANCE EVIDENCE: rule-level changes plus the decision delta produced by the same evaluator over the fixture corpus and recorded canonical actions. Adversarial: a reorder-only change that alters a first match; an `extends` change; an obligation removed.
- DOCS TO UPDATE: ROADMAP M17; POLICY §6.

**G5 — `direwolf security demo`**
- SOURCE: Capgate (compromised-agent job), IronSecCo/IronClaw (live containment demonstration).
- IDEA: a zero-credential scripted hostile runtime, runnable by any user, printing each attempt with the audit record that denied it.
- DIREWOLF CURRENT STATE: the hostile-client suites exist as CI evidence, not as a user-facing command.
- REAL GAP?: **Yes**, for inspectability: an operator should be able to see the boundary hold on their own machine.
- DECISION: **ADOPT.**
- TARGET MILESTONE: **M17.**
- WHY: a claim a user can re-run is worth more than a badge.
- ACCEPTANCE EVIDENCE: non-zero exit if any attempt succeeds; an attempt that cannot run is NOT EXERCISED and fails; runs in CI; a weakened configuration makes it fail.
- DOCS TO UPDATE: ROADMAP M17; EVALS §3.

**G6 — Memory: recall-loop prevention and unattended-session gating**
- SOURCE: OpenClaw memory architecture.
- IDEA: content recalled from memory is never re-extracted as a new candidate; scheduled and subagent sessions produce no semantic-scope candidates without approval.
- DIREWOLF CURRENT STATE: provenance chains, minimum-trust consolidation and human approval for untrusted promotion are designed (M13); neither mechanism is.
- REAL GAP?: **Yes.** Recall amplification is a laundering path the provenance rule alone does not close: a recalled untrusted item re-extracted as "new" could lose its chain.
- DECISION: **ADOPT WITH DIFFERENT DESIGN** — enforced by the authority's provenance record, not by session labels the runtime could set.
- TARGET MILESTONE: **M13.**
- WHY: I5 must hold across recall, not only at first write.
- ACCEPTANCE EVIDENCE: adversarial recall amplification, re-extraction laundering and a scheduled run writing memory — zero untrusted promotions without approval.
- DOCS TO UPDATE: ROADMAP M13; MEMORY §5; EVALS §3.

**G7 — Domain fronting through an allowlisted shared host**
- SOURCE: Claude Code's documented sandbox limits.
- IDEA: hostname allowlisting without TLS inspection cannot see the inner request.
- DIREWOLF CURRENT STATE: the M5 CONNECT tunnel is opaque by design and checks CONNECT target and SNI agreement ([NETWORK_SECURITY.md](NETWORK_SECURITY.md) §1); fronting was not named as a residual.
- REAL GAP?: **Yes, documentation**: the residual existed and was not stated.
- DECISION: **ADOPT** — state it now; bound it with M5's byte budgets and connection counts; keep credential-bearing requests on `net.http`, where the authority is the client.
- TARGET MILESTONE: stated now; bounded at **M5.**
- ACCEPTANCE EVIDENCE: NETWORK_SECURITY and THREAT_MODEL name the residual; M5's egress evidence shows the byte budget bounding a tunnel to an allowlisted host.
- DOCS TO UPDATE: NETWORK_SECURITY §1; THREAT_MODEL §9.

**G8 — Workload identity and signed remote permits**
- SOURCE: Capgate (mTLS, SPIFFE-style identity, certificate-bound tokens), NEAR AI/IronClaw (per-job worker authorization).
- IDEA: a remote executor proves possession of a key, and each remote effect carries a single-use permit bound to the canonical action.
- DIREWOLF CURRENT STATE: one host; the broker is identified by the kernel's peer credentials; no remote workers.
- REAL GAP?: Not for V1; yes for M28.
- DECISION: **DEFER** to M28: key-possession workload identity; permits bound to the canonical action digest, the epoch, the broker identity and an expiry, with a durable nonce; encrypted host–worker transport; multi-host authority state considered there, not before.
- DOCS TO UPDATE: ROADMAP post-V1 table.

**G9–G16 — ideas already addressed** (no roadmap change)

| # | Source | Idea | DireWolf state | Decision |
|---|---|---|---|---|
| G9 | NEAR AI/IronClaw | Leak scan on the outbound request | Mode A keeps the value out of every process the agent influences; return-path redaction implemented | ALREADY ADDRESSED DIFFERENTLY (I3, M4e) |
| G10 | OpenClaw SecretRefs; NEAR AI/IronClaw | Credential bound to endpoint | Origin and consumer binding | ALREADY IMPLEMENTED (M4e) |
| G11 | OpenFang, Capgate | Delegation only attenuates | Typed lattice, 10⁶ chains | ALREADY IMPLEMENTED (M3b) |
| G12 | IronSecCo/IronClaw | The agent cannot change its own configuration | The runtime identity cannot write `kernel.db`, the audit log or policy, verified by attempting it | ALREADY IMPLEMENTED (M3d write probe) |
| G13 | IronSecCo/IronClaw, Capgate | Private control-plane access | Kernel-reported peer identity on a Unix socket | ALREADY IMPLEMENTED (M3e) |
| G14 | Claude Code | The sandbox cannot write the agent's own settings, hooks or skills | The allowlisted-interpreter problem and protected paths | ALREADY PLANNED ([SANDBOX.md](SANDBOX.md) §4a; EVALS "allowlisted interpreter"; M5, M10) |
| G15 | OpenFang, NEAR AI/IronClaw | WASM tool sandbox with fuel and epoch metering | No plugin surface in V1 | DEFER (M26 candidate for out-of-process plugins) |
| G16 | IronSecCo/IronClaw, OpenFang | Pre-main daemon hardening | Core dumps off, non-dumpable | ALREADY IMPLEMENTED (M4e; convergent with Codex) |

---

## 18. Gap → roadmap traceability

| Gap | Decision | Roadmap | Docs changed with this re-baseline |
|---|---|---|---|
| G1 runtime network confinement | ADOPT | M9 deliverable, acceptance, adversarial | [NETWORK_SECURITY.md](NETWORK_SECURITY.md) §1, [ARCHITECTURE.md](ARCHITECTURE.md) §6, [EVALS.md](EVALS.md) §3, [PRODUCT_SPEC.md](PRODUCT_SPEC.md) §6 |
| G2 measured sandbox assurance | ADOPT WITH DIFFERENT DESIGN | M5 deliverable, acceptance, adversarial; M17 `doctor --sandbox` | [SANDBOX.md](SANDBOX.md) §1, §6, [EVALS.md](EVALS.md) §3 |
| G3 release integrity and notices | ADOPT | M18 deliverable, acceptance, adversarial | [NOTICE](../NOTICE), [CONTRIBUTING.md](../CONTRIBUTING.md), [SECURITY.md](SECURITY.md) §7, [THREAT_MODEL.md](THREAT_MODEL.md) §9, [PRODUCT_SPEC.md](PRODUCT_SPEC.md) §5 |
| G4 `policy diff` | ADOPT | M17 | [POLICY.md](POLICY.md) §6, [PRODUCT_SPEC.md](PRODUCT_SPEC.md) §5 |
| G5 `security demo` | ADOPT | M17 | [EVALS.md](EVALS.md) §3, [PRODUCT_SPEC.md](PRODUCT_SPEC.md) §5 |
| G6 memory recall loops, session gating | ADOPT WITH DIFFERENT DESIGN | M13 | [MEMORY.md](MEMORY.md) §5, [EVALS.md](EVALS.md) §3 |
| G7 domain fronting residual | ADOPT (documentation) | M5 adversarial | [NETWORK_SECURITY.md](NETWORK_SECURITY.md) §1, [THREAT_MODEL.md](THREAT_MODEL.md) §9 |
| G8 workload identity, remote permits | DEFER | M28 note | — |

Nothing in this re-baseline changes production code, the protocol, or an accepted ADR.

---

## 19. Measurable criteria for any comparative claim

No comparative claim ships without evidence of the stated type. Methodology:
[BENCHMARKS.md](BENCHMARKS.md).

| Claim | Evidence type | Threshold | Falsifiable? |
|---|---|---|---|
| Containment of a named threat class | The security probe set run against every system that can run it, default and hardened postures both disclosed | DireWolf's own release gate is 100 % contained and audited ([EVALS.md](EVALS.md) §3). For *comparative* reporting, raw counts per system and configuration; below 95 % contained DireWolf makes no comparative claim at all | Yes |
| Authority is inspectable | Structural — by inspection | 100 % of effects produce an audit record naming the matched rule | Yes |
| Delegation cannot escalate | Property test and adversarial eval | 0 escalations across 10⁶ generated chains | Yes |
| Budgets are enforceable | Adversarial eval | 0 successful overruns | Yes |
| Memory cannot be poisoned into durable trust | Poisoning suite, including recall amplification (G6) | 0 untrusted items reach semantic scope without approval | Yes |
| Comparable task success | Capability-parity task set | Within 15 % of competitors on tasks all can run | Yes |
| "More secure" in general | **No claim.** Security is per threat class, per configuration, per measurement | — | No — so it is not said |

**No comparative security claim is possible today**: DireWolf cannot run a task, so the
probe set has nothing to compare. The earliest point at which one could be measured is
after M10 (tools) and M5 (sandbox); publication is a V2.x item.

---

## 20. Keeping this document honest

- **Refresh** at each milestone closure that changes a DireWolf row, and before any public
  comparison. A refresh re-pins every snapshot commit and re-verifies every label; a label
  not re-verified becomes UNVERIFIED rather than staying as it was.
- **No automated collection.** No CI job scrapes or polls another project; research is a
  person reading primary sources.
- **Corrections are recorded**, as §10.2 and §11 do, rather than silently replaced.
- **Superlatives are banned**: this document ranks nothing and names no overall winner.

---

## 21. Analyst conclusion

DireWolf is no longer merely a paper architecture: M4 has demonstrated its local
authority/broker narrow waist on real hosted identities. However, it is not yet a complete
autonomous-agent platform, and it currently trails mature competitors substantially in
execution isolation, product features and ecosystem, because M5+ are not complete. Its
differentiating architectural hypothesis is now partially measurable, but the complete
target thesis cannot be judged until at least sandbox, approvals, provider egress and
runtime paths exist.

The landscape is wider than the previous edition's two subjects. Putting authority on the
far side of an OS boundary is not unique to DireWolf: in 2026-09 IronSecCo/IronClaw, Capgate
and OpenLegion ship forms of it, and OpenClaw implements the memory provenance that edition
called DireWolf's differentiator. What remains specific to DireWolf is a set
of narrower mechanisms — decisions on canonical objects, an authority/broker split, audit
made durable before the answer, every policy input held by the authority — which M3 and M4
built and measured. Whether they add up to a safer *agent* is the question M5–M10 exist to
answer, and until then this document makes no claim that they do.
