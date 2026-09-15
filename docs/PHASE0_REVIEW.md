# Phase 0 Final Review

Three independent adversarial review tracks were run against the completed specification: **security**, **architecture / implementability**, and **reliability / product**. Reviewers were briefed to find flaws, told that "this looks good" is a failed review, and given no stake in defending the design.

They found **62 substantive issues, 8 of them critical.** Two mechanisms turned out to be unbuildable as specified. One defect — introduced *during* Phase 0, by a fix intended to close a different hole — violated the architecture's central invariant.

This document records every finding and its disposition. It is kept because a review whose findings are quietly absorbed is indistinguishable from a review that found nothing.

**Disposition key:** **FIXED** — the specification changed · **ACCEPTED** — real, scheduled to a milestone · **NOTED** — real, documented as a known limit · **REJECTED** — with a reason.

---

## The four findings that changed the architecture

### 1. Policy inputs lived where the constrained process could write them — **FIXED**

*Security track, CRITICAL.*

Mid-review I fixed a bug where the session lease epoch — the value that fences a zombie runtime — lived in `runtime.db`, which the runtime can write. I wrote a paragraph explaining why that was fatal, and applied the reasoning **to exactly one field.**

`taint_level`, `origin`, `privacy_class`, `workspace.sensitivity`, the active skill set, skill trust levels, and artifact and memory provenance are all policy inputs, and all were runtime-writable. A compromised runtime could set `taint_level = NONE` after reading a hostile page, `origin = interactive` for an unattended run, or an empty skill set (which, since skills only narrow, *maximises* the capability intersection). Every taint-conditioned rule, every `require_untainted_run` standing grant, and the taint warning on the approval prompt would stop functioning — silently.

**Fix:** every policy input is derived and stored kernel-side ([DATA_MODEL.md](DATA_MODEL.md) §1). `runtime.db` keeps caches; divergence is audited. Added as architectural principle 10 and invariant I10, phrased generally so it cannot be applied to one field again: *anything the kernel reads from the runtime and then decides on is authority the runtime holds.*

### 2. `McpSend` was a second path to effect — **FIXED**

*Security track, CRITICAL.*

Earlier in Phase 0 I noticed the runtime had no way to speak to MCP servers and added kernel operations to relay JSON-RPC frames. I wrote a justification explaining that this *avoided* a second path.

It created one. A relayed frame `{"method":"tools/call","params":{"name":"write_file",...}}` **is** a tool invocation. Relaying it opaquely means it never reaches canonicalisation, policy, capabilities, approvals, budget or audit. A filesystem MCP server would have been a complete second filesystem path.

**Fix:** the kernel owns the MCP protocol, not merely the process. `McpOpen` handshakes and returns ordinary `ToolDefinition`s; invocation is a normal `ToolInvoke`; the kernel builds the frame from the canonical action. Server-initiated `sampling`/`elicitation`/`roots` are refused.

**And a rule, because this will recur:** every new DWKP operation must carry a written argument for why it is not a second path, reviewed by someone other than its author. The general tell: *an operation that relays bytes the kernel does not interpret cannot police what those bytes do.* ADR-0000 predicted this drift; it appeared before any code was written.

### 3. The egress proxy could not be reached by any client — **FIXED**

*Architecture track, CRITICAL.*

The sandbox had "no network interface; its only route is a Unix domain socket into the kernel's proxy, speaking HTTP CONNECT / SOCKS5." **No mainstream HTTP client can address a proxy over a Unix socket** — `http_proxy` takes `host:port`, and curl, git, pip, npm, cargo and Go's `net/http` all require a TCP endpoint. Stacked on top: TLS termination requiring a DireWolf CA in the sandbox trust store, which breaks every client carrying its own bundle.

**Fix:** two honestly separated paths ([NETWORK_SECURITY.md](NETWORK_SECURITY.md) §1). `net.http` is **performed by the kernel** — full inspection, credential injection, artifact capture. Sandbox egress is a CONNECT proxy on a TCP listener inside the sandbox's own network namespace, **opaque**: host and SNI checked, IP guard applied, byte-capped, no credentials, no content inspection. Less visibility than claimed, and a real design rather than an impossible one. Side benefit: `npm install` and `pip install` now work against allowlisted registries, which the previous blanket `network_deny` made impossible.

### 4. Taint only ever rose, and that would have killed the product — **FIXED**

*Architecture track, identified as "the thing that will actually kill this project."*

`taint_level` rose on untrusted content and had no declassification, decay, scoping or override anywhere in the corpus. Apply it to the actual product: a cloned repository is content the user did not write. Either repo files taint — in which case every run is tainted by turn two, every standing grant stops applying (`require_untainted_run` is the default), and the "≤ 2 approvals" criterion fails — or they do not, in which case the apparatus is inert in 90 % of cases and fires only on explicit web reads, where it is most infuriating.

Worse, the relief valve was nailed shut: the quarantined reader, the strongest defence in the document, *still raised taint*. **Correct behaviour did not buy the run back.** A control that cannot be satisfied by doing the right thing is a control users route around — ending exactly where ADR-0000 says the project dies.

**Fix** ([CONTEXT.md](CONTEXT.md) §5), three parts: taint has **tiers** (`LOCAL_UNVERIFIED` for content the operator pointed the agent at, `EXTERNAL_UNTRUSTED` for content the agent chose to reach — the distinction is *who introduced it*, not a claim about trustworthiness); taint is a property of the **current context manifest**, not run history, so it falls when tainted content is evicted or compacted out; and `direwolf run declassify` is an explicit audited operator act after seeing the content.

---

## Security track — remaining findings

| ID | Finding | Disposition |
|---|---|---|
| C3 | **Every allowlisted interpreter executes workspace-controlled code.** `pytest`→`conftest.py`, `git`→`core.pager`/hooks, `npm`→lifecycle scripts, `cargo`→`build.rs`, `python3`→`sitecustomize.py`. Arbitrary execution inside the sandbox with no approval; `(path, sha256)` identifies the binary but not the config it reads | **FIXED + NOTED** — [SANDBOX.md](SANDBOX.md) §4a states plainly that the sandbox, not the allowlist, is the boundary; adds `workspace_exec_hygiene` (neutralises auto-loaded config) and approval-gated control-surface paths. The honest part: exec argv scoping is a blast-radius and auditability control, **not confinement** |
| H1 | `ModelCall` carried an opaque `HttpRequestSpec`, making `model.call` a transitive unpoliced bidirectional network channel | **FIXED** — typed structure; kernel renders the request from the provider profile |
| H4 | Taint and obligations absent from the approval binding hash: approve while clean, read a hostile page, spend the approval within its TTL | **FIXED** — `taint_level`, `privacy_class`, `obligations` added to the binding |
| H5 | Approval response authenticated by a nonce that travels *through* the relay, so a compromised gateway could forge one | **FIXED** — device-key MAC established out of band at pairing; a compromised relay can suppress but not forge |
| H6 | `fs.patch` writes N attacker-chosen paths from one authorised call; only the target root was canonicalised | **FIXED** — every path inside the diff resolved under the pinned root; symlink, mode and control-surface hunks rejected whole-patch |
| H7 | Exec'd processes read and write the whole workspace mount with no per-file check, so sub-workspace `fs.*` scoping is unenforceable once `process.exec` is granted — falsifying the audit-completeness claim | **FIXED (claim corrected)** — [OBSERVABILITY.md](OBSERVABILITY.md) §1 now says *absence means nothing crossed the kernel boundary*; activity inside a recorded exec is not individually recorded |
| H8 | `GIT_WORKTREE` shares `.git` config and hooks with the parent — either the isolation claim is false or git does not work | **FIXED** — subagent workspaces are clones with their own `.git`; `--shared`/`--reference` refused |
| H9 | `force_quarantined_read` had no obligation, no predicate field, and the reader had no `model.call` so could not summarise | **FIXED** — obligation added; kernel enforces by delivering bytes only to a freshly-minted reader run; reader holds bounded `model.call` |
| H10 | The security suite tests *model-driven* attacks exclusively; nothing tests a hostile DWKP client, which is the architecture's stated assumption | **FIXED** — hostile-client suite added as an **M3** merge gate. C1, C2, H1, H2, H3 would each have been caught by it and by nothing else |
| M1 | The TCB contains more hostile-input parsers than "smallest privileged surface" admits | **FIXED by the kernel split** (below) |
| M2 | Channel URL extraction is a parser-parity race with each platform's auto-linker, described as "closes" the channel | **NOTED** — narrows, does not close; wording corrected |
| M3 | "Unknown fields preserved" applied to the authority protocol is a parser-differential surface | **ACCEPTED** — DWKP will reject unknown fields; forward-compat retained for DWCP and the event log. M2 |
| M4 | Exec verified by hash but launched by path; shebang and dynamic-linker paths unaddressed | **ACCEPTED** — `fexecve` on the hashed fd; `LD_*` env denial. M4 |
| M5 | `tool.intent_recorded` ownership contradictory; a runtime-owned copy is a repudiation primitive | **FIXED** — kernel `audit.log` is the sole oracle ([RELIABILITY.md](RELIABILITY.md) §1) |
| M6 | MCP server-initiated requests entirely absent from the threat model | **FIXED** — refused in V1 |
| M7 | Terminal-control phishing: the agent shares the TTY the kernel draws approvals on | **FIXED** — kernel takes the terminal to raw mode and suspends runtime output while drawing; ANSI stripped on `ChannelSend` |
| M8 | The content-addressed store is a cross-session existence oracle via dedup timing | **NOTED** — added to residual risks; low severity, high cost to fix |
| L1–L6 | Skills lack a V1 milestone; trace context is untrusted kernel input; policy clock source unstated; `PLUGINS.md` diagram contradicts the banned-import rule; missing THREAT_MODEL row | **L3, L6 FIXED** (clock source, threat row). **L1, L2, L5 ACCEPTED** to M1/M11/M26 |

---

## Architecture track — remaining findings

| ID | Finding | Disposition |
|---|---|---|
| §2 | **`dwkd` is a monolith with a security label** — twelve subsystems, including HTML/CSV/source excerpting of attacker-chosen content, in the same address space as the credentials and the capability MAC key | **FIXED** — split into `dwkd-authority` (deciders; no parsers, no network stack, no container client; holds `kernel.db`, `audit.log`, keys) and `dwkd-broker` (executors; fds, sockets, containers; no long-lived key). This is also what makes ADR-0001's Rust argument proportionate: the defended component is now small enough for "minimal auditable dependency set" to be a fact |
| §1 | **Three of five Rust justifications do not survive.** Dependency minimalism is asserted (15–40 crates) but unaudited against the actual job list (~250–400 with `bollard`+`hyper`+`rustls`); "Python cannot scrub secrets" argues against a strawman (`bytearray` works); "seccomp via ctypes" is moot because the V1 default path makes **zero** isolation syscalls — it configures Docker over HTTP | **PARTIALLY ACCEPTED** — the kernel split makes the dependency claim true for `dwkd-authority`, which is the component the argument is about. What survives honestly: `openat2` canonicalisation, sum types/newtypes, single static CLI binary. Recorded in the review rather than quietly repaired; ADR-0001 needs a revision noting the narrowed rationale |
| C1 | **Policy purity vs inode matching is unimplementable.** An inode is a point, not a subtree; there is no inode prefix relation. "Never a string prefix" made the design look more solid than it was | **FIXED** — [POLICY.md](POLICY.md) §3: canonicaliser resolves once, workspace root pinned by `(dev, ino)` at admission, policy prefix-matches the canonical path under that pinned root. Identity check is real and lives in the canonicaliser; the engine stays pure |
| C2 | "The runtime has no sockets" is false (`kernelclient` needs one), and `import-linter` is a static check a runtime `exec()` walks past | **RESOLVED at M1** — the OS-level restriction is the control; the lint is hygiene. The caveat now appears in `architecture.toml`, `dwcheck --help`, `CONTRIBUTING.md`, the checker's docstring and [ARCHITECTURE.md](ARCHITECTURE.md) §6 |
| C3 | Tool visibility recomputed per turn mutates the P0-pinned prefix and destroys prompt caching | **ACCEPTED** — visibility is computed once at admission and only *narrows* mid-run, with narrowing deferred to the next compaction boundary. M10/M11 |
| C14 | Tool handlers have nowhere to run: the kernel executes, so the Python handler is vestigial | **ACCEPTED** — registry holds definitions only for kernel-executed tools. M10 |
| §3 | Premature abstraction: `ChannelAdapter` (interface in an unbuilt component, CLI is Rust and cannot implement it, capability set is Telegram-shaped); `ExecutionEnvironment` signature shaped for local processes; compensation (no V1 tool has a meaningful inverse); event upcasters and multi-version compat CI with zero released versions; the general constraint lattice where a closed enum of the ~8 constraints actually used would be safer *and* would actually get the sum-type benefit | **ACCEPTED, all** — cut list for M1 scope review. The `ChannelAdapter` finding retracts a claim I made twice: "the CLI is a channel adapter so the abstraction is exercised" is wrong when the CLI is the degenerate case in a different language |
| §4 | **V1 is 24–30 months for three engineers, not 12.** Kernel 33–40 k lines vs 18–25 k stated. `evals/` is a merge gate with no owning milestone. The riskiest assumption is first measurable at M17 | **FIXED** — [ROADMAP.md](ROADMAP.md) "Timeline, honestly" accepts the estimate; adds **M2.5** (eval harness) and **M3.5** (vertical slice, measured and published, existing to retire the top risk before another eighteen months are spent) |
| §5 | p99 < 5 ms unreachable with `synchronous=FULL` (macOS `F_FULLFSYNC` is 10–30 ms alone); the worked trace in `OBSERVABILITY.md` omits the audit span entirely and shows a 30 µs budget reserve that cannot be a durable write; cold start < 400 ms impossible with Python imports plus O(history) audit verification | **FIXED** — [PRODUCT_SPEC.md](PRODUCT_SPEC.md) §9 restated: 5 ms for read-only, **15–40 ms side-effecting**, durability chosen over latency on macOS and said so; cold start 1–2 s cold; audit verification incremental against a signed checkpoint |
| §6 | Tool-layer components cannot be tested independently (definition in Python, execution in Rust); crash injection across a process boundary needs a harness nobody owns; false-memory rate and digest fidelity are unfalsifiable CI gates; the security suite cannot run in a 10-min PR budget | **FIXED** — harness owned by M2.5; CI split into PR-deterministic and post-merge-full; unfalsifiable gates demoted to sampled human adjudication |
| C5–C9, C16, C17 | Milestone numbers disagreed across four documents; `CONTEXT.md` contradicts itself on budget-remaining; artifact CAS diagram contradicts its own rule; vector example demonstrates a V1.1 feature; two of five memory stores do not exist in V1; `∪` with a declared non-set; AC-8 posits a fan-out the limits already prevent | **MOSTLY FIXED** — milestones reconciled, diagram corrected. C4, C8, C9, C16 **ACCEPTED** as wording cleanups |

---

## Reliability / product track — remaining findings

| ID | Finding | Disposition |
|---|---|---|
| A1 | **Budget re-reserved on every resume, never released on crash.** Four crashes on a flaky laptop → 5× budget reserved → `BUDGET_EXHAUSTED` on a run that spent under a dollar, silently, fail-closed | **FIXED** — `ReconcileBudgetLease`; budget leases expire and are reclaimed; child reservations return on *any* terminal outcome |
| A3 | **Nothing established that the runtime cannot reach the workspace at the OS level** — and `direwolf init` casually printed "kernel user", when creating one is privileged on all three platforms | **FIXED** — [PRODUCT_SPEC.md](PRODUCT_SPEC.md) §6a: two install modes, the single-user fallback documented as `ProcessIsolation` with `doctor` saying so permanently. Most people will run the fallback; pretending otherwise produces a worse outcome than documenting it |
| A4 | Container-runtime restart (Docker Desktop auto-update) kills every sandbox at once → mass `UNKNOWN` | **FIXED** — re-attach by run-id label rather than reap; `Unobservable` distinguished from "exited"; bulk resolution |
| A5 | Budget hard stop contradicted itself: "no new model calls" and "one final turn" | **FIXED** — summarisation reserve withheld at admission |
| A6 | No lease TTL, no renewal; a run blocked on a 1-hour approval loses its lease, and the human's approval does nothing | **FIXED** — 60 s TTL, `Heartbeat` renewal, approval-wait exemption |
| A9 | `UNKNOWN` resolution unusable: no result payload, no "I don't know", no bulk, and it silently expires with the run | **FIXED** — `indeterminate`, `--result-file`, `--all`, `approve --list`, and exemption from `resume_deadline` |
| A10 | The approval TTY mechanism — the delivery path for the headline security property — was one clause, and a daemon does not own the operator's terminal | **FIXED** — fd passed via `SCM_RIGHTS`, validated as untrusted input, raw mode during draw |
| A11 | Every expiry is wall-clock; a backward NTP step resurrects expired approvals, violating a stated property test. "Monotonic" ambiguous across suspend | **FIXED** — `CLOCK_BOOTTIME` named; dual wall+monotonic comparison; kernel supplies time |
| A12 | Ingress idempotency is keyed on `external_id`, which **V1's only interface does not have** — so the one duplicate-execution path that ships is the one uncovered | **ACCEPTED** — CLI submission key at M17 |
| A15 | `DRAINING` unbounded: Ctrl-C one second into a ten-minute run could wait ten minutes, making `--force` the reflex | **FIXED** — 30 s bounded grace, displayed |
| A16 | Expired approvals counted toward the fatigue counter, so a run could be terminated and its work discarded because the operator went to lunch | **FIXED** — expiry suspends; only explicit denials count |
| A18 | Effects with no settle point (long-lived processes, progressive message edits, streaming output) are outside intent-before-effect | **FIXED** — added to "what we do not promise"; `detached` declaration excludes long-lived processes from reaping |
| A19 | `fs.write` atomicity omitted the parent-directory fsync; atomic replacement is not atomic composition | **FIXED** — both stated; workspace *restored* to checkpoint revision on resume |
| A14 | `RETRY_WITH_KEY` cannot be verified by local crash injection — it is a property of the remote | **FIXED** — must name the endpoint and its idempotency contract, else degrades to `NON_RETRYABLE` |
| A20 | Cron had no timezone | **FIXED** — mandatory IANA tz, fires keyed in UTC |
| B1 | **V1 could not do unattended work, which is the entire reason the named primary persona would tolerate it** | **FIXED** — persona split V1/V1.1 honestly; **detached runs** added to V1 as the minimum unattended path |
| B2 | The "≤ 2 approvals" criterion fails against the shipped profile — realistically ~15: a nine-binary allowlist missing `uv`/`ruff`/`make`, `max_uses=1` on a *broad* scope, `argv_safe` tripping on `$` in a commit message, per-file delete approvals contradicting the one-prompt mock, and `network_deny` breaking `npm`/`cargo` | **FIXED** — allowlist widened to ~38; `max_uses` scales with scope breadth (20 for `executable_and_argv`); `PathSet` scope for batch deletes; `argv_safe` redefined as re-interpretation rather than metacharacters; `network_deny` removed in favour of host allowlisting |
| B3 | V1 unusable rather than limited: no dependency installation, `git push` over SSH unsupported and unstated, the `researcher` template needs a browser V1 lacks, and the core tool set was "~15" and never enumerated | **MOSTLY FIXED** — dependency installation works via the egress redesign; the inventory is enumerated and frozen at **18** (TOOL_SYSTEM §3). **NOTED:** SSH push and the `researcher`/`security-reviewer` templates are genuinely V1.2-dependent and are now marked as such |
| B5 | Claims with no measurement: "no second path" (no mechanism), "overhead vs unmediated < 10 %" (no unmediated build exists, and the metric passes trivially because model latency dominates), false-denial rate (no ground truth), duplicate-effect count contradicting the stated non-guarantee, and containment stated as both 100 % and ≥ 95 % | **FIXED** — overhead criterion replaced with measured targets at M3.5; thresholds reconciled; model re-issue excluded from duplicate-effect; false-denial demoted to sampled adjudication |
| B6 | **The adoption path.** Two plausible strategies — sell to buyers who need the audit trail (ruled out by the no-enterprise non-goal) or **ship `dwkd` as a standalone authority daemon other runtimes delegate to** (foreclosed by coupling DWKP to DireWolf's own runtime) | **NOTED — unresolved, and the most important open question.** Recorded in §Unresolved below rather than answered, because it is a product decision, not an architectural one |

---

## What I got right, per the reviewers

Recorded because a review record listing only failures is as misleading as one listing only successes: ADR-0000's thesis and the one-enforcement-point rule; tool visibility as a policy output rather than a prompt instruction; kernel-rendered approval prompts with model prose quarantined below the fold; `environment_profile_id` and `credential_handles` in the binding hash (each closes a specific documented real-world bug class); subtractive budgets; memory's structural backstop; refusing to blind-retry on `UNKNOWN`; no `bash(command: string)`; the requirement that every deny rule has a *negative* test; SQLite quarantine-on-corruption; and the honesty discipline in BENCHMARKS §7 and THREAT_MODEL §9.

---

# Phase 0.1 reconciliation — final disposition ledger

Every finding above now has a terminal state. **Nothing is ambiguous going into M1.** Four states are used: **RESOLVED** (specification changed in Phase 0.1), **SCHEDULED** (owning milestone named), **RESIDUAL** (accepted limitation, documented), **SUPERSEDED** (overtaken by another decision).

## New ADRs (12)

[0018](adr/0018-authority-broker-split.md) authority/broker split · [0019](adr/0019-language-rationale-v2.md) language v2 · [0020](adr/0020-provider-request-path-v2.md) typed `ModelCall` · [0021](adr/0021-approval-binding-v2.md) approval binding v2 · [0022](adr/0022-approval-response-authentication.md) approval response auth · [0023](adr/0023-dwkp-strict-schema.md) DWKP strict · [0024](adr/0024-sandbox-network-topology.md) `PROXY_ONLY` · [0025](adr/0025-subagent-workspace-clone.md) workspace clones · [0026](adr/0026-tool-visibility-and-cache-stability.md) visibility + cache · [0027](adr/0027-audit-scope-boundary.md) audit scope · [0028](adr/0028-policy-input-ownership.md) policy-input ownership · [0029](adr/0029-packaging-runtime-first-decoupled-authority.md) packaging.

**Fully superseded:** 0001 → 0019 · 0002 → 0020 · 0007 → 0021.
**Partially superseded:** 0005 (visibility timing) → 0026 · 0008 (network) → 0024 · 0013 (workspace) → 0025 · 0016 (DWKP compat) → 0023.
**Amended:** 0000 → 0018 · 0004 → 0022 · 0006, 0012 → 0028 · 0017 → 0027.

## Disposition of every open item

| Item | State | Where |
|---|---|---|
| **Sec M3** — DWKP unknown fields | **RESOLVED** | [ADR-0023](adr/0023-dwkp-strict-schema.md); PROTOCOL §1 per-protocol table; ROADMAP M2 acceptance split into three tests |
| **Sec M4** — `fexecve` on the hashed fd; shebang + `LD_*` | **SCHEDULED M4** | Named in the M4 deliverable; env allowlist must exclude `LD_PRELOAD`/`LD_LIBRARY_PATH` |
| **Sec M2** — channel URL parser parity with platform auto-linkers | **RESIDUAL** | Documented as "narrows, does not close." Per-platform linkers cannot be replicated exactly; Telegram `entities[]` handled explicitly |
| **Sec M8** — CAS dedup timing as an existence oracle | **RESIDUAL** | Low severity, high fix cost. Added to THREAT_MODEL residual risks |
| **Sec L1** — skills had no V1 milestone | **RESOLVED** | [SKILLS.md](SKILLS.md) §0 five-way split; new **M11a** owns static skills; M25 owns synthesis+validation |
| **Sec L2** — untrusted trace context into the kernel | **SCHEDULED M18** | Trace context is parsed strictly and never re-exported with `export_content` |
| **Sec L3** — policy clock source | **RESOLVED** | POLICY §4: kernel supplies time, never the runtime |
| **Sec L5** — PLUGINS diagram contradicted banned-import rule | **RESOLVED** | Redrawn to the authority→broker→plugin shape; kernel owns the plugin protocol |
| **Sec L6** — missing THREAT_MODEL row | **RESOLVED** | TB2→TB4 table now carries the false-policy-input row |
| **Arch §1** — Rust rationale overstated | **RESOLVED** | [ADR-0019](adr/0019-language-rationale-v2.md); LANGUAGE_SELECTION carries a superseded-rationale banner. **We do not claim Python is memory-unsafe** |
| **Arch §2** — kernel monolith | **RESOLVED** | [ADR-0018](adr/0018-authority-broker-split.md); diagram, module tree and responsibilities all split |
| **Arch C1** — policy purity vs inode matching | **RESOLVED** | POLICY §3 "How path matching actually works": canonicaliser resolves, root pinned by `(dev,ino)`, engine prefix-matches |
| **Arch C2** — "runtime has no sockets" | **RESOLVED** | ARCHITECTURE §6: `kernelclient` is the exception; the lint is hygiene, the **OS restriction is the control** |
| **Arch C3** — visibility vs cache | **RESOLVED** | [ADR-0026](adr/0026-tool-visibility-and-cache-stability.md); TOOL_SYSTEM §4 incl. emergency-revocation semantics |
| **Arch C14** — tool handlers vestigial | **SCHEDULED M10** | For kernel-executed tools the registry holds definitions only; the `handler` slot is `None`. Recorded in the M10 deliverable |
| **Arch §3** — `ChannelAdapter` premature | **RESOLVED (cut)** | Claim removed from ARCHITECTURE §27; interface deferred to M20 and designed against two real channels. No cross-language shim invented |
| **Arch §3** — `ExecutionEnvironment` over-general | **RESOLVED (cut)** | `ssh`/`microvm` removed from the design set; trait designed against `oci`+`local`; rewrite accepted when remote execution is real |
| **Arch §3** — compensation | **RESOLVED (cut)** | Removed from V1 with its three task states and `failure_policy=COMPENSATE`; `UNKNOWN` + reconciliation replaces it |
| **Arch §3** — upcasters + multi-version CI | **RESOLVED (cut)** | Only "unknown events retained verbatim" and "projections rebuildable" ship in V1 |
| **Arch §3** — open constraint lattice | **RESOLVED (cut)** | CAPABILITIES §2: closed set of **eight** constraints with hand-written containment |
| **Arch §3** — `CanonicalPreview` no consumer | **RESOLVED** | Consumer named: `policy simulate` and the approval `[w]hy` branch |
| **Arch §4** — timeline / eval ownership | **RESOLVED** | ROADMAP "Timeline, honestly"; **M2.5** eval harness, **M3.5** vertical slice |
| **Arch §5** — performance claims | **RESOLVED** | PRODUCT_SPEC §9 split by path; ROADMAP M17 cold-start acceptance normalised |
| **Arch §6** — unfalsifiable CI gates; suite too slow for PR | **RESOLVED** | EVALS §8 PR/post-merge split; false-memory and digest-fidelity demoted to sampled adjudication |
| **Arch C4** — budget-remaining contradiction | **RESOLVED** | CONTEXT §2 now says "budget **ceilings**" |
| **Arch C5** — milestone numbers | **RESOLVED** | Reconciled across all documents |
| **Arch C6** — artifact CAS diagram | **RESOLVED** | Diagram shows broker writes, runtime reads by id |
| **Arch C8** — vector example was V1.1 | **RESOLVED** | `memory explain` example shows FTS5-only with a V1.1 note |
| **Arch C9** — two of five memory stores not in V1 | **RESOLVED** | Stated in MEMORY §1 and ARCHITECTURE §21 |
| **Arch C12** — MCP transport undefined | **RESOLVED** | Kernel owns the MCP client; `McpOpen` returns `ToolDefinition`s; server-initiated requests refused |
| **Arch C13** — egress proxy unbuildable | **RESOLVED** | [ADR-0024](adr/0024-sandbox-network-topology.md) `PROXY_ONLY` |
| **Arch C16** — `∪` with a declared non-set | **RESOLVED** | CAPABILITIES §5 renders approvals as a separate side table |
| **Arch C17** — AC-8 fan-out of 200 | **RESOLVED** | Corrected to the profile-permitted shape; the real risk named as budget amplification |
| **Rel A12** — CLI has no `external_id` | **SCHEDULED M17** | CLI submission key, so V1's only interface gets duplicate-submission protection |
| **Rel B3** — SSH push; `researcher`/`security-reviewer` templates | **RESIDUAL** | SSH push needs `fd_at_spawn` + host-key policy (V1.2). Both templates are marked browser-dependent and not fully usable in V1 |
| **Prod B6** — packaging | **RESOLVED** | [ADR-0029](adr/0029-packaging-runtime-first-decoupled-authority.md): runtime-first, authority decoupled by three testable constraints |
| **Tool inventory** — 15 / 17 / 18 / 19 disagreement | **RESOLVED** | **18**, canonical table in TOOL_SYSTEM §3; every other document derives from it. `fs.create` is a capability verb, not a tool |

## Unresolved questions carried into Phase 1

1. **Packaging.** Is DireWolf an agent runtime, or is it an authority kernel that agent runtimes delegate to? The genuinely novel artifact is `dwkd`; the runtime scores B against two mature A's. Shipping the kernel would turn 630 k stars of competition into distribution — and would require decoupling DWKP from DireWolf's own runtime shape. **Not answered here.**
2. Whether the Rust/Python split survives its own narrowed rationale (architecture track §1). ADR-0001 needs revision, not defence.
3. Whether ~2 years to V1 is acceptable, or whether the scope should be cut to the kernel plus a reference runtime.
4. Whether taint tiers plus declassification actually hold the approval budget at a tolerable level. **M3.5 answers this with measurement, and it is the milestone most likely to kill the design.**
5. Whether the single-user install fallback — which most people will run — retains enough of the property to be worth the friction.
