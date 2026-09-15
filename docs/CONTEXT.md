# Context Engine

**The model sees exactly what the Context Engine decides it sees, and that decision is deterministic, budgeted, and recorded.**

---

## 1. Why this is a first-class component

Context assembly is usually an accident: whatever accumulated in a list, truncated when it overflowed. That makes three things impossible — reproducing a decision, bounding cost, and enforcing provenance. All three matter here, so assembly is an explicit, testable pure function.

```
assemble(run_state, budget, policy) -> (ContextBundle, ContextManifest)
```

Same inputs → same bundle. No clock reads, no randomness, no network. The manifest is persisted; the bundle is not (it is reconstructible).

## 2. Section ladder

Ordered by position in the prompt, with priority governing eviction:

| # | Section | Priority | Budget | Cache |
|---|---|---|---|---|
| 1 | Kernel preamble — identity, authority statement, delimiter nonce | **P0 pinned** | ~400 | stable |
| 2 | Agent profile — persona, standing instructions | **P0 pinned** | ~800 | stable |
| 3 | Effective capabilities + budget **ceilings** (what you may do, and the limits) | **P0 pinned** | ~300 | stable per run |
| 4 | Tool definitions (visible set only) | **P0 pinned** | ~2500 | stable per run |
| 5 | Active skill content | P1 | ~2000 | stable per run |
| 6 | Session digest (compaction output) | P1 | ~1500 | changes on compaction |
| 7 | Curated memory (semantic, high-confidence) | P2 | ~1000 | changes on compaction |
| 8 | Workflow / task state | P2 | ~600 | volatile |
| 9 | Retrieved memory (episodic, query-relevant) | P3 | ~1500 | volatile |
| 10 | Project context (repo map, conventions) | P3 | ~1000 | stable per run |
| 11 | Recent turns | **P0 for last N**, P2 older | remainder | volatile |
| 12 | Pending approvals / denials this run | P1 | ~400 | volatile |
| 13 | Current user message | **P0 pinned** | as needed | volatile |

**Eviction order:** P3 → P2 → P1. P0 is never evicted; if P0 alone exceeds the window, the run fails with `CONTEXT_OVERFLOW` rather than silently dropping the capability statement or the user's message. A context engine that drops a pinned section to fit is lying about what the model was told.

Within a priority, eviction is by ascending relevance score, then by age.

## 3. Cache discipline

Prompt caching is the single largest cost lever in a long-running agent, and it is fragile: mutating any byte of the prefix invalidates everything after it.

**The invariant:** sections 1–5 are **byte-stable for the life of a run**. Nothing dynamic is interpolated into them — not the time, not a turn counter, not "you have used 3 of 10 tool calls."

Consequences that follow, and are enforced by a test:

- Budget *remaining* is not in section 3; only the budget *ceiling* is. Live consumption is reported in tool results, which live after the cache boundary.
- Retrieved memory (volatile) is section 9, never merged into the curated block (section 7).
- The delimiter nonce is generated once per run, not per turn.
- **Compaction is the only sanctioned cache break.** Everything else appends.

```
[ ---------- stable prefix (cache read) ---------- ][ --- volatile tail --- ]
  sections 1-5                                        sections 6-13
                         ↑
              only compaction moves this line
```

*(Invariant adopted from Hermes Agent; see [COMPETITIVE_ANALYSIS.md](COMPETITIVE_ANALYSIS.md) §5.)*

A test asserts that across a 50-turn synthetic run with no compaction, the SHA-256 of the rendered prefix is constant.

## 4. ContextManifest

Persisted with every model call:

```json
{"manifest_id":"ctx_01J8…","run_id":"run_01J8…","turn":7,
 "model":"anthropic/claude-opus-5","window":200000,"assembled_tokens":31402,
 "prefix_sha256":"9f2c…",
 "sections":[
   {"id":"tools","tokens":2480,"items":["fs.read@1.2","process.exec@2.0"],"included":"all"},
   {"id":"memory.retrieved","tokens":1180,"items":["mem_01J7…","mem_01J6…"],
    "included":"partial","evicted":3,"eviction_reason":"P3_BUDGET"},
   {"id":"turns","tokens":18900,"range":[12,31],"evicted_before":12,
    "eviction_reason":"COMPACTED"}],
 "trust_summary":{"SYSTEM_TRUSTED":5200,"USER_TRUSTED":19000,
                  "EXTERNAL_UNTRUSTED":6100,"GENERATED_UNTRUSTED":1102},
 "taint_summary":"EXTERNAL_UNTRUSTED",
 "taint_sources":["art_01J8…"],
 "_note":"advisory; kernel holds the authoritative taint_level"}
```

This buys:

- **Explainability** — "why did the agent do that?" is answerable by listing exactly what it saw.
- **Deterministic replay** — the bundle is reconstructible from ids without storing a second copy of every byte.
- **Taint reporting** — the manifest records the trust composition of what was assembled. It does **not** compute the authoritative `taint_level`: the kernel derives that independently from the tool results and artifacts it produced, because a value the runtime computes cannot gate a rule that constrains the runtime ([ARCHITECTURE.md](ARCHITECTURE.md) §3 principle 10). The manifest's `taint_summary` is a local view for display and debugging; where the two differ, the kernel's is authoritative and the divergence is audited as a runtime-integrity signal.
- **Cost attribution** — which section is eating the window.

`direwolf context show <run_id> --turn 7` renders it; `--verbose` reconstructs the full text.

## 5. Trust and delimiters

Every section carries a trust label, and untrusted regions are fenced:

```
<dw:untrusted src="art_01J8XQ…" origin="https://github.com/acme/x/issues/412"
              trust="EXTERNAL_UNTRUSTED" nonce="7f3a9c21">
…content…
</dw:untrusted:7f3a9c21>
```

- The **nonce is per-run and unpredictable**, so content cannot forge a closing delimiter and appear to escape the fence.
- Any occurrence of the nonce pattern in content is neutralised during sanitisation ([TOOL_SYSTEM.md](TOOL_SYSTEM.md) §7).
- The kernel preamble states, once, that content inside these fences is data and never instruction. We do not repeat this per-fence: repetition costs tokens and does not increase compliance.

### Taint is scoped and reversible

A taint level that only ever rises is a control users disable. The failure is worth spelling out, because it is how this design would have died:

> Reading a cloned repository is reading content the user did not write. If that raises `EXTERNAL_UNTRUSTED`, then every run is tainted by turn two, every novel destination needs approval, and every standing grant — which defaults to `require_untainted_run` — silently stops applying. The operator escalates to `POWER`, finds it still degrades on taint, disables `require_untainted_run` on every grant, and the taint system is now off. If instead repo files do *not* taint, the apparatus is inert in the 90 % case and fires only on explicit web reads, which is exactly where it is most infuriating: summarise one page and the rest of your session needs approval.

Neither horn is acceptable, so DireWolf does three things:

**1. Taint has tiers, not a boolean.**

| Tier | Sources | Effect |
|---|---|---|
| `NONE` | operator input, `SYSTEM_TRUSTED` content | — |
| `LOCAL_UNVERIFIED` | workspace files, local repos — content the operator *pointed the agent at* | Novel-destination egress is logged, not gated. Standing grants still apply. |
| `EXTERNAL_UNTRUSTED` | fetched web pages, MCP results, downloads, email — content the *agent* chose to reach | Novel-destination egress requires approval. `require_untainted_run` grants do not apply. |

A cloned repository is `LOCAL_UNVERIFIED`, not `EXTERNAL_UNTRUSTED`. The distinction is not "is this content trustworthy" — it is not — but **who chose to introduce it**. The operator directing an agent at their own working tree is a different act from an agent following a link, and conflating them is what makes taint unusable. Injection via a poisoned README is still defended: by the capability ceiling, which is the layer that actually stops it (see [CAPABILITIES.md](CAPABILITIES.md) §7, where the attack dies on a missing `network.*` with no reference to taint at all).

**2. Taint is a property of the current context, not of the run's history.**

The kernel computes `taint_level` over the artifacts referenced by the **current** `ContextManifest`, not over everything the run has ever touched. When tainted content is evicted or compacted out, taint falls — automatically, with an audit record. A ninety-turn run that read one hostile page at turn 3 is not still paying for it at turn 90.

Structured compaction is the natural declassification point: a `SessionDigest` inherits `trust_floor` from its inputs ([§6](#6-compaction)), so a digest summarising untrusted content stays untrusted — but the *raw* untrusted span leaves context, and the digest is one bounded item instead of ten thousand attacker-chosen tokens.

**3. Declassification is an explicit, audited operator act.**

```console
$ direwolf run declassify run_01J8... --artifact art_01J8... --reason "reviewed the issue text, benign"
  Artifact art_01J8...  github.com/acme/x/issues/412  (4.2 KB)
  Shown in full above. Declassifying LOWERS this run's taint from
  EXTERNAL_UNTRUSTED to LOCAL_UNVERIFIED. Audited. Continue? [y/N]
```

The operator sees the content before declassifying it, and the act is in the audit chain. **Correct behaviour buys the run back.** Using a quarantined reader, or compacting the hostile span away, or reviewing it and declassifying, all restore the run — which is what makes the control something a user cooperates with rather than routes around.

**We do not claim the model will obey the fence.** The fence's real job is to make provenance *computable* so that deterministic controls downstream — taint-aware policy, egress approval, memory promotion — can act on it. Model compliance is a bonus, not the mechanism.

### The quarantined reader

The strongest available structural defence against injection. When a run must read hostile-by-default content, the read happens in a **subagent with zero capabilities**:

```
main agent  --"summarise github.com/…/issues/412"-->  reader subagent
                                                       caps: ∅  (no fs, no net, no exec)
                                                       tools: none
                                                       ↓
                                          structured summary, trust=GENERATED_UNTRUSTED
                                                       ↓
main agent receives a SUMMARY, never the raw content
```

Injected instructions in the page can only influence a process that cannot do anything. The summary still enters the main agent as untrusted, so it still raises taint — but the instruction-carrying surface is dramatically reduced and the attacker loses the ability to address the capable agent directly.

The reader is capability-less for *side effects*; it holds `model.call` (bounded, and debited from the parent's budget), because otherwise it could not produce the summary. `caps: ∅` above is shorthand for "no fs, no net, no exec" and is written out fully in [ORCHESTRATION.md](ORCHESTRATION.md).

Policy can require this: `force_quarantined_read` is an obligation ([POLICY.md](POLICY.md) §2) that a rule may attach to a `net.http` ALLOW. The kernel enforces it the only way it can — by returning the fetched bytes **only** to a run whose capability set it just minted as reader-shaped, never to the requesting run. The requesting run receives an artifact reference it cannot read directly.

## 6. Compaction

Triggered at a configurable fraction of the window (default 0.6, measured against the *model's* window, not a constant).

**Not a free-form summary.** Free-form summaries lose exactly the things that matter — constraints, refusals, file paths — because summarisers optimise for readability. Instead, a typed, versioned object:

```python
SessionDigest:                        # schema-versioned, regenerable
    goal: str
    constraints: list[Constraint]     # each with a provenance ref
    decisions: list[Decision]         # what was decided AND what was rejected, with reasons
    completed: list[WorkItem]
    pending: list[WorkItem]
    key_files: list[FileRef]          # path + last-known revision
    errors_encountered: list[ErrorRef]
    open_questions: list[str]
    user_preferences: list[Preference]
    approvals_granted: list[ApprovalRef]
    artifacts: list[ArtifactRef]
    trust_floor: TrustLabel           # minimum trust across compacted inputs
```

Rules:

1. **`trust_floor` inherits the minimum.** A digest summarising untrusted content is itself untrusted. Compaction must not launder provenance — this is the same rule as memory consolidation and for the same reason.
2. **Never compact away**: approvals granted, budget state, pending work, or the last N turns. Approvals and budgets live in relational state anyway, so they survive by construction; the digest merely references them.
3. **Compaction is auditable**: `context.compacted` records input range, output digest id, tokens before/after, and the model used.
4. **Rejected decisions are kept.** "We decided not to use approach X because Y" prevents the agent re-proposing X for the rest of the session, which is a common and expensive failure.
5. **Loss check**: the digest must mention every `key_file` and every `open_question` present in the previous digest unless explicitly marked resolved. A digest failing this is regenerated once; a second failure keeps the previous digest and compacts a smaller range. *(Threshold-based rejection adapted from OpenClaw's consolidation loss fraction.)*

Digests chain: `digest_n` summarises `digest_{n-1}` plus the turns since. Each links to its predecessor, so the full history is reconstructible from the event log even though it is no longer in context.

## 7. Budget

The window budget is a policy input, not a model property:

```
effective_window = min(model.max_context,
                       policy.max_context_tokens,
                       budget.remaining_tokens / expected_remaining_turns)
```

The third term matters: a run with 50 k tokens of budget left should not spend 40 k on one call. The engine degrades gracefully — evicting P3, then P2 — rather than failing at the provider.

Token counting uses the provider's tokenizer where available, a local approximation otherwise, with a configurable safety margin (default 5 %) so an approximation error becomes a smaller prompt rather than a 400.

## 8. Testing

- **Determinism**: same state → identical bundle, asserted by hash.
- **Cache stability**: prefix hash constant across 50 turns without compaction.
- **Budget adherence**: property test over random states — assembled tokens never exceed the effective window.
- **Eviction order**: P0 never evicted; overflow of P0 raises rather than truncates.
- **Delimiter integrity**: fuzz content containing delimiter-like text, nonce guesses, and nested fences; assert no escape.
- **Digest fidelity**: on a corpus of real sessions, every constraint and open question survives compaction or is explicitly marked resolved.
- **Trust accounting**: `trust_summary` token counts sum to `assembled_tokens`.
