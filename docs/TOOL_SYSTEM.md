# Tool System

---

## 1. ToolDefinition

```python
@dataclass(frozen=True)
class ToolDefinition:
    name: str                    # canonical, namespaced: "fs.read", "process.exec"
    version: str                 # semver; schema changes bump minor, semantics bump major
    description: str             # written for the model; part of the prompt budget
    args_schema: JsonSchema
    result_schema: JsonSchema

    side_effect: SideEffectClass # PURE | READ | WRITE | DESTRUCTIVE | EXTERNAL
    risk: RiskClass              # metadata for policy rules, never an authority source
    capabilities: list[CapabilityPattern]   # what it needs; may be argument-dependent
    environment: EnvRequirement  # ANY | SANDBOX_REQUIRED | HOST_ONLY
    network: NetworkRequirement  # NONE | PROXY | DIRECT_FORBIDDEN
    credentials: list[SecretHandlePattern]

    timeout_s: int
    max_output_bytes: int
    inline_budget_bytes: int     # above this, spill to artifact

    retry: RetryClass            # RETRY_SAFE | RETRY_WITH_KEY | NON_RETRYABLE | UNKNOWN
    idempotency: IdempotencyKind # NATURAL | KEYED | NONE
    resumable: bool
    compensation: CompensationSpec | None

    audit: AuditLevel            # HASH_ONLY | FULL_ARGS | FULL_ARGS_AND_RESULT
```

Several fields exist purely so the kernel and the reliability layer do not have to guess:

- **`side_effect`** drives parallelism (only `PURE`/`READ` batch concurrently) and cancellation semantics.
- **`retry` + `idempotency`** drive crash recovery. `UNKNOWN` is treated as `NON_RETRYABLE`; the default for a new tool is `UNKNOWN`, so forgetting to think about it fails safe.
- **`compensation`** lets a tool declare how to undo itself during `DRAINING`.
- **`capabilities`** may be a function of arguments — `fs.read` needs `fs.read:<the actual path>`, computed by the canonicaliser, not by the tool. As implemented for `fs.read` at M4b: `fs.read:<canonical path>?max_bytes=<the requested bound>&no_symlink_targets=true`, derived by the authority; the request states neither ([ADR-0043](adr/0043-m4b-private-broker-channel-and-brokered-fs-read.md)). `fs.read` is the only tool with a wire form; the rest of this inventory is design.

## 2. Registry

Explicit registration, not import-side-effect registration:

```python
registry.register(ToolDefinition(...), handler=fs_read_handler)
```

Import-time self-registration makes the available tool set depend on import order and makes it hard to answer "what tools exist?" statically. Ours is a declarative table assembled at startup and dumpable with `direwolf tools list --json`.

**No giant dispatch.** `registry.resolve(name) -> (definition, handler)`. Adding a tool touches one file plus a registration entry, never a `match` in the loop.

### Namespacing

| Prefix | Source |
|---|---|
| `fs.`, `process.`, `net.`, `memory.`, `agent.`, `artifact.` | built-in |
| `mcp.<server_id>.<tool>` | MCP-discovered |
| `plugin.<plugin_id>.<tool>` | plugin (V2) |
| `skill.<skill_id>.<tool>` | skill-provided script |

Collisions are impossible by construction, and the prefix tells the model — and the operator reading an audit log — where a tool came from.

## 3. The footprint ladder

Every tool definition is sent on every model call. A tool is not free; it costs tokens on every turn of every run forever, and it enlarges the surface the model can reach for. Before adding a **core** tool, exhaust in order:

1. Can an existing tool do it with different arguments?
2. Can it be a **skill** (instructions + scripts driving existing tools)?
3. Can it be an **MCP server** the user opts into?
4. Can it be a **plugin** (V2)?
5. Only then: a core tool, with an ADR note justifying it.

*(Pattern adapted from Hermes Agent's "narrow waist" doctrine — see [COMPETITIVE_ANALYSIS.md](COMPETITIVE_ANALYSIS.md) §5.)*

### The canonical V1 tool inventory — **18 tools**

This table is the single source of truth. Every other document derives from it; none restates it with a different count. `fs.create` is a **capability verb**, not a tool — `fs.write` requires `fs.write` on the target and additionally `fs.create` when the target does not exist, which lets policy express "may modify existing files but not add new ones" without a second tool.

| # | Tool | Side effect | Retry class |
|---|---|---|---|
| 1 | `fs.read` | READ | `RETRY_SAFE` |
| 2 | `fs.list` | READ | `RETRY_SAFE` |
| 3 | `fs.search` | READ | `RETRY_SAFE` |
| 4 | `fs.stat` | READ | `RETRY_SAFE` |
| 5 | `fs.write` | WRITE | `RETRY_SAFE` (atomic: temp → fsync → rename → fsync dir) |
| 6 | `fs.patch` | WRITE | `RETRY_SAFE` (base-revision checked) |
| 7 | `fs.move` | WRITE | `NON_RETRYABLE` |
| 8 | `fs.delete` | DESTRUCTIVE | `NON_RETRYABLE` |
| 9 | `process.exec` | varies; declared per invocation | `UNKNOWN` → treated as `NON_RETRYABLE` |
| 10 | `process.status` | READ | `RETRY_SAFE` |
| 11 | `process.kill` | WRITE | `NON_RETRYABLE` |
| 12 | `net.http` | EXTERNAL | `RETRY_SAFE` for GET; `RETRY_WITH_KEY` otherwise, endpoint-declared |
| 13 | `memory.search` | READ | `RETRY_SAFE` |
| 14 | `memory.propose` | WRITE | `RETRY_SAFE` (dedup on content hash) |
| 15 | `agent.spawn` | WRITE | `NON_RETRYABLE` |
| 16 | `agent.join` | READ | `RETRY_SAFE` |
| 17 | `artifact.read` | READ | `RETRY_SAFE` |
| 18 | `artifact.create` | WRITE | `RETRY_SAFE` (content-addressed) |

Counts by family: filesystem 8, process 3, network 1, memory 2, orchestration 2, artifacts 2 — **8+3+1+2+2+2 = 18.**

Notably absent by design: a `bash`/`shell` tool taking a command string. `process.exec` takes `argv` as an array. String-to-shell is argument injection with extra steps, and it makes canonical argv — which approvals bind to — impossible to compute reliably.

## 4. Tool visibility is a policy output

**At run admission**, the kernel returns the set of tools currently permitted for this run, and **only those schemas are sent**. A denied tool is invisible, not refused.

```
visible_tools = { t ∈ registry
                : capability_may_cover(run.caps, t)
                ∧ policy.preflight(t, admission_ctx) ≠ DENY
                ∧ environment_available(t) }
```

**Computed once, at admission; may only narrow thereafter** ([ADR-0026](adr/0026-tool-visibility-and-cache-stability.md)). An earlier draft recomputed this before *every* model call, which mutates the byte-stable cached prefix that tool definitions live in ([CONTEXT.md](CONTEXT.md) §3) — a full prompt-cache invalidation every turn, on the single largest cost lever in a long-running agent.

Narrowing mid-run (an MCP server died, an environment became unavailable, a budget dimension is exhausted) takes effect in the prefix at the **next cache boundary** — a compaction, or run end. Until then the stale schema stays visible and calling it returns a structured denial.

**Emergency revocation is immediate regardless.** When a capability is revoked, a standing grant withdrawn, or a budget exhausted, the kernel denies affected invocations **from the next call onward**. The model may still see a schema it can no longer use; it cannot use it. There is no window in which a revoked capability is honoured. Visibility is a cost and guidance optimisation — it has never been the enforcement mechanism.

Why this matters: asking a model to honour a refusal is asking an untrusted component to enforce policy. Removing the schema makes the tool structurally unavailable — the model cannot call what it cannot see, and it stops burning turns proposing actions that will be denied.

`REQUIRE_APPROVAL` tools **stay visible**, annotated as requiring approval, so the agent can plan around the friction and explain it to the user rather than being surprised.

*(Pattern adopted from OpenClaw's pre-model schema stripping.)*

## 5. Invocation lifecycle

```
validate args (JSON Schema, runtime-side — never trust provider validation)
  → attach capability token
  → kernel: canonicalise → policy → capability → approval → budget → secrets
  → TOCTOU re-verify → execute in environment
  → capture: cap size → scrub secrets → sanitise → classify MIME → spill to artifact
  → audit → settle budget → return ToolResult
```

### ToolResult

```python
ToolResult:
    ok: bool
    content: str | None            # bounded, already excerpted
    artifact_ref: ArtifactId | None
    truncated: bool
    total_bytes: int
    mime: str
    trust: TrustLabel              # provenance of the CONTENT, not of the tool
    provenance: ProvenanceChain
    error: StructuredError | None
    usage: ToolUsage               # duration, bytes, exit code, budget consumed
```

Errors are structured and model-readable, including denials:

```json
{"ok": false, "error": {
  "kind": "POLICY_DENIED",
  "reason": "OUTSIDE_WORKSPACE",
  "detail": "fs.read of /etc/passwd: path is outside workspace /workspace/project-x",
  "required_capability": "fs.read:/etc/passwd",
  "would_satisfy": null,
  "retryable": false}}
```

Telling the model *why* and *whether an approval could help* is deliberate: an agent that knows it will never get `/etc/passwd` stops trying, and an agent that knows an approval exists can ask the human for the right thing. Denials are teaching signals, not just failures.

## 6. Output control

No tool returns unbounded output. In order:

1. **Hard cap** at `max_output_bytes`; the process is killed if it exceeds it.
2. **Full output → artifact** (content-addressed, sha256).
3. **Structure-aware excerpt** to the model, chosen by MIME:

| Content | Excerpt strategy |
|---|---|
| Logs / stdout | head 100 lines + tail 100 lines + a line-count marker |
| Compiler/test output | error and failure lines first, then head/tail |
| JSON | schema sketch + first N elements + total count |
| CSV/TSV | header + first 20 rows + row count + column stats |
| Source code | the requested range, or a symbol outline if the whole file was asked for |
| Binary | MIME, size, sha256, and nothing else |
| HTML | structured text extraction, scripts and styles dropped |

4. **Reference** so the agent can fetch more deliberately: `artifact.read(id, offset, length)` or `fs.search` within it.

A 500 MB build log becomes: an artifact, ~4 KB of the parts that matter, and a handle. This is the largest single lever on both context cost and run cost.

## 7. Output sanitisation

Tool output is untrusted content. Before it enters context:

- **Strip Unicode TAG characters** (U+E0000–U+E007F) — invisible, and a known model-steering smuggling channel.
- Strip/neutralise bidi and invisible formatting (U+202A–U+202E, U+2066–U+2069, U+200B–U+200D, U+FEFF).
- Normalise to NFC.
- Strip ANSI escape sequences (terminal injection; also corrupts transcripts).
- Neutralise any text resembling DireWolf's own context delimiters, so content cannot forge a boundary and appear to be system-trusted.
- Wrap in a provenance-labelled envelope carrying the trust label and source reference.

The delimiter-forgery defence is essential: whatever markers we use to say "this region is untrusted", content that can emit those markers can appear to escape the region. We use a per-run random nonce in the delimiter so it cannot be predicted or replayed.

## 8. MCP tools

MCP-discovered tools become ordinary `ToolDefinition`s with `mcp.<server>.` prefixes and inherit nothing special.

- The server process is spawned **by the kernel**, sandboxed, no network unless separately granted.
- **Tool descriptions are untrusted text** — rendered to the model inside untrusted delimiters and never used in policy decisions or approval prompts.
- The declared `args_schema` is not trusted either: we validate results against `result_schema` and cap sizes independently.
- **Rug-pull detection**: the registry stores a `toolset_hash` over `(tool names, versions, schemas, descriptions)`. A change invalidates every approval and standing grant scoped to that server and requires re-consent, naming what changed.
- Capabilities required by an MCP tool are derived from what it actually does (declared at install time and approved by the operator), never from what the server says about itself.

## 9. Testing

- Every tool has a golden test for args→result shape and an adversarial test for its denial path.
- Property tests: argument schema round-trips; output capping never exceeds the cap; excerpting is deterministic; excerpting never splits a multi-byte character or an escape sequence.
- Mock execution environment for fast unit tests; the Docker-backed suite runs the real path.
- Every tool declares its `retry`/`idempotency` class and has a crash-injection test proving the declared class holds — a tool marked `RETRY_SAFE` that leaves a partial file fails that test.
