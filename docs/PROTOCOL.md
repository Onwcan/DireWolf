# DireWolf Protocol

Three protocols, three different jobs and three different threat models. Conflating them would be the mistake.

| Protocol | Between | Transport | Security role |
|---|---|---|---|
| **DWKP** — Kernel Protocol | runtime ⇄ kernel | Unix socket / named pipe | **The trust boundary.** Every message is an authority request. |
| **DWCP** — Client Protocol | clients ⇄ gateway | WebSocket / SSE / HTTP | Authenticates humans; carries no authority. |
| **DWWP** — Worker Protocol | kernel ⇄ remote worker | mTLS | Deferred. |

> **Implementation status (M2).** The wire format is implemented in
> [`crates/dwk-proto`](../crates/dwk-proto) and specified exactly by
> [ADR-0032](adr/0032-wire-contract-framing-strict-json-and-jcs.md): framing,
> the strict JSON profile, RFC 8785, the error model and version negotiation.
> Message shapes are generated from Rust into [`schemas/`](../schemas) and into
> the Python runtime ([ADR-0033](adr/0033-protocol-source-of-truth-and-tcb-dependencies.md)).
> **No transport exists yet**: no socket, no peer-credential check, no epoch
> table, no dedupe window. Those are M3 and later, and nothing below that
> depends on them is implemented. Decoding a message successfully means it is
> well-formed; it does not mean it is authorised.

---

## 1. Common envelope

```json
{"v": 1,
 "id": "msg_01J8XQ...",
 "type": "request" | "response" | "event",
 "schema": "direwolf.tool.invoke",
 "schema_version": 2,
 "ts": "2026-09-12T09:14:22.481Z",
 "correlation_id": "run_01J8XQ...",
 "causation_id": "msg_01J8XP...",
 "session_id": "ses_01J8...",
 "run_id": "run_01J8...",
 "epoch": 47,
 "idempotency_key": "...",
 "payload": { }}
```

The example shows a future message (`direwolf.tool.invoke` is reserved, not defined; §2). Field formats, as decoded by `dwk-proto` ([`schemas/common/envelope.v1.schema.json`](../schemas/common/envelope.v1.schema.json)):

| Field | Format | Notes |
|---|---|---|
| `v`, `schema_version` | integer 1–65535 | This build supports envelope version 1 |
| `id` | `msg_` (request, response) or `evt_` (event) + 26 Crockford base32 characters encoding a UUIDv7 | Format only; uniqueness is not a decoding property |
| `type` | `request` \| `response` \| `event` | |
| `schema` | `direwolf(.segment){1,6}`, lowercase, ≤ 128 characters | |
| `ts` | `YYYY-MM-DDTHH:MM:SS.mmmZ`, calendar-valid | **Advisory.** Never an input to ordering or authority |
| `correlation_id`, `causation_id` | any 2–8 letter prefix + UUIDv7 | |
| `session_id`, `run_id` | `ses_` / `run_` + UUIDv7 | Claims; compared with kernel state from M3 |
| `epoch` | integer 1 – 2^53−1; requires `session_id` | A claim, fenced against the kernel's value (§3) |
| `idempotency_key` | `[A-Za-z0-9][A-Za-z0-9._:-]{0,127}` | |
| `payload` | object | Typed per `schema` |

Each message declares every optional envelope field as required, optional or **forbidden**; a forbidden field present is `FORBIDDEN_FIELD`. `null` is never a value — an optional field is omitted.

- `schema` is a namespaced string; `schema_version` is an integer that bumps only on breaking payload changes.
- `correlation_id` groups everything belonging to one logical operation; `causation_id` points at the direct cause. Together they reconstruct the full tree of "what led to this."
- `epoch` is the session lease epoch — see §3.
- `idempotency_key` is **mandatory** on any request with a side effect.

### Compatibility rules — **per protocol, not blanket**

An earlier draft applied one rule everywhere: "unknown fields are preserved and ignored." That is right for a client protocol and for an event log, and **wrong for the authority boundary**, where it is a parser-differential surface and makes field-addition downgrades silent ([ADR-0023](adr/0023-dwkp-strict-schema.md)).

| | Unknown fields | Unknown operations / types | Why |
|---|---|---|---|
| **DWKP** | **REJECT** (`PROTOCOL_SCHEMA_VIOLATION`, audited) | **REJECT** | Both peers ship together; there is no skew to tolerate, and strictness removes a bug class from the boundary that matters most |
| **DWCP** | Preserved and ignored | Logged and skipped | Third-party and older clients are real |
| **Event log** | Retained verbatim | Retained verbatim, skipped by projectors | Events outlive the code that wrote them |
| **DWWP** | **REJECT**, as DWKP | **REJECT** | A worker is an authority peer, not a client. Fixed now so it cannot drift. **Not implemented in M2.** |

The event log's rule is implemented as retention of the record's **exact bytes** alongside whatever typed view this build can produce (known, unknown or invalid), so reading and re-writing a record can never drop information this build does not understand. DWCP re-emits preserved members, so a round trip through an older reader is value-preserving.

Parser rules shared by every family, in the order they are checked ([ADR-0032](adr/0032-wire-contract-framing-strict-json-and-jcs.md) §2):

| Rule | Limit / behaviour | Error |
|---|---|---|
| Frame body size | 1 byte – **1 MiB**, decided from the header before the body is buffered | `PROTOCOL_FRAME_EMPTY` / `PROTOCOL_FRAME_TOO_LARGE` |
| Encoding | Well-formed **UTF-8**, no lossy decoding | `PROTOCOL_INVALID_UTF8` |
| Grammar | Exactly one RFC 8259 value; no byte-order mark, no comments, trailing commas, `NaN`, raw control characters, lone surrogate escapes | `PROTOCOL_INVALID_JSON` |
| Nesting | Depth ≤ **32**, checked before descending | `PROTOCOL_MAX_DEPTH_EXCEEDED` |
| Duplicate keys | Rejected **lexically**, when the second key is read and before its value is parsed | `PROTOCOL_DUPLICATE_KEY` |
| Unicode | **No decision consults a Unicode database.** Keys are compared as text and never normalised, so two keys equal only under NFC are two members. On DWKP the second is an undeclared member and the message is refused; DWCP and event records preserve both ([ADR-0034](adr/0034-protocol-depends-on-no-unicode-database.md)) | — |
| Numbers | DWKP: integers only, \|n\| ≤ 2^53−1, no fraction or exponent. DWCP/events: any finite I-JSON number | `PROTOCOL_NUMBER_OUT_OF_DOMAIN` |
| Shape | Unknown field (DWKP), missing, forbidden, wrong type, `null`, out of range, too long, bad format, unknown enum variant, inconsistent fields | `PROTOCOL_SCHEMA_VIOLATION` + violation + JSON Pointer |
| Versions | Unsupported `v` or `schema_version` is never read as a supported one | `PROTOCOL_VERSION_UNSUPPORTED` + supported range |
| Operation | A DWKP message name this build does not define, including every reserved operation | `PROTOCOL_UNKNOWN_OPERATION` |

A protocol error is **not a policy denial**: `direwolf.protocol.error` says nothing was evaluated because nothing well-formed arrived. JSON Schema describes shapes; it does not enforce the lexical rules in this table, which are parser checks with their own tests.

Common to all: new fields are optional with a documented default; removing or retyping requires a `schema_version` bump; `v` is the envelope version, and a receiver that cannot handle it responds `PROTOCOL_VERSION_UNSUPPORTED` naming the range it supports — a clean actionable failure rather than a parse error; the handshake negotiates the highest mutually supported version.

**Consequence:** a DWKP change is a coordinated release, not a rolling one, and a mixed-version runtime/kernel pair is an error rather than a degraded mode. `direwolf doctor` detects and reports it.

## 2. DWKP — Kernel Protocol

**The critical protocol.** Every message crossing it is a request for authority.

### Transport

Unix domain socket at `$DIREWOLF_HOME/kernel.sock`, mode 0600, owned by the kernel user, runtime user in the owning group. On Windows, a named pipe with an explicit DACL. *(M3.)*

**Framing (implemented, M2):** a 4-byte big-endian body length, a 1-byte content type (`0x01` = UTF-8 JSON, the only one defined), then the body. Body length 1 B – 1 MiB. The limit is enforced from the 5-byte header before any body byte is buffered; any framing error poisons the decoder and is connection-fatal, because a length-prefixed stream has no safe resynchronisation point. Encoders emit RFC 8785 canonical JSON; decoders do not require it (§7).

**Peer verification on connect:** `SO_PEERCRED` (Linux) / `LOCAL_PEERCRED` (macOS) / `GetNamedPipeClientProcessId` (Windows) confirms the connecting process runs as the expected uid. A connection from any other user is refused and audited. This is what stops another local process from impersonating the runtime.

### Operations

The authoritative inventory — initiator, receiver, owning milestone, whether the operation can cause an effect, and the second-path argument for each — is generated from `dwk-proto` into **[DWKP_OPERATIONS.md](DWKP_OPERATIONS.md)**. As of M2:

- **Defined on the wire:** `Handshake` → `HandshakeAccepted`, `Heartbeat` → `Ack`, `AcquireLease` → `LeaseGrant{session_id, epoch}`, `ReleaseLease` → `Ack`; any of them may be answered with `direwolf.protocol.error`. Their *semantics* (epoch assignment, fencing, lease expiry) are M3/M8; M2 defines only their shape.
- **Reserved:** every other operation below. A reserved operation has no message name, no schema and no decoder; a message naming one is `PROTOCOL_UNKNOWN_OPERATION`. `QueryInvocationStatus` ([RELIABILITY.md](RELIABILITY.md)) is reserved too.
- **Not encoded in M2:** the approval binding (its eleven fields are fixed by [ADR-0021](adr/0021-approval-binding-v2.md); M6 encodes them), capability tokens, budget leases and denials.

The design list, unchanged from Phase 0.1:

```
AcquireLease    → LeaseGrant{ session_id, epoch }      # kernel holds the authoritative counter
ReleaseLease    → Ack
AdmitRun        → RunGrant{ run_id, capability_tokens[], budget_lease, epoch }
ReleaseRun      → Ack
ToolInvoke      → ToolResult | Denial | ApprovalPending
ToolCancel      → Ack
ModelCall       → stream(ModelDelta) | Denial        # kernel performs the HTTPS call
CanonicalPreview→ CanonicalAction                     # what would this resolve to?
ListVisibleTools→ ToolDefinition[]                    # policy-filtered, per turn
SpawnSubagent   → RunGrant                            # attenuation enforced here
CreateArtifact  → ArtifactId                          # streamed
ReadArtifact    → stream(bytes)
McpOpen         → McpServerHandle + ToolDefinition[]   # kernel spawns, handshakes, discovers
McpClose        → Ack
ChannelSend     → DeliveryReceipt                      # outbound message; egress-policed
QueryBudget     → BudgetSnapshot
QueryAuthority  → EffectiveAuthority                  # for `direwolf run authority`
Heartbeat       → Ack
```

Two of these exist specifically to avoid creating a second path to effect:

- **`McpOpen`/`McpClose`** — **the kernel owns the MCP protocol, not merely the process.** An earlier draft of this document had the kernel relay opaque JSON-RPC frames on the runtime's behalf (`McpSend`/`McpRecv`). That was a second path to effect: a frame such as `{"method":"tools/call","params":{"name":"write_file",...}}` *is* a tool invocation, and relaying it opaquely means it never traverses canonicalise → policy → capability → approval → budget → audit. The kernel could not have enforced "`mcp.use:<server>` plus the underlying capabilities the server's tools actually need" ([ARCHITECTURE.md](ARCHITECTURE.md) §28), because it never learned which tool was being called. A filesystem MCP server would have become a complete second filesystem path that never touches the canonicaliser.

  So: `McpOpen` spawns the server sandboxed, performs the JSON-RPC handshake, discovers the tool list, and returns it as ordinary `ToolDefinition`s. Invoking one is a normal `ToolInvoke` against `mcp.<server>.<tool>`, canonicalised and policed like any other tool; the kernel constructs the `tools/call` frame itself from the canonical action. The runtime never emits a frame.

  **Server-initiated requests are refused in V1.** MCP servers may send `sampling/createMessage`, `elicitation/create` and `roots/list` *to the client*. A sandboxed, untrusted server that could drive model calls would consume budget, choose content for an upstream the privacy class governs, and render its own text to the operator. The kernel answers all three with `method not supported`, and says so in `direwolf mcp status`. Revisit only with a design that routes them through policy.
- **`ChannelSend`** — outbound delivery to Telegram/Discord/etc. goes through the kernel, not the gateway, for two reasons. The channel's bot token is a credential and therefore lives in the secret broker (injected at egress, mode A). And outbound content is an egress surface ([NETWORK_SECURITY.md](NETWORK_SECURITY.md) §7), so URLs in agent-authored text must be policed before the platform fetches them for a link preview. A gateway that delivered messages itself would be a second path to effect *and* would need to hold the channel credential.

There is **no** operation that returns a secret value, widens a capability, creates an approval, writes a policy rule, writes the audit log, sets a policy input, or relays an opaque frame to anything. Those absences are the design; each is a deliberate hole in the API surface.

### The second-path rule

> **Every new DWKP operation must carry a written argument for why it is not a second path from cognition to effect, reviewed by someone other than its author.**

This rule exists because the failure already happened once, during Phase 0, before a line of code was written. `McpSend` was added specifically to *close* a second path (the runtime spawning processes) and opened a different one (the runtime invoking tools unpoliced). The tell is generic and worth memorising: **an operation that relays bytes the kernel does not interpret cannot police what those bytes do.** If the kernel cannot state in one sentence what canonical action an operation performs, it is a relay, and it is a second path.

`CanonicalPreview` has a concrete V1 consumer: `direwolf policy simulate` and the `[w]hy` branch of an approval prompt both need to show what an action *would* resolve to without executing it, and neither may duplicate canonicalisation logic on the untrusted side. It is an authority primitive ([ADR-0029](adr/0029-packaging-runtime-first-decoupled-authority.md)).

### Denial payload

```json
{"schema":"direwolf.tool.denied",
 "payload":{"kind":"POLICY_DENIED","reason":"OUTSIDE_WORKSPACE",
   "detail":"fs.read of /etc/passwd: outside workspace /workspace/project-x",
   "rule_id":"default","rule_source":"policy/balanced.toml:118",
   "required_capability":"fs.read:/etc/passwd",
   "satisfying_approval":null,"retryable":false}}
```

Denials are deliberately informative. An agent that knows *why* it was denied and whether an approval could help stops retrying and asks the human for the right thing.

### Backpressure and limits

Bounded in-flight requests per run (default 16); the kernel returns `BUSY` rather than queueing without limit. Per-run request rate limits. A runtime that stops reading responses gets its connection closed after a write timeout — a slow reader must not be able to exhaust kernel memory.

## 3. Epoch fencing

The mechanism that makes leases safe rather than merely convenient.

```
1. Runtime acquires a session lease → epoch 47
2. Every DWKP request carries epoch 47
3. Runtime hangs (GC pause, suspend, network partition)
4. Lease expires; another process acquires it → epoch 48
5. The first runtime wakes and sends a request with epoch 47
6. Kernel: 47 < current 48 → REJECT { STALE_EPOCH }
```

Without step 6 a zombie runtime keeps performing side effects with authority it no longer holds — a split-brain that silently duplicates work. Epochs are monotonic per session and stored kernel-side.

## 4. DWCP — Client Protocol

Clients ⇄ gateway. WebSocket for bidirectional streaming; SSE for one-way streaming; HTTP for request/response and file transfer.

```
Client → Gateway              Gateway → Client
  connect{token, caps}          connected{server_caps, protocol_versions}
  session.create/resume/list    session.created / .state
  message.send                  message.delta / .complete
  run.cancel / .status          run.state / .event
  approval.respond              approval.request        ← rendered from KERNEL state
  subscribe{topics}             error{code, detail, retryable}
                                ping / pong
```

**Authentication** is of the *human or client*, not the agent: a bearer token from `direwolf auth token create` (scoped, expiring, revocable), or mTLS for non-local clients. Default bind is `127.0.0.1` only; binding to a routable interface requires explicit configuration and emits a startup warning.

**`approval.request` is relayed, not generated, and the response is authenticated independently of the relay.** The gateway forwards what the kernel produced and cannot alter it. The *response* is **not** authenticated by the nonce alone — the nonce travels outbound through the relay, so a compromised gateway would hold everything needed to echo an approval. Remote approvals carry an HMAC over `{request_id, binding_hash, decision, scope, ttl, max_uses, device_id, response_nonce, not_after}` keyed by a device secret established out of band at pairing ([ADR-0022](adr/0022-approval-response-authentication.md)).

Gateway threat model, stated precisely: a compromised gateway can **suppress**, **delay** or **observe** an approval request. It cannot forge a response, alter what was approved, or replay a prior approval.

`connect` declares client capabilities (streaming, markdown flavour, attachments, buttons) so the runtime renders to a profile rather than branching on client type.

## 5. Events

Emitted over DWCP and persisted in the event log. Namespaced, versioned, additive.

```
run.queued  .admitted  .started  .suspended  .resumed  .draining
            .succeeded .failed   .cancelled  .expired
model.requested  .stream_delta  .completed  .failed  .metered
tool.requested   .policy_checked  .approval_required  .approved  .denied
                 .intent_recorded .started  .completed  .failed  .output_spilled
task.created  .ready  .started  .succeeded  .failed  .skipped  .compensating
subagent.spawned  .started  .completed  .failed  .cancelled
memory.retrieved  .proposed  .promoted  .superseded  .consolidated
artifact.created  .quarantined  .exported
context.assembled  .compacted  .overflow
approval.requested  .granted  .denied  .expired  .used  .drift_detected
grant.created  .used  .revoked
checkpoint.created  .restored
budget.reserved  .consumed  .exhausted
policy.loaded  .decision
secret.resolved  .injected  .denied  .redaction_hit
session.created  .lease_acquired  .lease_lost  .archived
worker.connected  .disconnected
```

Security-relevant events (`tool.*`, `approval.*`, `grant.*`, `secret.*`, `policy.*`, `budget.*`) are written by the **kernel** to the audit chain, not by the runtime. An audit record the audited process writes is a suggestion.

## 6. Schema evolution

Events persist for years; code does not. The rules:

1. **Additive within a `schema_version`**: new optional fields only.
2. **Unknown events are retained verbatim** and skipped by projectors with a counted metric. **This is the one rule that ships in V1**, and it is free.
3. **Projections are rebuildable** from the log at any time. The escape hatch for projection shape changes.
4. **Breaking changes bump `schema_version`.** Stored events are never rewritten — rewriting history to fit new code is exactly what an audit log must not do.

**Upcasters, the two-minor-version deprecation window, and the "corpus of recorded events from every released version" CI gate are cut from V1.** There are no released versions; the corpus is empty and the test is vacuous. Rules 2 and 3 preserve every option: an unknown event retained verbatim can be upcast later, by code written when there is something to upcast. Reintroduce when v1.0 ships and v1.1 needs to read v1.0 logs.

Client compatibility *is* tested from the first release that has a predecessor: a current DWCP client against the oldest supported server, and vice versa. DWKP is exempt — both peers ship together ([ADR-0023](adr/0023-dwkp-strict-schema.md)).

## 7. Wire format

JSON for V1: debuggable with `jq`, schema-tooled, browser-native for DWCP, and fast enough at our message rates (thousands per second, not millions).

The framing layer carries a content-type byte, so MessagePack or CBOR can be negotiated later without a protocol revision. We will do that when profiling shows serialisation on the critical path — not before.

**Canonical JSON** (RFC 8785 JCS) is used wherever bytes are hashed — binding hashes, audit chaining, capability MACs, approval-response MACs — so that key ordering and number formatting cannot change a hash. It is the **only** canonical encoding; the `canonical_cbor` in ADR-0021 and ADR-0022 is amended to JCS by [ADR-0032](adr/0032-wire-contract-framing-strict-json-and-jcs.md). What is hashed is always the JCS encoding of a decoded, typed value, never received bytes; a future content type changes transport encoding, not what is hashed.

## 9. Schemas, generation and review

- **Source of truth:** Rust types in `dwk-proto`. **Direction:** Rust → JSON Schema (`schemas/`, via `tools/protogen`) → Python (`runtime/src/direwolf/proto/`, via `scripts/gen_proto_python.py`, which reads only `schemas/`). [ADR-0033](adr/0033-protocol-source-of-truth-and-tcb-dependencies.md).
- `make schema` regenerates; `make schema-check` fails on any drift and runs in CI. Generated files are never edited by hand.
- Shared golden vectors in [`tests/protocol/vectors/`](../tests/protocol) are run by both the Rust and the Python test suites: the same input must produce the same acceptance, the same canonical bytes and the same `(code, violation, path)`.
- A change to an authority-facing DWKP operation answers the eight questions in [CONTRIBUTING.md](../CONTRIBUTING.md) "Changing the protocol".

## 8. Security properties

Design properties. At M2 only the parser row is implemented; the rest need the transport and the kernel (M3 onward).

| Property | Mechanism |
|---|---|
| Runtime cannot impersonate the kernel | Kernel owns the socket; runtime connects, never binds |
| Other local processes cannot impersonate the runtime | Peer credential check on connect |
| Zombie runtime cannot act | Epoch fencing |
| Replay of a side-effecting request | Idempotency key + kernel-side dedupe window |
| Gateway compromise | Gateway holds no authority; approvals relayed, not generated |
| Parser exploitation | Rust parser, `#![forbid(unsafe_code)]` and no third-party dependency, 1 MiB frame cap, depth 32, lexical duplicate-key rejection; fuzzed with libFuzzer weekly and on protocol pull requests, plus a stable mutation harness in every test run (M2) |
| Resource exhaustion | Bounded in-flight, rate limits, write timeouts |
| Downgrade attack | Version negotiation picks the highest mutual version; minimums are configurable and enforced |
