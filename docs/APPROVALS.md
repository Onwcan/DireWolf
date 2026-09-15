# Approvals

**How a human grants a specific exception, without granting a standing power.**

Approvals are where most agent systems leak authority. The observed failure modes in comparable systems — approvals outliving their reviewed working directory, approvals widening durable authority, an auxiliary LLM being persuaded to approve, containment silently disabling approval — are all failures of *binding*, *scope* or *lifetime* rather than of the approval UI. This document is written around those three properties.

---

## 1. The binding

An approval authorises **one canonical action**, not a tool, not a capability, not a category.

```rust
struct Approval {
    approval_id:   Uuid,
    binding_hash:  [u8; 32],     // over the canonical action — see §2
    granted_by:    PrincipalId,  // the human
    granted_via:   ChannelRef,   // where they approved, for forensics
    agent_id:      AgentId,      // NOT transferable
    run_id:        Option<RunId>,// None only for StandingGrants
    scope:         ApprovalScope,
    granted_at:    Timestamp,
    not_after:     Timestamp,    // always set; no unbounded approvals exist
    max_uses:      u32,          // default 1
    uses:          u32,
    revoked_at:    Option<Timestamp>,
    obligations:   Vec<Obligation>,
}
```

Every field is load-bearing:

- **`binding_hash`** — mutation of the action invalidates it.
- **`agent_id`** — a subagent cannot spend its parent's approval, and a parent cannot spend a child's. This blocks approval laundering through delegation.
- **`run_id`** — normally scopes the approval to the run it was requested in, so an approval cannot survive into tomorrow's scheduled job.
- **`not_after`** — there is no representation for "forever." The type has no `Option`.
- **`max_uses`** — defaults to 1. Burned atomically with execution.

## 2. The binding hash

```
binding_hash = SHA256( jcs({                 // RFC 8785; ADR-0032 (was canonical_cbor)
    schema: "direwolf.approval.binding.v1",
    verb,
    resource_identity,      // inode+device for paths; (path, sha256) for executables;
                            // resolved IP set + SNI for hosts
    canonical_args,         // normalised argv / normalised request, NOT the raw model string
    workspace_id,
    environment_profile_id, // the sandbox profile it will run in
    credential_handles,     // sorted
    agent_id,
    scope_discriminant,
    taint_level,            // the run's provenance state AT GRANT TIME
    privacy_class,
    obligations,            // sorted; the conditions the ALLOW carried
}))
```

Notes on what is and is not included:

- **`resource_identity`, not the path string.** `/workspace/data`, `/workspace/./data` and a symlink to it hash identically; a *different inode* with the same path does not. This is the direct defence against "the approved file was swapped after approval."
- **`environment_profile_id` is included**, so an approval granted for a sandboxed execution cannot be spent on a host execution. This is the structural fix for the "choosing a container skips the approval check" failure — here the two are bound together rather than being alternatives.
- **`credential_handles` included**, so an approval to run `git push` without credentials cannot be spent on `git push` *with* a credential injected.
- **`taint_level` is included.** Without it the attack is simple and patient: early in a run, while clean, trigger a `REQUIRE_APPROVAL` action and receive a prompt carrying no taint warning; the human approves; the agent then reads a hostile page and spends the approval inside its TTL. Re-canonicalisation checks the *resource*, not the run's provenance, so no drift is detected. Since §6 design rule 3 calls taint "the single most decision-relevant fact," it has to be part of what the decision binds to — otherwise the warning is decorative.
- **`obligations` are included**, so an approval granted under a rule carrying `network_deny` or `read_only_workspace` cannot be spent under a later match lacking them. `environment_profile_id` was already included for exactly this reason; obligations are the remainder of that argument.
- The model's natural-language description is **excluded**, because it must never be able to influence what a hash matches.

## 3. Scopes

```rust
enum ApprovalScope {
    ExactAction,                       // this argv, this inode, once
    PathSet { inodes: Vec<InodeId>, verb: Verb },  // one prompt, one binding, N files
    ExecutableAndArgv { .. },          // this executable with this argv shape
    PathSubtree { root: InodeId, verbs: Vec<Verb> },
    HostAndMethods  { host: ResolvedHost, methods: Vec<Method> },
    CredentialUse   { handle: SecretHandle, upstream: Origin },
}
```

Broader scopes exist because `ExactAction` alone produces approval fatigue, and approval fatigue produces reflexive clicking — which is worse than a slightly broader grant. But every broader scope is still bounded by `not_after`, `max_uses`, `agent_id` and `run_id`.

**Scope breadth and `max_uses` must scale together.** An earlier draft set `max_uses = 1` on `ExecutableAndArgv`, which reintroduced exactly the fatigue the broader scope existed to remove: a test-fix loop running `ruff check` after each of eight edits produced eight prompts for one already-approved command. A scope that describes a *shape* of action should permit that shape repeatedly within its TTL. The shipped `balanced` profile now uses `max_uses = 20` for `executable_and_argv` with a 1-hour TTL.

`PathSet` exists so a delete of three files is one decision. The binding hashes the **sorted set** of inode identities, so adding a fourth file invalidates it — the human approved a specific set, not a pattern.

**`PathSubtree` binds to the root's inode, captured at approval time.** If the directory is replaced (moved away and a new one created at the same path), the inode differs and the approval no longer matches. This is the direct defence for "approvals outliving their reviewed working directory."

## 4. Standing grants

The only long-lived construct, and deliberately awkward to create.

```rust
struct StandingGrant {
    grant_id, created_by, agent_id,
    predicate: ApprovalScope,     // never ExactAction — that would be pointless
    not_after: Timestamp,         // max 90 days, hard cap
    max_uses_total: Option<u32>,
    max_uses_per_day: Option<u32>,
    conditions: Vec<GrantCondition>,  // e.g. require_untainted_run, interactive_only
    created_via: ChannelRef,
    revoked_at: Option<Timestamp>,
}
```

Rules:

- **Never created implicitly.** "Approve" in a prompt creates an `Approval`. Creating a `StandingGrant` requires `direwolf grant create` or an explicit, separately-worded second confirmation. There is no "don't ask again" checkbox on an approval prompt — that checkbox is how every blanket permission in history got granted.
- **Always listed.** `direwolf grant list` shows all of them, with use counts and remaining lifetime. A grant nobody can see is a backdoor.
- **Always revocable**, instantly, and revocation applies to in-flight runs at the next check.
- **`require_untainted_run` by default**: a standing grant does not apply in a run that has ingested `EXTERNAL_UNTRUSTED` content. This means the convenience grant you created for routine work does not silently cover the run where you asked the agent to read a hostile web page.
- Expiry is capped at 90 days with no override.

## 5. The request path

```mermaid
sequenceDiagram
  participant K as Kernel
  participant CH as Approval channel
  participant H as Human
  K->>K: policy = REQUIRE_APPROVAL, compute binding_hash
  K->>K: lookup Approval | StandingGrant matching<br/>(binding_hash | predicate) ∧ agent_id ∧ ¬expired ∧ ¬revoked ∧ uses<max
  alt found
     K->>K: burn use, proceed
  else not found
     K->>CH: ApprovalRequest (kernel-rendered)
     CH->>H: display
     H-->>CH: decision
     CH->>K: signed response + request_nonce
     K->>K: verify nonce, store Approval
  end
  K->>K: RE-CANONICALISE, recompute binding_hash, compare
  alt mismatch
     K-->>K: DENY approval_binding_drift; audit
  else match
     K->>K: execute
  end
```

**The `request_nonce`** is generated by the kernel per request and must be echoed. It prevents an approval response captured from an earlier prompt being replayed against a later one.

**Re-canonicalisation after approval** is the TOCTOU gate. Between the human reading the prompt and the action executing, the world may have changed: a file replaced, a DNS record changed, an executable rewritten. The action that executes is the action that was hashed, or nothing executes.

## 6. What the human sees

Rendered entirely from kernel state. The agent contributes nothing to the authoritative region.

```
┌─ DireWolf approval required ──────────────────────────────────────────┐
│ Agent     coder-01   (run run_01J8X…, started 14:02, interactive)     │
│ Action    DELETE 3 files                                              │
│                                                                       │
│   /workspace/project-x/src/legacy/parser.py      12.4 KB              │
│   /workspace/project-x/src/legacy/lexer.py        8.1 KB              │
│   /workspace/project-x/src/legacy/__init__.py     0.2 KB              │
│                                                                       │
│   All within workspace  /workspace/project-x                          │
│   Tracked in git, committed as of 3 min ago (recoverable)             │
│                                                                       │
│ ⚠  This run has read UNTRUSTED content:                               │
│      github.com/acme/project-x/issues/412   (seq 31)                  │
│      Review it:  direwolf artifact show art_01J8…                     │
│                                                                       │
│ Rule      approve-workspace-delete  (policy/balanced.toml:71)         │
│ Grants    this exact action, once, expires in 10 minutes              │
│                                                                       │
│ ── the agent says (untrusted, not part of this decision) ──────────── │
│ │ "Removing the deprecated parser as discussed."                    │ │
│ ────────────────────────────────────────────────────────────────────  │
│                                                                       │
│ [a] approve once   [d] deny   [s] show diff   [w] why was this asked  │
└───────────────────────────────────────────────────────────────────────┘
```

Design rules for this surface:

1. **Facts above, agent prose below, visually separated and labelled untrusted.** The agent's explanation is often genuinely useful; it is never authoritative.
2. **Consequences, not just operations.** "Tracked in git (recoverable)" is the fact the human needs. Where DireWolf can cheaply compute reversibility, it shows it.
3. **Taint is surfaced with its source**, because "the agent read a hostile page earlier in this run" is the single most decision-relevant fact.
4. **The grant is stated in full**: what, how many times, for how long.
5. **No "always allow."** Broadening requires a separate deliberate command.
6. **Timeout = deny**, and the timeout is shown.

## 7. Delivery channels and authentication

| Channel | Use | Authentication |
|---|---|---|
| CLI (interactive) | Default | The CLI passes its controlling-terminal fd to the kernel over the DWKP socket (`SCM_RIGHTS`; `DuplicateHandle` on Windows). The kernel verifies it with `isatty` and a session-id check, then **writes and reads the approval directly on that fd** — the runtime is not in the path and cannot intercept, and the CLI cannot re-render what the kernel drew. See the note below. |
| CLI (`direwolf approve`) | Detached runs | Local user identity + socket peer credentials |
| Push channel (Telegram etc.) | Remote | Channel identity + a per-approval nonce **+ a response MAC keyed by a device secret established out of band at pairing**. The nonce alone is insufficient: it travels outbound through the relay, so a compromised gateway would hold everything needed to echo an approval. With the device key, a compromised relay can suppress an approval request (denial of service) but cannot forge a response. Rate-limited; **disabled by default** |
| Web UI | M27 | Session auth + nonce |

> **Why the fd is passed rather than the kernel opening a terminal.** `dwkd-authority` is a daemon running as a different OS user; it does not own the operator's terminal and cannot find it. The fd must therefore come from the CLI, which is less privileged — so the kernel treats it as untrusted input: it verifies the fd is a character device, is a TTY, and belongs to the session of the peer whose credentials it already checked on connect. A CLI that passes a pipe instead gets a refusal and the approval falls back to `direwolf approve`.
>
> While an approval is being drawn, the kernel takes the terminal to raw mode and the runtime's output stream to that TTY is suspended. This is what closes the terminal-control phishing path: an agent emitting cursor-positioning or scroll-region escape sequences cannot overdraw or scroll away a prompt it is not permitted to write during. Agent-authored output is additionally ANSI-stripped on the `ChannelSend` path, not merely on the way in.

Remote approval is off by default because it weakens the binding between "the operator" and "the account."  When enabled, high-risk classes (`DESTRUCTIVE`, `secret.use`, host execution) can be configured to require local approval regardless.

## 8. Threats and defences

| Threat | Defence |
|---|---|
| **Replay** — reuse a captured approval | Single-use default, `run_id` scope, `not_after`, per-request nonce, atomic burn |
| **Substitution** — approve A, execute B | `binding_hash` over canonical action; re-verified pre-exec |
| **Mutation after approval** — file swapped, DNS changed, binary rewritten | Inode identity, executable hash, pinned IP set, all inside the hash |
| **Laundering** — parent approves, child spends | `agent_id` in the binding |
| **Phishing** — agent writes a misleading prompt | Kernel-rendered from canonical data; agent text quarantined and labelled |
| **Fatigue** — spam until the human clicks yes | Rate limiting per run; repeated **explicit denials** for the same action escalate to a `REPETITION` fault and terminate the run. **Expiry is not denial**: an approval that timed out because nobody was present suspends the run for later resumption and does not count toward the fatigue counter. `approval.expired` and `approval.denied` are already distinct audit events; treating them as the same input would terminate a run, discard its budget and lose its work because the operator went to lunch. |
| **Escalation via LLM judge** | No LLM in the decision path at all |
| **Environment swap** — approved for sandbox, run on host | `environment_profile_id` in the binding hash |
| **Unattended auto-approval** | `REQUIRE_APPROVAL` with no human present degrades to `DENY`, not to `ALLOW` |
| **Grant sprawl** | All grants listed, capped at 90 days, `require_untainted_run` by default |

## 9. Audit

Every approval lifecycle event enters the hash-chained audit log: `approval.requested`, `approval.granted`, `approval.denied`, `approval.expired`, `approval.used`, `approval.drift_detected`, `approval.revoked`, `grant.created`, `grant.used`, `grant.revoked`.

Each record carries the full canonical action (not just the hash), the matched rule, the principal, the channel, and the latency between request and decision. Approval latency is a metric worth watching: a median under two seconds usually means people are clicking reflexively rather than reading, which is a signal that the policy is asking too often and should be tightened in scope rather than loosened in frequency.

## 10. Property tests

| Property | Statement |
|---|---|
| No forever | `∀ a : a.not_after` is set and ≤ `now + 90d` |
| Single-use default | Approval created without explicit `max_uses` has `max_uses == 1` |
| Burn atomicity | Concurrent uses of a `max_uses=1` approval: exactly one succeeds |
| Binding sensitivity | Any single-field mutation of the canonical action changes `binding_hash` |
| Non-transferability | An approval with `agent_id=A` never matches a request from `agent_id=B` |
| Drift denial | If the resource identity changes between grant and execution, the result is `DENY` |
| Unattended safety | `origin=scheduled ∧ effect=REQUIRE_APPROVAL ∧ ¬standing_grant ⟹ DENY` |
| Expiry monotonic | An approval never becomes valid again after `not_after` |
