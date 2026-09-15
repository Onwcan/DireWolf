# Capabilities

**The vocabulary of authority.** [POLICY.md](POLICY.md) is the decision function; [APPROVALS.md](APPROVALS.md) is how a human grants an exception. This document defines what authority *is*.

---

## 1. Why capabilities rather than roles or risk levels

Risk levels (`low`/`medium`/`high`) are a property of an *action in the abstract*. They cannot express "may read this directory but not that one," which is the distinction that actually matters. Roles are worse: they bundle authority into named sets that drift.

A capability is a **specific, scoped, checkable permission**. `fs.read:/workspace/src` either covers a given inode or it does not, and that question has a deterministic answer.

DireWolf keeps risk classes as *metadata used by policy rules* (a rule may say "require approval for anything `DESTRUCTIVE`"), but authority itself is always capability-shaped.

## 2. Capability grammar

```
capability := verb ":" scope [ "?" constraints ]
verb       := namespace "." action
scope      := "*" | typed-scope
```

| Namespace | Verbs | Scope type | Example |
|---|---|---|---|
| `fs` | `read`, `write`, `create`, `delete`, `list`, `stat`, `exec_bit` | canonical path prefix | `fs.write:/workspace/src` |
| `process` | `exec`, `signal`, `inspect` | executable identity | `process.exec:/usr/bin/git` |
| `network` | `http`, `https`, `tcp`, `dns` | host pattern + port | `network.https:api.github.com:443` |
| `secret` | `use` | credential handle | `secret.use:github-primary` |
| `model` | `call` | provider/model pattern | `model.call:anthropic/*` |
| `browser` | `use`, `download`, `upload`, `credential_entry` | domain pattern | `browser.use:*.github.com` |
| `mcp` | `use` | server id | `mcp.use:filesystem-server` |
| `agent` | `spawn`, `message`, `cancel` | agent profile pattern | `agent.spawn:researcher` |
| `memory` | `read`, `propose`, `promote` | memory scope | `memory.promote:semantic` |
| `scheduler` | `create`, `modify`, `delete` | intent pattern | `scheduler.create:*` |
| `artifact` | `read`, `create`, `export` | artifact scope | `artifact.export:*` |
| `channel` | `send` | channel + destination | `channel.send:telegram:<chat_id>` |

Constraints are a **closed set of eight**, not an open key/value map:

| Constraint | Applies to | Narrower means |
|---|---|---|
| `max_bytes` | fs verbs | smaller |
| `no_symlink_targets` | fs verbs | `true` narrower than absent |
| `methods` | network verbs | subset |
| `max_requests` | network verbs | smaller |
| `argv_allowlist` | `process.exec` | subset |
| `privacy_class` | `model.call` | stricter (`LOCAL_ONLY` ⊑ `VENDOR_OK` ⊑ `ANY`) |
| `depth` | `agent.spawn` | smaller |
| `fanout` | `agent.spawn` | smaller |

A closed enum with eight hand-written containment rules and eight named tests is strictly safer than a general typed lattice defended by property tests — **and it is the version that actually gets the Rust sum-type benefit the language decision was bought for.** An open `HashMap<Key, Value>` is precisely the shape exhaustive matching cannot protect, so the generality was the risk, not the mitigation. Adding a ninth constraint is an ADR note and a new variant; the compiler then finds every site that must handle it.

Written form:

```
fs.write:/workspace?max_bytes=10485760&no_symlink_targets=true
network.https:*.github.com?methods=GET,POST&max_requests=100
process.exec:/usr/bin/git?argv_allowlist=status,diff,log,show
model.call:*?privacy_class=LOCAL_ONLY
```

### Scope types and their containment relation

Each scope type defines what "narrower" means. This is the heart of the system.

| Scope type | Containment test |
|---|---|
| Canonical path | `b` is a path-prefix of `a` **after** canonicalisation to inode identity + NFC normalisation. Never a string prefix on raw input. |
| Host pattern | `*.example.com` contains `api.example.com`; explicit hosts contain only themselves. Wildcards may not appear in the TLD position. |
| Executable identity | `(resolved path, sha256)`. `*` contains any; a specific pair contains only itself. |
| Numeric constraint | `min` for counts/bytes, `max` for the *narrower* side: `max_requests=50 ⊑ max_requests=100`. |
| Set constraint | Subset: `{GET} ⊑ {GET,POST}` |
| Time constraint | `not_after` earlier ⇒ narrower |
| Pattern (agent, server, intent) | Glob containment, wildcards only at the trailing position |

## 3. The ⊑ lattice

**Invariant I2:** for capability sets, `child ⊑ parent` must hold for every delegation.

```
A ⊑ B  iff  ∀ a ∈ A, ∃ b ∈ B : a ⊑ b

a ⊑ b  iff  a.verb == b.verb
         ∧  scope_contains(b.scope, a.scope)
         ∧  ∀ k ∈ constraints(b) : constraint_narrower_or_equal(a[k], b[k])
         ∧  ∀ k ∈ constraints(a) \ constraints(b) : true     (extra constraints only narrow)
```

Two subtleties that are easy to get wrong, and are therefore property-tested:

1. **A missing constraint on the parent is unconstrained.** A child adding `max_requests=10` where the parent had none is *narrower*, and legal.
2. **A missing constraint on the child is unconstrained**, and therefore **wider** — illegal if the parent had one. `fs.write:/w` is *not* ⊑ `fs.write:/w?max_bytes=100`.

Getting rule 2 backwards would silently permit escalation, which is precisely the bug class that Rust's type system is meant to make hard to write (see [LANGUAGE_SELECTION.md](LANGUAGE_SELECTION.md) §2).

### Required algebraic properties (property tests, `proptest`)

| Property | Statement |
|---|---|
| Reflexivity | `a ⊑ a` |
| Transitivity | `a ⊑ b ∧ b ⊑ c ⟹ a ⊑ c` |
| Attenuation soundness | `∀ request r : attenuate(c, r) ⊑ c` |
| Attenuation idempotence | `attenuate(attenuate(c,r),r) == attenuate(c,r)` |
| Empty is bottom | `∅ ⊑ A` for all `A` |
| No synthesis | `∀ c ∉ closure(A) : ¬(c ⊑ A)` — no combination of held capabilities yields an unheld one |
| Chain monotonicity | For any delegation chain `c₀ … cₙ`, `cₙ ⊑ c₀` |
| Canonicalisation stability | `canon(canon(p)) == canon(p)`; `canon` of any spelling of the same inode is equal |

**Target:** 10⁶ generated delegation chains with zero escalations, as an evidence claim in [BENCHMARKS.md](BENCHMARKS.md).

## 4. Capability tokens

Capabilities are handed to the runtime as **tokens**, not as strings the runtime composes.

```
CapabilityToken {
  cap_id:        UUIDv7
  run_id:        RunId
  agent_id:      AgentId
  parent_cap_id: Option<CapId>      // delegation lineage
  capability:    Capability          // verb + scope + constraints
  epoch:         u64                 // session lease epoch, for fencing
  uses_remaining: Option<u32>
  not_before:    Timestamp
  not_after:     Timestamp
  binding:       Option<BindingHash> // set when tied to a specific approved action
  mac:           [u8; 32]            // HMAC over all fields, key never leaves the kernel
}
```

- **The MAC is defence in depth, not the primary control.** The kernel holds authoritative state for every live token in `kernel.db`; the MAC lets it reject obvious forgeries cheaply before a DB lookup. A token is only valid if the kernel's own record says so. Capability systems that rely on the token alone (bearer semantics) lose revocation; we keep the record so revocation is instant.
- Tokens are **not** transferable: `agent_id` is checked against the requesting run's identity.
- Tokens do not survive a restart of the run: resume re-mints through `ADMITTED`.

### Minting

```
mint(agent_id, requested: CapabilitySet, context) -> Result<TokenSet>
  1. base       := agent_profile.declared_capabilities
  2. skill_cap  := ∩ over active skills' declared capabilities   (skills only narrow)
  3. parent_cap := parent run's effective set, if a subagent
  4. eligible   := base ∩ skill_cap ∩ parent_cap ∩ mode_profile_ceiling
  5. granted    := requested ∩ eligible          // request more, get less; never an error
  6. assert granted ⊑ eligible                   // belt and braces; panics are a bug, not a denial
  7. policy preflight on each granted capability
  8. persist + return tokens
```

Step 5 is deliberate: an agent requesting more than it can have is not an error condition, because error conditions invite retry loops. It simply receives less, and the difference is reported to the run so the agent knows what it lacks and can ask the human coherently.

### Attenuation

```
attenuate(token, narrowing) -> Token'
```
Only narrowing operations exist in the API. There is **no widening operation in the kernel's interface at all** — not a privileged one, not an internal one. Widening is expressible only by minting a fresh token from a parent set, which requires going through `mint` and therefore through policy.

## 5. Effective authority

```
effective(run) = agent.declared
               ∩ skills.declared
               ∩ parent.effective            (if subagent)
               ∩ profile_ceiling(SAFE|BALANCED|POWER)
               ∩ workspace_scope

plus, in a SEPARATE side table:
               approved_actions(run)          ← one-shot action grants, NOT capabilities
```

The final line matters: **approvals do not add capabilities.** An approval authorises *one specific canonical action*, recorded separately. This is what prevents authority drift over a long run (abuse case AC-6): after 40 approvals, the run's capability set is byte-identical to what it was at admission.

`direwolf run authority <run_id>` prints this full derivation, including which term removed each capability the agent asked for.

## 6. Product mode profiles

Profiles are **capability ceilings plus policy rule packs**, never prompt changes. A profile that only makes the system prompt say "be careful" is security theatre and is explicitly rejected.

| | SAFE | BALANCED (default) | POWER |
|---|---|---|---|
| `fs.read` | workspace only | workspace + explicit extras | workspace + home, minus a deny list |
| `fs.write` | workspace only | workspace only | workspace + approved extras |
| `process.exec` | denied | allowlisted executables, sandboxed | any, sandboxed; approval per novel executable |
| `network.*` | denied | allowlisted hosts | allowlist + approval for novel hosts |
| `secret.use` | denied | approval per use | standing grants permitted, expiring |
| `agent.spawn` | denied | depth ≤ 2, fan-out ≤ 4 | depth ≤ 4, fan-out ≤ 8 |
| `scheduler.create` | denied | approval | allowed |
| Host execution | never | never | opt-in, per-invocation approval, loud |
| Unattended (scheduler) runs | denied | `REQUIRE_APPROVAL` → `DENY` | standing grants only |

Switching profile is a kernel-side configuration change. The agent cannot request or induce a profile change; `mode` is not in the runtime's request vocabulary.

## 7. Worked example

Operator: *"Refactor the auth module and run the tests."*

```
agent.declared        fs.read:/workspace, fs.write:/workspace, process.exec:*,
                      network.https:*, model.call:*, agent.spawn:*
BALANCED ceiling      process.exec limited to allowlist; network limited to allowlist
workspace scope       /workspace/project-x
skills (python-test)  fs.read:/workspace, fs.write:/workspace,
                      process.exec:/usr/bin/pytest, process.exec:/usr/bin/python
──────────────────────────────────────────────────────────────────────────
effective             fs.read:/workspace/project-x
                      fs.write:/workspace/project-x
                      process.exec:/usr/bin/pytest?argv_allowlist=...
                      process.exec:/usr/bin/python
                      model.call:anthropic/*
                      agent.spawn:*?depth<=2&fanout<=4
NOT granted           network.* (no rule matched; skill did not request it)
                      secret.use:* (not requested)
```

Consequences that follow without any further reasoning:

- Injected content in a source file telling the agent to `curl evil.com` → **DENY**, no network capability.
- The agent deciding to `pip install` something → **DENY**, `pip` is not in the exec allowlist, and it would need network anyway.
- A spawned test-runner subagent → at most this set, never more.
- The agent reading `~/.ssh/id_rsa` → **DENY**, outside workspace scope.

None of these required anticipating the specific attack. That is the point of capability ceilings: they deny by shape, not by blocklist.

## 8. Anti-patterns explicitly rejected

| Anti-pattern | Why rejected |
|---|---|
| `admin` / `full_access` capability | An all-encompassing capability is the absence of a capability system |
| Capabilities named in model-visible text that the model can request by name | Requests are fine; *grants* must not be derivable from context |
| Capability sets stored in the runtime's database | The constrained process must not be able to write its own constraints |
| Bearer tokens with no server-side record | Loses revocation; a leaked token becomes permanent authority |
| Risk levels as the primary authority model | Cannot express scope, which is where the real distinctions are |
| Inheriting authority "by depth" | Depth is not a scope; it produces uniform-privilege trees |
| Widening APIs "for internal use" | Every such API becomes the bypass |
