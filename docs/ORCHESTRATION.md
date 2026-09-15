# Multi-Agent Orchestration

Agent identity, subagents, delegation, inter-agent messaging and workspace isolation. The task-graph machinery lives in [WORKFLOWS.md](WORKFLOWS.md).

---

## 1. Agent identity

An agent is a persisted identity, not a prompt string.

```python
AgentProfile:
    id: AgentId
    name: str
    description: str
    system_profile: str                 # persona and standing instructions
    declared_capabilities: CapabilitySet # a CEILING, not a grant
    preferred_models: list[ModelPattern]
    privacy_class_default: PrivacyClass
    memory_scope: MemoryScope
    workspace_policy: WorkspacePolicy
    channel_permissions: list[ChannelRef]
    budget_defaults: Budget
    skills: list[SkillRef]
    parent_agent_id: AgentId | None
    policy_profile: ProfileName          # SAFE | BALANCED | POWER
    created_at, revision
```

`declared_capabilities` is a ceiling. Effective authority for a run is the intersection described in [CAPABILITIES.md](CAPABILITIES.md) §5 — never more, frequently less.

**Roles are configuration.** `researcher`, `coder`, `tester`, `reviewer`, `security-reviewer` ship as profile *templates*: a system profile, a capability ceiling, a skill set, a policy profile. There is no `if role == "coder"` anywhere in the runtime. A role that is hardcoded is a role nobody can adapt, and the interesting configurations are always the ones the author did not anticipate.

Example ceilings:

| Template | Ceiling highlights |
|---|---|
| `researcher` | `net.http` to allowlisted origins, `fs.read` workspace, **no write, no exec** |
| `coder` | `fs.read`/`fs.write` workspace, `process.exec` allowlist, no network |
| `tester` | `fs.read` workspace, `process.exec` test runners, no write outside a scratch dir |
| `reviewer` | `fs.read` workspace only — read-only by construction |
| `security-reviewer` | `fs.read` workspace, `process.exec` scanners, **no network** (findings must not leave) |

## 2. Subagents are runs

A subagent is a run with its own context, budget reservation, workspace and lifecycle — not a function call, not a nested prompt.

```python
agent.spawn(
    profile: AgentProfile | ProfileTemplate,
    task: TaskSpec,
    capabilities: CapabilityRequest,   # a REQUEST; the kernel decides
    budget: BudgetRequest,             # subtracted from the parent
    workspace: WorkspaceSpec,
    timeout_s: int,
    result_schema: JsonSchema | None,
) -> SubagentHandle
```

### Capability attenuation

```
child_granted = parent_effective
              ∩ child_profile.declared
              ∩ requested
              ∩ profile_ceiling
              ∩ depth_attenuation(depth)
```

Enforced by the **kernel's** Capability Broker at mint time. The orchestrator asks; it cannot grant. `child ⊑ parent` is invariant I2, property-tested over generated delegation chains ([CAPABILITIES.md](CAPABILITIES.md) §3).

`depth_attenuation` applies additional automatic narrowing with depth — for example, `agent.spawn` is removed at max depth, and write scopes narrow to the child's own workspace. Note that depth attenuation is a *supplement* to explicit per-child capability requests, never a substitute: deriving authority from depth alone produces uniform-privilege trees where a leaf researcher holds the same power as the root.

### Budgets are subtractive

```
parent.remaining -= child.reserved       at spawn
parent.remaining += child.unused         at completion
```

Children spend the parent's allowance. Ten subagents cannot each receive "the parent's budget" — the classic fan-out cost bomb, and the mechanism behind abuse case AC-8.

Additional limits: `max_depth` (default 2 in `BALANCED`), `max_live_children`, `max_total_descendants`, aggregate wall clock. Every one is enforced kernel-side at admission, so the runtime cannot exceed them even if its own accounting is wrong.

### Lineage

Every subagent run records `parent_run_id`, `parent_task_id`, `originating_user_request_id`, `spawned_by_agent_id`, and the `capability_request` it made versus what it received. `direwolf run lineage <run_id>` answers "why did this subagent run?" with a chain back to a human sentence.

## 3. The context firewall

**A parent sees a child's result, not a child's transcript.**

```
parent ──task──> child
                 ├─ 40 tool calls, 200 k tokens of intermediate reasoning
                 └──> structured result (schema-validated) + artifact refs
parent receives: the result. Not the 40 tool calls.
```

Two benefits. The obvious one is context economy — delegation stops being a way to blow up the parent's window. The less obvious one is **security**: a child that read hostile content does not relay that content verbatim into the parent's context. The child's summary enters the parent as `GENERATED_UNTRUSTED`, and the parent's taint level rises, but the raw injection surface does not propagate. This is the quarantined-reader pattern ([CONTEXT.md](CONTEXT.md) §5) generalised to all delegation.

The full child transcript remains in the event log and is inspectable on demand (`direwolf run show <child_run_id>`) — firewalled from context, not from the operator.

## 4. Inter-agent messaging

Typed messages, never shared mutable files.

```python
AgentMessage:
    id, from_agent, to_agent, run_id, correlation_id, causation_id
    kind: REQUEST | RESULT | PROGRESS | ARTIFACT_REF | QUESTION | CANCEL | FAILURE
    payload: dict            # schema per kind
    trust: TrustLabel        # a child's message is at most the child's own trust
    lineage: list[RunId]
```

Rules:

1. **Messages are data.** A `QUESTION` from a child renders into the parent's context as untrusted content with its origin labelled — never as an instruction the parent should obey. This blocks the confused-deputy path (AC-4).
2. **Messages carry no authority.** A child cannot request capabilities through a message; capability requests go to the kernel, which evaluates them against the parent's set.
3. **Delivery is idempotent** on message id.
4. **Cancellation propagates downward** automatically; failure propagates upward according to the parent's declared `failure_policy` (`FAIL_FAST` / `CONTINUE`; `COMPENSATE` is cut from V1).

## 5. Workspace isolation

Parallel coding agents editing one working tree is data loss with extra steps.

| Workspace kind | Mechanism | When |
|---|---|---|
| `SHARED_RO` | same directory, mounted read-only | reviewers, researchers |
| `GIT_CLONE` | local clone (`--shared` refused) | the workspace is a repo — **default for coders**; see note |
| `COW_COPY` | copy-on-write clone (reflink / overlayfs) | non-repo workspaces |
| `FRESH` | empty scratch | generation from nothing |

> **Why a clone rather than `git worktree`.** A linked worktree's `.git` is a *file* pointing into the parent repository's `.git/worktrees/<name>`, and config and hooks live in the shared common directory — outside the child's workspace root. Either that common directory is mounted into the child's sandbox, in which case the child can write the parent's `config` and `hooks/` and the isolation claim is false (and, per [SANDBOX.md](SANDBOX.md) §4a, the child obtains code execution in the parent's next git command); or it is not mounted, in which case git does not work in the child at all. Neither is acceptable, so subagent workspaces are local clones with their own `.git`, and `--shared`/`--reference` are refused because they reintroduce the same shared object store.
>
> The cost is disk and clone time for large repositories. `COW_COPY` on a reflink-capable filesystem is the fast path and the default where available.

### Merging is explicit

A child does not write into the parent's workspace. It produces a **`PATCH` artifact**, and the parent decides.

```
child completes → patch artifact (base revision recorded)
parent: fs.patch(artifact, target=parent_workspace)
   → base revision matches?   apply atomically
   → base revision moved?     3-way merge attempt
       → clean?   apply, record both parents
       → conflict? CONFLICT artifact + a task in state BLOCKED
```

**A conflict is a first-class outcome, never a silent resolution.** Two agents that edited the same function produce a conflict the human or a designated reconciler resolves. Last-writer-wins across parallel agents destroys work invisibly, which is the worst failure mode a coding agent can have.

Ordering is not assumed: patches are applied in a deterministic order (by task id), and the result does not depend on completion timing.

## 6. Orchestration patterns

Supported by the V1 task graph ([WORKFLOWS.md](WORKFLOWS.md)):

| Pattern | Shape |
|---|---|
| Sequential | A → B → C |
| Fan-out / fan-in | A → {B, C, D} → join → E |
| Map | one task template × N inputs, bounded concurrency |
| Review | worker → reviewer → {accept \| revise loop with an iteration cap} |
| Race | first acceptable result wins; losers cancelled and their budget returned |
| Quarantined read | zero-capability reader → summary → capable agent |

Not in V1: dynamic re-planning mid-DAG (the planner emits a graph per planning turn instead), cyclic graphs, cross-run orchestration.

**Speculative execution is restricted by side-effect class.** Parallel *reasoning* branches are encouraged; parallel *side effects* are not speculative. A task whose tools are all `PURE`/`READ` may run speculatively and be discarded. Any task containing `WRITE`/`DESTRUCTIVE`/`EXTERNAL` runs only when its branch is committed. Racing three agents to write the same file is not an optimisation.

## 7. Failure semantics

| Failure | Default |
|---|---|
| Child fails | Parent notified with the fault class; `failure_policy` decides |
| Child times out | Cancelled, marked `TIMEOUT`, budget returned, partial artifacts retained |
| Child denied a capability | Returns a structured `FAILURE` naming what it lacked, so the parent can ask the human coherently rather than retrying |
| Parent cancelled | Cancellation propagates; children enter `DRAINING` |
| Parent dies | Children are reaped by the kernel on lease expiry — orphans cannot outlive their parent's authority |
| Child exceeds budget | Terminated; parent notified; parent may re-reserve from its own remainder |
| Merge conflict | `CONFLICT` artifact, task `BLOCKED`, human or reconciler resolves |

The orphan rule matters: a subagent whose parent's capabilities have been revoked must not continue acting on them. The kernel ties child grants to the parent's lease epoch.
