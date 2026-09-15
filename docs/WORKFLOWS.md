# Workflows, Scheduler and Standing Intents

---

## 1. Scope discipline

The temptation here is to build a workflow engine. We are building the smallest task graph that makes multi-step agent work durable, and writing down in advance what would make us build more.

**V1 ships:** a persisted DAG inside a run — sequence, parallel fan-out, fan-in join, conditional skip, per-task retry, per-task compensation, checkpoint/resume.

**V1 does not ship:** durable multi-day workflows, distributed dispatch, a workflow DSL, sub-workflows as reusable units, dynamic mid-DAG rewriting, or a dependency on Temporal/Airflow.

### When to graduate

We adopt a real workflow engine only if **two or more** of these become true:

1. Workflows routinely exceed 24 hours.
2. Execution must span machines with independent failure domains.
3. Users author workflows directly, rather than a planner emitting them.
4. Exactly-once semantics against external systems become a hard requirement rather than a best effort.
5. The scheduler's own state machine exceeds ~2 000 lines.

Until then, a DAG in SQLite is the right amount of machinery. Recorded here so the decision gets re-made on evidence rather than on ambition.

## 2. Task

```python
Task:
    id, run_id, parent_task_id
    name: str
    depends_on: list[TaskId]
    kind: MODEL_TURN | TOOL_CALL | SUBAGENT | JOIN | CONDITION
    agent_id: AgentId | None
    spec: TaskSpec
    capabilities: CapabilityRequest
    workspace: WorkspaceRef
    budget: BudgetReservation
    state: PENDING | READY | RUNNING | SUCCEEDED | FAILED | SKIPPED | BLOCKED
    attempt: int
    max_attempts: int
    retry_class: RetryClass
    timeout_s: int
    result: TaskResult | None
    artifacts: list[ArtifactId]
    failure_policy: FAIL_FAST | CONTINUE          # COMPENSATE cut from V1, see below
    idempotency_key: str | None
    revision: int
```

Tasks are rows. A resumed run replays the *graph*, not the reasoning: completed tasks keep their results and are never re-executed.

## 3. Execution

```
loop:
  ready = tasks where state=PENDING and all deps SUCCEEDED (or SKIPPED-and-optional)
  if none ready and none running: terminal
  dispatch up to max_concurrent_tasks, respecting side-effect class:
      PURE/READ tasks may run concurrently
      WRITE/DESTRUCTIVE/EXTERNAL tasks serialise within a workspace
  on completion: persist result, mark deps satisfiable, checkpoint
  on failure: apply failure_policy and retry_class
```

Deterministic dispatch order for equal-priority ready tasks (by task id), so two runs of the same graph schedule identically. Non-deterministic ordering makes reproduction luck.

### Retry

Governed by the tool's declared class, never by optimism:

| Class | Behaviour |
|---|---|
| `RETRY_SAFE` | Retry with backoff up to `max_attempts` |
| `RETRY_WITH_KEY` | Retry only with the same `idempotency_key` |
| `NON_RETRYABLE` | Never retried automatically |
| `UNKNOWN` | Treated as `NON_RETRYABLE` |

`UNKNOWN` is the default for a new tool, so forgetting to think about retry semantics fails safe rather than silently double-charging someone.

### Compensation — **cut from V1**

An earlier draft gave tasks a declarable inverse, run in reverse topological order during `DRAINING`. Review asked the right question: name the V1 tool that can declare a meaningful inverse. `fs.write` via git, at a stretch. `process.exec` cannot. `net.http` cannot. `fs.delete` cannot.

So compensation is **removed from V1**, along with the `COMPENSATING` / `COMPENSATED` / `COMPENSATION_FAILED` task states and `failure_policy = COMPENSATE`. What remains is the mechanism that is honest and already good: **`UNKNOWN` plus explicit reconciliation** (§5). The `CompensationSpec` field stays in `ToolDefinition` as `None` for every V1 tool, so reintroducing it later is additive.

Revisit when a tool ships whose inverse is well-defined and testable — a transactional store, or a system with a documented undo endpoint.

## 4. Checkpoints

Written after each task state transition and at each turn boundary.

**Captured:** run lifecycle state, full task graph with results, budget position, approval state, artifact references, context manifest ids, workspace revision (git commit or snapshot id), committed memory writes, wait set.

**Not captured:** provider-side state, model internals, open sockets, in-flight tool processes, sandbox ephemeral filesystem beyond the workspace snapshot.

### Resume

```
load checkpoint
  → re-enter ADMITTED: re-mint capabilities, re-reserve budget   ← authority is re-checked
  → for each RUNNING task at crash time:
        outcome UNKNOWN?  →  see §5
        otherwise         →  reset to READY if retry_class permits, else FAIL
  → resume dispatch
```

Re-entering `ADMITTED` is deliberate: a run suspended for three days must not resume on capabilities that were revoked yesterday. Resume is a fresh authorisation, not a restoration of one.

`EXPIRED` exists for runs whose resume deadline passed — a run should not silently wake up next month.

## 5. The UNKNOWN outcome

The hardest reliability problem: the process died between "we started a side effect" and "we recorded its result."

**Intent-before-effect.** Every side-effecting invocation writes `tool.intent_recorded` with the canonical action and idempotency key *before* execution. On recovery:

| Evidence | Outcome |
|---|---|
| intent + completion | Known. Proceed. |
| no intent | Never started. Safe to run. |
| intent, no completion, `retry_class = RETRY_SAFE` | Re-run. |
| intent, no completion, `RETRY_WITH_KEY` | Re-run with the same key; the remote deduplicates. |
| intent, no completion, `NON_RETRYABLE`/`UNKNOWN` | **`UNKNOWN`.** Do not retry. |

An `UNKNOWN` task blocks its run and raises a specific reconciliation question:

```
Run run_01J8... cannot resume automatically.

  Task  deploy-staging   (process.exec /usr/bin/deploy --env staging)
  Started 14:22:07, no completion recorded; process died 14:22:09.
  This tool is NON_RETRYABLE — re-running may deploy twice.

  Check whether the deploy completed, then:
    direwolf approve --list          # every pending decision, including UNKNOWNs
    direwolf run resolve run_01J8... --task deploy-staging \
        --outcome succeeded|failed|indeterminate [--result-file r.json]
    direwolf run resolve --all --outcome indeterminate --reason "docker restarted"
```

Four properties this needs, and an earlier draft lacked:

- **`indeterminate`.** "Did the POST to the payment API go through?" is often genuinely unanswerable, and forcing the operator to assert a fact they do not possess is worse than recording that they do not. An `indeterminate` task fails its run without compensation and keeps its artifacts.
- **`--result-file`.** A task marked `succeeded` with no result feeds `null` to every dependent task. Harmless for a leaf; silent graph corruption for `fetch-customer-list → process-each`.
- **Bulk resolution.** One container-runtime restart kills every sandbox at once and produces a batch of `UNKNOWN`s, not one.
- **`UNKNOWN` is exempt from `resume_deadline`.** Otherwise the system's most emphatic promise — stop and ask — becomes "stop, ask, then stop asking" when the run expires. An unresolved `UNKNOWN` outlives its run as a standalone operator task.

This is the honest answer. Systems that blind-retry at this point are the ones that send two emails, charge two cards, or deploy twice.

## 6. Scheduler

Job kinds: one-shot, cron, interval, and (deferred) conditional monitors.

**No scheduler bypass.** A fire creates an ordinary run through admission, policy, capabilities, budget, approval and audit. There is no privileged path — which is why the scheduler is a thin component rather than a parallel execution engine.

**Fresh context per fire.** A scheduled run starts with no conversation history: agent profile, skills, relevant memory and the job's own spec. History accumulated over a hundred fires is expensive and is an injection persistence surface.

**Capabilities are re-evaluated at fire time** as `intent.declared ∩ agent.current`, so revoking a capability immediately affects every scheduled job that depended on it — no stale grants surviving in job definitions.

**Unattended runs are stricter.** Nobody is watching, so `REQUIRE_APPROVAL` degrades to `DENY` unless a standing grant covers the action. A scheduled job that needs approval fails and notifies, rather than waiting hours holding a lease or — far worse — auto-approving.

**Overlap policy** per job: `SKIP` (default), `QUEUE` (bounded), `CANCEL_PREVIOUS`. Missed fires during downtime follow a `catch_up` policy with a bound: `none` (default), `last_only`, or `all_within(window)`. Waking up to 400 queued fires after a laptop suspend is a real failure mode.

**Idempotency:** every fire has a deterministic key `(intent_id, scheduled_time_utc)` — UTC, not local, so the duplicate fire on a fall-back DST boundary collapses correctly and the skipped fire on spring-forward is visible as a gap rather than as a silent miss. `CronTrigger` requires an explicit IANA timezone; there is no "local time" default, because a schedule whose meaning changes when you travel is a bug generator.

## 7. Standing intents

Durable intentions as explicit objects, not invisible loops.

```python
StandingIntent:
    id, owner, agent_id, name
    description: str
    trigger: CronTrigger | IntervalTrigger | EventTrigger | ConditionTrigger
    timezone: IanaTz              # MANDATORY on CronTrigger; fires stored in UTC
    action: TaskSpec
    capabilities: CapabilitySet         # ceiling, re-intersected at fire time
    budget: Budget                      # per fire AND cumulative
    policy_profile: ProfileName
    standing_grants: list[GrantId]      # explicit, expiring, listed
    destination: ChannelRef             # where results go
    notify_on: ALWAYS | CHANGE | ERROR
    expires_at: Timestamp               # MANDATORY
    enabled: bool
    created_at, last_fired, fire_count
```

Every field is a control the operator can see and change. Three are load-bearing:

- **`expires_at` is mandatory.** No perpetual intents. A watcher you set up in March and forgot is a watcher you cannot reason about in September. Renewal is deliberate.
- **`notify_on: CHANGE`** is the default for monitors, because a daily "still fine" message trains people to ignore the alert.
- **Cumulative budget**, not just per-fire: an intent firing hourly for 90 days is 2 160 runs, and per-fire limits alone do not bound that.

```console
$ direwolf intent list
ID        NAME              TRIGGER      NEXT      BUDGET(used/total)  EXPIRES  FIRES
si_01J8…  watch-ci-main     cron 0 * * *  14:00     $2.10/$25.00       in 68d   412
si_01J8…  morning-digest    cron 0 7 * *  07:00     $8.40/$50.00       in 21d   96
```

An intent nobody can list is a cron job with better marketing. Visibility is the feature.
