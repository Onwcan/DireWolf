# Reliability

**Principle: fail closed, fail loudly, never fail ambiguously.** An agent that silently retried a destructive action is worse than one that stopped and asked.

---

## 1. The central mechanism: intent before effect

Almost every hard reliability question in an agent runtime reduces to one: *the process died — did the side effect happen?*

```
1. write  tool.intent_recorded { canonical_action, idempotency_key, retry_class }   ← durable, fsync
2. execute
3. write  tool.completed { outcome }                                                ← durable
```

### The authoritative record

`tool.intent_recorded` exists in two places, and **only one is authoritative: the kernel's `audit.log`.**

The kernel writes intent to `audit.log` (`synchronous = FULL`) before execution and the outcome after it. The runtime's `ToolInvocation.intent_recorded_at` in `runtime.db` (`synchronous = NORMAL`) is a **mirror for local querying**. It can legitimately be missing or stale after a power cut; that is what `NORMAL` means.

Recovery therefore never reads `runtime.db` to answer "did this happen?" It calls `QueryInvocationStatus(idempotency_key)` on the kernel, which answers from the audit chain; where the two disagree the kernel wins, the runtime row is repaired, and the divergence is audited.

This matters because the two stores are deliberately isolated — no cross-store foreign keys, no shared transaction ([DATA_MODEL.md](DATA_MODEL.md) §1) — so no two-phase commit is available and none is wanted. The resolution is not to synchronise them but to declare one the oracle. The kernel is the oracle for every question about whether an effect occurred, because it is the only component that performed it.

On recovery, the evidence **from the kernel** determines the outcome:

| Evidence | Conclusion |
|---|---|
| intent + completion | Known. Proceed. |
| no intent | Never started. Safe. |
| intent, no completion, `RETRY_SAFE` | Re-run. |
| intent, no completion, `RETRY_WITH_KEY` | Re-run with the same key; the remote deduplicates. |
| intent, no completion, `NON_RETRYABLE` or `UNKNOWN` | **`UNKNOWN`. Stop and ask.** |

The `fsync` on step 1 is the cost of this guarantee, and it is paid only for side-effecting calls — `PURE` and `READ` tools skip it entirely, which is most calls.

## 2. Retry classification

Declared per tool, never inferred:

| Class | Meaning | Examples |
|---|---|---|
| `RETRY_SAFE` | Idempotent by nature | `fs.read`, `fs.list`, HTTP GET to a safe endpoint |
| `RETRY_WITH_KEY` | Safe if the key deduplicates | API POST with an idempotency header |
| `NON_RETRYABLE` | May cause a duplicate effect | `process.exec` of an arbitrary program, email send, payment |
| `UNKNOWN` | Unclassified | **default for new tools** |

`UNKNOWN` is treated as `NON_RETRYABLE`, so forgetting to classify fails safe. Each tool's class is verified by a crash-injection test: a tool declaring `RETRY_SAFE` that leaves a partial file when killed mid-write fails its own test.

`fs.write` is interesting — it is `RETRY_SAFE` **only because** it is implemented atomically: temp file in the same directory, fsync the file, rename, **then fsync the parent directory** (the last step is what makes the rename itself durable, and is the one most often omitted).

*(As built at M4c, [ADR-0044](adr/0044-m4c-filesystem-operations-plans-and-atomic-mutation.md) §§5, 7, 10: the temporary file lives in a private `0700` staging directory inside the target's own directory — same filesystem, never a shared `/tmp` — and is swapped in with `renameat2(RENAME_EXCHANGE)`, or `RENAME_NOREPLACE` for a new file; after every namespace change — the staging directory made, the file and its record written, the exchange or rename, an undo, every clean-up removal — **every directory whose entries changed** is `fsync`ed before the next change and before the answer, because a file's `fsync` does not make its name durable and a rename changes two directories. That order of system calls is traced and mutation-tested, and recovery from a process crash is exercised at every point; recovery from a physical power loss is not exercised. `fs.patch` is `RETRY_SAFE` because it recognises its own post revision (`ALREADY_APPLIED`); `fs.move` and `fs.delete` are `NON_RETRYABLE`. The class is stored with the invocation. An effect whose outcome is not proved — the broker's answer lost after the authorisation left, or an intent a crashed incarnation never ended — is recorded `UNKNOWN` (a tool without effect is `INTERRUPTED` instead) and **the authority never performs it again**, at restart or otherwise. A version-2 `ToolInvoke` carries an `idempotency_key` bound to exactly one invocation; a retry is a new invocation with a new key, and `QueryInvocationStatus` — which will answer by key from the chain — is still M9's. The staging directory is recorded with the intent (`tool_staging`); the broker makes its record durable before any workspace name changes, and one a crash leaves is judged once a broker is at hand — after the outcome, after the run's next change, at start-up: removed if it provably holds only the broker's uncommitted data, retained — what it holds and the held object's identity recorded — if it holds a workspace object or the evidence of an effect. A reclamation re-pins the workspace root by its recorded fingerprint and resolves the parent beneath it by identity; a root or parent renamed, replaced or behind a symlink is never followed, and the record waits. Crash campaigns A–K and the staging campaigns in `make filesystem-operations-evidence` verify each window.)*

Two limits, stated because the guarantee is easy to over-read:

- **Atomic replacement is not atomic composition.** A resumed run re-executing one `RETRY_SAFE` write is safe for that file. A *sequence* — write A, write B, both required — resumed at B leaves A from attempt 1 and B from attempt 2, with the intervening model turn not replayed. The fix is at workspace level: on resume the workspace is **restored** to the checkpoint's recorded revision before the graph replays, not merely compared against it.
- **`RETRY_WITH_KEY` cannot be verified locally.** Its definition — safe if the key deduplicates — is a property of the *remote*, and no crash-injection test against our own fixture server establishes that `api.vendor.com` honours an `Idempotency-Key` on that endpoint. A tool declaring `RETRY_WITH_KEY` must name the specific endpoint and its documented idempotency contract; for any endpoint not on that list the class degrades to `NON_RETRYABLE`.

## 3. Failure semantics

| Failure | Behaviour |
|---|---|
| Provider timeout | Retry with backoff; circuit breaker counts it |
| Provider 429 | Honour `Retry-After`; degrade to a cheaper model if the budget is tight; never hot-loop |
| Provider 5xx | Retry up to N, then fall back down the ranked list |
| Provider auth failure | **No retry.** Trip the breaker, alert the operator. A bad key will not fix itself. |
| Malformed model response | Reparse once; then one repair turn with the schema error; then fail `MODEL_ERROR` |
| Invalid tool arguments | Structured error to the model — this is normal, not a failure |
| Shell hang | Wall-clock timeout, `SIGTERM`, grace period, `SIGKILL`, reap the process group |
| Process crash | Exit code and stderr captured as a tool failure; the run continues |
| **Container runtime restart** (Docker Desktop auto-update — the single most common disruption on macOS and Windows) | Every container dies at once. The supervisor detects the daemon reconnect, and **re-attaches by run-id label rather than reaping**: containers are labelled at creation precisely so recovery can distinguish "still there" from "gone." For containers that are genuinely gone, in-flight execs become `UNKNOWN` — so this event produces a *batch* of reconciliation questions, which is why `direwolf approve --list` and bulk resolution exist (§9). `ExecutionEnvironment::collect` returns a distinct `Unobservable` variant, separate from "process exited", so the two are never conflated. |
| Sandbox crash / OOM | Environment destroyed and recreated; the task fails with `SANDBOX_FAILURE`; OOM is reported distinctly because it usually means a bad limit, not a bad agent |
| Kernel unreachable | **Runtime can do nothing.** Runs suspend to checkpoints; clear operator error. |
| Runtime crash | Kernel reaps grants and children on lease expiry; runs resumable from checkpoints |
| Gateway restart | Clients reconnect; sessions re-lease; queued messages are already durable |
| Database lock | `busy_timeout`, then backoff; single-writer discipline makes this rare |
| Database corruption | Quarantine the handle ([STORAGE.md](STORAGE.md) §3) |
| FTS index corruption | Mark stale, drop triggers, fall back to `LIKE`, warn, keep writing |
| Browser crash | Session discarded; page state is not recoverable; the task fails honestly rather than pretending |
| Worker death | Tasks reassigned only if `RETRY_SAFE`; otherwise `UNKNOWN` |
| Network loss mid-stream | Partial output preserved as an artifact; classified by retry class |
| Partial write | Impossible for `fs.write` (atomic rename); other tools declare their own semantics |
| Duplicate event | Deduped on `event_id` |
| Duplicate webhook | Deduped on `(channel, external_id)` at ingress |
| Cancellation mid-side-effect | Await settlement or mark `UNKNOWN`; **never kill mid-write** |
| MCP server failure | Its tools are removed from the visible set for the turn; the run continues |
| Malicious tool output | Size-capped, sanitised, labelled untrusted — a data problem, not a crash |
| Corrupted skill | Hash mismatch → `QUARANTINED`, excluded, operator notified |
| Corrupted memory item | Excluded from retrieval, flagged; retrieval degrades rather than failing |
| Huge output | Capped, spilled to artifact, excerpted |
| Clock skew / jump | See §10 |

## 4. Cancellation

```
cancel requested
  → state = DRAINING
  → no NEW side effects may start          ← the hard rule
  → in-flight PURE/READ: cancelled immediately
  → in-flight WRITE/EXTERNAL: awaited to a known state, or marked UNKNOWN
  → subagents receive cancellation and drain
  → final checkpoint
  → state = CANCELLED
```

`DRAINING` exists precisely because cancellation is not instantaneous. A run cancelled during a database migration should finish the statement, not abandon it half-applied.

**`DRAINING` is bounded.** Default grace is 30 s, displayed and counting down. On expiry, remaining in-flight side effects are marked `UNKNOWN` and the run reaches its terminal state. Unbounded draining would mean a user who pressed Ctrl-C one second into a ten-minute test run waits ten minutes — at which point `--force` becomes the reflex and the careful drain logic protects nobody. Cancellation latency is an NFR, not an implementation detail.

`--force` skips draining and prints exactly what may be left inconsistent.

## 5. Budget exhaustion

Budgets are enforced kernel-side, so exhaustion is a hard stop rather than a request the runtime may ignore.

```
soft limit (80%)  → warn; router prefers cheaper models
admission         → kernel withholds a SUMMARISATION RESERVE (3% or 2k tokens, whichever
                    is larger) from the stated budget
hard limit        → no new tool invocations; no new model calls against the main budget
                  → run enters DRAINING
                  → ONE final model call, drawn from the reserve, with NO tools
                  → SUSPENDED (resumable if the operator raises the budget) or FAILED
```

The reserve is withheld at admission precisely so the final turn does not violate the limit that triggered it. Without it, "no new model calls" and "the agent gets one final turn" contradict each other, and the kernel — which is the enforcement point specifically so the runtime cannot ignore it — would have to refuse the call.

The final tool-less turn matters for usability: a run that dies mid-thought leaves nothing, whereas one that summarises what it learned and what remains can be resumed by a human or a later run.

## 6. Health and breakers

Per provider/model, per MCP server, per worker, per egress origin:

```
healthy → degraded → unavailable → half-open → healthy
```

Jittered exponential backoff (30 s → 15 min cap, ±20 %) prevents synchronised retry storms across parallel subagents — without jitter, 8 subagents hitting the same rate limit retry in lockstep forever.

## 7. Crash recovery

```
startup
  → verify store integrity; quarantine on structural corruption
  → verify audit chain
  → reclaim expired session leases AND expired budget leases
  → for each run in ACTIVE with no live owner:
        load latest checkpoint
        reconcile UNKNOWN invocations (§1, via the kernel)
        → resumable?  ADMITTED (re-mint capabilities, RECONCILE budget lease)
        → not?        SUSPENDED with a specific operator question
  → reap orphaned sandboxes, child processes, worktrees
  → resume the scheduler with catch-up policy applied
```

Re-minting capabilities on resume is deliberate: a run suspended for three days must not resume on authority revoked yesterday.

*(As built at M3d, [ADR-0039](adr/0039-durable-authority-state.md) §§7–8: a run is fenced to the epoch it was admitted under, and when that lease ends — released, expired and re-acquired, or invalidated because the authority restarted — every active run under it is **reaped**, durably and audited, and a trigger forbids it ever becoming active again. Resuming therefore always means a new admission, under a new idempotency key: the old key's record survives the restart and can never admit a second run. A retry of the old key is answered `ADMISSION_ENDED` — the admission happened and its authority is over — rather than with the grant, which would be a success that authorises nothing. Same-response replay holds only while the run is active under the lease that admitted it ([ADR-0040](adr/0040-m3d-reconciliation-admission-across-tenures-and-undecidable-proposals.md).)*

**Budget leases are reconciled, never re-reserved.** A crashed run never sends `ReleaseRun`, so its reservation is still outstanding. Resume calls `ReconcileBudgetLease(budget_lease_id)`, which reads actual consumption and adjusts the outstanding reservation to match — it does not take a second one. Without this, a run that crashed four times on a flaky laptop would hold 5× its budget in reservations and then fail `BUDGET_EXHAUSTED` having spent almost nothing: silent, and fail-closed, so it would present as "DireWolf randomly refuses to work."

Budget leases therefore carry the same expiry-and-reclaim treatment as session leases. The same applies down the tree: a subagent's reservation returns to its parent on **any** terminal outcome — success, failure, timeout, cancellation, or kernel reaping — not only on clean completion.

**Orphan reaping matters.** Containers, worktrees and child processes outliving their run are both a resource leak and a security problem — a container that outlives its capability grant is an execution environment nobody is accounting for. Every environment is labelled with its run id so reaping is exact.

## 7a. Leases have a TTL and a renewal

Leases are load-bearing in five places and an earlier draft specified neither a duration nor a renewal operation, which collides directly with approvals: `approve-novel-exec` has a 1-hour TTL, so a run waiting on a human would hold a session lease for an hour with no way to keep it alive.

- **Session lease TTL: 60 s.** Renewed by `Heartbeat`, which carries the session id and the epoch.
- **A lease blocked on an `approval` awaitable renews automatically** for as long as the approval is live, and only then. This is the distinction that makes the mechanism correct: a run waiting on a human is not a hung run, and a hung run does not get to look like one. `Heartbeat` renewal requires the runtime to be responsive; the approval-wait exemption requires an outstanding approval the kernel itself is tracking.
- **Budget leases: same TTL, same renewal.**
- *As built at M3d:* the session lease TTL defaults to 60 s (configurable from 1 s to 10 min), `Heartbeat` extends a live lease by one TTL, and a lease belongs to one **connection** — a second connection from the same uid is refused `LEASE_HELD` until the lease is released, expires or the authority restarts. Every authority restart invalidates every live lease without resetting its epoch. The approval-wait exemption does not exist, because approvals do not (M6).
- Without this, the sequence is: run blocks on approval, lease expires, another process acquires the session at epoch+1, the human approves, and the approving runtime's next request is rejected `STALE_EPOCH`. The human approved and nothing happened — and the `stale_epoch_rejections` alert fires claiming a zombie runtime, when the operator merely went to get coffee.

## 10. Clocks

Every expiry in the system is a wall-clock timestamp — `Approval.not_after`, `StandingGrant.not_after`, `CapabilityToken.not_after`, `lease_expiry`, `resume_deadline` — so clock behaviour is a security property, not an operational detail.

- **Durations use `CLOCK_BOOTTIME`** (or the platform equivalent), not `CLOCK_MONOTONIC`. The difference matters exactly where it is easiest to miss: `CLOCK_MONOTONIC` excludes suspend time, so a laptop closed for a week wakes with a lease that has not expired by one clock and has expired by the SQL comparison against `lease_expiry`. Two mechanisms, two answers, one lease. Naming the clock resolves it.
- **The kernel supplies time to the policy engine.** Never the runtime — otherwise `not_after` comparisons are runtime-controlled.
- **Backward steps are handled explicitly.** The kernel records a monotonic `issued_at_boottime` alongside every wall-clock expiry. An approval is valid only if *both* comparisons agree that it has not expired. A 30-minute NTP step backwards therefore cannot resurrect an expired approval — which would otherwise violate the stated property "an approval never becomes valid again after `not_after`." Backward steps beyond a threshold are logged at `warn` and surfaced by `doctor`.
- **M3d falls short of the two bullets above, and says so.** A lease's expiry is one absolute wall-clock millisecond in `kernel.db`, read through the authority's injectable clock; there is no boottime companion yet. A backward step prolongs a lease and a forward step expires one early. Neither can make two holders current — currency is an epoch comparison inside one transaction — so the cost is availability or a longer tenure, never a shared one. M3d has no approvals for a backward step to resurrect. The dual-clock check is owed before approvals exist (M6).
- `doctor`'s clock-skew check reads the local NTP daemon's status. It makes no network request — the no-phone-home rule has no exception.

## 8. Testing

| Test class | Method |
|---|---|
| Crash injection | `SIGKILL` at ~40 enumerated points (before/after intent, mid-write, mid-stream, during migration, during compaction, during approval) |
| Chaos | Random kernel restarts, socket drops, database locks, provider failures during long runs |
| Idempotency | Every `RETRY_SAFE` and `RETRY_WITH_KEY` tool: run twice, assert one effect |
| Duplicate delivery | Same webhook/message delivered 3× — assert one run |
| Lease/fencing | Two runtimes racing a session; assert exactly one writer and zero stale-epoch side effects |
| Resume fidelity | Checkpoint, kill, resume — assert task graph, budget and authority all match |
| `UNKNOWN` handling | Kill between intent and completion for a `NON_RETRYABLE` tool; assert the run refuses to auto-resume |
| Corruption | Inject corrupt pages; assert quarantine and that no writes follow |
| Long-run soak | 24-hour runs with induced failures; assert no leaks, no orphans, budget accounting exact |
| Cancellation | Cancel at each side-effect phase; assert no new effects after `DRAINING` |

**Acceptance for V1:** all crash-injection points resume correctly or fail closed with a specific, actionable question. Not "mostly recover" — every point, one of those two outcomes.

## 9. What we deliberately do not promise

- **Exactly-once against external systems.** Impossible without cooperation from the remote. We offer at-most-once for `NON_RETRYABLE`, effectively-once for `RETRY_WITH_KEY` where the remote honours keys, and honest `UNKNOWN` otherwise.
- **Resuming a browser session.** Page state, JS heap and server-side session state are not ours to checkpoint.
- **Resuming mid-model-call.** We re-issue; we do not pretend to resume a stream.
- **Effects with no settle point.** Three cases have no discrete completion, so intent-before-effect does not apply and we do not pretend it does: **long-lived processes** (a dev server, a watcher, `compose up` — the orphan reaper would otherwise kill exactly the process the task existed to start, so these need an explicit `detached` declaration and are excluded from reaping); **progressive outbound messages** on channels supporting `edit_message`, where one logical message is N visible edits and the first N−1 are already seen when the process dies; and **streaming tool output**, where the effect is continuous.
- **Exactly-once for a re-issued model call.** §9's "we re-issue" means the provider may bill twice for one turn. Budget accounting is exact for *brokered* spend; a re-issued call is a genuine duplicate charge and is excluded from the "duplicate-effect count must be 0" metric, which covers tool side effects.
- **High availability.** Single-node by design. The kernel being down means no agent work, and that is the correct trade for a system whose premise is that the kernel is the only path to effect.
