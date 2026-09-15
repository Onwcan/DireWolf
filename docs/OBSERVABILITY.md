# Observability and Audit

Two systems with different purposes, different guarantees, and deliberately different owners.

| | Observability | Audit |
|---|---|---|
| Question | "Is it working, and what is it costing?" | "What did it do, and who allowed it?" |
| Owner | runtime | **kernel** |
| Guarantee | best-effort, sampled, lossy | **complete, append-only, tamper-evident** |
| Content | metrics, spans, logs | canonical actions, decisions, principals |
| Loss | acceptable | a bug |

Conflating them produces the common failure where a system exports rich telemetry that deliberately omits prompts, tool arguments and results — excellent for monitoring, useless for answering "what did the agent actually do to my machine?" We keep both, and we do not let the privacy posture of one dictate the completeness of the other.

---

## 1. Audit

### What it records

Every security-relevant decision and action, written by the kernel at the moment of decision:

`tool.*` (requested, canonicalised, decided, approved/denied, executed, outcome) · `approval.*` · `grant.*` · `capability.*` (minted, attenuated, rejected) · `secret.*` (resolved, injected, denied, redaction_hit — never the value) · `policy.*` (loaded, decision) · `budget.*` · `run.admitted` / `run.authority_frozen` · `sandbox.*` (created, escape_attempt, destroyed) · `network.*` (allowed, denied, credential_injected) · `worker.*`

### Record

```json
{"seq": 184412, "ts": "2026-09-12T09:14:22.481731Z",
 "actor": {"principal":"user_01J8...","agent":"coder-01",
           "parent_agent":"orchestrator-01","run":"run_01J8...","session":"ses_01J8..."},
 "operation": "tool.executed",
 "canonical": {"verb":"fs.write","path":"/workspace/project-x/src/auth.py",
               "inode":[2049,8813472],"bytes":4821},
 "authority": {"capability":"cap_01J8...","approval":"apr_01J8...",
               "policy_decision":"ALLOW","rule":"allow-workspace-write",
               "rule_source":"policy/balanced.toml:47","policy_hash":"sha256:9c1f..."},
 "environment": {"id":"oci-strict","assurance":"ContainerIsolation"},
 "outcome": {"status":"success","duration_ms":34},
 "prev_hash": "sha256:a1b2...",
 "hash": "sha256:c3d4..."}
```

`policy_hash` is what makes a decision reproducible: months later you can load the exact rule set that was in force and recompute the decision from the canonical action.

### Integrity

```
hash_n = SHA256( prev_hash || canonical_json(record_n) )
```

Canonical JSON (RFC 8785) so key ordering cannot change a hash. Any modification or removal of a record breaks every subsequent link.

```console
$ direwolf audit verify
  184,412 records, chain intact, head sha256:c3d4...
$ direwolf audit anchor --export ./anchor-2026-09-12.json
```

**What this does and does not give you.** Chaining detects *tampering* — edits and deletions in the middle. It does not detect wholesale truncation or deletion of the file by an attacker with the kernel user's privileges or root, because they can also rewrite the chain. To detect that, chain heads must leave the host: periodic export to a separate location, a second machine, or a timestamping service. We ship the export command and document the limitation rather than implying local hash chaining is more than it is.

Honest statement, borrowed from a competitor's admirable candour and made stronger — but bounded precisely: **the absence of a record means the action did not cross the kernel boundary.** Activity *inside* a sandbox during an already-recorded `process.exec` is not individually recorded ([SANDBOX.md](SANDBOX.md) §4a point 3); one exec entry may cover a thousand file writes within the mount. What is guaranteed is that nothing crossed *out* of the sandbox unrecorded. Since no other path to a side effect exists, an action with no record either did not happen or is evidence that the architecture's central invariant has been broken — which is itself the most important thing an operator could learn. This is a stronger claim than "absence proves nothing", and it is only available because there is exactly one enforcement point.

### Querying

```console
$ direwolf audit query --run run_01J8... --operation 'tool.*'
$ direwolf audit query --since 24h --denied
$ direwolf audit query --secret github-primary       # every use, never the value
$ direwolf audit explain run_01J8... --seq 47
```

## 2. Observability

OpenTelemetry-native across traces, metrics and logs.

### Traces

One trace per run; the trace id **is** the run id, so a user-visible identifier joins the UI, the logs and the backend.

```
run (run_01J8...)
├── context.assemble         tokens=31402  sections=9  evicted=3
├── model.call               provider=anthropic  model=claude-opus-5
│   ├── kernel.policy_check  decision=ALLOW  rule=allow-model-anthropic   180µs
│   ├── http.request         upstream=api.anthropic.com                  2.4s
│   └── usage.meter          in=31402 out=847 cache_read=28900  $0.0412
├── tool.invoke fs.read
│   ├── kernel.canonicalise                                              210µs
│   ├── kernel.policy_check  decision=ALLOW  rule=allow-workspace-read    120µs
│   ├── kernel.capability                                                 40µs
│   ├── kernel.budget                                                     30µs
│   └── exec.sandbox         env=oci-strict                               18ms
└── subagent.spawn           child_run=run_01J8Y...   [linked trace]
```

Spans cross the process boundary: the runtime propagates trace context over DWKP, and the kernel continues the trace. Debugging a slow tool call means seeing which kernel stage cost the time, not guessing.

Subagent runs are **linked** traces rather than nested spans, so a parent trace stays readable when a child performs 400 operations.

### Metrics

| Family | Examples |
|---|---|
| Runs | `direwolf.run.{started,completed,failed,duration,turns}` by agent, origin, fault class |
| Model | `.calls`, `.tokens{input,output,cache_read,cache_write}`, `.cost_usd`, `.latency`, `.errors` by provider/model/class |
| Tools | `.invocations`, `.latency`, `.output_bytes`, `.spilled`, `.failures` by tool, outcome |
| **Policy** | `.decisions{allow,deny,require_approval}` by rule, `.latency` |
| **Approvals** | `.requested`, `.granted`, `.denied`, `.expired`, **`.latency`** |
| Budget | `.reserved`, `.consumed`, `.exhausted` by dimension |
| Context | `.tokens_assembled`, `.evictions`, `.compactions`, `.cache_hit_ratio` |
| Memory | `.retrievals`, `.latency`, `.promotions`, `.promotion_denied` |
| Sandbox | `.created`, `.destroyed`, `.oom`, `.timeout`, **`.escape_attempts`** |
| Kernel | `.requests`, `.latency` by operation, `.busy_rejections` |
| Sessions | `.active`, `.lease_contentions`, `.stale_epoch_rejections` |

Three deserve alerts:

- **`sandbox.escape_attempts > 0`** — something is actively probing containment.
- **`approval.latency` p50 < 2 s** — people are clicking without reading. The fix is narrower policy scope, not fewer prompts.
- **`stale_epoch_rejections > 0`** — a zombie runtime existed. Fencing worked, but something was wrong upstream.

### Logs

Structured JSON, correlation ids on every line, with secret redaction applied before emission.

```json
{"ts":"...","level":"warn","msg":"tool denied","run_id":"run_01J8...",
 "trace_id":"01J8...","tool":"process.exec","rule":"approve-novel-exec",
 "reason":"UNKNOWN_EXECUTABLE","agent":"coder-01"}
```

Levels are used with discipline: `error` means an operator should look; `warn` means something was denied or degraded; `info` is lifecycle; `debug` is off by default. An `error` that fires routinely trains people to ignore errors.

### Privacy

| Destination | Content |
|---|---|
| Local logs | Full, redacted, on your disk |
| Local traces | Full, redacted |
| **Exported OTLP** | Metadata and metrics only — no prompts, no tool arguments, no results, by default |
| Telemetry to us | **None.** No phone-home, no version check, no usage statistics, at any setting. |

Exporting content is possible (`observability.export_content = true`) for people running their own collector who want it, and it is off by default with a warning when enabled.

The no-phone-home position is deliberate and absolute: a local-first agent runtime that quietly contacts a vendor on startup has already conceded the premise. Version checks are a manual `direwolf update check`.

## 3. Replay vs re-run

A distinction worth stating precisely, because conflating them is dishonest.

### Deterministic replay

Reconstructs what happened from stored events and manifests **without contacting any model**. Reconstructible: run state transitions, task graph evolution, every context bundle (from manifests + referenced content), every tool invocation with canonical arguments and results, every policy decision (recomputable from `policy_hash` + canonical action), budget consumption, the audit chain.

```console
$ direwolf replay run_01J8...
$ direwolf replay run_01J8... --at turn=7 --show-context
$ direwolf replay run_01J8... --policy policy/stricter.toml   # what would have happened?
```

That last form is the most useful: replay a real run against a candidate policy to see exactly which actions it would have blocked, before deploying it.

### Behavioural re-run

Executes the same task again against a model. **Output will differ.** Same prompt, same model, same temperature — still differs, because providers do not guarantee determinism, and because model versions move.

```console
$ direwolf rerun run_01J8... --model anthropic/claude-opus-5
```

Useful for regression testing and evals. **It is not replay, and DireWolf never labels it as such.** Any UI or documentation calling a model re-execution "replay" is misrepresenting the guarantee.

## 4. `direwolf doctor`

The single command that tells an operator whether the security posture is what they think it is.

```console
$ direwolf doctor
  Kernel         running (pid 4412, user direwolf-kernel)           OK
  Socket         mode 0600, owner direwolf-kernel                   OK
  Store perms    runtime user CANNOT write kernel.db / audit.log    OK
  Policy         profile=balanced, 47 rules, hash 9c1f...           OK
  Audit          184,412 records, chain intact                      OK
  Sandbox        docker 29.7.2, oci-strict verified                 OK
  Seccomp        profile loaded, 14 syscalls blocked                OK
  Landlock       unavailable on this platform                       WARN
  Egress proxy   listening, default-deny, 3 hosts allowlisted       OK
  Secrets        4 handles, 1 rotation due (github-primary, 94d)    WARN
  Grants         2 standing grants, next expiry in 12d              OK
  Providers      anthropic OK, ollama unreachable                   WARN
  Clock skew     +0.4s                                              OK

  2 warnings. `direwolf doctor --explain landlock` for detail.
```

`doctor` is the answer to "is my hardening actually on?" It checks facts, not configuration intent — it verifies that the runtime user genuinely cannot write `kernel.db` by attempting it, rather than reading a setting that claims so.
