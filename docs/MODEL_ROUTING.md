# Model Routing

**The router proposes. The kernel disposes.** That separation is the whole design.

---

## 1. Why routing is not an enforcement point

A router is a heuristic component in the untrusted plane. It can be wrong, badly configured, or — because it takes a task description as input — influenced by injected content. "Route this to the cheap model" is a legitimate optimisation. "Route this to `attacker-proxy.example.com/v1`" must be impossible.

So the router produces a **ranked proposal**, and the kernel independently decides whether the chosen upstream may receive this content ([NETWORK_SECURITY.md](NETWORK_SECURITY.md) §6).

## 2. Interface

```python
route(task: TaskProfile, constraints: RouteConstraints) -> list[ModelChoice]

TaskProfile:
    kind: REASON | CODE | CLASSIFY | EXTRACT | SUMMARISE | VISION | EMBED
    est_input_tokens: int
    est_output_tokens: int
    needs_tools: bool
    needs_parallel_tools: bool
    needs_vision: bool
    needs_structured_output: bool
    latency_sensitivity: INTERACTIVE | BACKGROUND | BATCH
    quality_floor: float                 # 0..1

RouteConstraints:
    privacy_class: LOCAL_ONLY | VENDOR_OK | ANY    # from POLICY, not from the task
    allowed_upstreams: list[Origin]                 # from POLICY
    budget_remaining: Budget
    health: dict[ModelId, HealthState]
    user_pin: ModelId | None
```

`privacy_class` and `allowed_upstreams` arrive from the kernel's policy evaluation at run admission. The router receives them as given and cannot widen them.

## 3. Selection

```
1. eligible = models where
       capabilities ⊇ task requirements      (tools, vision, structured output, context)
     ∧ origin ∈ allowed_upstreams
     ∧ privacy_class permits origin
     ∧ health ≠ unavailable
     ∧ estimated_cost ≤ budget_remaining
2. if user_pin ∈ eligible → [user_pin, ...fallbacks]
3. score = quality_fit·w_q + cost_fit·w_c + latency_fit·w_l + health·w_h
       INTERACTIVE   0.35 / 0.15 / 0.40 / 0.10
       BACKGROUND    0.45 / 0.35 / 0.10 / 0.10
       BATCH         0.35 / 0.55 / 0.00 / 0.10
4. return ranked list; the loop falls through on failure
```

Declarative overrides:

```toml
[[route]]
when.kind = "CLASSIFY"
when.est_input_tokens = { lt = 4000 }
prefer = ["anthropic/claude-haiku-4-5", "local/qwen3-8b"]

[[route]]
when.workspace_sensitivity = "high"
require.privacy_class = "LOCAL_ONLY"      # a request; policy must also permit it

[[route]]
when.kind = "REASON"
when.quality_floor = { gte = 0.9 }
prefer = ["anthropic/claude-opus-5"]
```

`require.privacy_class` can only *tighten* what policy allows. A route rule asking for `ANY` where policy says `LOCAL_ONLY` is ignored and logged as a configuration error — not negotiated.

## 4. Fallback, escalation, degradation

**Fallback** (the model failed): walk the ranked list, respect the circuit breaker, jittered backoff, bounded by `max_model_attempts` per turn.

**Escalation** (the model succeeded but poorly): allowed only under narrow, explicit conditions — malformed tool arguments twice running, output failing schema validation twice, or an explicit low-confidence signal. Escalation costs money, so it is budget-debited and capped per run. An agent cannot escalate its way through a budget.

**Degradation** is the more useful direction: as budget nears exhaustion, drop to cheaper models for `CLASSIFY`/`EXTRACT`/`SUMMARISE` rather than failing the run, and record that in the context manifest so the quality drop is visible afterwards.

## 5. Health

Per `(provider, model)`:

```
healthy     → degraded      5 failures in 60 s, or p99 latency > 3× baseline
degraded    → unavailable   10 consecutive failures
unavailable → half-open     backoff 30 s, doubling, cap 15 m, ±20 % jitter
half-open   → healthy       3 consecutive successes
```

Error classes drive transitions: `RATE_LIMIT`/`OVERLOAD` count toward degradation and honour `Retry-After`; `AUTH` trips straight to unavailable and alerts the operator, because a bad key will not fix itself; `INVALID` does not count at all, because it is our bug.

## 6. Cost

A declarative price table per model — input, output, cache read, cache write, per million tokens — each entry carrying an `as_of` date. Pre-call estimates use the table; post-call actuals come from the kernel metering the provider's own usage block.

**Estimates are advisory; the ledger is authoritative.** Divergence above 20 % raises a warning naming the model, which almost always means a stale price entry.

Because the kernel performs the call, cost control is structural: there is no unmetered path, so a run cannot exceed its monetary budget by mis-estimating.

## 7. Privacy enforcement, end to end

| Layer | Role |
|---|---|
| Workspace sensitivity label | Sets the default privacy class |
| Policy (admission) | Decides the run's `privacy_class` and `allowed_upstreams` |
| Router | **Proposes** within those constraints |
| Kernel model egress | **Enforces** — holds the credential, refuses disallowed origins |
| Upstream aggregator or cloud platform | **Routes again, on its own side** — OpenRouter, Hugging Face's router or a platform's model catalogue picks the backend. The kernel authorises the aggregator's origin, and policy counts every backend it may forward to as reached: never `LOCAL_ONLY`, and a backend preference sent to it narrows a request without authorising anything. An operator-run gateway (LiteLLM Proxy; deferred, [ROADMAP.md](ROADMAP.md) M7) is an aggregator too, whatever address it listens on |
| Local or self-hosted server | **Declared, not discovered** — Ollama, llama.cpp's `llama-server`, vLLM, SGLang, LM Studio, a self-hosted Hugging Face or NVIDIA NIM deployment is reached only through an operator-declared profile naming its exact origin or Unix socket. Being on loopback authorises nothing; a profile's loopback exception is bound to its origin and to model egress alone; `LOCAL_ONLY` admits only origins the kernel resolves to loopback or to an operator-declared local address ([ROADMAP.md](ROADMAP.md) M7) |

A wrong router is a quality problem. A compromised router is still not a confidentiality problem.

Provider breadth ([ROADMAP.md](ROADMAP.md) M7) adds candidates to step 1's eligible set (§3); it never adds a way around it. A candidate's capabilities — tools, parallel tools, vision, structured output, context limit — are what its profile **declares** and a recorded fixture backs, so `needs_tools` or `needs_structured_output` (§2) excludes a local server that has not declared them rather than letting the request degrade silently. Fallback (§4) walks only that set, so health-driven failover is constrained routing, never permission to try any available vendor, and a provider family changes which model answers, never what the run may reach.

## 8. Testing

Property tests: a route never returns a model violating `privacy_class`, never one missing a hard capability, never one over remaining budget; results are deterministic given fixed health and pricing. A simulation harness replays recorded task profiles against candidate configs so routing defaults change on evidence rather than intuition.
