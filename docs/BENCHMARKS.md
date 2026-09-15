# Competitive Benchmark Methodology

How DireWolf may be compared to Hermes Agent and OpenClaw, and the rules that keep the comparison honest.

---

## 1. The problem with agent benchmarks

Agent benchmarks are trivially gameable. You pick tasks your architecture suits, configure your system optimally and theirs by default, run once, and publish a bar chart. Everyone does it and nobody believes any of it.

This document exists to constrain us before we have results, so that when results arrive we cannot quietly choose the flattering framing.

## 2. Binding rules

1. **Configuration disclosure.** Every result states the exact configuration of every system, including version, model, policy profile and any hardening applied. Comparing DireWolf-hardened against a competitor's default is dishonest; both competitors ship permissive defaults *and* document hardened postures, so **every security comparison reports both** — competitor-default and competitor-hardened — and says which is which.
2. **Same model, same day.** All systems use the same model version, run within the same 24 hours. Comparing across model generations measures the model.
3. **N ≥ 5, distributions not points.** Median and IQR. A single run is an anecdote.
4. **Task sets are published before results.** Tasks, fixtures and scoring rubrics are committed first, with a commit hash, so they cannot be adjusted after we see the numbers.
5. **Failures published.** Including every case where DireWolf loses. A benchmark repository with only wins is advertising.
6. **Third-party reproducibility.** Docker images, pinned versions, one command. If nobody else can run it, it is a claim, not a measurement.
7. **"Not applicable" is a valid result** and must never be scored as a win. Where a system cannot run a task because it lacks the feature, report `N/A` with a note — do not award ourselves a point for a browser benchmark our competitors run and we cannot.
8. **No metric invented after seeing results.** The metric set is fixed with the task set.
9. **Architecture is not benchmarked.** Design arguments are labelled as design arguments. There is no measurement that proves an architecture is better, and we do not manufacture one.

## 3. What can and cannot be compared

| Category | Comparable? | Why |
|---|---|---|
| Task success on shared tasks | **Yes** | All three take a natural-language task and produce a result |
| Token and monetary cost per success | **Yes** | Measurable from provider usage |
| Latency | **Yes** | Wall clock |
| Security containment | **Yes, with care** | Probes are runnable against any system; see §5 |
| Crash recovery | **Yes** | Kill the process, attempt resume |
| Context efficiency | Partially | Definitions differ; report raw tokens and normalise carefully |
| Memory quality | Partially | Memory models differ enough that a shared corpus is approximate |
| Channels, browser, plugins | **No — DireWolf V1 lacks them** | Report `N/A`, not a win |
| Audit completeness | Structural, not measured | Report what each system records, by inspection |
| Developer experience | **No** | Subjective. Describe, do not score. |

## 4. Capability-parity task set

Tasks all three can attempt, drawn from real repositories with committed fixture states.

| Group | Examples | Scoring |
|---|---|---|
| Coding | Fix a failing test; add a feature across 3 files; refactor with the suite green; diagnose a stack trace | Tests pass + no regression |
| Tool reliability | 30-step file/exec sequence; recover from a deliberately failing tool; handle a 200 MB output | Completion + correctness |
| Long-horizon | 50+ turn migration; maintain goal across compaction | Goal achieved + constraint retention |
| Research | Synthesise 5 sources; verify citations | Factual accuracy + citation validity |
| Multi-agent | Parallel work on 3 modules with a merge | Completion + conflicts correctly surfaced |
| Session continuity | Resume after 24 h; reference a decision from turn 3 | Correct recall |
| Crash recovery | `SIGKILL` mid-task, resume | Resumed, or failed closed with a specific reason |
| Cost discipline | Same task under a fixed budget | Success within budget |

**Partial credit** via rubric, scored by a *different* model than the one under test, with a human-scored sample to calibrate the grader. Grading rubrics are published.

## 5. Security probe set

The probes from [EVALS.md](EVALS.md) §3, packaged to run against any system exposing a CLI or API.

Reported per system as: **contained** (attack failed), **contained + audited** (failed *and* recorded), **partial** (some effect), **uncontained**, or **N/A** (feature absent).

Ethical rules, non-negotiable:

- Probes run **only against our own instances**, in isolated environments, with fake credentials and canary tokens.
- No probing of anyone else's deployment, ever.
- Novel exploitable findings against a competitor go to that project's security process **first**, under their disclosure policy, and are excluded from published comparisons until fixed or the disclosure window closes.
- We never publish a working exploit for an unpatched third-party system to make a competitive point.

**Expectation, stated in advance:** DireWolf should win decisively on containment when all systems run at their documented hardened postures, because that is the one thing it is built for. If it does not, the architecture has failed and the honest response is to publish that and reconsider — not to re-tune the probes.

Conversely, we should expect to **lose** on false-denial rate: strict defaults will block some legitimate actions competitors permit. That number gets published with equal prominence.

## 6. Reporting

```
benchmarks/results/2026-11-15/
  config.yaml       versions, models, hardware, profiles, dates
  tasks.lock        task set commit hash
  raw/              every run, every log, every trace
  summary.md        medians, IQRs, N/A counts
  caveats.md        every reason a comparison is imperfect
```

`caveats.md` is mandatory and written **before** `summary.md`. Known caveats already: DireWolf lacks browser/channels/plugins, so whole categories are `N/A`; competitors have vastly more real-world hardening; our task set will unconsciously reflect our design; competitor defaults differ from their hardened postures in ways that make a single number misleading; and a kernel round trip per tool call is a real latency cost that will show up in interactive tasks.

## 7. The claim ladder

What we may say, and what evidence each requires:

| Statement | Evidence required |
|---|---|
| "DireWolf contains X of Y probes in configuration Z" | Published results, reproducible |
| "DireWolf's authority boundary is a process boundary" | Structural, verifiable by reading the code |
| "DireWolf costs N% more/less per successful task" | ≥ 5 runs, same model, same day |
| "DireWolf is more secure" | **Never said without naming the threat class, the configuration and the measurement** |
| "DireWolf is better" | **Never.** Better at what, for whom, measured how — or it is not said. |

## 8. Self-benchmarking

Independent of competitors, tracked per release: capability-parity success, cost per success, p99 kernel overhead, security containment, false-denial rate, crash-recovery rate.

**Regression policy:** a containment regression blocks the release. A capability regression above 5 % blocks release pending explanation. A false-denial increase above 2 points requires a policy review — because tightening security by quietly blocking more legitimate work is not an improvement, and without this rule it would look like one on every other metric.
