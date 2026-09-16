# The DireWolf evaluation harness

**This package measures claims. It implements none of them.**

M2.5 exists because a security property that cannot be measured is not a gate,
and because building the measuring equipment *after* the thing it measures
means discovering at M18 that nothing was ever checkable. The harness is here
first, and later milestones must satisfy it.

The architecture this serves is [docs/EVALS.md](../docs/EVALS.md). This file is
the implementation: what exists today, and how to add to it.

---

## What it can say today, and what it cannot

**Can:** suites are discovered and run deterministically; hostile protocol
inputs are decided by the real decoder and counted; a known-bad result fails
the gate; replay is byte-deterministic; the fault-injection harness controls a
dummy process; pending suites are declared and counted apart.

**Cannot:** anything about authority, policy, capabilities, approvals,
sandboxing, secrets or model egress. Those systems do not exist yet. Their
suites are **PENDING** — see `python -m direwolf_evals inventory` — and pending
is never a pass.

## Commands

```bash
make eval                                    # every suite, JSONL + summary
make eval-check                              # the merge gate: gate subset vs baseline
make eval-one ID=protocol-security/framing   # re-run one eval
```

Underneath, all of them are one module:

```bash
uv run --frozen python -m direwolf_evals list
uv run --frozen python -m direwolf_evals run --suite protocol-security --seed 1234
uv run --frozen python -m direwolf_evals inventory
uv run --frozen python -m direwolf_evals baseline     # deliberate; review the diff
```

Exit codes: `0` nothing failed, `1` a failure or a baseline regression, `2` a
usage or configuration error.

## Adding an eval

1. Pick the suite in `suites/`, or add a file there. A suite must say what its
   `score` **means**: there is no DireWolf score, and unlike properties are
   never averaged.
2. Add an `[[eval]]` table: `name`, `description`, `runner`, and optionally
   `fixture`, `scorer`, `seed`, `runs`, `timeout_s`, `requires`, `tags`,
   `gate`, `pending_reason`. Unknown keys are an error, not a silent no-op.
3. If you need new behaviour, add a function to a module in
   `src/direwolf_evals/runners/` and register it in `runners/__init__.py`.
   **A suite file can only name a registered runner** — it can never point at
   an import path, because a fixture that chooses code is a second execution
   path.
4. Run `make eval`, then `make eval-check`. If the expectations changed on
   purpose, run `uv run --frozen python -m direwolf_evals baseline` and put the
   diff in the pull request.

### Identifiers

`<suite id>/<eval name>`, stable across commits — results are compared by it.
Discovery sorts suites by id and evals by id, so the same tree always produces
the same set, the same order and the same identifiers. Nothing depends on
filesystem traversal order, import order, the clock or a random value.

## Fixtures

Fixtures are JSON, read with `json.loads`, and **never executed**. No YAML
tags, no `pickle`, no `eval`, no import hooks. A fixture path that tries to
climb out of the fixture root is refused.

Every fixture declares provenance, from a fixed set: `authored`,
`protocol-adversarial`, `synthetic-mutation`, `recorded-response`,
`external-corpus`. An `external-corpus` fixture must record `source`, `licence`
and `modification`, and may only be added when redistribution is permitted.
The shared protocol vectors in [`tests/protocol`](../tests/protocol) are
`protocol-adversarial` by their own file's description.

**Replay fixtures** hold an input, a recorded response, a structured
tool-call-shaped field and scorer metadata, plus a digest of each case's
canonical rendering. They are test data, not a `ModelProvider`: there is no
transport, no base URL, no credential, and **no live model call anywhere in
this package**. The real recorded corpus arrives with M7.

## Results

JSONL, one object per line, ordered by `(eval_id, run_index)` so a diff between
commits is readable. `result_version` is `1`; a format change bumps it.

Each record carries the status, the score, the seed, the run index, the
duration, the metrics, the fixture digest, bounded artifacts and the
environment. Large blobs never go in a result.

Statuses: `pass`, `fail`, `error`, `skip`, `pending`. The gate fails on `fail`
and `error`; `pending` and `skip` are counted and printed separately, never
folded into a pass.

## Scores and statistics

A scorer turns one outcome into one number in `[0, 1]`: `binary`,
`rejection_rate`, `determinism_rate`, `stability_rate`. What a number *means*
is the suite's business, and every suite says so in its own file.

For evals with `runs > 1` the summary reports the pass rate with a **Wilson
score interval** at 95%, stating the count, `n` and the method. There is no
general statistics framework: two numbers are what M2.5 needs, and a continuous
metric will get an explicitly justified method when a suite has one.

## Seeds and reproduction

Every result records its seed. A failure prints the exact command that re-runs
it, and `make eval-one ID=... SEED=...` does the same from a terminal. Seeds
are fixed in the suite file; `--seed` overrides them for an experiment.

## Baselines

`baselines/main.json` states the expected status of each eval and any minimum
score. It is **not** "whatever passed last time": `make eval-check` compares
against it, and nothing rewrites it automatically — not locally, and
emphatically not in CI. Regressions (a worse status, a score below the
threshold, a missing eval) fail. An eval that improved is reported so that the
baseline can be updated on purpose.

## Fault injection

`direwolf_evals.process` starts a deterministic child
(`direwolf_evals.dummy_child`), waits for named checkpoints, releases it,
pauses it, terminates it and detects hangs. Platform support is reported rather
than faked: OS-level pause uses `SIGSTOP`/`SIGCONT` and is POSIX-only; on
Windows that half reports `unsupported` instead of passing.

The relationship is one-directional, so M3 can instrument the real daemon
without this package learning anything about authority:

```
real process ──(checkpoint lines)──▶ harness ──▶ eval
```

## The test-only execution environment

`direwolf_evals.test_environment.EvalTestEnvironment` models success, failure,
timeout, crash and partial output. It runs nothing: no shell, no subprocess, no
filesystem, no network. DireWolf's real `ExecutionEnvironment` is M5, in
`dwkd-broker`, in Rust. `architecture.toml` rule **PY003** forbids the runtime
and the tools from importing this package at all, so a test double cannot
become a product path.

## Known limitations of the harness itself

- **`timeout_s` bounds the child processes a runner drives, not the runner.**
  A runner that loops forever is not interrupted by the harness; pytest and CI
  time it out instead. Per-eval wall-clock enforcement needs a worker process
  per eval, which is a cost M2.5 does not need to pay for suites that run in
  milliseconds.
- **OS-level pause is POSIX-only.** On Windows that half of the pause/resume
  eval reports `unsupported`; the stdin-gated checkpoint mechanism works
  everywhere, and it is what the suites rely on.
- **Statuses are per run, and aggregation is per eval.** There is no
  cross-suite aggregate, deliberately: see *Scores and statistics*.
- **A fixture's digest proves it has not changed, not that it is right.**
  Provenance says where it came from; review says whether it should be trusted.

## What is deliberately not here

- No `FakeKernel`, `MockAuthorityServer`, `AuthoritySimulator` or
  `KernelClient`. A test convenience that accumulates M3 semantics would make
  M3 inherit them.
- No provider SDK, no network client, no live model call.
- No fuzzing. `make fuzz` and `make fuzz-smoke` own that; fuzzing *discovers*
  parser failures, evaluation *measures named properties*, and mixing them
  makes both harder to read.
- No `evals/results/` in git: runs write to `target/evals/`, which is ignored.
