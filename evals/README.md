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
   `gate`, `pending_reason`. Unknown keys are an error, not a silent no-op, and
   so is a malformed value: `seed = "zero"` or `gate = "false"` is a
   configuration error with a location, never a traceback (and never a `gate`
   that reads as the opposite of what the file says, which is what
   `bool("false")` would have given you).
3. If you need new behaviour, add a function to a module in
   `src/direwolf_evals/runners/` and register it in `runners/__init__.py`.
   **A suite file can only name a registered runner** — it can never point at
   an import path, because a fixture that chooses code is a second execution
   path. The same is true of `scorer`: it must name one of the four in
   `scoring.SCORERS`, and discovery says so before anything runs.
4. Run `make eval`, then `make eval-check`. If the expectations changed on
   purpose, run `uv run --frozen python -m direwolf_evals baseline` and put the
   diff in the pull request.

### Identifiers

`<suite id>/<eval name>`, stable across commits — results are compared by it.
Discovery sorts suites by id and evals by id, so the same tree always produces
the same set, the same order and the same identifiers. Nothing depends on
filesystem traversal order, import order, the clock or a random value.

## Pending, and how a suite turns on

An eval is PENDING **exactly when one of the milestones in its `requires` is
not in `AVAILABLE_MILESTONES`** (in `runner.py`). Nothing else makes it pending,
and nothing else keeps it pending.

In particular `pending_reason` does not. It is the human half of the sentence —
the clause after the colon in *"requires M3: there is no authority process to
lie to."* — and it is documentation, not a switch. It used to be read as one:
an eval that had the field was pending for ever, so adding `"M3"` to
`AVAILABLE_MILESTONES` would have left every M3 security property dormant while
the summary still said "pending", which is the exact shape of a gate that never
fires.

The machine half of the reason is generated from `requires`, so a property
deferred from M3 to M9 changes the recorded reason even if nobody edits the
prose — and the baseline notices (see *Baselines*). Writing the milestone into
`pending_reason` as well is refused: two sources of truth for the same fact are
how they come to disagree.

Turning a milestone on is therefore:

1. add it to `AVAILABLE_MILESTONES`;
2. give each eval that was waiting a real runner;
3. watch it pass.

Step 2 is not optional. An eval whose milestone has arrived and which has **no
runner, or an unknown one, reports ERROR** and fails the gate. That is
deliberate: a security property that cannot run once its component exists is a
configuration defect, and saying "pending" about it would be the original bug
wearing a different status. For the same reason, none of the evals in
`suites/pending-kernel.toml` names a placeholder runner — a placeholder would
start reporting a pass for a property it never measured.

`requires` is checked for shape too: `"m3"` is refused, because a milestone that
can never match would be permanent dormancy arriving through the other field.

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

**Numbers in a result are machine truth.** A `score` is `None` or a finite
number in [0, 1]; a metric may be any finite number (a count and a duration are
legitimate metrics) but never `NaN` or `Infinity`. This is enforced at four
places, because one layer is an assumption: the scorer, the runner before the
result is built, `Result.__post_init__`, and `json.dumps(..., allow_nan=False)`
on the way out.

`NaN` is the one that matters. `float("nan") < 1.0` is `False`, so a NaN score
compared against a baseline threshold reads as *not below it* — a silent pass
for a measurement that failed to produce a number. It cannot exist now, and if
one were smuggled in, the baseline comparison calls it out rather than waving it
through.

## Scores and statistics

A scorer turns one outcome into one number in `[0, 1]`: `binary`,
`rejection_rate`, `determinism_rate`, `stability_rate`. What a number *means*
is the suite's business, and every suite says so in its own file.

The registry is **closed**, and checked twice. Discovery rejects a suite that
names a scorer not in it — with the list of valid names — so a typo like
`rejecton_rate` is a configuration error and no eval on that suite runs. Scoring
itself then happens *inside* the runner's containment, so a scorer that raises
anyway is an ERROR for that one eval rather than the end of the process. The
blast radius of a bad suite file is one eval; the other twenty still run and
still reach the results file.

For evals with `runs > 1` the summary reports the pass rate with a **Wilson
score interval** at 95%, stating the count, `n` and the method. There is no
general statistics framework: two numbers are what M2.5 needs, and a continuous
metric will get an explicitly justified method when a suite has one.

## Seeds and reproduction

Every result records its seed. A failure prints the exact command that re-runs
it, and `make eval-one ID=... SEED=...` does the same from a terminal. Seeds
are fixed in the suite file; `--seed` overrides them for an experiment.

## Baselines

`baselines/main.json` states the expected status of each eval, any minimum
score, and — for a pending eval — the reason. It is **not** "whatever passed
last time": `make eval-check` compares against it, and nothing rewrites it
automatically, not locally and emphatically not in CI. Regressions (a worse
status, a score below the threshold, a missing eval) fail. An eval that improved
is reported so that the baseline can be updated on purpose.

**`pending_reason` is compared**, exactly, on the stripped string. A field that
is written but never read is decoration, and this one carries the milestone a
security property is waiting for: expected `"requires M3: …"` against an actual
`"requires M9: …"` is a property that slid six milestones into the future behind
an unchanged status, and it fails. A reason that disappeared fails; a reason
that appeared where the baseline recorded none is reported, so that it is added
deliberately rather than inherited. A threshold is validated on load as well — a
`min_score` of `NaN` bounds nothing while looking like a bound.

## Fault injection

`direwolf_evals.process` starts a deterministic child
(`direwolf_evals.dummy_child`), waits for named checkpoints, releases it,
pauses it, terminates it and detects hangs. Platform support is reported rather
than faked: OS-level pause uses `SIGSTOP`/`SIGCONT` and is POSIX-only; on
Windows that half reports `unsupported` instead of passing.

**`close()` returns only once the child has been reaped.** Killing is not
collecting: on POSIX a killed process stays in the table until its parent waits
for it, so `kill()` with no following `wait()` leaks a zombie per eval. The
sequence is terminate → bounded wait → kill → bounded wait → join the reader
threads → close the pipes, and a child that survives all of that raises
`CleanupError` rather than being quietly left behind. `close()` is idempotent
and correct at every stage of a child's life, including one that never started.
Correctness comes from `Popen.wait` blocking in the OS, not from polling.

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
- **Pending-reason drift is caught by exact string comparison.** That is a
  deliberate choice over anything fuzzier — fuzzy matching would hide the drift
  it exists to catch — but it means rewording a reason is a baseline diff a
  reviewer has to approve. That is the intended cost.
- **`CleanupError` reports an uncollectable child; it cannot remove one.** If a
  process survives SIGTERM and SIGKILL, something outside this harness is wrong
  with the host, and the harness says so rather than pretending otherwise.

## What is deliberately not here

- No `FakeKernel`, `MockAuthorityServer`, `AuthoritySimulator` or
  `KernelClient`. A test convenience that accumulates M3 semantics would make
  M3 inherit them.
- No provider SDK, no network client, no live model call.
- No fuzzing. `make fuzz` and `make fuzz-smoke` own that; fuzzing *discovers*
  parser failures, evaluation *measures named properties*, and mixing them
  makes both harder to read.
- No `evals/results/` in git: runs write to `target/evals/`, which is ignored.
