# Test layout

Where a test goes is decided by *what it needs*, not by what it is about.

| Location | Contains | Needs |
|---|---|---|
| `crates/<crate>/src/**` — `#[cfg(test)] mod tests` | Rust unit tests, next to the code | nothing |
| `crates/<crate>/tests/*.rs` | Rust integration tests: the built binary as a subprocess, or a library's public API against shared data | a build |
| `runtime/tests/` | Python unit tests for the `direwolf` package; `runtime/tests/proto/` for the wire layer and generated bindings | the package importable |
| `tests/protocol/` | **Data, not tests:** golden vectors both languages run, and the V8 oracle that produced their canonical bytes | nothing (Node only to regenerate) |
| `fuzz/` | cargo-fuzz targets; bodies shared with `crates/dwk-proto/tests/fuzz_smoke.rs` | nightly, cargo-fuzz, a C++ compiler |
| `tools/dwcheck/tests/` | Unit tests for the boundary checker itself | the package importable |
| `tests/architecture/` | Repository-level checks: the boundary rules and the quality gates | the tools installed |
| `tests/integration/` | Cross-process tests: runtime ↔ authority ↔ broker | **M3+**; does not exist yet |
| `evals/` | The evaluation harness, its suites, fixtures and baseline | the harness installed (`make eval`) |

`tests/integration/` is deliberately absent rather than empty. An empty
directory with a placeholder file is a promise nobody has to keep; a row in this
table is a decision about where the work will go when there is work.

## What each level is for

**Rust unit tests** live in the module they test. Pure functions —
canonicalisation, the capability lattice, policy matching — are tested here.

**Protocol tests (M2)** are the one place two languages must agree byte for
byte, so they are driven by shared data rather than written twice:

- `tests/protocol/vectors/valid.json` and `invalid.json` are run by
  `crates/dwk-proto/tests/golden.rs` *and* `runtime/tests/proto/test_golden.py`.
  A valid vector must decode and re-encode to the same canonical bytes and frame
  in both; an invalid one must fail with the same `(code, violation, path)`.
- `tests/protocol/vectors/numbers.json` is 8,915 doubles with the string V8
  produces for each; RFC 8785 number formatting is checked against it in both
  languages. `tests/protocol/oracle/*.mjs` regenerates it and the canonical
  columns of `valid.json`. Nothing in CI runs Node.
- Property tests: `proptest` in `crates/dwk-proto/tests/properties.rs`; seeded
  standard-library generators in `runtime/tests/proto/test_properties.py`.
- Fuzzing: the same four target bodies run under libFuzzer (`make fuzz`) and a
  stable mutation loop (`make fuzz-smoke`, and briefly in every `cargo test`).

**Rust integration tests** run the real binary. `crates/direwolf-cli/tests/cli.rs`
asserts the exit codes and output a user actually sees, which is the contract a
unit test cannot check.

**`tests/architecture/`** is the unusual one, and it is the point of M1. It
contains two things:

- `test_boundaries.py` — points the *real* rules in `architecture.toml` at a
  deliberately-invalid fixture tree and asserts every rule fires. A rule that
  never rejects anything is not a rule.
- `test_quality_gates.py` — runs each real tool against a fixture that is wrong
  in exactly one way, and asserts a non-zero exit. The acceptance criterion is
  not "a linter is configured" but "the linter rejected a known violation".

`tests/architecture/fixtures/` is excluded from ruff, mypy and pytest
collection. Those files are *supposed* to be broken; linting them would be
checking the wrong thing. The exclusions are in `pyproject.toml` and
`architecture.toml`, each with the reason next to it.

## Conventions

**Name the test after what breaks, not after the function.**
`test_broker_cannot_depend_on_authority` says what a failure means.
`test_check_crates_2` does not.

**A test for an invariant is named after the invariant.** When the kernel
exists, every invariant in [README.md](../README.md) gets a test named for it —
`test_I2_child_caps_cannot_exceed_parent` — so that deleting the invariant
deletes a specifically-named test rather than quietly passing.

**No coverage-percentage target.** The gate is behavioural: every invariant has
at least one test that fails if the invariant is removed
([LANGUAGE_SELECTION.md](../docs/LANGUAGE_SELECTION.md) §7).

**Do not write tests for unimplemented features.** A test asserting that a
`PolicyEngine` that does not exist behaves correctly is a test that will be
rewritten when the real one arrives, and in the meantime it makes the suite
look larger than it is. What M1 *does* assert is the opposite: that those
subsystems are absent (`test_no_subsystem_modules_exist_yet`,
`the_agent_command_surface_is_not_stubbed`). Those tests fail when someone adds
a stub, which is exactly when a foundation starts rotting.

## Running them

```bash
make test          # cargo test --workspace, then pytest
cargo test -p direwolf-cli
cargo test -p dwk-proto --test golden
uv run --frozen python -m pytest tests/architecture -v
uv run --frozen python -m pytest runtime/tests/proto
DWK_FUZZ_SECONDS=60 make fuzz-smoke
```

`pytest.ini` options live in the root `pyproject.toml`. Tests marked `slow`
invoke a compiler or a package manager; they still run by default, because a
gate that is routinely skipped is not a gate.

## The evaluation harness

`evals/` is the M2.5 harness: deterministic discovery, structured results, a
reviewed baseline, replayable fixtures, the hostile-protocol suites and a
fault-injection harness proved against a dummy process
([evals/README.md](../evals/README.md), [EVALS.md](../docs/EVALS.md)).

It is a *measuring* tool, so it lives beside the tests rather than in them:
`make eval-check` is part of `make check` and of CI, and `evals/tests/` holds
the tests **of the harness itself** — including the one that feeds it a known
bad result and asserts that the gate goes red.

Suites whose subject does not exist yet (everything needing the kernel, the
brokers, the sandbox, approvals or model egress) are **pending**, which is
counted apart from passing and from skipping.

## What arrives later

**M3.5 — the vertical slice.** One tool end to end, with published latency and
approval-frequency measurements. Its tests belong in `tests/integration/`.

Neither milestone may be merged into generic hardening or postponed: they exist
because the riskiest assumptions in this product were otherwise first
measurable two years in.
