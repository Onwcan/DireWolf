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
| `tests/architecture/` | Repository-level checks: the boundary rules, the quality gates, and the CI wiring that carries evidence only CI can produce (`test_ci_authority_gate.py`) | the tools installed |
| `tests/authority/` | Deployment verification run **as a different operating-system user**: `runtime_write_probe.py` attempts the runtime's forbidden writes to authority state (`make authority-write-probe`); `foreign_peer_client.py` is the M3e cross-uid DWKP client the transport evidence runs through `sudo -n -u $DW_PEER_AS` | a second identity; otherwise it reports NOT EXERCISED and fails |
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

**Authority state tests (M3d)** — `crates/dwkd-authority/tests/state_*.rs` —
drive the real store: real directories, real SQLite files, real `audit.log`s,
and DWKP requests passed through `dwk_proto`'s real decoder. Nothing is mocked.
Where a test tampers with a file or reads a row the API does not expose, it
opens its own `rusqlite` connection, as an attacker with file access would.
`state_crash.rs` covers every crash window both in process (a crash hook that
stops the authority at a named point) and by killing a child process, then
restarts on the files left behind. `state_wire.rs` sends every response the
state layer produces back through the encoder and decoder, and
`state_restart.rs` kills a real authority after committing an admission whose
response was never delivered, restarts it, and proves the same key can never
admit a second run (ADR-0040).
`make authority-state-evidence` runs the suites, a diagnostic latency run and
the closure report together; `state_probe.rs` holds the two `#[ignore]`d
fixtures that need something `cargo test` cannot provide — a second user, and
a quiet machine.

**Authority transport tests (M3e)** — `crates/dwkd-authority/tests/transport_*.rs`
— are **real-process** evidence: they spawn the released `dwkd-authority`
binary (`serve`, the operator's code path — there is no test server), prepare
state through the in-process operator API before it starts, and talk to it
from the test process over a real Unix-domain socket, reading `audit.log`
through the verifier. `transport_server.rs` covers the request path, the
kernel-derived subject, holders, fencing, `SIGKILL` and restart, a poisoned
store and socket-name attacks; `transport_hostile.rs` is the hostile DWKP
client; `transport_stress.rs` the resource bounds; `transport_foreign.rs`
(`#[ignore]`d) runs a client as a **different OS user**. Each passing case
prints one `DWKP-EVIDENCE` line, which the M3 evaluations read.
`make authority-transport-evidence` runs them all and needs `DW_PEER_AS` for the
cross-uid half ([ADR-0041](../docs/adr/0041-m3e-authenticated-dwkp-transport.md)).

**Filesystem operation tests (M4c)** are the evidence behind
`make filesystem-operations-evidence` ([ADR-0044](../docs/adr/0044-m4c-filesystem-operations-plans-and-atomic-mutation.md)):
`crates/dwkd-authority/tests/broker_fs_ops.rs` drives every tool end to end
through the released daemons — previews against a tree snapshot and the
preview/invoke differential, compound denials, idempotency keys, hard links,
symlinks, listing names, search bounds, `fs.create` scope semantics, version 1
answered in version 1, no content in the audit log, and stable descriptors;
`fs_ops_state.rs` runs the race campaigns (R1–R9, the tree changed between the
handoff and the broker), the crash campaigns (A–K: authority crash points,
and a debug broker aborting at `DWKD_BROKER_CRASH_AT`) with every staging
directory's settlement, and the staging campaigns (pre-effect crashes removed,
repeated crashes bounded and tracked, directories spelled like the broker's
never touched, reclamation never following a replaced, renamed or symlinked
root or a replaced parent) on the real channel; `broker_state.rs` proves a
stored grant re-reads unchanged while every tool target is resolved afresh,
and `src/state/lookup_tests.rs` — inside the authority crate, where the
test-only lookup counter lives — that a stored grant and an admission replay
begin zero filesystem lookups; the broker's own unit tests place
substitutions before and after its last check, fail its undos, and judge
every staging state, through a test-only hook that also records which points
were reached and traces every namespace change and `fsync`, holding every
operation to the durability order (each changed directory synced before the
next change);
`crates/dwk-proto/tests/dwkp_v2.rs` encodes the largest patch request whole
and proves it fits one frame; `crates/dwkd-broker/tests/private_protocol.rs`
adds hostile version-2 descriptors, reclamations included; `permission_model.rs` is the local half of the write permission
experiment; and `fs_ops_foreign.rs` needs three identities and a write group
(`DW_BROKER_AS`, `DW_PEER_AS`, `DW_WRITE_GROUP`) and is `#[ignore]`d unless the
evidence task selects it by name. Locally the three-identity half is NOT
EXERCISED; CI's Linux job creates the broker user and the group.

**Brokered `fs.read` tests (M4b)** are real-process evidence for the private
channel ([ADR-0043](../docs/adr/0043-m4b-private-broker-channel-and-brokered-fs-read.md)):
`crates/dwkd-authority/tests/broker_fs_read.rs` drives the released authority and
broker end to end over DWKP; `broker_state.rs` sweeps every crash point of one
invocation, proves from `/proc/self/fd` that no readable descriptor exists
before the intent is durable, fails an invocation whose file changes between
the intent and the open, scripts a hostile broker on the real channel and
changes the tree between the check and the read;
`crates/dwkd-broker/tests/private_protocol.rs` plays a hostile authority-side
peer against the released broker, measuring with the kernel's `rchar` count
that a read bounded at N reads N bytes and that a wrong descriptor count reads
none; `admission_fs.rs` proves admission resolves every new concrete `fs.read`
declaration through the M4a resolver;
`broker_foreign.rs` needs three identities (`DW_BROKER_AS`, `DW_PEER_AS`) and is
`#[ignore]`d unless `make broker-fs-read-evidence` selects it by name, with
`tests/authority/broker_foreign_client.py` as the process that runs as the other
users. Locally the three-identity half is NOT EXERCISED; CI's Linux job creates a
broker user and runs it. The authority's suites spawn the broker binary Cargo
builds beside the authority's, so run them through `cargo test --workspace` or
the evidence command.

**Canonical filesystem tests (M4a)** are real-filesystem evidence for the
one resolver ([ADR-0042](../docs/adr/0042-m4a-canonical-filesystem-resolution.md)).
`crates/dwkd-authority/src/resource/fs/linux/tests.rs` runs the production
resolver — there is no test resolver — against real symlinks, procfs magic
links, mount points, hard links, FIFOs, sockets, devices, NFC/NFD twins and
a replaced root, and runs six TOCTOU campaigns in which an attacker thread
exchanges names while the resolver walks; `tests/resource_workspace.rs`
covers the state layer — binding a root, resolving for a run, the workspace
anchor, and migrating an M3 store. Each case prints one `FS-EVIDENCE` line.
`make filesystem-canonicalization-evidence` (Linux) runs both and fails on a
category with no exercised case, a race campaign with an escape, or a case
not exercised that an ordinary machine can exercise.

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
