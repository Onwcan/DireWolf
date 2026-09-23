# Contributing to DireWolf

DireWolf is a security-first agent runtime. Most of what makes it different is
structural, so most of what this document says is about structure: which
process a change belongs in, which boundary it must not cross, and what a
reviewer needs from you.

Read [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) §3 and
[ADR-0018](docs/adr/0018-authority-broker-split.md) before your first change to
anything under `crates/`. Everything else here fits on two screens.

---

## Prerequisites

| | Why | Install |
|---|---|---|
| **Rust**, pinned by `rust-toolchain.toml` | The authority plane and the CLI | [rustup.rs](https://rustup.rs) — rustup reads the pin and installs it for you |
| **Python 3.12+** | The cognition runtime, the tooling, the tests | your platform's usual route |
| **uv** | The only Python package manager this repository uses | `python -m pip install --user uv`, or [docs.astral.sh/uv](https://docs.astral.sh/uv/) |
| **git** | | |

Nothing else. `make dev` installs the rest into the repository, including
`cargo-deny`, which it compiles from source the first time.

## Setup

```bash
git clone <url> direwolf && cd direwolf
make dev
```

`make dev` is idempotent: it verifies the toolchain, syncs the locked Python
environment, builds the Rust workspace, installs the cargo-hosted tools, runs
the architecture checks, and prints what to run next. Running it twice changes
nothing.

Then:

```bash
make check
```

That is every gate CI runs. If it passes locally it passes in CI, because CI
invokes the same commands.

**On Windows without WSL2**, `make` is absent. Run `python scripts/dw.py <task>`
instead — identical tasks, same output. See *Platforms* below for what native
Windows does and does not give you.

## Commands

| | |
|---|---|
| `make dev` | Set up or verify a development checkout |
| `make check` | Everything CI runs |
| `make fmt` | Format Rust and Python in place |
| `make lint` | `clippy -D warnings`, `ruff check` |
| `make typecheck` | `mypy --strict` |
| `make test` | `cargo test --workspace`, `pytest` |
| `make arch` | Architecture boundary checks |
| `make eval` | Run every evaluation suite (deterministic, offline) |
| `make eval-check` | The eval merge gate: the deterministic subset against the baseline (part of `make check`) |
| `make eval-one` | Re-run one eval: `make eval-one ID=protocol-security/framing` |
| `make capability-evidence` | The 10⁶ delegation-chain capability campaign ([CAPABILITIES.md](docs/CAPABILITIES.md) §3). Not part of `make check`: it is evidence, produced deliberately, and the fast suite runs a thousand chains to keep it working between runs. `DW_EVIDENCE_SEED` replays a run; `DW_EVIDENCE_CHAINS` shortens one while debugging |
| `make filesystem-canonicalization-evidence` | M4a's real-filesystem resolver evidence (Linux): symlinks, magic links, mounts, hard links, Unicode twins, a replaced root and the TOCTOU race campaigns ([ADR-0042](docs/adr/0042-m4a-canonical-filesystem-resolution.md) §14). Fails on a missing category, an escape, or a case left unexercised that the machine could exercise |
| `make schema` | Regenerate `schemas/`, `docs/DWKP_OPERATIONS.md` and the Python bindings from `dwk-proto` |
| `make schema-check` | Fail if any of those is stale or hand-edited (part of `make check`) |
| `make fuzz-smoke` | Type-check the cargo-fuzz targets; stable mutation fuzzing (`DWK_FUZZ_SECONDS`) |
| `make fuzz` | Coverage-guided libFuzzer, every target (nightly + cargo-fuzz; `DW_FUZZ_SECONDS`) |
| `make security` | `cargo-deny`, `pip-audit` |
| `make docs` | Relative links and ADR citations |
| `make help` | All of them |

Every target delegates to `scripts/dw.py`, which prints each command before
running it. There is no hidden build step.

## Where does my change go?

One question decides it:

> **Can this code make an authorisation decision, hold a credential, or cause a
> side effect?**

| Answer | Home | Language |
|---|---|---|
| It *decides* | `crates/dwkd-authority/` | Rust |
| It *does* — filesystem, exec, sandbox, egress | `crates/dwkd-broker/` | Rust |
| It reasons, plans or shapes data | `runtime/` | Python |
| It is the command-line surface | `crates/direwolf-cli/` | Rust |
| It is the *shape* of a message on the wire, and nothing else | `crates/dwk-proto/` | Rust (Python generated) |
| It *measures* DireWolf rather than being part of it | `evals/` | Python (test infrastructure) |

Rust holds authority. Python holds intelligence.
([ADR-0019](docs/adr/0019-language-rationale-v2.md).) There is no fourth
language; TypeScript arrives with the web UI at M27 and holds nothing.

## The boundaries, and what enforces them

`architecture.toml` holds the rules; `make arch` enforces them. Read that file
— the reasons are next to the rules.

In short:

- The cognition runtime imports no socket, no subprocess, no HTTP client, no
  `ctypes`. `direwolf.kernelclient` is the single exemption, because DWKP over
  a Unix socket is its whole job.
- Provider names appear only under `runtime/src/direwolf/providers/`.
- No autonomous-agent framework — LangChain, LangGraph, the Agents SDK or a
  successor — as an import or as a dependency. DireWolf is a runtime you run
  agents on, not a consumer of someone else's loop. Interoperating with one at
  the edges is a different question and is not what this forbids.
- `dwkd-authority` and `dwkd-broker` do not depend on each other, and the CLI
  depends on neither.
- Everything in `dwkd-authority`'s **transitive** dependency closure is
  allowlisted, because everything reachable from it is inside the TCB. That
  includes `dwk-proto`'s closure, checked now although the edge arrives at M3.
- `dwk-proto` is the only in-tree crate both daemons may link, and it links no
  in-tree crate itself. Its source names no `std::fs`, `std::net`,
  `std::process`, `std::env`, `std::os` or `unsafe`.
- No product module imports `direwolf_evals`. The eval harness may import the
  runtime; never the reverse. It holds a test-only execution-environment double
  and a process-control harness, and either one inside the runtime would be a
  second path to effect wearing test-infrastructure clothes.

> ### These checks are not a security boundary
>
> Every one of them is static analysis over source text. A prompt-injected
> `exec()` inside the runtime can call `__import__("socket")` and no rule here
> will ever run.
>
> The actual controls are the OS process and privilege boundary between the
> runtime and `dwkd-authority`, the absence of a network route on the runtime
> identity, and the absence of any credential in the runtime's address space.
>
> These rules stop the architecture eroding through ordinary development. Do
> not describe a passing `make arch` as containment, in a commit message, a
> README, or anywhere else.

## Adding a dependency

State the purpose in the pull request. Then, by destination:

**`dwkd-authority`** — this is the trusted computing base, and its small
dependency set is a load-bearing claim of
[ADR-0019](docs/adr/0019-language-rationale-v2.md), not an aspiration. You need
a **new ADR amending** it (never an edit to ADR-0019, which is accepted and
therefore immutable), a reviewer other than yourself, and an entry in
`[authority].allowed_third_party` in `architecture.toml` — or, for a crate that
only *executes while the authority is built* and is never linked (a C compiler
driver, a build script's helper), in `[authority].allowed_build_third_party`.
The two lists are reviewed separately and must not be mixed to silence the
gate. The check covers the whole transitive closure: a harmless-looking crate that pulls in an HTTP stack
breaks the claim exactly as thoroughly as adding the HTTP stack.

[ADR-0035](docs/adr/0035-m3-authority-dependency-set.md) reviews the four the
authority takes at M3 — `rusqlite` with bundled SQLite, `toml`, `rustix` and
`sha2` — with their measured transitive closure, their licences, and which of
them parse untrusted input. Each is added in the milestone that first links it,
not in advance. That ADR is also the model for the next one: measure the
closure, name what parses untrusted input, and do not describe a large C
dependency as small.

[ADR-0038](docs/adr/0038-policy-evaluation-phases-and-composition.md) is the
first to do that for real, and it is worth reading for one detail: the closure
it records is **one crate smaller** than ADR-0035 predicted, because the policy
loader walks `toml::de::DeTable` (behind the `parse` feature alone) rather than
`toml::Value` (which needs `serde` and carries no source spans). Re-measure;
do not copy the previous ADR's table.

[ADR-0039](docs/adr/0039-durable-authority-state.md) is the second, and the
reason re-measuring matters: measuring SQLite's closure found that the
exact-closure checker had been judging optionality **by crate name**, so a
crate declared once as optional and once as required (`rusqlite` declares
`libsqlite3-sys` that way) silently dropped out of the linked set — with all of
SQLite's C. It found that ADR-0035's amalgamation figures were the SQLCipher
copy's, and that five crates execute during the build without being linked.
`python -m dwcheck closure --report` prints the linked set, the build-only set,
the crates with build scripts and the crates that link native code; read it
before and after any dependency change.

**`dwk-proto`** — treat exactly as `dwkd-authority`: it is linked into it from
M3, and `dwcheck` already checks it as TCB. Dev-dependencies are not linked and
not counted, but they are still audited by `cargo deny`.

*The dependency inventory.* **TCB (`dwkd-authority` and `dwk-proto`): twenty-five
crates in the exact gate's union**, twenty-two linked on Linux x86_64. Since M3e
([ADR-0041](docs/adr/0041-m3e-authenticated-dwkp-transport.md)), `rustix` and `linux-raw-sys` for peer
credentials, declared for Linux only and usable in `server/peer.rs` alone
(TX008); `errno`, which rustix's libc backend links on Linux targets without a
raw-syscall backend; and `windows-sys` and `windows-link`, which the union
must name although no supported build links them. The policy loader's TOML chain — `toml`, `toml_parser`,
`toml_datetime`, `serde_spanned` and `winnow`, pinned exactly, added at M3c
([ADR-0038](docs/adr/0038-policy-evaluation-phases-and-composition.md)); three
of them parse the policy text, which is why the loader has fuzz targets in
`fuzz/` and a stable mutation harness in
`crates/dwkd-authority/tests/fuzz_smoke.rs`. And, since M3d
([ADR-0039](docs/adr/0039-durable-authority-state.md)), `kernel.db` and the
audit hash: `rusqlite` and `libsqlite3-sys` (the bundled **SQLite 3.53.2 C
amalgamation**, compiled into the authority) with `bitflags`,
`fallible-iterator`, `fallible-streaming-iterator` and `smallvec`; `sha2` with
`digest`, `block-buffer`, `crypto-common`, `hybrid-array`, `typenum`,
`cpufeatures` and `cfg-if`; and `libc`, which `cpufeatures` links on aarch64
and loongarch64 only. No derive macro and no proc-macro. **Build-only, never
linked, reviewed in their own list:** `cc`, `find-msvc-tools` and `shlex`
(which compile the amalgamation), and `pkg-config` and `vcpkg` (a default
feature of `libsqlite3-sys` that `rusqlite` does not let a dependent disable;
the bundled build consults neither). M2 briefly added
`unicode-normalization` and its two dependencies for NFC key comparison;
[ADR-0034](docs/adr/0034-protocol-depends-on-no-unicode-database.md) removed
the need and the crates, and `dwk-proto`'s own closure is still empty.
**Dev-only:** `proptest` (property tests) and `serde_json` (differential oracle
for the strict lexer), with their transitive dependencies; audited by the root
`deny.toml`, never linked. **Fuzz-only, outside the workspace:**
`libfuzzer-sys` and its build dependencies in `fuzz/`, audited by
`fuzz/deny.toml` — a separate policy so a fuzzing crate can never be mistaken
for a product one. **Python:** none; the protocol layer is standard library
only. Keep the TCB list short: it is a claim, and dependency count is not the
goal — a small trusted surface is.

**`dwkd-broker`** — this crate is *expected* to carry the large dependencies
authority must not: a container client, an HTTP/TLS stack, content parsers.
That is the point of the split. Normal review applies.

**Rust, anywhere** — declare it once in `[workspace.dependencies]` and inherit
it with `{ workspace = true }`. One table lists everything in the tree; a
per-crate version means a reviewer has to read every manifest, and two crates
can silently disagree.

**Python** — add it to the right `pyproject.toml`, run `uv sync`, and commit
`uv.lock`. The runtime has no transport dependency and will not get one.

`cargo deny check` enforces licences, advisories, banned crates, duplicate
versions and source registries. `pip-audit` covers the Python side.

## Security-sensitive changes

These rules come from the Phase 0 decisions, and they are the reason the
architecture is worth anything.

1. **A change to `crates/dwkd-authority/`, `crates/dwkd-broker/` or
   `crates/dwk-proto/` requires a reviewer other than the author.** No
   exceptions for small changes; the dangerous ones are always small. The same
   applies to the generators and to `runtime/src/direwolf/wire/`, which decide
   what the runtime accepts.
2. **Every new DWKP operation requires a written argument for why it is not a
   second path from cognition to effect**, reviewed by someone other than its
   author, plus a statement of whether it is an authority primitive or a
   runtime-shaped convenience ([ADR-0029](docs/adr/0029-packaging-runtime-first-decoupled-authority.md)).
   This rule exists because that failure has already happened once, during
   Phase 0, in a change whose stated purpose was closing a second path. The
   argument takes the form of the eight questions in *Changing the protocol*.
3. **An interface change between the planes requires an ADR.**
4. **Adding a dependency to authority code requires explicit review** — see
   above.
5. **No feature bypasses the authority plane "temporarily".** There is no
   temporary second path; there is a second path, and then there is a release
   with a second path in it.

Do not open a public issue for a vulnerability. See [SECURITY.md](SECURITY.md).

## Unsafe Rust

The workspace sets `unsafe_code = "forbid"` and **no workspace crate contains
`unsafe`** — `dwk-proto` included, whose own dependency closure is still empty
([ADR-0034](docs/adr/0034-protocol-depends-on-no-unicode-database.md)).

That no longer describes the whole of what the authority plane links, and
since M3d the gap is not theoretical. The lint governs this workspace's code,
not its dependencies': the authority links twenty crates this workspace does
not lint, and one of them, `libsqlite3-sys`, compiles **SQLite's C
amalgamation — 269,376 lines — into the authority process**
([ADR-0039](docs/adr/0039-durable-authority-state.md) §15). "DireWolf's Rust
contains no `unsafe`" is true. "The authority contains no unsafe or native
code" is false, and nothing in this repository may say it.

That is not a promise it never will. `dwkd-broker` will eventually need
`openat2` with `RESOLVE_*` flags, `fexecve` and rlimits, and some of that is
unreachable from safe Rust. When it happens:

- The exception is **crate-level and recorded in an ADR**, never a file-level
  `#[allow]` someone adds in passing.
- It is confined to the smallest module that needs it, with a name that says so.
- **Every `unsafe` block carries a comment stating the invariant that makes it
  sound** — not what it does, why it is correct.
- The change needs a reviewer other than the author, and that reviewer is
  reviewing the invariant, not the diff.
- `dwkd-authority` is expected to stay at `forbid` permanently. If it ever
  needs `unsafe`, something has been put in it that belongs in the broker.

A test asserts the workspace-level `forbid` and that no `unsafe` has appeared;
when the first legitimate exception lands, that test is updated in the same
commit as the ADR.

## Adding an eval

`evals/` measures DireWolf's claims and implements none of them.
[evals/README.md](evals/README.md) is the working guide; the short version:

```bash
make eval                                    # every suite
make eval-check                              # the gate: subset vs baseline
make eval-one ID=protocol-security/framing   # reproduce one
```

- A suite is a TOML file in `evals/suites/`, and it must say what its **score
  means**. There is no single DireWolf score, and unlike properties are never
  averaged: a security regression must not be payable by an unrelated
  improvement.
- A suite may only name a runner **registered in Python**
  (`evals/src/direwolf_evals/runners/__init__.py`). Suite files and fixtures
  are data; a fixture that could choose code would be a second execution path.
- An eval whose subject does not exist yet declares `pending_reason` and the
  milestone it `requires`. **Pending is not a pass**, and neither is skipped;
  the gate counts them separately, and
  `python -m direwolf_evals inventory` lists which security properties are
  measurable today and which are waiting for M3 and later.
- Changing what is expected means editing `evals/baselines/main.json`
  deliberately (`python -m direwolf_evals baseline`) and putting the diff in
  the pull request. Nothing rewrites it automatically, least of all CI.

## Changing the protocol

The wire is defined in one place and generated everywhere else
([ADR-0033](docs/adr/0033-protocol-source-of-truth-and-tcb-dependencies.md)):

```
crates/dwk-proto  ──tools/protogen──▶  schemas/ + docs/DWKP_OPERATIONS.md
                                          │
                        scripts/gen_proto_python.py (reads schemas/ only)
                                          ▼
                              runtime/src/direwolf/proto/
```

- Change the Rust type (or the operation inventory in
  `crates/dwk-proto/src/dwkp/registry.rs`), then run `make schema` and commit
  the regenerated files with the change. **Never edit a generated file by
  hand**: `make schema-check` compares byte for byte and CI fails on any
  difference, including a stray file in a generated directory.
- The Python generator understands a closed set of JSON Schema keywords and
  stops on anything else. If you need a new one, extend the generator on
  purpose, with a test that the Python side enforces it.
- Parser rules — UTF-8, grammar, depth 32, lexical duplicate keys, number
  domains, framing — live in the lexers, not in JSON Schema.
  A change to one lexer needs the same change in the other and a vector in
  `tests/protocol/vectors/` that both test suites run.
- Canonical bytes in the vectors come from V8
  (`tests/protocol/oracle/`), not from either implementation. Regenerating them
  needs Node; nothing in CI does.
- Fuzz with `make fuzz-smoke` (stable, any platform) or `make fuzz`
  (libFuzzer: Linux or WSL2, a nightly toolchain, cargo-fuzz and a C++
  compiler). CI runs both weekly and on pull requests that touch the protocol.
  Report what actually ran — targets, duration, executions, crashes — never
  "fuzzed" on its own.

**The protocol change review rule.** Any change that adds, defines, reshapes or
removes an authority-facing DWKP operation — including giving a reserved
operation its first wire form — answers these eight questions in the pull
request, and the operation's entry in `registry.rs` records the durable parts
(what it carries, who consumes it, whether it can cause an effect, the
second-path argument, the owning milestone):

1. **Why is this operation necessary?** Which milestone needs it now, and why an
   existing operation cannot do the job.
2. **Who is allowed to initiate it?** Runtime, CLI, broker — and who receives it.
3. **Which authority primitive does it map to?** Name the canonical action the
   kernel performs. If you cannot state it in one sentence, the operation is a
   relay ([PROTOCOL.md](docs/PROTOCOL.md) §2, "The second-path rule").
4. **Can it become a generic second path?** Could a payload make it do something
   that should have been a different, policed operation? Generic verbs —
   `Invoke`, `Execute`, `RawRequest`, `CallPlugin` — are rejected on sight.
5. **Does it introduce an opaque payload?** No uninterpreted bytes, no
   caller-chosen URL, HTTP header, credential header, raw body or upstream
   endpoint ([ADR-0020](docs/adr/0020-provider-request-path-v2.md)).
6. **Does it change policy-visible data ownership?** No field may let the runtime
   assert taint, privacy class, origin, skill trust, workspace sensitivity or
   provenance ([ADR-0028](docs/adr/0028-policy-input-ownership.md)).
7. **Does it require an ADR?** Yes if it creates a new effect path, changes the
   kernel/broker interface or the answer to 4–6 is anything but "no".
8. **Which negative tests prove malformed and extended forms fail safely?**
   At minimum: an unknown field, a missing field, a wrong type, an out-of-range
   value, and the operation's name under the wrong message type — each rejected
   with the expected code and path, in both languages.

A reviewer other than the author checks the answers, not just the diff. A DWKP
change is a coordinated release of runtime and kernel, never a rolling one.

## Architecture decision records

**Accepted ADRs are immutable.** A changed decision produces a *new* ADR that
supersedes or amends the old one; the old one stays, banner-marked, as a
historical record. Do not rewrite history — a superseded ADR is how a reader
finds out that a plausible-looking idea was already tried.

A superseding ADR must say what *survived* from the old one, not only what
changed.

An ADR is required for:

- authority-boundary changes;
- kernel/broker interface changes;
- new privileged execution paths;
- major storage or concurrency model changes;
- adding a core tool (plus an update to the canonical inventory in
  [TOOL_SYSTEM.md](docs/TOOL_SYSTEM.md) §3);
- new authority-bearing external integrations;
- anything that could create a second path from cognition to effect, which must
  explicitly address [ADR-0000](docs/adr/0000-authority-plane-separation.md).

An ADR is **not** required for implementation details, refactors that change no
interface, documentation, or tests.

The template and the full rules are in [docs/adr/README.md](docs/adr/README.md).
Number the new record after the highest existing one and add it to the index
and the dependency graph in the same commit.

Accepted records are immutable, and `dwcheck adr` enforces that in two layers
that are not equally strong:

- **The trust anchor is Git history.** Each ADR is compared against the content
  it had in the revision where it became Accepted. That revision is not part of
  your change, so nothing you edit can move it. Locally the anchor is `HEAD`,
  which catches the edit before you commit; in CI it is the merge base with the
  target branch.
- **`docs/adr/accepted.sha256` is a tripwire, not a control.** It catches
  accidental drift and it works with no history at all, but it sits in the same
  working tree as the ADRs: a change that edits an accepted ADR can re-record
  the digest in the same commit, and the pair is self-consistent. Do not read a
  passing digest check as proof that a record is unchanged.

When you add an ADR, run

```bash
uv run --frozen python -m dwcheck adr --record
```

in the same commit. When you are tempted to append a note to an accepted ADR
instead, write the new ADR — that temptation is exactly what broke the rule in
M2.

Supersede through a **new superseding ADR** plus the index in
[docs/adr/README.md](docs/adr/README.md). The one part of an accepted record
that stays writable is its `**Status:**` line, so the superseding ADR can
banner-mark it; the decision, context and consequences below it are anchored.
Correcting an accepted record anyway needs an `[[adr.history_exceptions]]` entry
in `architecture.toml` naming the file, the exact content it authorises and the
reason — a line in the diff that says in words that immutability is being
overridden, which is the point of it.

## Proposing an architecture change

Open an issue describing the problem before writing the ADR. An ADR is the
record of a decision, not the argument that produces it; writing one first
tends to produce a document defending a conclusion rather than reaching it.

If the change contradicts an accepted ADR, say which one and why the original
reasoning no longer holds. "Circumstances changed" is a real answer. "I would
have done it differently" is not.

## Tests

See [tests/README.md](tests/README.md) for the layout.

Expectations:

- New behaviour has a test that fails without the change.
- Name the test after what breaks, not after the function.
- **Do not write tests for unimplemented features.** A test asserting that a
  subsystem that does not exist behaves correctly will be rewritten when the
  real one arrives, and until then it makes the suite look larger than it is.
- There is no coverage-percentage target. The gate is behavioural.

## Formatting and lint

`make fmt` before you push. Rust is `rustfmt` with `rustfmt.toml`; Python is
`ruff format` and `ruff check`, one tool where three (black, isort, flake8)
would give the same signal.

The workspace denies `unwrap`, `expect` and `panic` in production Rust. Test
crates opt out at the crate root, which is why the opt-out is visible and why
it is absent everywhere else.

Optionally: `make hooks` installs a pre-commit hook that runs `fmt-check` and
`arch` only. It is opt-in and fast on purpose — a hook that takes thirty
seconds is a hook people bypass with `--no-verify`, and a bypassed hook
protects nothing. Types, tests and audits belong to `make check` and CI.

## Line endings

The repository is LF everywhere, enforced by `.gitattributes`. On Windows, do
not set `core.autocrlf true` for this repository; the shell scripts and git
hooks must not acquire CRLF.

## Platforms

| | Status |
|---|---|
| **Linux** | Primary. Everything works. |
| **macOS** | Supported. The container sandbox will run in a Linux VM. |
| **Windows + WSL2** | Supported, and the recommended Windows path. |
| **Native Windows** | Development only, reduced assurance, loudly stated. |

Native Windows builds and tests — CI covers it — but it lacks the uid model the
two-identity install assumes, and path resolution differs from `openat2`. It is
a real target and it is labelled rather than quietly downgraded;
`direwolf doctor` says so on every run.

We do not add platform-specific workarounds to claim parity that does not
exist.

## Secrets

Never commit one. `.gitignore` covers the usual accidents (`.env`, `*.pem`,
`*.key`, local databases, `audit.log`).

There is no secret-scanning tool in CI. GitHub push protection is the intended
mechanism, and it is better than a CI scan because it blocks the push rather
than failing a build after the secret is already in the history. It is a
repository setting: nothing in this repository enables it or can show that it
is enabled, and nobody should claim it ran on a local commit — it runs only on
push to GitHub. The repository is public; whether push protection is enabled is
visible only in the repository's GitHub settings, and this document does not
assert either way.

**M2 evaluated a maintained scanner (as M1 deferred) and did not add one.** The
reasons, so the decision can be checked rather than trusted:

- M2 adds no credential, configuration or code path that handles one. Its only
  high-entropy content is test data — UUIDv7 identifiers, hex frames, IEEE-754
  bit patterns — which a scanner would flag and a baseline would have to
  suppress, training reviewers to ignore it.
- A CI scan detects a secret after it has been pushed, when it must already be
  rotated; push protection is the control that prevents the push.
- Adding one means a pinned third-party binary or action in CI, which this
  repository admits only with a concrete benefit.

**Revisited at M4**, when the secret broker brings secret-shaped fixtures,
redaction tests and DireWolf-specific key formats that push protection's
provider patterns cannot know about. That is when a scanner with custom rules,
a reviewed baseline and a planted-fake-secret fixture earns its place.

If you do commit a secret by accident: rotate it first, then rewrite history —
in that order, because the secret is compromised the moment it is pushed.

## CI security

CI has a read-only token, no secrets, uses `pull_request` rather than
`pull_request_target`, and pins its two third-party-hosted actions — both
GitHub's own — by commit SHA. Nothing is installed by piping a URL into a
shell. The scheduled fuzz workflow follows the same rules and needs no secret,
so it cannot fail for want of one; its tools (a date-pinned nightly, cargo-fuzz)
are installed pinned and `--locked`.

Keeping it that way is a review matter: the first `permissions: write` is the
one nobody notices. A change under `.github/` is a security-sensitive change.

**Evidence CI alone can produce.** The cross-uid property of M3e (ADR-0041) —
a real second operating-system user is refused on the uid the kernel reports —
needs two identities, which a one-user workstation does not have; locally it is
NOT EXERCISED, and M3 is complete only when CI has run it. So CI's wiring is
part of the claim, and `tests/architecture/test_ci_authority_gate.py` holds it:
the `authority-transport` job runs on Linux, unconditionally, with
`DW_PEER_AS=nobody` (proven a second, non-root uid by number before anything
runs); it selects the `#[ignore]`d cross-uid tests by name and fails unless
both ran and reported every case; the eval gate there and in `evals` is strict;
nothing around it may `continue-on-error` or `|| true`; and the `CI` aggregate
needs every job and accepts only `success` — a *skipped* job is red.

## Commits and pull requests

Write the commit message for someone reading `git log` in two years and trying
to work out why. What changed is in the diff; why it changed is not.

The pull-request template asks the boundary questions above. Answer the ones
that apply and delete the rest.

## Licence

Apache-2.0 ([ADR-0030](docs/adr/0030-licence-apache-2.0.md)). By contributing
you agree your contribution is licensed under it. There is no CLA.
