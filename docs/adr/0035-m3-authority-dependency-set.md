# ADR-0035: The M3 authority dependency set — SQLite, TOML, peer credentials and SHA-256 enter the TCB

**Status:** Accepted · **Date:** 2026-09-17 · **Amends:** [ADR-0019](0019-language-rationale-v2.md) (the authority dependency set is no longer empty), [ADR-0033](0033-protocol-source-of-truth-and-tcb-dependencies.md) and [ADR-0034](0034-protocol-depends-on-no-unicode-database.md) (the TCB-destined closure they emptied is deliberately refilled, by different crates, for different reasons)

> M3 gives DireWolf an authority daemon that persists state, reads policy,
> authenticates a peer and hash-chains an audit log. None of those four can be
> done honestly with the standard library alone, and three of the four
> alternatives are worse than the dependency. This records what enters the
> trusted computing base, measured rather than estimated, and does not pretend
> the largest of them is small.

## Context

[ADR-0019](0019-language-rationale-v2.md) made "a genuinely small, enforceable
dependency set" a load-bearing claim of the authority plane.
[ADR-0033](0033-protocol-source-of-truth-and-tcb-dependencies.md) reviewed the
first three crates that would have entered it, and
[ADR-0034](0034-protocol-depends-on-no-unicode-database.md) removed all three by
removing the protocol's dependence on a Unicode database. Since M2's closeout
the TCB-destined closure has been **empty**, and `architecture.toml`'s
`[authority].allowed_third_party` has been `[]`, enforced over the transitive
closure by `dwcheck` RS004/RS006.

M3 changes that. The authority daemon must:

1. **persist authority state** — the kernel epoch, leases, run admissions and
   the policy inputs of [ADR-0028](0028-policy-input-ownership.md) — in
   `kernel.db`, which [ADR-0009](0009-storage-strategy.md) specifies as SQLite;
2. **read policy** — TOML rule files, ordered, first match wins
   ([POLICY.md](../POLICY.md) §3);
3. **authenticate a peer** — the uid behind a Unix-domain socket connection,
   which on Linux means `SO_PEERCRED`, a syscall the standard library does not
   expose;
4. **hash-chain an audit log** — SHA-256 over a canonical encoding
   ([ADR-0010](0010-event-model.md)).

Each of these is a decision the project owner has taken explicitly. This ADR
records them together, because they are one decision — *what the authority
plane is allowed to link* — with one rationale thread, and splitting them into
four would fragment the argument ADR-0019 and ADR-0033 built.

The measurements below were taken on 2026-09-17 with rustc 1.98.1 on
x86_64-unknown-linux-gnu, in a throwaway crate outside this repository, using
`cargo tree --edges normal --target x86_64-unknown-linux-gnu` and
`cargo metadata`. They are what the resolver actually produced, not an estimate.

## Decision

### 1. `rusqlite` with the bundled SQLite amalgamation

```toml
rusqlite = { version = "0.40", default-features = false, features = ["bundled"] }
```

`bundled` compiles SQLite's C amalgamation into the binary. **This is the
largest single addition to the trusted computing base in the project's
history**, and calling it anything else would be dishonest:

| | measured |
|---|---|
| `libsqlite3-sys` 0.38.2 bundles | `sqlite3.c`, **271,671 lines / 9,616,148 bytes of C** |
| SQLite version linked | **3.53.2** (`3053002`) |
| built by | the `cc` crate, at build time, requiring a C compiler |

It runs in the authority address space, which also holds the capability-token
key and (from M4) secret material. A memory-safety defect in it is a defect in
the most privileged process DireWolf has. `#![forbid(unsafe_code)]` does not
reach it: that lint governs Rust, and this is C behind an FFI boundary.

The decision is taken anyway, for one reason that outweighs it: **the
alternative is worse.** Linking the system SQLite makes a security-critical
component's behaviour a function of whichever version the host happens to ship
— SQLite's `PRAGMA` defaults, `WAL` behaviour, `ON CONFLICT` handling and
integrity-check output have all changed between releases. An authority whose
epoch monotonicity or transaction durability depends on an unpinned third-party
version is not an authority we can make claims about. A pinned, identical
implementation on every supported platform is worth a large audited C
dependency; an unpinned one is not.

### 2. `toml` for policy files, with no derive macros

```toml
toml = { version = "1.1", default-features = false, features = ["parse", "serde"] }
```

Policy stays TOML, as [POLICY.md](../POLICY.md) §3 specifies and as every other
configuration file in this repository is written. It is **not** replaced with
JSON to preserve a zero-dependency TCB: consistency for the people who write
policy is worth more than a smaller crate count, and a bespoke parser for a
format this repository already depends on would be a new, unfuzzed parser in
the TCB — strictly worse than a maintained one.

The `serde` feature is required to reach `toml`'s value API. It pulls
`serde_core` only: **no `serde_derive`, no `syn`, no `quote`, no
`proc-macro2`.** The policy loader walks the parsed document with hand-written
typed accessors, exactly as `tools/dwcheck/src/dwcheck/config.py` walks
`architecture.toml`, because a derive macro that silently accepts a field is the
failure mode strict configuration exists to prevent. Confirmed by measurement:
the Linux link closure below contains no proc-macro crate.

### 3. `rustix` for peer credentials

```toml
rustix = { version = "1.1", default-features = false, features = ["std", "net", "time"] }
```

The exact call, confirmed to compile against this version:

```rust
rustix::net::sockopt::socket_peercred(&stream) -> Result<rustix::net::UCred, rustix::io::Errno>
```

On Linux `rustix` uses `linux-raw-sys` — raw syscalls, no `libc`, no C. The
`time` feature is required: `net`'s `sockopt` module does not compile without
it, which is a resolver fact rather than a design choice.

This preserves the workspace-wide `unsafe_code = "forbid"` **unchanged**. The
alternative was a crate-level exception and a hand-written `getsockopt` FFI
block, which would put the unsafe in the crate that does authority decisions
rather than in a widely-audited library whose entire job is that boundary.
[CONTRIBUTING.md](../../CONTRIBUTING.md) "Unsafe Rust" asks for a maintained
safe wrapper first; this is that wrapper.

### 4. `sha2` for the audit hash chain

```toml
sha2 = { version = "0.11", default-features = false }
```

SHA-256 through the RustCrypto implementation. No homemade cryptography: a
hand-written hash would be a correct-looking function nobody has attacked, and
"it matches the NIST vectors" is a much weaker statement than "it is the
implementation everyone else attacks". Pure Rust, no C.

### 5. The allowlist and the gates

Every crate below goes into `architecture.toml` `[authority].allowed_third_party`
in the milestone that first links it, and `dwcheck` RS004/RS006 continue to
enforce the **transitive** closure, not the direct dependencies. `cargo-deny`
runs unchanged: advisories, bans, licences, sources, and `multiple-versions =
"deny"`.

**Dependencies are added in the milestone that first uses them, not here.** M3a
adds none: it defines protocol types, and `dwk-proto`'s closure stays empty.

## Consequences

### TCB consequences

The Linux runtime link closure of all four, measured:

| Crate | Version | Licence | Linked for | Parses untrusted input? |
|---|---|---|---|---|
| `rusqlite` | 0.40.2 | MIT | kernel.db | via SQL it does not accept from clients |
| `libsqlite3-sys` | 0.38.2 | MIT | bundled SQLite 3.53.2 | **yes** — the database file |
| `bitflags` | 2.13.2 | MIT OR Apache-2.0 | rusqlite, rustix | no |
| `fallible-iterator` | 0.3.0 | MIT/Apache-2.0 | rusqlite | no |
| `fallible-streaming-iterator` | 0.1.9 | MIT/Apache-2.0 | rusqlite | no |
| `smallvec` | 1.16.1 | MIT OR Apache-2.0 | rusqlite | no |
| `toml` | 1.1.6 | MIT OR Apache-2.0 | policy files | **yes** — policy text |
| `toml_parser` | 1.1.3 | MIT OR Apache-2.0 | toml | **yes** |
| `toml_datetime` | 1.1.1 | MIT OR Apache-2.0 | toml | **yes** |
| `serde_spanned` | 1.1.1 | MIT OR Apache-2.0 | toml | no |
| `serde_core` | 1.0.229 | MIT OR Apache-2.0 | toml's value API | no |
| `winnow` | 1.0.4 | MIT | toml_parser | **yes** |
| `rustix` | 1.1.5 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | peer credentials | no |
| `linux-raw-sys` | 0.12.1 | Apache-2.0 WITH LLVM-exception OR Apache-2.0 OR MIT | rustix on Linux | no |
| `sha2` | 0.11.0 | MIT OR Apache-2.0 | audit chain | no |
| `digest` | 0.11.3 | MIT OR Apache-2.0 | sha2 | no |
| `block-buffer` | 0.12.1 | MIT OR Apache-2.0 | digest | no |
| `crypto-common` | 0.2.2 | MIT OR Apache-2.0 | digest | no |
| `hybrid-array` | 0.4.15 | MIT OR Apache-2.0 | digest | no |
| `typenum` | 1.20.1 | MIT OR Apache-2.0 | hybrid-array | no |
| `cpufeatures` | 0.3.1 | MIT OR Apache-2.0 | sha2 | no |
| `cfg-if` | 1.0.5 | MIT OR Apache-2.0 | sha2 | no |

**22 crates**, every licence already in `deny.toml`'s allowlist. Build-time
only, not linked: `cc` (compiles the amalgamation) and the build scripts of
`libsqlite3-sys`, `rustix` and `serde_core`.

Three of them parse untrusted or semi-trusted input inside the authority:
the SQLite file format, and the TOML parser chain. That is the concentration of
risk this decision creates, and it is where review effort should go.

### Security consequences

- SQL is **structured by the authority only**. No query text, table name or
  column name comes from a client; every value is a bound parameter. M3d adds
  the rule and the test.
- Policy files are bounded before parsing — file size, profile count, rule
  count, identifier length — because a limit applied after the allocation it is
  meant to bound is not a limit ([`limits.rs`](../../crates/dwk-proto/src/limits.rs)
  states the same principle for frames).
- `kernel.db` is owned by the authority user and not writable by the runtime
  user ([ADR-0000](0000-authority-plane-separation.md)). Mode bits are not the
  claim: M3d verifies it by *attempting the write* as the runtime user, and
  says so explicitly where a hosted CI environment cannot provide two users.
- Peer credentials come from the kernel, never from a JSON field. A client's
  claimed uid is not an input.

### Portability consequences

- **Linux** is where the authority's security assurance is claimed. `rustix`
  with `linux-raw-sys` and `SO_PEERCRED` is a Linux mechanism.
- **macOS** has `LOCAL_PEERCRED`/`getpeereid`, which is a different mechanism
  with different guarantees; M3e implements or documents it, and does not claim
  equivalence it has not shown.
- **Windows** has no `SO_PEERCRED` and no Unix-domain-socket peer credential of
  the same shape. Native Windows remains a documented reduced-assurance target
  ([ADR-0029](0029-packaging-runtime-first-decoupled-authority.md)); the
  authority's peer authentication will not be claimed there, and nothing will
  fake a uid to make a test pass. WSL2 remains the supported path.
- The bundled amalgamation needs a **C compiler on every build host**, which
  the CI matrix (Ubuntu, macOS, Windows) already has, and which lengthens a cold
  build by the time it takes to compile 271,671 lines of C.

### Operational consequences

- A SQLite CVE becomes a DireWolf release. `cargo-deny check advisories` runs
  in CI on every pull request and weekly; `libsqlite3-sys` bumps are ordinary
  dependency maintenance with an unusually high priority.
- `multiple-versions = "deny"` means a second copy of `bitflags` — plausible,
  since `rusqlite` and `rustix` both use it — fails the gate until it is
  resolved deliberately.
- Build times rise for everyone, once per clean checkout.

### Explicit limitations

- **This ADR does not make SQLite safe.** It records that a large C dependency
  was accepted with open eyes because the alternative made security-critical
  behaviour depend on an arbitrary host version. Nothing here should be cited as
  evidence that the authority's memory safety is assured end to end; it is
  assured for the Rust, and the Rust is now not all of it.
- **It does not authorise anything beyond these four.** A fifth crate needs its
  own review, its own allowlist entry and a new ADR amending this one.
- **The measurements are of one resolution on one platform.** A different
  feature set, a different target or a later resolver produces a different
  closure; the numbers are dated and reproducible, not permanent.
- **Nothing here is implemented yet.** M3a records the decision and adds no
  dependency; the closure is still empty in this commit.

## Alternatives considered

**System SQLite (`rusqlite` without `bundled`).** Smaller build, no C in the
repository's build graph, and the host's patched SQLite. Rejected: it makes the
authority's durability and integrity behaviour a function of a version nobody
pinned, and Windows has no system SQLite to link at all. Steelmanned, this is
the distribution-friendly choice and a packager will eventually want it; it can
become a non-default feature later without changing this decision's default.

**A purpose-built append-only store instead of SQLite.** Zero C, full control,
and the audit log is append-only anyway. Rejected: it contradicts
[ADR-0009](0009-storage-strategy.md), and it means writing a database — crash
consistency, atomic multi-row transactions, recovery — which is a much larger
correctness surface than the one being avoided, in the process that can least
afford a correctness bug.

**Policy as strict JSON through the in-tree `dwk-proto` reader.** Zero new
crates, a parser already fuzzed by `make fuzz-smoke`, already depth-bounded and
already duplicate-key-rejecting. Genuinely attractive, and rejected by the
project owner: policy is written by people, TOML is what this repository uses
for configuration, and POLICY.md specifies it. Recorded here because it was the
closest call of the four, and because if the TOML chain ever produces a
vulnerability this is the fallback that already exists.

**A bespoke TOML subset parser.** Rejected outright: a new parser in the TCB,
unfuzzed and unattacked, to avoid four maintained crates. The repository hand-
wrote a JSON lexer for `dwk-proto` because the protocol's parser *is* the
product; policy configuration is not, and the same reasoning does not transfer.

**`nix` instead of `rustix` for peer credentials.** Equivalent safety, larger
surface, and it pulls `libc`. Rejected on size.

**Hand-written `getsockopt` FFI.** One `unsafe` block, no dependency.
Rejected: it would be the only `unsafe` in the workspace, and it would live in
the crate that makes authority decisions rather than in a library whose whole
purpose is that syscall boundary.

**A hand-written SHA-256.** Rejected by the project's own rule: no homemade
cryptography.

## Revisit if

- A memory-safety advisory lands in the bundled SQLite that cannot be closed by
  a version bump, or SQLite's release cadence stops matching our patch cadence.
- The authority's policy path is shown to be reachable by attacker-chosen TOML
  from outside the operator's control, which would change the TOML parser's
  threat model from "operator input" to "untrusted input".
- A packager needs system SQLite badly enough to make it a supported
  configuration, in which case the pinning argument above has to be answered.
- `rustix` stops supporting the `linux-raw-sys` backend, which would reintroduce
  `libc` into the closure.
