# ADR-0031: Repository layout, and how architectural boundaries are enforced in the build

**Status:** Accepted · **Date:** 2026-09-12 · **Refines:** [ADR-0018](0018-authority-broker-split.md), [ADR-0019](0019-language-rationale-v2.md)

> This record covers M1 decisions that later milestones inherit and should not
> have to relitigate: where code lives, which tools gate it, and what those
> gates do and do not prove. It changes no architectural decision.

## Context

[ARCHITECTURE.md](../ARCHITECTURE.md) §6 sketched a module tree during Phase 0,
before [ADR-0018](0018-authority-broker-split.md) split the authority plane.
That sketch put every Rust crate under `kernel/` and labelled the directory
"the TCB". Post-0018 that label is wrong for two of the three crates that
actually exist: `dwkd-broker` is explicitly *not* the TCB — holding no
long-lived key is its defining property — and `direwolf-cli` is presentation
and holds nothing. A directory whose name asserts a trust level its contents do
not share is exactly the kind of quiet inaccuracy that turns into a wrong
assumption two years later.

Phase 0 also named `import-linter` as the mechanism for the Python boundary
contracts. Attempting it at M1 exposed three mismatches: it operates on an
importable package graph, so it cannot run over the deliberately-invalid
fixtures that prove a rule works; it covers Python only, while half the
boundaries here are Cargo manifests; and the contracts we actually need are
"everywhere except this one module", which it expresses awkwardly.

And M1 must decide its tool set. The relevant risk is not picking a bad tool;
it is picking two tools that produce the same signal, because then a finding
has two places to be suppressed and neither reviewer knows about the other.

## Decision

### 1. `crates/`, not `kernel/`

The Rust workspace root is `crates/`, containing exactly three crates:

| Crate | Binary | Plane | Trust |
|---|---|---|---|
| `dwkd-authority` | `dwkd-authority` | Authority — decides | **TCB** |
| `dwkd-broker` | `dwkd-broker` | Authority — executes | Privileged, not TCB; holds no key |
| `direwolf-cli` | `direwolf` | Presentation | No authority |

The name is deliberately neutral. Trust level is stated per crate — in the
crate docs, in `architecture.toml`, and in the dependency allowlist — rather
than implied by a directory. `ARCHITECTURE.md` §6 is updated to match.

**No shared crate exists, and none is created speculatively.** `dwk-proto`,
`dwk-policy`, `dwk-capability` and the rest arrive when there is code to put in
them (M2 onward). A `common` crate created before it has contents becomes a
dumping ground, and a dumping ground shared by `dwkd-authority` and
`dwkd-broker` quietly collapses the boundary ADR-0018 exists to draw.

Python packages stay at `runtime/` (`direwolf`) and `tools/dwcheck/`
(`dwcheck`), in one `uv` workspace with one lockfile.

### 2. Dependency direction is checked, not assumed

`architecture.toml` declares, and `dwcheck deps` enforces:

- `dwkd-authority` may not depend on `dwkd-broker` or on the CLI;
- `dwkd-broker` may not depend on `dwkd-authority` or on the CLI;
- `direwolf-cli` may depend on neither daemon;
- every third-party crate is declared once in `[workspace.dependencies]` and
  inherited;
- **every crate in `dwkd-authority`'s transitive dependency closure**, read
  from `Cargo.lock`, is on an explicit allowlist;
- **no workspace crate may depend on either daemon at all.** The three named
  direction rules cover the crates that exist; this one covers the crate
  somebody adds at M3 "to share a little code between authority and broker",
  which breaks no named rule because no named rule is about it. That is how the
  boundary would actually be lost.

The closure rule is the one that matters. ADR-0019's claim is about everything
linked into the authority process, and nobody adds an HTTP stack to a TCB on
purpose — it arrives through something that looked harmless. Reading
`Cargo.lock` rather than `cargo metadata` means the check needs no toolchain,
no network and no registry index, so it runs everywhere rather than only where
a supply-chain tool happens to be installed.

The allowlist is currently **empty**, and the workspace has zero third-party
Rust dependencies.

### 3. `dwcheck`, not `import-linter`

One dependency-free, stdlib-only checker reading one declarative rules
file (`architecture.toml`), covering Python imports, provider-name confinement,
Python manifests, the Cargo graph, the lockfile closure, documentation links
and version synchronisation.

Chosen over `import-linter` because it works on files rather than on an
importable graph — which is what makes the fixture-based negative tests
possible — spans both languages, and expresses per-directory exemptions
directly. Rules live in data so a reviewer can read the boundaries without
reading the checker.

`ARCHITECTURE.md` §6's "Check" column is updated accordingly.

### 4. One tool per signal

| Signal | Tool | Not also |
|---|---|---|
| Rust format | `rustfmt` | |
| Rust lint | `clippy -D warnings`; `pedantic` on the two daemon crates | |
| Rust advisories, licences, bans, duplicates, sources | `cargo-deny` | **`cargo-audit`** — same RustSec database, so two places to suppress a finding |
| Python format **and** lint | `ruff` | **black, isort, flake8** — three tools, one signal |
| Python types | `mypy --strict` | |
| Python advisories | `pip-audit` | |
| Architecture boundaries, doc links, version sync | `dwcheck` | |

Developers and CI invoke these through the same `make` targets, which delegate
to `scripts/dw.py`, which prints every command it runs. CI runs the same
commands a contributor runs; there is no CI-only script that can diverge.

### 5. What the gates prove, and what they do not

Stated here because it is the easiest claim in the repository to overstate:

> **These checks are development hygiene, not containment.** Every one is
> static analysis over source text. A prompt-injected `exec()` inside the
> runtime can call `__import__("socket")` and no rule will run. The actual
> controls are the OS process and privilege boundary, the absence of a network
> route on the runtime identity, and the absence of any credential in the
> runtime's address space.

The same sentence appears in `architecture.toml`, in `dwcheck --help`, in
`CONTRIBUTING.md` and in the checker's module docstring, on the principle that
a caveat stated once is a caveat nobody reads.

Correspondingly, the acceptance criterion for a boundary rule is not that it is
configured but that it **rejects a known violation**:
`tests/architecture/fixtures/violations/` is a miniature repository that breaks
every rule at once, and a test asserts that each declared rule fires against
it. A rule that never rejects anything fails its own test.

### 6. Version: one source of truth

The root `VERSION` file is authoritative. Five manifests mirror it and are
written by `dwcheck version --write`, never edited by hand; `dwcheck version`
fails on drift.

The string stays plain semver with no pre-release suffix, because Cargo spells
a pre-release `0.1.0-alpha.1` and PEP 440 spells the same thing `0.1.0a1`, and
a byte-equality check across ecosystems is only possible while the two
spellings coincide. `0.0.0` until there is a wire format to be compatible with.

## Consequences

**Positive.** Trust level is stated rather than implied by a path. The
authority/broker boundary is a package boundary from the first commit rather
than an extraction someone attempts later — and retrofitting a privilege
boundary is the mistake this whole architecture exists to avoid. The tool set
has no redundant pair. Every gate has a test proving it can fail.

**Negative.** `dwcheck` is code we maintain, and a bespoke checker is a thing
new contributors have to learn instead of a tool they already know. It is the
largest single piece of code in M1: about 1 300 lines, of which ~970 are code
and the rest documentation, plus ~120 lines of its own unit tests. That is more
than a "small script", and it is tooling rather than product. We still think it
is the cheaper side of the trade -- the rules are data, the checker is tested,
and the alternative was three mechanisms with no coverage of the rule that
matters most -- but the cost is real and it will grow.
`architecture.toml` is a second place to look for rules alongside
`pyproject.toml` and `deny.toml` — mitigated by each rule carrying its reason
inline, but three files is three files.

**Also negative:** the fixture tree under `tests/architecture/fixtures/` has to
be excluded from ruff, mypy and pytest, and each exclusion is a small hole in a
gate. They are listed with reasons in `pyproject.toml` and `architecture.toml`,
and the exclusions are narrow, but somebody will eventually hide a real file in
there.

## Alternatives considered

**Keep `kernel/` as the directory name.** Zero doc churn, matches the Phase 0
sketch and the existing "kernel crates" phrasing throughout the corpus.
Rejected because the label is now false for two of three crates, and a false
trust label in a security architecture is worse than a rename.

**`import-linter` plus a grep gate plus a Cargo script.** Three mechanisms,
three output formats, and the negative tests would have to be written three
ways — and the one that matters most, the lockfile closure, has no tool at all.
Rejected on coherence, not on tool quality.

**Create `dwk-proto` now so M2 has somewhere to go.** Rejected under the M1
rule that a package needs a concrete reason to exist today. An empty crate
invites speculative types, and speculative wire types written before the kernel
exists are the worst kind to be stuck with.

**Add `cargo-audit` alongside `cargo-deny` "for defence in depth".** Rejected:
identical advisory source, so it is duplication rather than depth, and two
suppression files is how a known advisory ends up silenced in the one nobody
checks.

## Revisit if

A shared crate becomes genuinely necessary — most likely `dwk-proto` at M2 —
in which case its contents are constrained to wire types and value objects, and
it is reviewed specifically for whether it has started carrying behaviour that
belongs on one side of the authority/broker line.

Or: if a rule needs logic that cannot be expressed in `architecture.toml` —
the signal that the checker has become a program rather than an interpreter. At
that point buying a maintained tool for the Python half becomes the better
trade and this decision should be re-argued. A ceiling of ~1 500 code lines
applies as a backstop.
