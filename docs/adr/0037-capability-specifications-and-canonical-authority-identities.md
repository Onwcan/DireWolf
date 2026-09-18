# ADR-0037: A declared capability and an authority-comparable capability are different types

**Status:** Accepted · **Date:** 2026-09-18 · **Refines:** [ADR-0006](0006-policy-and-capability-boundary.md) (how the capability gate's vocabulary is represented), [ADR-0036](0036-m3-authority-operations-and-the-capability-wire-form.md) (what the authority does with the text that crosses the wire)

> `fs.read:/workspace` is a sentence about a path. Which bytes it names depends
> on symlinks, mounts, a rename that happened between two syscalls, and a
> Unicode spelling nobody normalised. M3b can compare authority; it cannot
> derive the identity that two `fs` capabilities would be compared *by*. So the
> declaration and the authority are two types, only one of them has a
> containment relation, and **only the module that will hold M4's resolver may
> create one**.

## Context

[ADR-0036](0036-m3-authority-operations-and-the-capability-wire-form.md) §3 put
a capability on the wire as **validated text**: `dwk-proto` checks the lexical
form and the bounds, and the authority interprets it. M3b is that interpreter.

[CAPABILITIES.md](../CAPABILITIES.md) §2 is specific about what interpretation
means for two of the twelve scope families:

| Scope type | Containment test |
|---|---|
| Canonical path | `b` is a path-prefix of `a` **after** canonicalisation to inode identity + NFC normalisation. **Never a string prefix on raw input.** |
| Executable identity | `(resolved path, sha256)` |

Both identities require reading the filesystem. Deriving them safely is the
first half of M4: `openat2` with `RESOLVE_NO_SYMLINKS`, a fallback walker where
that syscall is unavailable, inode pinning so the path checked is the path used,
and hashing the file that was actually opened. M3b has none of it and must not
appear to.

The other ten families have no such gap. A host pattern, a provider/model
pattern, a credential handle — each *is* its own identity, and comparing two of
them needs nothing but the two of them.

The failure this ADR exists to prevent is not exotic. It is one line:

```rust
parent_path.starts_with(&child_path)     // wrong twice over
```

wrong once because `/workspace` is not a prefix of `/workspaceX` in any sense
that matters, and wrong again because neither string was ever a resource.

## Decision

**A capability has two types, and containment is defined on only one.**

```text
          parse                      resolve (M4)
  text  ────────►  CapabilitySpec  ──────────────►  Capability
                   declared scope                   authority scope
                   no containment                   ⊑ is defined here
```

### 1. `CapabilitySpec` — what a declaration says

Produced by the parser. Holds a `ScopeSpec`, whose `fs` and `process` variants
carry a `DeclaredPath`: the text, verbatim.

It has **no containment method**. Not a private one, not a `PartialOrd`
shortcut standing in for one. A declaration cannot be compared with anything,
so a code path holding one cannot accidentally decide authority with it.

`DeclaredPath` deliberately does **not** reject `..`, and that is not an
oversight. Rejecting it would imply the survivors are safe, and they are not: a
path with no `..` still traverses a symlink. Sanitising a value that is about to
be quarantined only makes the quarantine look optional.

### 2. `Capability` — what authority is compared with

Holds a `Scope`, whose `fs` variant carries a `CanonicalPath` and whose
`process` variant carries an `ExecutableIdentity`.

**No production code outside `crate::resource` can construct one.** The types
live in their own module and *every* constructor is `pub(in crate::resource)`:

| caller | can construct a `CanonicalPath` or an `ExecutableIdentity`? |
|---|---|
| `crate::capability` — the lattice, the parser, `CapabilitySpec` | no |
| M3c's policy engine | no |
| M3d's admission, leases and audit | no |
| another crate, including the `dwkd-authority` binary | no |
| a `crate::resource::…` submodule — **M4's canonicaliser** | yes |

An earlier draft of this ADR stopped at "there is no constructor taking a path
string", and that was not enough. It stopped an accident. It did not stop
ordinary authority code assembling the components by hand and presenting the
result as though a resolver had produced it, and a security boundary that holds
only against carelessness is not a boundary. **`pub(crate)` would have been just
as weak**: it is exactly the visibility that lets M3c mint a path because it
happens to live in the same crate.

There is also no `Default` on `CanonicalPath` — deriving it would have been a
public constructor for the root, which covers every path there is.

Containment is component-wise, so the string-prefix bug is not merely untested:
it is unrepresentable.

`ExecutableIdentity` pairs a `CanonicalPath` with a `Sha256Digest` and covers
only itself. `/usr/bin/git` before and after a package update are two
authorities, which is the property the hash is there to give. Its constructor is
restricted for the same reason as the path's: *pairing two values* is the
forgery, and nothing outside the owning module may do it.

### 3. `resolve` is the only bridge, and it refuses

`CapabilitySpec::resolve` returns `Result<Capability, UnresolvedScope>`. For the
ten self-identifying families it succeeds. For `fs` and `process` it returns
`UnresolvedScope::CanonicalPath` or `UnresolvedScope::ExecutableIdentity`,
naming the identity M4 owes.

`fs.read:*` resolves, because `*` names no resource. It is also the widest `fs`
authority expressible, which is why it has to be written out and can never be
inferred from a path that failed to resolve.

### 4. Synthetic identities exist, and are test-only by construction

The lattice over canonical paths is testable today with paths the test invented.
That is worth doing — it is how the component-wise rule and the `/workspaceX`
trap are covered — and it proves exactly one thing: **given** an identity, the
comparison is right. It proves nothing about deriving one.

The synthetic constructors live in `crate::resource::synthetic`, behind
`#[cfg(test)]`. Three consequences, and the third is the one that matters:

* they do not exist in a production build;
* they are not a Cargo feature, so no build can switch them on by accident;
* **an integration test cannot reach them either**, because an integration test
  links the library compiled without `cfg(test)`.

So the tests that need a canonical identity are *unit* tests, in
`src/capability/resource_lattice.rs`. That is not a workaround for the
visibility rule — it is the rule working. A type whose construction is private
is tested where its construction is reachable, and the alternative (a public
"test support" constructor) is the escape hatch this ADR exists to refuse.

### 5. The boundary is evidenced at compile time

`compile_fail` doctests, which compile as an external crate and so see exactly
what production code outside `dwkd-authority` sees. They assert that a caller
cannot: build a `CanonicalPath` from components, from a string, from a
`std::path::Path`, by naming its private field, or via `Default`; build an
`ExecutableIdentity` from a path and a digest it already holds, from a raw path,
or by naming its private fields; or call `contains`, `is_contained_by` or
`CapabilitySet::insert` on a `CapabilitySpec`.

Each type also carries a **positive** doctest using its public accessors, so a
`compile_fail` case cannot pass because of a typo in an import path. No new
dependency: `compile_fail` is a rustdoc feature, and `trybuild` was not needed.

## Consequences

### Security consequences

- An unresolved resource cannot reach a containment check, because the function
  that would take it does not exist. The control is the absence of an API, not
  a rule a reviewer enforces.
- A canonical identity cannot be **forged** by ordinary authority code. Module
  visibility, not documentation, is what stops M3c or M3d assembling one from
  components and presenting it as resolved.
- The string-prefix escalation is unrepresentable. `/workspace` vs
  `/workspaceX` is in the property tests' scope ladder as a fixture whose
  expected answer is written out, so an implementation that regressed to
  `starts_with` would disagree with the table on its first generated pair.
- An executable's authority does not survive its contents changing.
- Ten families are fully comparable now, so M3c's policy engine and M3d's
  admission are not blocked waiting for M4.

### TCB consequences

Three different things, and only two of them are zero:

| | delta |
|---|---|
| Production third-party dependency | **zero** — `[authority].allowed_third_party` stays `[]` and the authority's production closure is empty |
| Native or foreign code | **zero** — no C, no build script, no FFI |
| Authority trusted-code surface | **increased** — roughly 3,300 lines of security-critical Rust now live inside `dwkd-authority`, which is itself the TCB |

Saying "no TCB impact" because no dependency was added would be the wrong claim.
`dwkd-authority` *is* the trusted computing base ([ADR-0018](0018-authority-broker-split.md)),
so code added to it is TCB whoever wrote it. What the capability core buys for
that surface is that the code deciding whether one authority contains another is
now written down, closed, exhaustively matched and property-tested, rather than
being implicit in whatever M3c would have inlined. What it costs is that a bug
in it is a bug in the TCB, which is why the lattice is differentially tested
against an independent reference rather than only against itself.

`proptest` is a dev dependency and is never linked into a shipped binary.

### Portability consequences

None here, and that is the point of putting the split at this line: the lattice
is pure Rust with no platform behaviour. M4's resolver is where `openat2`,
`LOCAL_PEERCRED`-era platform differences and case-insensitive filesystems
arrive, and they arrive on the far side of `CanonicalPath`.

### Operational consequences

- A capability naming an `fs` or `process` scope parses and then declines to
  become authority. Until M4, a runtime asking for one gets a well-formed
  request that no component can act on. That is visible and honest; the
  alternative was a comparison that looked authoritative and was not.
- `CanonicalPath::from_components` is the interface M4 must produce values
  through. If M4's resolver finds it needs a different shape — a device and
  inode pair rather than a component list — that is a change to this type and to
  this ADR, not to the lattice.

### Explicit limitations

- **`CanonicalPath` still cannot tell a resolved value from an invented one.**
  It holds components, and whoever may call the constructor is asserting they
  came from a resolver. What changed is *who may call it*: the assertion is now
  available only to `crate::resource`, so the set of code that could make it
  wrongly is the set of code that will contain M4's resolver. A marker proving
  resolution occurred was considered and rejected as type-system theatre for a
  value M4 has not yet defined. The residual risk is a future bug **inside**
  `crate::resource`, which is the module whose whole job is to be right about
  this.
- **M4 must resist the temptation to widen the visibility.** When the
  canonicaliser lands it will be a submodule of `crate::resource` and will
  inherit the right to construct. If it is ever convenient to put it elsewhere
  and relax `pub(in crate::resource)` to `pub(crate)`, that is this decision
  being reversed, and it needs a new ADR rather than a visibility edit.
- **No Unicode normalisation happens anywhere.** [ADR-0034](0034-protocol-depends-on-no-unicode-database.md)
  removed the protocol's dependence on a Unicode database and M3b does not
  reintroduce one. `CanonicalPath` compares components byte-wise. When M4
  produces NFC-normalised components, the comparison becomes NFC-correct
  because the *input* is; the lattice never consults a table.
- **Host labels refuse uppercase rather than folding it.** DNS is
  case-insensitive, so folding would be defensible, but a capability system with
  two spellings of one scope has two canonical forms. `API.example.com` must be
  written `api.example.com`. Fail-closed, and a real usability cost.

## Alternatives considered

**A `pub` constructor with a clearer name — `from_verified_components`.**
Rejected: renaming a reachable constructor changes what a caller reads, not what
a caller can do. The same applies to `new_unchecked`, `assume_canonical` and
every other spelling of the same escape hatch; all of them are the widening API
of `CAPABILITIES.md` §8 wearing a different hat.

**`pub(crate)` constructors.** Rejected, and this is the one that looks
sufficient and is not: every module of `dwkd-authority` is in the crate,
including M3c's policy engine and M3d's admission. The forgery this ADR is about
is a sibling module minting an identity, and `pub(crate)` permits exactly that.

**A Cargo feature that enables synthetic constructors for tests.** Rejected: a
feature is a thing a production build can turn on, by a typo in a dependency
table or by feature unification pulling it in. The security property would then
depend on a build configuration rather than on the language.

**A public "test support" module.** Rejected for the same reason: public is
public, and `#[doc(hidden)]` hides a thing from the documentation, not from a
caller.

**One type, with a `resolved: bool` flag.** Rejected: the flag is checkable and
therefore forgettable, and the forgotten check is a raw path compared as
authority. A type that cannot be passed to the wrong function needs no check.

**Resolve at parse time, with the filesystem.** Rejected twice over: it puts
I/O in the capability core, which [`architecture.toml`](../../architecture.toml)
TX003 now forbids, and it would mean writing M4's canonicaliser inside M3b
without M4's tests, its TOCTOU analysis or its platform work.

**Compare declared paths textually "for now", with a comment.** Rejected. It
would pass every test written against it, look complete in a demo, and be the
exact bug `CAPABILITIES.md` names in the sentence "never a string prefix on raw
input". A comment is not a control.

**Make `fs` and `process` capabilities unparseable until M4.** Rejected: the
wire form already accepts them ([ADR-0036](0036-m3-authority-operations-and-the-capability-wire-form.md)),
the profile fixtures M3c needs are full of them, and refusing to parse would
push the same problem into the policy loader with less type safety.

**A generic `Scope<R>` parameterised by the resource representation.** Rejected
as type-system theatre. Two enums with a shared `SyntacticScope` arm say the
same thing in a form a reviewer can read at a glance, and the duplication is two
variants.

## Revisit if

- M4's resolver produces an identity that is not a component list — a device and
  inode pair, or a handle — in which case `CanonicalPath` changes shape and the
  lattice above it should not have to.
- `compile_fail` doctests stop being enough — if a property needs to assert
  *which* error a program fails with, rather than only that it fails, that is
  what `trybuild` gives and what would justify the dev dependency.
- A scope family outside `fs` and `process` turns out to need resolution — a
  future `network` scope keyed on a resolved IP set would be the obvious
  candidate, and `ScopeFamily::needs_resolution` is where it would say so.
- Case-insensitive host comparison becomes a real operational cost, at which
  point folding is a decision with a written rationale rather than a default.
