//! Bounds on policy source, applied **before** the work they bound.
//!
//! Policy text is parsed inside the trusted computing base, by
//! [`toml`](https://docs.rs/toml) — the first third-party parser the authority
//! links ([ADR-0035]). A limit checked after the allocation it is meant to
//! prevent is not a limit, which is the principle
//! [`dwk-proto`'s `limits.rs`](../../../dwk-proto/src/limits.rs) states for
//! frames and this module restates for policy: the source length is checked
//! against [`MAX_SOURCE_BYTES`] *before* the parser is called, the profile
//! count before any of them is read, and every per-rule bound while the
//! document is walked rather than after a compiled policy exists.
//!
//! # These are not security boundaries
//!
//! A policy file is operator-owned configuration, not attacker input; the
//! authority reads it from a directory the runtime cannot write
//! ([ADR-0000]). These bounds exist so that a *mistake* — a generated file, a
//! loop in a template, a paste — fails as a refusal with a name rather than as
//! memory pressure inside the process that decides. They also bound the fuzz
//! target's work, which is how they get exercised.
//!
//! # Why these numbers
//!
//! [`POLICY.md`] §3 targets 300 rules and names 300 as the scale at which a
//! DSL would be reconsidered, so [`MAX_RULES`] is 512: comfortably above the
//! target, far below anything that makes a linear scan interesting.
//! [`MAX_SOURCE_BYTES`] is 256 KiB, which is roughly two hundred times the
//! largest shipped profile. The identifier and string bounds match the ones
//! the capability grammar already uses, so a path written in a rule and a path
//! written in a capability are bounded alike.
//!
//! [ADR-0000]: ../../../../../docs/adr/0000-authority-plane-separation.md
//! [ADR-0035]: ../../../../../docs/adr/0035-m3-authority-dependency-set.md
//! [`POLICY.md`]: ../../../../../docs/POLICY.md

/// The longest policy source the loader will parse, in bytes.
///
/// Checked against the input length before [`toml`] sees it.
pub const MAX_SOURCE_BYTES: usize = 256 * 1024;

/// The longest logical source name, in characters.
pub const MAX_SOURCE_NAME_CHARS: usize = 128;

/// The most `[[rule]]` entries one profile may declare.
pub const MAX_RULES: usize = 512;

/// The most `[[postcondition]]` entries one profile may declare.
///
/// Small on purpose. Postconditions are the second evaluation phase, they run
/// for every decision, and each one may only narrow; a policy needing dozens
/// of them is a policy whose primary rules are wrong.
pub const MAX_POSTCONDITIONS: usize = 32;

/// The longest rule or postcondition id, in characters.
pub const MAX_RULE_ID_CHARS: usize = 64;

/// The longest profile name, in characters.
pub const MAX_PROFILE_NAME_CHARS: usize = 64;

/// The longest sandbox- or redaction-profile reference, in characters.
pub const MAX_PROFILE_REF_CHARS: usize = 64;

/// The most elements in any list a rule writes.
pub const MAX_LIST_ITEMS: usize = 64;

/// The longest string value anywhere in a rule, in characters.
///
/// Matches `DeclaredPath::MAX_CHARS`, so a path in a rule and a path in a
/// capability are bounded identically.
pub const MAX_STRING_CHARS: usize = 384;

/// The most obligations one rule may impose.
pub const MAX_OBLIGATIONS_PER_RULE: usize = 8;

/// The deepest rule-side path, in segments below its anchor.
pub const MAX_PATH_SEGMENTS: usize = 32;

/// The deepest `extends` chain, counting the profile that starts it.
///
/// Four. A chain longer than this is a policy nobody can read, which is the
/// property [`POLICY.md`] §3 is protecting when it refuses a DSL.
///
/// [`POLICY.md`]: ../../../../../docs/POLICY.md
pub const MAX_EXTENDS_DEPTH: usize = 4;

/// The most profiles one load may be handed.
pub const MAX_PROFILES: usize = 16;

/// The largest approval TTL, in seconds. Twenty-four hours.
///
/// [`APPROVALS.md`] §4 caps a *standing grant* at ninety days and a per-action
/// approval far below that; the shipped profiles use ten minutes and one hour.
/// A day is generous headroom and still a bound.
///
/// [`APPROVALS.md`]: ../../../../../docs/APPROVALS.md
pub const MAX_APPROVAL_TTL_SECONDS: u32 = 24 * 60 * 60;

/// The largest `max_uses` an approval specification may ask for.
pub const MAX_APPROVAL_USES: u32 = 1000;

// These are compile-time assertions rather than tests, because every one of
// them is a fact about constants: a runtime `assert!` over a `const` is a test
// that can only fail if the build already succeeded with a broken value, which
// is too late to be useful. A `const` block fails the *build*.
const _: () = assert!(MAX_SOURCE_BYTES > 0);
const _: () = assert!(MAX_SOURCE_NAME_CHARS > 0);
const _: () = assert!(MAX_POSTCONDITIONS > 0);
const _: () = assert!(MAX_RULE_ID_CHARS > 0);
const _: () = assert!(MAX_PROFILE_NAME_CHARS > 0);
const _: () = assert!(MAX_PROFILE_REF_CHARS > 0);
const _: () = assert!(MAX_LIST_ITEMS > 0);
const _: () = assert!(MAX_STRING_CHARS > 0);
const _: () = assert!(MAX_OBLIGATIONS_PER_RULE > 0);
const _: () = assert!(MAX_PATH_SEGMENTS > 0);
const _: () = assert!(MAX_APPROVAL_TTL_SECONDS > 0);
const _: () = assert!(MAX_APPROVAL_USES > 0);

// POLICY.md section 3 targets p99 < 200us at 300 rules, and names 300 as the
// scale at which a DSL would be reconsidered. The bound must not be the thing
// that stops a profile reaching the size the document plans for.
const _: () = assert!(MAX_RULES > 300);

// A chain cannot be deeper than the set it is drawn from.
const _: () = assert!(MAX_EXTENDS_DEPTH <= MAX_PROFILES);
