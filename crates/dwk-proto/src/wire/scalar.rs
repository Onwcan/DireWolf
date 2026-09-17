//! Bounded scalar wire types.
//!
//! A raw `u64` or `String` never appears in a message type. Each field has a
//! newtype that states its range or format once, and that statement is used by
//! the decoder, the encoder and the emitted schema alike.
//!
//! String lengths are counted in **Unicode scalar values**, which is what JSON
//! Schema's `maxLength` counts and what Python's `len(str)` returns, so the
//! three agree without conversion.

use crate::error::{ProtocolError, Violation};
use crate::json::{Number, Value};
use crate::limits::MAX_SAFE_INTEGER;
use crate::schema::{Defs, int, obj, string};
use crate::wire::{Cx, WireType, expect_integer, expect_string};

/// Declare a bounded integer newtype.
macro_rules! wire_int {
    ($(#[doc = $doc:literal])* $name:ident($inner:ty), min = $min:expr, max = $max:expr) => {
        $(#[doc = $doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name($inner);

        impl $name {
            /// Smallest permitted value.
            pub const MIN: $inner = $min;
            /// Largest permitted value.
            pub const MAX: $inner = $max;

            /// Construct, returning `None` outside the declared range.
            #[must_use]
            pub fn new(value: $inner) -> Option<Self> {
                (Self::MIN..=Self::MAX).contains(&value).then_some(Self(value))
            }

            /// The inner value.
            #[must_use]
            pub const fn get(self) -> $inner {
                self.0
            }
        }

        impl WireType for $name {
            fn decode(value: Value, cx: &mut Cx) -> Result<Self, ProtocolError> {
                let raw = expect_integer(&value, cx)?;
                <$inner>::try_from(raw).ok().and_then(Self::new).ok_or_else(|| {
                    cx.violation(
                        Violation::OutOfRange,
                        format!(
                            "{} must be within {}..={}",
                            stringify!($name),
                            Self::MIN,
                            Self::MAX
                        ),
                    )
                })
            }

            fn encode(&self) -> Result<Value, ProtocolError> {
                let as_i64 = i64::try_from(self.0).unwrap_or(MAX_SAFE_INTEGER);
                Ok(Value::Number(Number::from_i64(as_i64).unwrap_or(Number::Int(0))))
            }

            fn schema(_: &mut Defs) -> Value {
                obj(vec![
                    ("type", string("integer")),
                    ("minimum", int(i64::try_from(Self::MIN).unwrap_or(0))),
                    ("maximum", int(i64::try_from(Self::MAX).unwrap_or(MAX_SAFE_INTEGER))),
                    ("x-direwolf-type", string(stringify!($name))),
                ])
            }
        }
    };
}

wire_int! {
    /// A protocol version number: the envelope `v`, a `schema_version`, or a
    /// bound of a negotiated range. Version 0 does not exist.
    Version(u16), min = 1, max = u16::MAX
}

wire_int! {
    /// A session lease epoch. Monotonic per session and owned by
    /// `dwkd-authority`, which is the only party that assigns one
    /// (`PROTOCOL.md` §3). A runtime echoes the epoch it was granted; it can
    /// never choose one.
    Epoch(u64), min = 1, max = 9_007_199_254_740_991
}

/// Declare a bounded string newtype with a validator.
///
/// `pattern` is the JSON Schema regex describing exactly what `validate`
/// accepts. The two are written side by side so a reviewer can check them
/// together, and the shared invalid-message vectors check them mechanically
/// against the Python bindings, which enforce `pattern` directly.
macro_rules! wire_text {
    (
        $(#[doc = $doc:literal])*
        $name:ident,
        max_chars = $max:expr,
        pattern = $pattern:expr,
        format = $format:expr,
        validate = $validate:expr
    ) => {
        $(#[doc = $doc])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash)]
        pub struct $name(String);

        impl $name {
            /// Maximum length in Unicode scalar values.
            pub const MAX_CHARS: usize = $max;

            /// Construct, returning `None` if the value is too long or
            /// malformed.
            #[must_use]
            pub fn new(value: impl Into<String>) -> Option<Self> {
                let value = value.into();
                let check: fn(&str) -> bool = $validate;
                (value.chars().count() <= Self::MAX_CHARS && check(&value)).then_some(Self(value))
            }

            /// The string.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl WireType for $name {
            fn decode(value: Value, cx: &mut Cx) -> Result<Self, ProtocolError> {
                let s = expect_string(value, cx)?;
                if s.chars().count() > Self::MAX_CHARS {
                    return Err(cx.violation(
                        Violation::TooLong,
                        format!("{} exceeds {} characters", stringify!($name), Self::MAX_CHARS),
                    ));
                }
                let check: fn(&str) -> bool = $validate;
                if !check(&s) {
                    return Err(cx.violation(
                        Violation::InvalidFormat,
                        format!("{} is not correctly formatted", stringify!($name)),
                    ));
                }
                Ok(Self(s))
            }

            fn encode(&self) -> Result<Value, ProtocolError> {
                Ok(Value::String(self.0.clone()))
            }

            fn schema(_: &mut Defs) -> Value {
                let mut members = vec![
                    ("type", string("string")),
                    ("maxLength", int(i64::try_from(Self::MAX_CHARS).unwrap_or(0))),
                    ("x-direwolf-type", string(stringify!($name))),
                ];
                let pattern: Option<&str> = $pattern;
                if let Some(p) = pattern {
                    members.push(("pattern", string(p)));
                }
                let format: Option<&str> = $format;
                if let Some(f) = format {
                    members.push(("x-direwolf-format", string(f)));
                }
                obj(members)
            }
        }
    };
}

wire_text! {
    /// A message `schema` name: `direwolf` followed by one to six dot-separated
    /// lowercase segments, e.g. `direwolf.lease.acquire`.
    SchemaName,
    max_chars = 128,
    pattern = Some("^direwolf(\\.[a-z][a-z0-9_]{0,31}){1,6}$"),
    format = None,
    validate = valid_schema_name
}

wire_text! {
    /// Free text explaining an error. Informational only: no decision may be
    /// taken on its content, and it is bounded because it is audited.
    Detail,
    max_chars = crate::limits::MAX_ERROR_DETAIL_CHARS,
    pattern = None,
    format = None,
    validate = |_| true
}

impl Detail {
    /// Build from any text, truncating to the limit. Always valid: `Detail`
    /// has no format, only a length.
    #[must_use]
    pub fn truncated(text: &str) -> Self {
        Self(crate::error::truncate_chars(text, Self::MAX_CHARS))
    }
}

wire_text! {
    /// An RFC 6901 JSON Pointer locating an error within a message.
    ErrorPath,
    max_chars = crate::limits::MAX_ERROR_PATH_CHARS,
    pattern = Some("^(/[\\s\\S]*)?$"),
    format = None,
    validate = |s| s.is_empty() || s.starts_with('/')
}

wire_text! {
    /// A sender-chosen key that makes a retried request one request.
    ///
    /// The kernel deduplicates on it (`PROTOCOL.md` §8). `AdmitRun` requires
    /// one and is the only operation that permits one: it is the first
    /// operation whose retry would otherwise mint a second grant, and a lost
    /// response is not an exotic event but the ordinary failure of a socket
    /// (ADR-0036 §8).
    ///
    /// It names an *admission attempt*, never a run. `run_id` stays forbidden
    /// on the request because the kernel assigns it, and the key is scoped
    /// kernel-side to the authenticated peer and the session, so it is not a
    /// name another caller can guess its way into.
    IdempotencyKey,
    max_chars = 128,
    pattern = Some("^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"),
    format = None,
    validate = valid_idempotency_key
}

wire_text! {
    /// A client-protocol error code. Open-ended by design: DWCP is
    /// forward-compatible, so a client must accept codes newer than itself.
    ClientErrorCode,
    max_chars = 64,
    pattern = Some("^[A-Z][A-Z0-9_]{0,63}$"),
    format = None,
    validate = valid_upper_snake
}

wire_text! {
    /// A UTC timestamp, `YYYY-MM-DDTHH:MM:SS.mmmZ`: RFC 3339 with exactly
    /// millisecond precision and a literal `Z`, so every instant has one
    /// spelling.
    ///
    /// **Advisory.** A timestamp is the sender's claim about its own clock.
    /// Expiry, lease and approval decisions use time the kernel reads itself
    /// (`RELIABILITY.md` §10); nothing on this field may gate authority.
    Timestamp,
    max_chars = 24,
    pattern = Some("^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3}Z$"),
    format = Some("rfc3339-utc-millis"),
    validate = valid_timestamp
}

wire_text! {
    /// One capability in the grammar of `CAPABILITIES.md` §2:
    /// `verb ":" scope [ "?" constraints ]`, where `verb` is
    /// `namespace "." action`.
    ///
    /// **This crate checks the lexical form and the bounds, and nothing else.**
    /// It does not know what a verb means, which scopes contain which, or how
    /// two constraints compare: that is the ⊑ lattice, it lives in the
    /// authority, and putting it here would put policy in the protocol crate
    /// (ADR-0031, ADR-0036). A string that parses here is still rejected by the
    /// authority if its verb, scope type or constraint key is not one the
    /// kernel knows — unknown forms fail closed there, not by being
    /// unrepresentable here.
    ///
    /// The character set is explicit ASCII rather than "anything but
    /// whitespace", so the Rust validator and the Python `pattern` cannot
    /// disagree about what a Unicode space is.
    CapabilityText,
    max_chars = 512,
    pattern = Some(concat!(
        "^[a-z][a-z0-9_]{0,15}\\.[a-z][a-z0-9_]{0,31}",
        ":[A-Za-z0-9._/*:@+~<>-]{1,384}",
        "(\\?[A-Za-z0-9_=,&.*/-]{1,96})?$"
    )),
    format = None,
    validate = valid_capability
}

wire_text! {
    /// The name of an agent profile, e.g. `researcher`.
    ///
    /// A name, not an identifier: profiles are written by an operator and
    /// referenced by capability scopes such as `agent.spawn:researcher`.
    AgentProfileName,
    max_chars = 64,
    pattern = Some("^[a-z][a-z0-9-]{0,63}$"),
    format = None,
    validate = valid_lower_kebab
}

wire_text! {
    /// The name of a skill offered to a run, e.g. `rust-review`.
    SkillName,
    max_chars = 64,
    pattern = Some("^[a-z][a-z0-9-]{0,63}$"),
    format = None,
    validate = valid_lower_kebab
}

wire_text! {
    /// Which policy decided: the SHA-256 of the loaded rule set, lowercase hex.
    ///
    /// A revision rather than a version number, because "the policy that was in
    /// force" must be identifiable from an audit record months later, and a
    /// number an operator can reuse is not that. The kernel computes it; it is
    /// never supplied by a client.
    PolicyRevision,
    max_chars = 64,
    pattern = Some("^[0-9a-f]{64}$"),
    format = None,
    validate = valid_sha256_hex
}

wire_text! {
    /// The `id` of the policy rule that decided, e.g. `deny-credential-paths`.
    RuleId,
    max_chars = 64,
    pattern = Some("^[a-z][a-z0-9-]{0,63}$"),
    format = None,
    validate = valid_lower_kebab
}

wire_text! {
    /// Where the decisive rule is written: a repository-relative path and a
    /// 1-based line, e.g. `policy/balanced.toml:63`.
    ///
    /// POLICY.md §1.5 requires every decision to be explainable, and a rule id
    /// alone does not say which file in a composed rule pack it came from.
    RuleSource,
    max_chars = 256,
    pattern = Some("^[A-Za-z0-9._/-]{1,240}:[0-9]{1,8}$"),
    format = None,
    validate = valid_rule_source
}

/// A lowercase letter followed by lowercase letters, digits and hyphens.
fn valid_lower_kebab(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some('a'..='z'))
        && chars.all(|c| matches!(c, 'a'..='z' | '0'..='9' | '-'))
}

fn valid_sha256_hex(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn valid_rule_source(s: &str) -> bool {
    let Some((path, line)) = s.rsplit_once(':') else {
        return false;
    };
    let path_ok = (1..=240).contains(&path.chars().count())
        && path
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '/' | '-'));
    let line_ok = (1..=8).contains(&line.len()) && line.bytes().all(|b| b.is_ascii_digit());
    path_ok && line_ok
}

/// The capability grammar's lexical form. Mirrors `CapabilityText`'s pattern
/// exactly; the shared vectors check the two against the Python bindings.
fn valid_capability(s: &str) -> bool {
    let Some((verb, rest)) = s.split_once(':') else {
        return false;
    };
    let Some((namespace, action)) = verb.split_once('.') else {
        return false;
    };
    if !bounded_lower_snake(namespace, 16) || !bounded_lower_snake(action, 32) {
        return false;
    }
    // The first `?` starts the constraints; a second one is not permitted in
    // either half, so a capability has exactly one reading.
    let (scope, constraints) = match rest.split_once('?') {
        Some((scope, constraints)) => (scope, Some(constraints)),
        None => (rest, None),
    };
    let scope_ok = (1..=384).contains(&scope.chars().count())
        && scope.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(
                    c,
                    '.' | '_' | '/' | '*' | ':' | '@' | '+' | '~' | '<' | '>' | '-'
                )
        });
    if !scope_ok {
        return false;
    }
    match constraints {
        None => true,
        Some(text) => {
            (1..=96).contains(&text.chars().count())
                && text.chars().all(|c| {
                    c.is_ascii_alphanumeric()
                        || matches!(c, '_' | '=' | ',' | '&' | '.' | '*' | '/' | '-')
                })
        }
    }
}

/// A lowercase letter followed by at most `max - 1` lowercase letters, digits
/// or underscores.
fn bounded_lower_snake(s: &str, max: usize) -> bool {
    let mut chars = s.chars();
    (1..=max).contains(&s.chars().count())
        && matches!(chars.next(), Some('a'..='z'))
        && chars.all(|c| matches!(c, 'a'..='z' | '0'..='9' | '_'))
}

// ---------------------------------------------------------------------------
// M3 authority decision vocabulary.
//
// Every one of these is a closed enumeration rather than a string, because a
// denial nobody can classify is a denial nobody can measure (POLICY.md §2), and
// because an exhaustive `match` is what makes adding a variant break at every
// site that must handle it.
// ---------------------------------------------------------------------------

wire_enum! {
    /// The capability ceiling a run was admitted under (`CAPABILITIES.md` §6).
    ///
    /// Kernel-owned configuration. It is reported, never requested: `mode` is
    /// not in the runtime's request vocabulary, so an agent cannot induce a
    /// profile change.
    ProfileName {
        /// Workspace only; no execution, no network, no secrets.
        Safe = "SAFE",
        /// The default: allowlisted execution and hosts, workspace writes.
        Balanced = "BALANCED",
        /// Widest ceiling; still sandboxed, still policed.
        Power = "POWER",
    }
}

wire_enum! {
    /// What policy decided (`POLICY.md` §2, `Effect`).
    DecisionEffect {
        /// Permitted, subject to any obligations.
        Allow = "ALLOW",
        /// Refused.
        Deny = "DENY",
        // There is deliberately no REQUIRE_APPROVAL here. Policy's own Effect
        // is three-valued (ADR-0006) and M3c will compute all three; what
        // crosses this wire is what the authority *decided*, and an authority
        // with no approval registry decides DENY -- the direction APPROVALS.md
        // already fixes for the case where no human is present. A third value
        // nothing in this build can satisfy is a value a client has to guess
        // at, and the dangerous guess ("not DENY, so proceed") is the easy one.
        // M6 adds it with a schema_version bump. ADR-0036 section 9.
    }
}

wire_enum! {
    /// The outcome of one of the two independent gates of ADR-0006.
    ///
    /// Both always run: neither substitutes for the other, and reporting both
    /// is what lets a reader see *which* one refused.
    GateResult {
        /// This gate permits the action.
        Satisfied = "SATISFIED",
        /// This gate refuses it.
        NotSatisfied = "NOT_SATISFIED",
    }
}

wire_enum! {
    /// Why the authority decided as it did.
    ///
    /// Machine-classifiable by construction: evals count denials by reason, and
    /// a free-text reason cannot be counted. Human text is rendered from this,
    /// never parsed back into it.
    DecisionReason {
        /// A rule matched and its effect was ALLOW.
        AllowedByRule = "ALLOWED_BY_RULE",
        /// A rule matched and its effect was DENY.
        DeniedByRule = "DENIED_BY_RULE",
        /// No rule matched before the mandatory `default` rule.
        DefaultDeny = "DEFAULT_DENY",
        /// Policy permitted it; no held capability covers it (ADR-0006).
        NoCapability = "NO_CAPABILITY",
        /// The proposed capability is lexically valid but names a verb, scope
        /// type or constraint the kernel's vocabulary does not contain. The
        /// gates ran; nothing covered it.
        CapabilityMalformed = "CAPABILITY_MALFORMED",
        // No APPROVAL_REQUIRED either, and for the same reason: routing the
        // removed effect back through the reason field would be the approval
        // semantics again, spelled differently. A rule whose effect is
        // REQUIRE_APPROVAL refuses in this build, and `rule_id` with
        // `rule_source` name exactly which rule refused -- which keeps the
        // refusal debuggable without the wire claiming a faculty the build
        // does not have.
        //
        // RUN_NOT_ADMITTED used to be here, and was in the wrong enum. Every
        // reason above is the outcome of an evaluation that *ran*: the two
        // gates of ADR-0006 were applied to a real grant under a real policy
        // revision. "This run holds no admission" is not an outcome of that
        // evaluation -- it is the reason no evaluation could happen, and a
        // kernel giving it has no grant, no profile and no policy_revision to
        // report, so it cannot fill an EffectiveAuthority at all. It is now
        // `RefusalReason::UnknownRun` on `direwolf.authority.refused`
        // (ADR-0036 section 10).
    }
}

wire_enum! {
    /// Which M3 authority operation a refusal answers.
    ///
    /// `causation_id` already binds a refusal to the message that caused it.
    /// This says which *operation* that message was, which is what lets the
    /// operation/reason pairing be closed: a refusal naming a reason the
    /// operation cannot produce is refused at the boundary rather than carried
    /// inwards and believed. It is also what makes a refusal legible in an
    /// audit record that no longer has the request beside it.
    ///
    /// Only operations that can be refused appear. `Handshake` cannot: it runs
    /// before there is any authority state to refuse against.
    RefusedOperation {
        /// `direwolf.lease.acquire`.
        AcquireLease = "ACQUIRE_LEASE",
        /// `direwolf.lease.release`.
        ReleaseLease = "RELEASE_LEASE",
        /// `direwolf.heartbeat`.
        Heartbeat = "HEARTBEAT",
        /// `direwolf.run.admit`.
        AdmitRun = "ADMIT_RUN",
        /// `direwolf.run.release`.
        ReleaseRun = "RELEASE_RUN",
        /// `direwolf.authority.query`.
        QueryAuthority = "QUERY_AUTHORITY",
    }
}

wire_enum! {
    /// Why the authority refused to act on a well-formed request.
    ///
    /// **Not a policy denial and not a protocol error.** A protocol error says
    /// nothing was evaluated because nothing well-formed arrived; a decision
    /// says the two gates of ADR-0006 ran and refused; a refusal says the
    /// authority's own state does not permit the operation to be attempted at
    /// all, so no evaluation happened. Collapsing any two of the three would
    /// make a client unable to tell "fix your message" from "ask for less"
    /// from "re-acquire your lease" (`PROTOCOL.md` §2).
    ///
    /// Closed, and deliberately small: every variant is required by an M3
    /// operation that exists today. Nothing here anticipates M4 or later — a
    /// reason for a milestone that cannot produce it is a branch a client
    /// writes and never exercises.
    RefusalReason {
        /// The epoch presented is not the session's current epoch: it is older,
        /// or there is no current epoch because no lease is held. One remedy
        /// covers both — `AcquireLease` — and the two cases are deliberately
        /// not distinguished, because the difference is an oracle for whether a
        /// session exists (`PROTOCOL.md` §3, ADR-0011 point 5).
        ///
        /// Checked **before** anything else, including idempotency replay: a
        /// key must never be a way past the fence.
        StaleEpoch = "STALE_EPOCH",
        /// The session's lease is held and unexpired, and this caller is not
        /// the holder. Exactly one process wins the conditional acquire
        /// (ADR-0011 point 2); this is what the others are told.
        LeaseHeld = "LEASE_HELD",
        /// The idempotency key has a record under this caller's scope, and it
        /// is bound to a different canonical request. The key is never
        /// reinterpreted for a second admission, and the first admission is
        /// never amended by the second request's contents (ADR-0036 §8 case 4).
        IdempotencyConflict = "IDEMPOTENCY_CONFLICT",
        /// The agent profile named by `AdmitRun` is not one the kernel holds.
        /// A denial rather than a protocol error: the name is well-formed, and
        /// which names exist is authority state, not wire syntax.
        UnknownAgentProfile = "UNKNOWN_AGENT_PROFILE",
        /// The `run_id` names no live admission for this caller. "Never
        /// existed" and "already released" are one answer on purpose: in M3 a
        /// run exists because it was admitted, and separating the two would
        /// turn the refusal into a probe for which run ids are real.
        UnknownRun = "UNKNOWN_RUN",
    }
}

wire_enum! {
    /// Which term of the minting expression removed a requested capability
    /// (`CAPABILITIES.md` §4, `mint`).
    ///
    /// Requesting more than you can have is not an error — it yields less — so
    /// the difference has to be reportable, or an agent cannot tell a human
    /// what it lacks.
    WithheldReason {
        /// Not in the agent profile's declared set.
        NotInAgentProfile = "NOT_IN_AGENT_PROFILE",
        /// Not in the intersection of the active skills' declared sets.
        NotInSkillSet = "NOT_IN_SKILL_SET",
        /// Not in the parent run's effective set (subagents).
        NotInParentGrant = "NOT_IN_PARENT_GRANT",
        /// Above the ceiling of the admitted profile.
        AboveProfileCeiling = "ABOVE_PROFILE_CEILING",
        /// Refused by the policy preflight at minting time.
        DeniedByPolicy = "DENIED_BY_POLICY",
    }
}

fn valid_schema_name(s: &str) -> bool {
    let Some(rest) = s.strip_prefix("direwolf.") else {
        return false;
    };
    let segments: Vec<&str> = rest.split('.').collect();
    (1..=6).contains(&segments.len())
        && segments.iter().all(|seg| {
            let mut chars = seg.chars();
            matches!(chars.next(), Some('a'..='z'))
                && seg.len() <= 32
                && chars.all(|c| matches!(c, 'a'..='z' | '0'..='9' | '_'))
        })
}

fn valid_idempotency_key(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some(c) if c.is_ascii_alphanumeric())
        && chars.all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '-'))
}

fn valid_upper_snake(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(chars.next(), Some('A'..='Z'))
        && chars.all(|c| matches!(c, 'A'..='Z' | '0'..='9' | '_'))
}

fn valid_timestamp(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() != 24 {
        return false;
    }
    let shape_ok = b.iter().enumerate().all(|(i, c)| match i {
        4 | 7 => *c == b'-',
        10 => *c == b'T',
        13 | 16 => *c == b':',
        19 => *c == b'.',
        23 => *c == b'Z',
        _ => c.is_ascii_digit(),
    });
    if !shape_ok {
        return false;
    }
    let num = |range: std::ops::Range<usize>| -> Option<u32> { s.get(range)?.parse().ok() };
    let (Some(year), Some(month), Some(day), Some(hour), Some(minute), Some(second)) = (
        num(0..4),
        num(5..7),
        num(8..10),
        num(11..13),
        num(14..16),
        num(17..19),
    ) else {
        return false;
    };
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1..=days_in_month).contains(&day) && hour < 24 && minute < 60 && second < 60
}

/// Declare a closed string enumeration.
macro_rules! wire_enum {
    (
        $(#[doc = $doc:literal])*
        $name:ident { $( $(#[doc = $vdoc:literal])* $variant:ident = $wire:literal ),+ $(,)? }
    ) => {
        $(#[doc = $doc])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum $name {
            $( $(#[doc = $vdoc])* $variant, )+
        }

        impl $name {
            /// Every variant, in declaration order.
            pub const ALL: &'static [Self] = &[$(Self::$variant),+];

            /// The wire spelling.
            #[must_use]
            pub const fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $wire,)+ }
            }
        }

        impl $crate::wire::WireType for $name {
            fn decode(
                value: $crate::json::Value,
                cx: &mut $crate::wire::Cx,
            ) -> Result<Self, $crate::error::ProtocolError> {
                let s = $crate::wire::expect_string(value, cx)?;
                Self::ALL.iter().copied().find(|v| v.as_str() == s).ok_or_else(|| {
                    cx.violation(
                        $crate::error::Violation::UnknownVariant,
                        format!("not a {} variant", stringify!($name)),
                    )
                })
            }

            fn encode(&self) -> Result<$crate::json::Value, $crate::error::ProtocolError> {
                Ok($crate::json::Value::String(self.as_str().to_owned()))
            }

            fn schema(_: &mut $crate::schema::Defs) -> $crate::json::Value {
                $crate::schema::obj(vec![
                    ("type", $crate::schema::string("string")),
                    ("enum", $crate::schema::strings(&[$($wire),+])),
                    ("x-direwolf-type", $crate::schema::string(stringify!($name))),
                ])
            }
        }
    };
}

pub(crate) use wire_enum;

#[cfg(test)]
mod tests {
    use super::{
        AgentProfileName, CapabilityText, PolicyRevision, RuleSource, valid_capability,
        valid_rule_source, valid_schema_name, valid_sha256_hex, valid_timestamp,
    };
    use crate::wire::WireType;

    #[test]
    fn the_capability_grammar_accepts_every_shape_the_architecture_writes() {
        // Straight from CAPABILITIES.md section 2. If one of these stops
        // parsing, the protocol has drifted from the document that defines it.
        for good in [
            "fs.read:/workspace/src",
            "fs.write:/workspace/src",
            "process.exec:/usr/bin/git",
            "network.https:api.github.com:443",
            "secret.use:github-primary",
            "model.call:anthropic/*",
            "browser.use:*.github.com",
            "mcp.use:filesystem-server",
            "agent.spawn:researcher",
            "memory.promote:semantic",
            "scheduler.create:*",
            "artifact.export:*",
            "channel.send:telegram:<chat_id>",
            "fs.exec_bit:/workspace",
            "fs.write:/workspace?max_bytes=10485760&no_symlink_targets=true",
            "network.https:*.github.com?methods=GET,POST&max_requests=100",
            "process.exec:/usr/bin/git?argv_allowlist=status,diff,log,show",
            "model.call:*?privacy_class=LOCAL_ONLY",
        ] {
            assert!(valid_capability(good), "{good}");
            assert!(CapabilityText::new(good).is_some(), "{good}");
        }
    }

    #[test]
    fn the_capability_grammar_refuses_what_is_not_a_capability() {
        for bad in [
            "",                            // nothing
            "fs.read",                     // no scope separator
            "fs.read:",                    // empty scope
            ":/workspace",                 // no verb
            "read:/workspace",             // no namespace
            "fs:/workspace",               // no action
            "Fs.read:/workspace",          // uppercase namespace
            "fs.Read:/workspace",          // uppercase action
            "fs.read:/work space",         // whitespace in the scope
            "fs.read:/workspace?",         // empty constraints
            "fs.read:/w?a=1?b=2",          // two constraint sections: two readings
            "fs.read:/w\u{a0}x",           // a non-breaking space is still a space
            "fs.read:/w\ncat /etc/passwd", // a newline is not a scope character
            "9fs.read:/w",                 // namespace must start with a letter
            "fs.9read:/w",                 // action must start with a letter
            "fs.read:/w?max bytes=1",      // whitespace in the constraints
        ] {
            assert!(!valid_capability(bad), "{bad:?} must not parse");
            assert!(CapabilityText::new(bad).is_none(), "{bad:?}");
        }
    }

    #[test]
    fn a_capability_longer_than_the_bound_is_refused() {
        let scope = "a".repeat(400);
        assert!(!valid_capability(&format!("fs.read:{scope}")));
        let at_bound = "a".repeat(384);
        assert!(valid_capability(&format!("fs.read:{at_bound}")));
    }

    #[test]
    fn the_capability_type_refuses_what_exceeds_its_character_bound() {
        // Two bounds apply: the scope's, and the whole string's. Both matter.
        let huge = format!("fs.read:{}", "a".repeat(600));
        assert!(CapabilityText::new(huge).is_none());
    }

    #[test]
    fn a_policy_revision_is_a_sha256_and_nothing_else() {
        assert!(valid_sha256_hex(&"9f".repeat(32)));
        assert!(PolicyRevision::new("0".repeat(64)).is_some());
        for bad in [
            "9F".repeat(32),                       // uppercase: one spelling only
            "9f".repeat(31),                       // too short
            format!("{}g", "9f".repeat(31) + "9"), // not hex
            "balanced-v2".to_owned(),
        ] {
            assert!(!valid_sha256_hex(&bad), "{bad}");
            assert!(PolicyRevision::new(bad.clone()).is_none(), "{bad}");
        }
    }

    #[test]
    fn a_rule_source_names_a_file_and_a_line() {
        assert!(valid_rule_source("policy/balanced.toml:63"));
        assert!(valid_rule_source("base.toml:1"));
        assert!(RuleSource::new("policy/balanced.toml:63").is_some());
        for bad in [
            "policy/balanced.toml",     // no line
            "policy/balanced.toml:",    // empty line
            "policy/balanced.toml:0x1", // not a number
            ":63",                      // no file
            "policy balanced.toml:63",  // whitespace
            "../../etc/shadow:1",       // dot-dot is not in the character set... it is,
                                        // and that is fine: this field is a diagnostic
                                        // string, never a path anything opens.
        ] {
            let ok = valid_rule_source(bad);
            if bad.starts_with("../..") {
                assert!(ok, "the field is diagnostic text, not a path to resolve");
            } else {
                assert!(!ok, "{bad}");
            }
        }
    }

    #[test]
    fn an_agent_profile_name_is_lowercase_kebab() {
        assert!(AgentProfileName::new("researcher").is_some());
        assert!(AgentProfileName::new("code-reviewer-2").is_some());
        for bad in [
            "Researcher",
            "-leading",
            "has_underscore",
            "",
            "a".repeat(65).as_str(),
        ] {
            assert!(AgentProfileName::new(bad).is_none(), "{bad}");
        }
    }

    #[test]
    fn the_capability_schema_pattern_and_the_validator_agree() {
        // The pattern is what Python enforces and the validator is what Rust
        // enforces; a disagreement is a message one language accepts and the
        // other does not. The shared vectors check specific cases -- this
        // checks that the pattern is actually emitted, so a future edit that
        // drops it cannot pass unnoticed.
        let mut defs = crate::schema::Defs::new();
        let crate::json::Value::Object(object) = CapabilityText::schema(&mut defs) else {
            unreachable!("a schema is an object")
        };
        let pattern = match object.get("pattern") {
            Some(crate::json::Value::String(p)) => p.clone(),
            _ => unreachable!("CapabilityText must publish its pattern"),
        };
        assert!(pattern.starts_with("^[a-z][a-z0-9_]{0,15}"));
        assert!(pattern.ends_with('$'));
    }

    #[test]
    fn timestamps_have_exactly_one_spelling_per_instant() {
        assert!(valid_timestamp("2026-09-12T09:14:22.481Z"));
        assert!(valid_timestamp("2024-02-29T23:59:59.999Z"));
        for bad in [
            "2026-09-12T09:14:22Z",      // no milliseconds
            "2026-09-12T09:14:22.4810Z", // too precise
            "2026-09-12T09:14:22.481+00:00",
            "2026-09-12t09:14:22.481z", // lowercase
            "2023-02-29T00:00:00.000Z", // not a leap year
            "1900-02-29T00:00:00.000Z", // century rule
            "2026-13-01T00:00:00.000Z",
            "2026-09-31T00:00:00.000Z",
            "2026-09-12T24:00:00.000Z",
            "2026-09-12T23:59:60.000Z", // leap seconds are not representable
            "2026-09-12T09:14:22.481Z ",
        ] {
            assert!(!valid_timestamp(bad), "{bad}");
        }
        assert!(valid_timestamp("2000-02-29T00:00:00.000Z"), "400-year rule");
    }

    #[test]
    fn schema_names() {
        assert!(valid_schema_name("direwolf.lease.acquire"));
        assert!(valid_schema_name("direwolf.session.lease_acquired"));
        for bad in [
            "direwolf",
            "direwolf.",
            "Direwolf.x",
            "direwolf.Lease",
            "direwolf.1x",
            "other.x",
        ] {
            assert!(!valid_schema_name(bad), "{bad}");
        }
    }
}
