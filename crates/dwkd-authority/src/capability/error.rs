//! Typed failures.
//!
//! Malformed capability text is *expected hostile input*: it arrives over DWKP
//! from the least trusted process in the system. So nothing here panics, and
//! nothing downstream is asked to branch on a message string — the `Display`
//! text is for humans, and the variants are for code.

use core::fmt;

use super::verb::{Namespace, Verb};

/// The name of one of the eight constraints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ConstraintName {
    /// `max_bytes`.
    MaxBytes,
    /// `no_symlink_targets`.
    NoSymlinkTargets,
    /// `methods`.
    Methods,
    /// `max_requests`.
    MaxRequests,
    /// `argv_allowlist`.
    ArgvAllowlist,
    /// `privacy_class`.
    PrivacyClass,
    /// `depth`.
    Depth,
    /// `fanout`.
    Fanout,
}

impl ConstraintName {
    /// All eight, in canonical order — the order canonical text renders them.
    pub const ALL: &'static [Self] = &[
        Self::MaxBytes,
        Self::NoSymlinkTargets,
        Self::Methods,
        Self::MaxRequests,
        Self::ArgvAllowlist,
        Self::PrivacyClass,
        Self::Depth,
        Self::Fanout,
    ];

    /// The wire spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MaxBytes => "max_bytes",
            Self::NoSymlinkTargets => "no_symlink_targets",
            Self::Methods => "methods",
            Self::MaxRequests => "max_requests",
            Self::ArgvAllowlist => "argv_allowlist",
            Self::PrivacyClass => "privacy_class",
            Self::Depth => "depth",
            Self::Fanout => "fanout",
        }
    }

    /// Parse exactly. No case folding, no aliases, no abbreviations.
    #[must_use]
    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL.iter().copied().find(|n| n.as_str() == text)
    }
}

impl fmt::Display for ConstraintName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Why a constraint's value was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ValueError {
    /// Not a decimal integer.
    MalformedInteger,
    /// A leading zero: one number, two spellings.
    LeadingZero,
    /// Too large for the constraint's type. Never truncated: a truncated limit
    /// is a wider limit.
    IntegerOverflow,
    /// Not `true`. `no_symlink_targets` has exactly one value.
    MalformedBoolean,
    /// An empty member, from a doubled or trailing comma.
    EmptySetMember,
    /// The same member twice.
    DuplicateSetMember,
    /// Not one of the HTTP methods this build defines.
    UnknownMethod,
    /// Not a valid `argv_allowlist` token.
    MalformedArgvToken,
    /// Not `LOCAL_ONLY`, `VENDOR_OK` or `ANY`.
    UnknownPrivacyClass,
    /// The value was empty.
    Empty,
}

impl fmt::Display for ValueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::MalformedInteger => "not a decimal integer",
            Self::LeadingZero => "leading zero",
            Self::IntegerOverflow => "integer out of range",
            Self::MalformedBoolean => "the only accepted value is `true`",
            Self::EmptySetMember => "empty set member",
            Self::DuplicateSetMember => "duplicate set member",
            Self::UnknownMethod => "unknown HTTP method",
            Self::MalformedArgvToken => "malformed argv token",
            Self::UnknownPrivacyClass => "unknown privacy class",
            Self::Empty => "empty value",
        })
    }
}

/// Why a scope was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ScopeError {
    /// Not a host: an empty label, an uppercase letter, an interior wildcard,
    /// or an address literal with no defined containment relation.
    MalformedHost,
    /// `*.com` — a wildcard with fewer than two labels behind it is authority
    /// over a top-level domain.
    WildcardInTldPosition,
    /// Not a port, or more than one colon (which is how an IPv6 literal
    /// arrives).
    MalformedPort,
    /// Not `provider/model-pattern`.
    MalformedProviderModel,
    /// A wildcard anywhere but the trailing position, or an empty literal.
    MalformedPattern,
    /// Not `channel:destination`.
    MalformedChannelTarget,
    /// Not a name this family accepts.
    MalformedName,
    /// Not an absolute path, or too long.
    MalformedPath,
}

impl fmt::Display for ScopeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::MalformedHost => "malformed host pattern",
            Self::WildcardInTldPosition => "a wildcard may not stand in for a top-level domain",
            Self::MalformedPort => "malformed port",
            Self::MalformedProviderModel => "expected provider/model",
            Self::MalformedPattern => "a wildcard is permitted only at the end",
            Self::MalformedChannelTarget => "expected channel:destination",
            Self::MalformedName => "malformed name",
            Self::MalformedPath => "expected an absolute path",
        })
    }
}

/// Why a capability string could not be interpreted, or a capability built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapabilityError {
    /// The input was empty.
    Empty,
    /// Longer than [`super::parse::MAX_CAPABILITY_CHARS`].
    TooLong,
    /// No `:` — a capability without a scope is a capability over everything,
    /// and that is `*`, written explicitly.
    MissingScope,
    /// No `.` in the verb.
    MissingAction,
    /// The namespace half was empty.
    EmptyNamespace,
    /// The action half was empty.
    EmptyAction,
    /// The scope was empty.
    EmptyScope,
    /// Not one of the twelve namespaces. Case matters: `FS` is not `fs`.
    UnknownNamespace,
    /// Not an action this namespace defines — including an action that exists
    /// in a *different* namespace.
    UnknownAction {
        /// The namespace whose actions were searched.
        namespace: Namespace,
    },
    /// The scope did not parse for this verb's family.
    InvalidScope(ScopeError),
    /// A `?` with nothing after it.
    EmptyConstraints,
    /// A second `?`.
    RepeatedConstraintSeparator,
    /// A constraint with no `=`.
    MalformedConstraint,
    /// A constraint with an empty name.
    EmptyConstraintName,
    /// A constraint with an empty value.
    EmptyConstraintValue,
    /// Not one of the eight.
    UnknownConstraint,
    /// The same constraint twice. Never "last value wins": two values for one
    /// constraint means the sender does not know which it is asking for, and
    /// picking one for them is picking the wider one half the time.
    DuplicateConstraint {
        /// Which constraint appeared twice.
        name: ConstraintName,
    },
    /// A valid constraint on a verb it does not apply to.
    ConstraintNotApplicable {
        /// The constraint.
        name: ConstraintName,
        /// The verb it was attached to.
        verb: Verb,
    },
    /// The constraint's value was rejected.
    InvalidConstraintValue {
        /// Which constraint.
        name: ConstraintName,
        /// Why.
        reason: ValueError,
    },
    /// The scope does not belong to this verb's family — a `Capability` built
    /// by hand with mismatched parts.
    ScopeFamilyMismatch,
}

impl fmt::Display for CapabilityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("empty capability"),
            Self::TooLong => f.write_str("capability too long"),
            Self::MissingScope => f.write_str("expected verb:scope"),
            Self::MissingAction => f.write_str("expected namespace.action"),
            Self::EmptyNamespace => f.write_str("empty namespace"),
            Self::EmptyAction => f.write_str("empty action"),
            Self::EmptyScope => f.write_str("empty scope"),
            Self::UnknownNamespace => f.write_str("unknown namespace"),
            Self::UnknownAction { namespace } => {
                write!(f, "unknown action for namespace `{namespace}`")
            }
            Self::InvalidScope(e) => write!(f, "invalid scope: {e}"),
            Self::EmptyConstraints => f.write_str("`?` with no constraints"),
            Self::RepeatedConstraintSeparator => f.write_str("more than one `?`"),
            Self::MalformedConstraint => f.write_str("expected name=value"),
            Self::EmptyConstraintName => f.write_str("empty constraint name"),
            Self::EmptyConstraintValue => f.write_str("empty constraint value"),
            Self::UnknownConstraint => f.write_str("unknown constraint"),
            Self::DuplicateConstraint { name } => write!(f, "duplicate constraint `{name}`"),
            Self::ConstraintNotApplicable { name, verb } => {
                write!(f, "constraint `{name}` does not apply to `{verb}`")
            }
            Self::InvalidConstraintValue { name, reason } => {
                write!(f, "invalid value for `{name}`: {reason}")
            }
            Self::ScopeFamilyMismatch => f.write_str("scope does not match the verb's family"),
        }
    }
}

impl core::error::Error for CapabilityError {}

/// Why a declaration could not be promoted to an authority-comparable
/// capability.
///
/// This is not a parse failure. The text was correct; the *resource* it names
/// has an identity this build cannot derive, and pretending otherwise is the
/// mistake the type split exists to prevent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum UnresolvedScope {
    /// An `fs` scope. Its authority identity is a canonical path — inode
    /// identity after symlink resolution and NFC normalisation — and deriving
    /// one from a path string safely is M4's canonicaliser.
    CanonicalPath,
    /// A `process` scope. Its authority identity is `(resolved path, sha256)`,
    /// and the hash requires reading the file M4 will have opened.
    ExecutableIdentity,
}

impl fmt::Display for UnresolvedScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::CanonicalPath => {
                "an fs scope names a path whose canonical identity only M4's resolver can derive"
            }
            Self::ExecutableIdentity => {
                "a process scope names an executable whose (path, sha256) identity only M4 can derive"
            }
        })
    }
}

impl core::error::Error for UnresolvedScope {}

/// Why an attenuation was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttenuationError {
    /// The narrowing named a different verb. Attenuation narrows one authority;
    /// it does not change what the authority is *for*.
    VerbChanged,
    /// The result would not be contained by the parent. The one error that
    /// matters: it is what makes widening unreachable rather than merely
    /// discouraged.
    WouldWiden,
    /// The narrowing was not a well-formed capability for this verb.
    Invalid(CapabilityError),
}

impl fmt::Display for AttenuationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VerbChanged => f.write_str("attenuation cannot change the verb"),
            Self::WouldWiden => f.write_str("the result would not be contained by the parent"),
            Self::Invalid(e) => write!(f, "invalid narrowing: {e}"),
        }
    }
}

impl core::error::Error for AttenuationError {}

impl From<CapabilityError> for AttenuationError {
    fn from(error: CapabilityError) -> Self {
        Self::Invalid(error)
    }
}

impl From<ScopeError> for CapabilityError {
    fn from(error: ScopeError) -> Self {
        Self::InvalidScope(error)
    }
}
